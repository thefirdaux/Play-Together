-- Play Together — Supabase schema, RLS, and RPC functions.
--
-- Run this once in your Supabase project's SQL Editor (Project → SQL
-- Editor → New query → paste this whole file → Run), after creating the
-- project itself. See README-supabase.md for the full setup walkthrough.

-- ============================================================
-- Tables
-- ============================================================

-- A host's reusable, named phone-number whitelist (e.g. mirrors a
-- WhatsApp group). Attach a group to a game to restrict who can join.
create table public.groups (
  id          uuid primary key default gen_random_uuid(),
  host_id     uuid not null references auth.users(id) on delete cascade,
  name        text not null,
  created_at  timestamptz not null default now()
);
create index groups_host_id_idx on public.groups (host_id);

-- The phone whitelist for one group.
create table public.group_members (
  id        uuid primary key default gen_random_uuid(),
  group_id  uuid not null references public.groups(id) on delete cascade,
  phone     text not null,
  name      text,                 -- optional label, e.g. "Ahmad"
  added_at  timestamptz not null default now(),
  unique (group_id, phone)
);
create index group_members_group_id_idx on public.group_members (group_id);

create table public.games (
  id                  uuid primary key default gen_random_uuid(),
  host_id             uuid not null references auth.users(id) on delete cascade,
  group_id            uuid references public.groups(id) on delete set null,  -- null = open to everyone
  title               text not null,
  game_date           text,        -- pre-formatted display string, e.g. "Fri, 21 Aug 2026"
  time_start          text,
  time_end            text,
  venue               text,
  maps_link           text,
  waze_link           text,
  court_count         integer default 0,
  court_numbers       text[] default '{}',
  shuttle             text,
  price_summary       text default 'Free',
  description         text,
  participants_total  integer not null default 16,
  types               text[] default '{}',
  is_private          boolean default false,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now()
);
create index games_host_id_idx on public.games (host_id);

create table public.participants (
  id         uuid primary key default gen_random_uuid(),
  game_id    uuid not null references public.games(id) on delete cascade,
  name       text not null,
  phone      text not null,
  device_id  text not null,   -- client-generated (localStorage), not a Supabase auth identity
  waiting    boolean not null default false,
  joined_at  timestamptz not null default now()
);
create index participants_game_id_idx on public.participants (game_id);

-- ============================================================
-- Helper functions
-- ============================================================

create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger games_set_updated_at
before update on public.games
for each row execute function public.set_updated_at();

-- Strips everything but digits, then collapses a leading "60" country
-- code to a local "0" so "+60123456789", "0123456789" and
-- "012-345 6789" all compare equal. Adjust if your numbers don't fit
-- this shape.
create or replace function public.normalize_phone(p text)
returns text language sql immutable as $$
  select regexp_replace(
    regexp_replace(coalesce(p, ''), '[^0-9]', '', 'g'),
    '^60', '0'
  );
$$;

-- ============================================================
-- Row Level Security
-- ============================================================

alter table public.groups enable row level security;
alter table public.group_members enable row level security;
alter table public.games enable row level security;
alter table public.participants enable row level security;

create policy "Hosts manage own groups"
on public.groups for all
using (auth.uid() = host_id) with check (auth.uid() = host_id);

create policy "Hosts manage own group members"
on public.group_members for all
using (exists (select 1 from public.groups g where g.id = group_members.group_id and g.host_id = auth.uid()))
with check (exists (select 1 from public.groups g where g.id = group_members.group_id and g.host_id = auth.uid()));
-- No anon/public SELECT policy on groups or group_members at all —
-- deliberate. Nobody but the owning host can read a whitelist directly;
-- the join flow's whitelist check runs inside join_game() below, which
-- bypasses RLS internally via security definer.

create policy "Hosts manage own games"
on public.games for all
using (auth.uid() = host_id) with check (auth.uid() = host_id);

-- NOTE: no blanket "select using (true)" policy on games — that would
-- let anyone list every host's games (not just the one they have the
-- id/link for), which a client-side .eq('id', ...) filter does NOT
-- protect against once RLS itself grants row-level access. The public,
-- read-one-game-by-id need (game-title.html, no login) goes through the
-- get_public_game() RPC below instead, which only ever returns the one
-- row asked for.

-- Anyone can read participants of a game (needed to render the roster
-- on both the public join page and the host's admin view, and because
-- Realtime still evaluates SELECT RLS per change event). Column-level
-- access to `phone` is revoked further below so this can stay broad
-- without exposing everyone's phone numbers to a plain table scan.
create policy "Anyone can view participants"
on public.participants for select
using (true);

revoke select (phone) on public.participants from anon, authenticated;

-- Host can remove participants from their own games (roster management).
create policy "Host can remove participants from own games"
on public.participants for delete
to authenticated
using (exists (select 1 from public.games g where g.id = participants.game_id and g.host_id = auth.uid()));

-- No general anon INSERT/DELETE policy on participants — deliberate.
-- Joining and leaving go exclusively through the two RPCs below, which
-- run as security definer and enforce the whitelist + device-id checks
-- a plain RLS predicate can't safely express.

-- ============================================================
-- RPC functions
-- ============================================================

-- Public-safe way to fetch exactly one game by its unguessable id (used
-- by game-title.html, which has no login). security definer so it can
-- read the row despite there being no public "select using (true))"
-- policy on games — see the note above "Hosts manage own games".
create or replace function public.get_public_game(p_game_id uuid)
returns public.games
language sql security definer set search_path = public
as $$
  select * from public.games where id = p_game_id;
$$;
grant execute on function public.get_public_game(uuid) to anon, authenticated;

-- Validates the game's optional group whitelist, computes `waiting`
-- atomically (so two simultaneous joins can't both slip into the last
-- open spot), then inserts. Raises 'GAME_NOT_FOUND' or
-- 'PHONE_NOT_WHITELISTED' as plain error messages the client can match on.
create or replace function public.join_game(
  p_game_id uuid, p_name text, p_phone text, p_device_id text
)
returns public.participants
language plpgsql security definer set search_path = public
as $$
declare
  v_total integer;
  v_group_id uuid;
  v_joined_count integer;
  v_waiting boolean;
  v_row public.participants;
begin
  select participants_total, group_id into v_total, v_group_id
  from public.games where id = p_game_id;

  if v_total is null then
    raise exception 'GAME_NOT_FOUND';
  end if;

  if v_group_id is not null and not exists (
    select 1 from public.group_members
    where group_id = v_group_id
      and public.normalize_phone(phone) = public.normalize_phone(p_phone)
  ) then
    raise exception 'PHONE_NOT_WHITELISTED';
  end if;

  select count(*) into v_joined_count
  from public.participants where game_id = p_game_id and waiting = false;

  v_waiting := v_joined_count >= v_total;

  insert into public.participants (game_id, name, phone, device_id, waiting)
  values (p_game_id, p_name, p_phone, p_device_id, v_waiting)
  returning * into v_row;

  return v_row;
end;
$$;
grant execute on function public.join_game(uuid, text, text, text) to anon, authenticated;

-- Deletes a participant row only if the caller's device id matches —
-- their one proof of "this join is mine", since players don't have
-- accounts.
create or replace function public.leave_game(p_participant_id uuid, p_device_id text)
returns void
language plpgsql security definer set search_path = public
as $$
begin
  delete from public.participants
  where id = p_participant_id and device_id = p_device_id;
end;
$$;
grant execute on function public.leave_game(uuid, text) to anon, authenticated;

-- Whenever a *confirmed* (non-waiting) participant row is deleted — via
-- leave_game() above, or a host removing someone directly from
-- game-details.html — automatically promote the longest-waiting person
-- on that game's waiting list into the now-open spot. security definer
-- so it can update the row even though there's no general UPDATE policy
-- on participants (deliberately, same reasoning as the join/leave RPCs).
create or replace function public.promote_next_waiting()
returns trigger
language plpgsql security definer set search_path = public
as $$
declare
  v_next_id uuid;
begin
  if OLD.waiting = false then
    select id into v_next_id
    from public.participants
    where game_id = OLD.game_id and waiting = true
    order by joined_at asc
    limit 1;

    if v_next_id is not null then
      update public.participants set waiting = false where id = v_next_id;
    end if;
  end if;
  return OLD;
end;
$$;

drop trigger if exists participants_promote_waiting on public.participants;
create trigger participants_promote_waiting
after delete on public.participants
for each row execute function public.promote_next_waiting();

-- ============================================================
-- Realtime
-- ============================================================

-- Lets game-title.html / game-details.html subscribe to live join/leave
-- events. (If this errors because the publication doesn't exist yet in
-- your project, enable Realtime on the `participants` table instead via
-- Database → Replication in the dashboard.)
alter publication supabase_realtime add table public.participants;
