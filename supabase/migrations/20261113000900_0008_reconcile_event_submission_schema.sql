-- Reconcile the event/submission schema to the names used by the app.
-- Safe when the canonical schema exists, the older "event_control" schema exists,
-- or team_submissions was created by the earlier unjournaled 0007 migration.
-- This migration preserves submission rows, stored files, claims, and evaluation data.

create table if not exists public.hackorbital_event_control (
  id integer primary key default 1 check (id = 1),
  is_live boolean not null default false,
  event_started_at timestamptz,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);

-- If the legacy event_control table was already installed manually, migrate its
-- current state only when the canonical table has no row. Do not overwrite an
-- already configured canonical event state.
do $$
begin
  if to_regclass('public.event_control') is not null
     and not exists (select 1 from public.hackorbital_event_control where id = 1) then
    execute $copy$
      insert into public.hackorbital_event_control
        (id, is_live, event_started_at, updated_at, updated_by)
      select 1, coalesce(is_active, false), started_at, coalesce(updated_at, now()), updated_by
      from public.event_control
      where id = 1
      on conflict (id) do nothing
    $copy$;
  end if;
end
$$;

insert into public.hackorbital_event_control (id, is_live)
values (1, false)
on conflict (id) do nothing;

alter table public.hackorbital_event_control enable row level security;
drop policy if exists "Authenticated users read event status" on public.hackorbital_event_control;
drop policy if exists "Authenticated users can read event control" on public.hackorbital_event_control;
create policy "Authenticated users read event status"
  on public.hackorbital_event_control for select to authenticated using (auth.uid() is not null);
revoke all on public.hackorbital_event_control from anon, public;
grant select on public.hackorbital_event_control to authenticated;
grant all on public.hackorbital_event_control to service_role;

create table if not exists public.team_submission_sessions (
  team_id uuid primary key references public.teams(id) on delete cascade,
  problem_id uuid not null references public.problem_statements(id) on delete cascade,
  timer_started_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
alter table public.team_submission_sessions enable row level security;
drop policy if exists "Team members and reviewers read submission timers" on public.team_submission_sessions;
create policy "Team members and reviewers read submission timers"
  on public.team_submission_sessions for select to authenticated
  using (
    public.has_role(auth.uid(), 'admin')
    or public.has_role(auth.uid(), 'judge')
    or exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_active and p.team_id = team_submission_sessions.team_id
    )
  );
revoke all on public.team_submission_sessions from anon, public;
grant select on public.team_submission_sessions to authenticated;
grant all on public.team_submission_sessions to service_role;

-- Backfill legacy single-team claims without deleting or replacing existing locks.
insert into public.problem_statement_claims (problem_id, team_id, claimed_at)
select ps.id, ps.claimed_by_team_id, coalesce(ps.claimed_at, now())
from public.problem_statements ps
where ps.claimed_by_team_id is not null
on conflict do nothing;

-- Record a submission timer for any existing claim, anchored to its original claim
-- time instead of resetting a team's countdown during migration.
insert into public.team_submission_sessions (team_id, problem_id, timer_started_at)
select c.team_id, c.problem_id, c.claimed_at
from public.problem_statement_claims c
on conflict (team_id) do nothing;

create table if not exists public.team_submissions (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams(id) on delete cascade,
  problem_id uuid not null references public.problem_statements(id) on delete cascade,
  uploaded_by uuid not null references public.profiles(id) on delete restrict,
  file_name text not null,
  source_type text,
  storage_path text,
  storage_bucket text,
  drive_url text,
  mime_type text,
  size_bytes bigint,
  created_at timestamptz not null default now()
);

-- Normalize columns in-place if the earlier unjournaled migration created the
-- alternate object_path/external_url/file_size representation.
alter table public.team_submissions add column if not exists source_type text;
alter table public.team_submissions add column if not exists storage_path text;
alter table public.team_submissions add column if not exists storage_bucket text;
alter table public.team_submissions add column if not exists drive_url text;
alter table public.team_submissions add column if not exists mime_type text;
alter table public.team_submissions add column if not exists size_bytes bigint;

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'team_submissions' and column_name = 'object_path'
  ) then
    execute $copy$
      update public.team_submissions
      set storage_path = coalesce(storage_path, object_path),
          storage_bucket = case
            when storage_path is null and object_path is not null then coalesce(storage_bucket, 'team-submissions')
            else storage_bucket
          end,
          source_type = coalesce(source_type,
            case when external_url is not null then 'drive'
                 when object_path is not null then 'upload'
                 else null end),
          drive_url = coalesce(drive_url, external_url)
    $copy$;
  elsif exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'team_submissions' and column_name = 'external_url'
  ) then
    execute $copy$
      update public.team_submissions
      set drive_url = coalesce(drive_url, external_url),
          source_type = coalesce(source_type, case when external_url is not null then 'drive' else 'upload' end)
    $copy$;
  end if;

  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'team_submissions' and column_name = 'file_size'
  ) then
    execute 'update public.team_submissions set size_bytes = coalesce(size_bytes, file_size)';
  end if;
end
$$;

update public.team_submissions
set source_type = coalesce(
      source_type,
      case when drive_url is not null then 'drive'
           when storage_path is not null then 'upload'
           else null end
    ),
    storage_bucket = case
      when storage_path is null then storage_bucket
      when storage_bucket is not null then storage_bucket
      else 'hackorbital-submissions'
    end;

-- Remove old checks that only understand the legacy column names; retain the
-- legacy columns themselves so no data is lost.
alter table public.team_submissions drop constraint if exists team_submissions_exactly_one_source;
alter table public.team_submissions drop constraint if exists team_submissions_external_https;
alter table public.team_submissions drop constraint if exists team_submissions_source_location_check;
alter table public.team_submissions drop constraint if exists team_submissions_source_type_check;
alter table public.team_submissions drop constraint if exists team_submissions_source_location_check_v2;

alter table public.team_submissions alter column source_type set not null;
alter table public.team_submissions alter column storage_bucket set default 'hackorbital-submissions';

alter table public.team_submissions
  add constraint team_submissions_source_type_check
  check (source_type in ('upload', 'drive'));
alter table public.team_submissions
  add constraint team_submissions_source_location_check
  check (
    (source_type = 'upload' and storage_path is not null and drive_url is null and storage_bucket is not null)
    or (source_type = 'drive' and storage_path is null and drive_url is not null)
  );

create index if not exists team_submissions_team_problem_created_idx
  on public.team_submissions (team_id, problem_id, created_at desc);
alter table public.team_submissions enable row level security;
drop policy if exists "Teams and reviewers read submissions" on public.team_submissions;
drop policy if exists "Active team members submit during their timer" on public.team_submissions;
drop policy if exists "Teams judges admins read submissions" on public.team_submissions;
drop policy if exists "Teams upload submissions during active window" on public.team_submissions;
drop policy if exists "Admins delete team submissions" on public.team_submissions;

create policy "Teams and reviewers read submissions"
  on public.team_submissions for select to authenticated
  using (
    public.has_role(auth.uid(), 'judge')
    or public.has_role(auth.uid(), 'admin')
    or exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_active and p.team_id = team_submissions.team_id
    )
  );

create policy "Active team members submit during their timer"
  on public.team_submissions for insert to authenticated
  with check (
    uploaded_by = auth.uid()
    and exists (
      select 1
      from public.profiles p
      join public.user_roles ur on ur.user_id = p.id
        and ur.role in ('team_leader'::public.app_role, 'participant'::public.app_role)
      join public.problem_statement_claims c
        on c.team_id = p.team_id and c.problem_id = team_submissions.problem_id
      join public.team_submission_sessions s
        on s.team_id = p.team_id and s.problem_id = team_submissions.problem_id
      join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
      where p.id = auth.uid()
        and p.is_active
        and p.team_id = team_submissions.team_id
        and s.timer_started_at + interval '4 hours' > now()
    )
  );
revoke all on public.team_submissions from anon, public;
grant select, insert on public.team_submissions to authenticated;
grant all on public.team_submissions to service_role;

-- Keep legacy Supabase Storage submissions readable. New submissions use Google Drive.
insert into storage.buckets (id, name, public, file_size_limit)
values ('hackorbital-submissions', 'hackorbital-submissions', false, 104857600)
on conflict (id) do update set public = false, file_size_limit = 104857600;
insert into storage.buckets (id, name, public, file_size_limit)
values ('team-submissions', 'team-submissions', false, 262144000)
on conflict (id) do update set public = false, file_size_limit = 262144000;

drop policy if exists "HackOrbital team members upload before deadline" on storage.objects;
drop policy if exists "HackOrbital teams and reviewers read submissions" on storage.objects;
drop policy if exists "Team members upload within submission window" on storage.objects;
drop policy if exists "Team members judges admins read submissions storage" on storage.objects;
drop policy if exists "Teams and reviewers read legacy submissions storage" on storage.objects;

create policy "HackOrbital team members upload before deadline"
  on storage.objects for insert to authenticated
  with check (
    bucket_id in ('hackorbital-submissions', 'team-submissions')
    and exists (
      select 1
      from public.profiles p
      join public.user_roles ur on ur.user_id = p.id
        and ur.role in ('team_leader'::public.app_role, 'participant'::public.app_role)
      join public.problem_statement_claims c on c.team_id = p.team_id
      join public.team_submission_sessions s
        on s.team_id = p.team_id and s.problem_id = c.problem_id
      join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
      where p.id = auth.uid()
        and p.is_active
        and p.team_id::text = (storage.foldername(name))[1]
        and (bucket_id = 'team-submissions' or c.problem_id::text = (storage.foldername(name))[2])
        and s.timer_started_at + interval '4 hours' > now()
    )
  );

create policy "HackOrbital teams and reviewers read submissions"
  on storage.objects for select to authenticated
  using (
    bucket_id in ('hackorbital-submissions', 'team-submissions')
    and (
      public.has_role(auth.uid(), 'judge')
      or public.has_role(auth.uid(), 'admin')
      or exists (
        select 1 from public.profiles p
        where p.id = auth.uid() and p.is_active
          and p.team_id::text = (storage.foldername(name))[1]
      )
    )
  );

-- Event off means no participant can query the pool at all, even if a stale claim
-- from an earlier event exists. Judges/admins always retain access.
drop policy if exists "Authenticated users read tier 1 statements" on public.problem_statements;
drop policy if exists "Users read available or their locked statement" on public.problem_statements;
drop policy if exists "Event active pool or own locked statement" on public.problem_statements;
drop policy if exists "Event-gated problem statement visibility" on public.problem_statements;
create policy "Event-gated problem statement visibility"
  on public.problem_statements for select to authenticated
  using (
    public.has_role(auth.uid(), 'judge')
    or public.has_role(auth.uid(), 'admin')
    or (
      exists (select 1 from public.hackorbital_event_control ec where ec.id = 1 and ec.is_live)
      and (
        exists (
          select 1 from public.profiles p
          join public.problem_statement_claims c on c.team_id = p.team_id
          where p.id = auth.uid() and p.is_active
            and c.problem_id = problem_statements.id
        )
        or not exists (
          select 1 from public.profiles p
          join public.problem_statement_claims c on c.team_id = p.team_id
          where p.id = auth.uid() and p.is_active
        )
      )
    )
  );

-- Replace the locking RPC so launch state and the four-hour timer are enforced in
-- the database, not only in the React UI.
create or replace function public.lock_problem_statement(p_problem_id uuid, p_team_id uuid)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user uuid := auth.uid();
  v_existing_problem uuid;
  v_claim_count integer;
begin
  if v_user is null then raise exception 'UNAUTHENTICATED'; end if;

  if not exists (select 1 from public.hackorbital_event_control where id = 1 and is_live) then
    raise exception 'EVENT_NOT_LIVE';
  end if;

  perform pg_advisory_xact_lock(hashtextextended('team:' || p_team_id::text, 0));
  perform pg_advisory_xact_lock(hashtextextended('problem:' || p_problem_id::text, 0));

  if not exists (
    select 1
    from public.teams t
    join public.profiles p on p.id = v_user and p.is_active and p.team_id = p_team_id
    join public.user_roles ur on ur.user_id = v_user and ur.role = 'team_leader'
    where t.id = p_team_id and t.leader_user_id = v_user
  ) then
    raise exception 'NOT_TEAM_LEADER';
  end if;

  select problem_id into v_existing_problem
  from public.problem_statement_claims
  where team_id = p_team_id
  limit 1;

  if v_existing_problem is not null then
    if v_existing_problem = p_problem_id then
      insert into public.team_submission_sessions (team_id, problem_id, timer_started_at)
      select p_team_id, p_problem_id, c.claimed_at
      from public.problem_statement_claims c
      where c.team_id = p_team_id and c.problem_id = p_problem_id
      on conflict (team_id) do nothing;
      return 'LOCKED';
    end if;
    raise exception 'ALREADY_CLAIMED';
  end if;

  if not exists (select 1 from public.problem_statements where id = p_problem_id) then
    raise exception 'PROBLEM_NOT_FOUND';
  end if;

  select count(*) into v_claim_count
  from public.problem_statement_claims
  where problem_id = p_problem_id;
  if v_claim_count >= 2 then raise exception 'ALREADY_TAKEN'; end if;

  insert into public.problem_statement_claims (problem_id, team_id)
  values (p_problem_id, p_team_id);

  update public.problem_statements
    set claimed_by_team_id = coalesce(claimed_by_team_id, p_team_id),
        claimed_at = coalesce(claimed_at, now())
    where id = p_problem_id;

  insert into public.team_submission_sessions (team_id, problem_id, timer_started_at)
  values (p_team_id, p_problem_id, now())
  on conflict (team_id) do update
    set problem_id = excluded.problem_id, timer_started_at = excluded.timer_started_at;

  return 'LOCKED';
exception
  when unique_violation then raise exception 'ALREADY_CLAIMED';
end
$$;
revoke all on function public.lock_problem_statement(uuid, uuid) from public, anon;
grant execute on function public.lock_problem_statement(uuid, uuid) to authenticated;

create or replace function public.set_hackorbital_event_live(p_is_live boolean)
returns public.hackorbital_event_control
language plpgsql
security definer
set search_path = public
as $$
declare v_result public.hackorbital_event_control;
begin
  if auth.uid() is null
     or lower(coalesce(auth.jwt()->>'email','')) <> 'prathmeshgpachling@gmail.com'
     or not public.has_role(auth.uid(), 'admin') then
    raise exception 'FORBIDDEN';
  end if;

  update public.hackorbital_event_control
    set is_live = p_is_live,
        event_started_at = case when p_is_live then coalesce(event_started_at, now()) else event_started_at end,
        updated_at = now(),
        updated_by = auth.uid()
    where id = 1
    returning * into v_result;
  if not found then raise exception 'EVENT_CONTROL_NOT_INITIALIZED'; end if;
  return v_result;
end
$$;
revoke all on function public.set_hackorbital_event_live(boolean) from public, anon;
grant execute on function public.set_hackorbital_event_live(boolean) to authenticated;

create or replace function public.reset_hackorbital_event()
returns text
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null
     or lower(coalesce(auth.jwt()->>'email','')) <> 'prathmeshgpachling@gmail.com'
     or not public.has_role(auth.uid(), 'admin') then
    raise exception 'FORBIDDEN';
  end if;

  update public.hackorbital_event_control
    set is_live = false, event_started_at = null, updated_at = now(), updated_by = auth.uid()
    where id = 1;
  delete from public.problem_statement_claims;
  update public.problem_statements set claimed_by_team_id = null, claimed_at = null;
  delete from public.team_submission_sessions;
  -- Keep team_submissions and all associated Drive/storage files for review.
  return 'RESET';
end
$$;
revoke all on function public.reset_hackorbital_event() from public, anon;
grant execute on function public.reset_hackorbital_event() to authenticated;

alter table public.hackorbital_event_control replica identity full;
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'hackorbital_event_control'
  ) then
    alter publication supabase_realtime add table public.hackorbital_event_control;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'team_submissions'
  ) then
    alter publication supabase_realtime add table public.team_submissions;
  end if;
end
$$;

-- Create a board row as soon as the organizer whitelists a team name, without
-- requiring the team leader to sign in first. Auth sign-in later attaches leader_user_id.
insert into public.teams (name)
select distinct btrim(team_name)
from public.allowed_users
where nullif(btrim(team_name), '') is not null
on conflict (name) do nothing;

create or replace function public.handle_whitelist_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid;
begin
  if tg_op = 'DELETE'
     or (tg_op = 'UPDATE' and old.email is distinct from new.email) then
    select id into v_user_id
    from auth.users
    where lower(email) = lower(old.email);

    if v_user_id is not null then
      perform public.sync_whitelisted_user(v_user_id);
    end if;
  end if;

  if tg_op <> 'DELETE' then
    if nullif(btrim(new.team_name), '') is not null then
      insert into public.teams (name)
      values (btrim(new.team_name))
      on conflict (name) do nothing;
    end if;

    select id into v_user_id
    from auth.users
    where lower(email) = lower(new.email);

    if v_user_id is not null then
      perform public.sync_whitelisted_user(v_user_id);
    end if;
  end if;

  if tg_op = 'DELETE' then return old; end if;
  return new;
end
$$;
revoke all on function public.handle_whitelist_change() from public, authenticated;

-- Force PostgREST to notice the final schema in environments where the migration is run manually.
notify pgrst, 'reload schema';
