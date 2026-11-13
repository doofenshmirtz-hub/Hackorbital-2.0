-- Event launch, four-hour team timers, and team file submissions.
-- New event control rows default to OFF so participants cannot lock before launch.
create table if not exists public.hackorbital_event_control (
  id integer primary key default 1 check (id = 1),
  is_live boolean not null default false,
  event_started_at timestamptz,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id) on delete set null
);
insert into public.hackorbital_event_control (id, is_live)
values (1, false)
on conflict (id) do nothing;

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
  public.has_role(auth.uid(), 'admin') or public.has_role(auth.uid(), 'judge')
  or exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.is_active and p.team_id = team_submission_sessions.team_id
  )
);
grant select on public.team_submission_sessions to authenticated;
grant all on public.team_submission_sessions to service_role;

-- Keep existing team locks and records intact during schema setup. The event remains
-- OFF until the organizer explicitly starts it. Use the admin Reset Event action if
-- a deliberate lock/timer reset is required.

create table if not exists public.team_submissions (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams(id) on delete cascade,
  problem_id uuid not null references public.problem_statements(id) on delete cascade,
  uploaded_by uuid not null references public.profiles(id) on delete restrict,
  file_name text not null,
  source_type text not null check (source_type in ('upload', 'drive')),
  storage_path text,
  drive_url text,
  mime_type text,
  size_bytes bigint,
  created_at timestamptz not null default now(),
  constraint team_submissions_source_location_check check (
    (source_type = 'upload' and storage_path is not null and drive_url is null)
    or (source_type = 'drive' and storage_path is null and drive_url is not null)
  )
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
  public.has_role(auth.uid(), 'admin') or public.has_role(auth.uid(), 'judge')
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
grant select, insert on public.team_submissions to authenticated;
grant all on public.team_submissions to service_role;

-- A private bucket keeps uploaded presentations accessible only through RLS/signed URLs.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('hackorbital-submissions', 'hackorbital-submissions', false, 104857600, null)
on conflict (id) do update set public = false, file_size_limit = 104857600;

drop policy if exists "HackOrbital team members upload before deadline" on storage.objects;
drop policy if exists "HackOrbital teams and reviewers read submissions" on storage.objects;
drop policy if exists "Team members upload within submission window" on storage.objects;
drop policy if exists "Team members judges admins read submissions storage" on storage.objects;
create policy "HackOrbital team members upload before deadline"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'hackorbital-submissions'
  and exists (
    select 1
    from public.profiles p
    join public.user_roles ur on ur.user_id = p.id
      and ur.role in ('team_leader'::public.app_role, 'participant'::public.app_role)
    join public.problem_statement_claims c
      on c.team_id = p.team_id and c.problem_id::text = (storage.foldername(name))[2]
    join public.team_submission_sessions s
      on s.team_id = p.team_id and s.problem_id = c.problem_id
    join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
    where p.id = auth.uid()
      and p.is_active
      and p.team_id::text = (storage.foldername(name))[1]
      and s.timer_started_at + interval '4 hours' > now()
  )
);
create policy "HackOrbital teams and reviewers read submissions"
on storage.objects for select to authenticated
using (
  bucket_id = 'hackorbital-submissions'
  and (
    public.has_role(auth.uid(), 'admin')
    or public.has_role(auth.uid(), 'judge')
    or exists (
      select 1 from public.profiles p
      where p.id = auth.uid() and p.is_active
        and p.team_id::text = (storage.foldername(name))[1]
    )
  )
);

-- Keep the lock RPC atomic and make the event switch an actual server-side gate.
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
  if v_user is null then
    raise exception 'UNAUTHENTICATED';
  end if;

  if not exists (
    select 1 from public.hackorbital_event_control where id = 1 and is_live
  ) then
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

  if v_claim_count >= 2 then
    raise exception 'ALREADY_TAKEN';
  end if;

  insert into public.problem_statement_claims (problem_id, team_id)
  values (p_problem_id, p_team_id);

  update public.problem_statements
    set claimed_by_team_id = p_team_id, claimed_at = now()
    where id = p_problem_id and claimed_by_team_id is null;

  insert into public.team_submission_sessions (team_id, problem_id, timer_started_at)
  values (p_team_id, p_problem_id, now())
  on conflict (team_id) do update
    set problem_id = excluded.problem_id, timer_started_at = excluded.timer_started_at;

  return 'LOCKED';
exception
  when unique_violation then
    raise exception 'ALREADY_CLAIMED';
end
$$;
grant execute on function public.lock_problem_statement(uuid, uuid) to authenticated;

-- Before launch, participants cannot read any problem statements. When a team locks one,
-- they can only read that statement; judges/admins continue to see the full pool.
drop policy if exists "Authenticated users read tier 1 statements" on public.problem_statements;
drop policy if exists "Users read available or their locked statement" on public.problem_statements;
drop policy if exists "Event active pool or own locked statement" on public.problem_statements;
drop policy if exists "Event-gated problem statement visibility" on public.problem_statements;
create policy "Event-gated problem statement visibility"
on public.problem_statements for select to authenticated
using (
  public.has_role(auth.uid(), 'judge')
  or public.has_role(auth.uid(), 'admin')
  or exists (
    select 1 from public.profiles p
    join public.problem_statement_claims c on c.team_id = p.team_id
    where p.id = auth.uid() and p.is_active
      and c.problem_id = problem_statements.id
  )
  or (
    exists (select 1 from public.hackorbital_event_control ec where ec.id = 1 and ec.is_live)
    and not exists (
      select 1 from public.profiles p
      join public.problem_statement_claims c on c.team_id = p.team_id
      where p.id = auth.uid() and p.is_active
    )
  )
);

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
  -- Preserve previously uploaded files and submission records for judge/admin review.
  return 'RESET';
end
$$;
revoke all on function public.reset_hackorbital_event() from public, anon;
grant execute on function public.reset_hackorbital_event() to authenticated;

grant select on public.hackorbital_event_control to authenticated;
grant all on public.hackorbital_event_control to service_role;
alter table public.hackorbital_event_control enable row level security;
drop policy if exists "Authenticated users read event status" on public.hackorbital_event_control;
create policy "Authenticated users read event status"
on public.hackorbital_event_control for select to authenticated using (true);

-- Ensure newly created tables and RPC signatures are immediately visible to PostgREST.
notify pgrst, 'reload schema';
