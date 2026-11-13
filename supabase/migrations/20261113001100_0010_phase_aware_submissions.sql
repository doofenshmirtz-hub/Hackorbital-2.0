-- Phase-aware HackOrbital submissions, qualification recommendations, and stage control.
-- Existing submission rows are retained and are classified as Phase 1 by default.

alter table public.hackorbital_event_control
  add column if not exists current_phase text not null default 'closed';
alter table public.hackorbital_event_control
  add column if not exists phase2_deadline_at timestamptz;
alter table public.hackorbital_event_control
  add column if not exists problem_lock_deadline_at timestamptz;

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.hackorbital_event_control'::regclass
      and conname = 'hackorbital_event_control_current_phase_check'
  ) then
    alter table public.hackorbital_event_control
      add constraint hackorbital_event_control_current_phase_check
      check (current_phase in ('closed', 'lock_open', 'phase1', 'phase1_review', 'phase2'));
  end if;
end
$$;

update public.hackorbital_event_control
set current_phase = case when is_live then 'phase1' else 'closed' end,
    problem_lock_deadline_at = coalesce(problem_lock_deadline_at, '2026-10-30 10:00:00+05:30'::timestamptz),
    phase2_deadline_at = coalesce(phase2_deadline_at, '2026-10-31 21:00:00+05:30'::timestamptz)
where id = 1;

alter table public.team_submissions
  add column if not exists submission_phase text not null default 'phase1';

do $$
begin
  if not exists (
    select 1 from pg_constraint
    where conrelid = 'public.team_submissions'::regclass
      and conname = 'team_submissions_submission_phase_check'
  ) then
    alter table public.team_submissions
      add constraint team_submissions_submission_phase_check
      check (submission_phase in ('phase1', 'phase2'));
  end if;
end
$$;

alter table public.phase1_evaluations
  add column if not exists recommend_phase2 boolean not null default false;

create table if not exists public.team_phase2_submission_details (
  team_id uuid primary key references public.teams(id) on delete cascade,
  problem_id uuid not null references public.problem_statements(id) on delete restrict,
  repository_url text,
  demo_url text,
  submitted_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now(),
  constraint team_phase2_repository_https check (repository_url is null or repository_url ~ '^https://'),
  constraint team_phase2_demo_https check (demo_url is null or demo_url ~ '^https://')
);

alter table public.team_phase2_submission_details enable row level security;
drop policy if exists "Team and reviewers read Phase 2 links" on public.team_phase2_submission_details;
drop policy if exists "Qualified team members submit Phase 2 links" on public.team_phase2_submission_details;
drop policy if exists "Qualified team members update Phase 2 links" on public.team_phase2_submission_details;

create policy "Team and reviewers read Phase 2 links"
on public.team_phase2_submission_details for select to authenticated
using (
  public.has_role(auth.uid(), 'admin')
  or public.has_role(auth.uid(), 'judge')
  or exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.is_active
      and p.team_id = team_phase2_submission_details.team_id
  )
);

create policy "Qualified team members submit Phase 2 links"
on public.team_phase2_submission_details for insert to authenticated
with check (
  submitted_by = auth.uid()
  and exists (
    select 1
    from public.profiles p
    join public.teams t on t.id = p.team_id
    join public.problem_statement_claims c
      on c.team_id = t.id and c.problem_id = team_phase2_submission_details.problem_id
    join public.hackorbital_event_control ec on ec.id = 1
    where p.id = auth.uid() and p.is_active
      and t.id = team_phase2_submission_details.team_id
      and t.is_qualified_phase2
      and ec.is_live and ec.current_phase = 'phase2'
      and ec.phase2_deadline_at > now()
  )
);

create policy "Qualified team members update Phase 2 links"
on public.team_phase2_submission_details for update to authenticated
using (
  exists (
    select 1
    from public.profiles p
    join public.teams t on t.id = p.team_id
    join public.hackorbital_event_control ec on ec.id = 1
    where p.id = auth.uid() and p.is_active
      and t.id = team_phase2_submission_details.team_id
      and t.is_qualified_phase2
      and ec.is_live and ec.current_phase = 'phase2'
      and ec.phase2_deadline_at > now()
  )
)
with check (
  submitted_by = auth.uid()
  and exists (
    select 1
    from public.profiles p
    join public.teams t on t.id = p.team_id
    join public.problem_statement_claims c
      on c.team_id = t.id and c.problem_id = team_phase2_submission_details.problem_id
    join public.hackorbital_event_control ec on ec.id = 1
    where p.id = auth.uid() and p.is_active
      and t.id = team_phase2_submission_details.team_id
      and t.is_qualified_phase2
      and ec.is_live and ec.current_phase = 'phase2'
      and ec.phase2_deadline_at > now()
  )
);

revoke all on public.team_phase2_submission_details from anon, public;
grant select, insert, update on public.team_phase2_submission_details to authenticated;
grant all on public.team_phase2_submission_details to service_role;

-- Preserve reviewer access and limit team uploads to the phase-specific rules.
drop policy if exists "Active team members submit during their timer" on public.team_submissions;
drop policy if exists "Teams upload submissions during active window" on public.team_submissions;
drop policy if exists "Teams upload files in authorized phase" on public.team_submissions;

create policy "Teams upload files in authorized phase"
on public.team_submissions for insert to authenticated
with check (
  uploaded_by = auth.uid()
  and exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.is_active
      and p.team_id = team_submissions.team_id
  )
  and exists (
    select 1 from public.problem_statement_claims c
    where c.team_id = team_submissions.team_id
      and c.problem_id = team_submissions.problem_id
  )
  and exists (
    select 1
    from public.hackorbital_event_control ec
    join public.teams t on t.id = team_submissions.team_id
    where ec.id = 1 and ec.is_live
      and (
        (
          team_submissions.submission_phase = 'phase1'
          and ec.current_phase = 'phase1'
          and exists (
            select 1 from public.team_submission_sessions s
            where s.team_id = team_submissions.team_id
              and s.problem_id = team_submissions.problem_id
              and s.timer_started_at + interval '4 hours' > now()
          )
        )
        or
        (
          team_submissions.submission_phase = 'phase2'
          and ec.current_phase = 'phase2'
          and t.is_qualified_phase2
          and ec.phase2_deadline_at > now()
        )
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

  if p_is_live then
    if exists (
      select 1 from public.hackorbital_event_control
      where id = 1 and (is_live or event_started_at is not null)
    ) then
      raise exception 'RESET_REQUIRED';
    end if;
    update public.hackorbital_event_control
      set is_live = true,
          current_phase = 'lock_open',
          event_started_at = '2026-10-30 09:00:00+05:30'::timestamptz,
          problem_lock_deadline_at = '2026-10-30 10:00:00+05:30'::timestamptz,
          phase2_deadline_at = '2026-10-31 21:00:00+05:30'::timestamptz,
          updated_at = now(),
          updated_by = auth.uid()
      where id = 1
      returning * into v_result;
  else
    update public.hackorbital_event_control
      set is_live = false,
          current_phase = 'closed',
          updated_at = now(),
          updated_by = auth.uid()
      where id = 1
      returning * into v_result;
  end if;

  if not found then raise exception 'EVENT_CONTROL_NOT_INITIALIZED'; end if;
  return v_result;
end
$$;
revoke all on function public.set_hackorbital_event_live(boolean) from public, anon;
grant execute on function public.set_hackorbital_event_live(boolean) to authenticated;

create or replace function public.set_hackorbital_event_phase(p_phase text)
returns public.hackorbital_event_control
language plpgsql
security definer
set search_path = public
as $$
declare
  v_result public.hackorbital_event_control;
  v_current text;
begin
  if auth.uid() is null
     or lower(coalesce(auth.jwt()->>'email','')) <> 'prathmeshgpachling@gmail.com'
     or not public.has_role(auth.uid(), 'admin') then
    raise exception 'FORBIDDEN';
  end if;

  if p_phase not in ('phase1', 'phase1_review', 'phase2', 'closed') then
    raise exception 'INVALID_EVENT_PHASE';
  end if;

  select current_phase into v_current
  from public.hackorbital_event_control
  where id = 1 and is_live
  for update;
  if not found then raise exception 'EVENT_NOT_LIVE'; end if;

  if p_phase = 'phase1' and (v_current <> 'lock_open' or not exists (
    select 1 from public.hackorbital_event_control
    where id = 1 and problem_lock_deadline_at <= now()
  )) then
    raise exception 'INVALID_PHASE_TRANSITION';
  end if;
  if p_phase = 'phase1_review' and v_current <> 'phase1' then
    raise exception 'INVALID_PHASE_TRANSITION';
  end if;
  if p_phase = 'phase2' and v_current <> 'phase1_review' then
    raise exception 'INVALID_PHASE_TRANSITION';
  end if;
  if p_phase = 'phase2' and not exists (
    select 1 from public.hackorbital_event_control
    where id = 1 and phase2_deadline_at > now()
  ) then
    raise exception 'PHASE2_DEADLINE_PASSED';
  end if;

  update public.hackorbital_event_control
    set current_phase = p_phase,
        is_live = (p_phase <> 'closed'),
        event_started_at = case when p_phase = 'phase1' then coalesce(event_started_at, now()) else event_started_at end,
        phase2_deadline_at = case when p_phase = 'phase1' then coalesce(phase2_deadline_at, '2026-10-31 21:00:00+05:30'::timestamptz) else phase2_deadline_at end,
        updated_at = now(),
        updated_by = auth.uid()
    where id = 1
    returning * into v_result;
  return v_result;
end
$$;
revoke all on function public.set_hackorbital_event_phase(text) from public, anon;
grant execute on function public.set_hackorbital_event_phase(text) to authenticated;

-- Rebuild the lock function with a database-enforced Phase 1 stage.
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

  if not exists (
    select 1 from public.hackorbital_event_control
    where id = 1 and is_live and current_phase = 'lock_open'
      and problem_lock_deadline_at > now()
  ) then raise exception 'LOCK_WINDOW_CLOSED'; end if;

  perform pg_advisory_xact_lock(hashtextextended('team:' || p_team_id::text, 0));
  perform pg_advisory_xact_lock(hashtextextended('problem:' || p_problem_id::text, 0));

  if not exists (
    select 1
    from public.teams t
    join public.profiles p on p.id = v_user and p.is_active and p.team_id = p_team_id
    join public.user_roles ur on ur.user_id = v_user and ur.role = 'team_leader'
    where t.id = p_team_id and t.leader_user_id = v_user
  ) then raise exception 'NOT_TEAM_LEADER'; end if;

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


create or replace function public.reset_hackorbital_event()
returns text
language plpgsql
security definer
set search_path = public
as $reset$
begin
  if auth.uid() is null
     or lower(coalesce(auth.jwt()->>'email','')) <> 'prathmeshgpachling@gmail.com'
     or not public.has_role(auth.uid(), 'admin') then
    raise exception 'FORBIDDEN';
  end if;

  update public.hackorbital_event_control
    set is_live = false,
        current_phase = 'closed',
        event_started_at = null,
        problem_lock_deadline_at = null,
        phase2_deadline_at = null,
        updated_at = now(),
        updated_by = auth.uid()
    where id = 1;

  delete from public.problem_statement_claims;
  update public.problem_statements set claimed_by_team_id = null, claimed_at = null;
  update public.teams set is_qualified_phase2 = false;
  delete from public.team_submission_sessions;
  -- Preserve team_submissions and all associated Drive/storage files.
  return 'RESET';
end
$reset$;
revoke all on function public.reset_hackorbital_event() from public, anon;
grant execute on function public.reset_hackorbital_event() to authenticated;

-- During Phase 1, teams that have not yet locked may browse the pool. During review/Phase 2,
-- teams can only read their own locked statement. Judges/admins retain full visibility.
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
      exists (
        select 1 from public.hackorbital_event_control ec
        where ec.id = 1 and ec.is_live and ec.current_phase = 'lock_open' and ec.problem_lock_deadline_at > now()
      )
      and not exists (
        select 1 from public.profiles p
        join public.problem_statement_claims c on c.team_id = p.team_id
        where p.id = auth.uid() and p.is_active
      )
    )
  );

alter table public.hackorbital_event_control replica identity full;
alter table public.team_submissions replica identity full;

do $$
begin
  if exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'team_phase2_submission_details'
  ) then
    null;
  else
    alter publication supabase_realtime add table public.team_phase2_submission_details;
  end if;
end
$$;

notify pgrst, 'reload schema';
