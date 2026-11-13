-- HACK-ORBITAL event workflow hardening:
-- 60-minute locking, random fallback assignment, leader-only submissions,
-- immediate Phase 2 upload access on admin qualification, and full event reset.

-- The shared locking deadline is one hour after organizer launch.
create or replace function public.set_hackorbital_event_live(p_is_live boolean)
returns public.hackorbital_event_control
language plpgsql
security definer
set search_path = public
as $$
declare
  v_result public.hackorbital_event_control;
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
          event_started_at = now(),
          problem_lock_deadline_at = now() + interval '60 minutes',
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

-- At the end of the 60-minute window, every team without a manual lock receives
-- a random problem statement with a free slot (maximum two teams per statement).
-- The team submission timer starts at the exact auto-assignment time.
create or replace function public.auto_assign_unlocked_teams_after_deadline()
returns integer
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_event public.hackorbital_event_control%rowtype;
  v_team_id uuid;
  v_problem_id uuid;
  v_assigned integer := 0;
begin
  select * into v_event
  from public.hackorbital_event_control
  where id = 1
  for update;

  if not found
     or not v_event.is_live
     or v_event.current_phase <> 'lock_open'
     or v_event.problem_lock_deadline_at is null
     or v_event.problem_lock_deadline_at > now() then
    return 0;
  end if;

  for v_team_id in
    select t.id
    from public.teams t
    where not exists (
      select 1 from public.problem_statement_claims c where c.team_id = t.id
    )
    order by random()
  loop
    v_problem_id := null;

    select ps.id into v_problem_id
    from public.problem_statements ps
    where (
      select count(*)
      from public.problem_statement_claims c
      where c.problem_id = ps.id
    ) < 2
    order by random()
    limit 1
    for update of ps skip locked;

    -- If all problem slots are full, stop without undoing successful assignments.
    exit when v_problem_id is null;

    insert into public.problem_statement_claims (problem_id, team_id, claimed_at)
    values (v_problem_id, v_team_id, now())
    on conflict (team_id) do nothing;

    if found then
      update public.problem_statements
      set claimed_by_team_id = coalesce(claimed_by_team_id, v_team_id),
          claimed_at = coalesce(claimed_at, now())
      where id = v_problem_id;

      insert into public.team_submission_sessions (team_id, problem_id, timer_started_at)
      values (v_team_id, v_problem_id, now())
      on conflict (team_id) do nothing;

      v_assigned := v_assigned + 1;
    end if;
  end loop;

  -- Close the lock phase automatically after the deadline, once fallback
  -- assignments have been attempted. Existing team timers continue independently.
  update public.hackorbital_event_control
    set current_phase = 'phase1',
        updated_at = now()
    where id = 1
      and is_live
      and current_phase = 'lock_open'
      and problem_lock_deadline_at <= now();

  return v_assigned;
end
$$;
revoke all on function public.auto_assign_unlocked_teams_after_deadline() from public, anon;
grant execute on function public.auto_assign_unlocked_teams_after_deadline() to authenticated;

-- If pg_cron is available in this Supabase project, schedule a server-side check
-- every minute so auto-assignment does not depend solely on a participant page
-- remaining open. The frontend poll remains a faster fallback.
do $cron_setup$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    begin
      execute $q$
        select cron.unschedule(jobid)
        from cron.job
        where jobname = 'hack-orbital-auto-assign-unlocked-teams'
      $q$;
      execute $q$
        select cron.schedule(
          'hack-orbital-auto-assign-unlocked-teams',
          '* * * * *',
          'select public.auto_assign_unlocked_teams_after_deadline();'
        )
      $q$;
    exception when others then
      raise notice 'Could not schedule HACK-ORBITAL auto-assignment with pg_cron; the website timer will still trigger it: %', sqlerrm;
    end;
  end if;
end
$cron_setup$;

-- Prevent the organizer from cutting the 60-minute lock window short. At the
-- deadline, finalize via the same auto-assignment routine, then return Phase 1.
create or replace function public.set_hackorbital_event_phase(p_phase text)
returns public.hackorbital_event_control
language plpgsql
security definer
set search_path = public
as $$
declare
  v_result public.hackorbital_event_control;
  v_current text;
  v_lock_deadline timestamptz;
begin
  if auth.uid() is null
     or lower(coalesce(auth.jwt()->>'email','')) <> 'prathmeshgpachling@gmail.com'
     or not public.has_role(auth.uid(), 'admin') then
    raise exception 'FORBIDDEN';
  end if;

  if p_phase not in ('phase1', 'phase1_review', 'phase2', 'closed') then
    raise exception 'INVALID_EVENT_PHASE';
  end if;

  select current_phase, problem_lock_deadline_at
    into v_current, v_lock_deadline
  from public.hackorbital_event_control
  where id = 1 and is_live
  for update;
  if not found then raise exception 'EVENT_NOT_LIVE'; end if;

  if p_phase = 'phase1' then
    if v_current <> 'lock_open' then
      raise exception 'INVALID_PHASE_TRANSITION';
    end if;
    if v_lock_deadline is null or v_lock_deadline > now() then
      raise exception 'LOCK_WINDOW_NOT_EXPIRED';
    end if;

    perform public.auto_assign_unlocked_teams_after_deadline();
    select * into v_result
    from public.hackorbital_event_control where id = 1;
    return v_result;
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
        updated_at = now(),
        updated_by = auth.uid()
    where id = 1
    returning * into v_result;

  return v_result;
end
$$;
revoke all on function public.set_hackorbital_event_phase(text) from public, anon;
grant execute on function public.set_hackorbital_event_phase(text) to authenticated;

-- Stop untrusted clients inserting submission rows directly. The registration RPC
-- owns row creation after validating the Storage object and the team's authority.
drop policy if exists "Active team members submit during their timer" on public.team_submissions;
drop policy if exists "Teams upload files in authorized phase" on public.team_submissions;
drop policy if exists "Teams upload submissions during active window" on public.team_submissions;
drop policy if exists "Authorized team submissions within phase timer" on public.team_submissions;
revoke insert on public.team_submissions from anon, authenticated;
grant select on public.team_submissions to authenticated;

create or replace function public.register_team_submission(
  p_team_id uuid,
  p_problem_id uuid,
  p_submission_phase text,
  p_file_name text,
  p_storage_path text,
  p_mime_type text default null,
  p_size_bytes bigint default null
)
returns uuid
language plpgsql
security definer
set search_path = public, storage, pg_temp
as $$
declare
  v_user_id uuid := auth.uid();
  v_prefix text;
  v_submission_id uuid;
begin
  if v_user_id is null then
    raise exception 'UNAUTHENTICATED';
  end if;

  if p_team_id is null
     or p_problem_id is null
     or p_submission_phase not in ('phase1', 'phase2')
     or p_file_name is null
     or length(trim(p_file_name)) = 0
     or length(p_file_name) > 255
     or p_storage_path is null
     or p_size_bytes is null
     or p_size_bytes < 0
     or p_size_bytes > 104857600 then
    raise exception 'INVALID_SUBMISSION_METADATA';
  end if;

  v_prefix := p_team_id::text || '/' || p_problem_id::text || '/' || p_submission_phase || '/';
  if left(p_storage_path, length(v_prefix)) <> v_prefix
     or length(p_storage_path) <= length(v_prefix) then
    raise exception 'INVALID_SUBMISSION_PATH';
  end if;

  if not exists (
    select 1 from storage.objects o
    where o.bucket_id = 'hackorbital-submissions'
      and o.name = p_storage_path
  ) then
    raise exception 'SUBMISSION_OBJECT_NOT_FOUND';
  end if;

  if not exists (
    select 1
    from public.profiles p
    join public.user_roles ur
      on ur.user_id = p.id and ur.role = 'team_leader'::public.app_role
    join public.teams t
      on t.id = p.team_id and t.leader_user_id = v_user_id
    join public.problem_statement_claims c
      on c.team_id = p.team_id and c.problem_id = p_problem_id
    join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
    where p.id = v_user_id
      and p.is_active
      and p.team_id = p_team_id
      and (
        (
          p_submission_phase = 'phase1'
          and ec.current_phase in ('lock_open', 'phase1')
          and exists (
            select 1 from public.team_submission_sessions s
            where s.team_id = p_team_id
              and s.problem_id = p_problem_id
              and s.timer_started_at + interval '4 hours' > now()
          )
        )
        or
        (
          p_submission_phase = 'phase2'
          and ec.current_phase in ('lock_open', 'phase1', 'phase1_review', 'phase2')
          and t.is_qualified_phase2
          and ec.phase2_deadline_at > now()
        )
      )
  ) then
    raise exception 'SUBMISSION_NOT_AUTHORIZED_FOR_TEAM_PHASE';
  end if;

  insert into public.team_submissions (
    team_id, problem_id, uploaded_by, file_name, source_type,
    submission_phase, storage_path, storage_bucket, drive_url, mime_type, size_bytes
  )
  values (
    p_team_id, p_problem_id, v_user_id, p_file_name, 'upload',
    p_submission_phase, p_storage_path, 'hackorbital-submissions', null,
    nullif(trim(coalesce(p_mime_type, '')), ''), p_size_bytes
  )
  returning id into v_submission_id;

  return v_submission_id;
end
$$;
revoke all on function public.register_team_submission(uuid, uuid, text, text, text, text, bigint) from public, anon;
grant execute on function public.register_team_submission(uuid, uuid, text, text, text, text, bigint) to authenticated;

-- Storage uploads are restricted to the authenticated team leader and the team's
-- active Phase 1 timer or its qualified Phase 2 window.
drop policy if exists "HackOrbital team members upload before deadline" on storage.objects;
drop policy if exists "HackOrbital team members upload within event and team timer" on storage.objects;
drop policy if exists "HackOrbital team members upload to private submissions" on storage.objects;
drop policy if exists "Team members upload within submission window" on storage.objects;
drop policy if exists "Team members upload within active submission timer" on storage.objects;
drop policy if exists "HackOrbital team leaders upload within phase rules" on storage.objects;
create policy "HackOrbital team leaders upload within phase rules"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'hackorbital-submissions'
  and exists (
    select 1
    from public.profiles p
    join public.user_roles ur on ur.user_id = p.id and ur.role = 'team_leader'::public.app_role
    join public.teams t on t.id = p.team_id and t.leader_user_id = auth.uid()
    join public.problem_statement_claims c
      on c.team_id = p.team_id and c.problem_id::text = (storage.foldername(name))[2]
    join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
    where p.id = auth.uid()
      and p.is_active
      and p.team_id::text = (storage.foldername(name))[1]
      and (
        (
          (storage.foldername(name))[3] = 'phase1'
          and ec.current_phase in ('lock_open', 'phase1')
          and exists (
            select 1 from public.team_submission_sessions s
            where s.team_id = p.team_id and s.problem_id = c.problem_id
              and s.timer_started_at + interval '4 hours' > now()
          )
        )
        or
        (
          (storage.foldername(name))[3] = 'phase2'
          and ec.current_phase in ('lock_open', 'phase1', 'phase1_review', 'phase2')
          and t.is_qualified_phase2
          and ec.phase2_deadline_at > now()
        )
      )
  )
);

drop policy if exists "Teams remove unregistered submission uploads" on storage.objects;
drop policy if exists "Team leaders remove unregistered submission uploads" on storage.objects;
create policy "Team leaders remove unregistered submission uploads"
on storage.objects for delete to authenticated
using (
  bucket_id = 'hackorbital-submissions'
  and exists (
    select 1
    from public.profiles p
    join public.user_roles ur on ur.user_id = p.id and ur.role = 'team_leader'::public.app_role
    join public.teams t on t.id = p.team_id and t.leader_user_id = auth.uid()
    join public.problem_statement_claims c
      on c.team_id = p.team_id and c.problem_id::text = (storage.foldername(name))[2]
    where p.id = auth.uid()
      and p.is_active
      and p.team_id::text = (storage.foldername(name))[1]
  )
  and not exists (
    select 1 from public.team_submissions ts
    where ts.storage_bucket = storage.objects.bucket_id
      and ts.storage_path = storage.objects.name
  )
);

-- Admins need to list private objects before removing them via the Storage API
-- during a full reset, including objects stored under the legacy bucket.
drop policy if exists "Admins read submission files for full reset" on storage.objects;
create policy "Admins read submission files for full reset"
on storage.objects for select to authenticated
using (
  bucket_id in ('hackorbital-submissions', 'team-submissions')
  and public.has_role(auth.uid(), 'admin')
);

-- Admin-only deletion supports the explicit full-reset action across current and
-- legacy private buckets; storage files are deleted via the Storage API, not SQL.
drop policy if exists "Admins delete submission files for full reset" on storage.objects;
create policy "Admins delete submission files for full reset"
on storage.objects for delete to authenticated
using (
  bucket_id in ('hackorbital-submissions', 'team-submissions')
  and public.has_role(auth.uid(), 'admin')
);

-- Phase 2 links appear as soon as the organizer marks the team qualified in the
-- review phase; only team leaders may insert/update the links.
drop policy if exists "Qualified team members submit Phase 2 links" on public.team_phase2_submission_details;
drop policy if exists "Qualified team members update Phase 2 links" on public.team_phase2_submission_details;
drop policy if exists "Qualified team leaders submit Phase 2 links" on public.team_phase2_submission_details;
create policy "Qualified team leaders submit Phase 2 links"
on public.team_phase2_submission_details for insert to authenticated
with check (
  submitted_by = auth.uid()
  and exists (
    select 1
    from public.profiles p
    join public.user_roles ur on ur.user_id = p.id and ur.role = 'team_leader'::public.app_role
    join public.teams t on t.id = p.team_id and t.leader_user_id = auth.uid()
    join public.problem_statement_claims c on c.team_id = t.id and c.problem_id = team_phase2_submission_details.problem_id
    join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
    where p.id = auth.uid() and p.is_active
      and t.id = team_phase2_submission_details.team_id
      and t.is_qualified_phase2
      and ec.current_phase in ('lock_open', 'phase1', 'phase1_review', 'phase2')
      and ec.phase2_deadline_at > now()
  )
);

drop policy if exists "Qualified team leaders update Phase 2 links" on public.team_phase2_submission_details;
create policy "Qualified team leaders update Phase 2 links"
on public.team_phase2_submission_details for update to authenticated
using (
  exists (
    select 1
    from public.profiles p
    join public.user_roles ur on ur.user_id = p.id and ur.role = 'team_leader'::public.app_role
    join public.teams t on t.id = p.team_id and t.leader_user_id = auth.uid()
    join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
    where p.id = auth.uid()
      and p.is_active
      and t.id = team_phase2_submission_details.team_id
      and t.is_qualified_phase2
      and ec.current_phase in ('lock_open', 'phase1', 'phase1_review', 'phase2')
      and ec.phase2_deadline_at > now()
  )
)
with check (
  submitted_by = auth.uid()
  and exists (
    select 1
    from public.profiles p
    join public.user_roles ur on ur.user_id = p.id and ur.role = 'team_leader'::public.app_role
    join public.teams t on t.id = p.team_id and t.leader_user_id = auth.uid()
    join public.problem_statement_claims c on c.team_id = t.id and c.problem_id = team_phase2_submission_details.problem_id
    join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
    where p.id = auth.uid()
      and p.is_active
      and t.id = team_phase2_submission_details.team_id
      and t.is_qualified_phase2
      and ec.current_phase in ('lock_open', 'phase1', 'phase1_review', 'phase2')
      and ec.phase2_deadline_at > now()
  )
);

-- Full reset clears every event run's submissions, both judging tables, Phase 2 links,
-- locks, sessions, qualification flags and event clock. Team accounts, whitelist and
-- problem bank remain so the organizer can start a fresh run without reprovisioning.
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

  delete from public.team_submissions;
  delete from public.team_phase2_submission_details;
  delete from public.evaluations;
  delete from public.phase1_evaluations;
  delete from public.ps_claim_events;
  delete from public.problem_statement_claims;
  update public.problem_statements set claimed_by_team_id = null, claimed_at = null;
  delete from public.team_submission_sessions;
  update public.teams set is_qualified_phase2 = false;

  return 'RESET';
end
$reset$;
revoke all on function public.reset_hackorbital_event() from public, anon;
grant execute on function public.reset_hackorbital_event() to authenticated;

-- Keep the submission data schema in sync when migrations are manually applied.
notify pgrst, 'reload schema';
