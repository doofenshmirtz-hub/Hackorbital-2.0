-- Event-relative problem-lock window and per-team Phase 1 upload enforcement.
-- The event clock starts only when the organizer opens problem locking.
-- Each team receives a four-hour Phase 1 window from its successful problem lock.

-- Repair a live lock-open event that was started with the previous hard-coded future
-- timestamp. `updated_at` is the launch action timestamp while the event is still
-- in lock_open, so use it as the actual event start for that active test/event.
update public.hackorbital_event_control
set event_started_at = updated_at,
    problem_lock_deadline_at = updated_at + interval '90 minutes'
where id = 1
  and is_live
  and current_phase = 'lock_open'
  and event_started_at > now();

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
          problem_lock_deadline_at = now() + interval '90 minutes',
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

-- The organizer can close the lock window early, but it is no longer tied to a
-- calendar timestamp. Moving to Phase 1 freezes new locks; already-locked teams
-- can continue uploading until their individual four-hour timers expire.
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

  if p_phase = 'phase1' and v_current <> 'lock_open' then
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
        event_started_at = coalesce(event_started_at, now()),
        phase2_deadline_at = case
          when p_phase = 'phase1' then coalesce(phase2_deadline_at, '2026-10-31 21:00:00+05:30'::timestamptz)
          else phase2_deadline_at
        end,
        updated_at = now(),
        updated_by = auth.uid()
    where id = 1
    returning * into v_result;
  return v_result;
end
$$;
revoke all on function public.set_hackorbital_event_phase(text) from public, anon;
grant execute on function public.set_hackorbital_event_phase(text) to authenticated;

-- Phase 1 files are allowed during the lock-open phase only when that team has
-- an active lock/session. The server checks the team's own 4-hour expiry.
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
          and ec.current_phase in ('lock_open', 'phase1')
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

-- Keep direct Supabase Storage writes under the same server-side phase and
-- four-hour deadline checks, even if a caller bypasses the regular submission UI.
drop policy if exists "HackOrbital team members upload before deadline" on storage.objects;
drop policy if exists "HackOrbital team members upload within event and team timer" on storage.objects;
create policy "HackOrbital team members upload within event and team timer"
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
    join public.hackorbital_event_control ec
      on ec.id = 1 and ec.is_live and ec.current_phase in ('lock_open', 'phase1')
    where p.id = auth.uid()
      and p.is_active
      and p.team_id::text = (storage.foldername(name))[1]
      and s.timer_started_at + interval '4 hours' > now()
  )
);

-- New problem locks are accepted only during the event-relative 90-minute window.
-- The lock RPC starts the team's four-hour timer atomically when the lock succeeds.
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
      and event_started_at is not null
      and problem_lock_deadline_at is not null
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

notify pgrst, 'reload schema';
