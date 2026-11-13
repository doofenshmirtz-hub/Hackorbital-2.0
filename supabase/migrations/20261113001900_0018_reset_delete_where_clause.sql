-- Fix the full reset for database environments that reject unqualified DELETEs.
-- Explicit WHERE true satisfies the guarded-delete requirement while intentionally
-- clearing all event-run rows from these event-specific tables.

create or replace function public.reset_hackorbital_event()
returns text
language plpgsql
security definer
set search_path = public, pg_temp
as $reset$
begin
  if auth.uid() is null or not public.has_role(auth.uid(), 'admin') then
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

  -- Phase 1 scores and recommendations are stored together in phase1_evaluations.
  -- Phase 2 judge scores are stored in evaluations. This is an intentionally full reset.
  delete from public.team_submissions where true;
  delete from public.team_phase2_submission_details where true;
  delete from public.evaluations where true;
  delete from public.phase1_evaluations where true;
  delete from public.ps_claim_events where true;
  delete from public.problem_statement_claims where true;
  delete from public.team_submission_sessions where true;

  update public.problem_statements
    set claimed_by_team_id = null,
        claimed_at = null
    where claimed_by_team_id is not null or claimed_at is not null;

  update public.teams
    set is_qualified_phase2 = false
    where is_qualified_phase2 is distinct from false;

  return 'RESET';
end
$reset$;

revoke all on function public.reset_hackorbital_event() from public, anon;
grant execute on function public.reset_hackorbital_event() to authenticated;

notify pgrst, 'reload schema';
