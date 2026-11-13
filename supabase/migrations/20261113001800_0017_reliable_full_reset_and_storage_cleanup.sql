-- Make the full reset usable by any authenticated account with the admin role,
-- and ensure the admin can list/remove private submission files through Storage API.
-- The UI calls the database reset first so score/recommendation/submission records are
-- cleared even if physical object cleanup reports a separate problem.

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
  -- Phase 2 judge scores are stored in evaluations.
  delete from public.team_submissions;
  delete from public.team_phase2_submission_details;
  delete from public.evaluations;
  delete from public.phase1_evaluations;
  delete from public.ps_claim_events;
  delete from public.problem_statement_claims;
  delete from public.team_submission_sessions;
  update public.problem_statements
    set claimed_by_team_id = null,
        claimed_at = null;
  update public.teams set is_qualified_phase2 = false;

  return 'RESET';
end
$reset$;

revoke all on function public.reset_hackorbital_event() from public, anon;
grant execute on function public.reset_hackorbital_event() to authenticated;

-- These policies are intentionally restricted to admins and cover current and
-- legacy private buckets. Storage files must be removed using the Storage API,
-- not by deleting storage.objects rows directly.
drop policy if exists "Admins read submission files for full reset" on storage.objects;
create policy "Admins read submission files for full reset"
on storage.objects for select to authenticated
using (
  bucket_id in ('hackorbital-submissions', 'team-submissions')
  and public.has_role(auth.uid(), 'admin')
);

drop policy if exists "Admins delete submission files for full reset" on storage.objects;
create policy "Admins delete submission files for full reset"
on storage.objects for delete to authenticated
using (
  bucket_id in ('hackorbital-submissions', 'team-submissions')
  and public.has_role(auth.uid(), 'admin')
);

-- Ensure an open Judge Portal refreshes recommendations immediately after reset.
alter table public.phase1_evaluations replica identity full;
do $realtime$
begin
  if exists (
    select 1 from pg_publication where pubname = 'supabase_realtime'
  ) and not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'phase1_evaluations'
  ) then
    execute 'alter publication supabase_realtime add table public.phase1_evaluations';
  end if;
exception
  when insufficient_privilege then
    raise notice 'Could not add phase1_evaluations to supabase_realtime publication; refresh the Judge Portal after reset.';
end
$realtime$;

notify pgrst, 'reload schema';
