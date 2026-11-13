-- Fix Storage RLS rejecting legitimate team-leader uploads when the policy's
-- cross-table lookups are themselves filtered by the referenced tables' RLS.
-- Authorization remains strict: active team leader, matching team/problem lock,
-- and the same phase-specific deadline/qualification rules as migration 0016.

create or replace function public.can_upload_hackorbital_submission(p_object_name text)
returns boolean
language plpgsql
security definer
set search_path = public, storage, pg_temp
as $function$
declare
  v_user_id uuid := auth.uid();
  v_folders text[];
  v_team_id uuid;
  v_problem_id uuid;
  v_phase text;
begin
  if v_user_id is null or p_object_name is null then
    return false;
  end if;

  v_folders := storage.foldername(p_object_name);
  if coalesce(array_length(v_folders, 1), 0) <> 3 then
    return false;
  end if;

  begin
    v_team_id := v_folders[1]::uuid;
    v_problem_id := v_folders[2]::uuid;
  exception when invalid_text_representation then
    return false;
  end;

  v_phase := v_folders[3];
  if v_phase not in ('phase1', 'phase2') then
    return false;
  end if;

  return exists (
    select 1
    from public.profiles p
    join public.user_roles ur
      on ur.user_id = p.id
      and ur.role = 'team_leader'::public.app_role
    join public.teams t
      on t.id = p.team_id
      and t.leader_user_id = v_user_id
    join public.problem_statement_claims c
      on c.team_id = p.team_id
      and c.problem_id = v_problem_id
    join public.hackorbital_event_control ec
      on ec.id = 1
      and ec.is_live
    where p.id = v_user_id
      and p.is_active
      and p.team_id = v_team_id
      and (
        (
          v_phase = 'phase1'
          and ec.current_phase in ('lock_open', 'phase1')
          and exists (
            select 1
            from public.team_submission_sessions s
            where s.team_id = p.team_id
              and s.problem_id = c.problem_id
              and s.timer_started_at + interval '4 hours' > now()
          )
        )
        or
        (
          v_phase = 'phase2'
          and ec.current_phase in ('lock_open', 'phase1', 'phase1_review', 'phase2')
          and t.is_qualified_phase2
          and ec.phase2_deadline_at > now()
        )
      )
  );
end
$function$;

revoke all on function public.can_upload_hackorbital_submission(text) from public, anon;
grant execute on function public.can_upload_hackorbital_submission(text) to authenticated;

-- Replace the policy with a single hardened entry point. The SECURITY DEFINER
-- helper evaluates the authoritative checks without client-side RLS filtering
-- hiding the rows it needs to validate.
drop policy if exists "HackOrbital team leaders upload within phase rules" on storage.objects;
drop policy if exists "HackOrbital team members upload before deadline" on storage.objects;
drop policy if exists "HackOrbital team members upload within event and team timer" on storage.objects;
drop policy if exists "HackOrbital team members upload to private submissions" on storage.objects;
drop policy if exists "Team members upload within submission window" on storage.objects;
drop policy if exists "Team members upload within active submission timer" on storage.objects;

create policy "HackOrbital team leaders upload within phase rules"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'hackorbital-submissions'
  and public.can_upload_hackorbital_submission(name)
);

notify pgrst, 'reload schema';
