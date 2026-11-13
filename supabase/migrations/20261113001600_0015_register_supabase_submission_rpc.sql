-- Register completed private Storage uploads through a narrowly validated SECURITY DEFINER RPC.
-- This avoids mismatched table INSERT RLS policies while re-validating every authorization
-- condition server-side before any submission record is created.

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

  -- Confirm that an object was uploaded under the exact expected key before
  -- recording it. Storage upload permissions independently validate the path.
  if not exists (
    select 1
    from storage.objects o
    where o.bucket_id = 'hackorbital-submissions'
      and o.name = p_storage_path
  ) then
    raise exception 'SUBMISSION_OBJECT_NOT_FOUND';
  end if;

  -- Re-check identity, active team membership, the existing lock/session, phase,
  -- and phase deadline in the database. Do not trust browser-provided team/phase IDs.
  if not exists (
    select 1
    from public.profiles p
    join public.user_roles ur
      on ur.user_id = p.id
      and ur.role in ('team_leader'::public.app_role, 'participant'::public.app_role)
    join public.problem_statement_claims c
      on c.team_id = p.team_id
      and c.problem_id = p_problem_id
    join public.teams t
      on t.id = p.team_id
    join public.hackorbital_event_control ec
      on ec.id = 1 and ec.is_live
    where p.id = v_user_id
      and p.is_active
      and p.team_id = p_team_id
      and (
        (
          p_submission_phase = 'phase1'
          and ec.current_phase in ('lock_open', 'phase1')
          and exists (
            select 1
            from public.team_submission_sessions s
            where s.team_id = p_team_id
              and s.problem_id = p_problem_id
              and s.timer_started_at + interval '4 hours' > now()
          )
        )
        or
        (
          p_submission_phase = 'phase2'
          and ec.current_phase = 'phase2'
          and t.is_qualified_phase2
          and ec.phase2_deadline_at > now()
        )
      )
  ) then
    raise exception 'SUBMISSION_NOT_AUTHORIZED_FOR_TEAM_PHASE';
  end if;

  insert into public.team_submissions (
    team_id,
    problem_id,
    uploaded_by,
    file_name,
    source_type,
    submission_phase,
    storage_path,
    storage_bucket,
    drive_url,
    mime_type,
    size_bytes
  )
  values (
    p_team_id,
    p_problem_id,
    v_user_id,
    p_file_name,
    'upload',
    p_submission_phase,
    p_storage_path,
    'hackorbital-submissions',
    null,
    nullif(trim(coalesce(p_mime_type, '')), ''),
    p_size_bytes
  )
  returning id into v_submission_id;

  return v_submission_id;
end
$$;

revoke all on function public.register_team_submission(uuid, uuid, text, text, text, text, bigint) from public, anon;
grant execute on function public.register_team_submission(uuid, uuid, text, text, text, text, bigint) to authenticated;

notify pgrst, 'reload schema';
