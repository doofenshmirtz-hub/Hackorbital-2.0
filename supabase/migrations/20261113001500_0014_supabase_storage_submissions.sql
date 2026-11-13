-- Replace Google Drive uploads with direct private Supabase Storage submissions.
-- Uploaded object paths are: <team UUID>/<problem UUID>/<phase1|phase2>/<unique-name>.
-- Access is enforced by the database; browser timers are only a convenience display.

insert into storage.buckets (id, name, public, file_size_limit)
values ('hackorbital-submissions', 'hackorbital-submissions', false, 104857600)
on conflict (id) do update
  set public = false,
      file_size_limit = 104857600,
      allowed_mime_types = null;

alter table public.team_submissions
  alter column storage_bucket set default 'hackorbital-submissions';

-- Remove legacy/permissive insert policies. Multiple permissive RLS policies are ORed,
-- so leaving an older policy in place could bypass phase-specific rules below.
drop policy if exists "Active team members submit during their timer" on public.team_submissions;
drop policy if exists "Teams upload files in authorized phase" on public.team_submissions;
drop policy if exists "Teams upload submissions during active window" on public.team_submissions;
drop policy if exists "Teams upload submissions during active team timer" on public.team_submissions;
drop policy if exists "Authorized team submissions within phase timer" on public.team_submissions;

create policy "Authorized team submissions within phase timer"
on public.team_submissions for insert to authenticated
with check (
  uploaded_by = auth.uid()
  and source_type = 'upload'
  and storage_path is not null
  and storage_bucket = 'hackorbital-submissions'
  and drive_url is null
  and storage_path like (
    team_id::text || '/' || problem_id::text || '/' || submission_phase || '/%'
  )
  and exists (
    select 1
    from public.profiles p
    join public.user_roles ur
      on ur.user_id = p.id
      and ur.role in ('team_leader'::public.app_role, 'participant'::public.app_role)
    join public.problem_statement_claims c
      on c.team_id = p.team_id and c.problem_id = team_submissions.problem_id
    join public.team_submission_sessions s
      on s.team_id = p.team_id and s.problem_id = team_submissions.problem_id
    join public.teams t on t.id = p.team_id
    join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
    where p.id = auth.uid()
      and p.is_active
      and p.team_id = team_submissions.team_id
      and (
        (
          team_submissions.submission_phase = 'phase1'
          and ec.current_phase in ('lock_open', 'phase1')
          and s.timer_started_at + interval '4 hours' > now()
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

-- Remove all earlier upload policies on Storage before installing phase-aware rules.
drop policy if exists "HackOrbital team members upload before deadline" on storage.objects;
drop policy if exists "HackOrbital team members upload within event and team timer" on storage.objects;
drop policy if exists "Team members upload within submission window" on storage.objects;
drop policy if exists "Team members upload within active submission timer" on storage.objects;
drop policy if exists "HackOrbital team members upload to private submissions" on storage.objects;

create policy "HackOrbital team members upload to private submissions"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'hackorbital-submissions'
  and exists (
    select 1
    from public.profiles p
    join public.user_roles ur
      on ur.user_id = p.id
      and ur.role in ('team_leader'::public.app_role, 'participant'::public.app_role)
    join public.problem_statement_claims c
      on c.team_id = p.team_id
      and c.problem_id::text = (storage.foldername(name))[2]
    join public.team_submission_sessions s
      on s.team_id = p.team_id and s.problem_id = c.problem_id
    join public.teams t on t.id = p.team_id
    join public.hackorbital_event_control ec on ec.id = 1 and ec.is_live
    where p.id = auth.uid()
      and p.is_active
      and p.team_id::text = (storage.foldername(name))[1]
      and (
        (
          (storage.foldername(name))[3] = 'phase1'
          and ec.current_phase in ('lock_open', 'phase1')
          and s.timer_started_at + interval '4 hours' > now()
        )
        or
        (
          (storage.foldername(name))[3] = 'phase2'
          and ec.current_phase = 'phase2'
          and t.is_qualified_phase2
          and ec.phase2_deadline_at > now()
        )
      )
  )
);

-- Permit an uploader to clean up an orphan object if its submission-record insert
-- failed. Registered submission objects are protected from this cleanup policy.
drop policy if exists "Teams remove unregistered submission uploads" on storage.objects;
create policy "Teams remove unregistered submission uploads"
on storage.objects for delete to authenticated
using (
  bucket_id = 'hackorbital-submissions'
  and exists (
    select 1
    from public.profiles p
    join public.user_roles ur
      on ur.user_id = p.id
      and ur.role in ('team_leader'::public.app_role, 'participant'::public.app_role)
    join public.problem_statement_claims c
      on c.team_id = p.team_id
      and c.problem_id::text = (storage.foldername(name))[2]
    where p.id = auth.uid()
      and p.is_active
      and p.team_id::text = (storage.foldername(name))[1]
  )
  and not exists (
    select 1
    from public.team_submissions ts
    where ts.storage_bucket = storage.objects.bucket_id
      and ts.storage_path = storage.objects.name
  )
);

notify pgrst, 'reload schema';
