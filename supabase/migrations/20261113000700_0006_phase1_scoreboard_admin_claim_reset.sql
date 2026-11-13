-- Phase 1 scorecard and organizer-only claim reset.
create table if not exists public.phase1_evaluations (
 id uuid primary key default gen_random_uuid(),
 team_id uuid not null references public.teams(id) on delete cascade,
 judge_id uuid not null references public.profiles(id) on delete cascade,
 solution_quality integer not null default 0 check (solution_quality between 0 and 25),
 innovation integer not null default 0 check (innovation between 0 and 20),
 technical integer not null default 0 check (technical between 0 and 15),
 feasibility integer not null default 0 check (feasibility between 0 and 15),
 relevance integer not null default 0 check (relevance between 0 and 15),
 presentation integer not null default 0 check (presentation between 0 and 10),
 total integer not null default 0 check (total between 0 and 100),
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 unique(team_id, judge_id)
);
alter table public.phase1_evaluations enable row level security;
drop policy if exists "Judges can read phase 1 evaluations" on public.phase1_evaluations;
drop policy if exists "Judges can insert phase 1 evaluations" on public.phase1_evaluations;
drop policy if exists "Judges can update phase 1 evaluations" on public.phase1_evaluations;
create policy "Judges read phase 1 evaluations" on public.phase1_evaluations
 for select to authenticated using ((public.has_role(auth.uid(),'judge') and judge_id=auth.uid()) or public.has_role(auth.uid(),'admin'));
create policy "Judges insert phase 1 evaluations" on public.phase1_evaluations
 for insert to authenticated with check ((public.has_role(auth.uid(),'judge') and judge_id=auth.uid()) or public.has_role(auth.uid(),'admin'));
create policy "Judges update phase 1 evaluations" on public.phase1_evaluations
 for update to authenticated using ((public.has_role(auth.uid(),'judge') and judge_id=auth.uid()) or public.has_role(auth.uid(),'admin'))
 with check ((public.has_role(auth.uid(),'judge') and judge_id=auth.uid()) or public.has_role(auth.uid(),'admin'));
grant select,insert,update on public.phase1_evaluations to authenticated;
grant all on public.phase1_evaluations to service_role;

create or replace function public.release_problem_statement_claim(p_team_id uuid)
returns text language plpgsql security definer set search_path=public
as $$
declare v_problem_id uuid; v_remaining_team uuid; v_remaining_time timestamptz;
begin
 if auth.uid() is null or lower(coalesce(auth.jwt()->>'email','')) <> 'prathmeshgpachling@gmail.com'
    or not public.has_role(auth.uid(),'admin') then raise exception 'FORBIDDEN'; end if;
 select problem_id into v_problem_id from public.problem_statement_claims where team_id=p_team_id;
 if v_problem_id is null then raise exception 'CLAIM_NOT_FOUND'; end if;
 delete from public.problem_statement_claims where team_id=p_team_id and problem_id=v_problem_id;
 select team_id,claimed_at into v_remaining_team,v_remaining_time from public.problem_statement_claims where problem_id=v_problem_id order by claimed_at limit 1;
 update public.problem_statements set claimed_by_team_id=v_remaining_team,claimed_at=v_remaining_time where id=v_problem_id;
 return 'RELEASED';
end $$;
revoke all on function public.release_problem_statement_claim(uuid) from public,anon;
grant execute on function public.release_problem_statement_claim(uuid) to authenticated;

-- Participant access narrows to their team's selected problem after locking.
drop policy if exists "Authenticated users read tier 1 statements" on public.problem_statements;
drop policy if exists "Users read available or their locked statement" on public.problem_statements;
create policy "Users read available or their locked statement" on public.problem_statements
 for select to authenticated using (
  public.has_role(auth.uid(),'judge') or public.has_role(auth.uid(),'admin')
  or not exists (
   select 1 from public.profiles p join public.problem_statement_claims c on c.team_id=p.team_id
   where p.id=auth.uid() and p.is_active
  )
  or exists (
   select 1 from public.profiles p join public.problem_statement_claims c on c.team_id=p.team_id
   where p.id=auth.uid() and p.is_active and c.problem_id=problem_statements.id
  )
);
