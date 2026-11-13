-- Allow up to two teams to work on each problem statement while each team may
-- lock only one statement. The RPC is the sole write path for claims.
create table if not exists public.problem_statement_claims (
  id uuid primary key default gen_random_uuid(),
  problem_id uuid not null references public.problem_statements(id) on delete cascade,
  team_id uuid not null references public.teams(id) on delete cascade,
  claimed_at timestamptz not null default now(),
  unique (problem_id, team_id),
  unique (team_id)
);

alter table public.problem_statement_claims enable row level security;
drop policy if exists "Authenticated users read problem statement claims" on public.problem_statement_claims;
create policy "Authenticated users read problem statement claims"
  on public.problem_statement_claims for select to authenticated
  using (auth.uid() is not null);
revoke all on public.problem_statement_claims from anon, public;
grant select on public.problem_statement_claims to authenticated;
grant all on public.problem_statement_claims to service_role;

-- Migrate existing single-team locks without clearing or replacing them.
insert into public.problem_statement_claims (problem_id, team_id, claimed_at)
select id, claimed_by_team_id, coalesce(claimed_at, now())
from public.problem_statements
where claimed_by_team_id is not null
on conflict do nothing;

create index if not exists problem_statement_claims_problem_id_idx
  on public.problem_statement_claims(problem_id);

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
  v_inserted uuid;
begin
  if v_user is null then
    raise exception 'UNAUTHENTICATED';
  end if;

  -- Serialize attempts by team and by statement to prevent duplicate team locks
  -- and to guarantee that no statement receives more than two teams.
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
  values (p_problem_id, p_team_id)
  returning id into v_inserted;

  -- Keep legacy single-claim fields populated for existing integrations.
  update public.problem_statements
    set claimed_by_team_id = p_team_id, claimed_at = now()
    where id = p_problem_id and claimed_by_team_id is null;

  return 'LOCKED';
exception
  when unique_violation then
    raise exception 'ALREADY_CLAIMED';
end
$$;
revoke all on function public.lock_problem_statement(uuid, uuid) from public, anon;
grant execute on function public.lock_problem_statement(uuid, uuid) to authenticated;

-- Tier 2 is resolved by the team's claim, not the legacy single-team column.
create or replace function public.get_tier2_for_caller(p_team_id uuid)
returns table (
  problem_code text,
  tier2_constraints text,
  tier2_live_test_harness text,
  is_qualified boolean
)
language plpgsql
stable
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_code text;
  v_constraints text;
  v_harness text;
  v_qualified boolean;
  v_allowed boolean;
begin
  if v_uid is null then
    raise exception 'UNAUTHENTICATED';
  end if;

  select ps.code, ps.tier2_constraints, ps.tier2_live_test_harness, t.is_qualified_phase2
    into v_code, v_constraints, v_harness, v_qualified
  from public.problem_statement_claims c
  join public.problem_statements ps on ps.id = c.problem_id
  join public.teams t on t.id = c.team_id
  where t.id = p_team_id;

  if not found then
    return;
  end if;

  if public.has_role(v_uid, 'judge') or public.has_role(v_uid, 'admin') then
    return query select v_code, v_constraints, v_harness, v_qualified;
    return;
  end if;

  v_allowed := exists (
    select 1 from public.profiles
    where id = v_uid and team_id = p_team_id and is_active
  );
  if not v_allowed then
    raise exception 'FORBIDDEN';
  end if;

  if v_qualified then
    return query select v_code, v_constraints, v_harness, v_qualified;
  else
    return query select v_code, null::text, null::text, false;
  end if;
end
$$;
revoke all on function public.get_tier2_for_caller(uuid) from public, anon;
grant execute on function public.get_tier2_for_caller(uuid) to authenticated;

-- Keep claims available to realtime listeners.
alter publication supabase_realtime add table public.problem_statement_claims;
