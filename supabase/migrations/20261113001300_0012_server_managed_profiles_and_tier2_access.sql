-- Treat profiles as server-managed authorization data.
-- Client-created profiles must never be able to assign themselves to a team.
drop policy if exists "Users insert own profile" on public.profiles;
revoke insert, delete on table public.profiles from public, anon, authenticated;

-- Reconcile every existing auth account against the organizer-managed whitelist.
-- This also removes any stale/forged team assignments and roles left by earlier
-- profile tampering, while preserving historical teams and evaluations.
do $$
declare
  v_user record;
begin
  for v_user in select id from auth.users loop
    perform public.sync_whitelisted_user(v_user.id);
  end loop;
end
$$;

-- Tier 2 access must be based on an active, whitelisted member of the requested
-- team. Resolve the statement through problem_statement_claims so both teams
-- sharing a problem statement can retrieve their own qualification-gated details.
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
  where t.id = p_team_id
  limit 1;

  if not found then
    return;
  end if;

  if public.has_role(v_uid, 'judge') or public.has_role(v_uid, 'admin') then
    return query select v_code, v_constraints, v_harness, v_qualified;
    return;
  end if;

  select exists (
    select 1
    from public.profiles p
    join auth.users u on u.id = p.id
    join public.allowed_users au on lower(au.email) = lower(u.email)
    join public.user_roles ur
      on ur.user_id = p.id
     and ur.role in ('team_leader'::public.app_role, 'participant'::public.app_role)
    join public.teams member_team
      on member_team.id = p.team_id
     and member_team.name = au.team_name
    where p.id = v_uid
      and p.is_active
      and p.team_id = p_team_id
      and au.assigned_role::text = ur.role::text
  ) into v_allowed;

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

-- PostgreSQL grants function execution to PUBLIC by default; keep this RPC
-- available only to logged-in callers, with authorization enforced inside it.
revoke all on function public.get_tier2_for_caller(uuid) from public, anon;
grant execute on function public.get_tier2_for_caller(uuid) to authenticated;
