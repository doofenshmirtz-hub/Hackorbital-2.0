-- Security hardening and account provisioning fixes.
-- Apply through the project's normal Supabase migration workflow.

-- Profiles: users must not be able to change identity, email, or team membership.
drop policy if exists "Users update own profile" on public.profiles;
revoke update on public.profiles from authenticated;
grant update (full_name) on public.profiles to authenticated;
create policy "Users update own display name"
  on public.profiles for update to authenticated
  using (id = auth.uid() or public.has_role(auth.uid(), 'admin'))
  with check (id = auth.uid() or public.has_role(auth.uid(), 'admin'));

alter table public.profiles
  add column if not exists is_active boolean not null default true;

-- Qualification is an organizer-only action. No authenticated client may
-- update arbitrary team columns directly.
drop policy if exists "Leaders judges admins update teams" on public.teams;
revoke update on public.teams from authenticated;

create or replace function public.set_team_qualification(
  p_team_id uuid,
  p_is_qualified boolean
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null or not public.has_role(auth.uid(), 'admin') then
    raise exception 'FORBIDDEN';
  end if;

  update public.teams
    set is_qualified_phase2 = p_is_qualified
    where id = p_team_id;

  if not found then
    raise exception 'TEAM_NOT_FOUND';
  end if;
end
$$;
revoke all on function public.set_team_qualification(uuid, boolean) from public;
grant execute on function public.set_team_qualification(uuid, boolean) to authenticated;

-- Repair any duplicate historical claims deterministically, retaining the
-- earliest claim for each team, then enforce one claim per team in the DB.
with ranked_claims as (
  select id,
         row_number() over (
           partition by claimed_by_team_id
           order by claimed_at asc nulls last, id asc
         ) as rn
  from public.problem_statements
  where claimed_by_team_id is not null
)
update public.problem_statements ps
  set claimed_by_team_id = null,
      claimed_at = null
  from ranked_claims rc
  where ps.id = rc.id and rc.rn > 1;

create unique index if not exists problem_statements_one_claim_per_team
  on public.problem_statements (claimed_by_team_id)
  where claimed_by_team_id is not null;

-- Serialize all claims for a team before checking whether it already owns one.
create or replace function public.lock_problem_statement(p_problem_id uuid, p_team_id uuid)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user uuid := auth.uid();
  v_existing uuid;
  v_claimed uuid;
begin
  if v_user is null then
    raise exception 'UNAUTHENTICATED';
  end if;

  -- Advisory transaction lock serializes requests targeting different
  -- statements for the same team. The partial unique index is a final guard.
  perform pg_advisory_xact_lock(hashtextextended(p_team_id::text, 0));

  if not exists (
    select 1
    from public.teams t
    join public.profiles p on p.id = v_user and p.is_active and p.team_id = p_team_id
    join public.user_roles ur on ur.user_id = v_user and ur.role = 'team_leader'
    where t.id = p_team_id and t.leader_user_id = v_user
  ) then
    raise exception 'NOT_TEAM_LEADER';
  end if;

  select id into v_existing
    from public.problem_statements
    where claimed_by_team_id = p_team_id
    limit 1;

  if v_existing is not null then
    if v_existing = p_problem_id then
      return 'LOCKED';
    end if;
    raise exception 'ALREADY_CLAIMED';
  end if;

  update public.problem_statements
    set claimed_by_team_id = p_team_id, claimed_at = now()
    where id = p_problem_id and claimed_by_team_id is null
    returning id into v_claimed;

  if v_claimed is null then
    raise exception 'ALREADY_TAKEN';
  end if;

  return 'LOCKED';
end
$$;
revoke all on function public.lock_problem_statement(uuid, uuid) from public;
grant execute on function public.lock_problem_statement(uuid, uuid) to authenticated;

-- Provision and synchronize an already-authenticated account when its
-- whitelist entry is added or changed. Revocation disables the profile and
-- removes app roles without deleting historical evaluations.
create or replace function public.sync_whitelisted_user(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_email text;
  v_role public.app_role;
  v_team_name text;
  v_team_id uuid;
begin
  select lower(email) into v_email
    from auth.users where id = p_user_id;

  if v_email is null then
    return;
  end if;

  select assigned_role, team_name
    into v_role, v_team_name
    from public.allowed_users where email = v_email;

  if v_role is null then
    update public.profiles
      set is_active = false, team_id = null
      where id = p_user_id;
    delete from public.user_roles where user_id = p_user_id;
    return;
  end if;

  if v_team_name is not null then
    insert into public.teams (name)
      values (v_team_name)
      on conflict (name) do nothing;

    select id into v_team_id
      from public.teams where name = v_team_name;

    if v_role = 'team_leader' then
      update public.teams
        set leader_user_id = p_user_id
        where id = v_team_id
          and (leader_user_id is null or leader_user_id = p_user_id);
    end if;
  else
    v_team_id := null;
  end if;

  insert into public.profiles (id, email, full_name, team_id, is_active)
    select p_user_id,
           v_email,
           coalesce(u.raw_user_meta_data->>'full_name',
                    u.raw_user_meta_data->>'name', ''),
           v_team_id,
           true
    from auth.users u
    where u.id = p_user_id
  on conflict (id) do update
    set email = excluded.email,
        team_id = excluded.team_id,
        is_active = true;

  delete from public.user_roles where user_id = p_user_id;
  insert into public.user_roles (user_id, role)
    values (p_user_id, v_role)
    on conflict (user_id, role) do nothing;
end
$$;
revoke all on function public.sync_whitelisted_user(uuid) from public, authenticated;

create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform public.sync_whitelisted_user(new.id);
  return new;
end
$$;

create or replace function public.handle_whitelist_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid;
begin
  -- On email changes, synchronize both accounts: the old email loses access
  -- unless independently whitelisted, and the new email gains its assigned role.
  if tg_op = 'DELETE'
     or (tg_op = 'UPDATE' and old.email is distinct from new.email) then
    select id into v_user_id from auth.users where lower(email) = lower(old.email);
    if v_user_id is not null then
      perform public.sync_whitelisted_user(v_user_id);
    end if;
  end if;

  if tg_op <> 'DELETE' then
    select id into v_user_id from auth.users where lower(email) = lower(new.email);
    if v_user_id is not null then
      perform public.sync_whitelisted_user(v_user_id);
    end if;
  end if;

  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end
$$;
revoke all on function public.handle_whitelist_change() from public, authenticated;

drop trigger if exists on_whitelist_changed on public.allowed_users;
create trigger on_whitelist_changed
  after insert or update or delete on public.allowed_users
  for each row execute function public.handle_whitelist_change();

-- Existing accounts are synchronized when the migration is applied too.
do $$
declare
  u record;
begin
  for u in select id from auth.users loop
    perform public.sync_whitelisted_user(u.id);
  end loop;
end
$$;
