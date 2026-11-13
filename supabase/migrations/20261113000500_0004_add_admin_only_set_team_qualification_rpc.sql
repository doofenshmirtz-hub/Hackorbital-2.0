create or replace function public.set_team_qualification(p_team_id uuid, p_is_qualified boolean)
returns void
language plpgsql
security definer
set search_path to 'public'
as $$
declare
  v_user uuid := auth.uid();
begin
  if v_user is null then
    raise exception 'UNAUTHENTICATED';
  end if;

  if not public.has_role(v_user, 'admin') then
    raise exception 'FORBIDDEN';
  end if;

  update public.teams
    set is_qualified_phase2 = p_is_qualified
    where id = p_team_id;
end $$;

revoke execute on function public.set_team_qualification(uuid, boolean) from anon, public;
grant execute on function public.set_team_qualification(uuid, boolean) to authenticated;
grant execute on function public.set_team_qualification(uuid, boolean) to service_role;