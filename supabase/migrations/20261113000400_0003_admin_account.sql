-- Make prathmeshgpachling@gmail.com the sole administrator.
-- The whitelist synchronization trigger from 0002 updates existing auth users.
insert into public.allowed_users (email, assigned_role, team_name)
values ('prathmeshgpachling@gmail.com', 'admin', null)
on conflict (email) do update
  set assigned_role = 'admin',
      team_name = null;

-- Ensure no other whitelisted account retains administrator privileges.
update public.allowed_users
set assigned_role = 'participant'
where assigned_role = 'admin'
  and email <> 'prathmeshgpachling@gmail.com';

-- Remove the former seeded organizer account from the allowlist.
delete from public.allowed_users
where email = 'organizer@hackorbital.in';
