-- ============ HackOrbital 2026 core schema ============

create type public.app_role as enum ('team_leader', 'participant', 'judge', 'admin');

-- ---------- Whitelist ----------
create table public.allowed_users (
  email text primary key check (email = lower(email)),
  assigned_role public.app_role not null,
  team_name text,
  created_at timestamptz not null default now()
);

-- ---------- Profiles ----------
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text,
  team_id uuid,
  created_at timestamptz not null default now()
);

-- ---------- Teams ----------
create table public.teams (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  leader_user_id uuid references public.profiles(id) on delete set null,
  is_qualified_phase2 boolean not null default false,
  created_at timestamptz not null default now()
);

-- ---------- Problem statements ----------
create table public.problem_statements (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  track text not null,
  domain text not null,
  title text not null,
  phase1_friction text not null,
  phase1_challenge text not null,
  datasets text[] not null default '{}',
  tier2_constraints text not null,
  tier2_live_test_harness text not null,
  claimed_by_team_id uuid references public.teams(id) on delete set null,
  claimed_at timestamptz
);

-- ---------- Lightweight realtime mirror of claim state ----------
create table public.ps_claim_events (
  problem_id uuid primary key references public.problem_statements(id) on delete cascade,
  code text not null,
  claimed_by_team_id uuid,
  team_name text,
  claimed_at timestamptz
);

-- ---------- Evaluations ----------
create table public.evaluations (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.teams(id) on delete cascade,
  judge_id uuid not null references public.profiles(id) on delete cascade,
  innovation integer not null default 0 check (innovation between 0 and 25),
  technical integer not null default 0 check (technical between 0 and 20),
  feasibility integer not null default 0 check (feasibility between 0 and 15),
  relevance integer not null default 0 check (relevance between 0 and 15),
  presentation integer not null default 0 check (presentation between 0 and 15),
  uiux integer not null default 0 check (uiux between 0 and 10),
  total integer not null default 0,
  qualifies boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (team_id, judge_id)
);

-- ---------- Roles (kept separate from profiles) ----------
create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  role public.app_role not null,
  unique (user_id, role)
);

-- ============ GRANTS ============
GRANT SELECT, INSERT, UPDATE, DELETE ON public.allowed_users TO authenticated;
GRANT ALL ON public.allowed_users TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.teams TO authenticated;
GRANT ALL ON public.teams TO service_role;
GRANT SELECT (id, code, track, domain, title, phase1_friction, phase1_challenge, datasets, claimed_by_team_id, claimed_at) ON public.problem_statements TO authenticated;
GRANT ALL ON public.problem_statements TO service_role;
GRANT SELECT ON public.ps_claim_events TO authenticated;
GRANT ALL ON public.ps_claim_events TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.evaluations TO authenticated;
GRANT ALL ON public.evaluations TO service_role;
GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;

-- ============ RLS ============
alter table public.allowed_users enable row level security;
alter table public.profiles enable row level security;
alter table public.teams enable row level security;
alter table public.problem_statements enable row level security;
alter table public.ps_claim_events enable row level security;
alter table public.evaluations enable row level security;
alter table public.user_roles enable row level security;

-- has_role: security definer to avoid recursive RLS on user_roles
create or replace function public.has_role(_user_id uuid, _role public.app_role)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.user_roles
    where user_id = _user_id and role = _role
  )
$$;

-- ---------- Policies ----------
create policy "Admins manage the whitelist"
  on public.allowed_users for all to authenticated
  using (public.has_role(auth.uid(), 'admin'))
  with check (public.has_role(auth.uid(), 'admin'));

create policy "Users read own profile"
  on public.profiles for select to authenticated
  using (id = auth.uid() or public.has_role(auth.uid(), 'admin') or public.has_role(auth.uid(), 'judge'));
create policy "Users insert own profile"
  on public.profiles for insert to authenticated
  with check (id = auth.uid());
create policy "Users update own profile"
  on public.profiles for update to authenticated
  using (id = auth.uid() or public.has_role(auth.uid(), 'admin'))
  with check (id = auth.uid() or public.has_role(auth.uid(), 'admin'));

create policy "Users read own roles"
  on public.user_roles for select to authenticated
  using (user_id = auth.uid() or public.has_role(auth.uid(), 'admin'));
create policy "Admins manage roles"
  on public.user_roles for all to authenticated
  using (public.has_role(auth.uid(), 'admin'))
  with check (public.has_role(auth.uid(), 'admin'));

create policy "Authenticated users read teams"
  on public.teams for select to authenticated
  using (true);
create policy "Admins insert teams"
  on public.teams for insert to authenticated
  with check (public.has_role(auth.uid(), 'admin'));
create policy "Leaders judges admins update teams"
  on public.teams for update to authenticated
  using (leader_user_id = auth.uid() or public.has_role(auth.uid(), 'judge') or public.has_role(auth.uid(), 'admin'))
  with check (leader_user_id = auth.uid() or public.has_role(auth.uid(), 'judge') or public.has_role(auth.uid(), 'admin'));
create policy "Admins delete teams"
  on public.teams for delete to authenticated
  using (public.has_role(auth.uid(), 'admin'));

create policy "Authenticated users read tier 1 statements"
  on public.problem_statements for select to authenticated
  using (true);
create policy "Admins update statements"
  on public.problem_statements for update to authenticated
  using (public.has_role(auth.uid(), 'admin'))
  with check (public.has_role(auth.uid(), 'admin'));

create policy "Authenticated users read claim events"
  on public.ps_claim_events for select to authenticated
  using (true);

create policy "Team members judges admins read evaluations"
  on public.evaluations for select to authenticated
  using (
    public.has_role(auth.uid(), 'judge') or public.has_role(auth.uid(), 'admin')
    or exists (select 1 from public.profiles p where p.id = auth.uid() and p.team_id = evaluations.team_id)
  );
create policy "Judges admins write evaluations"
  on public.evaluations for insert to authenticated
  with check ((public.has_role(auth.uid(), 'judge') and judge_id = auth.uid()) or public.has_role(auth.uid(), 'admin'));
create policy "Judges admins update evaluations"
  on public.evaluations for update to authenticated
  using ((public.has_role(auth.uid(), 'judge') and judge_id = auth.uid()) or public.has_role(auth.uid(), 'admin'))
  with check ((public.has_role(auth.uid(), 'judge') and judge_id = auth.uid()) or public.has_role(auth.uid(), 'admin'));
create policy "Admins delete evaluations"
  on public.evaluations for delete to authenticated
  using (public.has_role(auth.uid(), 'admin'));

-- ============ RPC: atomic FCFS problem statement lock ============
create or replace function public.lock_problem_statement(p_problem_id uuid, p_team_id uuid)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user uuid := auth.uid();
  v_team uuid;
  v_existing uuid;
  v_claimed uuid;
begin
  if v_user is null then
    raise exception 'UNAUTHENTICATED';
  end if;

  -- Only the team leader of exactly this team may lock
  select id into v_team from public.teams where id = p_team_id and leader_user_id = v_user;
  if v_team is null then
    raise exception 'NOT_TEAM_LEADER';
  end if;

  -- A team cannot hold more than one problem statement
  select id into v_existing from public.problem_statements where claimed_by_team_id = p_team_id limit 1;
  if v_existing is not null and v_existing <> p_problem_id then
    raise exception 'ALREADY_CLAIMED';
  end if;

  -- Atomic FCFS claim: row lock serialises concurrent attempts
  update public.problem_statements
    set claimed_by_team_id = p_team_id, claimed_at = now()
    where id = p_problem_id and claimed_by_team_id is null
    returning id into v_claimed;

  if v_claimed is null then
    raise exception 'ALREADY_TAKEN';
  end if;

  return 'LOCKED';
end $$;

GRANT EXECUTE ON FUNCTION public.lock_problem_statement(uuid, uuid) TO authenticated;

-- ============ RPC: Tier 2 access (qualified teams, judges, admins only) ============
create or replace function public.get_tier2_for_caller(p_team_id uuid)
returns table (problem_code text, tier2_constraints text, tier2_live_test_harness text, is_qualified boolean)
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
  from public.problem_statements ps
  join public.teams t on t.id = ps.claimed_by_team_id
  where t.id = p_team_id;

  if not found then
    return;
  end if;

  if public.has_role(v_uid, 'judge') or public.has_role(v_uid, 'admin') then
    return query select v_code, v_constraints, v_harness, v_qualified;
    return;
  end if;

  v_allowed := exists (select 1 from public.profiles where id = v_uid and team_id = p_team_id);
  if not v_allowed then
    raise exception 'FORBIDDEN';
  end if;

  if v_qualified then
    return query select v_code, v_constraints, v_harness, v_qualified;
  else
    return query select v_code, null::text, null::text, false;
  end if;
end $$;

GRANT EXECUTE ON FUNCTION public.get_tier2_for_caller(uuid) TO authenticated;

-- ============ Triggers ============

-- Keep ps_claim_events in sync for realtime broadcast (no tier 2 leakage)
create or replace function public.sync_ps_claim_event()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_team_name text;
begin
  if new.claimed_by_team_id is not null then
    select name into v_team_name from public.teams where id = new.claimed_by_team_id;
  end if;
  insert into public.ps_claim_events (problem_id, code, claimed_by_team_id, team_name, claimed_at)
  values (new.id, new.code, new.claimed_by_team_id, v_team_name, new.claimed_at)
  on conflict (problem_id) do update
    set claimed_by_team_id = excluded.claimed_by_team_id,
        team_name = excluded.team_name,
        claimed_at = excluded.claimed_at;
  return new;
end $$;

create trigger on_ps_claim_changed
  after insert or update of claimed_by_team_id, claimed_at on public.problem_statements
  for each row execute function public.sync_ps_claim_event();

-- Auto-provision whitelisted users on first sign-in: profile + synced role + team link
create or replace function public.handle_new_auth_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_email text := lower(new.email);
  v_role public.app_role;
  v_team_name text;
  v_team_id uuid;
begin
  select assigned_role, team_name into v_role, v_team_name from public.allowed_users where email = v_email;

  if v_role is null then
    -- Not on the whitelist: no profile is created; the app denies access post-login.
    return new;
  end if;

  insert into public.profiles (id, email, full_name)
  values (
    new.id,
    v_email,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', '')
  )
  on conflict (id) do nothing;

  insert into public.user_roles (user_id, role) values (new.id, v_role)
  on conflict (user_id, role) do nothing;

  if v_team_name is not null then
    select id into v_team_id from public.teams where name = v_team_name;
    if v_team_id is null then
      insert into public.teams (name) values (v_team_name) returning id into v_team_id;
    end if;
    if v_role = 'team_leader' then
      update public.teams set leader_user_id = new.id where id = v_team_id and leader_user_id is null;
    end if;
    update public.profiles set team_id = v_team_id where id = new.id and team_id is null;
  end if;

  return new;
end $$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_auth_user();

-- ============ Realtime ============
alter publication supabase_realtime add table public.ps_claim_events;
alter publication supabase_realtime add table public.teams;

-- ============ Seed data ============
insert into public.allowed_users (email, assigned_role, team_name) values
  ('organizer@hackorbital.in', 'admin', null),
  ('judge.one@hackorbital.in', 'judge', null),
  ('leader.aurora@hackorbital.in', 'team_leader', 'Aurora'),
  ('leader.vector@hackorbital.in', 'team_leader', 'Vector')
on conflict (email) do nothing;

insert into public.teams (name) values ('Aurora'), ('Vector')
on conflict (name) do nothing;

insert into public.problem_statements
  (code, track, domain, title, phase1_friction, phase1_challenge, datasets, tier2_constraints, tier2_live_test_harness)
values
  ('PS 1.1', 'Technology & Innovation', 'AI', 'Burnout Detection',
   'Remote teams have no reliable early signal for burnout: surveys are self-reported, infrequent, and arrive after the damage is done.',
   'Build a privacy-preserving system that detects early burnout risk in distributed teams from voluntary, consented behavioural signals.',
   array['Anonymised pulse-survey sample set', 'Synthetic calendar/activity signal generator'],
   'End-to-end inference under 100ms p95 on CPU-only hardware; model footprint <= 25MB; no cloud calls at inference time; explicit consent flow required; false-positive rate < 8% on the held-out validation cohort.',
   'Live bench: 48-hour rolling signal stream with injected burnout patterns, adversarial consent-violation probes, and a dynamic threshold sweep scoring recall at fixed precision >= 0.85.'),

  ('PS 3.1', 'Technology & Innovation', 'Robotics', 'Space Debris Capture',
   'Over 36,000 tracked debris objects orbit Earth; current capture missions depend on manual teleoperation with seconds-long latency.',
   'Design a closed-loop autonomy pipeline for a capture end-effector to intercept tumbling debris objects without ground-in-the-loop control.',
   array['Tumbling-object trajectory simulator', 'Synthetic LEO rendezvous frames'],
   'Pose estimation and trajectory planning under 100ms p95 per frame on CPU-only simulation; model/asset footprint <= 25MB; zero ground-station interventions during the demo run; capture success across 3 tumble rates.',
   'Live bench: hardware-in-the-loop tumbling target rig with unseen spin profiles, occlusion stress cases, and a scoring harness penalising each intervention by 15 points.'),

  ('PS 7.1', 'Technology & Innovation', 'Blockchain', 'Cross-Chain ZK Relay',
   'Bridging assets across chains today forces users to reveal transaction graphs and trust centralized custodians, adding minutes of latency.',
   'Build a zero-knowledge relay that proves a locked asset on a source chain to a destination chain without exposing user identities or amounts.',
   array['Public testnet fork snapshots', 'Anonymised bridge latency traces'],
   'Proof generation under 100ms p95 amortised on CPU-only nodes; circuit artefact <= 25MB; relay finality under 30 seconds; no trusted central signer; resistant to replay and re-org attacks in the stress harness.',
   'Live bench: dynamic adversarial relayer injecting re-orgs and replay attempts, with a latency ceiling enforced per epoch and a parameter sweep on circuit depth.'),

  ('PS 9.2', 'Agriculture & Rural Development', 'AgriTech', 'Mandi Price Advisory',
   'Smallholder farmers sell within hours of harvest based on yesterday''s prices, routinely losing 15-30% to information asymmetry.',
   'Build an offline-first advisory that forecasts short-horizon mandi prices and recommends when and where to sell, in local language.',
   array['AGMARKNET historical mandi prices', 'District-level rainfall normals'],
   'Forecast generation under 100ms p95 on CPU-only devices; model footprint <= 25MB; works with 24h network gaps; MAPE <= 12% on held-out seasons; advisory output in <= 2 languages beyond English.',
   'Live bench: rolling backtest across 4 unseen mandis with injected price shocks, a latency cap per forecast, and a dynamic language-coverage stress test.'),

  ('PS 10.1', 'Health, Environment & Sustainability', 'ClimateTech', 'Wildfire Prediction',
   'Fire departments still dispatch on yesterday''s risk maps; spotting fires early enough needs minute-scale updates over vast terrain.',
   'Build a system that fuses satellite, weather, and terrain feeds to produce minute-scale wildfire risk and spread forecasts for dispatch teams.',
   array['MODIS active fire archive', 'ERA5 reanalysis extracts', 'SRTM terrain tiles'],
   'Risk field update under 100ms p95 on CPU-only compute; model footprint <= 25MB; 6-hour lead-time AUC >= 0.80; degrade gracefully to the last known-good forecast on feed outages.',
   'Live bench: held-out fire seasons with unseen terrain, feed-drop chaos tests, and a dynamic ensemble-weight sweep scored on early-detection lead time.'),

  ('PS S.1', 'Autonomous Drone Swarms', 'Drone Swarms', 'Drone Swarm First Response',
   'Disaster first response loses its critical first hour to manual survey: teams cannot map, prioritise, and route survivors quickly enough.',
   'Build a decentralised swarm control stack that surveys a disaster grid, detects survivors, and routes rescue assets without central coordination.',
   array['Simulated urban disaster grid', 'Survivor-detection sensor sample set'],
   'Each agent''s planning loop under 100ms p95 on CPU-only simulation; per-agent model footprint <= 25MB; swarm degrades gracefully with 30% agent loss; no single point of coordination; zero out-of-bounds violations in the stress run.',
   'Live bench: dynamic stress harness mutating the disaster grid mid-run, injecting agent failures, and sweeping swarm sizes from 8 to 32 agents with a comm-blackout phase.')
on conflict (code) do nothing;

update public.problem_statements set claimed_by_team_id = null where claimed_by_team_id is not null and claimed_at > now();
