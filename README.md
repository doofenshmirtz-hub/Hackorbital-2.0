# HackOrbital 2.0

Independent rebuild of the HackOrbital event platform.

## Stack
- React + TypeScript + Vite
- Supabase Auth, Postgres, Storage and Realtime
- Username/email + password sign-in only. Google OAuth and AI APIs are intentionally excluded.

## Local setup
```bash
npm install
cp .env.example .env.local
npm run dev
```

Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_PUBLISHABLE_KEY` in `.env.local`. Never expose a Supabase secret/service-role key in browser code or any `VITE_` variable.

## Current status
The first commit contains the new visual foundation, sign-in screen and role-aware workspace shell. The problem pool, phase timers, submissions, judge scoreboards and organizer controls are not yet wired to live data.

Username aliases need a secure server-side username-to-auth-account mapping before they can authenticate; Supabase's native password sign-in uses email + password. Do not store passwords in the application database.

## Next build milestones
1. Review and recreate the existing HackOrbital database schema and RLS policies.
2. Implement secure account provisioning and username/email + password sign-in.
3. Build the team and problem statement workflow, including leader-only locking and random assignment after the 60-minute window.
4. Implement the four-hour Phase 1 timer and leader-only submissions.
5. Implement organizer-controlled Phase 2, private Storage uploads and submission status.
6. Build judge scorecards and separate phase scoreboards.
7. Build organizer controls, team/user management, qualification and full reset.
8. Add audit logs, realtime updates, tests and production deployment checks.

This repository is separate from the legacy `hackorbital` repository. The old repository and its data have not been modified by this rebuild.
