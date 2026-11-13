ALTER FUNCTION public.sync_whitelisted_user(uuid) SET search_path = public, pg_temp;

DROP POLICY IF EXISTS "Authenticated users read event status" ON public.hackorbital_event_control;
CREATE POLICY "Active members read event status" ON public.hackorbital_event_control
FOR SELECT TO authenticated
USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.is_active));

DROP POLICY IF EXISTS "Authenticated users read problem statement claims" ON public.problem_statement_claims;
CREATE POLICY "Active members read problem statement claims" ON public.problem_statement_claims
FOR SELECT TO authenticated
USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND p.is_active));

NOTIFY pgrst, 'reload schema';