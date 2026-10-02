-- ====================================================================
-- Builtbyus Studio: Step 4 Post-Deployment Migration
-- File: migrations/02_revoke_anon_direct_insert.sql
--
-- ⚠️ CAUTION: DO NOT APPLY THIS SCRIPT UNTIL:
-- 1. Netlify Function `submit-lead` is deployed.
-- 2. Real Cloudflare Turnstile keys (Site Key & Secret Key) are configured in Netlify.
-- 3. Live lead form submissions via the function have been verified end-to-end.
--
-- Once applied, direct REST API calls using the anon key can no longer insert leads.
-- Only the backend Netlify Function (using SUPABASE_SERVICE_ROLE_KEY) will have write access.
-- ====================================================================

-- 1. Drop anon insert policy
DROP POLICY IF EXISTS "Allow anonymous lead insert" ON public.project_leads;

-- 2. Revoke insert grant from anon role
REVOKE INSERT ON public.project_leads FROM anon;

-- 3. Ensure service_role has full access (bypasses RLS by default in Supabase)
GRANT ALL ON public.project_leads TO service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;
