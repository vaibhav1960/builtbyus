-- ====================================================================
-- Builtbyus Studio: Step 4 Post-Deployment Migration
-- File: migrations/02_revoke_anon_direct_insert.sql
--
-- Run this migration in Supabase SQL Editor to revoke all direct
-- insert permissions from the anonymous client role.
--
-- Result:
-- Direct REST API calls using the anon key can no longer insert leads.
-- Only the backend Netlify Function (using SUPABASE_SERVICE_ROLE_KEY) has write access.
-- ====================================================================

-- 1. Drop anon insert policy
DROP POLICY IF EXISTS "Allow anonymous lead insert" ON public.project_leads;
DROP POLICY IF EXISTS "Allow anonymous lead submission" ON public.project_leads;

-- 2. Revoke all table-level and sequence access from public roles
REVOKE ALL ON public.project_leads FROM anon, authenticated;
REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;

-- 3. Ensure service_role has full access (bypasses RLS by default in Supabase)
GRANT ALL ON public.project_leads TO service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;
