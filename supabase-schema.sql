-- ====================================================================
-- Builtbyus Studio: Supabase Database Schema for Leads (Hardened)
-- Run this script in your Supabase Project: SQL Editor -> New Query
--
-- Security Architecture:
-- 1. Netlify Serverless Function uses SUPABASE_SERVICE_ROLE_KEY exclusively.
-- 2. Direct client-side (anon / authenticated) database writes are completely revoked.
-- 3. Row Level Security (RLS) is ENABLED with ZERO public policies.
-- 4. In PostgreSQL, service_role bypasses RLS by default.
-- ====================================================================

-- 1. Create the `project_leads` table
CREATE TABLE IF NOT EXISTS public.project_leads (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  services TEXT,
  details TEXT,
  message TEXT,
  budget TEXT,
  timeline TEXT,
  status TEXT DEFAULT 'new' NOT NULL
);

-- Force column defaults
ALTER TABLE public.project_leads ALTER COLUMN status SET DEFAULT 'new';
ALTER TABLE public.project_leads ALTER COLUMN created_at SET DEFAULT NOW();

-- 2. Add Strict DB-Level CHECK Constraints
-- Status check: strictly 'new', 'contacted', 'qualified', 'converted', 'archived'
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_status;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_status
  CHECK (status IN ('new', 'contacted', 'qualified', 'converted', 'archived'));

-- Budget check matching allowed budget options
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_budget;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_budget
  CHECK (budget IS NULL OR budget IN ('Under $5,000', '$5,000 - $10,000', '$10,000 - $25,000', '$25,000+'));

-- Timeline check matching allowed timeline options
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_timeline;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_timeline
  CHECK (timeline IS NULL OR timeline IN ('ASAP', '1-3 months', '3-6 months', 'Flexible'));

-- Name: trimmed 1 to 100 characters
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_name;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_name
  CHECK (length(trim(name)) >= 1 AND length(trim(name)) <= 100);

-- Phone: optional, trimmed 7 to 30 characters
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_phone;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_phone
  CHECK (phone IS NULL OR (length(trim(phone)) >= 7 AND length(trim(phone)) <= 30));

-- Email: optional, max 255 chars, standard email format regex
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_email;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_email
  CHECK (email IS NULL OR (length(trim(email)) <= 255 AND email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'));

-- Services: optional, max 200 characters
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_services;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_services
  CHECK (services IS NULL OR length(services) <= 200);

-- Details: optional, max 2000 characters
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_details;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_details
  CHECK (details IS NULL OR length(details) <= 2000);

-- Message: optional, max 2000 characters
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_message;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_message
  CHECK (message IS NULL OR length(message) <= 2000);

-- 3. BEFORE INSERT Trigger: Enforce status = 'new' and created_at = NOW()
-- Guarantees that callers cannot spoof status or created_at timestamps
CREATE OR REPLACE FUNCTION public.enforce_lead_defaults()
RETURNS TRIGGER AS $$
BEGIN
  NEW.status := 'new';
  NEW.created_at := NOW();
  NEW.name := trim(NEW.name);
  IF NEW.phone IS NOT NULL THEN
    NEW.phone := trim(NEW.phone);
  END IF;
  IF NEW.email IS NOT NULL THEN
    NEW.email := lower(trim(NEW.email));
  END IF;
  IF NEW.details IS NOT NULL THEN
    NEW.details := trim(NEW.details);
  END IF;
  IF NEW.message IS NOT NULL THEN
    NEW.message := trim(NEW.message);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS trg_enforce_lead_defaults ON public.project_leads;
CREATE TRIGGER trg_enforce_lead_defaults
BEFORE INSERT ON public.project_leads
FOR EACH ROW
EXECUTE FUNCTION public.enforce_lead_defaults();

-- 4. Row Level Security (RLS) Configuration
ALTER TABLE public.project_leads ENABLE ROW LEVEL SECURITY;

-- Drop legacy / insecure policies
DROP POLICY IF EXISTS "Allow anonymous lead submission" ON public.project_leads;
DROP POLICY IF EXISTS "Allow authenticated admin read" ON public.project_leads;
DROP POLICY IF EXISTS "Allow authenticated admin update" ON public.project_leads;
DROP POLICY IF EXISTS "Allow authenticated users to read leads" ON public.project_leads;
DROP POLICY IF EXISTS "Allow authenticated users to update leads" ON public.project_leads;
DROP POLICY IF EXISTS "Allow anonymous lead insert" ON public.project_leads;

-- ZERO public policies exist.
-- Neither 'anon' nor 'authenticated' has any SELECT, INSERT, UPDATE, or DELETE policy.
-- The Netlify serverless function accesses the database exclusively via service_role,
-- which bypasses RLS in PostgreSQL. This ensures zero client write or read access.

-- 5. Revoke Public Permissions & Grant Exclusively to service_role
REVOKE ALL ON public.project_leads FROM anon, authenticated;
REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;

GRANT ALL ON public.project_leads TO service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;

-- 6. Performance Index
CREATE INDEX IF NOT EXISTS idx_project_leads_created_at ON public.project_leads (created_at DESC);
