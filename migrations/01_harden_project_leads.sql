-- ====================================================================
-- Builtbyus Studio: Step 3 Migration - Database & RLS Hardening
-- File: migrations/01_harden_project_leads.sql
-- Run this script in Supabase Project: SQL Editor -> New Query
-- ====================================================================

-- 1. Ensure Table Structure & Defaults
CREATE TABLE IF NOT EXISTS public.project_leads (
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  email TEXT,
  services TEXT,
  details TEXT,
  status TEXT DEFAULT 'new' NOT NULL
);

-- Force column defaults
ALTER TABLE public.project_leads ALTER COLUMN status SET DEFAULT 'new';
ALTER TABLE public.project_leads ALTER COLUMN created_at SET DEFAULT NOW();

-- 2. Add Strict DB-Level CHECK Constraints
-- Status check
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_status;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_status
  CHECK (status IN ('new', 'contacted', 'closed', 'archived'));

-- Name: trimmed 2 to 100 characters
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_name;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_name
  CHECK (length(trim(name)) >= 2 AND length(trim(name)) <= 100);

-- Phone: trimmed 7 to 30 characters
ALTER TABLE public.project_leads DROP CONSTRAINT IF EXISTS chk_project_leads_phone;
ALTER TABLE public.project_leads ADD CONSTRAINT chk_project_leads_phone
  CHECK (length(trim(phone)) >= 7 AND length(trim(phone)) <= 30);

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

-- 3. BEFORE INSERT Trigger: Enforce status = 'new' and created_at = NOW()
-- Guarantees that callers cannot spoof status or created_at timestamps
CREATE OR REPLACE FUNCTION public.enforce_lead_defaults()
RETURNS TRIGGER AS $$
BEGIN
  NEW.status := 'new';
  NEW.created_at := NOW();
  NEW.name := trim(NEW.name);
  NEW.phone := trim(NEW.phone);
  IF NEW.email IS NOT NULL THEN
    NEW.email := trim(NEW.email);
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

-- Anon INSERT policy (validated against CHECK constraints and trigger)
CREATE POLICY "Allow anonymous lead insert"
ON public.project_leads
FOR INSERT
TO anon
WITH CHECK (true);

-- No SELECT, UPDATE, or DELETE policies are granted to 'anon' or 'authenticated'.
-- Supabase Dashboard administrators view/manage records via service_role/superuser which bypasses RLS.
-- This ensures open public signup CANNOT expose customer leads to other registered users.

-- 5. Strict Column-Level Grants
-- Revoke all table-level access from public roles
REVOKE ALL ON public.project_leads FROM anon, authenticated;

-- Grant INSERT ONLY on customer-submitted columns to 'anon'
GRANT INSERT (name, phone, email, services, details) ON public.project_leads TO anon;

-- Ensure sequence access for identity column
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon;

-- 6. Performance Index
CREATE INDEX IF NOT EXISTS idx_project_leads_created_at ON public.project_leads (created_at DESC);
