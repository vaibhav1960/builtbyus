-- ====================================================================
-- Builtbyus Studio: Step 1 - Clean Up Test Data in Production
-- Run this script in your Supabase Project: SQL Editor -> New Query
-- ====================================================================

-- 1. PREVIEW MATCHING TEST ROWS (Check row count and records before deleting)
SELECT id, created_at, name, phone, email, status
FROM public.project_leads
WHERE name = 'Security Test Auditor'
   OR name LIKE '''; DROP TABLE%'
   OR LENGTH(name) > 1000
   OR email = 'audit@security.test';

-- 2. DELETE ONLY THE MATCHING TEST ROWS (Safe & Targeted)
DELETE FROM public.project_leads
WHERE name = 'Security Test Auditor'
   OR name LIKE '''; DROP TABLE%'
   OR LENGTH(name) > 1000
   OR email = 'audit@security.test';

-- 3. VERIFY DELETION (Should return 0 rows)
SELECT COUNT(*) AS remaining_test_rows
FROM public.project_leads
WHERE name = 'Security Test Auditor'
   OR name LIKE '''; DROP TABLE%'
   OR LENGTH(name) > 1000
   OR email = 'audit@security.test';
