# 📋 Builtbyus Studio — Security Architecture & Manual Deployment Checklist

All automated code fixes, serverless functions, input validation, rate limiting, and test suites are implemented in this repository.

This checklist outlines the deployment configuration and manual Supabase dashboard operations required to match the hardened production architecture.

---

## Architecture Overview

```
Browser (Static HTML / Tailwind / GSAP)
   │
   ▼ HTTPS POST /.netlify/functions/submit-lead
Netlify CDN Edge (Authoritative IP: x-nf-client-connection-ip, Strict CSP)
   │
   ▼
Netlify Serverless Function (Node.js runtime)
   ├─► 1. HTTP Method Gate (POST only)
   ├─► 2. Strict Service Role Key Check (fails 500 if missing)
   ├─► 3. Upstash Redis Sliding-Window Rate Limiter (5 requests / 10 min window per IP)
   ├─► 4. Anti-Bot Honeypot Trap (botTrap & website_url silent drop)
   ├─► 5. Zod Strict Schema Validation (name, email, phone, budget, timeline, message)
   ├─► 6. Cloudflare Turnstile Server-to-Server Siteverify (fails 403 on invalid token)
   │
   ▼ Direct REST API via SUPABASE_SERVICE_ROLE_KEY exclusively (Bypasses RLS)
Supabase PostgreSQL Database
   ├─► Row Level Security (RLS) ENABLED (ZERO public policies)
   ├─► Permissions: REVOKE ALL from anon, authenticated; GRANT to service_role
   ├─► Trigger: enforce_lead_defaults() (forces status='new' and created_at=NOW())
   └─► CHECK Constraints: status, budget, timeline, name, email, phone, details
```

> **CRITICAL SECURITY GUARANTEE:**
> The browser has **ZERO** direct database read or write access. No Supabase publishable or service role keys exist in the frontend bundle. All writes flow strictly through the serverless function.

---

## 1. Cloudflare Turnstile Setup

Obtain your bot-protection keys from Cloudflare:

1. Log into the **[Cloudflare Dashboard](https://dash.cloudflare.com/)** ➔ Select **Turnstile** from the sidebar.
2. Click **Add Site**.
3. Fill in details:
   - **Site name:** `Builtbyus Studio`
   - **Domain:** `builtbyus.dev` (also add `localhost` for local dev)
   - **Widget Mode:** Managed
4. Copy your **Site Key** and **Secret Key**.
5. In `index.html`, replace the test key `1x00000000000000000000AA` with your real **Site Key**:
   ```html
   <div id="cf-turnstile-container" class="cf-turnstile" data-sitekey="YOUR_PRODUCTION_SITE_KEY" data-theme="light"></div>
   ```

---

## 2. Netlify Environment Variables Configuration

Set these environment variables in your Netlify dashboard (**Site configuration** ➔ **Environment variables**):

| Variable Name | Required | Description |
| :--- | :--- | :--- |
| `SUPABASE_URL` | **YES** | `https://nirtydxacoujcbrbztyo.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | **YES** | Secret key from Supabase Dashboard (Project Settings ➔ API ➔ `service_role` secret). Function returns 500 if missing. |
| `TURNSTILE_SITE_KEY` | **YES** | Your Cloudflare Turnstile Site Key |
| `TURNSTILE_SECRET_KEY` | **YES** | Your Cloudflare Turnstile Secret Key (used server-side for siteverify) |
| `UPSTASH_REDIS_REST_URL` | **YES** | Free Redis database URL from [upstash.com](https://upstash.com) for durable sliding-window rate limiting |
| `UPSTASH_REDIS_REST_TOKEN` | **YES** | Upstash Redis REST access token |

---

## 3. Database Schema Application (Supabase SQL Editor)

Run the consolidated schema script in your Supabase Project (**SQL Editor** ➔ **New Query**):

1. Copy and paste the entire contents of `supabase-schema.sql` (or `migrations/01_harden_project_leads.sql`).
2. Click **Run**.
3. **What this enforces:**
   - Table `public.project_leads` created with integrity defaults.
   - `CHECK` constraints on status (`new`, `contacted`, `qualified`, `converted`, `archived`), budget, timeline, name (1–100 chars), phone (7–30 chars), email (regex), and message/details (≤2000 chars).
   - `BEFORE INSERT` trigger forcing `status = 'new'`, `created_at = NOW()`, trimmed strings, and lowercased email.
   - `ALTER TABLE public.project_leads ENABLE ROW LEVEL SECURITY;`
   - Drops all public/anon insert, read, and update policies. **Zero public policies exist.**
   - `REVOKE ALL ON public.project_leads FROM anon, authenticated;`
   - `GRANT ALL ON public.project_leads TO service_role;`

---

## 4. Post-Deployment Migration (If Table Already Existed with Anon Policies)

If your database previously had an `Allow anonymous lead insert` policy, run `migrations/02_revoke_anon_direct_insert.sql` to permanently revoke it:

```sql
DROP POLICY IF EXISTS "Allow anonymous lead insert" ON public.project_leads;
DROP POLICY IF EXISTS "Allow anonymous lead submission" ON public.project_leads;

REVOKE ALL ON public.project_leads FROM anon, authenticated;
REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;

GRANT ALL ON public.project_leads TO service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;
```

---

## 5. Clean Up Audit Test Rows

Delete any junk test records inserted during the earlier security audit:

1. In Supabase Dashboard, click **SQL Editor** ➔ **New query**.
2. Run `cleanup.sql`:
   ```sql
   DELETE FROM public.project_leads
   WHERE name = 'Security Test Auditor'
      OR name LIKE '''; DROP TABLE%'
      OR LENGTH(name) > 1000
      OR email = 'audit@security.test';
   ```

---

## 6. Supabase Authentication Hardening

Since Builtbyus Studio does not require customer login:

1. In Supabase Dashboard, click **Authentication** (padlock icon).
2. Under **Configuration** ➔ **Providers** ➔ **Email**:
   - Toggle **"Allow new users to sign up"** to **OFF** (prevents open user creation).
3. Under **Attack Protection**:
   - Toggle **"Enable leaked password protection"** to **ON**.
4. Click **Save**.

---

## 7. Account Security (2FA)

Ensure Two-Factor Authentication (2FA) is enabled on:
- **Supabase Account:** Avatar ➔ Account ➔ Security ➔ 2FA.
- **GitHub Account:** Settings ➔ Password & authentication ➔ 2FA.
- **Netlify Account:** User Settings ➔ Security ➔ 2FA.
