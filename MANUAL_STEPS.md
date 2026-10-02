# 📋 Manual Security Checklist & Dashboard Action Items

Follow this checklist in the **exact order** below. All automated code changes, input validation, serverless functions, security headers, and tests have already been implemented and verified locally.

---

## 1. Cloudflare Turnstile Keys (Step 1)
Obtain your bot-protection keys from Cloudflare:

1. Log into the **[Cloudflare Dashboard](https://dash.cloudflare.com/)** ➔ Select **Turnstile** from the sidebar.
2. Click **Add Site**.
3. Fill in the site details:
   - **Site name:** `Builtbyus Studio`
   - **Domain:** `builtbyus.dev` (also add `localhost` for local dev testing)
   - **Widget Mode:** Managed (interactive challenge only when suspicious)
4. Click **Create**.
5. Copy your **Site Key** and **Secret Key**.
6. In `index.html`, replace the test key `1x00000000000000000000AA` with your real **Site Key**:
   ```html
   <div id="cf-turnstile-container" class="cf-turnstile" data-sitekey="YOUR_PRODUCTION_SITE_KEY" data-theme="light"></div>
   ```

---

## 2. Netlify Environment Variables (Step 2)
Add your private backend keys to Netlify so your serverless functions can connect to Supabase, verify Turnstile, and apply durable rate limiting:

1. Go to the **[Netlify Dashboard](https://app.netlify.com/)** ➔ Select your site (`builtbyus`).
2. Click **Site configuration** in the sidebar ➔ Click **Environment variables**.
3. Click **Add a variable** (or **Import from .env**) and set the following:

| Variable Name | Value / Instructions |
| :--- | :--- |
| `SUPABASE_URL` | `https://nirtydxacoujcbrbztyo.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | *(From Supabase: Project Settings ➔ API ➔ Project API keys ➔ `service_role` secret)* |
| `TURNSTILE_SITE_KEY` | *(Your Cloudflare Turnstile Site Key from Step 1)* |
| `TURNSTILE_SECRET_KEY` | *(Your Cloudflare Turnstile Secret Key from Step 1)* |
| `UPSTASH_REDIS_REST_URL` | *(Optional but recommended: Free Redis at [upstash.com](https://upstash.com) for durable IP rate limiting across serverless instances)* |
| `UPSTASH_REDIS_REST_TOKEN` | *(Your Upstash Redis REST Token)* |

---

## 3. Apply Migration 01: Database Hardening (Step 3)
Enforce database-level check constraints, defaults trigger, and column-level grants:

1. Go to the **[Supabase Dashboard](https://supabase.com/dashboard)** ➔ Select your project (`nirtydxacoujcbrbztyo`).
2. Click **SQL Editor** in the left sidebar ➔ Click **New query**.
3. Copy and paste the entire contents of `migrations/01_harden_project_leads.sql` into the editor:
4. Click **Run**.
5. **What this enforces:**
   - Adds `CHECK` constraints on `name` (2–100 chars), `phone` (7–30 chars), `email` (valid regex), `services` (≤200 chars), and `details` (≤2000 chars).
   - Installs `BEFORE INSERT` trigger forcing `status = 'new'` and `created_at = NOW()` (preventing status/date manipulation).
   - Drops insecure permissive policies (`TO authenticated USING (true)`).
   - Restricts `anon` role to column-level `INSERT` grants strictly on `(name, phone, email, services, details)`.

---

## 4. Deploy + Live Test (Step 4)
Deploy your changes to Netlify and test lead submission end-to-end:

1. Push your updated code to GitHub (`master` branch). Netlify will automatically trigger a build and deploy.
2. Open your live website: `https://builtbyus.dev`.
3. Click **SEND PROJECT BRIEF**, fill in your own name and phone number, complete the Turnstile challenge, and submit.
4. Verify you receive the green success toast ("Project Brief Received!").
5. Check your **Supabase Table Editor** ➔ `project_leads` table to confirm the new lead appeared with `status: 'new'`.

---

## 5. Apply Migration 02: Revoke Anon Direct Insert (Step 5)
> ⚠️ **IMPORTANT:** Only run this after completing Step 4 (verifying the live form submitted successfully).

Now that your serverless function is handling live form submissions via `SUPABASE_SERVICE_ROLE_KEY`, lock down direct REST inserts:

1. In Supabase Dashboard, click **SQL Editor** ➔ Click **New query**.
2. Copy and paste the contents of `migrations/02_revoke_anon_direct_insert.sql`:
   ```sql
   DROP POLICY IF EXISTS "Allow anonymous lead insert" ON public.project_leads;
   REVOKE INSERT ON public.project_leads FROM anon;
   GRANT ALL ON public.project_leads TO service_role;
   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO service_role;
   ```
3. Click **Run**.
4. Direct inserts using the public anon key are now completely disabled; only your Netlify Function can write to `project_leads`.

---

## 6. Clean Up Production Test Rows (Step 6)
Delete the test records inserted during the earlier security audit:

1. In Supabase Dashboard, click **SQL Editor** ➔ Click **New query**.
2. Copy and paste `cleanup.sql` (or the snippet below):
   ```sql
   -- 1. PREVIEW MATCHING TEST ROWS
   SELECT id, created_at, name, phone, email, status
   FROM public.project_leads
   WHERE name = 'Security Test Auditor'
      OR name LIKE '''; DROP TABLE%'
      OR LENGTH(name) > 1000
      OR email = 'audit@security.test';

   -- 2. DELETE ONLY THE MATCHING TEST ROWS
   DELETE FROM public.project_leads
   WHERE name = 'Security Test Auditor'
      OR name LIKE '''; DROP TABLE%'
      OR LENGTH(name) > 1000
      OR email = 'audit@security.test';

   -- 3. VERIFY DELETION (Should return 0)
   SELECT COUNT(*) AS remaining_test_rows
   FROM public.project_leads
   WHERE name = 'Security Test Auditor'
      OR name LIKE '''; DROP TABLE%'
      OR LENGTH(name) > 1000
      OR email = 'audit@security.test';
   ```
3. Click **Run**.

---

## 7. Supabase Auth Settings (Step 7)
Lock down user registration and enable password protections:

1. In Supabase Dashboard, click **Authentication** (padlock icon in the sidebar).
2. Under **Configuration**, click **Providers** ➔ Click on **Email**.
3. Toggle **"Allow new users to sign up"** to **OFF** (disabled).
4. Click **Save**.
5. Under **Authentication** ➔ **Attack Protection**, toggle **"Enable leaked password protection"** to **ON**.
6. Under **Authentication** ➔ **Email Auth**, set **"OTP expiry"** to `300` seconds (5 minutes).
7. Click **Save**.

---

## 8. Two-Factor Authentication (2FA) (Step 8)
Protect all developer and admin accounts from credential takeover:

- **Supabase:** Profile Avatar (top right) ➔ **Account** ➔ **Security** ➔ **Two-Factor Authentication** ➔ Enable with an Authenticator App.
- **GitHub:** Profile ➔ **Settings** ➔ **Password and authentication** ➔ **Two-factor authentication** ➔ Enable.
- **Netlify:** User Settings ➔ **Security** ➔ **Two-factor authentication** ➔ Enable.

---

## 9. Tailwind CSS Self-Hosting (Plan to Remove 'unsafe-inline' in CSP)

### Why `'unsafe-inline'` exists today:
The page currently loads Tailwind CSS via CDN (`https://cdn.tailwindcss.com`). The CDN script inspects classes in the DOM at runtime and generates dynamic `<style>` elements into the `<head>`, which necessitates `'unsafe-inline'` in `style-src`.

### Plan to remove `'unsafe-inline'`:
1. Generate static compiled CSS using Tailwind CLI:
   ```bash
   npx tailwindcss -i ./input.css -o ./output.css --minify
   ```
2. In `index.html`, replace `<script src="https://cdn.tailwindcss.com"></script>` with:
   ```html
   <link rel="stylesheet" href="/output.css" />
   ```
3. In `server.js` and `netlify.toml`, update `style-src` in `Content-Security-Policy`:
   Change:
   `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;`
   To:
   `style-src 'self' https://fonts.googleapis.com;`
This completely removes `'unsafe-inline'`, maximizing CSP protection against DOM injection.
