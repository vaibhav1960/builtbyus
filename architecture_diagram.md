# Builtbyus Studio — Security Architecture Diagram

This document illustrates the end-to-end security architecture of **Builtbyus Studio** following the full security remediation.

---

## 1. High-Level Architecture Flow

```mermaid
flowchart TD
    subgraph Client["Client Tier (Untrusted)"]
        User["Visitor / Browser"]
        Form["HTML Contact Form (Tailwind + GSAP)"]
        TurnstileWidget["Cloudflare Turnstile Widget (Managed)"]
    end

    subgraph Edge["Edge / CDN Tier"]
        NetlifyCDN["Netlify CDN Edge"]
        SecHeaders["Security Headers (CSP, HSTS, XFO, nosniff, COOP, CORP)"]
    end

    subgraph Serverless["Application / Compute Tier"]
        NetlifyFunc["Netlify Serverless Function (submit-lead.js)"]
        MethodCheck["1. HTTP Method Gate (POST only)"]
        ConfigCheck["2. Service Role Key Guard (Fail 500 if missing)"]
        IPExtract["3. IP Extraction (x-nf-client-connection-ip only)"]
        RateLimiter["4. Durable Sliding Window Limiter (Upstash Redis)"]
        Honeypot["5. Anti-Bot Honeypot Trap (botTrap, website_url)"]
        ZodValidator["6. Zod Schema Strict Validation (Boundary enforcement)"]
        TurnstileVerify["7. Cloudflare Turnstile API Siteverify (Fail-closed 403)"]
    end

    subgraph External["External Services"]
        Upstash["Upstash Redis Cluster (Sorted Sets: ZADD / ZCARD / EXPIRE)"]
        CFTurnstile["Cloudflare Turnstile API (challenges.cloudflare.com)"]
    end

    subgraph Database["Database Tier (Isolated)"]
        SupabaseAPI["Supabase REST API (Protected)"]
        Postgres["PostgreSQL Database"]
        RLS["Row Level Security (ZERO Public Policies)"]
        Trigger["BEFORE INSERT Trigger (enforce_lead_defaults)"]
        Constraints["Database CHECK Constraints (Status, Budget, Timeline, Lengths)"]
    end

    %% Client Interactions
    User --> Form
    Form --> TurnstileWidget
    Form --"HTTPS POST /.netlify/functions/submit-lead (JSON)"--> NetlifyCDN

    %% Edge
    NetlifyCDN --> SecHeaders
    NetlifyCDN --"Forwards with x-nf-client-connection-ip"--> NetlifyFunc

    %% Serverless Pipeline
    NetlifyFunc --> MethodCheck
    MethodCheck --> ConfigCheck
    ConfigCheck --> IPExtract
    IPExtract --> RateLimiter
    RateLimiter <--"Atomic Sorted Set Pipeline (10m window, max 5)"--> Upstash
    RateLimiter --> Honeypot
    Honeypot --"If Bot Trap Filled: Silent HTTP 200 Drop"--> User
    Honeypot --> ZodValidator
    ZodValidator --"Invalid Input: HTTP 400"--> User
    ZodValidator --> TurnstileVerify
    TurnstileVerify <--"HTTPS POST /turnstile/v0/siteverify"--> CFTurnstile
    TurnstileVerify --"Failed Bot Check: HTTP 403"--> User

    %% Database Write
    TurnstileVerify --"Authorized Lead: HTTPS POST /rest/v1/project_leads<br/>[EXCLUSIVE: SUPABASE_SERVICE_ROLE_KEY]"--> SupabaseAPI
    SupabaseAPI --"Bypasses RLS (service_role only)"--> Postgres
    Postgres --> Trigger
    Trigger --> Constraints
    Constraints --> Postgres

    %% Forbidden Path
    Form -. "BLOCKED: Direct Browser REST Access (No Anon Grants / No Keys in Client)" .-x SupabaseAPI

    classDef secure fill:#e6fffa,stroke:#047857,stroke-width:2px;
    classDef warning fill:#fffbeb,stroke:#b45309,stroke-width:2px;
    classDef danger fill:#fef2f2,stroke:#b91c1c,stroke-width:2px;
    classDef component fill:#f8fafc,stroke:#334155,stroke-width:2px;

    class NetlifyFunc,Upstash,CFTurnstile,Postgres secure;
    class Form,User warning;
    class SupabaseAPI component;
```

---

## 2. Security Trust Boundaries & Defense in Depth

### Layer 1: Client Browser (Zero Trust)
- **Zero Client Credentials:** No Supabase publishable keys, anon keys, or service role keys exist in the client-side JavaScript or HTML bundle.
- **Single Submission Path:** The frontend form submits strictly to `/.netlify/functions/submit-lead`.
- **Content Security Policy (CSP):** Browser connections are restricted to `'self'` and `https://challenges.cloudflare.com`. Public connections to database endpoints are explicitly disallowed.

### Layer 2: Edge CDN (Netlify)
- **Authoritative IP Tracking:** Netlify sets `x-nf-client-connection-ip`. Client-supplied `X-Forwarded-For` headers are strictly ignored by backend code to prevent rate limit spoofing.
- **Authoritative Security Headers:**
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`
  - `Cross-Origin-Opener-Policy: same-origin`
  - `Cross-Origin-Resource-Policy: same-origin`

### Layer 3: Serverless Function (`submit-lead.js`)
- **Key Requirement Guard:** The function mandates `SUPABASE_SERVICE_ROLE_KEY`. If omitted, the handler immediately returns `500 Server Configuration Error`.
- **Durable Sliding-Window Rate Limiter:**
  - Backend: Upstash Redis sorted sets (`ZREMRANGEBYSCORE`, `ZADD`, `ZCARD`, `EXPIRE`).
  - Window: Rolling 10 minutes (600 seconds).
  - Limit: Maximum 5 submissions per connection IP per rolling window.
  - Fail-safe: In-memory sliding-window fallback if Redis is unavailable.
- **Honeypot Bot Defense:** Hidden fields (`botTrap`, `website_url`) silently return `200 OK` to bots without saving to the database.
- **Strict Input Validation (Zod):**
  - Schema configured with `.strict()` to reject unexpected fields.
  - Strict length limits: `name` (1–100 chars), `email` (valid format, max 255 chars, lowercased), `message`/`details` (max 2000 chars), `budget` and `timeline` (strictly whitelisted enums).
- **Server-to-Server CAPTCHA Verification:** Cloudflare Turnstile token validated server-to-server with `TURNSTILE_SECRET_KEY`. Fails closed (`403 Forbidden`) if verification fails or network times out.

### Layer 4: PostgreSQL Database (Supabase)
- **Zero Public Permissions:**
  - `REVOKE ALL ON public.project_leads FROM anon, authenticated;`
  - `REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public FROM anon, authenticated;`
  - Row Level Security (RLS) is enabled with zero policies for public roles.
- **Exclusive Service Role Access:**
  - Only `service_role` has permissions to interact with `project_leads`.
  - In Supabase PostgreSQL, `service_role` bypasses RLS, ensuring that only trusted backend functions can write leads.
- **Postgres Defaults & Tamper-Proof Trigger:**
  - `trg_enforce_lead_defaults` triggers `BEFORE INSERT`, guaranteeing `status = 'new'` and `created_at = NOW()`.
  - Callers cannot forge status (e.g. mark as `closed`) or backdate leads.
- **Database CHECK Constraints:**
  - Enforces status in `('new', 'contacted', 'qualified', 'converted', 'archived')`.
  - Enforces allowed budget and timeline values.
  - Enforces text length and valid email regex.
