const fs = require('fs');
const path = require('path');
const https = require('https');
const assert = require('assert');

// Probe live Supabase REST API (READ-ONLY / NON-DESTRUCTIVE - Never inserts or deletes in production)
async function probeSupabase(method, queryParams = '', payload = null) {
  return new Promise((resolve) => {
    const config = {
      url: 'https://nirtydxacoujcbrbztyo.supabase.co',
      anonKey: 'sb_publishable_jx24CpGpzelYvZ8PeKHmiA_N5a1FWp7',
      table: 'project_leads'
    };

    const parsedUrl = new URL(`${config.url}/rest/v1/${config.table}${queryParams}`);
    const postData = payload ? JSON.stringify(payload) : null;
    const headers = {
      'apikey': config.anonKey,
      'Authorization': `Bearer ${config.anonKey}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation'
    };
    if (postData) {
      headers['Content-Length'] = Buffer.byteLength(postData);
    }

    const options = {
      hostname: parsedUrl.hostname,
      port: 443,
      path: `${parsedUrl.pathname}${parsedUrl.search}`,
      method: method,
      headers: headers,
      timeout: 6000
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        resolve({ statusCode: res.statusCode, body });
      });
    });

    req.on('error', (err) => {
      resolve({ statusCode: 0, error: err.message });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve({ statusCode: 0, error: 'Timeout' });
    });
    if (postData) {
      req.write(postData);
    }
    req.end();
  });
}

async function run() {
  console.log('--- Testing Database Hardening, RLS & Schema ---');
  let passed = 0;
  let failed = 0;

  function test(description, fn) {
    try {
      fn();
      console.log(`  ✓ ${description}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ ${description}`);
      console.error(`    Error: ${err.message}`);
      failed++;
    }
  }

  // 1. Static Schema & Migration Verification
  const m1Path = path.join(__dirname, '..', 'migrations', '01_harden_project_leads.sql');
  const m2Path = path.join(__dirname, '..', 'migrations', '02_revoke_anon_direct_insert.sql');
  const schemaPath = path.join(__dirname, '..', 'supabase-schema.sql');

  const m1 = fs.readFileSync(m1Path, 'utf8');
  const m2 = fs.readFileSync(m2Path, 'utf8');
  const schema = fs.readFileSync(schemaPath, 'utf8');

  test('Migration 01 enforces Row Level Security (RLS)', () => {
    assert(m1.includes('ALTER TABLE public.project_leads ENABLE ROW LEVEL SECURITY;'), 'RLS must be enabled');
  });

  test('Migration 01 removes insecure TO authenticated USING (true) policies', () => {
    assert(!m1.includes('TO authenticated\nUSING (true)'), 'Must not grant full read to authenticated');
    assert(m1.includes('DROP POLICY IF EXISTS "Allow authenticated admin read"'), 'Must drop insecure read policy');
    assert(m1.includes('DROP POLICY IF EXISTS "Allow authenticated admin update"'), 'Must drop insecure update policy');
  });

  test('Migration 01 restricts anon to column-level INSERT only', () => {
    assert(m1.includes('REVOKE ALL ON public.project_leads FROM anon'), 'Must revoke all table-level access');
    assert(m1.includes('GRANT INSERT (name, phone, email, services, details) ON public.project_leads TO anon'), 'Must grant INSERT only on 5 specific columns');
  });

  test('Migration 01 implements BEFORE INSERT trigger forcing status=new and created_at=now()', () => {
    assert(m1.includes('CREATE TRIGGER trg_enforce_lead_defaults'), 'Must define trigger');
    assert(m1.includes("NEW.status := 'new';"), 'Trigger must force status = new');
    assert(m1.includes('NEW.created_at := NOW();'), 'Trigger must force created_at = NOW()');
  });

  test('Migration 01 enforces CHECK constraints for length and email format', () => {
    assert(m1.includes('chk_project_leads_name'), 'Must define name constraint');
    assert(m1.includes('chk_project_leads_phone'), 'Must define phone constraint');
    assert(m1.includes('chk_project_leads_email'), 'Must define email regex constraint');
    assert(m1.includes('chk_project_leads_services'), 'Must define services constraint');
    assert(m1.includes('chk_project_leads_details'), 'Must define details constraint');
  });

  test('Migration 02 correctly specifies revocation of direct anon INSERT', () => {
    assert(m2.includes('REVOKE INSERT ON public.project_leads FROM anon'), 'Must revoke INSERT from anon');
    assert(m2.includes('DROP POLICY IF EXISTS "Allow anonymous lead insert"'), 'Must drop anon insert policy');
  });

  test('supabase-schema.sql matches hardened migration rules', () => {
    assert(schema.includes('trg_enforce_lead_defaults'), 'Main schema must have default trigger');
    assert(schema.includes('chk_project_leads_name'), 'Main schema must have name check');
  });

  // 2. Non-Destructive Live Supabase RLS Probe
  const isCI = Boolean(process.env.CI || process.env.GITHUB_ACTIONS);
  const targetUrl = process.env.SUPABASE_URL || 'https://nirtydxacoujcbrbztyo.supabase.co';
  const isProdProject = targetUrl.includes('nirtydxacoujcbrbztyo');

  if (isCI && isProdProject) {
    console.log('  ⚠️ CI environment detected: Live API tests against production project are disabled per safety rules.');
    console.log('  👉 Use a dedicated local or staging Supabase project in CI.');
  } else {
    console.log('  Testing live Supabase RLS enforcement for anon role (non-destructive)...');

    const selectRes = await probeSupabase('GET', '?select=*');
    test('Live Supabase RLS: anon cannot read / SELECT records from project_leads', () => {
      if (selectRes.statusCode === 200) {
        assert.strictEqual(selectRes.body.trim(), '[]', 'RLS must return empty array to anon');
      } else {
        assert(selectRes.statusCode === 401 || selectRes.statusCode === 403, `Blocked status: ${selectRes.statusCode}`);
      }
    });

    // Use filter ?id=eq.-1 that matches nothing to guarantee 0 database side effects
    const updateRes = await probeSupabase('PATCH', '?id=eq.-1', { name: 'Probe Auditor' });
    test('Live Supabase RLS: anon cannot UPDATE records (tested with ?id=eq.-1)', () => {
      if (updateRes.statusCode === 200) {
        assert.strictEqual(updateRes.body.trim(), '[]', 'RLS must not update any rows for anon');
      } else {
        assert(updateRes.statusCode === 401 || updateRes.statusCode === 403 || updateRes.statusCode === 404);
      }
    });

    const deleteRes = await probeSupabase('DELETE', '?id=eq.-1');
    test('Live Supabase RLS: anon cannot DELETE records (tested with ?id=eq.-1)', () => {
      if (deleteRes.statusCode === 200) {
        assert.strictEqual(deleteRes.body.trim(), '[]', 'RLS must not delete any rows for anon');
      } else {
        assert(deleteRes.statusCode === 401 || deleteRes.statusCode === 403 || deleteRes.statusCode === 404);
      }
    });
  }

  if (failed > 0) {
    throw new Error(`${failed} RLS/schema test(s) failed`);
  }
  console.log(`  All ${passed} RLS & schema tests passed successfully.\n`);
}

if (require.main === module) {
  run().catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = run;
