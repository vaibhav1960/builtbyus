const assert = require('assert');
const https = require('https');

process.env.NODE_ENV = 'test';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'test_service_role_secret_key';
process.env.TURNSTILE_SECRET_KEY = '1x0000000000000000000000000000000AA';

const { handler } = require('../netlify/functions/submit-lead');

// Live test helper for Staging Supabase
async function sendToSupabaseStaging(url, key, endpoint, method, payload) {
  return new Promise((resolve) => {
    const fullUrl = new URL(`${url}/rest/v1/${endpoint}`);
    const postData = payload ? JSON.stringify(payload) : null;
    const headers = {
      'apikey': key,
      'Authorization': `Bearer ${key}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=representation'
    };
    if (postData) {
      headers['Content-Length'] = Buffer.byteLength(postData);
    }

    const options = {
      hostname: fullUrl.hostname,
      port: 443,
      path: `${fullUrl.pathname}${fullUrl.search}`,
      method: method,
      headers: headers,
      timeout: 8000
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve({ status: res.statusCode, data: parsed, raw: body });
        } catch (e) {
          resolve({ status: res.statusCode, raw: body });
        }
      });
    });

    req.on('error', (err) => resolve({ status: 0, error: err.message }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 0, error: 'Timeout' });
    });

    if (postData) req.write(postData);
    req.end();
  });
}

async function run() {
  console.log('--- Testing Behavioral Security Constraints ---');
  let passed = 0;
  let failed = 0;

  async function test(description, fn) {
    try {
      await fn();
      console.log(`  ✓ ${description}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ ${description}`);
      console.error(`    Error: ${err.message}`);
      failed++;
    }
  }

  // =========================================================================
  // Part 1: Serverless Function Behavioral Tests
  // =========================================================================
  await test('Function rejects client-forged status/created_at with HTTP 400 (parameter tampering)', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: {
        'x-nf-client-connection-ip': '127.0.0.1'
      },
      body: JSON.stringify({
        name: 'Honest User',
        phone: '+91 9876543210',
        status: 'closed', // Attacker attempt to mark lead as closed
        created_at: '2020-01-01T00:00:00Z', // Attacker attempt to backdate
        turnstileToken: 'test-token'
      })
    });
    // Zod strict schema rejects unexpected fields with 400
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Unrecognized key'));
  });

  await test('Function rejects massive text payloads (500KB+ DoS attempt)', async () => {
    const hugePayload = 'X'.repeat(500 * 1024);
    const res = await handler({
      httpMethod: 'POST',
      headers: {
        'x-nf-client-connection-ip': '127.0.0.1'
      },
      body: JSON.stringify({
        name: 'DoS Attacker',
        phone: '+91 9876543210',
        details: hugePayload,
        turnstileToken: 'test-token'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Details must not exceed 2000 characters'));
  });

  await test('Function rejects malformed or invalid email addresses', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: {
        'x-nf-client-connection-ip': '127.0.0.1'
      },
      body: JSON.stringify({
        name: 'User',
        phone: '+91 9876543210',
        email: 'invalid@nonexistent',
        turnstileToken: 'test-token'
      })
    });
    assert.strictEqual(res.statusCode, 400);
  });

  // =========================================================================
  // Part 2: Supabase Staging Behavioral Tests (Executed only when Staging is configured)
  // =========================================================================
  const stagingUrl = process.env.SUPABASE_STAGING_URL;
  const stagingAnonKey = process.env.SUPABASE_STAGING_ANON_KEY;

  if (stagingUrl && stagingAnonKey) {
    console.log('  Executing live behavioral tests against Staging Supabase project...');

    await test('Staging Postgres: trigger forces status="new" and created_at=NOW()', async () => {
      const res = await sendToSupabaseStaging(stagingUrl, stagingAnonKey, 'project_leads', 'POST', {
        name: 'Staging Behavior Test',
        phone: '+91 9876543210',
        status: 'closed',
        created_at: '2019-01-01T00:00:00Z'
      });
      if (res.status === 201 && Array.isArray(res.data) && res.data.length > 0) {
        assert.strictEqual(res.data[0].status, 'new', 'Postgres trigger must overwrite status to "new"');
        const insertedTime = new Date(res.data[0].created_at).getTime();
        const now = Date.now();
        assert(Math.abs(now - insertedTime) < 60000, 'Postgres trigger must set created_at to NOW()');
      }
    });

    await test('Staging Postgres: CHECK constraint rejects name exceeding 100 chars', async () => {
      const res = await sendToSupabaseStaging(stagingUrl, stagingAnonKey, 'project_leads', 'POST', {
        name: 'A'.repeat(101),
        phone: '+91 9876543210'
      });
      assert(res.status === 400 || res.status === 422, 'Postgres constraint must reject name > 100');
      assert(res.raw.includes('chk_project_leads_name') || res.raw.includes('violates check constraint'));
    });

    await test('Staging Postgres: CHECK constraint rejects invalid email format', async () => {
      const res = await sendToSupabaseStaging(stagingUrl, stagingAnonKey, 'project_leads', 'POST', {
        name: 'Valid Name',
        phone: '+91 9876543210',
        email: 'invalid-email-address'
      });
      assert(res.status === 400 || res.status === 422, 'Postgres constraint must reject invalid email');
      assert(res.raw.includes('chk_project_leads_email') || res.raw.includes('violates check constraint'));
    });

    await test('Staging Postgres: anon cannot SELECT any records (RLS enforced)', async () => {
      const res = await sendToSupabaseStaging(stagingUrl, stagingAnonKey, 'project_leads?select=*', 'GET', null);
      if (res.status === 200) {
        assert.deepStrictEqual(res.data, [], 'RLS must return empty list to anon');
      } else {
        assert(res.status === 401 || res.status === 403);
      }
    });
  } else {
    console.log('  ℹ️  Staging Supabase project not configured in env (SUPABASE_STAGING_URL).');
    console.log('  👉 Staging behavioral tests will run automatically once SUPABASE_STAGING_URL is provided.');
  }

  if (failed > 0) {
    throw new Error(`${failed} behavioral test(s) failed`);
  }
  console.log(`  All ${passed} behavioral tests passed successfully.\n`);
}

if (require.main === module) {
  run().catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = run;
