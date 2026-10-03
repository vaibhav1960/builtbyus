const assert = require('assert');

// Ensure test environment variables are established
process.env.NODE_ENV = 'test';
process.env.SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || 'test_service_role_secret_key';

const { handler } = require('../netlify/functions/submit-lead');

async function run() {
  console.log('--- Testing Netlify Serverless Function (submit-lead) ---');
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

  // 1. Method check
  await test('Rejects non-POST methods with HTTP 405', async () => {
    const res = await handler({ httpMethod: 'GET', headers: {} });
    assert.strictEqual(res.statusCode, 405);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Only POST is supported'));
  });

  // 2. Strict Service Role Key Check
  await test('Fails with HTTP 500 when SUPABASE_SERVICE_ROLE_KEY is missing', async () => {
    const originalKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    try {
      const res = await handler({
        httpMethod: 'POST',
        headers: { 'x-nf-client-connection-ip': '127.0.0.1' },
        body: JSON.stringify({ name: 'Test' })
      });
      assert.strictEqual(res.statusCode, 500);
      const body = JSON.parse(res.body);
      assert(body.error.includes('Server configuration error'));
    } finally {
      process.env.SUPABASE_SERVICE_ROLE_KEY = originalKey;
    }
  });

  // 3. Malformed JSON check
  await test('Rejects malformed JSON body with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.1' },
      body: 'not a json {{'
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Malformed JSON'));
  });

  // 4. Missing required name
  await test('Rejects missing name with HTTP 400 (Zod)', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.2' },
      body: JSON.stringify({
        email: 'test@example.com'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Validation error'));
  });

  // 5. Input bounds check (Oversize payload DoS protection)
  await test('Rejects oversized name (>100 chars) with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.3' },
      body: JSON.stringify({
        name: 'A'.repeat(101),
        phone: '+91 9876543210'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Name must not exceed 100 characters'));
  });

  await test('Rejects oversized message (>2000 chars) with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.4' },
      body: JSON.stringify({
        name: 'Valid Name',
        email: 'valid@example.com',
        message: 'M'.repeat(2001)
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Message must not exceed 2000 characters'));
  });

  // 6. Invalid email format
  await test('Rejects invalid email format with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.5' },
      body: JSON.stringify({
        name: 'Valid Name',
        phone: '+91 9876543210',
        email: 'invalid-email-format'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Invalid email address format'));
  });

  // 7. Budget & Timeline enum validation
  await test('Rejects unapproved budget option with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.6' },
      body: JSON.stringify({
        name: 'Valid Name',
        email: 'valid@example.com',
        budget: '$1,000,000+' // Not in allowed set
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Validation error'));
  });

  // 7b. Timeline enum validation
  await test('Rejects unapproved timeline option with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.7' },
      body: JSON.stringify({
        name: 'Valid Name',
        email: 'valid@example.com',
        timeline: 'Yesterday' // Not in allowed set
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Validation error'));
  });

  // 8. Strict schema: reject unexpected fields
  await test('Rejects unexpected payload fields with HTTP 400 (strict schema)', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.8' },
      body: JSON.stringify({
        name: 'Valid Name',
        email: 'valid@example.com',
        unrecognized_malicious_field: 'exploit_attempt'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Unrecognized key'));
  });

  // 9. Valid lead submission
  await test('Accepts valid lead submission without Turnstile or honeypot', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.11' },
      body: JSON.stringify({
        name: 'Valid Name',
        email: 'test@example.com'
      })
    });
    // Successfully passes Zod validation, attempts Supabase insert
    assert(res.statusCode === 201 || res.statusCode === 502);
  });

  // 10. XSS / SQLi payloads safely handled by validation & schema
  await test('XSS and SQL injection payloads are strictly validated without execution', async () => {
    const sqliName = "'; DROP TABLE project_leads; --";
    const xssDetails = "<script>alert('xss')</script>";

    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.12' },
      body: JSON.stringify({
        name: sqliName,
        phone: '+91 9876543210',
        details: xssDetails
      })
    });

    // Treated as plain data, validated within boundaries, reaches Supabase insert
    assert(res.statusCode === 201 || res.statusCode === 502);
  });

  if (failed > 0) {
    throw new Error(`${failed} function test(s) failed`);
  }
  console.log(`  All ${passed} serverless function tests passed successfully.\n`);
}

if (require.main === module) {
  run().catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = run;
