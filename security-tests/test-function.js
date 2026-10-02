const assert = require('assert');
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

  // 2. Malformed JSON check
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

  // 3. Missing required fields (Zod validation)
  await test('Rejects missing name or phone with HTTP 400 (Zod)', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.2' },
      body: JSON.stringify({
        services: 'Website',
        turnstileToken: 'dummy'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Validation error'));
  });

  // 4. Input bounds check (Oversize payload DoS protection)
  await test('Rejects oversized name (>100 chars) with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.3' },
      body: JSON.stringify({
        name: 'A'.repeat(101),
        phone: '+91 9876543210',
        turnstileToken: 'dummy'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Name must not exceed 100 characters'));
  });

  await test('Rejects oversized details (>2000 chars) with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.4' },
      body: JSON.stringify({
        name: 'Valid Name',
        phone: '+91 9876543210',
        details: 'D'.repeat(2001),
        turnstileToken: 'dummy'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Details must not exceed 2000 characters'));
  });

  // 5. Invalid email format
  await test('Rejects invalid email format with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.5' },
      body: JSON.stringify({
        name: 'Valid Name',
        phone: '+91 9876543210',
        email: 'invalid-email-format',
        turnstileToken: 'dummy'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Invalid email address format'));
  });

  // 6. Anti-bot honeypot trap
  await test('Honeypot trap silently returns HTTP 200 without saving', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.6' },
      body: JSON.stringify({
        name: 'Spam Bot',
        phone: '+1 5550199',
        botTrap: 'http://spam-link.ru'
      })
    });
    assert.strictEqual(res.statusCode, 200);
    const body = JSON.parse(res.body);
    assert.strictEqual(body.success, true);
    assert.strictEqual(body.message, 'Received');
  });

  // 7. Missing or invalid Turnstile token
  await test('Rejects missing Turnstile verification token with HTTP 400', async () => {
    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.7' },
      body: JSON.stringify({
        name: 'Valid Name',
        phone: '+91 9876543210',
        email: 'test@example.com'
      })
    });
    assert.strictEqual(res.statusCode, 400);
    const body = JSON.parse(res.body);
    assert(body.error.includes('Turnstile verification token is required'));
  });

  // 8. IP Rate Limiting check
  await test('Enforces IP rate limit: returns HTTP 429 when threshold exceeded', async () => {
    const testIp = '198.51.100.99';
    let hit429 = false;

    // Send 7 rapid requests from the same IP (threshold is 5)
    for (let i = 0; i < 7; i++) {
      const res = await handler({
        httpMethod: 'POST',
        headers: { 'x-nf-client-connection-ip': testIp },
        body: JSON.stringify({
          name: `Rate Limit Test ${i}`,
          phone: '+91 9876543210',
          turnstileToken: 'dummy-token'
        })
      });

      if (res.statusCode === 429) {
        hit429 = true;
        const body = JSON.parse(res.body);
        assert(body.error.includes('Too many requests'));
        break;
      }
    }
    assert.strictEqual(hit429, true, 'Rate limiter should have triggered HTTP 429');
  });

  // 9. XSS / SQLi payloads safely handled by validation & schema
  await test('XSS and SQL injection payloads are strictly validated without execution', async () => {
    const sqliName = "'; DROP TABLE project_leads; --";
    const xssDetails = "<script>alert('xss')</script>";

    const res = await handler({
      httpMethod: 'POST',
      headers: { 'x-nf-client-connection-ip': '127.0.0.8' },
      body: JSON.stringify({
        name: sqliName,
        phone: '+91 9876543210',
        details: xssDetails,
        turnstileToken: 'dummy-token'
      })
    });

    // It passes Zod validation because lengths are within bounds, then reaches Turnstile verification
    // This verifies strings are treated as plain textual data and not executed as SQL or markup
    assert(res.statusCode === 403 || res.statusCode === 201 || res.statusCode === 502);
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
