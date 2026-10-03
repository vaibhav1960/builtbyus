const http = require('http');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

async function checkLiveServerHeaders() {
  return new Promise((resolve, reject) => {
    http.get('http://localhost:3000', (res) => {
      resolve(res.headers);
    }).on('error', (err) => {
      reject(new Error(`Could not connect to http://localhost:3000: ${err.message}`));
    });
  });
}

function checkNetlifyTomlHeaders() {
  const tomlPath = path.join(__dirname, '..', 'netlify.toml');
  const content = fs.readFileSync(tomlPath, 'utf8');
  return content;
}

async function run() {
  console.log('--- Testing Security Headers & CSP ---');
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

  // 1. Live Server Headers
  let headers;
  try {
    headers = await checkLiveServerHeaders();
  } catch (e) {
    console.warn('  ⚠️ Live server check skipped (not responding):', e.message);
  }

  if (headers) {
    test('Server returns Content-Security-Policy', () => {
      assert(headers['content-security-policy'], 'CSP header must be set');
      const csp = headers['content-security-policy'];
      assert(csp.includes("default-src 'self'"), 'CSP must specify default-src');
      assert(csp.includes("connect-src 'self'"), 'CSP connect-src must allow self only');
      assert(!csp.includes('*.supabase.co'), 'CSP connect-src must NOT contain wildcard *.supabase.co');
      assert(csp.includes("frame-ancestors 'self'"), 'CSP must include frame-ancestors');
      assert(csp.includes("base-uri 'self'"), 'CSP must include base-uri');
      assert(csp.includes("form-action 'self'"), 'CSP must include form-action');
    });

    test('Server returns Strict-Transport-Security (HSTS)', () => {
      assert(headers['strict-transport-security'], 'HSTS header must be set');
      assert(headers['strict-transport-security'].includes('max-age=31536000'), 'HSTS max-age must be 1 year');
    });

    test('Server returns X-Content-Type-Options: nosniff', () => {
      assert.strictEqual(headers['x-content-type-options'], 'nosniff');
    });

    test('Server returns X-Frame-Options: SAMEORIGIN', () => {
      assert.strictEqual(headers['x-frame-options'], 'SAMEORIGIN');
    });

    test('Server returns Referrer-Policy', () => {
      assert.strictEqual(headers['referrer-policy'], 'strict-origin-when-cross-origin');
    });

    test('Server returns Permissions-Policy with camera, mic, geo, payment disabled', () => {
      const pp = headers['permissions-policy'];
      assert(pp, 'Permissions-Policy must be set');
      assert(pp.includes('camera=()') && pp.includes('microphone=()') && pp.includes('geolocation=()') && pp.includes('payment=()'));
    });

    test('Server returns COOP (Cross-Origin-Opener-Policy: same-origin)', () => {
      assert.strictEqual(headers['cross-origin-opener-policy'], 'same-origin');
    });

    test('Server returns CORP (Cross-Origin-Resource-Policy: same-origin)', () => {
      assert.strictEqual(headers['cross-origin-resource-policy'], 'same-origin');
    });
  }

  // 2. Netlify TOML Headers
  const toml = checkNetlifyTomlHeaders();

  test('netlify.toml defines Content-Security-Policy', () => {
    assert(toml.includes('Content-Security-Policy'), 'netlify.toml must define CSP');
    assert(toml.includes("connect-src 'self'"), 'netlify.toml connect-src must allow self only');
    assert(!toml.includes('*.supabase.co'), 'netlify.toml must NOT use wildcard *.supabase.co in connect-src');
  });

  test('netlify.toml defines HSTS, nosniff, COOP, CORP', () => {
    assert(toml.includes('Strict-Transport-Security'), 'netlify.toml must define HSTS');
    assert(toml.includes('X-Content-Type-Options = "nosniff"'), 'netlify.toml must define nosniff');
    assert(toml.includes('Cross-Origin-Opener-Policy = "same-origin"'), 'netlify.toml must define COOP');
    assert(toml.includes('Cross-Origin-Resource-Policy = "same-origin"'), 'netlify.toml must define CORP');
    assert(toml.includes('payment=()'), 'netlify.toml Permissions-Policy must disable payments');
  });

  if (failed > 0) {
    throw new Error(`${failed} header test(s) failed`);
  }
  console.log(`  All ${passed} header tests passed successfully.\n`);
}

if (require.main === module) {
  run().catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = run;
