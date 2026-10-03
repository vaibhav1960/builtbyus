const fs = require('fs');
const assert = require('assert');
const puppeteer = require('puppeteer-core');

function getBrowserExecutablePath() {
  const candidates = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    process.env.CHROME_BIN,
    process.env.EDGE_BIN
  ].filter(Boolean);

  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

async function run() {
  console.log('--- Testing Browser CSP Compliance (Playwright / Puppeteer Core) ---');
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

  const executablePath = getBrowserExecutablePath();
  if (!executablePath) {
    console.warn('  ⚠️ No local Chrome/Edge executable found on this system. Skipping browser test.');
    return;
  }

  console.log(`  Using browser engine: ${executablePath}`);

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath,
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-gpu'
      ]
    });

    const page = await browser.newPage();
    const cspErrors = [];
    const consoleErrors = [];

    // Capture security policy violation events
    await page.evaluateOnNewDocument(() => {
      window.__cspViolations = [];
      document.addEventListener('securitypolicyviolation', (e) => {
        window.__cspViolations.push({
          blockedURI: e.blockedURI,
          violatedDirective: e.violatedDirective,
          effectiveDirective: e.effectiveDirective,
          originalPolicy: e.originalPolicy
        });
      });
    });

    page.on('console', msg => {
      const text = msg.text();
      if (text.includes('Content Security Policy') || text.includes('refused to load') || text.includes('violates the following Content Security Policy')) {
        cspErrors.push(text);
      }
      if (msg.type() === 'error' && !text.includes('Failed to load resource: net::ERR_CONNECTION_REFUSED')) {
        consoleErrors.push(text);
      }
    });

    // Navigate to local server
    await page.goto('http://localhost:3000', {
      waitUntil: 'domcontentloaded',
      timeout: 20000
    });

    // Give runtime scripts and styles 2 seconds to initialize
    await new Promise(r => setTimeout(r, 2000));

    // Check DOM and library initialization
    const pageMetrics = await page.evaluate(() => {
      return {
        hasTailwind: Boolean(window.tailwind),
        hasGsap: Boolean(window.gsap),
        hasTurnstileScript: Boolean(document.querySelector('script[src*="turnstile"]')),
        cspViolations: window.__cspViolations || []
      };
    });

    test('Tailwind CDN script loads and initializes under CSP', () => {
      assert(pageMetrics.hasTailwind, 'Tailwind CDN script should load and be defined');
    });

    test('GSAP animation library loads successfully under CSP', () => {
      assert(pageMetrics.hasGsap, 'GSAP should be present and initialized');
    });

    test('Cloudflare Turnstile script is removed from DOM', () => {
      assert(!pageMetrics.hasTurnstileScript, 'Turnstile script tag should NOT be present');
    });

    test('Zero securitypolicyviolation DOM events triggered', () => {
      assert.strictEqual(
        pageMetrics.cspViolations.length,
        0,
        `CSP violations detected: ${JSON.stringify(pageMetrics.cspViolations)}`
      );
    });

    test('Zero CSP violation error messages logged in browser console', () => {
      assert.strictEqual(
        cspErrors.length,
        0,
        `Console logged CSP errors: ${JSON.stringify(cspErrors)}`
      );
    });

  } catch (err) {
    console.error('  Browser CSP test execution exception:', err.message);
    failed++;
  } finally {
    if (browser) {
      await browser.close();
    }
  }

  if (failed > 0) {
    throw new Error(`${failed} browser CSP test(s) failed`);
  }
  console.log(`  All ${passed} browser CSP tests passed successfully.\n`);
}

if (require.main === module) {
  run().catch(err => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = run;
