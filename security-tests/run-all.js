// ====================================================================
// Builtbyus Studio: Automated Security & QA Test Suite Runner
// Command: npm run test:security
// ====================================================================

const testHeaders = require('./test-headers');
const testBrowserCsp = require('./test-browser-csp');
const testFunction = require('./test-function');
const testRlsSchema = require('./test-rls-schema');
const testBehavioral = require('./test-behavioral');
const testSecretsAudit = require('./test-secrets-audit');

async function main() {
  console.log('\n======================================================');
  console.log('🛡️  BUILTBYUS APPLICATION SECURITY TEST SUITE');
  console.log('======================================================\n');

  const startTime = Date.now();
  let errors = 0;

  try {
    await testHeaders();
  } catch (err) {
    console.error('❌ Header tests failed:', err.message);
    errors++;
  }

  try {
    await testBrowserCsp();
  } catch (err) {
    console.error('❌ Browser CSP tests failed:', err.message);
    errors++;
  }

  try {
    await testFunction();
  } catch (err) {
    console.error('❌ Function tests failed:', err.message);
    errors++;
  }

  try {
    await testRlsSchema();
  } catch (err) {
    console.error('❌ RLS & schema tests failed:', err.message);
    errors++;
  }

  try {
    await testBehavioral();
  } catch (err) {
    console.error('❌ Behavioral tests failed:', err.message);
    errors++;
  }

  try {
    testSecretsAudit();
  } catch (err) {
    console.error('❌ Secrets & audit tests failed:', err.message);
    errors++;
  }

  const durationMs = Date.now() - startTime;

  console.log('======================================================');
  if (errors === 0) {
    console.log(`✅ ALL SECURITY TEST SUITES PASSED (${durationMs}ms)`);
    console.log('======================================================\n');
    process.exit(0);
  } else {
    console.error(`❌ ${errors} TEST SUITE(S) FAILED (${durationMs}ms)`);
    console.log('======================================================\n');
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Unhandled fatal error in test runner:', err);
  process.exit(1);
});
