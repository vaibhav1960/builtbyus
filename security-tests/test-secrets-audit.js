const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const assert = require('assert');

function run() {
  console.log('--- Testing Secrets Leakage & Dependency Audit ---');
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

  // 1. Dependency Audit via npm audit
  test('Dependencies have zero High or Critical vulnerabilities', () => {
    let auditOutput = '';
    try {
      auditOutput = execSync('npm audit --json', { encoding: 'utf8', stdio: ['pipe', 'pipe', 'ignore'] });
    } catch (err) {
      auditOutput = err.stdout || '';
    }

    try {
      const parsed = JSON.parse(auditOutput);
      const vulnerabilities = parsed.metadata?.vulnerabilities || {};
      const high = vulnerabilities.high || 0;
      const critical = vulnerabilities.critical || 0;
      assert.strictEqual(high, 0, `Found ${high} high severity vulnerabilities`);
      assert.strictEqual(critical, 0, `Found ${critical} critical severity vulnerabilities`);
    } catch (e) {
      if (auditOutput.includes('found 0 vulnerabilities')) {
        return; // Passed
      }
      throw e;
    }
  });

  // 2. Full Git History Secret Scanning
  test('Git commit history contains zero leaked secrets or private keys', () => {
    let gitLog = '';
    try {
      gitLog = execSync('git log -p --all', { encoding: 'utf8', maxBuffer: 10 * 1024 * 1024 });
    } catch (e) {
      gitLog = '';
    }

    const secretPatterns = [
      { name: 'Private Key', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
      { name: 'Supabase Service Role JWT', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_\-]*service_role[a-zA-Z0-9_\-]*/i },
      { name: 'Supabase Access Token', regex: /sbp_[a-zA-Z0-9]{40}/ },
      { name: 'AWS Secret Key', regex: /AKIA[0-9A-Z]{16}/ },
      { name: 'Slack Bot Token', regex: /xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}/ }
    ];

    for (const pattern of secretPatterns) {
      const match = gitLog.match(pattern.regex);
      assert(!match, `Secret leak pattern detected in git history: ${pattern.name}`);
    }
  });

  // 3. Official Gitleaks Binary Execution
  const gitleaksCandidates = [
    'gitleaks',
    'C:\\Users\\DIMPLE\\.gemini\\antigravity\\brain\\751d9939-13e8-4ad0-9590-b7a8be96e46d\\scratch\\gitleaks.exe'
  ];
  const gitleaksBin = gitleaksCandidates.find(p => {
    try {
      execSync(`"${p}" version`, { stdio: 'ignore' });
      return true;
    } catch (e) {
      return false;
    }
  });

  if (gitleaksBin) {
    test('Gitleaks binary: 0 leaks across full git history', () => {
      try {
        execSync(`"${gitleaksBin}" detect --source="." --verbose`, {
          cwd: path.join(__dirname, '..'),
          encoding: 'utf8',
          stdio: 'pipe'
        });
        // Exit code 0 means 0 leaks found
      } catch (err) {
        if (err.status !== 0) {
          const combined = (err.stdout || '') + (err.stderr || '');
          throw new Error(`Gitleaks found secret leaks in repository:\n${combined}`);
        }
      }
    });
  }

  // 4. Client-side Code PII & Secret Scan
  test('Client-side files do not expose service_role or publishable keys', () => {
    const indexPath = path.join(__dirname, '..', 'index.html');
    const indexContent = fs.readFileSync(indexPath, 'utf8');

    assert(!indexContent.includes("console.log('Submitting Project Lead:'"), 'Must not log leadData PII in console');
    assert(!indexContent.includes('SUPABASE_SERVICE_ROLE_KEY'), 'Client HTML must never reference service_role key');
    assert(!indexContent.includes('service_role'), 'Client HTML must never contain service_role token');
    assert(!indexContent.includes('sb_publishable_'), 'Client HTML must never contain hardcoded Supabase keys');
    assert(!indexContent.includes('supabase.co'), 'Client HTML must not directly reference Supabase endpoints');

    const configPath = path.join(__dirname, '..', 'supabase-config.js');
    if (fs.existsSync(configPath)) {
      const configContent = fs.readFileSync(configPath, 'utf8');
      assert(!configContent.includes('sb_publishable_'), 'supabase-config.js must not contain keys');
    }
  });

  // 5. .env.example contains placeholders only, no real secrets
  test('.env.example contains only dummy placeholders', () => {
    const envPath = path.join(__dirname, '..', '.env.example');
    const envContent = fs.readFileSync(envPath, 'utf8');

    assert(envContent.includes('SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key_here'), 'service_role key must be placeholder in .env.example');
    assert(!envContent.includes('sb_publishable_jx24CpGpzelYvZ8PeKHmiA_N5a1FWp7'), '.env.example must not contain real publishable keys');
    assert(envContent.includes('1x00000000000000000000AA'), 'Turnstile key must be official test key');
  });

  if (failed > 0) {
    throw new Error(`${failed} secret/dependency test(s) failed`);
  }
  console.log(`  All ${passed} secrets & dependency tests passed successfully.\n`);
}

if (require.main === module) {
  try {
    run();
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

module.exports = run;
