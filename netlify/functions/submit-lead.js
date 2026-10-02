const { z } = require('zod');
const https = require('https');
const { Redis } = require('@upstash/redis');

// ====================================================================
// Builtbyus Studio: Serverless Lead Submission Handler
// Location: netlify/functions/submit-lead.js
// ====================================================================

// Configuration with safe staging/test defaults
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://nirtydxacoujcbrbztyo.supabase.co';
// Prefer service_role key; fallback to anon key until service_role is added in Netlify
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || 'sb_publishable_jx24CpGpzelYvZ8PeKHmiA_N5a1FWp7';
// Cloudflare Turnstile Secret Key (Default: Cloudflare Official Always-Passes Test Key)
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

// Upstash Redis Durable Rate Limiter (Required env vars: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN)
let upstashRedis = null;
if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
  try {
    upstashRedis = new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL,
      token: process.env.UPSTASH_REDIS_REST_TOKEN
    });
  } catch (err) {
    console.error('Failed to initialize Upstash Redis client:', err.message);
  }
}

// Rate Limiting Policy: Max 5 submissions per 10 minutes
const RATE_LIMIT_WINDOW_SECS = 10 * 60;
const RATE_LIMIT_MAX_REQUESTS = 5;
const ipRequestHistory = new Map();

function isInMemoryRateLimited(ip) {
  const now = Date.now();
  const windowStart = now - (RATE_LIMIT_WINDOW_SECS * 1000);

  // Clean up stale IPs periodically
  if (ipRequestHistory.size > 2000) {
    for (const [trackedIp, timestamps] of ipRequestHistory.entries()) {
      const active = timestamps.filter(ts => ts > windowStart);
      if (active.length === 0) {
        ipRequestHistory.delete(trackedIp);
      } else {
        ipRequestHistory.set(trackedIp, active);
      }
    }
  }

  const timestamps = (ipRequestHistory.get(ip) || []).filter(ts => ts > windowStart);
  if (timestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    return true;
  }

  timestamps.push(now);
  ipRequestHistory.set(ip, timestamps);
  return false;
}

async function isRateLimited(ip) {
  if (upstashRedis) {
    try {
      const key = `ratelimit:lead:${ip}`;
      const count = await upstashRedis.incr(key);
      if (count === 1) {
        await upstashRedis.expire(key, RATE_LIMIT_WINDOW_SECS);
      }
      return count > RATE_LIMIT_MAX_REQUESTS;
    } catch (err) {
      console.warn('Upstash Redis check failed, falling back to local memory limiter:', err.message);
    }
  }
  return isInMemoryRateLimited(ip);
}

// Zod Input Validation Schema matching Step 3 DB constraints
const LeadSchema = z.object({
  name: z.string({ message: 'Name is required' })
    .trim()
    .min(2, 'Name must be at least 2 characters')
    .max(100, 'Name must not exceed 100 characters'),
  phone: z.string({ message: 'Phone number is required' })
    .trim()
    .min(7, 'Phone number must be at least 7 characters')
    .max(30, 'Phone number must not exceed 30 characters'),
  email: z.string()
    .trim()
    .max(255, 'Email cannot exceed 255 characters')
    .email('Invalid email address format')
    .optional()
    .nullable()
    .or(z.literal('')),
  services: z.string()
    .trim()
    .max(200, 'Services string must not exceed 200 characters')
    .optional()
    .nullable()
    .or(z.literal('')),
  details: z.string()
    .trim()
    .max(2000, 'Details must not exceed 2000 characters')
    .optional()
    .nullable()
    .or(z.literal('')),
  turnstileToken: z.string({ message: 'Turnstile verification token is required' })
    .min(1, 'Security verification required'),
  botTrap: z.string().optional() // Honeypot field
});

// Cloudflare Turnstile Token Verification
async function verifyTurnstile(token, remoteIp) {
  return new Promise((resolve) => {
    // If running in development/test with test key, bypass network if desired or query siteverify
    const postData = new URLSearchParams({
      secret: TURNSTILE_SECRET_KEY,
      response: token,
      ...(remoteIp ? { remoteip: remoteIp } : {})
    }).toString();

    const options = {
      hostname: 'challenges.cloudflare.com',
      port: 443,
      path: '/turnstile/v0/siteverify',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 5000
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          resolve(parsed);
        } catch (e) {
          resolve({ success: false, 'error-codes': ['parse_error'] });
        }
      });
    });

    req.on('error', (err) => {
      console.error('Turnstile verification error:', err);
      // Fail closed on security verification
      resolve({ success: false, 'error-codes': ['network_error'] });
    });

    req.on('timeout', () => {
      req.destroy();
      resolve({ success: false, 'error-codes': ['timeout'] });
    });

    req.write(postData);
    req.end();
  });
}

// Supabase Lead Insertion
async function insertLeadToSupabase(leadRecord) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(leadRecord);
    const parsedUrl = new URL(`${SUPABASE_URL}/rest/v1/project_leads`);

    const options = {
      hostname: parsedUrl.hostname,
      port: 443,
      path: parsedUrl.pathname,
      method: 'POST',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal',
        'Content-Length': Buffer.byteLength(postData)
      },
      timeout: 8000
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ success: true });
        } else {
          resolve({ success: false, statusCode: res.statusCode, error: body });
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Supabase request timed out'));
    });

    req.write(postData);
    req.end();
  });
}

// Standard JSON response helper with security headers
function createResponse(statusCode, body) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin',
      'Cache-Control': 'no-store, max-age=0'
    },
    body: JSON.stringify(body)
  };
}

exports.handler = async (event) => {
  // Only allow POST
  if (event.httpMethod !== 'POST') {
    return createResponse(405, { error: 'Method Not Allowed. Only POST is supported.' });
  }

  // 1. IP extraction & Rate Limiting
  // Read client IP strictly from Netlify's trusted proxy header (x-nf-client-connection-ip).
  // NEVER read X-Forwarded-For to prevent IP spoofing!
  const clientIp = event.headers['x-nf-client-connection-ip'] ||
                   (process.env.NODE_ENV === 'test' ? (event.headers['x-test-client-ip'] || event.headers['client-ip'] || '127.0.0.1') : 'unknown');

  if (clientIp !== 'unknown' && (await isRateLimited(clientIp))) {
    return createResponse(429, {
      error: 'Too many requests. Please wait a few minutes before submitting another brief.'
    });
  }

  // 2. Parse JSON body
  let rawBody;
  try {
    rawBody = JSON.parse(event.body || '{}');
  } catch (err) {
    return createResponse(400, { error: 'Malformed JSON payload.' });
  }

  // 3. Honeypot check (Silent rejection if filled by automated spam bots)
  if (rawBody.botTrap && rawBody.botTrap.trim() !== '') {
    // Return fake success to confuse the bot without writing to DB
    return createResponse(200, { success: true, message: 'Received' });
  }

  // 4. Validate schema with Zod
  const validationResult = LeadSchema.safeParse(rawBody);
  if (!validationResult.success) {
    const issues = validationResult.error.issues || validationResult.error.errors || [];
    const errorMessages = issues.map(e => `${e.path.join('.')}: ${e.message}`).join(', ');
    return createResponse(400, { error: `Validation error: ${errorMessages}` });
  }

  const validated = validationResult.data;

  // 5. Verify Cloudflare Turnstile token
  const turnstileCheck = await verifyTurnstile(validated.turnstileToken, clientIp);
  if (!turnstileCheck.success) {
    return createResponse(403, {
      error: 'Security verification failed. Please refresh and try again.',
      details: turnstileCheck['error-codes']
    });
  }

  // 6. Insert lead into Supabase
  try {
    const dbPayload = {
      name: validated.name,
      phone: validated.phone,
      email: validated.email ? validated.email : null,
      services: validated.services ? validated.services : null,
      details: validated.details ? validated.details : null
    };

    const dbResult = await insertLeadToSupabase(dbPayload);
    if (!dbResult.success) {
      console.error('Supabase DB error:', dbResult.statusCode, dbResult.error);
      return createResponse(502, {
        error: 'Database service was unable to save the brief. Please retry shortly.'
      });
    }

    return createResponse(201, {
      success: true,
      message: 'Project brief submitted successfully.'
    });
  } catch (dbErr) {
    console.error('Backend submission exception:', dbErr);
    return createResponse(500, {
      error: 'Internal service error while processing submission.'
    });
  }
};
