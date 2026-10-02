const { z } = require('zod');
const https = require('https');
const { Redis } = require('@upstash/redis');

// ====================================================================
// Builtbyus Studio: Serverless Lead Submission Handler
// Location: netlify/functions/submit-lead.js
//
// Architecture:
// Browser -> Netlify CDN -> Netlify Function -> Upstash Redis (Sliding Window)
// -> Cloudflare Turnstile -> Supabase (service_role exclusively) -> Postgres
// ====================================================================

// Configuration from Environment Variables
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://nirtydxacoujcbrbztyo.supabase.co';
// Cloudflare Turnstile Secret Key (Default: Cloudflare Official Test Secret Key)
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || '1x0000000000000000000000000000000AA';

// Upstash Redis Durable Rate Limiter
// Required env vars: UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
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

// Rate Limiting Policy: Max 5 submissions per 10 minutes (600 seconds)
const RATE_LIMIT_WINDOW_SECS = 10 * 60;
const RATE_LIMIT_MAX_REQUESTS = 5;

// In-Memory Sliding Window Fallback (used when Redis is not configured or unreachable)
const ipRequestHistory = new Map();

function isInMemoryRateLimited(ip) {
  const now = Date.now();
  const windowStart = now - (RATE_LIMIT_WINDOW_SECS * 1000);

  // Periodic pruning of stale IPs if map grows large
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

  const existingTimestamps = ipRequestHistory.get(ip) || [];
  const activeTimestamps = existingTimestamps.filter(ts => ts > windowStart);

  if (activeTimestamps.length >= RATE_LIMIT_MAX_REQUESTS) {
    return true;
  }

  activeTimestamps.push(now);
  ipRequestHistory.set(ip, activeTimestamps);
  return false;
}

// Durable Sliding Window Rate Limiter
async function isRateLimited(ip) {
  if (ip === 'unknown') {
    return false;
  }

  if (upstashRedis) {
    try {
      const key = `ratelimit:lead:${ip}`;
      const now = Date.now();
      const windowStart = now - (RATE_LIMIT_WINDOW_SECS * 1000);
      const member = `${now}:${Math.random().toString(36).slice(2, 9)}`;

      // Atomic sliding window pipeline via Redis Sorted Set
      const pipeline = upstashRedis.pipeline();
      // 1. Remove timestamps outside the current sliding 10-minute window
      pipeline.zremrangebyscore(key, 0, windowStart);
      // 2. Add current submission timestamp
      pipeline.zadd(key, { score: now, member });
      // 3. Count total active submissions within the window
      pipeline.zcard(key);
      // 4. Reset key TTL to ensure automatic cleanup
      pipeline.expire(key, RATE_LIMIT_WINDOW_SECS);

      const results = await pipeline.exec();
      const currentCount = typeof results[2] === 'number' ? results[2] : (Array.isArray(results) ? results[2] : 1);

      return currentCount > RATE_LIMIT_MAX_REQUESTS;
    } catch (err) {
      console.warn('Upstash Redis rate limiter error (falling back to memory):', err.message);
    }
  }

  return isInMemoryRateLimited(ip);
}

// Allowed Enums for Budget and Timeline
const ALLOWED_BUDGETS = ['Under $5,000', '$5,000 - $10,000', '$10,000 - $25,000', '$25,000+'];
const ALLOWED_TIMELINES = ['ASAP', '1-3 months', '3-6 months', 'Flexible'];

// Zod Input Validation Schema with Strict Boundaries
const LeadSchema = z.object({
  name: z.string({ required_error: 'Name is required' })
    .trim()
    .min(1, 'Name must be at least 1 character')
    .max(100, 'Name must not exceed 100 characters'),
  email: z.preprocess(
    val => (typeof val === 'string' && val.trim() === '' ? undefined : val),
    z.string()
      .trim()
      .max(255, 'Email cannot exceed 255 characters')
      .email('Invalid email address format')
      .transform(val => val.toLowerCase())
      .optional()
      .nullable()
  ),
  phone: z.preprocess(
    val => (typeof val === 'string' && val.trim() === '' ? undefined : val),
    z.string()
      .trim()
      .min(7, 'Phone number must be at least 7 characters')
      .max(30, 'Phone number must not exceed 30 characters')
      .optional()
      .nullable()
  ),
  budget: z.preprocess(
    val => (typeof val === 'string' && val.trim() === '' ? undefined : val),
    z.enum(ALLOWED_BUDGETS, {
      errorMap: () => ({ message: 'Budget must be one of the allowed options' })
    }).optional().nullable()
  ),
  timeline: z.preprocess(
    val => (typeof val === 'string' && val.trim() === '' ? undefined : val),
    z.enum(ALLOWED_TIMELINES, {
      errorMap: () => ({ message: 'Timeline must be one of the allowed options' })
    }).optional().nullable()
  ),
  message: z.preprocess(
    val => (typeof val === 'string' && val.trim() === '' ? undefined : val),
    z.string().trim().max(2000, 'Message must not exceed 2000 characters').optional().nullable()
  ),
  details: z.preprocess(
    val => (typeof val === 'string' && val.trim() === '' ? undefined : val),
    z.string().trim().max(2000, 'Details must not exceed 2000 characters').optional().nullable()
  ),
  services: z.preprocess(
    val => (typeof val === 'string' && val.trim() === '' ? undefined : val),
    z.string().trim().max(200, 'Services must not exceed 200 characters').optional().nullable()
  ),
  token: z.string().min(1, 'Turnstile token is required').optional(),
  turnstileToken: z.string().min(1, 'Turnstile token is required').optional(),
  botTrap: z.string().optional(),
  website_url: z.string().optional()
}).strict().refine(data => Boolean(data.token || data.turnstileToken), {
  message: 'Turnstile verification token is required',
  path: ['token']
}).refine(data => Boolean((data.email && data.email.trim() !== '') || (data.phone && data.phone.trim() !== '')), {
  message: 'At least one contact method (email or phone) is required',
  path: ['email']
});

// Cloudflare Turnstile Token Verification
async function verifyTurnstile(token, remoteIp) {
  return new Promise((resolve) => {
    const postData = new URLSearchParams({
      secret: TURNSTILE_SECRET_KEY,
      response: token,
      ...(remoteIp && remoteIp !== 'unknown' ? { remoteip: remoteIp } : {})
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
      console.error('Turnstile verification error:', err.message);
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

// Supabase Lead Insertion via service_role key exclusively
async function insertLeadToSupabase(leadRecord, serviceRoleKey) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify(leadRecord);
    const parsedUrl = new URL(`${SUPABASE_URL}/rest/v1/project_leads`);

    const options = {
      hostname: parsedUrl.hostname,
      port: 443,
      path: parsedUrl.pathname,
      method: 'POST',
      headers: {
        'apikey': serviceRoleKey,
        'Authorization': `Bearer ${serviceRoleKey}`,
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
          resolve({ success: true, statusCode: res.statusCode });
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
  // 1. Method check: Only allow POST
  if (event.httpMethod !== 'POST') {
    return createResponse(405, { error: 'Method Not Allowed. Only POST is supported.' });
  }

  // 2. Strict Service Role Key Check
  // The function MUST use ONLY SUPABASE_SERVICE_ROLE_KEY.
  // If not configured, fail immediately with 500 Server Configuration Error.
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!serviceRoleKey) {
    console.error('CRITICAL SECURITY CONFIGURATION ERROR: SUPABASE_SERVICE_ROLE_KEY is missing.');
    return createResponse(500, {
      error: 'Server configuration error: Database access key is missing.'
    });
  }

  // 3. Client IP Extraction & Sliding Window Rate Limiting
  // Authoritative Netlify connection IP header (x-nf-client-connection-ip).
  // NEVER read X-Forwarded-For to prevent IP spoofing!
  const headers = event.headers || {};
  let clientIp = headers['x-nf-client-connection-ip'];

  // Test environment fallback only
  if (!clientIp && process.env.NODE_ENV === 'test') {
    clientIp = headers['x-test-client-ip'] || headers['client-ip'] || '127.0.0.1';
  }
  if (!clientIp) {
    clientIp = 'unknown';
  }

  if (await isRateLimited(clientIp)) {
    return createResponse(429, {
      error: 'Too many requests. Please wait a few minutes before submitting another brief.'
    });
  }

  // 4. Parse JSON body
  let rawBody;
  try {
    rawBody = JSON.parse(event.body || '{}');
  } catch (err) {
    return createResponse(400, { error: 'Malformed JSON payload.' });
  }

  // 5. Anti-Bot Honeypot Trap
  // Silently drop spam submissions without writing to the database
  if ((rawBody.botTrap && String(rawBody.botTrap).trim() !== '') ||
      (rawBody.website_url && String(rawBody.website_url).trim() !== '')) {
    return createResponse(200, { success: true, message: 'Received' });
  }

  // 6. Server-Side Input Validation (Zod Schema)
  const validationResult = LeadSchema.safeParse(rawBody);
  if (!validationResult.success) {
    const issues = validationResult.error.issues || validationResult.error.errors || [];
    const errorMessages = issues.map(e => `${e.path.join('.')}: ${e.message}`).join(', ');
    return createResponse(400, { error: `Validation error: ${errorMessages}` });
  }

  const validated = validationResult.data;

  // 7. Cloudflare Turnstile Verification
  const token = validated.token || validated.turnstileToken;
  const turnstileCheck = await verifyTurnstile(token, clientIp);
  if (!turnstileCheck.success) {
    return createResponse(403, {
      error: 'Security verification failed. Please refresh and try again.',
      details: turnstileCheck['error-codes']
    });
  }

  // 8. Insert Lead into Supabase via service_role key exclusively
  try {
    const dbPayload = {
      name: validated.name,
      email: validated.email ? validated.email : null,
      phone: validated.phone ? validated.phone : null,
      services: validated.services ? validated.services : null,
      details: validated.details || validated.message || null,
      message: validated.message || validated.details || null,
      budget: validated.budget || null,
      timeline: validated.timeline || null
    };

    const dbResult = await insertLeadToSupabase(dbPayload, serviceRoleKey);
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
    console.error('Backend submission exception:', dbErr.message);
    return createResponse(500, {
      error: 'Internal service error while processing submission.'
    });
  }
};
