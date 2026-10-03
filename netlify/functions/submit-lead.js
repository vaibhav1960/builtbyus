const { z } = require('zod');
const https = require('https');

// ====================================================================
// Builtbyus Studio: Serverless Lead Submission Handler
// Location: netlify/functions/submit-lead.js
//
// Flow:
// Customer -> Lead Form -> Netlify Function -> Zod Validation -> Supabase (service_role exclusively) -> Postgres
// ====================================================================

// Configuration from Environment Variables
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://nirtydxacoujcbrbztyo.supabase.co';

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
  )
}).strict().refine(data => Boolean((data.email && data.email.trim() !== '') || (data.phone && data.phone.trim() !== '')), {
  message: 'At least one contact method (email or phone) is required',
  path: ['email']
});

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

  // 3. Parse JSON body
  let rawBody;
  try {
    rawBody = JSON.parse(event.body || '{}');
  } catch (err) {
    return createResponse(400, { error: 'Malformed JSON payload.' });
  }

  // 4. Server-Side Input Validation (Zod Schema)
  const validationResult = LeadSchema.safeParse(rawBody);
  if (!validationResult.success) {
    const issues = validationResult.error.issues || validationResult.error.errors || [];
    const errorMessages = issues.map(e => `${e.path.join('.')}: ${e.message}`).join(', ');
    return createResponse(400, { error: `Validation error: ${errorMessages}` });
  }

  const validated = validationResult.data;

  // 5. Insert Lead into Supabase via service_role key exclusively
  try {
    const dbPayload = {
      name: validated.name,
      email: validated.email ? validated.email : null,
      phone: validated.phone ? validated.phone : null,
      services: validated.services ? validated.services : null,
      details: validated.details || validated.message || null
    };

    if (validated.message) {
      dbPayload.message = validated.message;
    }
    if (validated.budget) {
      dbPayload.budget = validated.budget;
    }
    if (validated.timeline) {
      dbPayload.timeline = validated.timeline;
    }

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
