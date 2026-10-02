/**
 * Builtbyus Studio - Security Notice
 * 
 * Direct client-side access to Supabase has been removed in accordance with the
 * hardened security architecture. All database writes are processed exclusively
 * server-side via Netlify Serverless Functions using the service_role key.
 * 
 * No Supabase credentials or database endpoints should be declared in client code.
 */
