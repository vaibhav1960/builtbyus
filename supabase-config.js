/**
 * Builtbyus Studio - Supabase Integration Configuration
 * 
 * SETUP INSTRUCTIONS:
 * 1. Go to https://supabase.com and create a free project.
 * 2. In your Supabase Dashboard, go to "Project Settings" -> "API".
 * 3. Copy your "Project URL" and paste it into `url` below.
 * 4. Copy your "anon" / "public" key and paste it into `anonKey` below.
 * 5. Run the SQL schema in Supabase SQL Editor to create the `project_leads` table.
 */

window.BUILTBYUS_SUPABASE = {
  // Replace with your Supabase Project URL: e.g. "https://xxxxxxxxxxx.supabase.co"
  url: "https://nirtydxacoujcbrbztyo.supabase.co",

  // Replace with your Supabase Public Anon Key: e.g. ""
  anonKey: "sb_publishable_jx24CpGpzelYvZ8PeKHmiA_N5a1FWp7",

  // Table where lead submissions will be saved
  table: "project_leads"
};
