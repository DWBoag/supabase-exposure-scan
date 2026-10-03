-- Supabase Exposure Scan
-- Run in the Supabase SQL Editor or with: psql "$DATABASE_URL" -f supabase-exposure-scan.sql
-- SELECT only: reads PostgreSQL catalog metadata and privilege flags; does not read user rows.
-- Assumes the Supabase roles anon and authenticated exist.
-- This reports database grants + schema USAGE. API exposure depends additionally on
-- your Data API being enabled and the schema being in its configured exposed schemas.
-- Auth/JWT references and write statements are HEURISTICS, not proof of safety or harm.

WITH
functions AS (
  SELECT p.oid,
         n.nspname AS schema_name,
         p.proname AS function_name,
         pg_get_function_identity_arguments(p.oid) AS arguments,
         has_function_privilege('anon', p.oid, 'EXECUTE')
           AND has_schema_privilege('anon', n.oid, 'USAGE') AS anon_exec,
         has_function_privilege('authenticated', p.oid, 'EXECUTE')
           AND has_schema_privilege('authenticated', n.oid, 'USAGE') AS auth_exec
  FROM pg_catalog.pg_proc AS p
  JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
  WHERE p.prosecdef
    AND p.prokind = 'f'
    AND p.prorettype <> 'pg_catalog.trigger'::regtype
    AND n.nspname !~ '^pg_'
    AND n.nspname NOT IN (
      'information_schema', 'extensions', 'pgbouncer', 'graphql',
      'graphql_public', 'realtime', 'storage', 'vault', 'auth', 'net',
      'cron', 'supabase_functions', 'supabase_migrations'
    )
),
function_flags AS (
  SELECT f.*,
         pg_catalog.pg_get_functiondef(f.oid) ~*
           '(\minsert\s+into\M|\mupdate\M[^;]*\mset\M|\mdelete\s+from\M|\mtruncate\M|\mmerge\s+into\M|\mdo\s+update\s+set\M)' AS writes,
         pg_catalog.pg_get_functiondef(f.oid) ~*
           '(auth\.uid\s*\(|auth\.jwt\s*\(|auth\.role\s*\(|auth\.email\s*\(|request\.jwt|current_setting\s*\(\s*''request\.jwt|fn_jwt|_jwt|jwt_)' AS auth_reference
  FROM functions AS f
  WHERE f.anon_exec OR f.auth_exec
),
function_findings AS (
  SELECT CASE
           WHEN anon_exec AND writes AND NOT auth_reference THEN 'CRITICAL'
           WHEN anon_exec THEN 'HIGH'
           WHEN auth_exec AND writes AND NOT auth_reference THEN 'HIGH'
           ELSE 'MEDIUM'
         END AS severity,
         'FUNCTION' AS category,
         format('%I.%I(%s)', schema_name, function_name, arguments) AS object,
         concat_ws('; ',
           'database-callable by ' || concat_ws(', ',
             CASE WHEN anon_exec THEN 'anon' END,
             CASE WHEN auth_exec THEN 'authenticated' END),
           CASE WHEN writes THEN 'write syntax detected' ELSE 'no write syntax detected' END,
           CASE WHEN auth_reference THEN 'auth/JWT reference seen (NOT verified)'
                ELSE 'NO auth/JWT reference detected' END,
           CASE WHEN schema_name <> 'public' THEN 'non-public schema: API exposure unknown' END
         ) AS detail
  FROM function_flags
),
tables AS (
  SELECT c.oid, c.relname AS table_name, c.relrowsecurity AS rls_on,
         (SELECT count(*) FROM pg_catalog.pg_policy AS pol WHERE pol.polrelid = c.oid) AS policy_count,
         has_schema_privilege('anon', n.oid, 'USAGE')
           AND has_table_privilege('anon', c.oid, 'SELECT') AS anon_read,
         has_schema_privilege('anon', n.oid, 'USAGE')
           AND (has_table_privilege('anon', c.oid, 'INSERT')
                OR has_table_privilege('anon', c.oid, 'UPDATE')
                OR has_table_privilege('anon', c.oid, 'DELETE')) AS anon_write,
         has_schema_privilege('authenticated', n.oid, 'USAGE')
           AND has_table_privilege('authenticated', c.oid, 'SELECT') AS auth_read,
         has_schema_privilege('authenticated', n.oid, 'USAGE')
           AND (has_table_privilege('authenticated', c.oid, 'INSERT')
                OR has_table_privilege('authenticated', c.oid, 'UPDATE')
                OR has_table_privilege('authenticated', c.oid, 'DELETE')) AS auth_write
  FROM pg_catalog.pg_class AS c
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p') AND n.nspname = 'public'
),
table_findings AS (
  SELECT CASE
           WHEN NOT rls_on AND anon_write THEN 'CRITICAL'
           WHEN NOT rls_on AND (anon_read OR auth_write) THEN 'HIGH'
           WHEN NOT rls_on AND auth_read THEN 'MEDIUM'
           WHEN rls_on AND policy_count = 0 THEN 'INFO'
         END AS severity,
         'TABLE' AS category,
         format('public.%I', table_name) AS object,
         concat_ws('; ',
           CASE WHEN rls_on THEN 'RLS on; default-deny (no policies)'
                ELSE 'RLS OFF' END,
           'policies=' || policy_count,
           'database grants: ' || concat_ws(', ',
             CASE WHEN anon_read THEN 'anon:read' END,
             CASE WHEN anon_write THEN 'anon:write' END,
             CASE WHEN auth_read THEN 'authenticated:read' END,
             CASE WHEN auth_write THEN 'authenticated:write' END)
         ) AS detail
  FROM tables
  WHERE (anon_read OR anon_write OR auth_read OR auth_write)
    AND (NOT rls_on OR policy_count = 0)
),
all_findings AS (
  SELECT * FROM function_findings
  UNION ALL
  SELECT * FROM table_findings
)
SELECT severity, category, object, detail
FROM all_findings
ORDER BY CASE severity
           WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
           WHEN 'MEDIUM' THEN 2 WHEN 'INFO' THEN 3 ELSE 4 END,
         category, object;
