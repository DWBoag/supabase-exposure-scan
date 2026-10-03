# Supabase Exposure Scan

A **single, read-only SQL query** that highlights Supabase/Postgres tables and `SECURITY DEFINER` functions worth reviewing for unintended access. No signup, extension, stored procedure, or service is required.

> **This is an exposure review, not a vulnerability verdict.** Grants and source-code patterns cannot establish whether an operation is safe for your users and tenants.

## Run it

In the **Supabase SQL Editor**, paste the entire contents of [`supabase-exposure-scan.sql`](supabase-exposure-scan.sql) and click **Run**. Or use:

```sh
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f supabase-exposure-scan.sql
```

Use a database role that can view the relevant catalog metadata. The query assumes a Supabase project with `anon` and `authenticated` PostgreSQL roles. It returns `severity`, `category`, `object`, and `detail`; an empty result means **nothing matched this scan's limited criteria**, not that the project is secure.

## What it reports

- `SECURITY DEFINER` functions, excluding trigger functions, with an effective `EXECUTE` grant **and** schema `USAGE` for `anon` or `authenticated`. The query scans user schemas but skips listed Supabase/internal schemas.
- Ordinary and partitioned **`public` tables** with RLS off and effective `SELECT`, `INSERT`, `UPDATE`, or `DELETE` grants for those roles.
- `public` tables with RLS on, **zero policies**, and a matching grant; these appear as `INFO` because ordinary row access defaults to deny.
- Heuristic flags for apparent write statements and auth/JWT references in function definitions.

The query checks **database-level reachability**. It cannot read whether the Supabase Data API is enabled or which custom schemas it exposes. A function in a non-`public` schema may be callable directly in SQL but *not* through the Data API; the result labels this distinction. Likewise, a `public` object may not have an API endpoint if the API is disabled or that schema is not exposed.

| Severity | Meaning | Next step |
| --- | --- | --- |
| **CRITICAL** | Anonymous role has a table write grant with RLS off, or can execute a function containing apparent write syntax with no detected auth/JWT reference. | Investigate promptly; reproduce with an unprivileged role and fix if unintended. |
| **HIGH** | Anonymous read/function reachability, or authenticated write reachability without a detected auth/JWT reference; includes anon functions with write syntax *and* an auth/JWT reference. | Confirm intended public access and enforce authorization. |
| **MEDIUM** | Authenticated-only read/function reachability, or an authenticated-only apparent-write function with an auth/JWT reference. | Check tenant/row-level authorization. |
| **INFO** | RLS enabled with zero policies on a granted table (default-deny for ordinary row access). | Review grants and any exceptional access paths. |

The severities are **triage priorities, not proof of exploitability or safety**. In particular, an auth/JWT reference is *not* an authorization check: it may be in a comment, unused, or implemented incorrectly. A function without detected write syntax can still write via another function, dynamic SQL, or an extension. An intentionally public marketplace listing may be a perfectly acceptable `HIGH`.

## Privacy and read-only behavior

The supplied scan is one `WITH … SELECT` statement. It queries PostgreSQL catalog metadata (`pg_proc`, `pg_namespace`, `pg_class`, `pg_policy`), obtains function definitions for pattern checks, and checks effective privileges. It issues **no DML or DDL**, never selects your application table rows, and contains **no network or telemetry call**. Its results are returned to the SQL client as normal; do not publish the resulting object names if your schema is confidential. For additional assurance, run it in a read-only transaction or with a suitably limited database role.

## Boundaries and false positives/negatives

- RLS policies **are not audited**: tables with RLS on and at least one policy are omitted, even when a policy is overly broad. Views, materialized views, foreign tables, sequences, column-specific grants, `TRUNCATE`, direct service-role access, and `SECURITY INVOKER` functions are outside scope.
- A `SECURITY DEFINER` function runs with the **function owner's** privileges; this does not unconditionally bypass RLS. Table owners normally bypass RLS unless `FORCE ROW LEVEL SECURITY` is set; roles with `BYPASSRLS` bypass it. Check the actual owner and target tables.
- Source inspection looks for common write verbs and `auth.uid()`, `auth.jwt()`, `request.jwt`, or JWT-helper names. It does **not** parse PL/pgSQL or prove that a reference guards an operation. Comments and strings can create false signals, and custom guards, sub-functions, or dynamic SQL can evade them.
- Effective grants plus schema `USAGE` do not prove that PostgREST exposes the object, that an API route accepts its signature, or that an invocation succeeds. Supabase may expose custom schemas, not necessarily only `public`; table scanning is deliberately limited to `public`.
- Role-level settings, pre-request hooks, and custom app-layer authorization are not inspected. Neither are built-in Supabase Security Advisors; use those as an additional check.

## Typical remediation (review before applying)

For a table that must not be public, remove unnecessary grants and/or enable RLS with appropriately scoped policies. For a function, restrict `EXECUTE`, use `SECURITY INVOKER` when possible, and add *verified* in-function authorization where elevated privileges are necessary. Set a safe `search_path` for `SECURITY DEFINER` functions. Do not apply blanket revocations without checking your app's dependencies.

To test this scanner against disposable local fixtures (the **test setup**, unlike the scanner, creates objects):

```sh
bash tests/run.sh
```

The test script requires local PostgreSQL utilities and permission to create/drop a throwaway database; it never connects to your Supabase project.

## References

- [Supabase: Securing your API](https://supabase.com/docs/guides/api/securing-your-api)
- [Supabase: Database Functions](https://supabase.com/docs/guides/database/functions)
- [PostgreSQL: Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)

## License

MIT. See [LICENSE](LICENSE).
