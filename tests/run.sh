#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
db="exposure_scan_test_${$}"
if psql -d postgres -Atqc 'SELECT 1' >/dev/null 2>&1; then
  admin=( )
elif command -v sudo >/dev/null && sudo -n -u postgres psql -d postgres -Atqc 'SELECT 1' >/dev/null 2>&1; then
  admin=(sudo -n -u postgres)
else
  echo 'Need a local PostgreSQL admin connection (psql or passwordless sudo -u postgres).' >&2
  exit 1
fi
psql_admin() { "${admin[@]}" psql -X "$@"; }
createdb_admin() { "${admin[@]}" createdb "$@"; }
dropdb_admin() { "${admin[@]}" dropdb "$@"; }

for role in anon authenticated; do
  if [[ "$(psql_admin -d postgres -Atqc "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = '$role')")" == t ]]; then
    echo "Local role '$role' already exists; refusing to change or drop it." >&2
    exit 1
  fi
done

cleanup() {
  dropdb_admin --if-exists "$db" >/dev/null 2>&1 || true
  psql_admin -d postgres -v ON_ERROR_STOP=1 -qc 'DROP ROLE IF EXISTS anon, authenticated' >/dev/null 2>&1 || true
}
trap cleanup EXIT
createdb_admin "$db"
psql_admin -d "$db" -v ON_ERROR_STOP=1 < "$root/tests/fixtures.sql" >/dev/null
output="$(
  { printf 'BEGIN READ ONLY;\n'; cat "$root/supabase-exposure-scan.sql"; printf '\nCOMMIT;\n'; } |
    psql_admin -d "$db" -v ON_ERROR_STOP=1 -A -t -F '|'
)"

printf '%s\n' "$output"
printf '%s\n' "$output" | grep -q '^CRITICAL|FUNCTION|public.unsafe_write()|'
printf '%s\n' "$output" | grep -q '^CRITICAL|TABLE|public.open_write|'
printf '%s\n' "$output" | grep -q '^HIGH|TABLE|public.open_read|'
printf '%s\n' "$output" | grep -q '^MEDIUM|TABLE|public.member_read|'
printf '%s\n' "$output" | grep -q '^MEDIUM|FUNCTION|public.member_function()|'
printf '%s\n' "$output" | grep -q '^INFO|TABLE|public.default_deny|'
printf '%s\n' "$output" | grep -q '^HIGH|FUNCTION|public.auth_reference_only()|.*NOT verified'
if printf '%s\n' "$output" | grep -qE 'public.has_policy|private.hidden'; then
  echo 'Protected table or inaccessible function was included.' >&2
  exit 1
fi
echo 'All scanner smoke tests passed.'
