#!/usr/bin/env bash
# Runs the migrations + SQL tests against a throwaway local PostgreSQL 16 cluster.
# NOTE: this is vanilla Postgres with a small Supabase stub (supabase/tests/00_supabase_stub.sql).
# It is NOT a test against Supabase. Run the same migrations on a real project before trusting them there.
set -euo pipefail

PGBIN="${PGBIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
PORT="${PGTEST_PORT:-54329}"
RUN_AS=""

# Postgres refuses to run as root; fall back to the first regular (non-root) user.
if [ "$(id -u)" = "0" ]; then
  PG_USER="${PGTEST_USER:-$(getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}')}"
  [ -n "$PG_USER" ] || { echo "run as a non-root user, or set PGTEST_USER"; exit 1; }
  chown "$PG_USER" "$WORK"
  RUN_AS="runuser -u $PG_USER --"
fi

cleanup() { $RUN_AS "$PGBIN/pg_ctl" -D "$WORK/data" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

$RUN_AS "$PGBIN/initdb" -D "$WORK/data" -A trust -U postgres >/dev/null
$RUN_AS "$PGBIN/pg_ctl" -D "$WORK/data" -o "-p $PORT -k $WORK -c listen_addresses=''" -l "$WORK/pg.log" -w start >/dev/null

PSQL=( $RUN_AS psql -h "$WORK" -p "$PORT" -U postgres -v ON_ERROR_STOP=1 -X -q )
"${PSQL[@]}" -c "create database karlion_test" >/dev/null
PSQL+=( -d karlion_test )

"${PSQL[@]}" -f "$ROOT/supabase/tests/00_supabase_stub.sql"
for f in "$ROOT"/supabase/migrations/*.sql; do
  echo "applying $(basename "$f")"
  "${PSQL[@]}" -f "$f"
done
"${PSQL[@]}" -f "$ROOT/supabase/tests/10_phase1_rls_and_logic.sql" 2>&1 | grep -E "PASS|FAIL|ALL DATABASE|ERROR" | sed 's/^psql:[^ ]* //; s/^NOTICE:  //'
