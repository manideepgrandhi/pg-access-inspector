#!/usr/bin/env bash
# Runs the test suite against a throwaway PostgreSQL cluster.
#   PG_BINDIR=/usr/lib/postgresql/17/bin tests/run_tests.sh
# Never points at an existing server: it creates, uses and deletes its own.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
PG_BINDIR=${PG_BINDIR:-$(pg_config --bindir)}
for tool in initdb pg_ctl postgres; do
  [[ -x "$PG_BINDIR/$tool" ]] || { echo "Missing $PG_BINDIR/$tool: install the PostgreSQL server or set PG_BINDIR" >&2; exit 1; }
done
command -v psql >/dev/null || { echo "psql not found" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }

PORT=${PGIT_PORT:-55432}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/pg-access-inspector.XXXXXX")
cleanup() {
  "$PG_BINDIR/pg_ctl" -D "$TMP/data" -m immediate stop >/dev/null 2>&1 || true
  rm -rf -- "$TMP"
}
trap cleanup EXIT

"$PG_BINDIR/initdb" -D "$TMP/data" -U postgres --no-locale -E UTF8 \
  --auth-local=trust --auth-host=reject >"$TMP/initdb.log"
"$PG_BINDIR/pg_ctl" -D "$TMP/data" -l "$TMP/server.log" -w \
  -o "-k '$TMP' -p $PORT -c listen_addresses=''" start >/dev/null

export PGHOST="$TMP" PGPORT="$PORT" PGUSER=postgres PGDATABASE=postgres PGTZ=UTC
unset PGHOSTADDR PGSERVICE PGSERVICEFILE PGOPTIONS PGPASSWORD
export PAI_ISOLATED_TEST_CLUSTER=1 PAI_ROOT="$ROOT"

psql -X -At -c 'SELECT version()'
psql -X -q -v ON_ERROR_STOP=1 -f "$ROOT/tests/fixture.sql" >/dev/null
psql -X -q -v ON_ERROR_STOP=1 -d inspector_test -f "$ROOT/install.sql" >/dev/null

if [[ "${1:-}" == "--shell" ]]; then
  echo "Cluster is up: PGHOST=$PGHOST PGPORT=$PGPORT (exit the shell to stop it)"
  PGDATABASE=inspector_test bash -i
  exit 0
fi
if [[ "${1:-}" == "--examples" ]]; then
  PGDATABASE=inspector_test bash "$ROOT/tests/make_examples.sh"
  exit 0
fi
python3 "$ROOT/tests/test_inspector.py" -v
