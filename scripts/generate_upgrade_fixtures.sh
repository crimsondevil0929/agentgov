#!/usr/bin/env bash
# Write tests/fixtures/upgrades/: a ledger as every released version wrote it.
#
# Each release's source is checked out into a scratch worktree and put first
# on PYTHONPATH, and scripts/write_upgrade_fixture.py writes a SQLite ledger
# with it, recording what that release itself read back. For the releases
# with a PostgreSQL store (0.3.0, 0.4.0) it also writes a schema in a fresh
# database and dumps it as SQL. tests/test_upgrades.py opens every fixture
# with this checkout, upgrades it, and checks it still reads back the same.
#
#   PG_CONTAINER=<docker container running PostgreSQL> \
#   PG_DSN=postgresql://user:password@localhost:<port> \
#   scripts/generate_upgrade_fixtures.sh
#
# The fixtures are committed; re-run this only to add a release.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
out="$here/tests/fixtures/upgrades"
work="$(mktemp -d)"
trap 'git -C "$here" worktree prune; rm -rf "$work"' EXIT
python="${PYTHON:-$here/.venv/bin/python}"
mkdir -p "$out"

# release   revision  postgres?
releases=(
  "0.1.0 v0.1.0 no"
  "0.1.1 v0.1.1 no"
  "0.1.2 v0.1.2 no"
  "0.2.0 v0.2.0 no"
  "0.2.1 v0.2.1 no"
  "0.3.0 263892e yes"
  "0.4.0 7bb97a8 yes"
)

for release in "${releases[@]}"; do
  read -r version revision with_pg <<<"$release"
  tree="$work/$version"
  git -C "$here" worktree add --quiet --detach "$tree" "$revision"
  rm -f "$out/v$version.db"
  args=("$out/v$version.db")
  if [ "$with_pg" = yes ]; then
    database="fixture_${version//./_}"
    docker exec "$PG_CONTAINER" psql -q -U "${PG_USER:-agentgov_admin}" -d postgres \
      -c "DROP DATABASE IF EXISTS $database" -c "CREATE DATABASE $database"
    args+=("$PG_DSN/$database" "fixture")
  fi
  (cd "$work" && PYTHONPATH="$tree/src" "$python" "$here/scripts/write_upgrade_fixture.py" "${args[@]}") \
    >"$out/v$version.json"
  if [ "$with_pg" = yes ]; then
    # Plain INSERTs, and no psql meta-commands, so a driver can replay it.
    docker exec "$PG_CONTAINER" pg_dump -U "${PG_USER:-agentgov_admin}" --schema=fixture \
      --no-owner --no-privileges --inserts "$database" | grep -v '^\\' >"$out/v$version.pg.sql"
    docker exec "$PG_CONTAINER" psql -q -U "${PG_USER:-agentgov_admin}" -d postgres \
      -c "DROP DATABASE $database"
  fi
  rm -f "$out/v$version.db-wal" "$out/v$version.db-shm" "$out/v$version.db.lock"
  git -C "$here" worktree remove --force "$tree"
  echo "wrote v$version: $(cat "$out/v$version.json")"
done
