#!/usr/bin/env bash
# Run Interlock's test suite against this agentgov checkout.
#
# Interlock is agentgov's main downstream consumer. This copies its source
# into a work directory (so the Interlock checkout is never written to),
# builds a virtual environment with this checkout of agentgov installed in
# place of the released one, and runs Interlock's tests there.
#
#   scripts/downstream_interlock.sh <interlock-dir> [pytest args...]
#
# Environment:
#   WORKDIR                      where to build (default: a fresh temp dir)
#   PYTHON                       interpreter version for uv (default: 3.12)
#   AGENTGOV_SPEC                what to install as agentgov (default: this
#                                checkout, editable); pass a wheel path to
#                                test a built release candidate instead
#   INTERLOCK_TEST_POSTGRES_DSN  run Interlock's PostgreSQL tests too
#   INTERLOCK_TEST_PGBOUNCER     and its PgBouncer tests (host:port)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
src="${1:?usage: downstream_interlock.sh <interlock-dir> [pytest args...]}"
shift
work="${WORKDIR:-$(mktemp -d)}"
python="${PYTHON:-3.12}"
spec="${AGENTGOV_SPEC:-$here}"

mkdir -p "$work"
rsync -a --delete \
  --exclude .venv --exclude .git --exclude dist --exclude __pycache__ \
  --exclude .pytest_cache --exclude .mypy_cache --exclude .ruff_cache \
  "$src/" "$work/interlock/"

if [ ! -x "$work/venv/bin/python" ]; then
  uv venv --quiet --python "$python" "$work/venv"
fi
export VIRTUAL_ENV="$work/venv"

# agentgov first, with the extras Interlock's tests use; then Interlock
# without dependencies, so the released agentgov is never pulled in.
if [ "$spec" = "$here" ]; then
  uv pip install --quiet -e "$here[postgres,sign]"
else
  uv pip install --quiet --reinstall "$spec" "psycopg[binary]>=3.2" "cryptography>=42"
fi
uv pip install --quiet --no-deps -e "$work/interlock"
uv pip install --quiet "pytest>=8.0.0" "hypothesis>=6.100" "psycopg[binary]>=3.2" \
  "cryptography>=42"

"$work/venv/bin/python" -c 'import agentgov, sys; print("agentgov", agentgov.__version__, "from", agentgov.__file__, file=sys.stderr)'
cd "$work/interlock"
exec "$work/venv/bin/python" -m pytest -p no:cacheprovider "$@"
