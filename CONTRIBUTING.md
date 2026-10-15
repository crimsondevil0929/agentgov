# Contributing to AgentGov

Thanks for considering a contribution. AgentGov is a financial control plane
— correctness, auditability, and test coverage matter more here than in most
projects, so this guide is a little stricter than usual.

## Ground rules

- **This is a financial and safety-critical library.** Changes to `core.py`
  (the ledger, `BudgetManager`), `cognitive.py` (the loop detectors), or
  `interceptor.py` (the authorize/capture lifecycle) need tests that prove
  the invariant you touched still holds — not just that the happy path works.
- **Zero runtime dependencies is a design constraint, not an accident.**
  New functionality in `src/agentgov/` must not add a runtime dependency.
  The optional `ui` extra (Streamlit dashboard) is the one sanctioned
  exception, and it lives outside the core import graph.
- **Money is `Decimal`, never `float`.** Every monetary value in the
  codebase is `decimal.Decimal`, quantized via `agentgov.core.money()`. A
  PR introducing `float` arithmetic on currency will be rejected.
- **Additive over invasive.** Prefer new modules and opt-in parameters over
  changing the default behavior of `Ledger`, `BudgetManager`, `Interceptor`,
  or the cognitive breaker. If a change isn't additive, say so explicitly in
  the PR description and explain why it's necessary.

## Getting set up

AgentGov uses [uv](https://docs.astral.sh/uv/) for dependency management.

```bash
git clone https://github.com/crimsondevil0929/agentgov.git
cd agentgov
uv sync --all-extras   # installs dev tools + the optional Streamlit UI extra
```

## Running the test suite

```bash
uv run pytest -v                                       # full suite
uv run pytest -v --cov=agentgov --cov-report=term-missing  # with coverage
uv run coverage report --fail-under=95                 # the CI floor
```

Run a single file or test while iterating:

```bash
uv run pytest tests/test_cognitive_breaker.py -v
uv run pytest tests/test_cognitive_breaker.py::test_near_duplicate_detector -v
```

The PostgreSQL tests run when `AGENTGOV_TEST_POSTGRES_DSN` names a server and a
role that may create databases and roles (each test gets a database of its own),
and are skipped otherwise; `AGENTGOV_REQUIRE_POSTGRES=1` makes a missing server a
failure instead:

```bash
docker run -d --name agentgov-pg -e POSTGRES_PASSWORD=agentgov -p 5432:5432 postgres:16
AGENTGOV_TEST_POSTGRES_DSN=postgresql://postgres:agentgov@localhost:5432/postgres \
  AGENTGOV_REQUIRE_POSTGRES=1 uv run pytest
```

## Mutation testing

`scripts/mutate.py` changes one thing at a time in the functions a spec under
`mutation/` names (a comparison turned around, a guard removed, a state update
dropped) and runs the spec's tests against each change. Every mutant must be
killed by a test, or named in the spec's `equivalent` table with the reason no
test can tell it apart from the original. A change to one of those functions
that leaves a mutant alive needs a test, or a reason:

```bash
uv run python scripts/mutate.py mutation/phase2.json --jobs 8      # the rule engine
uv run python scripts/mutate.py mutation/phase6-ledger.json --only BudgetManager.checkpoint
uv run python scripts/mutate.py mutation/phase6-receipts.json --list
uv run python scripts/mutate.py mutation/phase2.json --shard 0/3   # a third, as nightly runs it
uv run python scripts/mutate.py mutation/phase6-ledger.json --jobs 6 --timeout 900  # a busy machine
```

A spec's `recheck` names tests that bound time: a mutant they kill under the
parallel load is run again alone, and counts as killed only if they kill it
there too. The runner reads the spec and copies `src/` when it starts, but
reads `tests/` as they stand: do not edit the sources while a pass runs, and
add only tests that pass on the sources it started from (one they fail kills
every mutant after it). The nightly job runs each spec in three shards.

## The soak

`scripts/soak.py` runs governor processes against one ledger under load while
it SIGKILLs them and cuts their connections, then checks every operation a
worker saw succeed is in the ledger exactly once, the ledger verifies, the
auditor found nothing, and memory and connections stayed bounded:

```bash
uv run python scripts/soak.py --ledger postgresql://postgres:agentgov@localhost:5432/postgres --minutes 30
uv run python scripts/soak.py --ledger sqlite:///tmp/soak.db --minutes 10 --governors 1
```

## Linting and type checking

All three must pass clean before a PR is merged — this is what CI enforces:

```bash
uv run ruff check .              # lint
uv run ruff format --check .     # formatting (use `ruff format .` to fix)
uv run mypy src/                 # strict type check on the package
uv run mypy --strict tests/ examples/  # strict type check on tests/examples
```

## Verifying the demos still work

If your change touches `core.py`, `cognitive.py`, `interceptor.py`, or the
CLI, run the example scripts end to end — they're the closest thing to an
integration test this project has:

```bash
uv run python examples/denial_of_wallet_benchmark.py --seconds 1
uv run python examples/persistence_demo.py
uv run python examples/live_demo.py --out /tmp/agentgov-demo --no-color
uv run agentgov verify /tmp/agentgov-demo/governor.db
```

## Submitting a pull request

1. **Fork the repo and branch from `main`.** Use a descriptive branch name
   (`fix/reconciliation-timestamp-drift`, not `patch-1`).
2. **Write tests first, or alongside.** A PR that changes behavior in
   `core.py`, `cognitive.py`, or `interceptor.py` without a corresponding
   test change will be asked to add one before review continues.
3. **Keep commits focused.** One logical change per commit is easier to
   review and easier to revert if something's wrong.
4. **Run the full gate locally before opening the PR:**
   ```bash
   uv run ruff check . && uv run ruff format --check . && \
   uv run mypy src/ && uv run mypy --strict tests/ examples/ && \
   uv run pytest -v
   ```
5. **Describe the *why*, not just the *what*, in the PR description.** For
   changes to ledger invariants, breaker thresholds, or reconciliation
   tolerances, explain the failure mode you're fixing or the tradeoff you're
   making. "Fixes a bug" is not enough context to review a change to a
   double-entry ledger.
6. **CI must pass.** The workflow in `.github/workflows/ci.yml` runs the
   full lint/type/test/coverage gate on Python 3.11 to 3.14, on Linux and
   macOS, on free-threaded 3.14t, against PostgreSQL 14, 16, 17 and 18 and
   behind PgBouncer, plus the demo scripts end to end; Windows is reported,
   not yet required.

## Reporting bugs and requesting features

Open an issue at
[github.com/crimsondevil0929/agentgov/issues](https://github.com/crimsondevil0929/agentgov/issues).
For bugs, include:

- The AgentGov version (`python -c "import agentgov; print(agentgov.__version__)"`)
- A minimal reproduction — ideally a failing test
- What you expected vs. what happened

## Reporting security issues

**Do not open a public issue for security vulnerabilities.** See
[SECURITY.md](SECURITY.md) for the disclosure process.

## Code style notes

- Docstrings are expected on every public class, method, and function —
  this project is read as much as it's run. Follow the existing style
  (Sphinx-style `:param:`/`:returns:`/`:raises:`).
- Prefer explicit over clever. This codebase favors readable control flow
  over dense one-liners, especially anywhere money or a breaker decision
  is involved.
- New public API should be exported from the relevant module's `__all__`
  and, if broadly useful, from `agentgov/__init__.py`.

## License

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](LICENSE), the same license as the rest of the
project.
