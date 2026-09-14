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
   full lint/type/test/coverage gate on Python 3.11 and 3.12, on Linux and
   macOS, plus the demo scripts end to end.

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
