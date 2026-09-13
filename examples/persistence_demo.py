#!/usr/bin/env python3
"""Demonstrates that a SQLite-backed governor survives a real process exit.

This does not simulate a restart by discarding a Python object — it forks a
genuinely separate child process to write the initial state, lets that
process exit completely, then opens a second, independent process against
the same database file and proves every figure (balances, hash chain, an
open authorization mid-call, and a latched circuit breaker) came back
exactly as it was left.

Usage::

    uv run python examples/persistence_demo.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

_WRITER = """
import sys
from agentgov import BudgetManager, money

with BudgetManager.open_sqlite(sys.argv[1]) as gov:
    gov.open_root("orchestrator", money("5.00"))
    gov.delegate("orchestrator", "researcher", money("1.00"))
    gov.delegate("orchestrator", "scraper", money("0.02"))

    gov.spend("researcher", money("0.30"))

    # Leave one call mid-flight, as if this process died before capture().
    auth = gov.authorize("researcher", money("0.05"))

    # Drain the scraper's tiny sub-budget until the breaker latches.
    try:
        while True:
            gov.spend("scraper", money("0.01"))
    except Exception:
        pass

print(f"WRITER  balance(researcher)={gov.available('researcher')}", flush=True)
print(f"WRITER  halted(scraper)={gov.is_halted('scraper')}", flush=True)
print(f"WRITER  chain_length={len(gov.ledger)}", flush=True)
print(f"WRITER  open_authorization_id={auth.authorization_id}", flush=True)
"""

_READER = """
import sys
from agentgov import BudgetManager
from agentgov.exceptions import CircuitOpenError

with BudgetManager.open_sqlite(sys.argv[1]) as gov:
    gov.verify_integrity()
    print("READER  verify_integrity() = PASS", flush=True)
    print(f"READER  balance(researcher)={gov.available('researcher')}", flush=True)
    print(f"READER  halted(scraper)={gov.is_halted('scraper')}", flush=True)
    print(f"READER  chain_length={len(gov.ledger)}", flush=True)
    print(f"READER  open_authorizations={len(gov._open_auths)}", flush=True)

    try:
        gov.authorize("scraper", "0.00000001")
    except CircuitOpenError as exc:
        print(f"READER  scraper still refuses calls: {exc}", flush=True)
"""


def run(script: str, db_path: str, label: str) -> None:
    print(f"\n--- {label} (separate `python` process, pid to follow) ---", flush=True)
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script, db_path],
        capture_output=True,
        text=True,
        check=True,
    )
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, file=sys.stderr, end="")


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = str(Path(tmp) / "governor.db")

        run(_WRITER, db_path, "process 1: writes state, then exits completely")
        run(_READER, db_path, "process 2: independent interpreter, same file")

        print(
            "\nEvery figure above was read by a process that never held the "
            "first process's Python objects — only the file on disk."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
