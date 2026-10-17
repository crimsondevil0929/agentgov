"""One governor, many threads: writes, reads of history and checkpoints at once.

A store has one connection, and a transaction on it is the connection's, not
the thread's: a read made from one thread inside another's write transaction
would read inside it (on SQLite, its uncommitted rows; on PostgreSQL, it could
end it), and a checkpoint's snapshot written meanwhile would join it. Each
store holds a guard around every transaction on its connection, so threads'
writes, reads and checkpoints never share one.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.core import EntryType

POLICY = GovernancePolicy(max_calls_per_window=0, checkpoint_every=40)
WRITERS, ROUNDS = 6, 40


@pytest.fixture(params=["sqlite", "postgres"])
def opener(
    request: pytest.FixtureRequest, tmp_path: Path
) -> Iterator[Callable[..., BudgetManager]]:
    if request.param == "sqlite":
        path = str(tmp_path / "ledger.db")

        def open_sqlite(**kwargs: object) -> BudgetManager:
            return BudgetManager.open_sqlite(path, auditor=False, **kwargs)  # type: ignore[arg-type]

        yield open_sqlite
    else:
        dsn = request.getfixturevalue("pg_dsn")

        def open_postgres(**kwargs: object) -> BudgetManager:
            return BudgetManager.open_postgres(dsn, auditor=False, **kwargs)  # type: ignore[arg-type]

        yield open_postgres


def test_writes_reads_and_checkpoints_on_many_threads(
    opener: Callable[..., BudgetManager],
) -> None:
    gov = opener(policy=POLICY)
    errors: list[BaseException] = []
    try:
        gov.open_root("root", money("1000"))
        for n in range(WRITERS):
            gov.delegate("root", f"w{n}", money("10"))
        done = threading.Event()

        def write(scope: str) -> None:
            try:
                for _ in range(ROUNDS):
                    hold = gov.authorize(scope, money("0.01"))
                    gov.capture(hold, money("0.005"))
            except BaseException as exc:
                errors.append(exc)

        def read() -> None:
            try:
                while not done.is_set():
                    gov.find_entries(scope_id="w0", entry_type=EntryType.SPEND)
                    gov.entries(after=max(0, len(gov.ledger) - 30), limit=30)
                    gov.entry(1)
                    for _ in zip(range(50), gov.iter_audit_trail(), strict=False):
                        pass
            except BaseException as exc:
                errors.append(exc)

        def checkpoint() -> None:
            try:
                while not done.is_set():
                    gov.checkpoint()
            except BaseException as exc:
                errors.append(exc)

        writers = [threading.Thread(target=write, args=(f"w{n}",)) for n in range(WRITERS)]
        others = [threading.Thread(target=read), threading.Thread(target=read)]
        others.append(threading.Thread(target=checkpoint))
        for thread in [*writers, *others]:
            thread.start()
        for thread in writers:
            thread.join(120)
        done.set()
        for thread in others:
            thread.join(60)
        assert not errors, errors
        spends = gov.find_entries(entry_type=EntryType.SPEND)
        assert len(spends) == WRITERS * ROUNDS
        assert gov.available("w0") == money("10") - money("0.005") * ROUNDS
        gov.verify_integrity()
    finally:
        gov.close()
    with opener(read_only=True, verify="full") as view:
        assert len(view.find_entries(entry_type=EntryType.SPEND)) == WRITERS * ROUNDS
        view.verify_integrity()
