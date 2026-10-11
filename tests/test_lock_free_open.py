"""Opening a governor takes no writer lock (F1).

The committed prefix of a shared chain never changes, so a governor opens
from one consistent snapshot without the fleet's writer lock: it neither
waits for a governor holding the lock nor makes the fleet wait for it. The
first mutation catches up under the lock, as every mutation does. Only a
repair takes the lock, and it re-reads under it before writing.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from typing import Any

import psycopg
import pytest

from agentgov import BudgetManager, money
from agentgov.core import _Overlay
from agentgov.exceptions import StorageError
from agentgov.postgres import PostgresStore, _lock_keys
from agentgov.storage import StoreImage

pytestmark = pytest.mark.usefixtures("pg_dsn")


@pytest.fixture
def seeded(pg_dsn: str) -> Iterator[BudgetManager]:
    gov = BudgetManager.open_postgres(pg_dsn)
    gov.open_root("org", money("100"))
    gov.delegate("org", "agent", money("10"))
    try:
        yield gov
    finally:
        gov.close()


def _hold_writer_lock(dsn: str, schema: str = "agentgov") -> psycopg.Connection[Any]:
    """A raw session that takes the ledger's writer lock and keeps it."""
    conn = psycopg.connect(dsn)
    k1, k2 = _lock_keys(schema)
    conn.execute("SELECT pg_advisory_xact_lock(%s, %s)", (k1, k2))
    return conn


def test_a_governor_opens_while_another_holds_the_writer_lock(
    pg_dsn: str, seeded: BudgetManager
) -> None:
    holder = _hold_writer_lock(pg_dsn)
    try:
        started = time.monotonic()
        gov = BudgetManager.open_postgres(pg_dsn, lock_timeout=0.2)
        assert time.monotonic() - started < 5
        try:
            assert gov.available("agent") == money("10")
            with pytest.raises(StorageError, match="waiting for the writer lock"):
                gov.spend("agent", money("1"))
            assert gov.available("agent") == money("10")
        finally:
            gov.close()
    finally:
        holder.close()


def test_a_read_only_view_and_a_store_open_while_the_lock_is_held(
    pg_dsn: str, seeded: BudgetManager
) -> None:
    holder = _hold_writer_lock(pg_dsn)
    try:
        PostgresStore(pg_dsn, lock_timeout=0.2).close()
        with BudgetManager.open_postgres(pg_dsn, read_only=True) as reader:
            assert reader.available("org") == money("90")
    finally:
        holder.close()


def test_the_first_mutation_after_a_lock_free_open_catches_up(
    pg_dsn: str, seeded: BudgetManager
) -> None:
    late = BudgetManager.open_postgres(pg_dsn)
    try:
        seeded.spend("agent", money("3"))  # committed after `late` opened
        assert late.available("agent") == money("10"), "a view serves its snapshot"
        late.spend("agent", money("2"))
        assert late.available("agent") == money("5")
        assert [e.sequence for e in late.audit_trail()] == list(range(1, len(late.ledger) + 1))
        late.verify_integrity()
    finally:
        late.close()


def test_every_open_sees_one_consistent_snapshot_while_writers_commit(
    pg_dsn: str, seeded: BudgetManager
) -> None:
    stop = threading.Event()
    errors: list[BaseException] = []

    def write() -> None:
        try:
            with BudgetManager.open_postgres(pg_dsn) as writer:
                n = 0
                while not stop.is_set():
                    n += 1
                    hold = writer.authorize("agent", money("0.001"))
                    writer.capture(hold, money("0.0005"))
                    if n % 7 == 0:
                        writer.delegate("org", f"scope-{n}", money("0.01"))
        except BaseException as exc:
            errors.append(exc)

    writer = threading.Thread(target=write)
    writer.start()
    opened = 0
    try:
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with BudgetManager.open_postgres(pg_dsn) as gov:
                gov.verify_integrity()
                opened += 1
    finally:
        stop.set()
        writer.join(30)
    assert errors == []
    assert opened > 3


def test_open_applies_each_entry_once(
    pg_dsn: str, seeded: BudgetManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    for _ in range(5):
        seeded.spend("agent", money("0.01"))
    applied: list[int] = []
    original = _Overlay.apply

    def counting(self: _Overlay, entry: Any, **kwargs: Any) -> None:
        applied.append(entry.sequence)
        original(self, entry, **kwargs)

    monkeypatch.setattr(_Overlay, "apply", counting)
    with BudgetManager.open_postgres(pg_dsn) as gov:
        assert sorted(applied) == list(range(1, len(gov.ledger) + 1))


def test_a_repair_re_reads_under_the_lock_and_erases_nothing_written_since(
    pg_dsn: str, seeded: BudgetManager
) -> None:
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute("DELETE FROM agentgov.nodes WHERE scope_id = 'agent'")

    class Racing(PostgresStore):
        """Lets another governor commit between the open's snapshot and its repair."""

        raced = False

        def load(self, **kwargs: Any) -> StoreImage:
            image = super().load(**kwargs)
            if not Racing.raced:
                Racing.raced = True
                seeded.delegate("org", "late-arrival", money("1"))
            return image

    store = Racing(pg_dsn)
    try:
        gov = BudgetManager(store=store, repair=True)
        assert gov.repairs, "the missing row was found and repaired"
        assert "late-arrival" in gov.scopes(), "the repair worked from a read under the lock"
    finally:
        store.close()
    with BudgetManager.open_postgres(pg_dsn) as reopened:
        assert {"org", "agent", "late-arrival"} <= set(reopened.scopes())
        reopened.verify_integrity()


def test_a_governor_left_dirty_re_reads_before_it_takes_the_lock(
    pg_dsn: str, seeded: BudgetManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After a commit whose outcome was lost, the governor rebuilds its view
    from a snapshot at once, as an open does, before anyone reads what may
    never have committed; and the full read never runs under the fleet's
    lock. If that read fails too, the next mutation makes it, first."""
    original_end = PostgresStore._end

    def commit_then_lose_the_answer(self: PostgresStore, session: Any) -> None:
        original_end(self, session)
        session.committed = False
        raise StorageError("connection lost after COMMIT was sent")

    full_reads_under_the_lock: list[bool] = []
    original_load = PostgresStore.load

    def watched_load(self: PostgresStore, **kwargs: Any) -> StoreImage:
        full_reads_under_the_lock.append(self._session is not None)
        return original_load(self, **kwargs)

    monkeypatch.setattr(PostgresStore, "load", watched_load)
    with monkeypatch.context() as patch:
        patch.setattr(PostgresStore, "_end", commit_then_lose_the_answer)
        with pytest.raises(StorageError, match="connection lost"):
            seeded.spend("agent", money("1"))
    assert full_reads_under_the_lock == [False] and not seeded._dirty
    assert seeded.available("agent") == money("9"), "the lost commit had in fact committed"

    def unreadable(self: PostgresStore, **kwargs: Any) -> StoreImage:
        full_reads_under_the_lock.append(self._session is not None)
        raise StorageError("the database is unreachable")

    full_reads_under_the_lock.clear()
    with monkeypatch.context() as patch:
        patch.setattr(PostgresStore, "_end", commit_then_lose_the_answer)
        patch.setattr(PostgresStore, "load", unreadable)
        with pytest.raises(StorageError, match="connection lost"):
            seeded.spend("agent", money("1"))
    assert full_reads_under_the_lock == [False] and seeded._dirty
    full_reads_under_the_lock.clear()
    seeded.spend("agent", money("2"))
    assert full_reads_under_the_lock == [False]
    assert seeded.available("agent") == money("6")
    seeded.verify_integrity()
