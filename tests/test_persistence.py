"""Tests for the durable SQLite-backed store.

The claim under test: a governor's ledger, topology, control events, and
open authorizations survive a process restart bit-for-bit, and a corrupted
or tampered database file is refused rather than silently trusted. These
tests simulate a "restart" the honest way — by throwing away the in-memory
:class:`BudgetManager`/:class:`Ledger` objects entirely and constructing
fresh ones against the same database file, exactly as a new process would.
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import threading
import uuid
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from agentgov.core import (
    BudgetManager,
    Direction,
    EntryType,
    GovernancePolicy,
    Ledger,
    LedgerEntry,
    LedgerLine,
    money,
)
from agentgov.exceptions import BudgetExceededError, CircuitOpenError, LedgerIntegrityError
from agentgov.storage import SqliteStore

ZERO = Decimal("0")


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "governor.db")


# -- basic durability -------------------------------------------------------


def test_a_fresh_database_starts_empty(db_path: str) -> None:
    with BudgetManager.open_sqlite(db_path) as gov:
        assert gov.scopes() == ()
        assert len(gov.ledger) == 0


def test_state_survives_being_reopened_from_scratch(db_path: str) -> None:
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("1.00"))
        gov.delegate("root", "worker", money("0.40"))
        gov.spend("worker", money("0.05"))

    # Simulate a real restart: nothing from the first manager is reused.
    with BudgetManager.open_sqlite(db_path) as reopened:
        assert reopened.available("root") == money("0.60")
        assert reopened.available("worker") == money("0.35")
        assert reopened.node("worker").parent_id == "root"
        assert reopened.node("worker").depth == 1
        # funding(1) + allocation(2) + spend's own hold(1) + capture(2) = 6
        assert len(reopened.ledger) == 6
        reopened.verify_integrity()


def test_reopened_ledger_hash_chain_matches_the_original(db_path: str) -> None:
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("1.00"))
        gov.delegate("root", "worker", money("0.40"))
        original_head = gov.ledger.head_hash
        original_entries = gov.ledger.entries()

    with BudgetManager.open_sqlite(db_path) as reopened:
        assert reopened.ledger.head_hash == original_head
        assert reopened.ledger.entries() == original_entries


def test_control_events_survive_a_restart(db_path: str) -> None:
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("0.10"))
        gov.delegate("root", "worker", money("0.10"))
        gov.spend("worker", money("0.10"))  # drains it, trips the breaker
        assert gov.is_halted("worker")

    with BudgetManager.open_sqlite(db_path) as reopened:
        assert reopened.is_halted("worker")
        events = reopened.control_events
        assert len(events) == 1
        assert events[0].event_type == "circuit_tripped"
        assert events[0].scope_id == "worker"

        # A halted scope stays halted across the restart: the breaker did
        # not quietly reset just because the process did.
        with pytest.raises(CircuitOpenError):
            reopened.authorize("worker", money("0.00000001"))


def test_a_reset_breaker_also_survives_a_restart(db_path: str) -> None:
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("1.00"))
        gov.delegate("root", "worker", money("0.10"))
        gov.trip("worker", "manual halt")
        gov.reset("worker")

    with BudgetManager.open_sqlite(db_path) as reopened:
        assert not reopened.is_halted("worker")
        reopened.authorize("worker", money("0.01"))  # does not raise


def test_a_deep_tree_survives_a_restart(db_path: str) -> None:
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("1.00"))
        gov.delegate("root", "a", money("0.50"))
        gov.delegate("a", "b", money("0.25"))
        gov.delegate("b", "c", money("0.10"))

    with BudgetManager.open_sqlite(db_path) as reopened:
        assert reopened.ancestry("c") == ("c", "b", "a", "root")
        assert [n.scope_id for n in reopened.descendants("root")] == ["a", "b", "c"]
        assert reopened.subtree_available("root") == money("1.00")
        reopened.verify_integrity()


def test_policy_is_not_persisted_and_must_be_supplied_again(db_path: str) -> None:
    """Policy is runtime configuration, not ledger state — it is the
    caller's job to pass the same policy back in, same as any other config.
    """
    custom = GovernancePolicy(max_depth=3)
    with BudgetManager.open_sqlite(db_path, policy=custom) as gov:
        gov.open_root("root", money("1.00"))

    with BudgetManager.open_sqlite(db_path) as reopened:
        assert reopened.policy.max_depth != 3  # the default, not the custom one

    with BudgetManager.open_sqlite(db_path, policy=custom) as reopened_with_policy:
        assert reopened_with_policy.policy.max_depth == 3


# -- open authorizations: the crash-mid-call case ---------------------------


def test_an_open_authorization_survives_a_restart(db_path: str) -> None:
    """A process that dies between authorize() and capture() does not lose
    the hold: it comes back as an open authorization for the operator (or
    the caller, if it retains the id) to resolve.
    """
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("1.00"))
        gov.delegate("root", "worker", money("0.10"))
        auth = gov.authorize("worker", money("0.05"))
        auth_id = auth.authorization_id
        # No capture()/void() call: simulates the process dying mid-call.

    with BudgetManager.open_sqlite(db_path) as reopened:
        assert reopened.available("worker") == money("0.05"), "the hold is still encumbered"
        assert auth_id in reopened._open_auths
        restored = reopened._open_auths[auth_id]
        assert restored.amount == money("0.05")
        assert restored.scope_id == "worker"
        reopened.verify_integrity()

        # The operator can resolve it exactly as if nothing had happened.
        reopened.void(restored)
        assert reopened.available("worker") == money("0.10")


def test_a_captured_authorization_does_not_reappear_after_restart(db_path: str) -> None:
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("1.00"))
        gov.delegate("root", "worker", money("0.10"))
        auth = gov.authorize("worker", money("0.05"))
        gov.capture(auth, money("0.02"))

    with BudgetManager.open_sqlite(db_path) as reopened:
        assert reopened._open_auths == {}
        assert reopened.available("worker") == money("0.08")


# -- fail-closed on corruption -----------------------------------------------


def test_a_tampered_entry_refuses_to_load(db_path: str) -> None:
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("1.00"))
        gov.spend("root", money("0.25"))

    conn = sqlite3.connect(db_path)
    with conn:
        conn.execute("UPDATE entries SET amount = '999.00000000' WHERE sequence = 2")
    conn.close()

    with pytest.raises(LedgerIntegrityError, match="tampered with"):
        BudgetManager.open_sqlite(db_path)


def test_a_broken_hash_chain_refuses_to_load(db_path: str) -> None:
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("1.00"))
        gov.spend("root", money("0.25"))

    conn = sqlite3.connect(db_path)
    with conn:
        conn.execute("UPDATE entries SET prev_hash = ? WHERE sequence = 2", ("f" * 64,))
    conn.close()

    with pytest.raises(LedgerIntegrityError, match="broken chain link"):
        BudgetManager.open_sqlite(db_path)


def test_an_orphaned_open_authorization_refuses_to_load(db_path: str) -> None:
    """A hold whose ledger entry vanished is a corruption signal, not
    something to silently drop."""
    with BudgetManager.open_sqlite(db_path) as gov:
        gov.open_root("root", money("1.00"))
        gov.authorize("root", money("0.10"))

    conn = sqlite3.connect(db_path)
    with conn:
        conn.execute("UPDATE open_authorizations SET entry_id = ?", (str(uuid.uuid4()),))
    conn.close()

    with pytest.raises(LedgerIntegrityError, match="missing hold entry"):
        BudgetManager.open_sqlite(db_path)


def test_an_incompatible_schema_version_refuses_to_load(db_path: str) -> None:
    SqliteStore(db_path).close()  # create the schema

    conn = sqlite3.connect(db_path)
    with conn:
        conn.execute("UPDATE schema_meta SET value = '999' WHERE key = 'schema_version'")
    conn.close()

    with pytest.raises(LedgerIntegrityError, match="schema version"):
        SqliteStore(db_path)


def test_appending_a_duplicate_sequence_number_is_rejected(db_path: str) -> None:
    """Defense in depth: even if core.py's own bookkeeping were wrong, the
    store's PRIMARY KEY constraint is a second, independent backstop."""
    store = SqliteStore(db_path)
    ledger = Ledger(store=store)
    ledger.post([LedgerLine(EntryType.FUNDING, Direction.CREDIT, "root", money("1.00"))])
    duplicate = replace(ledger.entries()[0], entry_hash="forced-duplicate")
    with pytest.raises(LedgerIntegrityError, match="failed to durably append"):
        store.append_entries([duplicate])
    store.close()


# -- a failed durable write must not corrupt in-memory state -----------------


class _BrokenStoreAfterN:
    """Wraps a real store but fails ``append_entries`` after N successes.

    Used to simulate a disk-full / I/O-error mid-run without needing to
    actually exhaust disk space.
    """

    def __init__(self, inner: SqliteStore, fail_after: int) -> None:
        self._inner = inner
        self._fail_after = fail_after
        self._calls = 0

    def append_entries(self, entries: Sequence[LedgerEntry]) -> None:
        self._calls += 1
        if self._calls > self._fail_after:
            raise OSError("simulated disk failure")
        self._inner.append_entries(entries)

    def __getattr__(self, name: str) -> object:
        return getattr(self._inner, name)


def test_a_store_failure_leaves_the_ledger_exactly_as_it_was(db_path: str) -> None:
    real_store = SqliteStore(db_path)
    broken = _BrokenStoreAfterN(real_store, fail_after=1)
    ledger = Ledger(store=broken)  # type: ignore[arg-type]
    gov = BudgetManager(ledger=ledger, store=broken)  # type: ignore[arg-type]

    gov.open_root("root", money("1.00"))  # succeeds: call #1
    balance_before = gov.available("root")
    entries_before = len(gov.ledger)

    with pytest.raises(OSError, match="simulated disk failure"):
        gov.spend("root", money("0.10"))  # fails durably on call #2

    assert gov.available("root") == balance_before, "in-memory balance did not move"
    assert len(gov.ledger) == entries_before, "no partial entry was appended"
    gov.verify_integrity()
    real_store.close()


def test_a_failed_settlement_leaves_the_hold_open_not_orphaned(db_path: str) -> None:
    """If capture()'s durable write fails, the authorization must remain in
    the open set — recoverable — rather than vanishing with the money stuck.
    """
    real_store = SqliteStore(db_path)
    ledger = Ledger(store=real_store)
    gov = BudgetManager(ledger=ledger, store=real_store)
    gov.open_root("root", money("1.00"))
    gov.delegate("root", "worker", money("0.10"))
    auth = gov.authorize("worker", money("0.05"))

    broken = _BrokenStoreAfterN(real_store, fail_after=0)
    gov._ledger._store = broken  # type: ignore[assignment]

    with pytest.raises(OSError, match="simulated disk failure"):
        gov.capture(auth, money("0.02"))

    assert auth.authorization_id in gov._open_auths, "the hold was not silently dropped"
    assert gov.available("worker") == money("0.05"), "balance still reflects the open hold"
    real_store.close()


# -- concurrency still holds with a real store on the write path ------------


def test_concurrency_guarantees_hold_with_persistence_enabled(db_path: str) -> None:
    """The double-spend guarantee must not regress when writes go to disk."""
    unit = money("0.01")
    workers = 32
    affordable = 12

    policy = GovernancePolicy(
        trip_on_overdraft=False, trip_on_exhaustion=False, max_calls_per_window=0
    )
    with BudgetManager.open_sqlite(db_path, policy=policy) as gov:
        gov.open_root("root", unit * affordable)
        barrier = threading.Barrier(workers)

        def attempt(_: int) -> bool:
            barrier.wait()
            try:
                gov.spend("root", unit)
            except BudgetExceededError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=workers) as pool:
            wins = sum(pool.map(attempt, range(workers)))

        assert wins == affordable
        assert gov.available("root") == ZERO
        gov.verify_integrity()

    with BudgetManager.open_sqlite(db_path) as reopened:
        spends = [e for e in reopened.audit_trail("root") if e.entry_type is EntryType.SPEND]
        assert len(spends) == affordable
        assert sum((e.amount for e in spends), ZERO) == unit * affordable
        reopened.verify_integrity()


# -- in-memory store parity: no store means no persistence, cleanly --------


def test_an_in_memory_sqlite_store_does_not_survive_a_reconnect() -> None:
    """ ":memory:" is for tests that want store *behavior* without files —
    it is explicitly documented not to survive a restart, and this proves
    that claim rather than asserting it only in a docstring."""
    with BudgetManager.open_sqlite(":memory:") as gov:
        gov.open_root("root", money("1.00"))
        assert gov.available("root") == money("1.00")

    with BudgetManager.open_sqlite(":memory:") as fresh:
        assert fresh.scopes() == ()


def test_a_plain_budget_manager_has_no_store_and_needs_none() -> None:
    gov = BudgetManager()
    assert gov.store is None
    assert gov.ledger.store is None
    gov.open_root("root", money("1.00"))
    gov.close()  # a no-op; must not raise


def test_the_persistence_demo_script_runs_and_proves_its_own_claim() -> None:
    """Smoke-test examples/persistence_demo.py so it cannot rot.

    It asserts internally (via verify_integrity() inside the reader process)
    that the restored state checks out, so a clean exit is a real check.
    """
    script = Path(__file__).resolve().parent.parent / "examples" / "persistence_demo.py"
    assert script.is_file(), f"demo not found at {script}"

    result = subprocess.run(  # noqa: S603
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, f"demo failed:\n{result.stdout}\n{result.stderr}"
    assert "READER  verify_integrity() = PASS" in result.stdout
    assert "READER  halted(scraper)=True" in result.stdout
    assert "READER  open_authorizations=1" in result.stdout
