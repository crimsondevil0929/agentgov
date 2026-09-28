"""Fleet concurrency: many governors, one ledger, not one dollar spent twice.

``test_concurrency.py`` proves one governor's lock holds against its own
threads. These prove the same properties across *governors*: separate
``BudgetManager`` instances, each with its own connection and its own memory,
sharing one PostgreSQL ledger, the way separate hosts would. Several tests use
separate processes, so nothing in-process can be what serializes them.

Every property is read back from the chain by a fresh read-only governor, not
from the workers' own bookkeeping: the point is to prove the ledger is right.
"""

from __future__ import annotations

import multiprocessing
import os
import signal
import sys
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from decimal import Decimal
from multiprocessing.queues import Queue
from multiprocessing.synchronize import Barrier, Event
from typing import TypeVar

import pytest
from psycopg import sql

from agentgov.core import BudgetManager, EntryType, GovernancePolicy, WriteBatch, money
from agentgov.exceptions import (
    AgentGovError,
    BudgetExceededError,
    DuplicateScopeError,
    LedgerIntegrityError,
    StorageError,
    SubBudgetAllocationError,
)
from agentgov.postgres import PostgresStore

pytestmark = pytest.mark.usefixtures("pg_dsn")

ZERO = Decimal("0")
T = TypeVar("T")

# Advisory mode, as in test_concurrency.py: a refusal must not halt the other
# workers, so "exactly N succeed" is a meaningful assertion.
ADVISORY = GovernancePolicy(
    trip_on_overdraft=False, trip_on_exhaustion=False, max_calls_per_window=0
)

GOVERNORS = 8
WORKERS = 64


@contextmanager
def fleet(dsn: str, size: int = GOVERNORS, **kwargs: object) -> Iterator[list[BudgetManager]]:
    """``size`` governors of one ledger, each on its own connection."""
    governors: list[BudgetManager] = []
    try:
        for _ in range(size):
            governors.append(BudgetManager.open_postgres(dsn, **kwargs))  # type: ignore[arg-type]
        yield governors
    finally:
        for governor in governors:
            governor.close()


def race(workers: int, attempt: Callable[[int], T]) -> list[T]:
    """Run ``attempt(i)`` on ``workers`` threads released at the same instant."""
    barrier = threading.Barrier(workers)

    def gated(i: int) -> T:
        barrier.wait()
        return attempt(i)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(gated, range(workers)))


def audit(dsn: str) -> BudgetManager:
    """A fresh, fully verified read of the shared ledger."""
    reader = BudgetManager.open_postgres(dsn, read_only=True)
    reader.verify_integrity()
    reader.verify_conservation()
    return reader


def audit_spend(gov: BudgetManager, scope: str) -> tuple[int, Decimal, Decimal]:
    """Settled spend read back from the chain: (count, total, lowest balance)."""
    spends = [e for e in gov.audit_trail(scope) if e.entry_type is EntryType.SPEND]
    total = sum((e.amount for e in spends), ZERO)
    lowest = min((e.balance_after for e in spends), default=ZERO)
    return len(spends), total, lowest


def assert_fleet_converges(governors: list[BudgetManager], reader: BudgetManager) -> None:
    """Every governor, caught up, serves exactly the ledger the reader verified."""
    for governor in governors:
        governor.refresh()
        assert len(governor.ledger) == len(reader.ledger)
        assert governor.ledger.head_hash == reader.ledger.head_hash
        assert governor.ledger.balances() == reader.ledger.balances()
        governor.verify_integrity()


# --------------------------------------------------------------------------
# Threads across governors
# --------------------------------------------------------------------------


def test_64_threads_on_8_governors_race_the_last_cent(pg_dsn: str) -> None:
    """Budget for exactly 25 calls, 64 workers on 8 governors. Exactly 25 win."""
    unit, affordable = money("0.02"), 25
    with fleet(pg_dsn, policy=ADVISORY) as governors:
        governors[0].open_root("root", unit * affordable)

        def attempt(i: int) -> bool:
            try:
                governors[i % GOVERNORS].spend("root", unit)
            except BudgetExceededError:
                return False
            return True

        wins = sum(race(WORKERS, attempt))

        with audit(pg_dsn) as reader:
            count, total, lowest = audit_spend(reader, "root")
            assert wins == affordable, "exactly the affordable number of calls executed"
            assert count == wins, "one ledger entry per executed call, no more"
            assert total == unit * affordable, "not one unit of double-spend"
            assert lowest >= ZERO, "the balance never went negative, even transiently"
            assert reader.available("root") == ZERO
            assert_fleet_converges(governors, reader)


def test_64_workers_holding_across_a_simulated_call_never_overcommit(pg_dsn: str) -> None:
    """Holds encumber funds fleet-wide while calls are in flight on other hosts.

    As in the single-governor version, the property is read from the chain:
    however the workers interleave, never more than ten holds are open at once.
    """
    hold, settle, capacity = money("0.05"), money("0.01"), 10
    with fleet(pg_dsn, policy=ADVISORY) as governors:
        governors[0].open_root("root", hold * capacity)

        def attempt(i: int) -> bool:
            governor = governors[i % GOVERNORS]
            try:
                auth = governor.authorize("root", hold)
            except BudgetExceededError:
                return False
            time.sleep(0.005)  # the model call is in flight; funds stay encumbered
            # Settled by a different governor than the one that placed the hold.
            governors[(i + 1) % GOVERNORS].capture(auth, settle)
            return True

        wins = sum(race(WORKERS, attempt))

        with audit(pg_dsn) as reader:
            open_now = peak = 0
            for entry in reader.audit_trail("root"):
                if entry.entry_type is EntryType.HOLD:
                    open_now += 1
                    peak = max(peak, open_now)
                elif entry.entry_type is EntryType.HOLD_VOID:
                    open_now -= 1
            count, total, lowest = audit_spend(reader, "root")
            assert 0 < peak <= capacity, "holds bounded concurrency across the fleet"
            assert open_now == 0, "every hold was released"
            assert wins >= capacity
            assert count == wins
            assert total == settle * wins
            assert lowest >= ZERO
            assert reader.available("root") == hold * capacity - total
            assert_fleet_converges(governors, reader)


def test_siblings_on_different_governors_cannot_spend_each_others_budget(pg_dsn: str) -> None:
    unit = money("0.01")
    scopes = ("alpha", "beta", "gamma")
    with fleet(pg_dsn, policy=ADVISORY) as governors:
        governors[0].open_root("root", "1.00")
        for scope in scopes:
            governors[1].delegate("root", scope, "0.10")

        def hammer(i: int) -> tuple[str, int]:
            scope, governor = scopes[i % 3], governors[i % GOVERNORS]
            wins = 0
            for _ in range(15):
                try:
                    governor.spend(scope, unit)
                except BudgetExceededError:
                    continue
                wins += 1
            return scope, wins

        succeeded = dict.fromkeys(scopes, 0)
        for scope, wins in race(24, hammer):
            succeeded[scope] += wins

        with audit(pg_dsn) as reader:
            assert succeeded == dict.fromkeys(scopes, 10)
            assert all(reader.available(scope) == ZERO for scope in scopes)
            assert reader.available("root") == money("0.70")


def test_the_breaker_latches_once_for_the_whole_fleet(pg_dsn: str) -> None:
    """Enforced mode: the envelope is never exceeded, the scope is halted on
    every governor, and the trip is recorded exactly once, not once per host."""
    unit, envelope = money("0.01"), money("0.20")
    with fleet(pg_dsn) as governors:
        governors[0].open_root("root", envelope)
        governors[0].delegate("root", "swarm", envelope)

        def attempt(i: int) -> None:
            for _ in range(8):
                try:
                    governors[i % GOVERNORS].spend("swarm", unit)
                except AgentGovError:
                    return

        race(WORKERS, attempt)

        with audit(pg_dsn) as reader:
            count, total, lowest = audit_spend(reader, "swarm")
            assert total <= envelope, "the envelope was never breached"
            assert count * unit == total
            assert lowest >= ZERO
            trips = [
                e for e in reader.audit_trail("swarm") if e.entry_type is EntryType.CIRCUIT_TRIPPED
            ]
            assert len(trips) == 1, "one latch, however many governors raced into it"
            assert_fleet_converges(governors, reader)
            assert all(governor.is_halted("swarm") for governor in governors)


def test_racing_governors_create_a_root_exactly_once(pg_dsn: str) -> None:
    with fleet(pg_dsn) as governors:

        def attempt(i: int) -> bool:
            try:
                governors[i % GOVERNORS].open_root("org", "1.00")
            except DuplicateScopeError:
                return False
            return True

        assert sum(race(32, attempt)) == 1
        with audit(pg_dsn) as reader:
            fundings = [e for e in reader.audit_trail() if e.entry_type is EntryType.FUNDING]
            assert len(fundings) == 1
            assert reader.available("org") == money("1.00")


def test_racing_delegations_never_overcommit_the_parent(pg_dsn: str) -> None:
    """32 governors-worth of delegations against a parent that can fund 10."""
    with fleet(pg_dsn) as governors:
        governors[0].open_root("root", "1.00")

        def attempt(i: int) -> bool:
            try:
                governors[i % GOVERNORS].delegate("root", f"child-{i}", "0.10")
            except SubBudgetAllocationError:
                return False
            return True

        assert sum(race(32, attempt)) == 10
        with audit(pg_dsn) as reader:
            assert reader.available("root") == ZERO
            children = [s for s in reader.scopes() if s.startswith("child-")]
            assert len(children) == 10
            assert all(reader.available(child) == money("0.10") for child in children)
            assert_fleet_converges(governors, reader)


def test_the_chain_holds_even_with_the_lock_removed(pg_dsn: str) -> None:
    """The lock is for liveness; the chain is for safety.

    Every governor here skips the writer lock, so they race freely. A governor
    that checked a balance on a head another has since moved past builds its
    entries on that old head, and the database refuses them: an entry commits
    only if it extends the committed head. Writers fail; money does not.
    """
    unit, affordable = money("0.02"), 25
    with fleet(pg_dsn, policy=ADVISORY) as governors:
        governors[0].open_root("root", unit * affordable)
        for governor in governors:
            store = governor.store
            assert isinstance(store, PostgresStore)
            store._sql.begin_locked = sql.Composed(
                [sql.SQL("BEGIN ISOLATION LEVEL READ COMMITTED")]
            )

        refused: list[str] = []
        lock = threading.Lock()

        def attempt(i: int) -> bool:
            for _ in range(3):
                try:
                    governors[i % GOVERNORS].spend("root", unit)
                except BudgetExceededError:
                    return False
                except (LedgerIntegrityError, StorageError) as exc:
                    with lock:
                        refused.append(type(exc).__name__)
                    continue
                return True
            return False

        wins = sum(race(WORKERS, attempt))

        assert refused, "with the lock removed the writers must have collided"
        with audit(pg_dsn) as reader:
            count, total, lowest = audit_spend(reader, "root")
            assert count == wins, f"one entry per win ({len(refused)} writes refused)"
            assert wins <= affordable, "not one unit of double-spend"
            assert total == unit * wins
            assert lowest >= ZERO
            assert reader.available("root") == unit * (affordable - wins)


# --------------------------------------------------------------------------
# Separate processes: nothing in-process can be what serializes them
# --------------------------------------------------------------------------


def _spend_until_refused(dsn: str, unit: str, start: Barrier, results: Queue[int]) -> None:
    governor = BudgetManager.open_postgres(dsn, policy=ADVISORY)
    wins = 0
    try:
        start.wait(60)
        while True:
            try:
                governor.spend("root", unit)
            except BudgetExceededError:
                break
            wins += 1
    finally:
        governor.close()
        results.put(wins)


def test_8_processes_race_one_envelope_to_exactly_zero(pg_dsn: str) -> None:
    """Eight processes, each its own governor, spend until refused.

    Each worker stops at its first refusal, and no money ever comes back, so
    between them they must have spent the envelope exactly: not one call short
    (a lost write) and not one over (a double spend).
    """
    unit, affordable = money("0.01"), 240
    with BudgetManager.open_postgres(pg_dsn) as setup:
        setup.open_root("root", unit * affordable)

    context = multiprocessing.get_context("spawn")
    start = context.Barrier(GOVERNORS)
    results: Queue[int] = context.Queue()
    workers = [
        context.Process(target=_spend_until_refused, args=(pg_dsn, str(unit), start, results))
        for _ in range(GOVERNORS)
    ]
    for worker in workers:
        worker.start()
    wins = [results.get(timeout=120) for _ in workers]
    for worker in workers:
        worker.join(30)
        assert worker.exitcode == 0

    with audit(pg_dsn) as reader:
        count, total, lowest = audit_spend(reader, "root")
        assert sum(wins) == affordable, f"per-process wins {wins}"
        assert count == affordable
        assert total == unit * affordable
        assert lowest >= ZERO
        assert reader.available("root") == ZERO
        assert sum(1 for w in wins if w > 0) > 1, "the processes really did interleave"


def _die_holding_the_lock(dsn: str, written: Event, die: Event) -> None:
    governor = BudgetManager.open_postgres(dsn)
    store = governor.store
    assert isinstance(store, PostgresStore)
    original = store.commit

    def commit_then_die(batch: WriteBatch) -> None:
        original(batch)  # written into the transaction, which holds the lock
        written.set()
        die.wait(60)
        os.kill(os.getpid(), signal.SIGKILL)

    store.commit = commit_then_die  # type: ignore[method-assign]
    governor.spend("agent", "1.50")


@pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL")
def test_a_governor_killed_holding_the_lock_frees_it_and_leaves_nothing(pg_dsn: str) -> None:
    """While it lives, the dead governor's lock stops everyone; once it dies,
    the server rolls its transaction back, the lock goes with it, and the
    fleet carries on from the ledger as it stood."""
    with BudgetManager.open_postgres(pg_dsn) as setup:
        setup.open_root("org", "10.00")
        setup.delegate("org", "agent", "2.00")
        before = setup.ledger.entries()

    context = multiprocessing.get_context("spawn")
    written, die = context.Event(), context.Event()
    child = context.Process(target=_die_holding_the_lock, args=(pg_dsn, written, die))
    child.start()
    try:
        assert written.wait(60)
        with (
            BudgetManager.open_postgres(pg_dsn, read_only=True) as reader,
            pytest.raises(StorageError, match="waiting for the writer lock"),
        ):
            store = PostgresStore(pg_dsn, lock_timeout=0.3)
            try:
                BudgetManager(store=store)  # opening a writer needs the lock too
            finally:
                store.close()
        assert reader.ledger.entries() == before
    finally:
        die.set()
        child.join(30)
    assert child.exitcode == -signal.SIGKILL

    with BudgetManager.open_postgres(pg_dsn, lock_timeout=10) as survivor:
        assert survivor.ledger.entries() == before, "nothing the dead governor wrote landed"
        survivor.spend("agent", "0.50")
        assert survivor.available("agent") == money("1.50")
    with audit(pg_dsn) as reader:
        assert reader.stale_authorizations(0) == ()
