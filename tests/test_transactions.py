"""Transactions, try_authorize, idempotency keys and current reads (Phase 5.3).

``BudgetManager.transaction()`` is a unit of work the caller holds: reads
inside it are current (on a shared ledger, the fleet's writer lock is held and
the view caught up under it), every mutation inside it joins one commit, and a
block that raises writes nothing. ``try_authorize()`` refuses without
tripping. ``idempotency_key=`` makes a retried call return the first call's
result. ``authorization(id)`` finds a hold another governor placed, and
``fresh=True`` reads catch up first.
"""

from __future__ import annotations

import functools
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.core import Authorization, LedgerEntry
from agentgov.exceptions import (
    BudgetExceededError,
    CircuitOpenError,
    DenialOfWalletError,
    DoubleSpendError,
    IdempotencyConflictError,
    ReadOnlyLedgerError,
    StorageError,
)

POLICY = GovernancePolicy(max_calls_per_window=0)
ADVISORY = GovernancePolicy(max_calls_per_window=0, trip_on_overdraft=False)


class Backend:
    """Governors over one ledger of a kind: ``memory``, ``sqlite`` or ``postgres``."""

    def __init__(self, kind: str, tmp_path: Path, dsn: str | None) -> None:
        self.kind = kind
        self._path = str(tmp_path / "ledger.db")
        self._dsn = dsn
        self._opened: list[BudgetManager] = []

    def open(self, policy: GovernancePolicy = POLICY) -> BudgetManager:
        if self.kind == "memory":
            gov = BudgetManager(policy=policy)
        elif self.kind == "sqlite":
            gov = BudgetManager.open_sqlite(self._path, policy=policy, auditor=False)
        else:
            assert self._dsn is not None
            gov = BudgetManager.open_postgres(self._dsn, policy=policy, auditor=False)
        self._opened.append(gov)
        return gov

    def seeded(self, policy: GovernancePolicy = POLICY) -> BudgetManager:
        gov = self.open(policy)
        gov.open_root("org", money("100"))
        gov.delegate("org", "a", money("10"))
        gov.delegate("org", "b", money("10"))
        return gov

    def durable(self, gov: BudgetManager) -> BudgetManager | None:
        """A fresh view of what ``gov``'s ledger holds durably (``None`` in
        memory). A SQLite governor is closed for it: one writer at a time."""
        if self.kind == "memory":
            return None
        if self.kind == "sqlite":
            gov.close()
            return self.open()
        assert self._dsn is not None
        view = BudgetManager.open_postgres(self._dsn, read_only=True, auditor=False)
        self._opened.append(view)
        return view

    def close(self) -> None:
        for gov in self._opened:
            gov.close()


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def backend(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Backend]:
    dsn = request.getfixturevalue("pg_dsn") if request.param == "postgres" else None
    made = Backend(request.param, tmp_path, dsn)
    try:
        yield made
    finally:
        made.close()


@pytest.fixture
def fleet(pg_dsn: str, tmp_path: Path) -> Iterator[Backend]:
    made = Backend("postgres", tmp_path, pg_dsn)
    try:
        yield made
    finally:
        made.close()


def _holds(gov: BudgetManager) -> set[uuid.UUID]:
    return {auth.authorization_id for auth in gov.stale_authorizations(0)}


# -- transaction() --------------------------------------------------------------


def test_a_transaction_commits_its_mutations_together(backend: Backend) -> None:
    gov = backend.seeded()
    before = len(gov.ledger)
    with gov.transaction() as txn:
        assert txn.available("a") == money("10")
        hold = txn.authorize("a", money("3"))
        assert txn.available("a") == money("7"), "reads inside see the transaction's own work"
        txn.spend("b", money("2"))
        txn.delegate("a", "c", money("1"))
    assert gov.available("a") == money("6") and gov.available("b") == money("8")
    assert _holds(gov) == {hold.authorization_id}
    assert len(gov.ledger) > before
    gov.verify_integrity()
    view = backend.durable(gov)
    if view is not None:
        assert view.available("a") == money("6") and view.available("c") == money("1")
        assert view.available("b") == money("8")
        view.verify_integrity()


def test_a_block_that_raises_writes_nothing(backend: Backend) -> None:
    gov = backend.seeded()
    before = len(gov.ledger)
    with pytest.raises(RuntimeError, match="boom"), gov.transaction() as txn:
        txn.authorize("a", money("3"))
        txn.spend("b", money("2"))
        txn.delegate("a", "c", money("1"))
        raise RuntimeError("boom")
    assert len(gov.ledger) == before
    assert gov.available("a") == money("10") and gov.available("b") == money("10")
    assert "c" not in gov.scopes() and _holds(gov) == set()
    gov.verify_integrity()
    gov.authorize("a", money("1"))  # and it goes on
    view = backend.durable(gov)
    if view is not None:
        assert view.available("b") == money("10") and "c" not in view.scopes()
        view.verify_integrity()


def test_a_refusal_caught_inside_a_transaction_does_not_end_it(backend: Backend) -> None:
    gov = backend.seeded(ADVISORY)
    with gov.transaction() as txn:
        with pytest.raises(BudgetExceededError):
            txn.authorize("a", money("50"))
        txn.authorize("a", money("4"))
    assert gov.available("a") == money("6")
    view = backend.durable(gov)
    if view is not None:
        assert view.available("a") == money("6")


def test_a_trip_on_the_way_still_commits_when_the_block_raises(backend: Backend) -> None:
    """The trip an overdraft attempt records is the breaker's, not the
    caller's work: it commits even though the block's own work does not."""
    gov = backend.seeded()
    with pytest.raises(DenialOfWalletError), gov.transaction() as txn:
        txn.authorize("b", money("1"))
        txn.authorize("a", money("50"))  # trips a, raises, and the block with it
    assert gov.is_halted("a") and not gov.is_halted("b")
    assert gov.available("b") == money("10"), "b's hold was the block's, and went with it"
    gov.verify_integrity()
    view = backend.durable(gov)
    if view is not None:
        assert view.is_halted("a") and view.available("b") == money("10")


def test_transactions_do_not_nest_and_end_with_their_block(backend: Backend) -> None:
    gov = backend.seeded()
    with gov.transaction() as txn:
        with pytest.raises(RuntimeError, match=r"nest"):
            gov.transaction().__enter__()
        errors: list[BaseException] = []

        def elsewhere() -> None:
            try:
                txn.available("a")
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=elsewhere)
        thread.start()
        thread.join(10)
        assert len(errors) == 1 and isinstance(errors[0], RuntimeError)
        assert "thread" in str(errors[0])
    with pytest.raises(RuntimeError, match=r"ended"):
        txn.authorize("a", money("1"))


def test_other_callers_wait_for_a_transaction_to_end(backend: Backend) -> None:
    gov = backend.seeded()
    done = threading.Event()

    def spend() -> None:
        gov.spend("a", money("5"))
        done.set()

    with gov.transaction() as txn:
        thread = threading.Thread(target=spend, daemon=True)
        thread.start()
        time.sleep(0.2)
        assert not done.is_set(), "the other caller ran inside the transaction"
        assert txn.available("a") == money("10")
        txn.authorize("a", money("5"))
    assert done.wait(10)
    thread.join(10)
    assert gov.available("a") == money("0")


def test_a_read_only_view_opens_no_transaction(fleet: Backend) -> None:
    fleet.seeded()
    view = fleet.durable(fleet.open())
    assert view is not None
    with pytest.raises(ReadOnlyLedgerError), view.transaction():
        pass


def test_reads_inside_a_transaction_are_current_across_the_fleet(fleet: Backend) -> None:
    one = fleet.seeded()
    two = fleet.open()
    one.spend("a", money("4"))
    assert two.available("a") == money("10"), "outside a transaction, a read is the last refresh"
    with two.transaction() as txn:
        assert txn.available("a") == money("6")


def test_a_check_and_its_act_are_atomic_across_the_fleet(fleet: Backend) -> None:
    """Two governors race for the last funds, each checking and then acting
    inside a transaction: exactly one gets them, and nothing trips."""
    first = fleet.seeded()
    governors = [first, fleet.open(), fleet.open()]
    holds: list[Authorization] = []
    barrier = threading.Barrier(len(governors))

    def race(gov: BudgetManager) -> None:
        barrier.wait(10)
        with gov.transaction() as txn:
            if txn.available("a") >= money("8"):
                holds.append(txn.authorize("a", money("8")))

    threads = [threading.Thread(target=race, args=(gov,)) for gov in governors]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(20)
    assert len(holds) == 1
    first.refresh()
    assert first.available("a") == money("2") and not first.is_halted("a")


def test_a_transaction_is_one_unit_of_work_on_a_shared_ledger(
    fleet: Backend, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentgov.postgres import PostgresStore

    gov = fleet.seeded()
    count = [0]
    original = PostgresStore.writer

    def counted(self: PostgresStore, **kwargs: Any) -> Any:
        if self._session is None:
            count[0] += 1
        return original(self, **kwargs)

    monkeypatch.setattr(PostgresStore, "writer", counted)
    with gov.transaction() as txn:
        txn.authorize("a", money("1"))
        txn.spend("b", money("1"))
        txn.fund("org", money("5"))
    assert count[0] == 1


def test_a_sqlite_transaction_whose_commit_fails_leaves_memory_as_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentgov.storage import SqliteStore

    def auditors() -> set[threading.Thread]:
        return {t for t in threading.enumerate() if t.name == "agentgov-auditor"}

    backend = Backend("sqlite", tmp_path, None)
    try:
        gov = backend.seeded()
        running = auditors()

        def refuse(self: SqliteStore) -> None:
            raise StorageError("disk I/O error")

        with monkeypatch.context() as patch:
            patch.setattr(SqliteStore, "_commit_unit", refuse)
            with pytest.raises(StorageError), gov.transaction() as txn:
                txn.authorize("a", money("3"))
        assert gov.available("a") == money("10") and _holds(gov) == set()
        # Read again as a fresh open would, but no auditor of its own: the view
        # it was read into is adopted and dropped, and its auditor would follow
        # the ledger for nothing, reporting to no governor.
        assert auditors() == running
        gov.verify_integrity()
        gov.authorize("a", money("1"))
    finally:
        backend.close()


# -- try_authorize() --------------------------------------------------------------


def test_try_authorize_refuses_without_tripping_or_writing(backend: Backend) -> None:
    gov = backend.seeded()
    before = len(gov.ledger)
    assert gov.try_authorize("a", money("50")) is None
    assert len(gov.ledger) == before and not gov.is_halted("a")
    hold = gov.try_authorize("a", money("4"))
    assert hold is not None and hold.amount == money("4")
    assert gov.available("a") == money("6")
    gov.trip("b", "operator")
    with pytest.raises(CircuitOpenError):
        gov.try_authorize("b", money("1"))


# -- idempotency keys ---------------------------------------------------------------


def test_a_retried_call_returns_the_first_calls_result(backend: Backend) -> None:
    gov = backend.seeded()
    hold = gov.authorize("a", money("3"), idempotency_key="req-1")
    length = len(gov.ledger)
    again = gov.authorize("a", money("3"), idempotency_key="req-1")
    assert again == hold and len(gov.ledger) == length and gov.available("a") == money("7")
    assert gov.try_authorize("a", money("3"), idempotency_key="req-1") == hold

    spent = gov.capture(hold, money("2"), idempotency_key="req-1:capture")
    assert gov.capture(hold, money("2"), idempotency_key="req-1:capture") == spent
    with pytest.raises(DoubleSpendError):
        gov.capture(hold, money("2"))  # without the key, a second capture

    other = gov.authorize("b", money("1"), idempotency_key="req-2")
    voided = gov.void(other, idempotency_key="req-2:void")
    assert gov.void(other, idempotency_key="req-2:void") == voided

    spend = gov.spend("b", money("1"), idempotency_key="req-3")
    assert gov.spend("b", money("1"), idempotency_key="req-3") == spend
    refund = gov.refund("b", money("1"), reverses=spend, idempotency_key="req-4")
    assert gov.refund("b", money("1"), reverses=spend, idempotency_key="req-4") == refund
    funded = gov.fund("org", money("5"), idempotency_key="req-5")
    assert gov.fund("org", money("5"), idempotency_key="req-5") == funded
    child = gov.delegate("org", "c", money("2"), idempotency_key="req-6")
    assert gov.delegate("org", "c", money("2"), idempotency_key="req-6") == child

    assert gov.available("b") == money("10"), "voided, spent and refunded: once each"
    assert gov.available("org") == money("83")
    gov.verify_integrity()


def test_a_different_call_under_a_used_key_is_refused(backend: Backend) -> None:
    gov = backend.seeded()
    gov.authorize("a", money("3"), idempotency_key="req-1")
    length = len(gov.ledger)
    for call in (
        functools.partial(gov.authorize, "a", money("4"), idempotency_key="req-1"),
        functools.partial(gov.authorize, "b", money("3"), idempotency_key="req-1"),
        functools.partial(gov.spend, "a", money("3"), idempotency_key="req-1"),
    ):
        with pytest.raises(IdempotencyConflictError, match=r"req-1"):
            call()
    assert len(gov.ledger) == length


def test_a_refused_call_records_no_key(backend: Backend) -> None:
    """Only a call that wrote records its key: a refused one, retried once
    it can pay, is decided again."""
    gov = backend.seeded(ADVISORY)
    blocker = gov.authorize("a", money("5"))
    with pytest.raises(BudgetExceededError):
        gov.authorize("a", money("8"), idempotency_key="req-1")
    gov.void(blocker)
    assert gov.authorize("a", money("8"), idempotency_key="req-1").amount == money("8")
    assert gov.try_authorize("a", money("5"), idempotency_key="req-2") is None
    assert gov.try_authorize("a", money("2"), idempotency_key="req-2") is not None


def test_keys_are_durable(backend: Backend) -> None:
    if backend.kind == "memory":
        pytest.skip("a memory ledger does not outlive its governor")
    gov = backend.seeded()
    hold = gov.authorize("a", money("3"), idempotency_key="req-1")
    if backend.kind == "sqlite":
        gov.close()
    reopened = backend.open()
    assert reopened.authorize("a", money("3"), idempotency_key="req-1") == hold
    assert reopened.available("a") == money("7")
    with pytest.raises(IdempotencyConflictError):
        reopened.authorize("a", money("1"), idempotency_key="req-1")


def test_a_key_used_in_a_block_that_raises_is_not_recorded(backend: Backend) -> None:
    gov = backend.seeded()
    with pytest.raises(RuntimeError), gov.transaction() as txn:
        txn.authorize("a", money("3"), idempotency_key="req-1")
        raise RuntimeError("boom")
    hold = gov.authorize("a", money("2"), idempotency_key="req-1")  # a different request: free
    assert hold.amount == money("2") and gov.available("a") == money("8")


def test_a_key_used_twice_in_one_transaction_is_one_call(backend: Backend) -> None:
    gov = backend.seeded()
    with gov.transaction() as txn:
        first = txn.authorize("a", money("3"), idempotency_key="req-1")
        assert txn.authorize("a", money("3"), idempotency_key="req-1") == first
        with pytest.raises(IdempotencyConflictError):
            txn.authorize("a", money("1"), idempotency_key="req-1")
    assert gov.available("a") == money("7")


def test_a_retry_on_another_governor_returns_the_first_result(fleet: Backend) -> None:
    one = fleet.seeded()
    two = fleet.open()
    hold = one.authorize("a", money("3"), idempotency_key="req-1")
    assert two.authorize("a", money("3"), idempotency_key="req-1") == hold
    two.refresh()
    assert two.available("a") == money("7")


def test_callers_sharing_a_unit_of_work_share_a_key(
    fleet: Backend, monkeypatch: pytest.MonkeyPatch
) -> None:
    gov = fleet.seeded()
    with gov._lock:
        runs = [
            _Run(functools.partial(gov.authorize, "a", money("3"), idempotency_key="req-1"))
            for _ in range(3)
        ]
        deadline = time.monotonic() + 10
        while len(gov._queue) < 3:
            assert time.monotonic() < deadline
            time.sleep(0.001)
    outcomes = [run.outcome() for run in runs]
    holds = [o for o in outcomes if isinstance(o, Authorization)]
    assert len(holds) == 3, outcomes
    assert len({hold.authorization_id for hold in holds}) == 1
    assert gov.available("a") == money("7")


def test_a_retry_after_a_lost_commit_outcome_returns_what_committed(
    fleet: Backend, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The commit went through, but its answer was lost: the caller saw a
    StorageError. Retried under its key, the call returns the hold the lost
    commit placed, and places no second one."""
    from agentgov.postgres import PostgresStore

    gov = fleet.seeded()
    original = PostgresStore._end

    def lost(self: PostgresStore, session: Any) -> None:
        original(self, session)
        session.committed = False
        raise StorageError("the ledger transaction did not commit, or its outcome was lost")

    with monkeypatch.context() as patch:
        patch.setattr(PostgresStore, "_end", lost)
        with pytest.raises(StorageError):
            gov.authorize("a", money("3"), idempotency_key="req-1")
    hold = gov.authorize("a", money("3"), idempotency_key="req-1")
    assert gov.available("a") == money("7") and _holds(gov) == {hold.authorization_id}
    gov.verify_integrity()


# -- authorization(), fresh reads ---------------------------------------------------


def test_an_authorization_is_found_by_its_id(backend: Backend) -> None:
    gov = backend.seeded()
    hold = gov.authorize("a", money("3"))
    assert gov.authorization(hold.authorization_id) == hold
    assert gov.authorization(str(hold.authorization_id)) == hold
    gov.capture(hold, money("1"))
    assert gov.authorization(hold.authorization_id) is None
    assert gov.authorization(uuid.uuid4()) is None


def test_a_hold_another_governor_placed_is_found_and_captured(fleet: Backend) -> None:
    one = fleet.seeded()
    two = fleet.open()
    hold = one.authorize("a", money("3"))
    found = two.authorization(hold.authorization_id)  # no refresh first
    assert found == hold
    spent = two.capture(found, money("2"))
    assert isinstance(spent, LedgerEntry)
    one.refresh()
    assert one.available("a") == money("8")


def test_fresh_reads_catch_up_first(fleet: Backend) -> None:
    one = fleet.seeded()
    two = fleet.open()
    one.spend("a", money("4"))
    one.trip("b", "operator")
    assert two.available("a") == money("10") and not two.is_halted("b")
    assert two.available("a", fresh=True) == money("6")
    assert two.is_halted("b", fresh=True)
    assert two.subtree_available("org", fresh=True) == one.subtree_available("org")


class _Run(threading.Thread):
    def __init__(self, call: Callable[[], object]) -> None:
        super().__init__(daemon=True)
        self._call = call
        self.result: object = None
        self.error: BaseException | None = None
        self.start()

    def run(self) -> None:
        try:
            self.result = self._call()
        except BaseException as exc:  # the test inspects it
            self.error = exc

    def outcome(self) -> object:
        self.join(20)
        assert not self.is_alive()
        return self.error if self.error is not None else self.result
