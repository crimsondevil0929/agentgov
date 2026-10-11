"""Group commit (Phase 5.2, D9): concurrent callers share units of work.

On a shared ledger every mutation takes the fleet's writer lock, catches up
and commits. Callers of one governor that arrive together share that: the
first to get the governor's lock runs everything queued, in order, in one
unit of work. Each caller's failure is its own, a trip recorded on the way
still commits, and a commit that fails fails every mutation it carried. A
caller holding ``ledger.lock`` around a check and its act runs alone.
"""

from __future__ import annotations

import functools
import threading
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.exceptions import (
    BudgetExceededError,
    CircuitOpenError,
    DenialOfWalletError,
    StorageError,
)
from agentgov.postgres import PostgresStore

pytestmark = pytest.mark.usefixtures("pg_dsn")
UNLIMITED = GovernancePolicy(max_calls_per_window=0)


@pytest.fixture
def gov(pg_dsn: str) -> Iterator[BudgetManager]:
    manager = BudgetManager.open_postgres(pg_dsn, policy=UNLIMITED, auditor=False)
    manager.open_root("root", money("100"))
    for name in ("a", "b", "c", "d"):
        manager.delegate("root", name, money("10"))
    try:
        yield manager
    finally:
        manager.close()


class Run(threading.Thread):
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


def _sessions(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    count = [0]
    original = PostgresStore.writer

    def counted(self: PostgresStore, **kwargs: Any) -> Any:
        if self._session is None:
            count[0] += 1
        return original(self, **kwargs)

    monkeypatch.setattr(PostgresStore, "writer", counted)
    return count


def _queued(gov: BudgetManager, calls: list[Callable[[], object]]) -> list[Run]:
    """Start ``calls`` while this thread holds the governor's lock, so they
    queue up, and let them go together: one unit of work runs them all."""
    with gov.ledger.lock:
        runs = [Run(call) for call in calls]
        deadline = time.monotonic() + 10
        while len(gov._queue) < len(calls):
            assert time.monotonic() < deadline, "the callers never queued"
            time.sleep(0.001)
    return runs


def test_callers_that_arrive_together_share_one_unit_of_work(
    gov: BudgetManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions = _sessions(monkeypatch)
    runs = _queued(gov, [functools.partial(gov.authorize, s, money("1")) for s in "abcd"])
    holds = [run.outcome() for run in runs]
    assert sessions[0] == 1, "four authorizations, one unit of work"
    assert all(hold.scope_id == s for hold, s in zip(holds, "abcd", strict=True))  # type: ignore[attr-defined]
    assert [gov.available(s) for s in "abcd"] == [money("9")] * 4
    with BudgetManager.open_postgres(gov.store._conninfo, read_only=True) as view:  # type: ignore[union-attr]
        assert [view.available(s) for s in "abcd"] == [money("9")] * 4
        view.verify_integrity()


def test_each_caller_keeps_its_own_failure(
    gov: BudgetManager, monkeypatch: pytest.MonkeyPatch, pg_dsn: str
) -> None:
    """In one unit of work: a refused authorization writes nothing and raises
    its own error; an overdraw trips its scope, which commits, and raises; the
    others commit as if alone."""
    advisory = BudgetManager.open_postgres(
        pg_dsn,
        policy=GovernancePolicy(max_calls_per_window=0, trip_on_overdraft=False),
        auditor=False,
    )
    try:
        sessions = _sessions(monkeypatch)
        runs = _queued(
            advisory,
            [
                lambda: advisory.authorize("a", money("1")),
                lambda: advisory.authorize("b", money("50")),  # refused, nothing written
                lambda: advisory.authorize("c", money("2")),
            ],
        )
        outcomes = [run.outcome() for run in runs]
        assert sessions[0] == 1
        assert isinstance(outcomes[1], BudgetExceededError)
        assert [advisory.available(s) for s in "abc"] == [money("9"), money("10"), money("8")]
    finally:
        advisory.close()

    runs = _queued(
        gov,
        [
            lambda: gov.authorize("a", money("1")),
            lambda: gov.authorize("b", money("50")),  # overdraws: trips b, then raises
            lambda: gov.authorize("c", money("2")),
        ],
    )
    outcomes = [run.outcome() for run in runs]
    assert isinstance(outcomes[1], DenialOfWalletError)
    assert gov.is_halted("b") and not gov.is_halted("a")
    with BudgetManager.open_postgres(pg_dsn, read_only=True) as view:
        assert view.is_halted("b"), "the trip committed with the others"
        assert view.available("a") == money("8") and view.available("c") == money("6")
    with pytest.raises(CircuitOpenError):
        gov.authorize("b", money("1"))


def test_a_commit_that_fails_fails_every_mutation_it_carried(
    gov: BudgetManager, monkeypatch: pytest.MonkeyPatch, pg_dsn: str
) -> None:
    def refuse(self: PostgresStore, session: Any) -> None:
        self._rollback_quietly()
        session.batches.clear()
        raise StorageError("the database refused the commit")

    with monkeypatch.context() as patch:
        patch.setattr(PostgresStore, "_end", refuse)
        runs = _queued(gov, [functools.partial(gov.authorize, s, money("1")) for s in "abc"])
        outcomes = [run.outcome() for run in runs]
    assert all(isinstance(o, StorageError) for o in outcomes), outcomes
    assert [gov.available(s) for s in "abc"] == [money("10")] * 3, "re-read: nothing committed"
    assert gov.stale_authorizations(0) == ()
    gov.authorize("a", money("1"))
    gov.verify_integrity()


def test_a_caller_holding_the_lock_runs_alone(gov: BudgetManager) -> None:
    """A check and the act it decides, under ``ledger.lock``: work queued by
    other callers meanwhile runs after, never between them."""
    with gov.ledger.lock:
        other = Run(lambda: gov.spend("a", money("5")))
        deadline = time.monotonic() + 10
        while not gov._queue:
            assert time.monotonic() < deadline
            time.sleep(0.001)
        assert gov.available("a") == money("10")  # the check
        gov.authorize("a", money("10"))  # the act: all of it, and nothing else ran
        assert gov.available("a") == money("0") and len(gov._queue) == 1
    outcome = other.outcome()
    assert isinstance(outcome, DenialOfWalletError), "it ran after, and found nothing left"


def test_many_threads_on_one_governor_stay_exact(
    gov: BudgetManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    sessions = _sessions(monkeypatch)

    def work(scope: str) -> None:
        for _ in range(25):
            hold = gov.authorize(scope, money("0.01"))
            gov.capture(hold, money("0.004"))

    runs = [Run(functools.partial(work, s)) for s in "abcd" for _ in range(4)]
    for run in runs:
        assert run.outcome() is None
    assert [gov.available(s) for s in "abcd"] == [money("10") - money("0.004") * 100] * 4
    assert sessions[0] < 800, f"{sessions[0]} units of work for 800 mutations"
    gov.verify_integrity()
