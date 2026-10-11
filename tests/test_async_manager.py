"""AsyncBudgetManager: a governor's operations as coroutines (Phase 5.2).

Each runs on a worker thread, so the event loop never waits on the ledger,
and there it joins the governor's group commit: coroutines that write at once
share units of work. A cancelled caller's operation still completes, and a
hold placed for it is voided unless it was placed under an idempotency key.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agentgov import AsyncBudgetManager, BudgetManager, GovernancePolicy, money
from agentgov.core import EntryType, Transaction, WriteBatch
from agentgov.storage import SqliteStore

POLICY = GovernancePolicy(max_calls_per_window=0)


class _SlowStore(SqliteStore):
    """Every commit takes ``delay`` seconds, and says when it starts."""

    delay = 0.0
    committing = threading.Event()

    def commit(self, batch: WriteBatch) -> None:
        _SlowStore.committing.set()
        time.sleep(self.delay)
        super().commit(batch)


@pytest.fixture
def gov(tmp_path: Path) -> Iterator[BudgetManager]:
    _SlowStore.delay = 0.0
    manager = BudgetManager(store=_SlowStore(tmp_path / "slow.db"), policy=POLICY)
    manager.open_root("root", money("100"))
    for name in "abcdefgh":
        manager.delegate("root", name, money("10"))
    _SlowStore.committing.clear()
    try:
        yield manager
    finally:
        _SlowStore.delay = 0.0
        manager.close()


OPERATIONS = (
    "available",
    "subtree_available",
    "is_halted",
    "authorization",
    "scopes",
    "entry",
    "entries",
    "find_entries",
    "stale_authorizations",
    "refresh",
    "verify_integrity",
    "open_root",
    "fund",
    "delegate",
    "release",
    "authorize",
    "try_authorize",
    "capture",
    "void",
    "spend",
    "refund",
    "anchor",
    "trip",
    "reset",
    "void_stale",
    "checkpoint",
)


def test_every_operation_is_the_governors_as_a_coroutine() -> None:
    for name in OPERATIONS:
        mine = getattr(AsyncBudgetManager, name)
        theirs = getattr(BudgetManager, name)
        assert inspect.iscoroutinefunction(mine), name
        assert list(inspect.signature(mine).parameters) == list(
            inspect.signature(inspect.unwrap(theirs)).parameters
        ), name


def test_operations_run_off_the_event_loop(gov: BudgetManager) -> None:
    agov = AsyncBudgetManager(gov)
    _SlowStore.delay = 0.3
    ticks = [0]

    async def heartbeat(stop: asyncio.Event) -> None:
        while not stop.is_set():
            ticks[0] += 1
            await asyncio.sleep(0.01)

    async def run() -> None:
        stop = asyncio.Event()
        beat = asyncio.ensure_future(heartbeat(stop))
        await agov.spend("a", money("1"))
        stop.set()
        await beat

    asyncio.run(run())
    assert ticks[0] >= 10, f"the loop ticked {ticks[0]} times during a 0.6 s write"
    assert gov.available("a") == money("9")


def test_coroutines_that_write_at_once_share_units_of_work(
    gov: BudgetManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    agov = AsyncBudgetManager(gov)
    units = [0]
    original = SqliteStore.unit

    def counted(self: SqliteStore) -> Any:
        units[0] += 1
        return original(self)

    monkeypatch.setattr(SqliteStore, "unit", counted)
    _SlowStore.delay = 0.2  # the first unit is long enough for the rest to queue

    async def run() -> list[object]:
        return list(await asyncio.gather(*(agov.authorize(s, money("1")) for s in "abcdefgh")))

    holds = asyncio.run(run())
    assert len(holds) == 8
    assert units[0] <= 3, f"{units[0]} units of work for eight authorizations"
    assert [gov.available(s) for s in "abcdefgh"] == [money("9")] * 8


async def _cancel_once_committing(task: asyncio.Task[Any]) -> None:
    while not _SlowStore.committing.is_set():
        await asyncio.sleep(0.005)
    task.cancel()


def test_a_cancelled_callers_hold_is_voided_unless_placed_under_a_key(
    gov: BudgetManager,
) -> None:
    agov = AsyncBudgetManager(gov)
    _SlowStore.delay = 0.2

    async def cancelled(**kwargs: Any) -> None:
        _SlowStore.committing.clear()
        task = asyncio.ensure_future(agov.authorize("a", money("3"), **kwargs))
        await _cancel_once_committing(task)
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancelled())
    assert gov.available("a") == money("10") and gov.stale_authorizations(0) == ()
    kinds = [e.entry_type for e in gov.audit_trail("a")]
    assert kinds[-2:] == [EntryType.HOLD, EntryType.HOLD_VOID]

    asyncio.run(cancelled(idempotency_key="req-1"))
    assert gov.available("a") == money("7"), "kept: the caller can retry under its key"
    _SlowStore.delay = 0.0
    hold = asyncio.run(agov.authorize("a", money("3"), idempotency_key="req-1"))
    assert gov.stale_authorizations(0) == (hold,)


def test_transact_runs_a_function_in_one_transaction(gov: BudgetManager) -> None:
    agov = AsyncBudgetManager(gov)

    def pay(txn: Transaction) -> object:
        if txn.available("a") >= money("4"):
            return txn.authorize("a", money("4"))
        return None

    def fail(txn: Transaction) -> None:
        txn.authorize("b", money("4"))
        raise RuntimeError("boom")

    async def run() -> object:
        hold = await agov.transact(pay)
        with pytest.raises(RuntimeError, match="boom"):
            await agov.transact(fail)
        return hold

    hold = asyncio.run(run())
    assert hold is not None and gov.available("a") == money("6")
    assert gov.available("b") == money("10"), "the failed transaction wrote nothing"


def test_reads_and_closing(tmp_path: Path) -> None:
    async def run() -> None:
        gov = BudgetManager.open_sqlite(str(tmp_path / "l.db"), policy=POLICY, auditor=False)
        async with AsyncBudgetManager(gov) as agov:
            assert agov.manager is gov
            await agov.open_root("root", money("10"))
            await agov.delegate("root", "a", money("5"))
            hold = await agov.authorize("a", money("2"))
            assert await agov.available("a") == money("3")
            assert await agov.subtree_available("root") == money("8")
            assert not await agov.is_halted("a")
            assert await agov.authorization(hold.authorization_id) == hold
            assert await agov.scopes() == ("root", "a")
            assert (await agov.entry(1)).entry_type is EntryType.FUNDING
            assert len(await agov.entries(limit=2)) == 2
            assert len(await agov.find_entries(entry_type=EntryType.HOLD)) == 1
            assert await agov.stale_authorizations(0) == (hold,)
            spent = await agov.capture(hold, money("1"))
            await agov.refund("a", money("1"), reverses=spent)
            await agov.verify_integrity()
        with pytest.raises(Exception):  # noqa: B017 - closed: any error will do
            gov.authorize("a", money("1"))

    asyncio.run(run())
