"""Ledger calls from asyncio run off the event loop, and survive cancellation (F8).

A governor write cannot be interrupted once it has started, so a cancelled
task never abandons one half-way: the write finishes, a hold placed for a
call that will now never be made is released, and only then is the
cancellation raised. No hold leaks, no settlement is lost.
"""

from __future__ import annotations

import asyncio
import contextvars
import threading
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentgov import BudgetManager, Interceptor, money
from agentgov._aio import off_loop, off_loop_or_undo
from agentgov.core import EntryType, WriteBatch
from agentgov.dummy import DummyLLM, DummyResponse
from agentgov.interceptor import TokenUsage
from agentgov.storage import SqliteStore


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
    manager = BudgetManager(store=_SlowStore(tmp_path / "slow.db"))
    manager.open_root("root", money("1.00"))
    manager.delegate("root", "worker", money("0.50"))
    _SlowStore.delay = 0.3
    _SlowStore.committing.clear()
    try:
        yield manager
    finally:
        _SlowStore.delay = 0.0
        manager.close()


async def _cancel_once_committing(task: asyncio.Task[object]) -> None:
    while not _SlowStore.committing.is_set():
        await asyncio.sleep(0.005)
    task.cancel()


def test_a_task_cancelled_while_its_hold_is_written_releases_the_hold(
    gov: BudgetManager,
) -> None:
    metered = Interceptor(gov, "worker", model="claude-opus-5")
    llm = DummyLLM(model="claude-opus-5")

    async def run() -> None:
        task = asyncio.ensure_future(metered.ainvoke(llm.acomplete, "prompt"))
        await _cancel_once_committing(task)  # cancelled mid-authorize
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert llm.call_count == 0, "the call was never made"
    assert gov.stale_authorizations(0) == (), "the hold was released, not leaked"
    assert gov.available("worker") == money("0.50")
    kinds = [e.entry_type for e in gov.audit_trail("worker")]
    assert kinds[-2:] == [EntryType.HOLD, EntryType.HOLD_VOID]
    gov.verify_integrity()


def test_a_task_cancelled_during_the_call_releases_the_hold(gov: BudgetManager) -> None:
    _SlowStore.delay = 0.0
    metered = Interceptor(gov, "worker", model="claude-opus-5")
    started = asyncio.Event()

    async def slow_call(prompt: str) -> DummyResponse:
        started.set()
        await asyncio.sleep(10)
        raise AssertionError("never reached")

    async def run() -> None:
        task = asyncio.ensure_future(metered.ainvoke(slow_call, "prompt"))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert gov.stale_authorizations(0) == ()
    assert gov.available("worker") == money("0.50")


def test_a_task_cancelled_while_it_settles_still_records_the_spend(
    gov: BudgetManager,
) -> None:
    _SlowStore.delay = 0.0
    metered = Interceptor(gov, "worker", model="claude-opus-5")
    answered = asyncio.Event()

    async def call(prompt: str) -> DummyResponse:
        response = await DummyLLM(model="claude-opus-5").acomplete(prompt)
        _SlowStore.delay = 0.3
        _SlowStore.committing.clear()
        answered.set()
        return response

    async def run() -> None:
        task = asyncio.ensure_future(metered.ainvoke(call, "prompt"))
        await answered.wait()
        await _cancel_once_committing(task)  # cancelled mid-capture
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    spends = [e for e in gov.audit_trail("worker") if e.entry_type is EntryType.SPEND]
    assert len(spends) == 1, "the provider was paid, so the spend is recorded"
    assert gov.stale_authorizations(0) == ()
    gov.verify_integrity()


def test_an_async_stream_cancelled_while_authorizing_releases_its_hold(
    gov: BudgetManager,
) -> None:
    async def events() -> AsyncIterator[SimpleNamespace]:
        yield SimpleNamespace(usage=TokenUsage(input_tokens=10))

    async def consume() -> None:
        metered = Interceptor(gov, "worker", model="claude-opus-5")
        async with metered.astream(events) as stream:
            async for _ in stream:
                pass

    async def run() -> None:
        task = asyncio.ensure_future(consume())
        await _cancel_once_committing(task)
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert gov.stale_authorizations(0) == ()
    assert gov.available("worker") == money("0.50")


def test_off_loop_carries_context_and_errors() -> None:
    request: contextvars.ContextVar[str] = contextvars.ContextVar("request")

    def read() -> tuple[str, bool]:
        return request.get(), threading.current_thread() is threading.main_thread()

    def fail() -> None:
        raise ValueError("from the worker")

    async def run() -> None:
        request.set("req-81f3")
        assert await off_loop(read) == ("req-81f3", False)
        with pytest.raises(ValueError, match="from the worker"):
            await off_loop(fail)

    asyncio.run(run())


def test_an_undo_that_fails_is_logged_and_the_cancellation_still_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    gate = threading.Event()

    def work() -> int:
        gate.wait(5)
        return 7

    def undo(value: int) -> None:
        raise RuntimeError(f"cannot undo {value}")

    async def run() -> None:
        task = asyncio.ensure_future(off_loop_or_undo(work, undo))
        await asyncio.sleep(0.05)
        task.cancel()
        await asyncio.sleep(0.05)
        task.cancel()  # cancelled again while it waits: it still waits
        gate.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    assert "undoing a governor call whose caller was cancelled failed" in caplog.text
