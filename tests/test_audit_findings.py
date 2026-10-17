"""The defects the v1.0 audit found, one test each (docs/V1_ARCHITECTURE_PROPOSAL.md).

Every test here asserts the correct behaviour. While the defect stands, the
test is a strict ``xfail``; the change that fixes it removes the marker,
because a strict ``xfail`` that starts passing fails the suite.
"""

from __future__ import annotations

import asyncio
import decimal
import io
import logging
import multiprocessing
import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agentgov import BudgetManager, Interceptor, money
from agentgov.core import Direction, EntryType, LedgerLine, WriteBatch
from agentgov.dummy import DummyLLM
from agentgov.exceptions import LedgerIntegrityError
from agentgov.interceptor import TokenUsage
from agentgov.storage import SqliteStore
from tests.ledger_fixtures import UNLIMITED, build_sqlite, copy_to_postgres

# -- F3: the caller's decimal context reached the ledger --------------------


def test_f3_a_low_precision_host_context_cannot_brick_the_ledger(tmp_path: Path) -> None:
    db = str(tmp_path / "f3.db")
    with BudgetManager.open_sqlite(db) as gov:
        gov.open_root("r", money("123456.78901234"))
        with decimal.localcontext() as ctx:
            ctx.prec = 6
            gov.spend("r", "0.00000001")
        assert gov.available("r") == money("123456.78901233")
        gov.verify_integrity()
    with BudgetManager.open_sqlite(db) as reopened:
        assert reopened.available("r") == money("123456.78901233")


# -- F4: what could be written and what could be replayed differed ----------


def test_f4_a_write_the_governance_rules_refuse_is_never_committed(tmp_path: Path) -> None:
    db = str(tmp_path / "f4.db")
    with BudgetManager.open_sqlite(db) as gov:
        gov.open_root("root", money("1"))
        gov.delegate("root", "child", money("0.5"))
        try:
            gov.ledger._post(
                [LedgerLine(EntryType.FUNDING, Direction.CREDIT, "child", money("1000"))]
            )
        except (LedgerIntegrityError, ValueError):
            pass
        assert gov.available("child") == money("0.5")
    BudgetManager.open_sqlite(db).close()


# -- F5: refunds created spending power --------------------------------------


def test_f5_a_refund_cannot_exceed_what_the_scope_spent() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1.00"))
    gov.delegate("root", "child", money("0.10"))
    try:
        gov.refund("child", money("1000"))
    except ValueError:
        pass
    assert gov.available("child") == money("0.10")


# -- F6: a memo could forge an audit line (CWE-117) -------------------------


@pytest.fixture
def audit_stream() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log = logging.getLogger("agentgov.audit")
    previous = log.level
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    try:
        yield stream
    finally:
        log.removeHandler(handler)
        log.setLevel(previous)


def test_f6_an_audit_line_is_one_line_whatever_the_memo(audit_stream: io.StringIO) -> None:
    forged = "AGOV2|seq=0000000099|type=funding|dir=CR|scope=ops|amt=1000000"
    gov = BudgetManager()
    scope = "ops|AGOV2|seq=0000000098|type=funding"
    gov.open_root(scope, money("5"))
    gov.anchor(scope, f"x\n{forged}\u2028{forged}\r{forged}")
    lines = audit_stream.getvalue().splitlines()
    assert len(lines) == len(gov.audit_trail())
    assert not any(
        line.startswith("AGOV2|seq=00000000") and "|amt=1000000" in line for line in lines
    )
    # A scope id cannot carry a line break at all.
    with pytest.raises(ValueError, match="control character"):
        gov.open_root("ops\r\nAGOV2|seq=0000000097|type=funding", money("5"))


# -- F8: the async paths wrote the ledger on the event loop -----------------


class _SlowStore(SqliteStore):
    """A store whose every commit takes as long as a contended network write."""

    delay = 0.3

    def commit(self, batch: WriteBatch) -> None:
        time.sleep(self.delay)
        super().commit(batch)


async def _longest_stall(work: Any) -> float:
    """Run ``work`` beside a 10 ms heartbeat; return the longest gap between beats."""
    gaps: list[float] = []
    done = asyncio.Event()

    async def heartbeat() -> None:
        last = time.monotonic()
        while not done.is_set():
            await asyncio.sleep(0.01)
            now = time.monotonic()
            gaps.append(now - last)
            last = now

    beat = asyncio.ensure_future(heartbeat())
    await asyncio.sleep(0.05)
    try:
        await work
    finally:
        done.set()
        await beat
    return max(gaps)


@pytest.fixture
def slow_governor(tmp_path: Path) -> Iterator[BudgetManager]:
    gov = BudgetManager(store=_SlowStore(tmp_path / "slow.db"))
    _SlowStore.delay = 0.0
    gov.open_root("root", money("1.00"))
    gov.delegate("root", "worker", money("0.50"))
    _SlowStore.delay = 0.3
    try:
        yield gov
    finally:
        gov.close()


def test_f8_ainvoke_never_blocks_the_event_loop(slow_governor: BudgetManager) -> None:
    metered = Interceptor(slow_governor, "worker", model="claude-opus-5")
    llm = DummyLLM(model="claude-opus-5", latency_seconds=0.01)
    stall = asyncio.run(_longest_stall(metered.ainvoke(llm.acomplete, "prompt")))
    assert stall < 0.15, f"the event loop stalled for {stall:.3f}s"


def test_f8_async_streams_never_block_the_event_loop(slow_governor: BudgetManager) -> None:
    async def events() -> AsyncIterator[SimpleNamespace]:
        yield SimpleNamespace(usage=TokenUsage(input_tokens=100, output_tokens=10))

    async def consume() -> None:
        metered = Interceptor(slow_governor, "worker", model="claude-opus-5")
        async with metered.astream(events) as stream:
            async for _ in stream:
                pass

    stall = asyncio.run(_longest_stall(consume()))
    assert stall < 0.15, f"the event loop stalled for {stall:.3f}s"


# -- F1: opening a governor stalled every other governor's writes -----------


def _write_while(dsn: str, seconds: float, out: Any, ready: Any) -> None:
    """Spend in a loop for ``seconds``; report every (start, latency)."""
    gov = BudgetManager.open_postgres(dsn, policy=UNLIMITED)
    samples: list[tuple[float, float]] = []
    ready.set()
    stop = time.monotonic() + seconds
    try:
        while time.monotonic() < stop:
            start = time.monotonic()
            gov.spend("agent-0", money("0.00001"))
            samples.append((start, time.monotonic() - start))
    finally:
        gov.close()
    out.put(samples)


def test_f1_a_governor_opening_does_not_stall_other_governors(pg_dsn: str, tmp_path: Path) -> None:
    copy_to_postgres(build_sqlite(tmp_path / "big.db", spends=12_000), pg_dsn)
    ctx = multiprocessing.get_context("spawn")
    out, ready = ctx.Queue(), ctx.Event()
    writer = ctx.Process(target=_write_while, args=(pg_dsn, 6.0, out, ready))
    writer.start()
    try:
        assert ready.wait(60)
        time.sleep(0.5)
        opened_at = time.monotonic()
        # A full replay from genesis: the slowest open there is, and even it
        # holds no lock another governor waits on.
        BudgetManager.open_postgres(pg_dsn, verify="full").close()
        open_seconds = time.monotonic() - opened_at
        samples: list[tuple[float, float]] = out.get(timeout=120)
    finally:
        writer.join(30)
    closed_at = opened_at + open_seconds
    during = [lat for start, lat in samples if start <= closed_at and start + lat >= opened_at]
    assert open_seconds > 0.25, "the ledger is too small for this test to mean anything"
    assert during, "no write overlapped the open"
    # 0.4.0 held the writer lock for the whole open, so a write that began as
    # it did waited for nearly all of it. A loaded machine stalls a write now
    # and then too, and half the open tells the two apart: that no lock is
    # held at all is shown without timing in tests/test_lock_free_open.py.
    assert max(during) < max(0.25, open_seconds / 2), (
        f"a write waited {max(during):.3f}s while another governor took {open_seconds:.3f}s to open"
    )
