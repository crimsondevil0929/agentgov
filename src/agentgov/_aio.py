"""Running a governor's blocking calls from asyncio, off the event loop.

A governor operation is a database transaction: an fsync on SQLite, several
round trips and possibly a lock wait on PostgreSQL. Made on the event loop,
it stalls every other coroutine for as long as it takes. :func:`off_loop`
runs it on a worker thread instead.

Such a call cannot be interrupted once it has started: abandoning a ledger
write half-way would leave its caller not knowing whether it committed. So a
task cancelled while it waits does not abandon it. The call runs to
completion, its result is handed to ``undo`` if one was given (a hold placed
for a call that will now never be made, say, is released there), and only
then is the cancellation raised.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import logging
import uuid
from collections.abc import Callable
from concurrent.futures import Executor
from datetime import timedelta
from decimal import Decimal
from typing import TYPE_CHECKING, ParamSpec, TypeVar

if TYPE_CHECKING:
    from agentgov.core import (
        Authorization,
        BudgetManager,
        BudgetNode,
        EntryType,
        LedgerEntry,
        Transaction,
    )

__all__ = ["AsyncBudgetManager", "off_loop", "off_loop_or_undo"]

logger = logging.getLogger("agentgov")

P = ParamSpec("P")
R = TypeVar("R")


async def off_loop(
    fn: Callable[P, R],
    /,
    *args: P.args,
    **kwargs: P.kwargs,
) -> R:
    """Run ``fn(*args, **kwargs)`` on a worker thread and await its result.

    The calling context's variables are carried to the thread. If the
    awaiting task is cancelled, ``fn`` still runs to completion before the
    cancellation is raised.
    """
    return await _run(functools.partial(fn, *args, **kwargs), None)


async def off_loop_or_undo(fn: Callable[[], R], undo: Callable[[R], object]) -> R:
    """:func:`off_loop`, and if the awaiting task is cancelled after ``fn``
    succeeded, ``undo(result)`` (also off the loop) before the cancellation
    is raised: what ``fn`` did was for a caller that is no longer there."""
    return await _run(fn, undo)


async def _run(
    call: Callable[[], R],
    undo: Callable[[R], object] | None,
    executor: Executor | None = None,
) -> R:
    loop = asyncio.get_running_loop()
    context = contextvars.copy_context()
    future = loop.run_in_executor(executor, context.run, call)
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        await _finish(future)
        if undo is not None and not future.cancelled() and future.exception() is None:
            undone = loop.run_in_executor(executor, context.run, undo, future.result())
            await _finish(undone)
            if not undone.cancelled() and undone.exception() is not None:
                logger.error(
                    "undoing a governor call whose caller was cancelled failed",
                    exc_info=undone.exception(),
                )
        raise


async def _finish(future: asyncio.Future[object] | asyncio.Future[R]) -> None:
    """Wait for ``future`` to complete, through any number of cancellations."""
    while not future.done():
        try:
            await asyncio.shield(future)
        except asyncio.CancelledError:
            continue
        except BaseException:  # its outcome is the caller's to read
            return


_CANCELLED_MEMO = "released: the caller was cancelled before using the hold"


class AsyncBudgetManager:
    """A governor's operations as coroutines that never block the event loop.

    Wraps a :class:`~agentgov.core.BudgetManager`, which stays usable beside
    it::

        agov = agentgov.AsyncBudgetManager(gov)
        hold = await agov.authorize("researcher", money("0.02"))
        await agov.capture(hold, money("0.013"))

    Each operation runs on a worker thread (the loop's default executor, or
    ``executor``), where it joins the governor's group commit: coroutines
    writing at once share units of work, as threads do.

    A task cancelled while its operation runs does not abandon it: a ledger
    write cannot be taken back half-way, so the operation completes, and
    only then is the cancellation raised. A hold placed for a caller that
    was cancelled is voided, since that caller will never capture it, unless
    it was placed under an idempotency key: then the caller can retry under
    the key and get it back.
    """

    __slots__ = ("_executor", "_manager")

    def __init__(self, manager: BudgetManager, *, executor: Executor | None = None) -> None:
        self._manager = manager
        self._executor = executor

    @property
    def manager(self) -> BudgetManager:
        """The governor this runs."""
        return self._manager

    async def _call(self, fn: Callable[P, R], /, *args: P.args, **kwargs: P.kwargs) -> R:
        return await _run(functools.partial(fn, *args, **kwargs), None, self._executor)

    def _void_unused(self, hold: Authorization | None) -> None:
        if hold is not None:
            self._manager.void(hold, memo=_CANCELLED_MEMO)

    # -- reads ----------------------------------------------------------------

    async def available(self, scope_id: str, *, fresh: bool = False) -> Decimal:
        """:meth:`BudgetManager.available`."""
        return await self._call(self._manager.available, scope_id, fresh=fresh)

    async def subtree_available(self, scope_id: str, *, fresh: bool = False) -> Decimal:
        """:meth:`BudgetManager.subtree_available`."""
        return await self._call(self._manager.subtree_available, scope_id, fresh=fresh)

    async def is_halted(self, scope_id: str, *, fresh: bool = False) -> bool:
        """:meth:`BudgetManager.is_halted`."""
        return await self._call(self._manager.is_halted, scope_id, fresh=fresh)

    async def authorization(self, authorization_id: uuid.UUID | str) -> Authorization | None:
        """:meth:`BudgetManager.authorization`."""
        return await self._call(self._manager.authorization, authorization_id)

    async def scopes(self) -> tuple[str, ...]:
        """:meth:`BudgetManager.scopes`."""
        return await self._call(self._manager.scopes)

    async def entry(self, sequence: int) -> LedgerEntry:
        """:meth:`BudgetManager.entry`."""
        return await self._call(self._manager.entry, sequence)

    async def entries(self, *, after: int = 0, limit: int = 1000) -> tuple[LedgerEntry, ...]:
        """:meth:`BudgetManager.entries`."""
        return await self._call(self._manager.entries, after=after, limit=limit)

    async def find_entries(
        self,
        *,
        scope_id: str | None = None,
        entry_type: EntryType | None = None,
        memo: str | None = None,
        transaction_id: uuid.UUID | None = None,
        ref: uuid.UUID | None = None,
        after: int = 0,
        limit: int | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """:meth:`BudgetManager.find_entries`."""
        return await self._call(
            self._manager.find_entries,
            scope_id=scope_id,
            entry_type=entry_type,
            memo=memo,
            transaction_id=transaction_id,
            ref=ref,
            after=after,
            limit=limit,
        )

    async def stale_authorizations(
        self, older_than: timedelta | float, *, scope_id: str | None = None
    ) -> tuple[Authorization, ...]:
        """:meth:`BudgetManager.stale_authorizations`."""
        return await self._call(self._manager.stale_authorizations, older_than, scope_id=scope_id)

    async def refresh(self) -> int:
        """:meth:`BudgetManager.refresh`."""
        return await self._call(self._manager.refresh)

    async def verify_integrity(self) -> None:
        """:meth:`BudgetManager.verify_integrity`."""
        await self._call(self._manager.verify_integrity)

    # -- mutations ------------------------------------------------------------

    async def open_root(
        self, scope_id: str, envelope: Decimal | int | str, *, memo: str = ""
    ) -> BudgetNode:
        """:meth:`BudgetManager.open_root`."""
        return await self._call(self._manager.open_root, scope_id, envelope, memo=memo)

    async def fund(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """:meth:`BudgetManager.fund`."""
        return await self._call(
            self._manager.fund, scope_id, amount, memo=memo, idempotency_key=idempotency_key
        )

    async def delegate(
        self,
        parent_id: str,
        child_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> BudgetNode:
        """:meth:`BudgetManager.delegate`."""
        return await self._call(
            self._manager.delegate,
            parent_id,
            child_id,
            amount,
            memo=memo,
            idempotency_key=idempotency_key,
        )

    async def release(
        self, scope_id: str, amount: Decimal | int | str | None = None, *, memo: str = ""
    ) -> Decimal:
        """:meth:`BudgetManager.release`."""
        return await self._call(self._manager.release, scope_id, amount, memo=memo)

    async def authorize(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> Authorization:
        """:meth:`BudgetManager.authorize`. A hold placed for a caller that was
        cancelled meanwhile is voided, unless placed under a key."""
        call = functools.partial(
            self._manager.authorize, scope_id, amount, memo=memo, idempotency_key=idempotency_key
        )
        undo = self._void_unused if idempotency_key is None else None
        return await _run(call, undo, self._executor)

    async def try_authorize(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> Authorization | None:
        """:meth:`BudgetManager.try_authorize`, cancelled as :meth:`authorize` is."""
        call = functools.partial(
            self._manager.try_authorize,
            scope_id,
            amount,
            memo=memo,
            idempotency_key=idempotency_key,
        )
        undo = self._void_unused if idempotency_key is None else None
        return await _run(call, undo, self._executor)

    async def capture(
        self,
        authorization: Authorization,
        actual_cost: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """:meth:`BudgetManager.capture`."""
        return await self._call(
            self._manager.capture,
            authorization,
            actual_cost,
            memo=memo,
            idempotency_key=idempotency_key,
        )

    async def void(
        self, authorization: Authorization, *, memo: str = "", idempotency_key: str | None = None
    ) -> LedgerEntry:
        """:meth:`BudgetManager.void`."""
        return await self._call(
            self._manager.void, authorization, memo=memo, idempotency_key=idempotency_key
        )

    async def spend(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """:meth:`BudgetManager.spend`."""
        return await self._call(
            self._manager.spend, scope_id, amount, memo=memo, idempotency_key=idempotency_key
        )

    async def refund(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        reverses: LedgerEntry | uuid.UUID | None = None,
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """:meth:`BudgetManager.refund`."""
        return await self._call(
            self._manager.refund,
            scope_id,
            amount,
            memo=memo,
            reverses=reverses,
            idempotency_key=idempotency_key,
        )

    async def anchor(self, scope_id: str, memo: str) -> LedgerEntry:
        """:meth:`BudgetManager.anchor`."""
        return await self._call(self._manager.anchor, scope_id, memo)

    async def trip(self, scope_id: str, reason: str) -> None:
        """:meth:`BudgetManager.trip`."""
        await self._call(self._manager.trip, scope_id, reason)

    async def reset(self, scope_id: str) -> None:
        """:meth:`BudgetManager.reset`."""
        await self._call(self._manager.reset, scope_id)

    async def void_stale(
        self, older_than: timedelta | float, *, scope_id: str | None = None, memo: str = ""
    ) -> tuple[Authorization, ...]:
        """:meth:`BudgetManager.void_stale`."""
        return await self._call(self._manager.void_stale, older_than, scope_id=scope_id, memo=memo)

    async def checkpoint(self) -> int:
        """:meth:`BudgetManager.checkpoint`."""
        return await self._call(self._manager.checkpoint)

    async def transact(self, work: Callable[[Transaction], R]) -> R:
        """Run ``work`` inside :meth:`BudgetManager.transaction`, on a worker
        thread, and return what it returns.

        ``work`` is a plain function, given the transaction: a transaction
        holds the governor's lock, which belongs to one thread, so it cannot
        span an ``await``. Keep it short, with no slow call inside: other
        writers wait while it runs. If it raises, nothing it did is written.
        """

        def run() -> R:
            with self._manager.transaction() as txn:
                return work(txn)

        return await _run(run, None, self._executor)

    async def aclose(self) -> None:
        """Close the governor, off the loop."""
        await self._call(self._manager.close)

    async def __aenter__(self) -> AsyncBudgetManager:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
