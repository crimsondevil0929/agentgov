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
from collections.abc import Callable
from typing import ParamSpec, TypeVar

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


async def _run(call: Callable[[], R], undo: Callable[[R], object] | None) -> R:
    loop = asyncio.get_running_loop()
    context = contextvars.copy_context()
    future = loop.run_in_executor(None, context.run, call)
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        await _finish(future)
        if undo is not None and not future.cancelled() and future.exception() is None:
            undone = loop.run_in_executor(None, context.run, undo, future.result())
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
