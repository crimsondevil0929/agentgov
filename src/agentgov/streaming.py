"""Metered streaming: governing a response that arrives in pieces.

Streaming is the dominant shape for real agents, and it does not fit the
call-and-settle contract in :mod:`agentgov.interceptor`. A streamed call has
no single return value to price: usage is disclosed across events, the caller
may walk away half-way through, and the cost is only knowable once the
generator is done — or abandoned.

:class:`MeteredStream` and :class:`AsyncMeteredStream` wrap that lifecycle:

1. **Authorize** on entry, with a hold sized from the payload.
2. **Accumulate** usage as events arrive, merging the partial reports SDKs
   emit (input counts up front, output counts at the end).
3. **Resolve exactly once**, in a ``finally``, whatever happens — clean
   exhaustion, an early ``break``, an exception, or a timeout.

**On abandonment the hold is resolved, not discarded.** A stream broken off
half-way still generated tokens, and the provider still billed them; voiding
that would make the governor under-report real spend, which is the precise
failure this project exists to prevent. So the rule is: settle whatever usage
was actually observed, and void only when nothing was observed at all — a
connection that died before its first event. Either way the encumbrance is
always released, so funds are never stranded.

The stream must be used as a context manager. A stream that is entered and
then dropped without exiting leaves a hold that
:meth:`~agentgov.core.BudgetManager.void_stale` will reap, and logs a warning
saying so.
"""

from __future__ import annotations

import logging
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping, Sequence
from decimal import Decimal
from types import TracebackType
from typing import TYPE_CHECKING, Generic, TypeVar

from agentgov.core import Authorization, BudgetManager, LedgerEntry
from agentgov.interceptor import ModelPricing, TokenUsage, UsageExtractor

if TYPE_CHECKING:
    from agentgov.cognitive import CognitiveBreaker

if TYPE_CHECKING:
    _StreamFinalizer = weakref.finalize[[str, object], "_StreamCore"]

__all__ = ["AsyncMeteredStream", "MeteredStream"]

logger = logging.getLogger("agentgov.streaming")

T = TypeVar("T")


def _try_usage(extract: UsageExtractor, chunk: object) -> TokenUsage | None:
    """Read usage off one event, if it carries any.

    Most events in a stream carry no usage at all, so a failure here is the
    normal case and must be cheap and silent — not an error.
    """
    try:
        return extract(chunk)
    except (TypeError, AttributeError, KeyError, ValueError):
        return None


class _StreamCore:
    """Lifecycle shared by the sync and async stream wrappers.

    Owns the one invariant that matters: the authorization is resolved
    exactly once, no matter which path the caller takes out of the stream.
    """

    __slots__ = (
        # weakref.finalize needs this; a slotted class does not get it free.
        "__weakref__",
        "_auth",
        "_cognitive",
        "_entry",
        "_extract",
        "_finalizer",
        "_hold",
        "_manager",
        "_memo",
        "_pricing",
        "_resolved",
        "_scope_id",
        "_settled",
        "_trajectory",
        "_usage",
        "chunks",
    )

    def __init__(
        self,
        manager: BudgetManager,
        scope_id: str,
        hold: Decimal,
        pricing: ModelPricing,
        extract: UsageExtractor,
        *,
        memo: str = "",
        cognitive: CognitiveBreaker | None = None,
        trajectory: str | None = None,
    ) -> None:
        self._manager = manager
        self._scope_id = scope_id
        self._hold = hold
        self._pricing = pricing
        self._extract = extract
        self._memo = memo or "settled streamed call"
        self._cognitive = cognitive
        self._trajectory = trajectory
        self._auth: Authorization | None = None
        self._entry: LedgerEntry | None = None
        self._usage = TokenUsage()
        self._settled: Decimal | None = None
        self._resolved = False
        self._finalizer: _StreamFinalizer | None = None
        self.chunks = 0

    # -- observation ------------------------------------------------------

    @property
    def usage(self) -> TokenUsage:
        """Usage accumulated so far, merged across every event seen."""
        return self._usage

    @property
    def cost(self) -> Decimal | None:
        """The settled cost, once the stream has resolved."""
        return self._settled

    @property
    def entry(self) -> LedgerEntry | None:
        """The committed ledger entry, once the stream has resolved."""
        return self._entry

    @property
    def authorization(self) -> Authorization | None:
        """The hold placed on entry, while it is outstanding."""
        return self._auth

    @property
    def resolved(self) -> bool:
        """Whether the hold has been settled or voided."""
        return self._resolved

    def record_usage(self, usage: TokenUsage) -> None:
        """Merge an authoritative usage report into the running total.

        Call this when the SDK exposes usage somewhere the per-event
        extractor cannot see it.

        :param usage: Usage to merge, per-field, into what has been seen.
        """
        self._usage = self._usage.merged(usage)

    def absorb(self, chunk: object) -> None:
        """Fold one event's usage into the running total."""
        self.chunks += 1
        found = _try_usage(self._extract, chunk)
        if found is not None:
            self._usage = self._usage.merged(found)

    def absorb_final(self, source: object) -> None:
        """Pull authoritative usage from the SDK's final-message accessor.

        The Anthropic SDK exposes the settled message — and its exact usage —
        through ``get_final_message()`` once a stream completes. Preferring
        that over event fragments makes the settled cost exact rather than
        reconstructed.
        """
        getter = getattr(source, "get_final_message", None)
        if not callable(getter):
            return
        try:
            found = _try_usage(self._extract, getter())
        except Exception:  # an SDK may refuse this on an abandoned stream
            return
        if found is not None:
            self._usage = self._usage.merged(found)

    # -- lifecycle --------------------------------------------------------

    def authorize(self) -> None:
        """Place the hold. Raises before any provider call is made."""
        if self._cognitive is not None:
            self._cognitive.observe(
                self._scope_id, "stream", self._memo, trajectory=self._trajectory
            )
        self._auth = self._manager.authorize(
            self._scope_id, self._hold, memo="streamed call authorization"
        )
        self._finalizer = weakref.finalize(
            self, _warn_unresolved, self._scope_id, self._auth.authorization_id
        )

    def resolve(self) -> None:
        """Settle or void the hold. Idempotent, and never raises on re-entry.

        Settles at whatever usage was actually observed. A stream abandoned
        after producing tokens *did* cost money, and a governor that quietly
        forgot that would be under-reporting spend. Only a stream that
        produced no usage at all is voided.
        """
        if self._resolved or self._auth is None:
            return
        self._resolved = True
        if self._finalizer is not None:
            self._finalizer.detach()
            self._finalizer = None

        cost = self._pricing.cost_of(self._usage)
        if cost <= 0:
            self._manager.void(self._auth, memo="stream produced no billable usage")
            self._settled = Decimal(0)
            return
        self._settled = cost
        self._entry = self._manager.capture(self._auth, cost, memo=self._memo)


def _warn_unresolved(scope_id: str, authorization_id: object) -> None:
    """Warn that a stream was dropped without being exited.

    Deliberately does not touch the ledger: this runs during garbage
    collection, and taking the governor's mutex to write SQLite from a
    finalizer is not a trade worth making. The hold is recoverable through
    ``BudgetManager.void_stale()``, which is exactly what it is for.
    """
    logger.warning(
        "stream for scope %s was dropped without exiting its context manager; "
        "authorization %s is still open and can be reclaimed with "
        "BudgetManager.void_stale()",
        scope_id,
        authorization_id,
    )


class MeteredStream(Generic[T]):
    """A governed streaming call, used as a context manager.

    ::

        with interceptor.stream(client.messages.stream, model=…, messages=…) as events:
            for event in events:
                render(event)
        print(events.cost)

    Breaking out of that loop, raising inside it, or letting a timeout fire
    all resolve the hold on the way out.

    :param manager: The governor to enforce against.
    :param scope_id: The scope charged for this stream.
    :param hold: Amount to authorize before the call is made.
    :param pricing: Rates used to price the accumulated usage.
    :param extract: Reads usage off each event.
    :param call: Zero-argument callable that opens the provider's stream.
    :param memo: Audit context recorded on the settled spend.
    :param cognitive: Optional thrashing breaker, checked before authorizing.
    :param trajectory: Cognitive trajectory this stream belongs to.
    """

    __slots__ = ("_call", "_core", "_inner", "_source")

    def __init__(
        self,
        manager: BudgetManager,
        scope_id: str,
        hold: Decimal,
        pricing: ModelPricing,
        extract: UsageExtractor,
        call: Callable[[], object],
        *,
        memo: str = "",
        cognitive: CognitiveBreaker | None = None,
        trajectory: str | None = None,
    ) -> None:
        self._core = _StreamCore(
            manager,
            scope_id,
            hold,
            pricing,
            extract,
            memo=memo,
            cognitive=cognitive,
            trajectory=trajectory,
        )
        self._call = call
        self._inner: object = None
        self._source: Iterator[T] | None = None

    # -- delegation to the shared core ------------------------------------

    @property
    def usage(self) -> TokenUsage:
        """Usage accumulated across every event seen so far."""
        return self._core.usage

    @property
    def cost(self) -> Decimal | None:
        """The settled cost, once the stream has resolved."""
        return self._core.cost

    @property
    def entry(self) -> LedgerEntry | None:
        """The committed ledger entry, once the stream has resolved."""
        return self._core.entry

    @property
    def chunks(self) -> int:
        """How many events were pulled from the provider."""
        return self._core.chunks

    @property
    def resolved(self) -> bool:
        """Whether the hold has been settled or voided."""
        return self._core.resolved

    def record_usage(self, usage: TokenUsage) -> None:
        """Merge an authoritative usage report into the running total."""
        self._core.record_usage(usage)

    # -- context manager --------------------------------------------------

    def __enter__(self) -> MeteredStream[T]:
        """Authorize, then open the provider's stream.

        :raises ~agentgov.exceptions.AgentThrashingError: If a cognitive
            breaker is attached and this trajectory is looping.
        :raises ~agentgov.exceptions.CircuitOpenError: If the scope is halted.
        :raises ~agentgov.exceptions.DenialOfWalletError: If the hold exceeds
            the available balance.
        """
        self._core.authorize()
        try:
            raw = self._call()
        except BaseException:
            # The provider call failed before producing anything; nothing was
            # billed, so release the encumbrance rather than leave it open.
            self._core.resolve()
            raise

        try:
            enter = getattr(raw, "__enter__", None)
            if callable(enter):
                # Anthropic's .stream() hands back a context manager.
                self._inner = raw
                source = enter()
            else:
                source = raw
            self._source = iter(source)
        except BaseException:
            self._core.resolve()
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the provider's stream and resolve the hold, always."""
        try:
            if self._inner is not None:
                exit_ = getattr(self._inner, "__exit__", None)
                if callable(exit_):
                    exit_(exc_type, exc_value, traceback)
        finally:
            # The whole point: no path out of this block leaves the hold open.
            self._core.resolve()

    # -- iteration --------------------------------------------------------

    def __iter__(self) -> Iterator[T]:
        return self

    def __next__(self) -> T:
        if self._source is None:
            raise RuntimeError("MeteredStream must be entered before iterating")
        try:
            chunk = next(self._source)
        except StopIteration:
            # Exhausted cleanly: take the SDK's authoritative usage if it has
            # one. Settlement is deliberately *not* done here — the caller may
            # still call record_usage() after the loop, and resolving early
            # would silently settle before that lands. __exit__ owns it.
            self._core.absorb_final(self._inner if self._inner is not None else self._source)
            raise
        self._core.absorb(chunk)
        return chunk

    def close(self) -> None:
        """Resolve the hold explicitly, without exiting a context manager."""
        self._core.resolve()


class AsyncMeteredStream(Generic[T]):
    """The async counterpart of :class:`MeteredStream`.

    ::

        async with interceptor.astream(client.messages.stream, …) as events:
            async for event in events:
                await render(event)

    The governor's mutex is never held across an ``await``: the hold is taken
    on entry and resolved on exit, and both are short synchronous sections.

    Constructor arguments match :class:`MeteredStream`, except ``call`` may
    return an awaitable, an async context manager, or an async iterable.
    """

    __slots__ = ("_call", "_core", "_inner", "_source")

    def __init__(
        self,
        manager: BudgetManager,
        scope_id: str,
        hold: Decimal,
        pricing: ModelPricing,
        extract: UsageExtractor,
        call: Callable[[], object],
        *,
        memo: str = "",
        cognitive: CognitiveBreaker | None = None,
        trajectory: str | None = None,
    ) -> None:
        self._core = _StreamCore(
            manager,
            scope_id,
            hold,
            pricing,
            extract,
            memo=memo,
            cognitive=cognitive,
            trajectory=trajectory,
        )
        self._call = call
        self._inner: object = None
        self._source: AsyncIterator[T] | None = None

    @property
    def usage(self) -> TokenUsage:
        """Usage accumulated across every event seen so far."""
        return self._core.usage

    @property
    def cost(self) -> Decimal | None:
        """The settled cost, once the stream has resolved."""
        return self._core.cost

    @property
    def entry(self) -> LedgerEntry | None:
        """The committed ledger entry, once the stream has resolved."""
        return self._core.entry

    @property
    def chunks(self) -> int:
        """How many events were pulled from the provider."""
        return self._core.chunks

    @property
    def resolved(self) -> bool:
        """Whether the hold has been settled or voided."""
        return self._core.resolved

    def record_usage(self, usage: TokenUsage) -> None:
        """Merge an authoritative usage report into the running total."""
        self._core.record_usage(usage)

    async def __aenter__(self) -> AsyncMeteredStream[T]:
        """Authorize, then open the provider's stream."""
        self._core.authorize()
        try:
            raw = self._call()
            if isinstance(raw, Awaitable):
                raw = await raw
        except BaseException:
            self._core.resolve()
            raise

        try:
            aenter = getattr(raw, "__aenter__", None)
            if callable(aenter):
                self._inner = raw
                source = await aenter()
            else:
                source = raw
            self._source = source.__aiter__()
        except BaseException:
            self._core.resolve()
            raise
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the provider's stream and resolve the hold, always."""
        try:
            if self._inner is not None:
                aexit = getattr(self._inner, "__aexit__", None)
                if callable(aexit):
                    await aexit(exc_type, exc_value, traceback)
        finally:
            self._core.resolve()

    def __aiter__(self) -> AsyncIterator[T]:
        return self

    async def __anext__(self) -> T:
        if self._source is None:
            raise RuntimeError("AsyncMeteredStream must be entered before iterating")
        try:
            chunk = await self._source.__anext__()
        except StopAsyncIteration:
            # See MeteredStream.__next__: settlement belongs to __aexit__, so
            # a post-loop record_usage() is still honoured.
            self._core.absorb_final(self._inner if self._inner is not None else self._source)
            raise
        self._core.absorb(chunk)
        return chunk

    async def aclose(self) -> None:
        """Resolve the hold explicitly, without exiting a context manager."""
        self._core.resolve()


def build_call(
    fn: Callable[..., object], args: Sequence[object], kwargs: Mapping[str, object]
) -> Callable[[], object]:
    """Bind a provider call so the stream can open it at ``__enter__`` time.

    Opening the stream must happen *after* the hold is placed, so the call is
    deferred rather than made eagerly by the caller.
    """
    return lambda: fn(*args, **kwargs)
