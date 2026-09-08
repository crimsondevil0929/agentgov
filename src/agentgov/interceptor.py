"""API interception: wrapping model calls in budget enforcement.

This is the surface agent code actually touches. Wrapping a call in an
:class:`Interceptor` gives it the payments-industry authorize/capture
lifecycle:

1. **Authorize** — before the call, an estimated maximum cost is held
   against the caller's scope. The funds are encumbered, so a concurrent
   sibling sub-agent cannot also spend them.
2. **Execute** — the call runs with **no lock held**. This is the whole
   reason the ledger uses short critical sections rather than a lock spanning
   the request: an in-flight HTTP call must never block the governor.
3. **Capture** — the exact token cost is computed from the response's usage
   and settled atomically: the hold is released and the true spend posted in
   a single ledger transaction.

If the call raises, the hold is voided and nothing is charged. If the settled
cost overruns what the scope could cover, the spend is recorded anyway (money
that left cannot be un-spent), the breaker trips, and
:class:`~agentgov.exceptions.DenialOfWalletError` propagates.

Pricing is expressed per million tokens, matching how model vendors publish
it, and every rate is a :class:`~decimal.Decimal`.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal
from types import MappingProxyType, TracebackType
from typing import Any, Generic, Self, TypeVar

from agentgov.core import QUANTUM, Authorization, BudgetManager, LedgerEntry, money

__all__ = [
    "PRICING",
    "Interceptor",
    "MeteredCall",
    "ModelPricing",
    "SpendGuard",
    "TokenUsage",
    "UsageExtractor",
    "default_usage_extractor",
    "pricing_for",
]

logger = logging.getLogger("agentgov.interceptor")

_PER_MILLION = Decimal("1000000")


# --------------------------------------------------------------------------
# Token accounting
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Token counts for a single model call.

    Field names match the Anthropic Messages API usage object, so
    :func:`default_usage_extractor` can read a real SDK response directly.

    :ivar input_tokens: Uncached input tokens, billed at the full input rate.
    :ivar output_tokens: Generated tokens, billed at the output rate.
    :ivar cache_read_input_tokens: Tokens served from the prompt cache.
    :ivar cache_creation_input_tokens: Tokens written into the prompt cache.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0

    def __post_init__(self) -> None:
        for name in (
            "input_tokens",
            "output_tokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise TypeError(f"{name} must be an int, got {type(value).__name__}")
            if value < 0:
                raise ValueError(f"{name} must not be negative, got {value}")

    @property
    def total_tokens(self) -> int:
        """Total tokens across every billed category."""
        return (
            self.input_tokens
            + self.output_tokens
            + self.cache_read_input_tokens
            + self.cache_creation_input_tokens
        )


@dataclass(frozen=True, slots=True)
class ModelPricing:
    """Per-million-token rates for one model.

    :ivar model_id: The vendor's model identifier.
    :ivar input_usd_per_mtok: Rate for uncached input tokens.
    :ivar output_usd_per_mtok: Rate for generated tokens.
    :ivar cache_read_usd_per_mtok: Rate for prompt-cache reads.
    :ivar cache_write_usd_per_mtok: Rate for prompt-cache writes.
    """

    model_id: str
    input_usd_per_mtok: Decimal
    output_usd_per_mtok: Decimal
    cache_read_usd_per_mtok: Decimal
    cache_write_usd_per_mtok: Decimal

    def cost_of(self, usage: TokenUsage) -> Decimal:
        """Compute the exact cost of ``usage`` under these rates.

        The per-category products are summed at full ``Decimal`` precision and
        quantized once at the end, rounding **up** — a governor that rounds
        sub-quantum costs down would let a high-frequency loop spend for free.

        :param usage: The token counts to price.
        :returns: The cost in USD, quantized to :data:`~agentgov.core.QUANTUM`.
        """
        raw = (
            self.input_usd_per_mtok * usage.input_tokens
            + self.output_usd_per_mtok * usage.output_tokens
            + self.cache_read_usd_per_mtok * usage.cache_read_input_tokens
            + self.cache_write_usd_per_mtok * usage.cache_creation_input_tokens
        ) / _PER_MILLION
        return raw.quantize(QUANTUM, rounding=ROUND_CEILING)

    def estimate(self, input_tokens: int, max_output_tokens: int) -> Decimal:
        """Compute a worst-case pre-flight cost for an authorization hold.

        Assumes the model generates its full output allowance, which is the
        correct assumption for a hold: it may over-reserve, never under.

        :param input_tokens: Expected input tokens.
        :param max_output_tokens: The call's ``max_tokens`` ceiling.
        :returns: The cost to hold, in USD.
        """
        return self.cost_of(TokenUsage(input_tokens=input_tokens, output_tokens=max_output_tokens))


def _rates(
    model_id: str,
    input_rate: str,
    output_rate: str,
    *,
    cache_read: str | None = None,
) -> ModelPricing:
    """Build a :class:`ModelPricing` from published input/output rates.

    Cache rates follow the standard multipliers — reads at 0.1x input, writes
    at 1.25x input for the default 5-minute TTL — unless a model publishes an
    explicit cache-read rate.
    """
    inp = Decimal(input_rate)
    return ModelPricing(
        model_id=model_id,
        input_usd_per_mtok=inp,
        output_usd_per_mtok=Decimal(output_rate),
        cache_read_usd_per_mtok=Decimal(cache_read) if cache_read else inp / 10,
        cache_write_usd_per_mtok=inp * Decimal("1.25"),
    )


PRICING: Mapping[str, ModelPricing] = MappingProxyType(
    {
        p.model_id: p
        for p in (
            # Claude Fable 5.1 publishes an explicit $0.25/MTok cache-read rate
            # rather than the usual 0.1x-of-input multiplier.
            _rates("claude-fable-5-1", "10.00", "50.00", cache_read="0.25"),
            _rates("claude-fable-5", "10.00", "50.00"),
            _rates("claude-opus-5", "5.00", "25.00"),
            _rates("claude-opus-4-8", "5.00", "25.00"),
            _rates("claude-opus-4-7", "5.00", "25.00"),
            _rates("claude-opus-4-6", "5.00", "25.00"),
            _rates("claude-sonnet-5", "2.00", "10.00"),
            _rates("claude-sonnet-4-6", "3.00", "15.00"),
            _rates("claude-haiku-4-5", "1.00", "5.00"),
        )
    }
)
"""Published list rates, in USD per million tokens, as of 2026-06.

A snapshot, not an oracle: vendor pricing changes and partner platforms
(Bedrock, Vertex) bill differently. Pass an explicit :class:`ModelPricing` to
:class:`Interceptor` for any model or platform not covered here, and treat
reconciliation against the vendor invoice as a production requirement.
"""


def pricing_for(model_id: str) -> ModelPricing:
    """Look up the published rates for ``model_id``.

    :param model_id: The vendor model identifier.
    :returns: The matching :class:`ModelPricing`.
    :raises KeyError: If the model is not in :data:`PRICING`. Construct a
        :class:`ModelPricing` explicitly rather than guessing a rate — an
        unmetered model is an unmetered budget.
    """
    try:
        return PRICING[model_id]
    except KeyError:
        known = ", ".join(sorted(PRICING))
        raise KeyError(
            f"no published pricing for {model_id!r}; pass an explicit "
            f"ModelPricing. Known models: {known}"
        ) from None


# --------------------------------------------------------------------------
# Usage extraction
# --------------------------------------------------------------------------

UsageExtractor = Callable[[Any], TokenUsage]
"""Reads the true token usage off a call's return value."""

_USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
)


def default_usage_extractor(response: object) -> TokenUsage:
    """Pull a :class:`TokenUsage` out of a model response.

    Understands, in order: a :class:`TokenUsage`; any object or mapping with
    a ``usage`` member (the Anthropic Messages API shape); and any object or
    mapping carrying the token-count fields directly.

    :param response: The value returned by the wrapped call.
    :returns: The token usage it reports.
    :raises TypeError: If no usage information can be found. This is a hard
        error by design — silently metering zero would let an unrecognized
        response shape spend without limit.
    """
    if isinstance(response, TokenUsage):
        return response

    usage: object = response
    if isinstance(response, Mapping):
        if "usage" in response:
            usage = response["usage"]
    elif hasattr(response, "usage"):
        usage = response.usage

    if isinstance(usage, TokenUsage):
        return usage

    counts = {name: _read_count(usage, name) for name in _USAGE_FIELDS}
    if all(value is None for value in counts.values()):
        raise TypeError(
            f"cannot extract token usage from {type(response).__name__}; "
            f"pass an explicit extract_usage callable to the Interceptor"
        )
    return TokenUsage(**{name: value or 0 for name, value in counts.items()})


def _read_count(source: object, name: str) -> int | None:
    """Read one token count from a mapping or an object, if present."""
    raw: object
    if isinstance(source, Mapping):
        if name not in source:
            return None
        raw = source[name]
    else:
        raw = getattr(source, name, None)
        if raw is None:
            return None
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise TypeError(f"usage field {name!r} must be an int, got {raw!r}")
    return raw


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------

R = TypeVar("R")


@dataclass(frozen=True)
class MeteredCall(Generic[R]):
    """The outcome of one governed call: what came back, and what it cost.

    :ivar response: The wrapped call's return value, untouched.
    :ivar usage: The token counts the response reported.
    :ivar cost: The exact settled cost, as posted to the ledger.
    :ivar hold: The amount that was authorized before the call.
    :ivar scope_id: The scope that was charged.
    :ivar model_id: The pricing model applied.
    :ivar entry: The committed ledger entry, for audit correlation.
    :ivar latency_seconds: Wall-clock duration of the wrapped call alone,
        excluding governor overhead.
    """

    response: R
    usage: TokenUsage
    cost: Decimal
    hold: Decimal
    scope_id: str
    model_id: str
    entry: LedgerEntry
    latency_seconds: float

    @property
    def transaction_id(self) -> uuid.UUID:
        """The ledger transaction that settled this call."""
        return self.entry.transaction_id


# --------------------------------------------------------------------------
# SpendGuard
# --------------------------------------------------------------------------


class SpendGuard:
    """Context manager enforcing authorize/capture around one call site.

    Use it directly when the cost only becomes known part-way through — a
    stream that must settle whatever it consumed before re-raising, say::

        with manager_guard as guard:
            chunks = consume(stream)
            guard.settle(pricing.cost_of(usage_so_far))

    No lock is held between ``__enter__`` and ``__exit__``: the governor's
    critical sections live entirely inside
    :meth:`~agentgov.core.BudgetManager.authorize` and
    :meth:`~agentgov.core.BudgetManager.capture`, so the guarded body may
    block on I/O or ``await`` freely.

    :param manager: The governor to enforce against.
    :param scope_id: The scope making the call.
    :param hold: The amount to authorize before the body runs.
    :param memo: Free-form audit context recorded on the settled spend.
    """

    __slots__ = ("_auth", "_entry", "_hold", "_manager", "_memo", "_scope_id", "_settled")

    def __init__(
        self,
        manager: BudgetManager,
        scope_id: str,
        hold: Decimal,
        *,
        memo: str = "",
    ) -> None:
        self._manager = manager
        self._scope_id = scope_id
        self._hold = hold
        self._memo = memo
        self._auth: Authorization | None = None
        self._settled: Decimal | None = None
        self._entry: LedgerEntry | None = None

    @property
    def authorization(self) -> Authorization | None:
        """The active hold, once :meth:`__enter__` has placed it."""
        return self._auth

    @property
    def entry(self) -> LedgerEntry | None:
        """The settled ledger entry, once the guard has exited."""
        return self._entry

    @property
    def cost(self) -> Decimal | None:
        """The cost passed to :meth:`settle`, if any."""
        return self._settled

    def settle(self, cost: Decimal | int | str) -> None:
        """Declare the true cost of the guarded call.

        May be called more than once; the last value wins. If it is never
        called and the body completes normally, the guard conservatively
        captures the full hold and logs a warning — under-charging is the one
        failure mode a spend governor must not have.

        :param cost: The actual cost incurred.
        """
        self._settled = money(cost)

    def __enter__(self) -> Self:
        """Place the authorization hold.

        :raises ~agentgov.exceptions.CircuitOpenError: If the scope is halted.
        :raises ~agentgov.exceptions.DenialOfWalletError: If the hold exceeds
            the scope's available balance.
        """
        self._auth = self._manager.authorize(
            self._scope_id, self._hold, memo=self._memo or "call authorization"
        )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Capture the settled cost, or void the hold if the body raised."""
        auth = self._auth
        if auth is None:
            return

        if exc_type is not None:
            self._manager.void(auth, memo="call failed; hold released")
            return

        if self._settled is None:
            logger.warning(
                "scope %s did not settle its call cost; capturing the full authorization of %s",
                self._scope_id,
                auth.amount,
            )
            self._settled = auth.amount

        self._entry = self._manager.capture(
            auth, self._settled, memo=self._memo or "settled call cost"
        )


# --------------------------------------------------------------------------
# Interceptor
# --------------------------------------------------------------------------


class Interceptor:
    """Wraps model calls so every one of them is metered and enforced.

    Bind one to a scope, then call through it::

        gov = Interceptor(manager, "researcher", model="claude-opus-5")
        result = gov.invoke(client.messages.create, model=..., messages=[...])
        print(result.cost)

    Each :meth:`invoke` authorizes a worst-case hold, runs the call outside
    the governor's lock, prices the returned usage exactly, and settles.

    Interceptors are cheap and immutable in practice — use :meth:`for_scope`
    to bind a child sub-agent and :meth:`with_hold` to override the hold for
    one prompt, rather than mutating a shared instance.

    :param manager: The governor to enforce against.
    :param scope_id: The scope charged for calls made through this instance.
    :param model: Model id used to look up pricing when ``pricing`` is omitted.
    :param pricing: Explicit rates, for models or platforms not in
        :data:`PRICING`.
    :param max_output_tokens: Output ceiling assumed when sizing the default
        hold. Should match the ``max_tokens`` sent to the model.
    :param estimated_input_tokens: Input size assumed when sizing the default
        hold.
    :param extract_usage: Reads token usage off the response;
        :func:`default_usage_extractor` handles Anthropic SDK responses,
        mappings, and :class:`TokenUsage` directly.
    :param hold: Fixed hold amount, overriding the estimate entirely.
    :raises KeyError: If ``model`` has no published pricing and ``pricing``
        was not supplied.
    """

    __slots__ = (
        "_estimated_input_tokens",
        "_extract_usage",
        "_hold",
        "_manager",
        "_max_output_tokens",
        "_pricing",
        "_scope_id",
    )

    def __init__(
        self,
        manager: BudgetManager,
        scope_id: str,
        *,
        model: str = "claude-opus-5",
        pricing: ModelPricing | None = None,
        max_output_tokens: int = 4096,
        estimated_input_tokens: int = 2000,
        extract_usage: UsageExtractor = default_usage_extractor,
        hold: Decimal | None = None,
    ) -> None:
        if max_output_tokens < 0 or estimated_input_tokens < 0:
            raise ValueError("token estimates must not be negative")
        self._manager = manager
        self._scope_id = scope_id
        self._pricing = pricing if pricing is not None else pricing_for(model)
        self._max_output_tokens = max_output_tokens
        self._estimated_input_tokens = estimated_input_tokens
        self._extract_usage = extract_usage
        self._hold = hold

    # -- accessors --------------------------------------------------------

    @property
    def manager(self) -> BudgetManager:
        """The governor this interceptor enforces against."""
        return self._manager

    @property
    def scope_id(self) -> str:
        """The scope charged for calls made through this interceptor."""
        return self._scope_id

    @property
    def pricing(self) -> ModelPricing:
        """The rates applied to metered calls."""
        return self._pricing

    @property
    def hold_amount(self) -> Decimal:
        """The amount authorized before each call.

        The explicit ``hold``, when one was given; otherwise a worst-case
        estimate from the configured token bounds.
        """
        if self._hold is not None:
            return self._hold
        return self._pricing.estimate(self._estimated_input_tokens, self._max_output_tokens)

    # -- derivation -------------------------------------------------------

    def for_scope(self, scope_id: str) -> Interceptor:
        """Return a copy of this interceptor bound to a different scope.

        The natural way to hand a freshly delegated sub-agent its own
        metered client while sharing pricing and extraction config.

        :param scope_id: The scope the copy will charge.
        """
        return self._clone(scope_id=scope_id)

    def with_hold(self, hold: Decimal | int | str) -> Interceptor:
        """Return a copy that authorizes a specific amount per call.

        Use it to size the hold to a particular prompt::

            gov.with_hold(gov.pricing.estimate(len(prompt) // 4, 1024)).invoke(fn)

        :param hold: The exact amount to authorize.
        """
        return self._clone(hold=money(hold))

    def with_limits(
        self,
        *,
        estimated_input_tokens: int | None = None,
        max_output_tokens: int | None = None,
    ) -> Interceptor:
        """Return a copy whose default hold is sized by different token bounds.

        :param estimated_input_tokens: New expected input size.
        :param max_output_tokens: New output ceiling.
        """
        return self._clone(
            estimated_input_tokens=estimated_input_tokens,
            max_output_tokens=max_output_tokens,
            hold=None,
        )

    def _clone(
        self,
        *,
        scope_id: str | None = None,
        hold: Decimal | None = None,
        estimated_input_tokens: int | None = None,
        max_output_tokens: int | None = None,
    ) -> Interceptor:
        """Construct a variant of this interceptor."""
        return Interceptor(
            self._manager,
            scope_id if scope_id is not None else self._scope_id,
            pricing=self._pricing,
            max_output_tokens=(
                max_output_tokens if max_output_tokens is not None else self._max_output_tokens
            ),
            estimated_input_tokens=(
                estimated_input_tokens
                if estimated_input_tokens is not None
                else self._estimated_input_tokens
            ),
            extract_usage=self._extract_usage,
            hold=hold if hold is not None else self._hold,
        )

    # -- enforcement ------------------------------------------------------

    def guard(self, *, memo: str = "") -> SpendGuard:
        """Return a :class:`SpendGuard` for manual authorize/capture.

        :param memo: Free-form audit context recorded on the settled spend.
        """
        return SpendGuard(self._manager, self._scope_id, self.hold_amount, memo=memo)

    def invoke(
        self,
        fn: Callable[..., R],
        /,
        *args: object,
        **kwargs: object,
    ) -> MeteredCall[R]:
        """Call ``fn`` under budget enforcement and settle its exact cost.

        ``fn`` is invoked with no lock held, so it may block on I/O for as
        long as it needs.

        :param fn: The model or tool call to make.
        :param args: Positional arguments forwarded to ``fn``.
        :param kwargs: Keyword arguments forwarded to ``fn``.
        :returns: The response together with its usage, settled cost, and
            ledger entry.
        :raises ~agentgov.exceptions.CircuitOpenError: If the scope is halted.
        :raises ~agentgov.exceptions.DenialOfWalletError: If the hold exceeds
            the available balance, or the settled cost overdrew the scope.
        :raises TypeError: If token usage cannot be read from the response.
        """
        hold = self.hold_amount
        guard = SpendGuard(self._manager, self._scope_id, hold)
        with guard:
            started = time.perf_counter()
            response = fn(*args, **kwargs)
            latency = time.perf_counter() - started
            usage, cost = self._price(response)
            guard.settle(cost)
        return self._result(response, usage, cost, hold, guard, latency)

    async def ainvoke(
        self,
        fn: Callable[..., Awaitable[R]],
        /,
        *args: object,
        **kwargs: object,
    ) -> MeteredCall[R]:
        """Await ``fn`` under budget enforcement and settle its exact cost.

        The async counterpart of :meth:`invoke`. The governor's mutex is
        never held across the ``await``, so concurrent tasks contend only for
        the microseconds each ledger write takes.

        :param fn: The awaitable model or tool call to make.
        :param args: Positional arguments forwarded to ``fn``.
        :param kwargs: Keyword arguments forwarded to ``fn``.
        :returns: The response together with its usage, settled cost, and
            ledger entry.
        """
        hold = self.hold_amount
        guard = SpendGuard(self._manager, self._scope_id, hold)
        with guard:
            started = time.perf_counter()
            response = await fn(*args, **kwargs)
            latency = time.perf_counter() - started
            usage, cost = self._price(response)
            guard.settle(cost)
        return self._result(response, usage, cost, hold, guard, latency)

    def _price(self, response: object) -> tuple[TokenUsage, Decimal]:
        """Extract usage from a response and price it."""
        usage = self._extract_usage(response)
        return usage, self._pricing.cost_of(usage)

    def _result(
        self,
        response: R,
        usage: TokenUsage,
        cost: Decimal,
        hold: Decimal,
        guard: SpendGuard,
        latency: float,
    ) -> MeteredCall[R]:
        """Assemble the metered result once the guard has settled."""
        entry = guard.entry
        if entry is None:  # pragma: no cover - the guard always settles here
            raise RuntimeError("spend guard exited without settling")
        logger.info(
            "metered call scope=%s model=%s tokens=%d cost=%s hold=%s latency=%.4fs txn=%s",
            self._scope_id,
            self._pricing.model_id,
            usage.total_tokens,
            cost,
            hold,
            latency,
            entry.transaction_id,
        )
        return MeteredCall(
            response=response,
            usage=usage,
            cost=cost,
            hold=hold,
            scope_id=self._scope_id,
            model_id=self._pricing.model_id,
            entry=entry,
            latency_seconds=latency,
        )
