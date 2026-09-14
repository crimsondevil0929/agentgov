"""CrewAI adapter, and a generic wrapper for any framework reporting usage totals.

CrewAI does not surface individual model calls. It runs a crew to completion
and hands back a ``UsageMetrics`` object with the totals for the whole run.
That shapes the integration in two ways worth stating plainly:

**Settlement is per-run, not per-call.** A hold is placed before ``kickoff()``
covering the whole crew, and settled once against the reported totals. Budget
enforcement is therefore at run granularity: AgentGov stops the *next* run, not
the middle of this one. For mid-run enforcement, govern the underlying model
too — the LangChain adapter or :func:`~agentgov.proxy.govern` on the client
gives per-call control, and the two compose.

**Usage metrics are cumulative.** CrewAI accumulates ``token_usage`` across
every ``kickoff()`` on the same crew object. Settling the reported total each
time would bill the first run again on the second, and again on the third.
:class:`GovernedCrew` tracks what it has already settled and charges only the
delta — a detail that is easy to miss and expensive to get wrong.

Nothing here imports CrewAI; every object is duck-typed and tested with fakes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, TypeVar

from agentgov.core import BudgetManager
from agentgov.exceptions import CircuitBreakerError
from agentgov.interceptor import Interceptor, TokenUsage
from agentgov.reconciliation import MeteringJournal

__all__ = [
    "CrewHalted",
    "GovernedCrew",
    "extract_crew_usage",
    "govern_agent",
    "govern_crew",
]

logger = logging.getLogger("agentgov.adapters.crewai")

R = TypeVar("R")

_USAGE_CONTAINERS = ("token_usage", "usage_metrics", "usage")
_INPUT_ALIASES = ("prompt_tokens", "input_tokens")
_OUTPUT_ALIASES = ("completion_tokens", "output_tokens")
_CACHED_ALIASES = ("cached_prompt_tokens", "cache_read_input_tokens")


@dataclass(frozen=True, slots=True)
class CrewHalted:
    """Returned in place of a result when a halted crew exits gracefully.

    A circuit-breaker trip mid-crew is a governance decision, not a crash. When
    :class:`GovernedCrew` is built with ``raise_on_halt=False`` it returns this
    instead of propagating, so an orchestrator can record a failed task and
    move on without unwinding the rest of the crew's state.

    :ivar scope_id: The scope that was halted.
    :ivar reason: Why the breaker tripped.
    :ivar error: The original exception, for logging or re-raising.
    :ivar settled_cost: What the run had already spent when it was stopped.
    """

    scope_id: str
    reason: str
    error: CircuitBreakerError
    settled_cost: Decimal = Decimal(0)

    def __bool__(self) -> bool:
        """Falsey, so ``if not result:`` reads correctly at a call site."""
        return False


def _read_int(source: object, aliases: Sequence[str]) -> int:
    """Pull the first present integer among ``aliases`` off a dict or object."""
    for alias in aliases:
        value = source.get(alias) if isinstance(source, Mapping) else getattr(source, alias, None)
        if isinstance(value, bool):
            continue
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
    return 0


def extract_crew_usage(result: object) -> TokenUsage:
    """Read cumulative token counts off a CrewAI result or usage object.

    Accepts a ``CrewOutput`` (looking at ``token_usage``), a bare
    ``UsageMetrics``, a crew object carrying ``usage_metrics``, or a plain
    mapping of the same fields.

    :param result: The object to read.
    :returns: The token counts found; all-zero when the object reports none.
    """
    for container in _USAGE_CONTAINERS:
        holder = (
            result.get(container)
            if isinstance(result, Mapping)
            else getattr(result, container, None)
        )
        if holder is None:
            continue
        usage = TokenUsage(
            input_tokens=_read_int(holder, _INPUT_ALIASES),
            output_tokens=_read_int(holder, _OUTPUT_ALIASES),
            cache_read_input_tokens=_read_int(holder, _CACHED_ALIASES),
        )
        if usage.total_tokens:
            return usage

    direct = TokenUsage(
        input_tokens=_read_int(result, _INPUT_ALIASES),
        output_tokens=_read_int(result, _OUTPUT_ALIASES),
        cache_read_input_tokens=_read_int(result, _CACHED_ALIASES),
    )
    return direct


class GovernedCrew:
    """A CrewAI crew whose runs are budgeted, metered, and settled.

    The two-line drop-in::

        crew = GovernedCrew(Crew(agents=[...], tasks=[...]), gov, "research-crew")
        result = crew.kickoff()          # unchanged call site, now governed

    Attribute access falls through to the wrapped crew, so everything this
    adapter does not govern keeps working unchanged.

    **Graceful halting.** With the default ``raise_on_halt=True`` a breaker
    trip propagates as a :class:`~agentgov.exceptions.CircuitBreakerError`.
    Set it to ``False`` and :meth:`kickoff` returns a falsey
    :class:`CrewHalted` instead, so a supervising orchestrator can record the
    failure and continue. Either way the hold is always resolved first, so a
    halted crew never strands budget.

    :param crew: The CrewAI crew to wrap. Never mutated.
    :param manager: The governor to enforce against.
    :param scope_id: The scope this crew's runs are charged to.
    :param model: Model id used to look up pricing.
    :param raise_on_halt: Whether a breaker trip propagates or returns
        :class:`CrewHalted`.
    :param journal: Optional metering journal, for later reconciliation.
    :param interceptor: An existing interceptor to use instead of building one.
    :param interceptor_options: Forwarded to :class:`~agentgov.interceptor.Interceptor`.
    """

    __slots__ = ("_crew", "_interceptor", "_journal", "_raise_on_halt", "_settled_usage")

    def __init__(
        self,
        crew: object,
        manager: BudgetManager | None = None,
        scope_id: str = "",
        *,
        model: str = "claude-opus-5",
        raise_on_halt: bool = True,
        journal: MeteringJournal | None = None,
        interceptor: Interceptor | None = None,
        **interceptor_options: Any,
    ) -> None:
        if interceptor is None:
            if manager is None or not scope_id:
                raise ValueError(
                    "provide either an interceptor, or a manager and scope_id to build one"
                )
            interceptor = Interceptor(manager, scope_id, model=model, **interceptor_options)
        self._crew = crew
        self._interceptor = interceptor
        self._raise_on_halt = raise_on_halt
        self._journal = journal
        # CrewAI accumulates usage across kickoffs on one crew object; this is
        # what has already been billed, so each run settles only its delta.
        self._settled_usage = TokenUsage()

    @property
    def interceptor(self) -> Interceptor:
        """The underlying primitive, unchanged and reachable."""
        return self._interceptor

    @property
    def raw(self) -> object:
        """The unwrapped crew."""
        return self._crew

    @property
    def settled_usage(self) -> TokenUsage:
        """Cumulative usage already billed across every run of this crew."""
        return self._settled_usage

    def __repr__(self) -> str:
        return f"<governed {self._crew!r} scope={self._interceptor.scope_id!r}>"

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            # Without this, an attribute miss during construction or copying
            # recurses forever through this same __getattr__.
            raise AttributeError(name)
        return getattr(self._crew, name)

    def kickoff(self, *args: object, **kwargs: object) -> Any:
        """Run the crew under budget enforcement and settle its true cost.

        :param args: Forwarded to the crew's own ``kickoff``.
        :param kwargs: Forwarded to the crew's own ``kickoff``.
        :returns: The crew's own result, or :class:`CrewHalted` when the
            breaker tripped and ``raise_on_halt`` is ``False``.
        :raises ~agentgov.exceptions.DenialOfWalletError: If the scope cannot
            afford the run.
        :raises ~agentgov.exceptions.CircuitBreakerError: If the scope is
            halted and ``raise_on_halt`` is ``True``.
        """
        return self._run(self._crew.kickoff, args, kwargs)  # type: ignore[attr-defined]

    async def kickoff_async(self, *args: object, **kwargs: object) -> Any:
        """Async counterpart of :meth:`kickoff`."""
        try:
            authorization = self._authorize(args, kwargs)
        except CircuitBreakerError as error:
            return self._halted(error)

        try:
            result = await self._crew.kickoff_async(*args, **kwargs)  # type: ignore[attr-defined]
        except BaseException:
            self._interceptor.manager.void(authorization, memo="crew run failed")
            raise
        return self._settle(authorization, result)

    # -- internals --------------------------------------------------------

    def _run(
        self, call: Callable[..., Any], args: Sequence[object], kwargs: Mapping[str, object]
    ) -> Any:
        try:
            authorization = self._authorize(args, kwargs)
        except CircuitBreakerError as error:
            # Halted before anything ran: nothing to unwind, nothing to bill.
            return self._halted(error)

        try:
            result = call(*args, **kwargs)
        except BaseException:
            # The crew failed on its own terms. Release the encumbrance rather
            # than bill for a run that produced nothing we can account for.
            self._interceptor.manager.void(authorization, memo="crew run failed")
            raise
        return self._settle(authorization, result)

    def _authorize(self, args: Sequence[object], kwargs: Mapping[str, object]) -> Any:
        """Check the breakers and place a hold for one whole run."""
        payload = dict(kwargs)
        breaker = self._interceptor.cognitive
        if breaker is not None:
            breaker.observe_call(
                self._interceptor.scope_id,
                "crewai.kickoff",
                args,
                payload,
                trajectory=self._interceptor.trajectory,
            )
        hold = self._interceptor.size_hold(args, payload)
        return self._interceptor.manager.authorize(
            self._interceptor.scope_id, hold, memo="crew run authorization"
        )

    def _settle(self, authorization: Any, result: object) -> Any:
        """Bill only what this run added to the crew's cumulative totals."""
        cumulative = extract_crew_usage(result)
        if cumulative.total_tokens == 0:
            cumulative = extract_crew_usage(self._crew)

        delta = TokenUsage(
            input_tokens=max(0, cumulative.input_tokens - self._settled_usage.input_tokens),
            output_tokens=max(0, cumulative.output_tokens - self._settled_usage.output_tokens),
            cache_read_input_tokens=max(
                0,
                cumulative.cache_read_input_tokens - self._settled_usage.cache_read_input_tokens,
            ),
        )
        cost = self._interceptor.pricing.cost_of(delta)
        if cost <= 0:
            logger.warning(
                "crew run for scope %s reported no new usage; releasing the hold",
                self._interceptor.scope_id,
            )
            self._interceptor.manager.void(authorization, memo="crew run reported no usage")
            return result

        entry = self._interceptor.manager.capture(authorization, cost, memo="crew run")
        # Only advance the watermark once the settlement is committed.
        self._settled_usage = cumulative
        if self._journal is not None:
            self._journal.record_usage(
                entry.transaction_id,
                self._interceptor.pricing.model_id,
                delta,
                self._interceptor.scope_id,
                entry.timestamp,
            )
        return result

    def _halted(self, error: CircuitBreakerError) -> Any:
        """Raise or return, per policy — but never leave state half-built."""
        if self._raise_on_halt:
            raise error
        logger.warning(
            "crew for scope %s halted by the governor: %s", self._interceptor.scope_id, error
        )
        return CrewHalted(
            scope_id=self._interceptor.scope_id,
            reason=str(error),
            error=error,
            settled_cost=self._interceptor.pricing.cost_of(self._settled_usage),
        )


def govern_crew(
    crew: object, manager: BudgetManager, scope_id: str, **options: Any
) -> GovernedCrew:
    """Wrap a CrewAI crew in one call.

    :param crew: The crew to govern.
    :param manager: The governor to enforce against.
    :param scope_id: The scope this crew's runs are charged to.
    :param options: Forwarded to :class:`GovernedCrew`.
    :returns: The governed crew.
    """
    return GovernedCrew(crew, manager, scope_id, **options)


def govern_agent(
    manager: BudgetManager,
    scope_id: str,
    *,
    model: str = "claude-opus-5",
    usage_of: Callable[[object], TokenUsage] = extract_crew_usage,
    journal: MeteringJournal | None = None,
    interceptor: Interceptor | None = None,
    **interceptor_options: Any,
) -> Callable[[Callable[..., R]], Callable[..., R]]:
    """Decorate any agent-execution function so its run is governed.

    The generic escape hatch: for a framework this package has no adapter for,
    wrap the function that runs one unit of agent work and tell AgentGov how to
    read usage off whatever it returns::

        @govern_agent(gov, "researcher", usage_of=my_framework_usage)
        def run_research(topic: str) -> Report:
            ...

    A hold is placed before the call, the result is priced by ``usage_of``, and
    the hold is settled — or voided if the function raises.

    :param manager: The governor to enforce against.
    :param scope_id: The scope charged for these runs.
    :param model: Model id used to look up pricing.
    :param usage_of: Reads token counts off the wrapped function's return value.
    :param journal: Optional metering journal, for later reconciliation.
    :param interceptor: An existing interceptor to use instead of building one.
    :param interceptor_options: Forwarded to :class:`~agentgov.interceptor.Interceptor`.
    :returns: A decorator.
    """
    resolved = (
        interceptor
        if interceptor is not None
        else Interceptor(manager, scope_id, model=model, **interceptor_options)
    )

    def decorate(function: Callable[..., R]) -> Callable[..., R]:
        def governed(*args: object, **kwargs: object) -> R:
            breaker = resolved.cognitive
            if breaker is not None:
                breaker.observe_call(
                    resolved.scope_id,
                    getattr(function, "__name__", "agent"),
                    args,
                    kwargs,
                    trajectory=resolved.trajectory,
                )
            authorization = resolved.manager.authorize(
                resolved.scope_id, resolved.size_hold(args, kwargs), memo="agent run authorization"
            )
            try:
                result = function(*args, **kwargs)
            except BaseException:
                resolved.manager.void(authorization, memo="agent run failed")
                raise

            usage = usage_of(result)
            cost = resolved.pricing.cost_of(usage)
            if cost <= 0:
                resolved.manager.void(authorization, memo="agent run reported no usage")
                return result
            entry = resolved.manager.capture(authorization, cost, memo="agent run")
            if journal is not None:
                journal.record_usage(
                    entry.transaction_id,
                    resolved.pricing.model_id,
                    usage,
                    resolved.scope_id,
                    entry.timestamp,
                )
            return result

        governed.__name__ = getattr(function, "__name__", "governed")
        governed.__doc__ = function.__doc__
        governed.__wrapped__ = function  # type: ignore[attr-defined]
        return governed

    return decorate
