"""Exception hierarchy for AgentGov's circuit-breaker and ledger enforcement.

Every error an agent-facing caller can observe is one of these types. The
hierarchy separates three concerns that must never be conflated in a
financial control plane:

- :class:`BudgetError` — the spend was **refused**. Expected, catchable
  control flow. No money moved.
- :class:`CircuitBreakerError` — the scope is **halted**. A latching safety
  control has tripped; execution must stop until an operator resets it.
- :class:`LedgerError` — the ledger itself is **compromised**. Never
  expected; indicates a bug, a race, or tampering. Let it propagate.

The single most important type here is :class:`DenialOfWalletError`: the
hard backstop raised when an agent attempts to overdraw its envelope. It is
both a budget refusal *and* a breaker trip, so it subclasses
:class:`BudgetExceededError` while carrying the tripped-scope details.
"""

from __future__ import annotations

from decimal import Decimal

__all__ = [
    "AgentGovError",
    "AgentThrashingError",
    "AgentThrashingException",
    "BudgetError",
    "BudgetExceededError",
    "CircuitBreakerError",
    "CircuitOpenError",
    "DenialOfWalletError",
    "DenialOfWalletException",
    "DoubleSpendError",
    "DuplicateScopeError",
    "LedgerError",
    "LedgerIntegrityError",
    "RunawayLoopDetectedError",
    "ScopeError",
    "SubBudgetAllocationError",
    "UnknownScopeError",
]


class AgentGovError(Exception):
    """Base class for all errors raised by AgentGov.

    Catch this to handle any AgentGov-originated failure without
    distinguishing budget exhaustion from ledger integrity failures.
    """


# --------------------------------------------------------------------------
# Scope / topology errors
# --------------------------------------------------------------------------


class ScopeError(AgentGovError):
    """Base class for errors about the identity or shape of a budget scope."""


class UnknownScopeError(ScopeError):
    """Raised when an operation names a scope that is not registered.

    :param scope_id: The scope identifier that could not be resolved.
    """

    def __init__(self, scope_id: str) -> None:
        self.scope_id = scope_id
        super().__init__(f"Unknown budget scope: {scope_id!r}")


class DuplicateScopeError(ScopeError):
    """Raised when registering a scope identifier that is already in use.

    Scope ids are permanent: reusing one would splice a new agent's spend
    into another agent's audit history, so it is always rejected.

    :param scope_id: The scope identifier that is already registered.
    """

    def __init__(self, scope_id: str) -> None:
        self.scope_id = scope_id
        super().__init__(f"Budget scope already registered: {scope_id!r}")


# --------------------------------------------------------------------------
# Budget errors — the spend was refused; no money moved
# --------------------------------------------------------------------------


class BudgetError(AgentGovError):
    """Base class for errors related to spend envelopes and budget limits."""


class BudgetExceededError(BudgetError):
    """Raised when a spend would exceed the caller's remaining budget.

    Signals that the requested debit was rejected *before* any funds moved,
    not that the ledger is broken.

    :param requested: The amount that was requested to be spent.
    :param available: The amount actually available in the budget.
    :param scope_id: Identifier of the budget node that rejected the spend.
    """

    def __init__(self, requested: Decimal, available: Decimal, scope_id: str) -> None:
        self.requested = requested
        self.available = available
        self.scope_id = scope_id
        super().__init__(
            f"Budget exceeded for scope {scope_id!r}: requested {requested}, available {available}"
        )


class DenialOfWalletError(BudgetExceededError):
    """The hard backstop: an agent tried to overdraw its spend envelope.

    Raised when a scope requests more than it has available, or when a
    settled cost overran the authorization that covered it. Unlike a plain
    :class:`BudgetExceededError`, raising this **latches the circuit
    breaker** for the offending scope and every descendant beneath it —
    subsequent calls fail fast with :class:`CircuitOpenError` until an
    operator calls ``BudgetManager.reset()``.

    This is the OWASP ASI "Denial of Wallet" control point: it stops a
    runaway sub-agent tree at the kernel level rather than discovering the
    overspend at settlement time.

    :param requested: The amount the scope attempted to spend.
    :param available: The amount actually available when the attempt was made.
    :param scope_id: Identifier of the budget node that was halted.
    :param overspent: ``True`` when the money was already irreversibly spent
        (a capture overran its authorization) and the ledger had to record
        an overdraft. ``False`` when the spend was refused pre-flight and
        nothing moved.
    """

    def __init__(
        self,
        requested: Decimal,
        available: Decimal,
        scope_id: str,
        *,
        overspent: bool = False,
    ) -> None:
        super().__init__(requested, available, scope_id)
        self.overspent = overspent
        verb = "overspent" if overspent else "refused"
        self.args = (
            f"Denial-of-wallet backstop tripped for scope {scope_id!r} ({verb}): "
            f"requested {requested}, available {available}",
        )


DenialOfWalletException = DenialOfWalletError
"""Alias for :class:`DenialOfWalletError`, for callers who prefer the
``Exception`` suffix. Both names refer to the same class."""


class SubBudgetAllocationError(BudgetError):
    """Raised when a parent budget cannot delegate the requested sub-limit.

    Occurs when a root or intermediate agent attempts to allocate a child
    budget larger than its own remaining, unencumbered balance, or when the
    delegation would breach the configured maximum tree depth.

    :param requested: The sub-budget amount requested for delegation.
    :param available: The amount actually available to delegate.
    :param parent_scope_id: Identifier of the parent budget node.
    :param detail: Optional explanation when the failure is structural
        (e.g. maximum depth exceeded) rather than a shortfall.
    """

    def __init__(
        self,
        requested: Decimal,
        available: Decimal,
        parent_scope_id: str,
        detail: str = "",
    ) -> None:
        self.requested = requested
        self.available = available
        self.parent_scope_id = parent_scope_id
        self.detail = detail
        message = (
            f"Cannot allocate sub-budget from {parent_scope_id!r}: "
            f"requested {requested}, available {available}"
        )
        if detail:
            message = f"{message} ({detail})"
        super().__init__(message)


# --------------------------------------------------------------------------
# Circuit-breaker errors — the scope is halted
# --------------------------------------------------------------------------


class CircuitBreakerError(AgentGovError):
    """Base class for errors raised by the kernel-level circuit breaker."""


class CircuitOpenError(CircuitBreakerError):
    """Raised when a call is attempted while the circuit breaker is open.

    The breaker latches: once tripped it stays open until
    ``BudgetManager.reset()`` is called. A trip on any ancestor halts the
    entire subtree beneath it, so ``tripped_scope_id`` may differ from the
    scope that attempted the call.

    :param scope_id: The scope that attempted the call.
    :param tripped_scope_id: The scope whose breaker is actually open —
        equal to ``scope_id``, or one of its ancestors.
    :param reason: Human-readable reason the breaker tripped.
    """

    def __init__(self, scope_id: str, tripped_scope_id: str, reason: str) -> None:
        self.scope_id = scope_id
        self.tripped_scope_id = tripped_scope_id
        self.reason = reason
        where = (
            "its own breaker" if scope_id == tripped_scope_id else f"ancestor {tripped_scope_id!r}"
        )
        super().__init__(f"Scope {scope_id!r} is halted by {where}: {reason}")


class AgentThrashingError(CircuitBreakerError):
    """Raised when the cognitive breaker finds an agent looping without progress.

    Where :class:`DenialOfWalletError` is reactive — it fires once the money
    is gone — this is the *causal* control: it halts the open-loop execution
    cycle that would have burned the envelope, typically for a fraction of a
    cent. An agent re-issuing the same tool call, nudging a query without
    advancing, or oscillating between two tools is thrashing, and no amount
    of remaining budget makes continuing worthwhile.

    Like every other breaker trip this latches: the trajectory stays halted
    until :meth:`~agentgov.cognitive.CognitiveBreaker.reset` is called, so a
    retry storm cannot wear it down.

    :param scope_id: The budget scope that made the offending call.
    :param trajectory: The logical unit of work that was found to be looping.
        May span several scopes when an orchestrator retries via fresh
        sub-agents.
    :param detector: Name of the heuristic that fired.
    :param reason: Human-readable explanation of the loop.
    :param observations: Calls seen in this trajectory when it tripped.
    :param confidence: The detector's confidence, ``0..1``.
    :param tier: ``"deterministic"`` for an inline detector, ``"semantic"``
        for one reached on the background lane.
    :param evidence: Detector-specific detail, for debugging and audit.
    """

    def __init__(
        self,
        scope_id: str,
        trajectory: str,
        detector: str,
        reason: str,
        *,
        observations: int = 0,
        confidence: float = 1.0,
        tier: str = "deterministic",
        evidence: dict[str, str] | None = None,
    ) -> None:
        self.scope_id = scope_id
        self.trajectory = trajectory
        self.detector = detector
        self.reason = reason
        self.observations = observations
        self.confidence = confidence
        self.tier = tier
        self.evidence = evidence if evidence is not None else {}
        where = (
            f"scope {scope_id!r}"
            if trajectory == scope_id
            else f"scope {scope_id!r} (trajectory {trajectory!r})"
        )
        super().__init__(
            f"Agent thrashing halted for {where} after {observations} calls "
            f"[{tier}/{detector}, confidence {confidence:.2f}]: {reason}"
        )


AgentThrashingException = AgentThrashingError
"""Alias for :class:`AgentThrashingError`, for callers who prefer the
``Exception`` suffix. Both names refer to the same class."""


class RunawayLoopDetectedError(CircuitBreakerError):
    """Raised when the breaker detects a denial-of-wallet loop pattern.

    Signals that call frequency for a scope exceeded the configured
    velocity limit, independent of whether the dollar budget itself has
    been exhausted yet. This catches the runaway-loop failure mode *before*
    it converts into spend.

    :param scope_id: Identifier of the budget node exhibiting runaway behavior.
    :param call_count: Number of calls observed within the detection window.
    :param window_seconds: Length of the detection window, in seconds.
    """

    def __init__(self, scope_id: str, call_count: int, window_seconds: float) -> None:
        self.scope_id = scope_id
        self.call_count = call_count
        self.window_seconds = window_seconds
        super().__init__(
            f"Runaway loop detected for scope {scope_id!r}: "
            f"{call_count} authorizations in {window_seconds}s"
        )


# --------------------------------------------------------------------------
# Ledger errors — the books are compromised
# --------------------------------------------------------------------------


class LedgerError(AgentGovError):
    """Base class for errors indicating the ledger itself is compromised.

    These are never expected in normal operation. They indicate a bug,
    a concurrent-write race, or a tamper attempt, and callers should
    generally let them propagate rather than catch-and-continue.
    """


class LedgerIntegrityError(LedgerError):
    """Raised when the ledger fails an atomicity, hash-chain, or
    conservation check.

    :param detail: Description of the specific integrity violation.
    :param scope_id: The scope the violation was detected on, when the
        violation is scope-local rather than global.
    """

    def __init__(self, detail: str, scope_id: str | None = None) -> None:
        self.detail = detail
        self.scope_id = scope_id
        where = f" for scope {scope_id!r}" if scope_id else ""
        super().__init__(f"Ledger integrity violation{where}: {detail}")


class DoubleSpendError(LedgerError):
    """Raised when an authorization is settled more than once.

    Each authorization hold may be captured or voided exactly once.
    A second attempt would debit the same encumbrance twice, so it is
    rejected before anything is written.

    :param scope_id: Identifier of the contended budget node.
    :param authorization_id: The authorization that was already settled.
    :param detail: What the second attempt tried to do.
    """

    def __init__(self, scope_id: str, authorization_id: str, detail: str) -> None:
        self.scope_id = scope_id
        self.authorization_id = authorization_id
        self.detail = detail
        super().__init__(
            f"Double-spend rejected for scope {scope_id!r}: "
            f"authorization {authorization_id} {detail}"
        )
