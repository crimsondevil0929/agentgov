"""Exception hierarchy for AgentGov's circuit-breaker and ledger enforcement.

Every error an agent-facing caller can observe is one of these types. The
hierarchy separates three concerns that must never be conflated in a
financial control plane:

- :class:`BudgetError` — the spend was **refused**. Expected, catchable
  control flow. No money moved.
- :class:`CircuitBreakerError` — the scope is **halted**. A latching safety
  control has tripped; execution must stop until an operator resets it.
- :class:`LedgerError` — the ledger itself is **compromised**. Never
  expected; indicates a bug or tampering. Let it propagate.
- :class:`StorageError` — the durable backend is **unavailable or
  contended**. An operational condition with an operational fix, kept
  strictly apart from :class:`LedgerError` so that a second process opening
  the same database never masquerades as a corrupted audit chain.
- :class:`ReceiptError` — a receipt, proof or witness record **does not
  verify**. Evidence handed to a verifier is untrusted input; this is the
  answer when it does not hold up.

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
    "ConcurrentGovernorError",
    "DenialOfWalletError",
    "DenialOfWalletException",
    "DoubleSpendError",
    "DuplicateScopeError",
    "LedgerError",
    "LedgerIntegrityError",
    "MalformedReceiptError",
    "ReadOnlyLedgerError",
    "ReceiptError",
    "ReceiptLogError",
    "ReceiptSignatureError",
    "RowDisclosureError",
    "RunawayLoopDetectedError",
    "ScopeError",
    "SignerUnavailableError",
    "StorageError",
    "SubBudgetAllocationError",
    "UnknownScopeError",
    "WitnessError",
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
# Storage errors — the backend is unavailable, not the books untrustworthy
# --------------------------------------------------------------------------


class StorageError(AgentGovError):
    """Base class for problems with the durable backend itself.

    Deliberately *not* a :class:`LedgerError`. A ledger error means the books
    cannot be trusted and someone should be paged; a storage error means the
    process could not reach or claim its database, which has an operational
    remedy. Conflating the two trains operators to ignore the alarm that
    actually matters.
    """


class ConcurrentGovernorError(StorageError):
    """Raised when another process already holds this database.

    A :class:`~agentgov.core.BudgetManager` keeps authoritative balances in
    memory and writes through to disk. Two processes doing that against one
    file would each hold a private, diverging view of the same envelope, so
    the second one is refused at open rather than allowed to start and then
    fail on its first write.

    The remedies, in the order most deployments want them:

    - run a single governor process and let workers call into it;
    - give each worker its own database file and its own delegated
      sub-budget, so the envelopes are genuinely separate;
    - open read-only (``read_only=True``) to inspect or audit a live ledger.

    :param path: The database file that is already claimed.
    :param holder_pid: PID recorded by the holding process, when it could be
        read. ``None`` if the lock file was unreadable or held by a process
        that never wrote its identity.
    :param holder_host: Hostname recorded by the holding process, if known.
    :param holder_since: ISO-8601 instant the holder claimed the lock.
    """

    def __init__(
        self,
        path: str,
        holder_pid: int | None = None,
        holder_host: str | None = None,
        holder_since: str | None = None,
    ) -> None:
        self.path = path
        self.holder_pid = holder_pid
        self.holder_host = holder_host
        self.holder_since = holder_since
        if holder_pid is None:
            who = "another process"
        else:
            where = f"@{holder_host}" if holder_host else ""
            since = f", since {holder_since}" if holder_since else ""
            who = f"PID {holder_pid}{where}{since}"
        super().__init__(
            f"{path!r} is already governed by {who}. A second writer would keep a "
            f"diverging in-memory view of the same envelope. Use one governor "
            f"process, give each worker its own database and delegated sub-budget, "
            f"or open with read_only=True for audit access."
        )


class ReadOnlyLedgerError(StorageError):
    """Raised when a write is attempted against a read-only governor.

    Read-only mode exists so an operator can inspect or verify a ledger that
    another process is actively governing. Every mutating path is refused up
    front, rather than surfacing as a backend error from somewhere deep in a
    transaction.

    :param operation: The write that was attempted.
    """

    def __init__(self, operation: str) -> None:
        self.operation = operation
        super().__init__(f"cannot {operation}: this governor was opened read-only for audit access")


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


# --------------------------------------------------------------------------
# Receipt errors — the evidence does not verify
# --------------------------------------------------------------------------


class ReceiptError(AgentGovError):
    """Base class for errors about receipts, their logs and their witnesses.

    A receipt, a proof or a cosignature arriving at a verifier is untrusted
    input. Each subclass names the part of the evidence that failed, which
    is also what ``agentgov verify-receipt`` reports as its exit code.
    """


class MalformedReceiptError(ReceiptError):
    """The input is not a well-formed ARC1 document.

    Raised for anything that cannot be decoded into the schema: invalid JSON,
    a duplicate object key, a float, a missing or unknown field, a value of
    the wrong type or format, or fields that contradict each other.
    """


class ReceiptSignatureError(ReceiptError):
    """A signature does not verify under the key the verifier was given."""


class WitnessError(ReceiptError):
    """A checkpoint is not witnessed, or a witness refused to cosign it.

    A witness refuses a checkpoint that rolls the log back, forks it (a
    second root at a size it already cosigned), or does not extend what it
    saw before. Each is evidence that the log operator rewrote history.
    """


class RowDisclosureError(ReceiptError):
    """A disclosed row does not verify against the receipt's row commitment."""


class ReceiptLogError(ReceiptError):
    """A receipt log cannot be opened, resumed or appended to."""


class SignerUnavailableError(ReceiptError):
    """A signing algorithm needs an optional dependency that is not installed.

    Ed25519 signing uses the ``cryptography`` package: install it with
    ``pip install 'agentgov[sign]'``. Verification never needs it.
    """
