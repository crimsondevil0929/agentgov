"""AgentGov: a runtime spend-governance kernel for AI agents.

Provides hierarchical, capability-scoped spend budgets over an immutable,
hash-chained ledger, with a latching kernel-level circuit breaker — so a
runaway agent (or a tree of sub-agents spawning sub-agents) cannot exceed
its delegated envelope. A denial-of-wallet backstop for agentic systems.

Quick start::

    from agentgov import BudgetManager, Interceptor, money

    gov = BudgetManager()
    gov.open_root("orchestrator", money("1.00"))
    gov.delegate("orchestrator", "researcher", money("0.25"))

    metered = Interceptor(gov, "researcher", model="claude-opus-5")
    result = metered.invoke(client.messages.create, model=..., messages=[...])

    print(result.cost, gov.available("researcher"))

For a governor whose ledger and topology survive a process restart, open a
SQLite-backed one instead::

    with BudgetManager.open_sqlite("governor.db") as gov:
        ...  # same API; state above is durable across restarts

Or name any ledger by URL: ``agentgov.open("postgresql://...")``,
``agentgov.open("sqlite:///governor.db")``, ``agentgov.open("memory:")``.

See :mod:`agentgov.core` for the ledger and budget DAG,
:mod:`agentgov.exceptions` for the error hierarchy,
:mod:`agentgov.interceptor` for the call-site enforcement wrappers,
:mod:`agentgov.spi` for what a store implementer needs,
:mod:`agentgov.adapters` for the LangChain and CrewAI drop-ins, and
:mod:`agentgov.reconciliation` for matching a provider invoice against the
ledger.
"""

from __future__ import annotations

from agentgov._aio import AsyncBudgetManager
from agentgov.cognitive import (
    CallCycleDetector,
    CognitiveBreaker,
    CognitivePolicy,
    ExactRepeatDetector,
    LoopDetector,
    NearDuplicateDetector,
    Redactor,
    SemanticObserver,
    ToolCall,
    TrajectoryEntropyObserver,
    Verdict,
    canonical_arguments,
    extract_result_text,
)
from agentgov.core import (
    Authorization,
    BudgetManager,
    BudgetNode,
    CheckpointSigning,
    ControlEvent,
    Direction,
    EntryType,
    GovernancePolicy,
    JoinedTransaction,
    Ledger,
    LedgerEntry,
    SettlementClaim,
    Transaction,
    format_audit_line,
    money,
)
from agentgov.exceptions import (
    AgentGovError,
    AgentThrashingError,
    BudgetError,
    BudgetExceededError,
    CircuitBreakerError,
    CircuitOpenError,
    ConcurrentGovernorError,
    DenialOfWalletError,
    DoubleSpendError,
    DuplicateScopeError,
    IdempotencyConflictError,
    LedgerConflictError,
    LedgerError,
    LedgerIntegrityError,
    LedgerRollbackError,
    ReadOnlyLedgerError,
    RunawayLoopDetectedError,
    ScopeError,
    StorageError,
    SubBudgetAllocationError,
    UnknownScopeError,
)
from agentgov.interceptor import (
    CHARS_PER_TOKEN,
    PRICING,
    Interceptor,
    MeteredCall,
    ModelPricing,
    SpendGuard,
    TokenUsage,
    default_usage_extractor,
    estimate_tokens,
    extract_prompt_text,
    normalize_model_id,
    pricing_for,
)
from agentgov.opening import open_url as open  # agentgov.open(url), as gzip.open
from agentgov.proxy import GovernedClient, GovernorHandle, govern
from agentgov.reconciliation import (
    MeteringJournal,
    ProviderUsageRecord,
    ReconciliationPolicy,
    ReconciliationReport,
    load_provider_export,
    reconcile,
)
from agentgov.storage import SqliteStore
from agentgov.streaming import AsyncMeteredStream, MeteredStream

__all__ = [
    "CHARS_PER_TOKEN",
    "PRICING",
    "AgentGovError",
    "AgentThrashingError",
    "AsyncBudgetManager",
    "AsyncMeteredStream",
    "Authorization",
    "BudgetError",
    "BudgetExceededError",
    "BudgetManager",
    "BudgetNode",
    "CallCycleDetector",
    "CheckpointSigning",
    "CircuitBreakerError",
    "CircuitOpenError",
    "CognitiveBreaker",
    "CognitivePolicy",
    "ConcurrentGovernorError",
    "ControlEvent",
    "DenialOfWalletError",
    "Direction",
    "DoubleSpendError",
    "DuplicateScopeError",
    "EntryType",
    "ExactRepeatDetector",
    "GovernancePolicy",
    "GovernedClient",
    "GovernorHandle",
    "IdempotencyConflictError",
    "Interceptor",
    "JoinedTransaction",
    "Ledger",
    "LedgerConflictError",
    "LedgerEntry",
    "LedgerError",
    "LedgerIntegrityError",
    "LedgerRollbackError",
    "LoopDetector",
    "MeteredCall",
    "MeteredStream",
    "MeteringJournal",
    "ModelPricing",
    "NearDuplicateDetector",
    "ProviderUsageRecord",
    "ReadOnlyLedgerError",
    "ReconciliationPolicy",
    "ReconciliationReport",
    "Redactor",
    "RunawayLoopDetectedError",
    "ScopeError",
    "SemanticObserver",
    "SettlementClaim",
    "SpendGuard",
    "SqliteStore",
    "StorageError",
    "SubBudgetAllocationError",
    "TokenUsage",
    "ToolCall",
    "TrajectoryEntropyObserver",
    "Transaction",
    "UnknownScopeError",
    "Verdict",
    "canonical_arguments",
    "default_usage_extractor",
    "estimate_tokens",
    "extract_prompt_text",
    "extract_result_text",
    "format_audit_line",
    "govern",
    "load_provider_export",
    "money",
    "normalize_model_id",
    "open",
    "pricing_for",
    "reconcile",
]

__version__ = "0.4.0"


# Names this package served before 1.0 that now live elsewhere: still served,
# with a DeprecationWarning, until 2.0 removes them.
_MOVED: dict[str, tuple[str, str, str]] = {
    **{
        name: ("agentgov.spi", name, f"from agentgov.spi import {name}")
        for name in (
            "JoinableStore",
            "PersistedAuthorization",
            "PersistedNode",
            "PersistenceStore",
            "SharedStore",
            "StoreDelta",
            "StoreImage",
            "WriteBatch",
            "WriterSession",
        )
    },
    "AgentThrashingException": (
        "agentgov.exceptions",
        "AgentThrashingError",
        "catch AgentThrashingError, which it has always been",
    ),
    "DenialOfWalletException": (
        "agentgov.exceptions",
        "DenialOfWalletError",
        "catch DenialOfWalletError, which it has always been",
    ),
    "LedgerLine": (
        "agentgov.core",
        "LedgerLine",
        "it described a line for Ledger.post(), which 1.0 removed; write through BudgetManager",
    ),
}


def __getattr__(name: str) -> object:
    moved = _MOVED.get(name)
    if moved is None:
        raise AttributeError(f"module 'agentgov' has no attribute {name!r}")
    import importlib
    import warnings

    module, attribute, advice = moved
    warnings.warn(
        f"agentgov.{name} is deprecated and is removed in 2.0: {advice}",
        DeprecationWarning,
        stacklevel=2,
    )
    return getattr(importlib.import_module(module), attribute)
