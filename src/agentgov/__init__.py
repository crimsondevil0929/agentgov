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

See :mod:`agentgov.core` for the ledger and budget DAG,
:mod:`agentgov.exceptions` for the error hierarchy,
:mod:`agentgov.interceptor` for the call-site enforcement wrappers,
:mod:`agentgov.storage` for the durable-store interface,
:mod:`agentgov.adapters` for the LangChain and CrewAI drop-ins, and
:mod:`agentgov.reconciliation` for matching a provider invoice against the
ledger.
"""

from __future__ import annotations

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
)
from agentgov.core import (
    Authorization,
    BudgetManager,
    BudgetNode,
    ControlEvent,
    Direction,
    EntryType,
    GovernancePolicy,
    Ledger,
    LedgerEntry,
    LedgerLine,
    format_audit_line,
    money,
)
from agentgov.exceptions import (
    AgentGovError,
    AgentThrashingError,
    AgentThrashingException,
    BudgetError,
    BudgetExceededError,
    CircuitBreakerError,
    CircuitOpenError,
    ConcurrentGovernorError,
    DenialOfWalletError,
    DenialOfWalletException,
    DoubleSpendError,
    DuplicateScopeError,
    LedgerError,
    LedgerIntegrityError,
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
    pricing_for,
)
from agentgov.proxy import GovernedClient, GovernorHandle, govern
from agentgov.reconciliation import (
    MeteringJournal,
    ProviderUsageRecord,
    ReconciliationPolicy,
    ReconciliationReport,
    load_provider_export,
    reconcile,
)
from agentgov.storage import PersistedAuthorization, PersistedNode, PersistenceStore, SqliteStore
from agentgov.streaming import AsyncMeteredStream, MeteredStream

__all__ = [
    "CHARS_PER_TOKEN",
    "PRICING",
    "AgentGovError",
    "AgentThrashingError",
    "AgentThrashingException",
    "AsyncMeteredStream",
    "Authorization",
    "BudgetError",
    "BudgetExceededError",
    "BudgetManager",
    "BudgetNode",
    "CallCycleDetector",
    "CircuitBreakerError",
    "CircuitOpenError",
    "CognitiveBreaker",
    "CognitivePolicy",
    "ConcurrentGovernorError",
    "ControlEvent",
    "DenialOfWalletError",
    "DenialOfWalletException",
    "Direction",
    "DoubleSpendError",
    "DuplicateScopeError",
    "EntryType",
    "ExactRepeatDetector",
    "GovernancePolicy",
    "GovernedClient",
    "GovernorHandle",
    "Interceptor",
    "Ledger",
    "LedgerEntry",
    "LedgerError",
    "LedgerIntegrityError",
    "LedgerLine",
    "LoopDetector",
    "MeteredCall",
    "MeteredStream",
    "MeteringJournal",
    "ModelPricing",
    "NearDuplicateDetector",
    "PersistedAuthorization",
    "PersistedNode",
    "PersistenceStore",
    "ProviderUsageRecord",
    "ReadOnlyLedgerError",
    "ReconciliationPolicy",
    "ReconciliationReport",
    "Redactor",
    "RunawayLoopDetectedError",
    "ScopeError",
    "SemanticObserver",
    "SpendGuard",
    "SqliteStore",
    "StorageError",
    "SubBudgetAllocationError",
    "TokenUsage",
    "ToolCall",
    "TrajectoryEntropyObserver",
    "UnknownScopeError",
    "Verdict",
    "canonical_arguments",
    "default_usage_extractor",
    "estimate_tokens",
    "extract_prompt_text",
    "format_audit_line",
    "govern",
    "load_provider_export",
    "money",
    "pricing_for",
    "reconcile",
]

__version__ = "0.1.0"
