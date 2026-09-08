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

See :mod:`agentgov.core` for the ledger and budget DAG,
:mod:`agentgov.exceptions` for the error hierarchy, and
:mod:`agentgov.interceptor` for the call-site enforcement wrappers.
"""

from __future__ import annotations

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
    BudgetError,
    BudgetExceededError,
    CircuitBreakerError,
    CircuitOpenError,
    DenialOfWalletError,
    DenialOfWalletException,
    DoubleSpendError,
    DuplicateScopeError,
    LedgerError,
    LedgerIntegrityError,
    RunawayLoopDetectedError,
    ScopeError,
    SubBudgetAllocationError,
    UnknownScopeError,
)
from agentgov.interceptor import (
    PRICING,
    Interceptor,
    MeteredCall,
    ModelPricing,
    SpendGuard,
    TokenUsage,
    default_usage_extractor,
    pricing_for,
)

__all__ = [
    "PRICING",
    "AgentGovError",
    "Authorization",
    "BudgetError",
    "BudgetExceededError",
    "BudgetManager",
    "BudgetNode",
    "CircuitBreakerError",
    "CircuitOpenError",
    "ControlEvent",
    "DenialOfWalletError",
    "DenialOfWalletException",
    "Direction",
    "DoubleSpendError",
    "DuplicateScopeError",
    "EntryType",
    "GovernancePolicy",
    "Interceptor",
    "Ledger",
    "LedgerEntry",
    "LedgerError",
    "LedgerIntegrityError",
    "LedgerLine",
    "MeteredCall",
    "ModelPricing",
    "RunawayLoopDetectedError",
    "ScopeError",
    "SpendGuard",
    "SubBudgetAllocationError",
    "TokenUsage",
    "UnknownScopeError",
    "default_usage_extractor",
    "format_audit_line",
    "money",
    "pricing_for",
]

__version__ = "0.1.0"
