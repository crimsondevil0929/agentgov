"""The 1.0 API, frozen (Phase 6.1).

``agentgov`` exports what a user of the governor needs; ``agentgov.spi`` what
a store implementer needs. The lists below are the 1.0 surface: a change to
either is a change to the API, made on purpose, here. Names 1.0 moved or
retired are still served, with a ``DeprecationWarning``, until 2.0.
"""

from __future__ import annotations

import asyncio
import re
import warnings
from pathlib import Path

import pytest

import agentgov
import agentgov.spi
from agentgov.core import Ledger, LedgerLine, WriteBatch

PUBLIC = [
    "AgentGovError",
    "AgentThrashingError",
    "AsyncBudgetManager",
    "AsyncMeteredStream",
    "Authorization",
    "BudgetError",
    "BudgetExceededError",
    "BudgetManager",
    "BudgetNode",
    "CHARS_PER_TOKEN",
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
    "PRICING",
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

SPI = [
    "AuditMark",
    "IdempotencyRecord",
    "JoinableStore",
    "PersistedAuthorization",
    "PersistedNode",
    "PersistenceStore",
    "SharedStore",
    "Snapshot",
    "StoreDelta",
    "StoreImage",
    "WriteBatch",
    "WriterSession",
]


def test_the_public_api_is_the_frozen_list() -> None:
    assert sorted(agentgov.__all__) == PUBLIC
    assert all(hasattr(agentgov, name) for name in PUBLIC)


def test_the_spi_is_the_frozen_list_and_apart_from_the_api() -> None:
    assert sorted(agentgov.spi.__all__) == SPI
    assert all(hasattr(agentgov.spi, name) for name in SPI)
    assert not set(SPI) & set(PUBLIC), "a store implementer's types are not the user's"
    assert agentgov.spi.WriteBatch is WriteBatch


@pytest.mark.parametrize(
    ("name", "advice"),
    [
        ("WriteBatch", "from agentgov.spi import WriteBatch"),
        ("PersistenceStore", "from agentgov.spi import PersistenceStore"),
        ("AgentThrashingException", "catch AgentThrashingError"),
        ("DenialOfWalletException", "catch DenialOfWalletError"),
        ("LedgerLine", "Ledger.post(), which 1.0 removed"),
    ],
)
def test_names_moved_or_retired_still_resolve_with_a_warning(name: str, advice: str) -> None:
    with pytest.warns(
        DeprecationWarning, match=rf"agentgov\.{name} is deprecated.*{re.escape(advice)}"
    ):
        found = getattr(agentgov, name)
    assert found is not None
    if name == "WriteBatch":
        assert found is WriteBatch
    if name == "LedgerLine":
        assert found is LedgerLine


def test_an_unknown_name_is_an_attribute_error() -> None:
    with pytest.raises(AttributeError, match="no attribute 'Nonexistent'"):
        _ = agentgov.Nonexistent


def test_ledger_post_is_gone_and_ledger_lock_warns() -> None:
    """D6: Ledger.post() could commit what a later open refused; 1.0 removes
    it. Ledger.lock is atomic in one process only: it warns, through 1.x."""
    assert not hasattr(Ledger, "post")
    gov = agentgov.BudgetManager()
    with pytest.warns(DeprecationWarning, match="transaction"):
        lock = gov.ledger.lock
    with lock:
        gov.open_root("root", agentgov.money("1"))


def test_a_refund_naming_no_spend_is_deprecated_at_the_callers_line(tmp_path: Path) -> None:
    """A DeprecationWarning shows only where the caller's code made it, so
    the warning names the caller's line, whichever way the call comes."""
    with agentgov.BudgetManager.open_sqlite(str(tmp_path / "g.db")) as gov:
        gov.open_root("root", agentgov.money("1"))
        spend = gov.spend("root", agentgov.money("0.5"))
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            gov.refund("root", agentgov.money("0.1"), reverses=spend)  # names its spend
        with pytest.warns(DeprecationWarning, match="names no spend") as direct:
            gov.refund("root", agentgov.money("0.1"))
        with gov.transaction() as txn:
            with pytest.warns(DeprecationWarning, match="names no spend") as inside:
                txn.refund("root", agentgov.money("0.1"))

        async def refund_off_the_loop() -> list[warnings.WarningMessage]:
            manager = agentgov.AsyncBudgetManager(gov)
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                named = await manager.refund("root", agentgov.money("0.1"), reverses=spend)
            assert named.entry_type is agentgov.EntryType.REVERSAL and named.ref == spend.entry_id
            with pytest.warns(DeprecationWarning, match="names no spend") as caught:
                await manager.refund("root", agentgov.money("0.1"))
            return list(caught)

        off_loop = asyncio.run(refund_off_the_loop())
    assert [w.filename for w in (*direct, *inside, *off_loop)] == [__file__] * 3


def test_open_names_any_ledger_by_url(tmp_path: object) -> None:
    with agentgov.open("memory:") as gov:
        gov.open_root("root", agentgov.money("1"))
        assert gov.available("root") == agentgov.money("1")
