"""Package-surface tests: the public API is importable and coherent."""

from __future__ import annotations

import agentgov
from agentgov import exceptions


def test_package_version_is_set() -> None:
    assert agentgov.__version__


def test_every_exported_name_resolves() -> None:
    missing = [name for name in agentgov.__all__ if not hasattr(agentgov, name)]
    assert missing == []


def test_exception_hierarchy_separates_refusal_halt_and_corruption() -> None:
    # A refusal is catchable control flow.
    assert issubclass(exceptions.BudgetExceededError, exceptions.BudgetError)
    assert issubclass(exceptions.DenialOfWalletError, exceptions.BudgetExceededError)
    # A halt is a safety-control event.
    assert issubclass(exceptions.CircuitOpenError, exceptions.CircuitBreakerError)
    assert issubclass(exceptions.RunawayLoopDetectedError, exceptions.CircuitBreakerError)
    # Corruption is never expected.
    assert issubclass(exceptions.LedgerIntegrityError, exceptions.LedgerError)
    assert issubclass(exceptions.DoubleSpendError, exceptions.LedgerError)
    # Everything is catchable at the root.
    for cls in (exceptions.BudgetError, exceptions.CircuitBreakerError, exceptions.LedgerError):
        assert issubclass(cls, exceptions.AgentGovError)
