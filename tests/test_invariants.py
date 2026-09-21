"""Tests for the invariant checks themselves.

An integrity check that is never exercised is not a control. These tests
corrupt the governor's internal state deliberately and assert that
:meth:`BudgetManager.verify_integrity` catches it, plus the argument
validation that keeps malformed money out of the ledger in the first place.
"""

from __future__ import annotations

import dataclasses
import time
from decimal import Decimal

import pytest

from agentgov.core import (
    BudgetManager,
    Direction,
    EntryType,
    GovernancePolicy,
    LedgerLine,
    _Totals,
    money,
)
from agentgov.exceptions import LedgerIntegrityError

ZERO = Decimal("0")


@pytest.fixture
def gov() -> BudgetManager:
    manager = BudgetManager()
    manager.open_root("root", money("1.00"))
    manager.delegate("root", "child", money("0.50"))
    return manager


# -- amount validation -----------------------------------------------------


@pytest.mark.parametrize("amount", ["0", "-0.01"])
def test_non_positive_amounts_are_refused_everywhere(gov: BudgetManager, amount: str) -> None:
    with pytest.raises(ValueError, match="must be positive"):
        gov.open_root("other", Decimal(amount))
    with pytest.raises(ValueError, match="must be positive"):
        gov.fund("root", Decimal(amount))
    with pytest.raises(ValueError, match="must be positive"):
        gov.delegate("root", "fresh", Decimal(amount))
    with pytest.raises(ValueError, match="must be positive"):
        gov.authorize("child", Decimal(amount))
    with pytest.raises(ValueError, match="must be positive"):
        gov.refund("child", Decimal(amount))


def test_capture_refuses_a_negative_cost(gov: BudgetManager) -> None:
    auth = gov.authorize("child", money("0.01"))
    with pytest.raises(ValueError, match="must not be negative"):
        gov.capture(auth, Decimal("-0.01"))


def test_release_beyond_the_balance_is_refused(gov: BudgetManager) -> None:
    with pytest.raises(ValueError, match=r"only 0\.50000000 available"):
        gov.release("child", money("0.90"))


def test_releasing_an_empty_scope_is_a_no_op(gov: BudgetManager) -> None:
    gov.spend("child", money("0.50"))
    assert gov.release("child") == ZERO
    assert gov.available("root") == money("0.50")
    gov.verify_integrity()


def test_resetting_a_healthy_scope_is_a_no_op(gov: BudgetManager) -> None:
    gov.reset("child")
    assert gov.control_events == ()
    assert not gov.is_halted("child")


# -- ledger corruption -----------------------------------------------------


def test_a_renumbered_entry_is_caught(gov: BudgetManager) -> None:
    ledger = gov.ledger
    ledger._entries[1] = dataclasses.replace(ledger._entries[1], sequence=99)
    with pytest.raises(LedgerIntegrityError, match="sequence gap"):
        gov.verify_integrity()


def test_a_forged_head_hash_is_caught(gov: BudgetManager) -> None:
    gov.ledger._head_hash = "f" * 64
    with pytest.raises(LedgerIntegrityError, match="head hash does not match"):
        gov.verify_integrity()


def test_forged_boundary_totals_are_caught(gov: BudgetManager) -> None:
    gov.ledger._totals = dataclasses.replace(gov.ledger._totals, funded=money("99.00"))
    with pytest.raises(LedgerIntegrityError, match="boundary totals disagree"):
        gov.verify_integrity()


def test_replay_reconstructs_state_from_the_chain_alone(gov: BudgetManager) -> None:
    gov.spend("child", money("0.10"))
    balances, totals = gov.ledger.replay()

    assert balances["root"] == money("0.50")
    assert balances["child"] == money("0.40")
    assert totals == _Totals(
        funded=money("1.00"), spent=money("0.10"), reversed_=ZERO, holds_open=ZERO
    )


def test_an_outstanding_hold_still_conserves(gov: BudgetManager) -> None:
    gov.authorize("child", money("0.20"))
    assert gov.available("child") == money("0.30")
    gov.verify_integrity()  # Σ balances + holds == funded


# -- topology corruption ---------------------------------------------------


def test_an_orphaned_parent_reference_is_caught(gov: BudgetManager) -> None:
    gov.node("child").parent_id = "vanished"
    with pytest.raises(LedgerIntegrityError, match="is not registered"):
        gov.verify_integrity()


def test_a_parentless_non_root_is_caught(gov: BudgetManager) -> None:
    gov._roots.clear()
    with pytest.raises(LedgerIntegrityError, match="parentless scope is not a root"):
        gov.verify_integrity()


def test_a_severed_child_link_is_caught(gov: BudgetManager) -> None:
    gov.node("root").child_ids.clear()
    with pytest.raises(LedgerIntegrityError, match="not listed as a child"):
        gov.verify_integrity()


def test_an_inconsistent_depth_is_caught(gov: BudgetManager) -> None:
    gov.node("child").depth = 7
    with pytest.raises(LedgerIntegrityError, match="depth 7 is inconsistent"):
        gov.verify_integrity()


def test_a_delegation_cycle_is_caught(gov: BudgetManager) -> None:
    root, child = gov.node("root"), gov.node("child")
    root.parent_id = "child"
    root.depth = child.depth + 1
    child.child_ids.append("root")

    with pytest.raises(LedgerIntegrityError, match="delegation cycle detected"):
        gov.verify_integrity()


# -- velocity window -------------------------------------------------------


def test_the_velocity_window_slides(gov: BudgetManager) -> None:
    """Calls spread across windows must not accumulate into a false trip."""
    fast = BudgetManager(policy=GovernancePolicy(max_calls_per_window=3, window_seconds=0.05))
    fast.open_root("root", money("10.00"))

    for _ in range(2):
        for _ in range(3):
            fast.void(fast.authorize("root", money("0.01")))
        time.sleep(0.06)

    assert not fast.is_halted("root")
    fast.verify_integrity()


def test_velocity_checking_can_be_disabled() -> None:
    off = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    off.open_root("root", money("10.00"))
    for _ in range(50):
        off.void(off.authorize("root", money("0.01")))
    assert not off.is_halted("root")


# -- ledger reuse ----------------------------------------------------------


def test_two_managers_sharing_a_ledger_share_one_mutex() -> None:
    """Sharing a ledger must share its lock, or the guarantee is void."""
    first = BudgetManager()
    second = BudgetManager(ledger=first.ledger)
    assert second.ledger is first.ledger
    assert second._lock is first._lock


def test_raw_ledger_lines_still_validate(gov: BudgetManager) -> None:
    with pytest.raises(ValueError, match="may not be a"):
        gov.ledger.post([LedgerLine(EntryType.HOLD, Direction.CREDIT, "child", money("0.01"))])
    gov.verify_integrity()


# -- verification is reachable from the manager -----------------------------


def test_manager_exposes_chain_and_conservation_checks(gov: BudgetManager) -> None:
    """The README names all three beside each other, so all three live here.

    ``verify_chain`` and ``verify_conservation`` were previously reachable only
    as ``manager.ledger.*``, which no reader of the README had reason to guess.
    """
    gov.open_root("orchestrator", money("5.00"))
    gov.delegate("orchestrator", "researcher", money("1.00"))
    gov.capture(gov.authorize("researcher", money("0.10")), money("0.04"))

    gov.verify_chain()
    gov.verify_conservation()
    gov.verify_integrity()


def test_manager_conservation_check_catches_a_tampered_ledger(gov: BudgetManager) -> None:
    """A pass-through that never fails is not a check."""
    gov.open_root("orchestrator", money("5.00"))
    # Conservation reads the balance cache, not the entry list: it is the check
    # that catches a balance which no longer follows from the funding.
    gov.ledger._balances["orchestrator"] = money("9999.00")

    with pytest.raises(LedgerIntegrityError, match="conservation violated"):
        gov.verify_conservation()


def test_manager_chain_check_catches_a_tampered_ledger(gov: BudgetManager) -> None:
    import dataclasses

    gov.open_root("orchestrator", money("5.00"))
    gov.delegate("orchestrator", "researcher", money("1.00"))
    ledger = gov.ledger
    ledger._entries[1] = dataclasses.replace(ledger._entries[1], memo="edited")

    with pytest.raises(LedgerIntegrityError):
        gov.verify_chain()
