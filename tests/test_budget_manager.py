"""Tests for the hierarchical budget DAG and the circuit breaker."""

from __future__ import annotations

from decimal import Decimal

import pytest

from agentgov.core import BudgetManager, EntryType, GovernancePolicy, money
from agentgov.exceptions import (
    BudgetExceededError,
    CircuitOpenError,
    DenialOfWalletError,
    DenialOfWalletException,
    DoubleSpendError,
    DuplicateScopeError,
    RunawayLoopDetectedError,
    SubBudgetAllocationError,
    UnknownScopeError,
)

ZERO = Decimal("0")


@pytest.fixture
def gov() -> BudgetManager:
    manager = BudgetManager()
    manager.open_root("root", money("1.00"))
    return manager


# -- topology --------------------------------------------------------------


def test_root_is_funded_with_its_envelope(gov: BudgetManager) -> None:
    assert gov.available("root") == money("1.00")
    assert gov.node("root").depth == 0
    assert gov.node("root").parent_id is None
    gov.verify_integrity()


def test_delegation_moves_money_from_parent_to_child(gov: BudgetManager) -> None:
    child = gov.delegate("root", "researcher", money("0.25"))

    assert child.depth == 1
    assert child.parent_id == "root"
    assert gov.available("root") == money("0.75")
    assert gov.available("researcher") == money("0.25")
    assert gov.subtree_available("root") == money("1.00")
    gov.verify_integrity()


def test_delegation_is_recursive(gov: BudgetManager) -> None:
    gov.delegate("root", "lead", money("0.50"))
    gov.delegate("lead", "worker", money("0.20"))
    gov.delegate("worker", "tool", money("0.05"))

    assert gov.node("tool").depth == 3
    assert gov.ancestry("tool") == ("tool", "worker", "lead", "root")
    assert [n.scope_id for n in gov.descendants("root")] == ["lead", "worker", "tool"]
    assert gov.subtree_available("root") == money("1.00")
    gov.verify_integrity()


def test_a_child_cannot_be_granted_more_than_its_parent_holds(
    gov: BudgetManager,
) -> None:
    gov.delegate("root", "lead", money("0.10"))

    with pytest.raises(SubBudgetAllocationError) as excinfo:
        gov.delegate("lead", "worker", money("0.50"))

    assert excinfo.value.available == money("0.10")
    assert gov.available("lead") == money("0.10")
    gov.verify_integrity()


def test_delegation_depth_is_bounded() -> None:
    gov = BudgetManager(policy=GovernancePolicy(max_depth=2))
    gov.open_root("root", money("1.00"))
    gov.delegate("root", "a", money("0.50"))
    gov.delegate("a", "b", money("0.25"))

    with pytest.raises(SubBudgetAllocationError, match="exceeds max_depth"):
        gov.delegate("b", "c", money("0.10"))


def test_scope_ids_are_permanent(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    with pytest.raises(DuplicateScopeError):
        gov.delegate("root", "worker", money("0.10"))
    with pytest.raises(DuplicateScopeError):
        gov.open_root("root", money("1.00"))


def test_unknown_scopes_are_rejected(gov: BudgetManager) -> None:
    with pytest.raises(UnknownScopeError):
        gov.available("ghost")
    with pytest.raises(UnknownScopeError):
        gov.authorize("ghost", money("0.01"))


def test_release_returns_unused_budget_to_the_parent(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.40"))
    gov.spend("worker", money("0.10"))

    returned = gov.release("worker")

    assert returned == money("0.30")
    assert gov.available("worker") == ZERO
    assert gov.available("root") == money("0.90")
    gov.verify_integrity()


def test_a_root_has_no_parent_to_release_to(gov: BudgetManager) -> None:
    with pytest.raises(ValueError, match="no parent"):
        gov.release("root")


def test_only_roots_can_be_topped_up(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    gov.fund("root", money("0.50"))
    assert gov.available("root") == money("1.40")

    with pytest.raises(ValueError, match="not a root"):
        gov.fund("worker", money("0.10"))


# -- spending --------------------------------------------------------------


def test_spend_decrements_exactly(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    entry = gov.spend("worker", money("0.00004500"), memo="claude call")

    assert entry.entry_type is EntryType.SPEND
    assert entry.amount == money("0.00004500")
    assert gov.available("worker") == money("0.09995500")
    gov.verify_integrity()


def test_authorization_encumbers_funds_until_settled(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))

    auth = gov.authorize("worker", money("0.05"))
    assert gov.available("worker") == money("0.05"), "hold must be visible immediately"

    gov.capture(auth, money("0.01"))
    assert gov.available("worker") == money("0.09"), "unused hold returns"
    gov.verify_integrity()


def test_void_returns_the_whole_hold(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    auth = gov.authorize("worker", money("0.05"))
    gov.void(auth)

    assert gov.available("worker") == money("0.10")
    gov.verify_integrity()


def test_an_authorization_settles_only_once(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    auth = gov.authorize("worker", money("0.05"))
    gov.capture(auth, money("0.01"))

    with pytest.raises(DoubleSpendError):
        gov.capture(auth, money("0.01"))
    with pytest.raises(DoubleSpendError):
        gov.void(auth)

    assert gov.available("worker") == money("0.09")
    gov.verify_integrity()


def test_capture_at_zero_cost_releases_the_hold(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    auth = gov.authorize("worker", money("0.05"))
    entry = gov.capture(auth, money("0"))

    assert entry.entry_type is EntryType.HOLD_VOID
    assert gov.available("worker") == money("0.10")
    gov.verify_integrity()


def test_cost_rounds_up_so_sub_quantum_calls_are_never_free(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    gov.spend("worker", Decimal("0.000000001"))
    assert gov.available("worker") == money("0.09999999")


def test_refund_credits_without_rewriting_history(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    gov.spend("worker", money("0.05"))
    gov.refund("worker", money("0.02"), memo="vendor credit")

    assert gov.available("worker") == money("0.07")
    types = [e.entry_type for e in gov.audit_trail("worker")]
    assert EntryType.SPEND in types and EntryType.REVERSAL in types
    gov.verify_integrity()


# -- the denial-of-wallet backstop ----------------------------------------


def test_hitting_the_exact_limit_trips_the_breaker_and_halts(
    gov: BudgetManager,
) -> None:
    """The headline behaviour: spend to exactly zero, and execution halts."""
    gov.delegate("root", "worker", money("0.10"))
    gov.spend("worker", money("0.10"))

    assert gov.available("worker") == ZERO
    assert gov.is_halted("worker")
    assert gov.halted_by("worker") == "worker"

    with pytest.raises(CircuitOpenError, match="exhausted"):
        gov.authorize("worker", money("0.00000001"))

    gov.verify_integrity()


def test_overdrawing_raises_denial_of_wallet_and_writes_nothing(
    gov: BudgetManager,
) -> None:
    gov.delegate("root", "worker", money("0.10"))
    entries_before = len(gov.audit_trail())

    with pytest.raises(DenialOfWalletError) as excinfo:
        gov.authorize("worker", money("0.50"))

    assert excinfo.value.requested == money("0.50")
    assert excinfo.value.available == money("0.10")
    assert excinfo.value.overspent is False
    assert len(gov.audit_trail()) == entries_before, "refusal must not touch the ledger"
    assert gov.is_halted("worker")
    gov.verify_integrity()


def test_denial_of_wallet_exception_alias_is_the_same_class() -> None:
    assert DenialOfWalletException is DenialOfWalletError
    assert issubclass(DenialOfWalletError, BudgetExceededError)


def test_a_trip_halts_the_whole_subtree(gov: BudgetManager) -> None:
    gov.delegate("root", "lead", money("0.50"))
    gov.delegate("lead", "worker", money("0.20"))

    gov.trip("lead", "manual halt")

    assert gov.is_halted("worker")
    assert gov.halted_by("worker") == "lead"
    assert not gov.is_halted("root")

    with pytest.raises(CircuitOpenError) as excinfo:
        gov.authorize("worker", money("0.01"))
    assert excinfo.value.tripped_scope_id == "lead"

    # A halted parent may not spawn new sub-agents either.
    with pytest.raises(CircuitOpenError):
        gov.delegate("lead", "another", money("0.01"))


def test_reset_re_arms_a_halted_scope(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    gov.trip("worker", "test halt")
    assert gov.is_halted("worker")

    gov.reset("worker")

    assert not gov.is_halted("worker")
    gov.authorize("worker", money("0.01"))
    assert [e.event_type for e in gov.control_events] == [
        "circuit_tripped",
        "circuit_reset",
    ]


def test_a_realized_overdraft_is_recorded_and_halts(gov: BudgetManager) -> None:
    """Money that was really spent must be booked, even past the limit."""
    gov.delegate("root", "worker", money("0.10"))
    auth = gov.authorize("worker", money("0.10"))

    with pytest.raises(DenialOfWalletError) as excinfo:
        gov.capture(auth, money("0.15"))

    assert excinfo.value.overspent is True
    assert gov.available("worker") == money("-0.05"), "the overdraft is visible"
    assert gov.is_halted("worker")
    gov.verify_integrity()  # conservation still holds across an overdraft


def test_advisory_mode_refuses_without_halting_siblings() -> None:
    gov = BudgetManager(policy=GovernancePolicy(trip_on_overdraft=False))
    gov.open_root("root", money("1.00"))
    gov.delegate("root", "worker", money("0.10"))

    with pytest.raises(BudgetExceededError) as excinfo:
        gov.authorize("worker", money("0.50"))

    assert not isinstance(excinfo.value, DenialOfWalletError)
    assert not gov.is_halted("worker")
    gov.authorize("worker", money("0.01"))


def test_runaway_loop_trips_before_the_budget_is_spent() -> None:
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=5, window_seconds=60.0))
    gov.open_root("root", money("100.00"))
    gov.delegate("root", "looper", money("50.00"))

    for _ in range(5):
        gov.void(gov.authorize("looper", money("0.01")))

    with pytest.raises(RunawayLoopDetectedError) as excinfo:
        gov.authorize("looper", money("0.01"))

    assert excinfo.value.call_count == 6
    assert gov.is_halted("looper")
    assert gov.available("looper") == money("50.00"), "no money was spent"
    gov.verify_integrity()


# -- audit trail -----------------------------------------------------------


def test_the_audit_trail_records_every_micro_transaction(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    auth = gov.authorize("worker", money("0.05"))
    gov.capture(auth, money("0.00001234"))

    trail = gov.audit_trail("worker")
    assert [e.entry_type for e in trail] == [
        EntryType.ALLOCATION,
        EntryType.HOLD,
        EntryType.HOLD_VOID,
        EntryType.SPEND,
    ]
    # Capture is one atomic transaction, so the void and the spend share an id.
    assert trail[2].transaction_id == trail[3].transaction_id
    assert trail[1].transaction_id != trail[2].transaction_id
    # Every entry is chained and every balance is attested.
    assert trail[-1].balance_after == gov.available("worker")
    gov.verify_integrity()


def test_control_events_are_anchored_to_the_ledger(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("0.10"))
    gov.spend("worker", money("0.03"))
    head = gov.ledger.head_hash

    gov.trip("worker", "manual halt")

    (event,) = gov.control_events
    assert event.event_type == "circuit_tripped"
    assert event.scope_id == "worker"
    assert event.ledger_head_hash == head


def test_audit_logging_emits_one_record_per_entry(
    gov: BudgetManager, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("INFO", logger="agentgov.audit"):
        gov.delegate("root", "worker", money("0.10"))
        gov.spend("worker", money("0.01"))

    records = [r for r in caplog.records if r.name == "agentgov.audit"]
    # allocation (2 legs) + hold + hold_void + spend
    assert len(records) == 5
    assert all(r.message.startswith("AGOV1|") for r in records)
    assert all(hasattr(r, "agentgov_entry") for r in records)
