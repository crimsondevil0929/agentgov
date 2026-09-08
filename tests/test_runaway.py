"""Runaway recursive-agent scenarios: the denial-of-wallet failure mode itself.

An agent that spawns sub-agents that spawn sub-agents is the shape OWASP ASI
calls "Denial of Wallet", and the shape today's rate limiters cannot see: no
single scope looks abusive, but the tree drains the envelope. These tests
drive that exact topology and assert the governor latches closed.
"""

from __future__ import annotations

import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from agentgov.core import BudgetManager, EntryType, GovernancePolicy, money
from agentgov.dummy import DummyLLM
from agentgov.exceptions import (
    CircuitOpenError,
    DenialOfWalletException,
    DuplicateScopeError,
    RunawayLoopDetectedError,
    SubBudgetAllocationError,
)
from agentgov.interceptor import Interceptor

ZERO = Decimal("0")
ENVELOPE = money("1.00")


def total_spent(gov: BudgetManager) -> Decimal:
    """Every dollar that actually left the system, read back from the chain."""
    return sum(
        (e.amount for e in gov.audit_trail() if e.entry_type is EntryType.SPEND),
        ZERO,
    )


def test_unbounded_recursive_spawning_is_latched_closed_by_denial_of_wallet() -> None:
    """A sub-agent tree recursing forever is stopped, and stays stopped.

    Each level makes a billable call, then hands 80% of what it has left to a
    fresh child and recurses. Nothing bounds the recursion but the money.
    """
    gov = BudgetManager(policy=GovernancePolicy(max_depth=64))
    gov.open_root("agent.0", ENVELOPE)
    llm = DummyLLM("claude-opus-5", output_tokens=200)
    base = Interceptor(
        gov,
        "agent.0",
        model="claude-opus-5",
        estimated_input_tokens=100,
        max_output_tokens=200,
    )

    spawned = ["agent.0"]
    calls = 0

    def run(scope: str, depth: int) -> None:
        nonlocal calls
        base.for_scope(scope).invoke(llm.complete, f"work at depth {depth}")
        calls += 1
        child = f"agent.{depth + 1}"
        gov.delegate(scope, child, gov.available(scope) * Decimal("0.8"))
        spawned.append(child)
        run(child, depth + 1)  # unbounded: only the budget can stop this

    with pytest.raises(DenialOfWalletException) as excinfo:
        run("agent.0", 0)

    failed_at = spawned[-1]
    assert excinfo.value.scope_id == failed_at
    assert excinfo.value.overspent is False, "refused pre-flight; no money moved"
    assert calls > 5, "the tree really did recurse before being stopped"
    assert llm.call_count == calls, "the model was never called after the refusal"

    # The breaker latched: the next attempt fails on the *breaker*, not on the
    # balance. That distinction is the whole point of a latching backstop.
    assert gov.is_halted(failed_at)
    with pytest.raises(CircuitOpenError):
        gov.authorize(failed_at, money("0.00000001"))
    # ...and the halted subtree cannot grow its way out by spawning more.
    with pytest.raises(CircuitOpenError):
        gov.delegate(failed_at, "agent.escape", money("0.00000001"))

    # Containment: the halt is scoped to the offending branch, not the world.
    assert not gov.is_halted("agent.0")

    # The envelope was never breached, and every dollar is accounted for.
    spent = total_spent(gov)
    assert spent < ENVELOPE
    assert gov.subtree_available("agent.0") + spent == ENVELOPE
    gov.verify_integrity()


def test_recursive_spawning_also_hits_the_structural_depth_bound() -> None:
    """Money is not the only backstop: depth bounds recursion independently.

    With a large envelope the budget would never stop the recursion, so the
    depth bound has to.
    """
    gov = BudgetManager(policy=GovernancePolicy(max_depth=6))
    gov.open_root("agent.0", money("1000.00"))

    def run(scope: str, depth: int) -> None:
        child = f"agent.{depth + 1}"
        gov.delegate(scope, child, gov.available(scope) / 2)
        run(child, depth + 1)

    with pytest.raises(SubBudgetAllocationError, match="exceeds max_depth"):
        run("agent.0", 0)

    assert gov.node("agent.6").depth == 6
    assert "agent.7" not in gov.scopes()
    gov.verify_integrity()


def test_a_delegation_cycle_cannot_be_created() -> None:
    """Re-entering a scope id would splice a cycle into the tree. Refused."""
    gov = BudgetManager()
    gov.open_root("a", ENVELOPE)
    gov.delegate("a", "b", money("0.50"))
    gov.delegate("b", "c", money("0.25"))

    with pytest.raises(DuplicateScopeError):
        gov.delegate("c", "a", money("0.10"))
    with pytest.raises(DuplicateScopeError):
        gov.delegate("c", "b", money("0.10"))

    gov.verify_integrity()


def test_a_wide_fanout_cannot_outspend_the_parent() -> None:
    """Breadth is bounded by the same envelope as depth.

    Sixty siblings each try to claim a tenth of a budget that only covers ten.
    """
    gov = BudgetManager()
    gov.open_root("root", money("1.00"))
    gov.delegate("root", "fanout", money("0.10"))

    granted = 0
    for index in range(60):
        try:
            gov.delegate("fanout", f"worker.{index}", money("0.01"))
        except SubBudgetAllocationError:
            break
        granted += 1

    assert granted == 10
    assert gov.available("fanout") == ZERO
    assert gov.subtree_available("fanout") == money("0.10")
    gov.verify_integrity()


def test_a_runaway_loop_trips_before_it_can_spend(caplog: pytest.LogCaptureFixture) -> None:
    """Velocity detection catches a tight loop even on a huge envelope."""
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=25, window_seconds=60.0))
    gov.open_root("root", money("10000.00"))
    llm = DummyLLM("claude-haiku-4-5", output_tokens=10)
    metered = Interceptor(
        gov,
        "root",
        model="claude-haiku-4-5",
        estimated_input_tokens=10,
        max_output_tokens=10,
    )

    with (
        caplog.at_level("WARNING", logger="agentgov.audit"),
        pytest.raises(RunawayLoopDetectedError) as excinfo,
    ):
        for index in range(1000):
            metered.invoke(llm.complete, f"tight loop {index}")

    assert excinfo.value.call_count == 26
    assert gov.is_halted("root")
    assert llm.call_count <= 26, "the loop was stopped in its first window"
    assert gov.available("root") > money("9999.00"), "almost nothing was spent"
    assert "circuit_tripped" in caplog.text
    gov.verify_integrity()


def test_the_benchmark_script_runs_and_proves_its_own_claim() -> None:
    """Smoke-test examples/denial_of_wallet_benchmark.py so it cannot rot.

    Run briefly: the script asserts internally that the governed scenario
    never breached its envelope and that its tally matches the ledger, so a
    clean exit is a real check, not just "it didn't crash".
    """
    script = Path(__file__).resolve().parent.parent / "examples" / "denial_of_wallet_benchmark.py"
    assert script.is_file(), f"benchmark not found at {script}"

    result = subprocess.run(  # noqa: S603
        [sys.executable, str(script), "--seconds", "0.25", "--budget", "0.50"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )

    assert result.returncode == 0, f"benchmark failed:\n{result.stdout}\n{result.stderr}"
    assert "verify_integrity()" in result.stdout
    assert "PASS - no money created or destroyed" in result.stdout
    assert "LATCHED OPEN" in result.stdout
