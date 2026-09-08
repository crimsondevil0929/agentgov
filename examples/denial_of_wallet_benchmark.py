#!/usr/bin/env python3
"""Denial-of-wallet benchmark: the same runaway agent, with and without a backstop.

This is the validation step from CONCEPT.md, made reproducible. It runs one
agent workload twice:

  Scenario A - Ungoverned.  A runaway orchestrator spawns sub-agents and calls
    a model in an unbounded loop. Nothing can stop it. We record what it would
    have cost.

  Scenario B - AgentGov protected.  Byte-for-byte the same agent logic, but
    issued a strict spend envelope that it sub-delegates to its workers. Every
    call is authorized against the ledger before it is made.

Both scenarios run the *identical* workload function; only the harness behind
``attempt()`` and ``spawn()`` differs, so the comparison is apples-to-apples.

Scenario B deliberately keeps hammering after it is refused, modelling an
agent that ignores the error entirely. That is the adversarial case a backstop
has to survive: no matter how many times it retries, it cannot spend another
cent.

Costs are computed from the published per-token rates in ``agentgov.interceptor``
against a deterministic offline model stub, so the run is reproducible and
spends no real money. The ungoverned figure is therefore a *theoretical*
cost - what this call volume would have been billed at list price.

Usage::

    uv run python examples/denial_of_wallet_benchmark.py
    uv run python examples/denial_of_wallet_benchmark.py --seconds 5 --budget 10.00
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Protocol

from agentgov import BudgetManager, Interceptor, money
from agentgov.core import EntryType, GovernancePolicy, format_audit_line
from agentgov.dummy import DummyLLM
from agentgov.exceptions import (
    AgentGovError,
    CircuitOpenError,
    DenialOfWalletException,
    SubBudgetAllocationError,
)
from agentgov.interceptor import ModelPricing, TokenUsage, pricing_for

ROOT = "orchestrator"
SPAWN_EVERY = 10_000
"""Calls a worker makes before the orchestrator rotates it out anyway.

Set high on purpose: in the governed run, worker rotation should be driven by
the backstop refusing a call, not by this counter, so what the table reports
is the governor working rather than a scheduling artefact. In the ungoverned
run nothing ever refuses, so this is the only thing that rotates workers.
"""

WORKER_SLICE = Decimal("0.10")
"""Fraction of the root envelope handed to each newly spawned worker."""


# --------------------------------------------------------------------------
# Result record
# --------------------------------------------------------------------------


@dataclass
class Outcome:
    """What one scenario did."""

    label: str
    governed: bool
    budget: Decimal
    elapsed: float = 0.0
    attempted: int = 0
    executed: int = 0
    refused: int = 0
    spawned: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost: Decimal = Decimal("0")
    breached_after: float | None = None
    breaker: str = "n/a - no backstop exists"
    integrity: str = "n/a - no ledger exists"
    conservation: str = "n/a - no ledger exists"
    notes: list[str] = field(default_factory=list)

    @property
    def tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def overshoot(self) -> Decimal:
        """Cost as a percentage of the budget that was supposed to bound it."""
        if self.budget <= 0:
            return Decimal("0")
        return (self.cost / self.budget) * 100


# --------------------------------------------------------------------------
# Harnesses - the only thing that differs between the two scenarios
# --------------------------------------------------------------------------


class Harness(Protocol):
    """The capability surface the runaway workload is written against."""

    def attempt(self, scope: str, prompt: str) -> bool:
        """Try to make one model call. Returns whether it actually executed."""

    def spawn(self, index: int, retiring: str | None) -> str | None:
        """Retire ``retiring`` and spawn its replacement.

        Returns the new worker's scope id, or ``None`` when no further worker
        can be funded.
        """


class UngovernedHarness:
    """No budget, no ledger, no backstop. What today's tooling gives you."""

    def __init__(self, llm: DummyLLM, pricing: ModelPricing, outcome: Outcome) -> None:
        self._llm = llm
        self._pricing = pricing
        self._outcome = outcome
        self._started = time.perf_counter()

    def attempt(self, scope: str, prompt: str) -> bool:
        response = self._llm.complete(prompt)
        usage: TokenUsage = response.usage
        cost = self._pricing.cost_of(usage)

        out = self._outcome
        out.executed += 1
        out.input_tokens += usage.input_tokens
        out.output_tokens += usage.output_tokens
        out.cost += cost
        if out.breached_after is None and out.cost > out.budget:
            out.breached_after = time.perf_counter() - self._started
        return True

    def spawn(self, index: int, retiring: str | None) -> str | None:
        # Spawning is free and unbounded: nothing tracks the tree, and a
        # retiring worker's "budget" is a fiction with nothing to return.
        self._outcome.spawned += 1
        return f"worker.{index}"


class GovernedHarness:
    """The same agent, behind AgentGov."""

    def __init__(
        self,
        gov: BudgetManager,
        llm: DummyLLM,
        interceptor: Interceptor,
        outcome: Outcome,
    ) -> None:
        self._gov = gov
        self._llm = llm
        self._interceptor = interceptor
        self._outcome = outcome
        # A worker that cannot cover a single worst-case call is not worth
        # spawning; without this floor the orchestrator thrashes, minting
        # thousands of stillborn sub-agents that are refused on their first
        # call and immediately retired.
        self._min_viable = interceptor.hold_amount

    def attempt(self, scope: str, prompt: str) -> bool:
        out = self._outcome
        try:
            result = self._interceptor.for_scope(scope).invoke(self._llm.complete, prompt)
        except AgentGovError:
            # The agent ignores the refusal and will try again. It cannot win.
            out.refused += 1
            return False
        out.executed += 1
        out.input_tokens += result.usage.input_tokens
        out.output_tokens += result.usage.output_tokens
        out.cost += result.cost
        return True

    def spawn(self, index: int, retiring: str | None) -> str | None:
        # Reclaim whatever the outgoing worker never spent, so an abandoned
        # sub-agent cannot strand budget its siblings could have used.
        if retiring is not None and retiring != ROOT:
            self._gov.release(retiring, memo="worker retired")

        remaining = self._gov.available(ROOT)
        amount = min(self._outcome.budget * WORKER_SLICE, remaining)
        if amount < self._min_viable:
            return None  # the envelope is spent; no viable worker can be funded

        scope = f"worker.{index}"
        try:
            self._gov.delegate(ROOT, scope, amount)
        except (SubBudgetAllocationError, CircuitOpenError):
            return None
        self._outcome.spawned += 1
        return scope


# --------------------------------------------------------------------------
# The workload - identical for both scenarios
# --------------------------------------------------------------------------


def run_runaway(harness: Harness, outcome: Outcome, deadline: float) -> None:
    """An orchestrator that spawns workers and calls a model, without bound.

    This function has no idea whether it is governed. That is the point.
    """
    scope = harness.spawn(0, None) or ROOT
    since_spawn = 0
    index = 1

    while time.perf_counter() < deadline:
        outcome.attempted += 1
        executed = harness.attempt(scope, f"process record {outcome.attempted}")
        since_spawn += 1

        # Rotate workers when the current one stops making progress, or simply
        # because enough work has passed through it. Ungoverned runs only ever
        # hit the second condition; governed runs are driven by the first.
        if not executed or since_spawn >= SPAWN_EVERY:
            since_spawn = 0
            replacement = harness.spawn(index, scope)
            index += 1
            if replacement is not None:
                scope = replacement
            # If no replacement could be funded, keep hammering the old scope.


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------


def scenario_ungoverned(seconds: float, budget: Decimal, model: str, latency: float) -> Outcome:
    """Scenario A: a runaway agent with zero backstop."""
    outcome = Outcome(label="Scenario A - Ungoverned", governed=False, budget=budget)
    llm = DummyLLM(model, latency_seconds=latency)
    harness = UngovernedHarness(llm, pricing_for(model), outcome)

    started = time.perf_counter()
    run_runaway(harness, outcome, started + seconds)
    outcome.elapsed = time.perf_counter() - started

    outcome.notes.append(
        f"Nothing stopped it. It intended to spend ${budget}; it spent ${outcome.cost}."
    )
    return outcome


def scenario_governed(
    seconds: float, budget: Decimal, model: str, latency: float
) -> tuple[Outcome, BudgetManager]:
    """Scenario B: the same runaway agent under a strict spend envelope."""
    outcome = Outcome(label="Scenario B - AgentGov", governed=True, budget=budget)

    # Velocity detection is disabled so the benchmark measures the *budget*
    # backstop in isolation; otherwise the loop trips on call rate in
    # milliseconds and never reaches the spend limit at all.
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0, max_depth=8))
    gov.open_root(ROOT, budget)

    llm = DummyLLM(model, latency_seconds=latency)
    interceptor = Interceptor(
        gov,
        ROOT,
        model=model,
        estimated_input_tokens=64,
        max_output_tokens=576,
    )
    harness = GovernedHarness(gov, llm, interceptor, outcome)

    started = time.perf_counter()
    run_runaway(harness, outcome, started + seconds)
    outcome.elapsed = time.perf_counter() - started

    halted = [s for s in gov.scopes() if gov.is_halted(s)]
    outcome.breaker = (
        f"LATCHED OPEN - {len(halted)}/{len(gov.scopes())} scopes halted"
        if halted
        else "closed (never tripped)"
    )

    try:
        gov.verify_integrity()
        outcome.integrity = f"PASS - {len(gov.audit_trail())} entries chained"
    except AgentGovError as exc:  # pragma: no cover - would be a real defect
        outcome.integrity = f"FAIL - {exc}"
    try:
        gov.ledger.verify_conservation()
        outcome.conservation = "PASS - no money created or destroyed"
    except AgentGovError as exc:  # pragma: no cover - would be a real defect
        outcome.conservation = f"FAIL - {exc}"

    # Reconcile our own tally against the ledger; they must agree exactly.
    settled = sum(
        (e.amount for e in gov.audit_trail() if e.entry_type is EntryType.SPEND),
        Decimal("0"),
    )
    assert settled == outcome.cost, f"tally {outcome.cost} != ledger {settled}"
    assert settled <= budget, f"envelope breached: {settled} > {budget}"

    outcome.notes.append(f"Refused {outcome.refused:,} attempts after the envelope was spent.")
    outcome.notes.append(
        f"Ledger and caller tally agree exactly: ${settled} settled, "
        f"${gov.subtree_available(ROOT)} unspent."
    )
    return outcome, gov


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def usd(amount: Decimal) -> str:
    """Render an amount as dollars, keeping sub-cent precision visible."""
    quantized = amount.quantize(Decimal("0.000001"))
    return f"${quantized:,.6f}"


def render_table(a: Outcome, b: Outcome) -> str:
    """Build the side-by-side comparison table."""
    rows: list[tuple[str, str, str]] = [
        ("Wall clock", f"{a.elapsed:.2f}s", f"{b.elapsed:.2f}s"),
        ("Sub-agents spawned", f"{a.spawned:,}", f"{b.spawned:,}"),
        ("Calls attempted", f"{a.attempted:,}", f"{b.attempted:,}"),
        ("Calls executed", f"{a.executed:,}", f"{b.executed:,}"),
        ("Calls refused", f"{a.refused:,}", f"{b.refused:,}"),
        ("Tokens consumed", f"{a.tokens:,}", f"{b.tokens:,}"),
        ("", "", ""),
        ("Intended budget", usd(a.budget), usd(b.budget)),
        ("Actual cost realized", usd(a.cost), usd(b.cost)),
        ("Cost vs budget", f"{a.overshoot:,.1f}%", f"{b.overshoot:,.1f}%"),
        (
            "Budget breached after",
            f"{a.breached_after:.3f}s" if a.breached_after else "never",
            f"{b.breached_after:.3f}s" if b.breached_after else "never",
        ),
        ("", "", ""),
        ("Circuit breaker", a.breaker, b.breaker),
        ("verify_integrity()", a.integrity, b.integrity),
        ("verify_conservation()", a.conservation, b.conservation),
    ]

    label_w = max(len(r[0]) for r in rows)
    col_a = max([len(r[1]) for r in rows] + [len(a.label)])
    col_b = max([len(r[2]) for r in rows] + [len(b.label)])

    def line(char: str = "-") -> str:
        return f"+-{char * label_w}-+-{char * col_a}-+-{char * col_b}-+".replace(
            "-", char if char != "-" else "-"
        )

    def row(label: str, left: str, right: str) -> str:
        if not label and not left and not right:
            return line()
        return f"| {label:<{label_w}} | {left:>{col_a}} | {right:>{col_b}} |"

    out = [
        line("="),
        row("METRIC", a.label.center(col_a), b.label.center(col_b)),
        line("="),
    ]
    out.extend(row(*r) for r in rows)
    out.append(line("="))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark a runaway agent with and without a spend governor.",
    )
    parser.add_argument(
        "--seconds", type=float, default=3.0, help="runaway duration (default: 3.0)"
    )
    parser.add_argument("--budget", type=str, default="5.00", help="spend envelope (default: 5.00)")
    parser.add_argument("--model", type=str, default="claude-opus-5", help="model to price against")
    parser.add_argument(
        "--latency",
        type=float,
        default=0.0,
        help="simulated per-call latency in seconds (default: 0.0, machine speed)",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="stream every audit log line live instead of showing a tail sample",
    )
    args = parser.parse_args(argv)
    budget = money(args.budget)

    # The audit logger writes a line per ledger entry. Streaming a million of
    # them would bury the comparison, so it is quiet unless asked for.
    logging.getLogger("agentgov.audit").setLevel(
        logging.INFO if args.audit else logging.CRITICAL + 1
    )
    if args.audit:
        logging.basicConfig(level=logging.INFO, format="%(message)s", stream=sys.stdout)

    print("\nDENIAL-OF-WALLET BENCHMARK")
    print(
        f"  model={args.model}  envelope={usd(budget)}  "
        f"runaway={args.seconds}s  latency={args.latency}s"
    )
    print("  Simulated model calls (agentgov.dummy); no real spend, no network.\n")

    print(f"  running Scenario A (ungoverned) for {args.seconds}s ...", flush=True)
    ungoverned = scenario_ungoverned(args.seconds, budget, args.model, args.latency)

    print(f"  running Scenario B (AgentGov) for {args.seconds}s ...\n", flush=True)
    governed, gov = scenario_governed(args.seconds, budget, args.model, args.latency)

    print(render_table(ungoverned, governed))

    if not args.audit:
        print(
            "\nAUDIT TRAIL (last 5 of "
            f"{len(gov.audit_trail()):,} hash-chained entries; --audit for all)"
        )
        for entry in gov.audit_trail()[-5:]:
            print(f"  {format_audit_line(entry)}")
        for event in gov.control_events[-1:]:
            print(
                f"  CIRCUIT  {event.event_type} scope={event.scope_id} "
                f"anchored_at={event.ledger_head_hash[:16]} reason={event.reason}"
            )

    overspend = ungoverned.cost - budget
    print("\nVERDICT")
    if ungoverned.breached_after is not None:
        print(
            f"  Ungoverned blew through its {usd(budget)} budget after "
            f"{ungoverned.breached_after:.3f}s and kept going to "
            f"{usd(ungoverned.cost)} - {usd(overspend)} of unbudgeted spend, "
            f"{ungoverned.overshoot:,.0f}% of the intended cap."
        )
    else:
        print(
            f"  Ungoverned did not reach the budget in {args.seconds}s "
            f"(try --seconds or a pricier --model)."
        )
    print(
        f"  AgentGov settled {usd(governed.cost)} of a {usd(budget)} envelope "
        f"and refused {governed.refused:,} further attempts."
    )
    for note in governed.notes:
        print(f"  {note}")

    # A demonstrable backstop, or the benchmark has failed to demonstrate it.
    assert governed.cost <= budget
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DenialOfWalletException as exc:  # pragma: no cover - safety net
        print(f"\nunexpected escape: {exc}", file=sys.stderr)
        sys.exit(1)
