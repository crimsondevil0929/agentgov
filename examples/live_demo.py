#!/usr/bin/env python3
"""The three-minute live demo: govern an agent, stop a runaway, prove the books.

Runs the first two acts of the demo and leaves behind the artifacts the last
two inspect from a real terminal:

    demo/governor.db              the hash-chained ledger
    demo/tokens.jsonl             the metering journal
    demo/provider_invoice.json    a mock provider invoice, with one leaked call

Then::

    agentgov inspect   demo/governor.db
    agentgov reconcile demo/governor.db demo/provider_invoice.json \\
                       --journal demo/tokens.jsonl

Every number this prints is measured at runtime, not hardcoded — including the
breaker's inline latency, which is timed live on the machine running the demo.

The model is :class:`~agentgov.dummy.DummyLLM`, a deterministic offline stub:
the demo spends no money and needs no network or API key, and the run is
reproducible on any machine. Swapping in a real client is a one-line change,
and the governor cannot tell the difference; that is what the adapter layer is for.

Usage::

    uv run python examples/live_demo.py
    uv run python examples/live_demo.py --out demo --no-color
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import statistics
import sys
import time
from datetime import timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.adapters.langchain import GovernedChatModel
from agentgov.cognitive import CognitiveBreaker, CognitivePolicy, canonical_arguments
from agentgov.core import EntryType
from agentgov.dummy import DummyLLM
from agentgov.exceptions import AgentThrashingError, CircuitOpenError
from agentgov.reconciliation import MeteringJournal, metered_records

ENVELOPE = money("5.00")
RESEARCH_BUDGET = money("1.00")

# An agent that cannot find what it is looking for and keeps re-asking with
# cosmetic edits. Every string differs, so nothing an exact-match cache or a
# deduplicating rate limiter would ever catch.
THRASHING_PROMPTS = [
    "find the Q3 revenue report for the northwest region",
    "find the Q3 revenue reports for the northwest region",
    "find the Q3 revenue report for the northwest regions",
    "find the Q3 revenue report for the northwest region now",
    "find the Q3 revenue report for the north west region",
]

PRODUCTIVE_PROMPTS = [
    "summarise the consolidated Q3 revenue figures",
    "compare gross margin against the Q2 guidance we published",
    "draft the three risks worth flagging to the board",
]


class _Style:
    """ANSI styling, switched off when stdout is not a terminal."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)


# --------------------------------------------------------------------------
# A stand-in for a LangChain chat model
# --------------------------------------------------------------------------


class HumanMessage:
    """The LangChain message shape, so the adapter is exercised for real."""

    def __init__(self, content: str) -> None:
        self.content = content


class AIMessage:
    def __init__(self, content: str, usage: dict[str, int]) -> None:
        self.content = content
        self.usage_metadata = usage


class DemoChatModel:
    """A LangChain-shaped chat model backed by the deterministic stub.

    Reports usage exactly where a real ``ChatAnthropic`` does, so the adapter
    reads it through the same code path it would in production.
    """

    def __init__(self, model: str = "claude-opus-5") -> None:
        self.model = model
        self._llm = DummyLLM(model, output_tokens=380)
        self.calls = 0

    def invoke(self, messages: list[Any], **_: object) -> AIMessage:
        self.calls += 1
        prompt = " ".join(getattr(m, "content", str(m)) for m in messages)
        response = self._llm.complete(prompt)
        return AIMessage(
            response.text,
            {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
        )


# --------------------------------------------------------------------------
# Acts
# --------------------------------------------------------------------------


def act_one(style: _Style, gov: BudgetManager, journal: MeteringJournal) -> GovernedChatModel:
    """Wrap an existing agent in two lines, and do real work under budget."""
    print(style.bold("\n[1/4]  Two lines to govern an existing LangChain agent"))
    print(
        style.dim(
            "       gov.delegate('orchestrator', 'researcher', money('1.00'))\n"
            "       model = GovernedChatModel(model, gov, 'researcher', journal=journal)"
        )
    )

    gov.delegate("orchestrator", "researcher", RESEARCH_BUDGET)
    model = GovernedChatModel(DemoChatModel(), gov, "researcher", journal=journal)

    print()
    for prompt in PRODUCTIVE_PROMPTS:
        before = gov.available("researcher")
        model.invoke([HumanMessage(prompt)])
        spent = before - gov.available("researcher")
        print(f"       {style.green('OK')}  {prompt[:52]:<54} {style.cyan(f'${spent}')}")

    used = RESEARCH_BUDGET - gov.available("researcher")
    print(
        f"\n       3 calls, {style.cyan(f'${used}')} of a ${RESEARCH_BUDGET} sub-budget. "
        f"The call sites did not change."
    )
    return model


def act_two(style: _Style, gov: BudgetManager, journal: MeteringJournal) -> dict[str, Any]:
    """Turn the same agent adversarial and let the cognitive breaker stop it."""
    print(style.bold("\n[2/4]  An adversarial runaway loop, stopped for a fraction of a cent"))

    breaker = CognitiveBreaker(observer=None, manager=gov, policy=CognitivePolicy())
    gov.delegate("orchestrator", "runaway", RESEARCH_BUDGET)
    # A cheap retrieval sub-agent, as a real fan-out would use — which is what
    # makes the halt land in fractions of a cent rather than fractions of a
    # dollar. The breaker does not care either way; the invoice does.
    model = GovernedChatModel(
        DemoChatModel("claude-haiku-4-5"), gov, "runaway", journal=journal, cognitive=breaker
    )

    executed = 0
    halt: AgentThrashingError | None = None
    for prompt in THRASHING_PROMPTS * 60:
        try:
            model.invoke([HumanMessage(prompt)])
        except AgentThrashingError as error:
            halt = error
            break
        executed += 1
        print(f"       {style.dim('..')}  {prompt[:52]:<54} {style.dim('executed')}")

    assert halt is not None, "the breaker failed to trip"
    burned = RESEARCH_BUDGET - gov.available("runaway")

    print(f"\n       {style.red('HALTED')} after {executed} calls")
    print(f"       detector   {halt.detector} ({halt.tier}), confidence {halt.confidence:.2f}")
    print(f"       reason     {halt.reason}")
    print(f"       burned     {style.cyan(f'${burned}')} of a ${RESEARCH_BUDGET} sub-budget")

    # Measure the inline cost live rather than quoting a number from a README.
    samples = _measure_inline_latency()
    print(
        f"       overhead   {style.cyan(f'{samples[0]:.0f}us')} mean, "
        f"{samples[1]:.0f}us p99 per call, measured just now on this machine"
    )

    # And prove the halt latches: retrying does not wear it down.
    retries = 0
    for _ in range(500):
        try:
            model.invoke([HumanMessage("a completely different question")])
        except (AgentThrashingError, CircuitOpenError):
            retries += 1
    after = RESEARCH_BUDGET - gov.available("runaway")
    print(
        f"       {retries} further attempts refused; spend unchanged at "
        f"{style.cyan(f'${after}')} — the breaker latches"
    )
    return {"executed": executed, "burned": burned, "halt": halt}


def _measure_inline_latency() -> tuple[float, float]:
    """Time the deterministic detectors on this machine, in microseconds."""
    never_trips = CognitivePolicy(
        max_identical_repeats=10**9, max_similar_streak=10**9, min_cycle_repeats=10**9
    )
    breaker = CognitiveBreaker(observer=None, policy=never_trips)
    payload = "x" * 4000
    timings: list[float] = []
    for index in range(2000):
        arguments = canonical_arguments((f"{payload}{index}",))
        started = time.perf_counter_ns()
        breaker.observe("bench", "tool", arguments)
        timings.append((time.perf_counter_ns() - started) / 1000)
    timings.sort()
    return statistics.mean(timings), timings[int(len(timings) * 0.99)]


def write_invoice(
    style: _Style, gov: BudgetManager, journal: MeteringJournal, destination: Path
) -> Decimal:
    """Build a mock provider invoice: every real call, plus one leaked key."""
    records = metered_records(gov, journal)
    rows = []
    for record in records:
        rows.append(
            {
                "id": str(record.transaction_id),
                # A realistic sub-second gap between the call and the billed line.
                "timestamp": (record.timestamp + timedelta(seconds=1.4)).isoformat(),
                "model": record.model or "claude-opus-5",
                "input_tokens": record.input_tokens,
                "output_tokens": record.output_tokens,
                "cost": str(record.settled_cost),
            }
        )

    phantom_cost = money("2.47")
    rows.append(
        {
            "id": "req_LEAKED_KEY_7f3a",
            "timestamp": (records[-1].timestamp + timedelta(seconds=3)).isoformat(),
            "model": "claude-opus-5",
            "input_tokens": 410_000,
            "output_tokens": 22_000,
            "cost": str(phantom_cost),
        }
    )
    destination.write_text(json.dumps({"data": rows}, indent=2))
    print(
        f"\n       wrote {len(rows)} invoice lines "
        f"({len(records)} governed + {style.red('1 from a leaked key')})"
    )
    return phantom_cost


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AgentGov three-minute live demo.")
    parser.add_argument("--out", default="demo", help="artifact directory (default: demo)")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI styling")
    args = parser.parse_args(argv)

    style = _Style(enabled=not args.no_color and sys.stdout.isatty())
    # The governor is chatty by design; the demo does the narrating.
    for name in ("agentgov.audit", "agentgov.cognitive", "agentgov.interceptor"):
        logging.getLogger(name).setLevel(logging.CRITICAL + 1)

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    ledger = out / "governor.db"

    print(style.bold("\n" + "=" * 74))
    print(style.bold("  AgentGov — runtime spend governor and denial-of-wallet breaker"))
    print(style.dim("  Simulated model calls; no network, no API key, no real spend."))
    print(style.bold("=" * 74))

    journal = MeteringJournal()
    # Velocity detection off: this demo is showcasing the *semantic* breaker,
    # and a machine-speed loop would otherwise trip the rate detector first.
    gov = BudgetManager.open_sqlite(str(ledger), policy=GovernancePolicy(max_calls_per_window=0))
    try:
        gov.open_root("orchestrator", ENVELOPE)
        act_one(style, gov, journal)
        result = act_two(style, gov, journal)

        print(style.bold("\n[3/4]  Prove the ledger — run this in your terminal"))
        print(style.cyan(f"       agentgov inspect {ledger}"))

        print(style.bold("\n[4/4]  Prove there was no unmetered spend"))
        phantom = write_invoice(style, gov, journal, out / "provider_invoice.json")
        journal.save(out / "tokens.jsonl")
        print(
            style.cyan(
                f"       agentgov reconcile {ledger} {out}/provider_invoice.json "
                f"--journal {out}/tokens.jsonl"
            )
        )

        settled = sum(
            (e.amount for e in gov.audit_trail() if e.entry_type is EntryType.SPEND), Decimal(0)
        )
        gov.verify_integrity()
        print(style.bold("\n" + "-" * 74))
        burned = result["burned"]
        share = burned / ENVELOPE * 100
        print(
            f"  Runaway stopped after {result['executed']} calls for "
            f"{style.cyan(f'${burned}')} "
            f"{style.dim(f'({share:.2f}% of the ${ENVELOPE} envelope)')}"
        )
        print(f"  Total settled spend       {style.cyan(f'${settled}')}")
        print(f"  Ledger integrity          {style.green('PASS')} (SHA-256 chain re-derived)")
        print(f"  Planted unmetered spend   {style.red(f'${phantom}')} — step 4 will find it")
        print(style.bold("-" * 74 + "\n"))
    finally:
        gov.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
