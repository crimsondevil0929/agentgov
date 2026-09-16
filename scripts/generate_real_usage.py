#!/usr/bin/env python3
"""Meter real Anthropic API traffic through AgentGov, and keep the receipts.

Every benchmark in this repository before this script ran against
:class:`~agentgov.dummy.DummyLLM`, a deterministic offline stub. That proves
the accounting invariants — no double-spend, conservation, an unbroken hash
chain — but it proves nothing about the *integration* surface: whether the
usage extractor reads a real SDK response, whether the published rates in
:data:`~agentgov.interceptor.PRICING` match what Anthropic actually bills, and
whether the cognitive breaker halts a loop that is burning real tokens.

This script closes that gap. It drives four governed workflows across four
model tiers against the live API, writes every raw response payload to disk as
evidence, and prints a cost summary reconciled against AgentGov's ledger.

    Tier 1  The Runaway       claude-haiku-4-5   a Jaccard thrashing loop that
                              the cognitive breaker must halt mid-flight
    Tier 2  The Workhorse     claude-sonnet-5    a genuinely progressing
                              multi-step agent workflow (the control: it must
                              *not* trip the breaker)
    Tier 3  The Analyst       claude-opus-5      one complex reasoning call
    Tier 4  The Heavy Lifter  claude-fable-5-1   one long-horizon call on the
                              most expensive tier, to prove metric extraction
                              holds where a mistake costs the most

Authentication is deliberately explicit: the client is constructed with
``api_key=os.environ["BENCHMARK_API_KEY"]`` so this never silently picks up an
ambient ``ANTHROPIC_API_KEY`` or a logged-in CLI profile and bills the wrong
account.

Budget safety (this spends real money):

* Every call carries a small, explicit ``max_tokens``.
* The runaway loop is bounded by a hardcoded ``while`` counter that breaks at
  :data:`MAX_RUNAWAY_ITERATIONS`, so if the cognitive breaker ever regressed
  the loop still cannot run away.
* The whole run executes inside an AgentGov envelope of
  :data:`ENVELOPE`; a bug that tried to overspend it would raise
  ``DenialOfWalletError`` rather than drain the account.
* ``--dry-run`` exercises every code path against a local stub and spends
  nothing. Debug there first.

Usage::

    export BENCHMARK_API_KEY=sk-ant-...
    uv run python scripts/generate_real_usage.py --dry-run   # free rehearsal
    uv run python scripts/generate_real_usage.py             # ~$0.11 of real spend
    uv run python scripts/generate_real_usage.py --tiers analyst

Receipts land in ``benchmarks/live_data/`` as timestamped JSON and are
gitignored — they are evidence for the maintainer, not repository content.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, Final

import anthropic

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.cognitive import CognitiveBreaker, CognitivePolicy
from agentgov.core import QUANTUM
from agentgov.exceptions import AgentGovError, AgentThrashingError, CircuitOpenError
from agentgov.interceptor import Interceptor, MeteredCall, TokenUsage, pricing_for
from agentgov.reconciliation import MeteringJournal

# --------------------------------------------------------------------------
# Phase 3 — hard budget guardrails
# --------------------------------------------------------------------------

MAX_RUNAWAY_ITERATIONS: Final = 4
"""Fail-safe bound on Tier 1, independent of AgentGov.

The cognitive breaker is the thing under test, and a thing under test is a
thing that might be broken. This counter is the seatbelt: even with the
breaker disabled entirely, Tier 1 cannot issue a fifth API call.
"""

ENVELOPE: Final = money("1.50")
"""Total spend authorized for one run. Worst case is roughly $0.11."""

OUTPUT_DIR: Final = Path("benchmarks/live_data")


# --------------------------------------------------------------------------
# Tier configuration
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Tier:
    """One governed workflow against one model.

    :ivar key: Selector used by ``--tiers``.
    :ivar title: Human-readable banner.
    :ivar scope: AgentGov scope charged for this tier's calls.
    :ivar model: Model id requested.
    :ivar fallbacks: Models to try if ``model`` is unavailable on this account.
    :ivar budget: Sub-budget delegated to :attr:`scope`.
    :ivar max_tokens: Hard output ceiling sent on every call.
    :ivar est_input_tokens: Input size assumed when sizing the static hold
        floor. Keeping it near the real prompt size stops the floor from
        dominating the payload-derived estimate.
    :ivar effort: ``output_config.effort``, or ``None`` for models that reject
        it (Haiku 4.5 errors on the parameter).
    """

    key: str
    title: str
    scope: str
    model: str
    fallbacks: tuple[str, ...]
    budget: Decimal
    max_tokens: int
    est_input_tokens: int
    effort: str | None


TIERS: Final = (
    Tier(
        key="runaway",
        title="Tier 1 - The Runaway (cognitive breaker under live load)",
        scope="tier1-runaway",
        model="claude-haiku-4-5",
        fallbacks=(),
        budget=money("0.10"),
        max_tokens=128,
        est_input_tokens=200,
        effort=None,  # Haiku 4.5 rejects output_config.effort.
    ),
    Tier(
        key="workhorse",
        title="Tier 2 - The Workhorse (multi-step agent, must not false-positive)",
        scope="tier2-workhorse",
        model="claude-sonnet-5",
        fallbacks=(),
        budget=money("0.25"),
        max_tokens=600,
        est_input_tokens=600,
        effort="low",
    ),
    Tier(
        key="analyst",
        title="Tier 3 - The Analyst (complex reasoning)",
        scope="tier3-analyst",
        model="claude-opus-5",
        fallbacks=(),
        budget=money("0.30"),
        max_tokens=900,
        est_input_tokens=500,
        effort="medium",
    ),
    Tier(
        key="heavy",
        title="Tier 4 - The Heavy Lifter (most expensive tier)",
        scope="tier4-heavy",
        model="claude-fable-5-1",
        # Same tier, same published rates ($10/$50 per MTok); served as a
        # fallback if this account is not enabled for 5.1.
        fallbacks=("claude-fable-5",),
        budget=money("0.60"),
        max_tokens=1000,
        est_input_tokens=700,
        effort="low",
    ),
)


# An agent that cannot find what it is looking for and keeps re-asking with
# cosmetic edits. Every string differs, so an exact-match dedupe cache would
# forward all of them; character-trigram Jaccard sees one loop.
THRASHING_PROMPTS: Final = (
    "find the Q3 revenue report for the northwest region",
    "find the Q3 revenue reports for the northwest region",
    "find the Q3 revenue report for the northwest regions",
    "find the Q3 revenue report for the northwest region now",
)

WORKHORSE_STEPS: Final = (
    "List the three largest cost drivers in a typical SaaS gross margin. "
    "One line each, no preamble.",
    "For the first driver you named, give one concrete lever a finance team "
    "can pull this quarter. Two sentences.",
    "Now write the single sentence a CFO would put in a board deck about that "
    "lever's expected impact.",
)

ANALYST_PROMPT: Final = (
    "A fleet of autonomous agents shares one API budget. Each agent may spawn "
    "sub-agents that inherit part of its remaining budget. Two sub-agents call "
    "the model concurrently and both read the balance before either writes. "
    "Name the failure, then explain why a reserve-before-call protocol fixes "
    "it where a decrement-after-call protocol cannot. Be concise and precise."
)

HEAVY_PROMPT: Final = (
    "You are reviewing the architecture of a runtime spend governor for AI "
    "agents. It keeps a SHA-256 hash-chained, double-entry ledger in SQLite, "
    "guarded by a single re-entrant mutex, with one writer process holding an "
    "advisory file lock. Spend is authorized as a hold before each model call "
    "and captured at the true cost afterwards. Identify the single most "
    "important property this design gets right, and the single most important "
    "threat it does not address. Be specific and brief."
)


# --------------------------------------------------------------------------
# Dry-run stub
# --------------------------------------------------------------------------


class _StubUsage:
    """The four token fields AgentGov's extractor reads off a real response."""

    def __init__(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = 0
        self.cache_creation_input_tokens = 0


class _StubMessage:
    """A local stand-in shaped like ``anthropic.types.Message``.

    Exists so ``--dry-run`` can exercise the governor, the cognitive breaker,
    the journal and the receipt writer without a network call or a cent of
    spend. It is not a fake of the API — it is a fake of the *response shape*,
    which is all this script's own logic touches.
    """

    def __init__(self, model: str, prompt: str, max_tokens: int) -> None:
        self.id = f"msg_dryrun_{uuid.uuid4().hex[:16]}"
        self.model = model
        self.stop_reason = "end_turn"
        self.stop_details = None
        self.content = [{"type": "text", "text": "[dry run - no model was called]"}]
        self.usage = _StubUsage(max(len(prompt) // 4, 1), min(max_tokens, 64))
        self._request_id = f"req_dryrun_{uuid.uuid4().hex[:12]}"

    def model_dump(self, *, mode: str = "python") -> dict[str, Any]:
        """Match the Pydantic surface the receipt writer serializes."""
        del mode
        return {
            "id": self.id,
            "model": self.model,
            "stop_reason": self.stop_reason,
            "content": self.content,
            "usage": {
                "input_tokens": self.usage.input_tokens,
                "output_tokens": self.usage.output_tokens,
                "cache_read_input_tokens": self.usage.cache_read_input_tokens,
                "cache_creation_input_tokens": self.usage.cache_creation_input_tokens,
            },
            "_dry_run": True,
        }


class _StubClient:
    """Minimal ``client.messages.create`` surface for ``--dry-run``."""

    def __init__(self) -> None:
        self.messages = self

    def create(self, **kwargs: Any) -> _StubMessage:
        model = str(kwargs["model"])
        max_tokens = int(kwargs["max_tokens"])
        prompt = json.dumps(kwargs.get("messages", []))
        return _StubMessage(model, prompt, max_tokens)


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass
class TierOutcome:
    """What one tier actually did, measured rather than assumed."""

    tier: Tier
    model_served: str = ""
    calls_executed: int = 0
    calls_refused: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost: Decimal = field(default_factory=lambda: money("0"))
    holds: Decimal = field(default_factory=lambda: money("0"))
    latency_seconds: float = 0.0
    halted_by: str = ""
    halt_reason: str = ""
    note: str = ""
    error: str = ""

    def absorb(self, call: MeteredCall[Any]) -> None:
        """Fold one settled call into the tier totals."""
        self.calls_executed += 1
        self.input_tokens += call.usage.input_tokens + call.usage.cache_read_input_tokens
        self.output_tokens += call.usage.output_tokens
        self.cost += call.cost
        self.holds += call.hold
        self.latency_seconds += call.latency_seconds
        served = getattr(call.response, "model", "") or ""
        if served:
            self.model_served = str(served)

    def to_json(self) -> dict[str, Any]:
        return {
            "tier": self.tier.key,
            "title": self.tier.title,
            "scope": self.tier.scope,
            "model_requested": self.tier.model,
            "model_served": self.model_served,
            "calls_executed": self.calls_executed,
            "calls_refused": self.calls_refused,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "settled_cost_usd": str(self.cost),
            "authorized_holds_usd": str(self.holds),
            "api_latency_seconds": round(self.latency_seconds, 4),
            "halted_by": self.halted_by,
            "halt_reason": self.halt_reason,
            "note": self.note,
            "error": self.error,
        }


# --------------------------------------------------------------------------
# Call plumbing
# --------------------------------------------------------------------------


def call_kwargs(tier: Tier, prompt: str, model: str) -> dict[str, Any]:
    """Build one Messages API request for ``tier``.

    ``max_tokens`` is always present and always small — it is both the cost
    ceiling and the bound AgentGov's dynamic hold sizing reads back out of the
    payload.
    """
    kwargs: dict[str, Any] = {
        "model": model,
        "max_tokens": tier.max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if tier.effort is not None:
        kwargs["output_config"] = {"effort": tier.effort}
    return kwargs


def resolve_model(client: Any, tier: Tier, *, dry_run: bool) -> str:
    """Pick the first model in ``tier`` this account can actually serve.

    Only Tier 4 declares fallbacks: Claude Fable 5.1 requires 30-day data
    retention, so an account not enabled for it gets a hard error rather than
    a silent downgrade. The fallback is the same tier at identical published
    rates, so the cost comparison stays honest either way.
    """
    if dry_run or not tier.fallbacks:
        return tier.model
    candidates = (tier.model, *tier.fallbacks)
    for candidate in candidates[:-1]:
        try:
            client.models.retrieve(candidate)
        except anthropic.APIStatusError as exc:
            print(f"    model {candidate} unavailable ({exc.status_code}); trying next")
            continue
        return candidate
    return candidates[-1]


def receipt(tier: Tier, step: str, call: MeteredCall[Any]) -> dict[str, Any]:
    """Serialize one governed call: the raw API payload plus AgentGov's view.

    The raw payload is the evidence — a reader should be able to re-derive the
    settled cost from ``raw_response.usage`` and the published rates without
    trusting anything this script computed.
    """
    response = call.response
    dump = getattr(response, "model_dump", None)
    raw: Any = dump(mode="json") if callable(dump) else repr(response)
    return {
        "tier": tier.key,
        "step": step,
        "model_requested": tier.model,
        "model_served": getattr(response, "model", None),
        "request_id": getattr(response, "_request_id", None),
        "stop_reason": getattr(response, "stop_reason", None),
        "raw_response": raw,
        "extracted_usage": {
            "input_tokens": call.usage.input_tokens,
            "output_tokens": call.usage.output_tokens,
            "cache_read_input_tokens": call.usage.cache_read_input_tokens,
            "cache_creation_input_tokens": call.usage.cache_creation_input_tokens,
            "total_tokens": call.usage.total_tokens,
        },
        "agentgov": {
            "scope_id": call.scope_id,
            "pricing_model_id": call.model_id,
            "authorized_hold_usd": str(call.hold),
            "settled_cost_usd": str(call.cost),
            "transaction_id": str(call.transaction_id),
            "ledger_sequence": call.entry.sequence,
            "ledger_entry_hash": call.entry.entry_hash,
            "api_latency_seconds": round(call.latency_seconds, 6),
        },
    }


def independent_cost(model_id: str, usage: TokenUsage) -> Decimal:
    """Re-price a call straight from the published rates.

    A deliberate second opinion: if this ever disagrees with what the ledger
    settled, the metering path has a bug and the run should not be trusted.
    """
    return pricing_for(model_id).cost_of(usage)


# --------------------------------------------------------------------------
# Tier 1 - the runaway
# --------------------------------------------------------------------------


def run_runaway(
    client: Any,
    gov: BudgetManager,
    journal: MeteringJournal,
    tier: Tier,
    receipts: list[dict[str, Any]],
    *,
    dry_run: bool,
) -> TierOutcome:
    """Drive a thrashing loop against the live API until something stops it.

    The interesting question is not whether AgentGov *can* stop a loop — the
    offline benchmark shows that. It is whether the inline detector still
    fires when the calls are real, the latency is real, and the responses come
    back in whatever order the network delivers them.
    """
    outcome = TierOutcome(tier=tier)
    breaker = CognitiveBreaker(
        manager=gov,
        policy=CognitivePolicy(retain_arguments=False),
    )
    metered = Interceptor(
        gov,
        tier.scope,
        model=tier.model,
        max_output_tokens=tier.max_tokens,
        estimated_input_tokens=tier.est_input_tokens,
        cognitive=breaker,
        trajectory="tier1-runaway",
    )
    model = resolve_model(client, tier, dry_run=dry_run)

    try:
        iteration = 0
        # Phase 3 fail-safe. Bounded independently of the governor: if the
        # breaker under test regressed to a no-op, this is what stops the
        # loop, and it stops it after four calls costing under a cent.
        while iteration < MAX_RUNAWAY_ITERATIONS:
            prompt = THRASHING_PROMPTS[iteration % len(THRASHING_PROMPTS)]
            try:
                call = metered.invoke(client.messages.create, **call_kwargs(tier, prompt, model))
            except AgentThrashingError as exc:
                outcome.halted_by = "cognitive"
                outcome.halt_reason = str(exc)
                break
            except CircuitOpenError as exc:
                outcome.halted_by = "circuit"
                outcome.halt_reason = str(exc)
                break
            iteration += 1
            outcome.absorb(call)
            journal.record(call)
            receipts.append(receipt(tier, f"thrash-{iteration}", call))
            print(
                f"    call {iteration}: {call.usage.input_tokens} in / "
                f"{call.usage.output_tokens} out -> ${call.cost}"
            )

        # Prove the latch: a halted trajectory must refuse retries without
        # moving the balance, not merely fail the one call that tripped it.
        if outcome.halted_by:
            before = gov.available(tier.scope)
            for _ in range(5):
                try:
                    metered.invoke(
                        client.messages.create,
                        **call_kwargs(tier, THRASHING_PROMPTS[0], model),
                    )
                except (AgentThrashingError, CircuitOpenError):
                    outcome.calls_refused += 1
            if gov.available(tier.scope) != before:
                outcome.error = "balance moved while the breaker was latched"
        else:
            outcome.note = (
                f"fail-safe counter stopped the loop after {MAX_RUNAWAY_ITERATIONS} "
                f"calls; the cognitive breaker did not fire"
            )
    finally:
        breaker.close()
    return outcome


# --------------------------------------------------------------------------
# Tiers 2-4 - the productive workloads
# --------------------------------------------------------------------------


def run_sequence(
    client: Any,
    gov: BudgetManager,
    journal: MeteringJournal,
    tier: Tier,
    prompts: tuple[str, ...],
    receipts: list[dict[str, Any]],
    *,
    dry_run: bool,
) -> TierOutcome:
    """Run a genuinely progressing workflow and meter every call.

    Tiers 2-4 share this path. Tier 2 is the control for the cognitive
    breaker: a multi-step workflow whose steps differ substantively must run
    to completion without a halt, or the detector is too eager to ship.
    """
    outcome = TierOutcome(tier=tier)
    breaker = CognitiveBreaker(
        manager=gov,
        policy=CognitivePolicy(retain_arguments=False),
    )
    metered = Interceptor(
        gov,
        tier.scope,
        model=tier.model,
        max_output_tokens=tier.max_tokens,
        estimated_input_tokens=tier.est_input_tokens,
        cognitive=breaker,
        trajectory=tier.scope,
    )
    model = resolve_model(client, tier, dry_run=dry_run)
    outcome.model_served = model

    try:
        for index, prompt in enumerate(prompts, start=1):
            try:
                call = metered.invoke(client.messages.create, **call_kwargs(tier, prompt, model))
            except AgentThrashingError as exc:
                # A halt here is a false positive worth knowing about.
                outcome.halted_by = "cognitive"
                outcome.halt_reason = str(exc)
                outcome.error = "cognitive breaker halted a legitimately progressing workflow"
                break
            except AgentGovError as exc:
                outcome.halted_by = type(exc).__name__
                outcome.halt_reason = str(exc)
                break
            outcome.absorb(call)
            journal.record(call)
            receipts.append(receipt(tier, f"step-{index}", call))

            stop_reason = getattr(call.response, "stop_reason", None)
            if stop_reason == "refusal":
                outcome.note = "model declined this request (stop_reason=refusal)"
            print(
                f"    step {index}: {call.usage.input_tokens} in / "
                f"{call.usage.output_tokens} out -> ${call.cost} "
                f"({call.latency_seconds:.2f}s, stop={stop_reason})"
            )
    finally:
        breaker.close()
    return outcome


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def format_table(outcomes: list[TierOutcome]) -> str:
    """Render the per-tier summary as a fixed-width table."""
    headers = ("TIER", "MODEL SERVED", "CALLS", "IN TOK", "OUT TOK", "COST", "HALTED BY")
    rows: list[tuple[str, ...]] = []
    for out in outcomes:
        rows.append(
            (
                out.tier.key,
                out.model_served or out.tier.model,
                str(out.calls_executed),
                f"{out.input_tokens:,}",
                f"{out.output_tokens:,}",
                f"${out.cost}",
                out.halted_by or "-",
            )
        )
    totals = (
        "TOTAL",
        "",
        str(sum(o.calls_executed for o in outcomes)),
        f"{sum(o.input_tokens for o in outcomes):,}",
        f"{sum(o.output_tokens for o in outcomes):,}",
        f"${sum((o.cost for o in outcomes), money('0'))}",
        "",
    )
    widths = [
        max(len(headers[i]), len(totals[i]), *(len(r[i]) for r in rows))
        for i in range(len(headers))
    ]
    rule = "+" + "+".join("=" * (w + 2) for w in widths) + "+"
    thin = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def line(cells: tuple[str, ...]) -> str:
        return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"

    parts = [rule, line(headers), thin]
    parts.extend(line(r) for r in rows)
    parts.extend([thin, line(totals), rule])
    return "\n".join(parts)


def write_artifacts(
    out_dir: Path,
    stamp: str,
    receipts: list[dict[str, Any]],
    summary: dict[str, Any],
) -> tuple[Path, Path]:
    """Persist the raw payloads and the summary as timestamped JSON."""
    out_dir.mkdir(parents=True, exist_ok=True)
    receipts_path = out_dir / f"{stamp}_raw_responses.json"
    summary_path = out_dir / f"{stamp}_cost_summary.json"
    receipts_path.write_text(json.dumps(receipts, indent=2, sort_keys=False), encoding="utf-8")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=False), encoding="utf-8")
    return receipts_path, summary_path


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def build_client(*, dry_run: bool, workspace_id: str | None = None) -> Any:
    """Construct the API client, or the local stub for a dry run.

    An organization-level key is not accepted on its own: the API rejects it
    with a 400 unless the request names a workspace. Supply the workspace via
    ``--workspace-id`` or ``BENCHMARK_WORKSPACE_ID``, or export a key that is
    already scoped to one.
    """
    if dry_run:
        return _StubClient()
    try:
        api_key = os.environ["BENCHMARK_API_KEY"]
    except KeyError:
        raise SystemExit(
            "BENCHMARK_API_KEY is not set. This script deliberately refuses to fall "
            "back to ANTHROPIC_API_KEY or an `ant auth login` profile so it cannot "
            "bill an account you did not intend. Export the benchmark key, or run "
            "with --dry-run."
        ) from None
    workspace = workspace_id or os.environ.get("BENCHMARK_WORKSPACE_ID")
    headers = {"anthropic-workspace-id": workspace} if workspace else None
    # Explicit api_key, never the ambient default.
    return anthropic.Anthropic(api_key=api_key, max_retries=2, default_headers=headers)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--tiers",
        nargs="+",
        choices=[t.key for t in TIERS],
        default=[t.key for t in TIERS],
        help="Subset of tiers to run. Debug one tier without re-spending on the rest.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Exercise every path against a local stub. No network, no spend.",
    )
    parser.add_argument(
        "--workspace-id",
        default=None,
        help=(
            "Workspace to bill, sent as the anthropic-workspace-id header. "
            "Required when BENCHMARK_API_KEY is an organization-level key; "
            "defaults to $BENCHMARK_WORKSPACE_ID."
        ),
    )
    parser.add_argument(
        "--out",
        default=str(OUTPUT_DIR),
        help=f"Directory for receipts and the cost summary (default: {OUTPUT_DIR}).",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    selected = [t for t in TIERS if t.key in set(args.tiers)]
    dry_run = bool(args.dry_run)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")

    out_dir = Path(args.out)

    # The breaker logs every refusal at WARNING; this script narrates its own
    # results, so the duplicate stream is noise.
    logging.getLogger("agentgov.cognitive").setLevel(logging.ERROR)
    logging.getLogger("agentgov.core").setLevel(logging.ERROR)

    mode = "DRY RUN (no network, no spend)" if dry_run else "LIVE API (real spend)"
    print(f"\nAgentGov live metering run - {mode}")
    print(f"envelope ${ENVELOPE}   tiers: {', '.join(t.key for t in selected)}\n")

    client = build_client(dry_run=dry_run, workspace_id=args.workspace_id)
    journal = MeteringJournal()
    receipts: list[dict[str, Any]] = []
    outcomes: list[TierOutcome] = []

    db_path = out_dir / f"{stamp}_governor.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with BudgetManager.open_sqlite(
        str(db_path),
        # A runaway *is* the workload here; velocity tripping mid-loop would
        # mask the cognitive breaker, which is the thing under test.
        policy=GovernancePolicy(max_calls_per_window=10_000),
    ) as gov:
        gov.open_root("benchmark", ENVELOPE)
        for tier in selected:
            gov.delegate("benchmark", tier.scope, tier.budget)

        for tier in selected:
            print(f"  {tier.title}")
            print(f"    model={tier.model} max_tokens={tier.max_tokens} budget=${tier.budget}")
            try:
                if tier.key == "runaway":
                    outcome = run_runaway(client, gov, journal, tier, receipts, dry_run=dry_run)
                else:
                    prompts = {
                        "workhorse": WORKHORSE_STEPS,
                        "analyst": (ANALYST_PROMPT,),
                        "heavy": (HEAVY_PROMPT,),
                    }[tier.key]
                    outcome = run_sequence(
                        client, gov, journal, tier, prompts, receipts, dry_run=dry_run
                    )
            except anthropic.APIStatusError as exc:
                outcome = TierOutcome(tier=tier)
                outcome.error = f"{type(exc).__name__} {exc.status_code}: {exc.message}"
                print(f"    API error: {outcome.error}")
            except anthropic.APIConnectionError as exc:
                outcome = TierOutcome(tier=tier)
                outcome.error = f"connection error: {exc}"
                print(f"    {outcome.error}")

            if outcome.halted_by:
                print(f"    HALTED by {outcome.halted_by}: {outcome.halt_reason}")
            if outcome.calls_refused:
                print(f"    {outcome.calls_refused} retries refused with no balance movement")
            if outcome.note:
                print(f"    note: {outcome.note}")
            if outcome.error:
                print(f"    ERROR: {outcome.error}")
            print(f"    subtotal ${outcome.cost}\n")
            outcomes.append(outcome)

        # Independent re-pricing: recompute every settled call straight from
        # the published rates and compare against what the ledger captured.
        repriced = money("0")
        for entry in journal.entries():
            repriced += independent_cost(entry.model, entry.usage)
        ledger_total = sum((o.cost for o in outcomes), money("0"))
        drift = (repriced - ledger_total).copy_abs()

        gov.verify_integrity()
        chain_entries = len(gov.audit_trail())

        journal_path = out_dir / f"{stamp}_tokens.jsonl"
        journal.save(journal_path)

    print(format_table(outcomes))

    total_in = sum(o.input_tokens for o in outcomes)
    total_out = sum(o.output_tokens for o in outcomes)
    print(f"\n  ledger settled total      ${ledger_total}")
    print(f"  independent re-price      ${repriced}")
    print(f"  drift                     ${drift}  ({'MATCH' if drift <= QUANTUM else 'MISMATCH'})")
    print(f"  envelope utilization      {ledger_total / ENVELOPE * 100:.2f}% of ${ENVELOPE}")
    print(f"  verify_integrity()        PASS - {chain_entries} entries chained")

    summary: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "dry-run" if dry_run else "live",
        "sdk_version": anthropic.__version__,
        "envelope_usd": str(ENVELOPE),
        "ledger_settled_total_usd": str(ledger_total),
        "independent_reprice_total_usd": str(repriced),
        "pricing_drift_usd": str(drift),
        "pricing_matches_ledger": drift <= QUANTUM,
        "total_input_tokens": total_in,
        "total_output_tokens": total_out,
        "ledger_entries": chain_entries,
        "verify_integrity": "PASS",
        "ledger_db": str(db_path),
        "journal": str(journal_path),
        "tiers": [o.to_json() for o in outcomes],
    }
    receipts_path, summary_path = write_artifacts(out_dir, stamp, receipts, summary)
    print(f"\n  raw payloads              {receipts_path}")
    print(f"  cost summary              {summary_path}")
    print(f"  ledger                    {db_path}")
    print(f"  metering journal          {journal_path}\n")

    failures = [o for o in outcomes if o.error]
    return 1 if failures or drift > QUANTUM else 0


if __name__ == "__main__":
    sys.exit(main())
