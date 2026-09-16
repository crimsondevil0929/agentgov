#!/usr/bin/env python3
"""Calibrate ``CognitivePolicy.result_similarity_threshold`` against live traffic.

The near-duplicate detector only counts a pair of calls as stagnant when their
*results* are also similar. That veto is what stops pagination from looking
like a loop — and if its threshold is wrong in the other direction, it
silently disables the detector entirely.

The shipped 0.70 was calibrated against :class:`~agentgov.dummy.DummyLLM`,
whose completions are templated and therefore share most of their characters.
Real model prose does not behave that way: two answers that mean the same
thing ("I don't have access to that, here's what I'd try instead") overlap far
less at the character level than two renderings of the same template. A
threshold tuned on the stub is not a threshold that holds in production.

This script measures both sides of the distribution against the live API and
prints the separating value, so the constant in ``cognitive.py`` is a measured
number rather than an inherited guess.

It drives two families of trajectory through ``claude-haiku-4-5``:

* **Thrashing** - four cosmetically-edited restatements of one request. The
  answers should be near-identical restatements of one non-answer.
* **Progressing** - four genuinely advancing steps on one topic. Inputs stay
  topically close (the hard case) but each answer carries new information.

Similarity is computed through the exact production path:
:func:`~agentgov.cognitive.extract_result_text` then
:func:`~agentgov.cognitive.shingles`, with the policy's own shingle size and
truncation bound.

Budget: every trajectory is a fixed-length tuple, not a loop, and each call is
capped at :data:`MAX_TOKENS`. A full run is roughly $0.03.

Usage::

    export BENCHMARK_API_KEY=sk-ant-...
    uv run python scripts/calibrate_result_threshold.py
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import anthropic

from agentgov import BudgetManager, money
from agentgov.cognitive import (
    CognitivePolicy,
    canonical_arguments,
    extract_result_text,
    jaccard,
    shingles,
)
from agentgov.interceptor import Interceptor

MODEL: Final = "claude-haiku-4-5"
MAX_TOKENS: Final = 200
ENVELOPE: Final = money("1.00")  # 12 trajectories x $0.05 delegated; ~$0.04 actually spent
OUT_DIR: Final = Path("benchmarks/live_data")

# Four restatements of one request, differing only cosmetically. An agent
# producing these is making no progress; a governor should say so.
THRASHING: Final[tuple[tuple[str, ...], ...]] = (
    (
        "find the Q3 revenue report for the northwest region",
        "find the Q3 revenue reports for the northwest region",
        "find the Q3 revenue report for the northwest regions",
        "find the Q3 revenue report for the northwest region now",
    ),
    (
        "look up our employee handbook policy on remote work",
        "look up our employee handbook policies on remote work",
        "look up the employee handbook policy on remote work",
        "look up our employee handbook policy on remote working",
    ),
    (
        "what is the current price of widget SKU 44821 in our catalog",
        "what is the current price for widget SKU 44821 in our catalog",
        "what is the current price of widget SKU 44821 in the catalog",
        "what is the current price of widget SKU 44821 in our catalogue",
    ),
    (
        "retrieve the customer churn numbers for enterprise accounts in May",
        "retrieve the customer churn number for enterprise accounts in May",
        "retrieve the customer churn numbers for enterprise account in May",
        "retrieve the customer churn numbers for our enterprise accounts in May",
    ),
)

# Four genuinely advancing steps. Deliberately kept on one topic so inputs stay
# similar — this is the hard case the veto exists to protect.
PROGRESSING: Final[tuple[tuple[str, ...], ...]] = (
    (
        "Name one common cause of memory leaks in long-running Python services.",
        "For that cause, name the standard tool used to detect it. One line.",
        "Write the one-line code change that fixes it.",
        "Name the single test that would catch a regression of it.",
    ),
    (
        "Name the three messages of the TCP three-way handshake, in order.",
        "Which of those three messages does a SYN flood abuse?",
        "Name one standard mitigation for that attack.",
        "State the main operational cost of that mitigation. One sentence.",
    ),
    (
        "What does the acronym RAII stand for?",
        "Which programming language popularized that idiom?",
        "Give one concrete standard-library type from that language using it.",
        "What happens to that type during exception unwinding?",
    ),
    (
        "Name the largest cost driver in a typical SaaS gross margin.",
        "Name one lever a finance team can pull on it this quarter.",
        "Quantify a realistic percentage impact of that lever in one line.",
        "State the main risk of pulling that lever. One sentence.",
    ),
)


# Near-identical inputs that produce genuinely different outputs: only the
# index changes. This — not a multi-step workflow — is the population the
# result veto actually has to discriminate, because it is the only other kind
# of traffic that clears the 0.70 input gate.
PAGINATING: Final[tuple[tuple[str, ...], ...]] = (
    (
        "Give me fact number 1 about the Apollo program. One sentence.",
        "Give me fact number 2 about the Apollo program. One sentence.",
        "Give me fact number 3 about the Apollo program. One sentence.",
        "Give me fact number 4 about the Apollo program. One sentence.",
    ),
    (
        "Name element number 11 of the periodic table and its symbol.",
        "Name element number 12 of the periodic table and its symbol.",
        "Name element number 13 of the periodic table and its symbol.",
        "Name element number 14 of the periodic table and its symbol.",
    ),
    (
        "Name the country with the 1st largest land area and its capital.",
        "Name the country with the 2nd largest land area and its capital.",
        "Name the country with the 3rd largest land area and its capital.",
        "Name the country with the 4th largest land area and its capital.",
    ),
    (
        "Describe page 1 of a 4-page incident report outline. One sentence.",
        "Describe page 2 of a 4-page incident report outline. One sentence.",
        "Describe page 3 of a 4-page incident report outline. One sentence.",
        "Describe page 4 of a 4-page incident report outline. One sentence.",
    ),
)


def render_arguments(prompt: str) -> str:
    """The canonical form the breaker shingles for a Messages API call."""
    return canonical_arguments(
        (),
        {
            "model": MODEL,
            "max_tokens": MAX_TOKENS,
            "messages": [{"role": "user", "content": prompt}],
        },
    )


def similarities(texts: list[str], policy: CognitivePolicy) -> list[float]:
    """Consecutive result-to-result Jaccard, through the production path."""
    digests = [
        shingles(t, size=policy.shingle_size, max_chars=policy.max_argument_chars) for t in texts
    ]
    return [jaccard(digests[i], digests[i + 1]) for i in range(len(digests) - 1)]


def input_similarities(prompts: tuple[str, ...], policy: CognitivePolicy) -> list[float]:
    """Consecutive argument-to-argument Jaccard — the detector's primary gate."""
    digests = [
        shingles(render_arguments(p), size=policy.shingle_size, max_chars=policy.max_argument_chars)
        for p in prompts
    ]
    return [jaccard(digests[i], digests[i + 1]) for i in range(len(digests) - 1)]


def run_trajectory(
    client: Any, metered: Interceptor, prompts: tuple[str, ...]
) -> tuple[list[str], int, int]:
    """Execute one fixed-length trajectory and return its answer texts."""
    texts: list[str] = []
    tokens_in = tokens_out = 0
    for prompt in prompts:
        call = metered.invoke(
            client.messages.create,
            model=MODEL,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
        )
        tokens_in += call.usage.input_tokens
        tokens_out += call.usage.output_tokens
        texts.append(extract_result_text(call.response) or "")
    return texts, tokens_in, tokens_out


def describe(label: str, values: list[float]) -> dict[str, float]:
    """Print and return the distribution summary for one family."""
    stats = {
        "n": float(len(values)),
        "min": min(values),
        "median": statistics.median(values),
        "mean": statistics.fmean(values),
        "max": max(values),
    }
    print(
        f"  {label:<12} n={len(values):<3} min={stats['min']:.4f}  "
        f"median={stats['median']:.4f}  mean={stats['mean']:.4f}  max={stats['max']:.4f}"
    )
    return stats


def _would_fire(
    trajectory: dict[str, Any], result_threshold: float, gate: float, max_streak: int
) -> bool:
    """Replay NearDuplicateDetector's rule over one recorded trajectory.

    A pair counts as stagnant when the arguments clear the input gate *and*
    the results clear ``result_threshold``; the detector trips once
    ``max_streak`` of them occur back to back.
    """
    run = 0
    inputs: list[float] = trajectory["consecutive_input_similarity"]
    results: list[float] = trajectory["consecutive_result_similarity"]
    for argument_similarity, result_similarity in zip(inputs, results, strict=True):
        if argument_similarity >= gate and result_similarity >= result_threshold:
            run += 1
            if run >= max_streak:
                return True
        else:
            run = 0
    return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(OUT_DIR))
    parser.add_argument("--workspace-id", default=None)
    args = parser.parse_args(argv)

    try:
        api_key = os.environ["BENCHMARK_API_KEY"]
    except KeyError:
        raise SystemExit("BENCHMARK_API_KEY is not set.") from None
    workspace = args.workspace_id or os.environ.get("BENCHMARK_WORKSPACE_ID")
    client = anthropic.Anthropic(
        api_key=api_key,
        max_retries=2,
        default_headers={"anthropic-workspace-id": workspace} if workspace else None,
    )

    policy = CognitivePolicy()
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nResult-similarity calibration - {MODEL}, max_tokens={MAX_TOKENS}")
    print(f"envelope ${ENVELOPE}\n")

    families: dict[str, tuple[tuple[str, ...], ...]] = {
        "thrashing": THRASHING,
        "paginating": PAGINATING,
        "progressing": PROGRESSING,
    }
    corpus: dict[str, list[dict[str, Any]]] = {name: [] for name in families}
    result_scores: dict[str, list[float]] = {name: [] for name in families}
    input_scores: dict[str, list[float]] = {name: [] for name in families}
    total_in = total_out = 0

    gov = BudgetManager()
    gov.open_root("calibration", ENVELOPE)

    for family, trajectories in families.items():
        print(f"  {family}:")
        for index, prompts in enumerate(trajectories, start=1):
            scope = f"{family}-{index}"
            gov.delegate("calibration", scope, money("0.05"))
            # No cognitive breaker attached: this run must observe the raw
            # distribution, not be halted partway through measuring it.
            metered = Interceptor(
                gov,
                scope,
                model=MODEL,
                max_output_tokens=MAX_TOKENS,
                estimated_input_tokens=100,
            )
            texts, t_in, t_out = run_trajectory(client, metered, prompts)
            total_in += t_in
            total_out += t_out
            scores = similarities(texts, policy)
            inputs = input_similarities(prompts, policy)
            result_scores[family].extend(scores)
            input_scores[family].extend(inputs)
            corpus[family].append(
                {
                    "scope": scope,
                    "prompts": list(prompts),
                    "answers": texts,
                    "consecutive_result_similarity": scores,
                    "consecutive_input_similarity": inputs,
                }
            )
            print(f"    {scope:<16} results " + ", ".join(f"{s:.4f}" for s in scores))

    # Stage 1. The result veto is a *secondary* gate: it is only consulted for
    # pairs whose arguments already cleared similarity_threshold. Any family
    # that never clears that gate is irrelevant to calibrating the veto.
    gate = policy.similarity_threshold
    print(f"\n  stage 1 - which families reach the {gate:.2f} input gate at all:")
    reaches: dict[str, bool] = {}
    for family, values in input_scores.items():
        passing = sum(1 for v in values if v >= gate)
        reaches[family] = passing > 0
        verdict = "REACHES the result veto" if passing else "excluded by input gate alone"
        print(
            f"    {family:<12} {passing:>2}/{len(values)} pairs >= {gate:.2f}  "
            f"(max {max(values):.4f})  -> {verdict}"
        )

    print("\n  stage 2 - result similarity, for families that reach the veto:")
    summaries: dict[str, dict[str, float]] = {}
    for family, values in result_scores.items():
        summaries[family] = describe(family, values)

    # Stage 3. Per-pair distributions overlap, so no single-pair threshold
    # separates the families. The detector does not fire on a pair, though —
    # it needs `max_streak` *consecutive* stagnant pairs. Pagination's
    # similarity is erratic (one framing-heavy pair, then divergence) while
    # thrashing's stays persistently elevated, so the streak requirement is
    # what discriminates. Sweep the real rule and read the answer off it.
    print(
        f"\n  stage 3 - sweep of the real detector rule (max_streak={policy.max_similar_streak}):"
    )
    print(f"    {'thr':>6} | {'thrash detected':>15} | {'paginate FP':>11} | {'progress FP':>11}")
    print("    " + "-" * 54)
    sweep: list[dict[str, float]] = []
    for step in range(20, 75, 5):
        threshold = step / 100
        counts = {
            family: sum(
                _would_fire(t, threshold, gate, policy.max_similar_streak) for t in corpus[family]
            )
            for family in families
        }
        sweep.append({"threshold": threshold, **{k: float(v) for k, v in counts.items()}})
        clean = counts["paginating"] == 0 and counts["progressing"] == 0
        flag = "  <- zero false positives" if clean else ""
        print(
            f"    {threshold:>6.2f} | {counts['thrashing']:>12}/4 | "
            f"{counts['paginating']:>8}/4 | {counts['progressing']:>8}/4{flag}"
        )

    detected_all = [
        row
        for row in sweep
        if row["thrashing"] == len(THRASHING) and row["paginating"] == 0 and row["progressing"] == 0
    ]
    separated = bool(detected_all)
    # Within the band that catches everything with no false positive, take the
    # HIGHEST value: a higher result threshold makes agreement harder to reach,
    # which is the conservative direction for a rule that halts an agent.
    recommended = max(row["threshold"] for row in detected_all) if separated else float("nan")

    ceiling = summaries["paginating"]["max"]
    floor = summaries["thrashing"]["min"]
    print(f"\n  per-pair ranges overlap: paginating max {ceiling:.4f} > thrashing min {floor:.4f}")
    if separated:
        band = [row["threshold"] for row in detected_all]
        print(f"  full-detection, zero-FP band:             {min(band):.2f} - {max(band):.2f}")
        print(f"  RECOMMENDED result_similarity_threshold:  {recommended:.2f}")
        print(
            f"  shipped {policy.result_similarity_threshold:.2f} detects "
            f"{int(sweep[-1]['thrashing'])}/{len(THRASHING)} thrashing trajectories"
        )
    else:
        print("  NO THRESHOLD achieves full detection with zero false positives.")

    cost = (
        ENVELOPE
        - gov.available("calibration")
        - sum(gov.available(f"{f}-{i}") for f in families for i in range(1, 5))
    )
    print(f"\n  tokens: {total_in:,} in / {total_out:,} out    spend: ${cost}\n")

    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "shingle_size": policy.shingle_size,
        "max_argument_chars": policy.max_argument_chars,
        "input_gate": gate,
        "reaches_result_veto": reaches,
        "result_similarity": summaries,
        "input_similarity": {
            f: {"min": min(v), "max": max(v), "median": statistics.median(v)}
            for f, v in input_scores.items()
        },
        "separated": separated,
        "sweep": sweep,
        "false_positive_ceiling": ceiling,
        "detection_floor": floor,
        "recommended_threshold": None if not separated else round(recommended, 2),
        "shipped_threshold": policy.result_similarity_threshold,
        "total_input_tokens": total_in,
        "total_output_tokens": total_out,
        "spend_usd": str(cost),
        "corpus": corpus,
    }
    path = out_dir / f"{stamp}_result_threshold_calibration.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  corpus + report: {path}\n")
    return 0 if separated else 1


if __name__ == "__main__":
    sys.exit(main())
