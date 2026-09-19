"""Tests for invoiced-to-metered reconciliation.

The property that matters is the one a security reviewer asks about: a call
billed by the provider that AgentGov never authorized must be surfaced as a
**phantom** and must fail the audit. Everything else here exists to make sure
that signal is trustworthy — that normal drift in timestamps and token counts
does not manufacture false phantoms, and that real ones are never absorbed.
"""

from __future__ import annotations

import io
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.cli import main as cli_main
from agentgov.dummy import DummyLLM
from agentgov.interceptor import Interceptor, TokenUsage, pricing_for
from agentgov.reconciliation import (
    MeteredRecord,
    MeteringJournal,
    ProviderUsageRecord,
    ReconciliationPolicy,
    UsageParseError,
    format_report,
    load_provider_export,
    metered_records,
    parse_anthropic_csv,
    parse_openai_json,
    reconcile,
)

ZERO = Decimal("0")
NO_VELOCITY = GovernancePolicy(max_calls_per_window=0)
T0 = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)
OPUS = pricing_for("claude-opus-5")


def settled(
    index: int,
    *,
    at: datetime | None = None,
    input_tokens: int | None = 1000,
    output_tokens: int | None = 500,
    cost: Decimal | None = None,
) -> MeteredRecord:
    """A locally settled call, for driving the matcher directly."""
    usage_cost = cost
    if usage_cost is None:
        usage_cost = OPUS.cost_of(
            TokenUsage(input_tokens=input_tokens or 0, output_tokens=output_tokens or 0)
        )
    return MeteredRecord(
        transaction_id=__import__("uuid").uuid4(),
        sequence=index,
        timestamp=at if at is not None else T0,
        scope_id=f"agent-{index}",
        model="claude-opus-5",
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        settled_cost=usage_cost,
        entry_hash=f"hash{index}",
    )


def billed(
    index: int,
    *,
    at: datetime | None = None,
    input_tokens: int = 1000,
    output_tokens: int = 500,
    cost: Decimal | None = None,
) -> ProviderUsageRecord:
    """A provider invoice line."""
    return ProviderUsageRecord(
        record_id=f"req_{index}",
        timestamp=at if at is not None else T0,
        model="claude-opus-5",
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_cost=cost
        if cost is not None
        else OPUS.cost_of(TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens)),
    )


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------


def test_openai_json_is_parsed_in_both_shapes() -> None:
    modern = json.dumps(
        {
            "data": [
                {
                    "id": "req_1",
                    "timestamp": "2026-09-14T12:00:00Z",
                    "model": "gpt-4o",
                    "input_tokens": 1200,
                    "output_tokens": 300,
                    "cost": "0.0195",
                }
            ]
        }
    )
    (record,) = parse_openai_json(modern)
    assert record.record_id == "req_1"
    assert record.timestamp == T0
    assert record.input_tokens == 1200
    assert record.total_cost == Decimal("0.0195")
    assert not record.cost_was_derived

    legacy = json.dumps(
        {
            "data": [
                {
                    "aggregation_timestamp": int(T0.timestamp()),
                    "snapshot_id": "claude-opus-5",
                    "n_context_tokens_total": 1000,
                    "n_generated_tokens_total": 500,
                }
            ]
        }
    )
    (old,) = parse_openai_json(legacy)
    assert old.timestamp == T0
    assert old.model == "claude-opus-5"
    # No cost column, so it was priced from the local rate card — and flagged.
    assert old.cost_was_derived
    assert old.total_cost == OPUS.cost_of(TokenUsage(input_tokens=1000, output_tokens=500))


def test_a_bare_json_list_is_accepted() -> None:
    records = parse_openai_json(
        json.dumps([{"timestamp": "2026-09-14T12:00:00Z", "model": "m", "cost": "1.00"}])
    )
    assert len(records) == 1


def test_anthropic_csv_is_parsed_with_flexible_headers() -> None:
    text = (
        "usage_date_utc,model,input_tokens,output_tokens,cost_usd\n"
        "2026-09-14T12:00:00Z,claude-opus-5,1000,500,0.0175\n"
        "2026-09-14T12:00:05Z,claude-opus-5,2000,900,0.0325\n"
    )
    records = parse_anthropic_csv(text)
    assert len(records) == 2
    assert records[0].total_cost == Decimal("0.0175")
    assert records[1].input_tokens == 2000


def test_csv_headers_are_normalised_and_currency_is_stripped() -> None:
    text = "Usage Date UTC,Model,Input Tokens,Output Tokens,Cost USD\n2026-09-14,m,10,20,$1234.50\n"
    (record,) = parse_anthropic_csv(text)
    assert record.total_cost == Decimal("1234.50")


def test_blank_csv_rows_are_skipped() -> None:
    text = "timestamp,model,input_tokens,output_tokens,cost\n2026-09-14,m,1,1,0.01\n,,,,\n"
    assert len(parse_anthropic_csv(text)) == 1


def test_unreadable_exports_fail_loudly() -> None:
    with pytest.raises(UsageParseError, match="invalid JSON"):
        parse_openai_json("{not json")
    with pytest.raises(UsageParseError, match="list of usage rows"):
        parse_openai_json(json.dumps({"unexpected": True}))
    with pytest.raises(UsageParseError, match="no timestamp"):
        parse_openai_json(json.dumps([{"model": "m"}]))
    with pytest.raises(UsageParseError, match="unrecognised timestamp"):
        parse_openai_json(json.dumps([{"timestamp": "not-a-date", "model": "m"}]))


def test_the_format_is_detected_from_the_extension(tmp_path: Path) -> None:
    as_json = tmp_path / "usage.json"
    as_json.write_text(json.dumps([{"timestamp": "2026-09-14T12:00:00Z", "cost": "1"}]))
    assert len(load_provider_export(as_json)) == 1

    as_csv = tmp_path / "usage.csv"
    as_csv.write_text("timestamp,cost\n2026-09-14T12:00:00Z,1\n")
    assert len(load_provider_export(as_csv)) == 1

    with pytest.raises(UsageParseError, match="unknown format"):
        load_provider_export(as_json, fmt="sap-idoc")
    with pytest.raises(UsageParseError, match="cannot read"):
        load_provider_export(tmp_path / "absent.json")


# --------------------------------------------------------------------------
# The journal
# --------------------------------------------------------------------------


def test_the_journal_round_trips_through_a_file(tmp_path: Path) -> None:
    manager = BudgetManager(policy=NO_VELOCITY)
    manager.open_root("agent", money("5.00"))
    metered = Interceptor(manager, "agent", model="claude-opus-5")
    journal = MeteringJournal()
    journal.record(metered.invoke(DummyLLM("claude-opus-5", output_tokens=300).complete, "hello"))

    path = tmp_path / "tokens.jsonl"
    journal.save(path)
    restored = MeteringJournal.load(path)

    assert len(restored) == 1
    original, copy = journal.entries()[0], restored.entries()[0]
    assert copy.transaction_id == original.transaction_id
    assert copy.usage == original.usage
    assert copy.model == original.model
    assert copy.settled_at == original.settled_at
    assert original.transaction_id in restored


def test_a_corrupt_journal_line_is_reported_with_its_position(tmp_path: Path) -> None:
    path = tmp_path / "tokens.jsonl"
    path.write_text('{"transaction_id": "not-a-uuid"}\n')
    with pytest.raises(UsageParseError, match=":1:"):
        MeteringJournal.load(path)


def test_metered_records_are_read_from_a_ledger() -> None:
    manager = BudgetManager(policy=NO_VELOCITY)
    manager.open_root("agent", money("5.00"))
    metered = Interceptor(manager, "agent", model="claude-opus-5")
    journal = MeteringJournal()
    for _ in range(3):
        journal.record(metered.invoke(DummyLLM("claude-opus-5", output_tokens=200).complete, "x"))

    with_tokens = metered_records(manager, journal)
    assert len(with_tokens) == 3
    assert all(record.total_tokens is not None for record in with_tokens)
    assert all(record.scope_id == "agent" for record in with_tokens)

    without = metered_records(manager)
    assert all(record.total_tokens is None for record in without)
    assert [r.settled_cost for r in without] == [r.settled_cost for r in with_tokens]


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------


def test_a_perfect_invoice_reconciles_cleanly() -> None:
    metered = [settled(i, at=T0 + timedelta(seconds=i)) for i in range(5)]
    provider = [billed(i, at=T0 + timedelta(seconds=i)) for i in range(5)]

    report = reconcile(metered, provider)

    assert len(report.matched) == 5
    assert not report.discrepant and not report.phantom and not report.unsettled
    assert report.variance == ZERO
    assert report.passed
    assert all(match.exact for match in report.matched)
    assert report.token_matching


def test_network_delay_within_tolerance_still_matches() -> None:
    """The provider's clock and ours will never agree exactly."""
    metered = [settled(0, at=T0)]
    provider = [billed(0, at=T0 + timedelta(seconds=4.2))]

    report = reconcile(metered, provider)

    assert len(report.matched) == 1
    assert report.matched[0].time_delta_seconds == pytest.approx(4.2)
    assert report.passed


def test_delay_beyond_tolerance_is_not_matched() -> None:
    report = reconcile([settled(0, at=T0)], [billed(0, at=T0 + timedelta(seconds=45))])

    assert not report.matched
    assert len(report.phantom) == 1
    assert len(report.unsettled) == 1
    assert not report.passed


def test_the_time_window_is_configurable() -> None:
    report = reconcile(
        [settled(0, at=T0)],
        [billed(0, at=T0 + timedelta(seconds=45))],
        ReconciliationPolicy(time_tolerance_seconds=60.0),
    )
    assert len(report.matched) == 1


def test_token_drift_within_tolerance_still_matches() -> None:
    """chars/4 is a heuristic; small drift is expected, not a mismatch."""
    metered = [settled(0, input_tokens=1000, output_tokens=500)]
    provider = [billed(0, input_tokens=1010, output_tokens=505)]  # +1%

    report = reconcile(metered, provider, ReconciliationPolicy(cost_tolerance_percent=5.0))

    assert len(report.matched) == 1
    assert report.matched[0].token_delta_percent == pytest.approx(1.0)
    assert not report.matched[0].exact


def test_token_drift_beyond_tolerance_is_a_different_call() -> None:
    """Same instant, same model, wildly different size: two calls, not one."""
    metered = [settled(0, input_tokens=1000, output_tokens=500)]
    provider = [billed(0, input_tokens=40_000, output_tokens=4_000)]

    report = reconcile(metered, provider)

    assert not report.matched
    assert len(report.phantom) == 1
    assert len(report.unsettled) == 1


def test_a_phantom_call_fails_the_audit() -> None:
    """The finding that matters: billed spend with no local authorization."""
    metered = [settled(0, at=T0)]
    provider = [billed(0, at=T0), billed(99, at=T0 + timedelta(seconds=1), cost=money("12.50"))]

    report = reconcile(metered, provider)

    assert len(report.matched) == 1
    assert len(report.phantom) == 1
    assert report.phantom[0].record_id == "req_99"
    assert report.phantom_total == money("12.50")
    assert not report.passed


def test_an_unsettled_call_alone_does_not_fail_the_audit() -> None:
    """A call settled near a billing boundary lands on the next invoice."""
    report = reconcile([settled(0), settled(1, at=T0 + timedelta(seconds=30))], [billed(0)])

    assert len(report.matched) == 1
    assert len(report.unsettled) == 1
    assert not report.phantom
    assert report.passed, "an unbilled local settlement is a timing artefact, not a breach"


def test_a_cost_discrepancy_is_flagged_and_fails() -> None:
    """Same call, different money: usually a stale rate card."""
    metered = [settled(0, cost=money("0.0175"))]
    provider = [billed(0, cost=money("0.0350"))]

    report = reconcile(metered, provider)

    assert not report.matched
    (discrepancy,) = report.discrepant
    assert discrepancy.cost_delta == money("0.0175")
    assert discrepancy.cost_delta_percent == pytest.approx(100.0)
    assert "stale rate card" in discrepancy.reason
    assert not report.passed


def test_small_cost_drift_is_tolerated() -> None:
    metered = [settled(0, cost=Decimal("1.0000"))]
    provider = [billed(0, cost=Decimal("1.0050"))]  # 0.5%
    report = reconcile(metered, provider)
    assert len(report.matched) == 1 and report.passed


def test_matching_is_one_to_one() -> None:
    """Two identical billed lines cannot both claim one settlement."""
    report = reconcile([settled(0)], [billed(0), billed(1)])
    assert len(report.matched) == 1
    assert len(report.phantom) == 1


def test_a_different_model_is_never_matched() -> None:
    metered = [settled(0)]
    other = ProviderUsageRecord(
        record_id="req_x",
        timestamp=T0,
        model="gpt-4o",
        input_tokens=1000,
        output_tokens=500,
        total_cost=metered[0].settled_cost,
    )
    report = reconcile(metered, [other])
    assert not report.matched
    assert len(report.phantom) == 1


def test_a_dated_model_snapshot_still_matches() -> None:
    metered = [settled(0)]
    dated = ProviderUsageRecord(
        record_id="req_x",
        timestamp=T0,
        model="claude-opus-5-20260401",
        input_tokens=1000,
        output_tokens=500,
        total_cost=metered[0].settled_cost,
    )
    assert len(reconcile(metered, [dated]).matched) == 1


def test_reconciliation_works_without_a_journal() -> None:
    """Degrades to cost-and-time matching, and says so."""
    reference = billed(0)
    # No journal means no token counts — but the settled cost is still known,
    # which is what cost-and-time matching runs on.
    metered = [settled(0, input_tokens=None, output_tokens=None, cost=reference.total_cost)]
    report = reconcile(metered, [reference])

    assert len(report.matched) == 1
    assert report.matched[0].token_delta_percent is None
    assert not report.token_matching
    assert any("No metering journal" in note for note in report.notes)


def test_the_report_totals_and_variance() -> None:
    metered = [settled(0, cost=Decimal("1.00")), settled(1, cost=Decimal("2.00"))]
    provider = [
        billed(0, cost=Decimal("1.00")),
        billed(1, cost=Decimal("2.00")),
        billed(9, at=T0 + timedelta(seconds=2), cost=Decimal("0.50")),
    ]
    report = reconcile(metered, provider)

    assert report.invoiced_total == Decimal("3.50")
    assert report.metered_total == Decimal("3.00")
    assert report.variance == Decimal("0.50")
    assert report.variance_percent == pytest.approx(16.666, abs=0.01)
    assert report.total_provider_records == 3


def test_an_empty_reconciliation_is_a_pass() -> None:
    report = reconcile([], [])
    assert report.passed
    assert report.variance == ZERO
    assert report.variance_percent == 0.0


def test_the_rendered_report_is_readable() -> None:
    report = reconcile([settled(0)], [billed(0), billed(9, cost=money("9.99"))])
    text = format_report(report, path="gov.db", export="invoice.json")

    assert "RECONCILIATION" in text
    assert "AUDIT FAILED" in text
    assert "PHANTOM CALLS" in text
    assert "$9.99" in text

    clean = format_report(reconcile([settled(0)], [billed(0)]))
    assert "AUDIT PASSED" in clean


# --------------------------------------------------------------------------
# End to end, through the CLI
# --------------------------------------------------------------------------


def build_ledger(tmp_path: Path, calls: int = 3) -> tuple[str, str, list[Decimal]]:
    """A real governed run, plus the journal that reconciliation needs."""
    db = str(tmp_path / "gov.db")
    manager = BudgetManager.open_sqlite(db, policy=NO_VELOCITY)
    manager.open_root("agent", money("5.00"))
    metered = Interceptor(manager, "agent", model="claude-opus-5")
    journal = MeteringJournal()
    costs: list[Decimal] = []
    for index in range(calls):
        result = metered.invoke(
            DummyLLM("claude-opus-5", output_tokens=200).complete, f"question {index}"
        )
        journal.record(result)
        costs.append(result.cost)
    journal_path = str(tmp_path / "tokens.jsonl")
    journal.save(journal_path)
    manager.close()
    return db, journal_path, costs


def invoice_for(db: str, journal_path: str, tmp_path: Path, *, phantom: bool = False) -> str:
    """An invoice built from what actually happened, plus optional leakage."""
    manager = BudgetManager.open_sqlite(db, read_only=True)
    journal = MeteringJournal.load(journal_path)
    rows = []
    for record in metered_records(manager, journal):
        rows.append(
            {
                "id": str(record.transaction_id),
                # A realistic sub-second delay between call and invoice line.
                "timestamp": (record.timestamp + timedelta(seconds=1.1)).isoformat(),
                "model": record.model,
                "input_tokens": record.input_tokens,
                "output_tokens": record.output_tokens,
                "cost": str(record.settled_cost),
            }
        )
        last = record
    if phantom:
        rows.append(
            {
                "id": "req_LEAKED_KEY",
                "timestamp": last.timestamp.isoformat(),
                "model": "claude-opus-5",
                "input_tokens": 200_000,
                "output_tokens": 8_000,
                "cost": "1.20",
            }
        )
    manager.close()
    path = tmp_path / "invoice.json"
    path.write_text(json.dumps({"data": rows}))
    return str(path)


def run_cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    return cli_main(list(argv), out=out), out.getvalue()


def test_the_cli_passes_on_a_clean_invoice(tmp_path: Path) -> None:
    db, journal_path, costs = build_ledger(tmp_path)
    invoice = invoice_for(db, journal_path, tmp_path)

    code, output = run_cli("reconcile", db, invoice, "--journal", journal_path)

    assert code == 0, output
    assert "AUDIT PASSED" in output
    assert "Matched (billed and metered)" in output
    assert "token-level (journal supplied)" in output
    assert f"{len(costs)}" in output


def test_the_cli_fails_on_unmetered_spend(tmp_path: Path) -> None:
    """The demo moment: a leaked key shows up as a phantom and exits nonzero."""
    db, journal_path, _ = build_ledger(tmp_path)
    invoice = invoice_for(db, journal_path, tmp_path, phantom=True)

    code, output = run_cli("reconcile", db, invoice, "--journal", journal_path)

    assert code == 1, "unmetered spend must fail the pipeline"
    assert "AUDIT FAILED" in output
    assert "PHANTOM CALLS" in output
    assert "req_LEAKED_KEY" in output
    assert "$1.20" in output


def test_the_cli_works_without_a_journal(tmp_path: Path) -> None:
    db, journal_path, _ = build_ledger(tmp_path)
    invoice = invoice_for(db, journal_path, tmp_path)

    code, output = run_cli("reconcile", db, invoice)

    assert code == 0, output
    assert "cost and time only" in output
    assert "No metering journal" in output


def test_the_cli_reports_unreadable_inputs_cleanly(tmp_path: Path) -> None:
    db, journal_path, _ = build_ledger(tmp_path)

    code, output = run_cli("reconcile", db, str(tmp_path / "missing.json"))
    assert code == 1
    assert "could not read" in output

    invoice = invoice_for(db, journal_path, tmp_path)
    code, output = run_cli("reconcile", db, invoice, "--journal", str(tmp_path / "nope.jsonl"))
    assert code == 1
    assert "journal" in output


def test_cli_tolerances_are_configurable(tmp_path: Path) -> None:
    db, journal_path, _ = build_ledger(tmp_path)
    invoice = invoice_for(db, journal_path, tmp_path)

    # The invoice is offset by 1.1s; a 0.5s window must reject every match.
    code, output = run_cli(
        "reconcile", db, invoice, "--journal", journal_path, "--time-tolerance", "0.5"
    )
    assert code == 1
    assert "Phantom" in output


def test_the_cli_reconciles_a_live_governor(tmp_path: Path) -> None:
    """Read-only access means finance can run this against production."""
    db, journal_path, _ = build_ledger(tmp_path)
    invoice = invoice_for(db, journal_path, tmp_path)

    live = BudgetManager.open_sqlite(db, policy=NO_VELOCITY)
    try:
        code, _ = run_cli("reconcile", db, invoice, "--journal", journal_path)
        assert code == 0
    finally:
        live.close()


# --------------------------------------------------------------------------
# Dated snapshot identifiers
# --------------------------------------------------------------------------


def test_a_dated_invoice_line_matches_an_undated_ledger_line() -> None:
    """The invoice names the model that served; the ledger names the alias.

    A provider bills `claude-haiku-4-5-20251001` for a call the governor
    metered as `claude-haiku-4-5`. Folding the dated suffix is what keeps the
    two the same model, and without it a healthy invoice reads as every line
    being a model mismatch.
    """
    local = replace(settled(1), model="claude-haiku-4-5")
    invoice = replace(billed(1), model="claude-haiku-4-5-20251001")

    report = reconcile([local], [invoice])

    assert len(report.matched) == 1
    assert not report.phantom
    assert not report.unsettled


def test_a_genuinely_different_model_is_still_a_mismatch() -> None:
    """Folding the suffix must not fold two different models together."""
    local = replace(settled(1), model="claude-haiku-4-5")
    invoice = replace(billed(1), model="claude-opus-5-20260401")

    report = reconcile([local], [invoice])

    assert not report.matched
    assert len(report.phantom) == 1
    assert len(report.unsettled) == 1


def test_cost_is_derived_for_a_dated_model_with_no_billed_total() -> None:
    """An export with tokens and no cost has to find the rate card.

    `_derive_cost` looks the model up in PRICING, which is keyed on undated
    aliases, so a dated line silently derived nothing before.
    """
    rows = parse_openai_json(
        json.dumps(
            {
                "data": [
                    {
                        "id": "req_dated",
                        "timestamp": T0.isoformat(),
                        "model": "claude-haiku-4-5-20251001",
                        "input_tokens": 1000,
                        "output_tokens": 500,
                    }
                ]
            }
        )
    )

    haiku = pricing_for("claude-haiku-4-5")
    expected = haiku.cost_of(TokenUsage(input_tokens=1000, output_tokens=500))
    assert len(rows) == 1
    assert rows[0].total_cost == expected
    assert rows[0].cost_was_derived is True
