"""ARC1 1.3: how an action was measured, and what it cost in any unit.

``coverage.measurement`` says how strongly an effect was measured (one of
``transactional``, ``plan-bound``, ``predicted``, ``request-only``);
``cost.quantities`` what it consumed in ledgers of other units; and
``cost.served_by`` the systems other than models that served it. Each is
written only when it is not the default, so every receipt before 1.3 keeps
its bytes, and reads as the transactional, dollar-priced, model-served
action it was.
"""

from __future__ import annotations

import io
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from agentgov import BudgetManager, Unit
from agentgov.cli import main
from agentgov.exceptions import MalformedReceiptError
from agentgov.receipts import (
    MEASUREMENTS,
    PLAN_BOUND,
    PREDICTED,
    REQUEST_ONLY,
    TRANSACTIONAL,
    ActionReceipt,
    Cost,
    Ed25519Signer,
    Quantity,
    ReceiptBundle,
    ReceiptLog,
    canonical_bytes,
    verify_bundle,
)

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
TEMPLATE = ReceiptBundle.loads(
    (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
).action_receipt
SIGNER = Ed25519Signer(b"\x13" * 32)


def _round_trip(receipt: ActionReceipt) -> dict[str, Any]:
    signed = receipt.sign(SIGNER)
    again = ActionReceipt.from_json(signed.to_json())
    assert again == signed
    again.verify(SIGNER.public_key())
    document: dict[str, Any] = signed.to_json()
    return document


def test_the_defaults_are_never_written_so_old_receipts_keep_their_bytes() -> None:
    assert TEMPLATE.coverage.measurement == TRANSACTIONAL
    body = TEMPLATE.to_json()
    assert set(body["coverage"]) == {
        "observed_tables",
        "cascade_closed",
        "authorizer_on",
        "known_gaps",
    }
    assert set(body["cost"]) == {"ledger_txn_ids", "settled_usd", "served_models"}
    raw = (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
    bundle = ReceiptBundle.loads(raw)
    assert canonical_bytes(bundle.action_receipt.to_json()) == canonical_bytes(
        ReceiptBundle.loads(raw).to_json()["receipt"]
    )


@pytest.mark.parametrize("measurement", [PLAN_BOUND, PREDICTED, REQUEST_ONLY])
def test_every_other_measurement_class_round_trips(measurement: str) -> None:
    receipt = replace(TEMPLATE, coverage=replace(TEMPLATE.coverage, measurement=measurement))
    assert _round_trip(receipt)["coverage"]["measurement"] == measurement
    assert MEASUREMENTS[0] == TRANSACTIONAL


def test_a_measurement_class_that_does_not_exist_is_refused() -> None:
    with pytest.raises(MalformedReceiptError, match="measurement must be one of"):
        replace(TEMPLATE.coverage, measurement="estimated")
    document = TEMPLATE.to_json()
    document["coverage"]["measurement"] = "transactional"
    with pytest.raises(MalformedReceiptError, match="written only when it is not"):
        ActionReceipt.from_json(document)


def test_a_receipt_may_name_only_its_own_tenant_and_count_the_others() -> None:
    assert "other_tenants" not in TEMPLATE.to_json()["effect"]["summary"]
    summary = replace(TEMPLATE.effect.summary, tenants=("acme",), other_tenants=3)
    receipt = replace(TEMPLATE, effect=replace(TEMPLATE.effect, summary=summary))
    found = _round_trip(receipt)["effect"]["summary"]
    assert (found["tenants"], found["other_tenants"]) == (["acme"], 3)
    with pytest.raises(MalformedReceiptError, match="a count"):
        replace(summary, other_tenants=-1)
    document = TEMPLATE.to_json()
    document["effect"]["summary"]["other_tenants"] = 0
    with pytest.raises(MalformedReceiptError, match="written only when"):
        ActionReceipt.from_json(document)


def test_quantities_and_served_by_round_trip_sorted() -> None:
    cost = Cost(
        ledger_txn_ids=TEMPLATE.cost.ledger_txn_ids,
        settled_usd=Decimal("0.0023"),
        quantities=(Quantity("vcpu", Decimal(8)), Quantity("mme", Decimal("30.5"))),
        served_by=("terraform", "fhir:epic"),
    )
    assert [q.unit for q in cost.quantities] == ["mme", "vcpu"]
    document = _round_trip(replace(TEMPLATE, cost=cost))["cost"]
    assert document["quantities"] == [
        {"unit": "mme", "amount": "30.50000000", "ledger_txn_ids": []},
        {"unit": "vcpu", "amount": "8.00000000", "ledger_txn_ids": []},
    ]
    assert document["served_by"] == ["fhir:epic", "terraform"]


@pytest.mark.parametrize(
    ("change", "match"),
    [
        (lambda c: c.update(quantities=[]), "only when it holds a quantity"),
        (lambda c: c.update(served_by=[]), "only when it names a system"),
        (
            lambda c: c.update(
                quantities=[
                    {"unit": "vcpu", "amount": "1.00000000", "ledger_txn_ids": []},
                    {"unit": "mme", "amount": "1.00000000", "ledger_txn_ids": []},
                ]
            ),
            "sorted by unit",
        ),
        (
            lambda c: c.update(
                quantities=[{"unit": "mme", "amount": "1.00000000", "ledger_txn_ids": []}] * 2
            ),
            "names a unit twice",
        ),
        (
            lambda c: c.update(
                quantities=[{"unit": "MME", "amount": "1.00000000", "ledger_txn_ids": []}]
            ),
            "a unit code",
        ),
        (
            lambda c: c.update(quantities=[{"unit": "mme", "amount": "-1.00000000"}]),
            "missing ledger_txn_ids",
        ),
        (lambda c: c.update(rate="1"), "unknown field"),
    ],
)
def test_a_cost_that_breaks_1_3_is_refused(change: Any, match: str) -> None:
    document = TEMPLATE.to_json()
    change(document["cost"])
    with pytest.raises(MalformedReceiptError, match=match):
        ActionReceipt.from_json(document)


def _dose_receipt(
    tmp_path: Path, *, claimed: Decimal
) -> tuple[ReceiptBundle, BudgetManager, BudgetManager]:
    """A receipt for a dose order that consumed 30 MME from a ledger of mme."""
    mme = BudgetManager(unit=Unit("mme"))
    mme.open_root("pharmacy", Decimal(900))
    capture = mme.capture(mme.authorize("pharmacy", Decimal(90)), Decimal(30))
    usd = BudgetManager()
    usd.open_root("pharmacy", Decimal(1))
    log = ReceiptLog("rx-1", SIGNER, path=tmp_path / "receipts.jsonl")
    draft = replace(
        TEMPLATE,
        cost=Cost(
            quantities=(Quantity("mme", claimed, (str(capture.transaction_id),)),),
            served_by=("fhir:epic",),
        ),
        anchors=replace(TEMPLATE.anchors, agentgov=None),
    )
    issued = log.issue(draft)
    bundle = log.bundle(0, log.publish())
    assert bundle.receipt == issued
    log.close()
    return bundle, mme, usd


def test_a_quantity_is_held_to_the_ledger_of_its_unit(tmp_path: Path) -> None:
    bundle, mme, usd = _dose_receipt(tmp_path, claimed=Decimal(30))
    key = SIGNER.public_key()
    report = verify_bundle(bundle, issuer_key=key, ledgers={"mme": mme})
    assert report.passed, report.first_failure
    (check,) = [c for c in report.checks if c.name == "unit ledgers"]
    assert check.status == "pass" and "30.00000000 mme" in check.detail
    skipped = verify_bundle(bundle, issuer_key=key)
    assert [c.status for c in skipped.checks if c.name == "unit ledgers"] == ["skip"]
    wrong = verify_bundle(bundle, issuer_key=key, ledgers={"mme": usd})
    assert wrong.first_failure is not None and "conserves usd" in wrong.first_failure.detail


def test_a_quantity_its_ledger_did_not_settle_fails(tmp_path: Path) -> None:
    bundle, mme, _ = _dose_receipt(tmp_path, claimed=Decimal(25))
    report = verify_bundle(bundle, issuer_key=SIGNER.public_key(), ledgers={"mme": mme})
    failed = report.first_failure
    assert failed is not None and failed.name == "unit ledgers"
    assert "settled 30.00000000; it claims 25.00000000" in failed.detail
    assert report.exit_code == 7


def test_verify_receipt_takes_ledgers_of_other_units(tmp_path: Path) -> None:
    vcpu = Unit("vcpu", 0)
    path = tmp_path / "vcpu.db"
    with BudgetManager.open_sqlite(str(path), unit=vcpu) as gov:
        gov.open_root("platform", Decimal(64))
        txn = gov.capture(gov.authorize("platform", Decimal(8)), Decimal(8)).transaction_id
    log = ReceiptLog("sre-1", SIGNER, path=tmp_path / "receipts.jsonl")
    log.issue(
        replace(
            TEMPLATE,
            coverage=replace(TEMPLATE.coverage, measurement=PLAN_BOUND),
            cost=Cost(quantities=(Quantity("vcpu", Decimal(8), (str(txn),)),)),
        )
    )
    bundle_path = tmp_path / "scale.bundle.json"
    bundle_path.write_bytes(canonical_bytes(log.bundle(0, log.publish()).to_json()))
    log.close()
    key_path = tmp_path / "issuer.pub"
    key_path.write_text(SIGNER.public_key().spec() + "\n")
    out = io.StringIO()
    code = main(
        [
            "verify-receipt",
            str(bundle_path),
            "--pubkey",
            str(key_path),
            "--unit-ledger",
            f"vcpu={path}",
        ],
        out=out,
    )
    assert code == 0, out.getvalue()
    assert "measured plan-bound" in out.getvalue()
    assert "settled 8.00000000 vcpu" in out.getvalue()
    out = io.StringIO()
    assert (
        main(
            [
                "verify-receipt",
                str(bundle_path),
                "--pubkey",
                str(key_path),
                "--unit-ledger",
                "vcpu",
            ],
            out=out,
        )
        == 2
    )
