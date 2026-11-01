"""ARC1 1.4: a write that was put back.

A plan admitted and written whose writes did not stand (one failed part way,
or the read-back was not what was measured) was put back from the undo the
issuer recorded before its first write. Its receipt says ``compensated``,
and names the id its writes and their put-back carried, so a system of
record that logged both ties them to it.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from agentgov.exceptions import MalformedReceiptError
from agentgov.receipts import (
    ActionReceipt,
    Ed25519Signer,
    Outcome,
    OutcomeStatus,
    ReceiptBundle,
    verify_bundle,
)

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
ISSUER = Ed25519Signer(bytes.fromhex((VECTORS / "keys" / "issuer.seed").read_text().strip()))


def _bundle(name: str) -> ReceiptBundle:
    return ReceiptBundle.loads((VECTORS / "v14" / "valid" / f"{name}.bundle.json").read_bytes())


def test_a_compensated_receipt_names_the_id_its_writes_carried() -> None:
    undone = _bundle("order-compensated")
    receipt = undone.action_receipt
    assert receipt.outcome.status is OutcomeStatus.COMPENSATED
    assert receipt.coverage.measurement == "predicted"
    assert receipt.outcome.substrate_txid and receipt.outcome.substrate_txid.startswith("fhir:")
    assert verify_bundle(undone, issuer_key=ISSUER.public_key()).passed
    again = ActionReceipt.from_json(receipt.to_json())
    assert again == receipt


def test_compensated_is_of_an_admitted_plan_and_names_its_writes() -> None:
    receipt = _bundle("order-predicted").action_receipt
    with pytest.raises(MalformedReceiptError, match="cannot have been written"):
        replace(
            receipt,
            decision=replace(receipt.decision, admitted=False),
            outcome=Outcome(OutcomeStatus.COMPENSATED, "fhir:x"),
        )
    with pytest.raises(MalformedReceiptError, match="names no substrate_txid"):
        replace(receipt, outcome=Outcome(OutcomeStatus.COMPENSATED, None))
