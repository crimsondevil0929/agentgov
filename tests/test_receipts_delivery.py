"""ARC1 v1.1: delivery receipts, the attestation they carry, and their binding.

What these prove:

- an attestation verifies only under the relay key that signed it, over the
  request and the outcome it names, and an attestation of one outcome never
  verifies as another's;
- a delivery receipt is strict as every ARC1 document is, and cannot claim a
  place at or before the action receipt it follows from;
- a receipt log holds both kinds, resumes both, and accepts a delivery that
  names one of its own action receipts only when it binds that receipt's
  exact bytes;
- the verifier checks a delivery's signature, attestation, inclusion,
  witness and binding, each failure under its own exit code, and verifies an
  action receipt exactly as before.
"""

from __future__ import annotations

import io
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentgov.cli import main
from agentgov.exceptions import MalformedReceiptError, ReceiptLogError, ReceiptSignatureError
from agentgov.receipts import (
    ActionBinding,
    ActionReceipt,
    Attestation,
    AttestedOutcome,
    CheckpointPolicy,
    DeliveredRequest,
    Delivery,
    DeliveryReceipt,
    Ed25519Signer,
    FileWitness,
    ReceiptBundle,
    ReceiptLog,
    document_from_json,
    load_cosignatures,
    verify_bundle,
)
from agentgov.receipts.schema import Signature
from agentgov.receipts.verify import Failure

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
NEVER = CheckpointPolicy(every_receipts=10**6, every_seconds=10**9)
LOG_KEY = Ed25519Signer(bytes(range(32)))
RELAY = Ed25519Signer(bytes(range(96, 128)))
OTHER_RELAY = Ed25519Signer(bytes(range(128, 160)))
WITNESS_KEY = Ed25519Signer(bytes(range(32, 64)))
LOG_ID = "support-eu-1"
AT = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)


def template() -> ActionReceipt:
    receipt = ReceiptBundle.loads(
        (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
    ).receipt
    assert isinstance(receipt, ActionReceipt)
    return replace(receipt, signature=None)


REQUEST = DeliveredRequest(
    message_id="0b8f2b0e-8a0e-4d5c-9b1a-2f6e7c3d4a5b",
    effect_id="pay_refund",
    sink="payments",
    operation="refunds.create",
    payload_hash="a" * 64,
    idempotency_key="b" * 64,
)
DELIVERY = Delivery(
    attempt=2,
    status_code=200,
    response_digest="c" * 64,
    remote_ref="re_123",
    delivered_at=AT,
    log_seq=4,
    log_hash="d" * 64,
)


def attest(request: DeliveredRequest = REQUEST, delivery: Delivery = DELIVERY) -> Signature:
    signed = Attestation(request=request, outcome=delivery.outcome()).sign(RELAY)
    assert signed.signature is not None
    return signed.signature


def delivery_draft(committed: ActionReceipt, **changes: object) -> DeliveryReceipt:
    fields: dict[str, object] = {
        "receipt_id": "1d3f6e2a-7b8c-4d9e-a0f1-b2c3d4e5f607",
        "issued_at": AT + timedelta(seconds=1),
        "issuer": "interlock test",
        "action": ActionBinding.of(committed),
        "request": REQUEST,
        "delivery": DELIVERY,
        "attestation": attest(),
    }
    fields.update(changes)
    return DeliveryReceipt(**fields)  # type: ignore[arg-type]


def logged(tmp_path: Path) -> tuple[ReceiptLog, ActionReceipt, DeliveryReceipt]:
    witness = FileWitness(
        tmp_path / "cosignatures.jsonl",
        WITNESS_KEY,
        witness_id="w",
        logs={LOG_ID: LOG_KEY.public_key()},
    )
    log = ReceiptLog(
        LOG_ID, LOG_KEY, path=tmp_path / "receipts.jsonl", witnesses=[witness], policy=NEVER
    )
    action = log.issue(template())
    delivered = log.issue(delivery_draft(action))
    return log, action, delivered


# --------------------------------------------------------------------------
# the attestation
# --------------------------------------------------------------------------


def test_an_attestation_verifies_only_as_what_it_attests() -> None:
    signed = Attestation(request=REQUEST, outcome=DELIVERY.outcome()).sign(RELAY)
    signed.verify(RELAY.public_key())
    with pytest.raises(ReceiptSignatureError):
        signed.verify(OTHER_RELAY.public_key())
    for changed in (
        replace(signed, request=replace(REQUEST, payload_hash="e" * 64)),
        replace(signed, outcome=replace(signed.outcome, status_code=500)),
        replace(signed, outcome=replace(signed.outcome, result="unknown")),
        replace(signed, outcome=replace(signed.outcome, remote_ref="re_somebody_else")),
    ):
        with pytest.raises(ReceiptSignatureError, match="does not verify"):
            changed.verify(RELAY.public_key())
    assert Attestation.from_json(json.loads(json.dumps(signed.to_json()))) == signed


@pytest.mark.parametrize(
    ("change", "match"),
    [
        (lambda o: o.update(result="maybe"), "result is one of"),
        (lambda o: o.update(attempt=0), "between 1"),
        (lambda o: o.update(status_code=999), "HTTP status"),
        (lambda o: o.update(response_digest="not hex"), "SHA-256"),
        (lambda o: o.update(extra=1), "unknown field"),
    ],
)
def test_an_attestation_is_strict(change: object, match: str) -> None:
    document = Attestation(request=REQUEST, outcome=DELIVERY.outcome()).sign(RELAY).to_json()
    assert callable(change)
    change(document["outcome"])
    with pytest.raises(MalformedReceiptError, match=match):
        Attestation.from_json(document)


# --------------------------------------------------------------------------
# the delivery receipt
# --------------------------------------------------------------------------


def test_a_delivery_receipt_round_trips_and_carries_its_attestation(tmp_path: Path) -> None:
    log, action, delivered = logged(tmp_path)
    log.close()
    text = json.dumps(delivered.to_json())
    assert DeliveryReceipt.loads(text) == delivered
    assert document_from_json(json.loads(text)) == delivered
    assert document_from_json(action.to_json()) == action
    delivered.verify(LOG_KEY)
    delivered.attested().verify(RELAY.public_key())
    assert delivered.action.problem(action) is None


def test_a_delivery_cannot_precede_the_action_it_follows(tmp_path: Path) -> None:
    log, _, delivered = logged(tmp_path)
    log.close()
    with pytest.raises(MalformedReceiptError, match="delivered after it was committed"):
        delivered.with_log_anchor(LOG_ID, 0)
    document = delivered.to_json()
    document["anchors"]["log"]["leaf_index"] = 0
    with pytest.raises(MalformedReceiptError):
        DeliveryReceipt.from_json(document)
    with pytest.raises(MalformedReceiptError, match="signed action receipt"):
        ActionBinding.of(template())


def test_a_binding_names_one_receipt_exactly(tmp_path: Path) -> None:
    log, action, _ = logged(tmp_path)
    log.close()
    binding = ActionBinding.of(action)
    other = replace(action, receipt_id="ffffffff-0000-4000-8000-000000000000")
    assert "binds receipt" in str(binding.problem(other))
    moved = replace(binding, leaf_index=7)
    assert "binds leaf 7" in str(moved.problem(action))
    edited = replace(action, issuer="someone else")
    assert "a different or altered receipt" in str(binding.problem(edited))


# --------------------------------------------------------------------------
# the log
# --------------------------------------------------------------------------


def test_a_log_holds_and_resumes_both_kinds(tmp_path: Path) -> None:
    log, action, delivered = logged(tmp_path)
    log.publish()
    log.close()
    resumed = ReceiptLog(LOG_ID, LOG_KEY, path=tmp_path / "receipts.jsonl", policy=NEVER)
    try:
        assert resumed.receipts() == (action, delivered)
        assert resumed.deliveries() == (delivered,)
        assert resumed.index_of(delivered.receipt_id) == 1
    finally:
        resumed.close()


def test_a_log_takes_a_delivery_only_bound_to_its_own_action(tmp_path: Path) -> None:
    log, action, _ = logged(tmp_path)
    try:
        wrong = replace(ActionBinding.of(action), leaf_hash="0" * 64)
        with pytest.raises(ReceiptLogError, match="does not bind"):
            log.issue(delivery_draft(action, receipt_id=fresh(1), action=wrong))
        beyond = replace(ActionBinding.of(action), leaf_index=40)
        with pytest.raises(MalformedReceiptError, match="delivered after it was committed"):
            log.issue(delivery_draft(action, receipt_id=fresh(2), action=beyond))
        on_delivery = replace(ActionBinding.of(action), leaf_index=1)
        with pytest.raises(ReceiptLogError, match="not an action receipt"):
            log.issue(delivery_draft(action, receipt_id=fresh(3), action=on_delivery))
        # A delivery of an action in another log is the other log's to check.
        foreign = replace(ActionBinding.of(action), log_id="another-log")
        assert log.issue(delivery_draft(action, receipt_id=fresh(4), action=foreign))
        assert len(log) == 3
    finally:
        log.close()


def fresh(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


def test_a_resumed_log_refuses_an_unbound_delivery(tmp_path: Path) -> None:
    log, _, delivered = logged(tmp_path)
    log.close()
    path = tmp_path / "receipts.jsonl"
    lines = path.read_bytes().splitlines()
    forged = replace(
        delivered.with_log_anchor(LOG_ID, 1),
        action=replace(delivered.action, leaf_hash="0" * 64),
    ).sign(LOG_KEY)
    path.write_bytes(lines[0] + b"\n" + forged.canonical() + b"\n")
    with pytest.raises(ReceiptLogError, match="does not bind"):
        ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER)


# --------------------------------------------------------------------------
# the verifier
# --------------------------------------------------------------------------


def bundles(tmp_path: Path) -> tuple[ReceiptBundle, ReceiptBundle, Path]:
    log, _, _ = logged(tmp_path)
    try:
        checkpoint = log.publish()
        return log.bundle(0, checkpoint), log.bundle(1, checkpoint), tmp_path
    finally:
        log.close()


def statuses(report: object) -> dict[str, str]:
    return {c.name: c.status for c in report.checks}  # type: ignore[attr-defined]


def test_a_delivery_verifies_every_way_it_can(tmp_path: Path) -> None:
    action, delivered, work = bundles(tmp_path)
    report = verify_bundle(
        delivered,
        issuer_key=LOG_KEY.public_key(),
        cosignatures=load_cosignatures(work / "cosignatures.jsonl"),
        witness_key=WITNESS_KEY.public_key(),
        relay_keys=[OTHER_RELAY.public_key(), RELAY.public_key()],
        action=json.dumps(action.to_json()),
    )
    assert report.passed and report.exit_code == 0
    assert statuses(report) == {
        "ARC1 schema": "pass",
        "receipt signature": "pass",
        "relay attestation": "pass",
        "log inclusion": "pass",
        "witnessed": "pass",
        "action binding": "pass",
    }
    bare = verify_bundle(ReceiptBundle(delivered.receipt), issuer_key=LOG_KEY.public_key())
    assert bare.passed
    assert statuses(bare)["relay attestation"] == statuses(bare)["action binding"] == "skip"


def test_each_broken_delivery_fails_under_its_own_code(tmp_path: Path) -> None:
    action, delivered, _ = bundles(tmp_path)
    receipt = delivered.receipt
    assert isinstance(receipt, DeliveryReceipt)
    key = LOG_KEY.public_key()

    def code(bundle: ReceiptBundle, **kwargs: object) -> int:
        return verify_bundle(bundle, issuer_key=key, **kwargs).exit_code  # type: ignore[arg-type]

    unknown = code(delivered, relay_keys=[OTHER_RELAY.public_key()])
    assert unknown == Failure.ATTESTED
    forged = Attestation(request=REQUEST, outcome=DELIVERY.outcome()).sign(OTHER_RELAY)
    assert forged.signature is not None
    claimed = Signature(forged.signature.alg, RELAY.key_id, forged.signature.value)
    resigned = replace(receipt, signature=None, attestation=claimed).sign(LOG_KEY)
    assert code(ReceiptBundle(resigned), relay_keys=[RELAY.public_key()]) == Failure.ATTESTED
    rebound = replace(
        receipt, signature=None, action=replace(receipt.action, leaf_hash="0" * 64)
    ).sign(LOG_KEY)
    assert code(ReceiptBundle(rebound), action=action) == Failure.BINDING
    edited = replace(receipt, delivery=replace(receipt.delivery, status_code=503))
    assert code(ReceiptBundle(edited)) == Failure.SIGNATURE
    # An action bundle that holds something else, or a forged action receipt.
    assert code(delivered, action=delivered) == Failure.BINDING
    assert code(delivered, action=b"{not json") == Failure.MALFORMED
    tampered_action = action.receipt
    assert isinstance(tampered_action, ActionReceipt)
    tampered = replace(tampered_action, issuer="an impostor")
    assert code(delivered, action=ReceiptBundle(tampered)) == Failure.BINDING


def test_two_receipts_proven_against_two_roots_of_one_size_are_a_fork(tmp_path: Path) -> None:
    action, delivered, _ = bundles(tmp_path)
    assert action.checkpoint is not None
    forked_checkpoint = replace(action.checkpoint, root_hash="f" * 64).sign(LOG_KEY)
    fork = replace(action, checkpoint=forked_checkpoint)
    report = verify_bundle(delivered, issuer_key=LOG_KEY.public_key(), action=fork)
    assert report.exit_code == Failure.BINDING


def test_an_action_receipt_verifies_exactly_as_before() -> None:
    bundle = (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
    from agentgov.receipts import parse_key

    issuer = parse_key((VECTORS / "keys" / "issuer.pub").read_text())
    report = verify_bundle(bundle, issuer_key=issuer, relay_keys=[RELAY.public_key()])
    assert [c.name for c in report.checks] == [
        "ARC1 schema",
        "receipt signature",
        "log inclusion",
        "witnessed",
        "agentgov ledger",
        "disclosed rows",
    ]
    assert report.passed


def test_the_command_line_verifies_a_delivery() -> None:
    out = io.StringIO()
    root = VECTORS
    code = main(
        [
            "verify-receipt",
            str(root / "delivery" / "valid" / "refund-delivered.bundle.json"),
            "--pubkey",
            str(root / "keys" / "issuer.pub"),
            "--relay-key",
            str(root / "delivery" / "keys" / "relay.pub"),
            "--action",
            str(root / "delivery" / "valid" / "refund-call.bundle.json"),
        ],
        out=out,
    )
    assert code == 0, out.getvalue()
    assert "relay attestation" in out.getvalue() and "action binding" in out.getvalue()
    with pytest.raises(SystemExit):
        main(["verify-receipt", "--relay-key"], out=io.StringIO())
    missing = io.StringIO()
    assert main(["verify-receipt", "x.json", "--pubkey", "y", "--action", "nope.json"], out=missing)
    assert "error" in missing.getvalue()


def test_an_outcome_is_attested_whatever_it_was() -> None:
    for result in ("delivered", "retryable", "permanent", "unknown"):
        outcome = AttestedOutcome(attempt=1, result=result)
        Attestation(request=REQUEST, outcome=outcome).sign(RELAY).verify(RELAY.public_key())


def test_a_bundle_says_which_kind_it_holds(tmp_path: Path) -> None:
    action, delivered, _ = bundles(tmp_path)
    assert action.action_receipt.receipt_id == action.receipt.receipt_id
    assert delivered.delivery_receipt.receipt_id == delivered.receipt.receipt_id
    with pytest.raises(MalformedReceiptError, match="holds a delivery receipt"):
        _ = delivered.action_receipt
    with pytest.raises(MalformedReceiptError, match="holds an action receipt"):
        _ = action.delivery_receipt
    assert ReceiptBundle.loads(json.dumps(delivered.receipt.to_json())).receipt == delivered.receipt
