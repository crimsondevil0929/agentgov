"""The verifier, against receipts of real executions.

A support agent refunds orders and is refused a prompt-injected, cross-tenant
wipe, against a real SQLite database, paying for its model calls through a
real AgentGov ledger (see ``receipt_scenarios``). Each receipt is issued into
a durable log and witnessed. Then every piece of evidence is tampered with,
one piece at a time, and the verifier must fail each one with the right
check and the right exit code, and pass the untouched originals.
"""

from __future__ import annotations

import io
import json
import sqlite3
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from agentgov import TokenUsage, pricing_for
from agentgov.cli import main
from agentgov.receipts import (
    ActionReceipt,
    ChainAnchor,
    Checkpoint,
    CheckpointPolicy,
    Cosignature,
    Ed25519Signer,
    Failure,
    FileWitness,
    HmacKey,
    InclusionProof,
    MerkleTree,
    OutcomeStatus,
    ReceiptBundle,
    ReceiptLog,
    RowDisclosure,
    VerificationReport,
    canonical_bytes,
    load_cosignatures,
    verify_bundle,
)
from agentgov.receipts.schema import Signature
from tests.receipt_scenarios import MODEL, Execution, SupportDesk

LOG_ID = "support-eu-1"
ISSUER = Ed25519Signer(bytes([7]) * 32)
WITNESS = Ed25519Signer(bytes([11]) * 32)
ATTACKER = Ed25519Signer(bytes([13]) * 32)
NEVER = CheckpointPolicy(every_receipts=10**6, every_seconds=10**9)


@dataclass
class World:
    """Three real executions, issued, logged and witnessed."""

    workdir: Path
    desk: SupportDesk
    log: ReceiptLog
    witness_path: Path
    refund: Execution
    wipe: Execution
    second_refund: Execution
    receipts: tuple[ActionReceipt, ...]

    def bundle(self, index: int) -> ReceiptBundle:
        return self.log.bundle(index)

    def cosignatures(self) -> tuple[Cosignature, ...]:
        return load_cosignatures(self.witness_path)

    def verify(
        self,
        bundle: ReceiptBundle | bytes,
        *,
        rows: RowDisclosure | None = None,
        witness: bool = True,
        ledger: bool = True,
    ) -> VerificationReport:
        return verify_bundle(
            bundle,
            issuer_key=ISSUER.public_key(),
            cosignatures=self.cosignatures() if witness else None,
            witness_key=WITNESS.public_key() if witness else None,
            ledger=self.desk.governor if ledger else None,
            rows=rows,
        )

    def issue(self, draft: ActionReceipt) -> ReceiptBundle:
        """Issue a (possibly lying) draft, under a fresh id, through the
        honest log, and witness it."""
        receipt = self.log.issue(replace(draft, receipt_id=str(uuid.uuid4())))
        self.log.publish()
        assert receipt.anchors.log is not None
        return self.log.bundle(receipt.anchors.log.leaf_index)


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    desk = SupportDesk(tmp_path)
    witness_path = tmp_path / "notary.jsonl"
    witness = FileWitness(
        witness_path,
        WITNESS,
        witness_id="notary-1",
        logs={LOG_ID: ISSUER.public_key()},
        fsync=False,
    )
    log = ReceiptLog(
        LOG_ID,
        ISSUER,
        path=tmp_path / "receipts.jsonl",
        witnesses=[witness],
        policy=NEVER,
        fsync=False,
    )
    refund = desk.refund(1040)
    wipe = desk.tenant_wipe()
    second = desk.refund(1044, reason="never delivered")
    receipts = tuple(log.issue(execution.draft) for execution in (refund, wipe, second))
    log.publish()
    try:
        yield World(tmp_path, desk, log, witness_path, refund, wipe, second, receipts)
    finally:
        log.close()
        desk.close()


def _names(report: VerificationReport) -> list[str]:
    return [check.name for check in report.checks]


# -- the untouched originals -------------------------------------------------


def test_a_committed_refund_verifies_end_to_end(world: World) -> None:
    receipt = world.receipts[0]
    disclosure = world.refund.commitment.disclose([0, 1, 2], receipt_id=receipt.receipt_id)
    report = world.verify(world.bundle(0), rows=disclosure)
    assert report.passed and report.exit_code == 0 and report.first_failure is None
    assert [c.status for c in report.checks] == ["pass"] * 6
    assert _names(report) == [
        "ARC1 schema",
        "receipt signature",
        "log inclusion",
        "witnessed",
        "agentgov ledger",
        "disclosed rows",
    ]
    # And the receipt says what really happened.
    assert receipt.outcome.status is OutcomeStatus.COMMITTED and receipt.decision.admitted
    assert receipt.effect.row_count == 3
    assert receipt.effect.summary.tables == ("order_audit", "orders", "refunds")
    assert receipt.effect.summary.tenants == ("acme",)
    assert (1040, "120.00", "refunded") in world.desk.orders()
    pricing = pricing_for(MODEL)
    expected = pricing.cost_of(TokenUsage(input_tokens=1840, output_tokens=212)) + pricing.cost_of(
        TokenUsage(input_tokens=2210, output_tokens=96)
    )
    assert receipt.cost.settled_usd == expected > 0
    assert len(receipt.cost.ledger_txn_ids) == 2


def test_a_refused_plan_is_receipted_and_changes_nothing(world: World) -> None:
    receipt = world.receipts[1]
    assert world.wipe.blocked_by == ("blast_radius", "tenant_isolation", "no_delete")
    assert receipt.outcome.status is OutcomeStatus.REFUSED and not receipt.decision.admitted
    # 12 order totals zeroed and 13 audit rows (one from the refund) deleted,
    # then all of it rolled back.
    assert receipt.effect.row_count == 25
    assert receipt.effect.summary.tenants == ("acme", "globex", "initech", "umbrella")
    assert [total for _, total, _ in world.desk.orders()] == [
        f"{120 + i * 30}.00" for i in range(12)
    ]
    deleted = [i for i, row in enumerate(world.wipe.commitment.rows) if row.op == "delete"]
    assert len(deleted) == 13
    disclosure = world.wipe.commitment.disclose(deleted[:2], receipt_id=receipt.receipt_id)
    assert all(row.row.after is None for row in disclosure.rows)
    report = world.verify(world.bundle(1), rows=disclosure)
    assert report.passed, report.to_json()


def test_the_verifier_accepts_json_text_and_bare_receipts(world: World) -> None:
    text = json.dumps(world.bundle(2).to_json())
    assert world.verify(text.encode()).passed
    bare = world.verify(canonical_bytes(world.receipts[2].to_json()), witness=False)
    assert bare.passed
    assert [c.status for c in bare.checks] == ["pass", "pass", "skip", "skip", "pass", "skip"]


def test_the_report_serializes(world: World) -> None:
    report = world.verify(world.bundle(0))
    doc: dict[str, Any] = json.loads(json.dumps(report.to_json()))  # plain JSON
    assert doc["receipt_id"] == world.receipts[0].receipt_id
    assert doc["passed"] is True and doc["exit_code"] == 0
    assert doc["checks"][0] == {
        "check": "ARC1 schema",
        "status": "pass",
        "detail": doc["checks"][0]["detail"],
        "failure": None,
    }
    assert doc["checks"][-1]["status"] == "skip"


# -- one piece of evidence tampered at a time --------------------------------

Tamper = Callable[[World], VerificationReport]


def _edited(world: World, index: int, edit: Callable[[dict[str, Any]], None]) -> bytes:
    doc = world.bundle(index).to_json()
    edit(doc)
    return json.dumps(doc).encode()


def _signature(document: ActionReceipt | Cosignature) -> Signature:
    assert document.signature is not None
    return document.signature


def field_edited(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["receipt"]["cost"]["settled_usd"] = "0.00000001"

    return world.verify(_edited(world, 0, edit))


def refusal_rewritten_as_a_commit(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["receipt"]["outcome"]["status"] = "committed"
        doc["receipt"]["decision"]["admitted"] = True

    return world.verify(_edited(world, 1, edit))


def row_root_swapped(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["receipt"]["effect"]["row_root"] = world.receipts[2].effect.row_root

    return world.verify(_edited(world, 0, edit))


def signed_position_edited(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["receipt"]["anchors"]["log"]["leaf_index"] = 2
        doc["inclusion"] = world.log.inclusion_proof(2).to_json()

    return world.verify(_edited(world, 0, edit))


def signature_bit_flipped(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        value = bytearray.fromhex(doc["receipt"]["sig"]["signature"])
        value[17] ^= 0x01
        doc["receipt"]["sig"]["signature"] = value.hex()

    return world.verify(_edited(world, 0, edit))


def resigned_by_another_key_claiming_the_issuers(world: World) -> VerificationReport:
    receipt = world.receipts[0]
    lowered = replace(receipt, cost=replace(receipt.cost, settled_usd=Decimal("0.00000001")))
    forged = lowered.sign(ATTACKER)
    claimed = replace(
        forged,
        signature=replace(_signature(forged), key_id=_signature(receipt).key_id),
    )
    return world.verify(replace(world.bundle(0), receipt=claimed))


def signed_by_a_key_the_verifier_does_not_trust(world: World) -> VerificationReport:
    return world.verify(replace(world.bundle(0), receipt=world.receipts[0].sign(ATTACKER)))


def alg_confusion(world: World) -> VerificationReport:
    # An HMAC keyed with the issuer's *public* key, claiming the issuer's key id.
    confused = world.receipts[0].sign(HmacKey(ISSUER.public_key().raw, key_id=ISSUER.key_id))
    return world.verify(replace(world.bundle(0), receipt=confused))


def audit_path_reordered(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        path = doc["inclusion"]["audit_path"]
        assert len(path) == 2
        path.reverse()

    return world.verify(_edited(world, 0, edit))


def audit_path_truncated(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["inclusion"]["audit_path"].pop()

    return world.verify(_edited(world, 0, edit))


def audit_path_padded(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["inclusion"]["audit_path"].append("00" * 32)

    return world.verify(_edited(world, 0, edit))


def proof_of_another_leaf(world: World) -> VerificationReport:
    return world.verify(replace(world.bundle(0), inclusion=world.log.inclusion_proof(1)))


def receipt_without_a_log_position(world: World) -> VerificationReport:
    receipt = world.receipts[0]
    unplaced = replace(receipt, anchors=replace(receipt.anchors, log=None)).sign(ISSUER)
    return world.verify(replace(world.bundle(0), receipt=unplaced))


def checkpoint_root_edited(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["checkpoint"]["root_hash"] = world.log.root(2)

    return world.verify(_edited(world, 0, edit))


def checkpoint_signed_by_another_key(world: World) -> VerificationReport:
    bundle = world.bundle(0)
    assert bundle.checkpoint is not None
    return world.verify(replace(bundle, checkpoint=bundle.checkpoint.sign(ATTACKER)))


def proof_for_another_tree_size(world: World) -> VerificationReport:
    bundle = world.bundle(0)
    return world.verify(replace(bundle, inclusion=world.log.inclusion_proof(0, 2)))


def leaves_reordered_by_the_operator(world: World) -> VerificationReport:
    """The log swaps receipts 0 and 1, signs the new root with its real key,
    and hands out a valid audit path to receipt 0's new position."""
    swapped = [world.receipts[1], world.receipts[0], world.receipts[2]]
    tree = MerkleTree(r.leaf_hash() for r in swapped)
    checkpoint = Checkpoint(LOG_ID, 3, tree.root().hex(), datetime.now(UTC)).sign(ISSUER)
    proof = InclusionProof(1, 3, tuple(p.hex() for p in tree.inclusion_proof(1)))
    return world.verify(
        ReceiptBundle(world.receipts[0], proof, checkpoint), witness=False, ledger=False
    )


def forked_log(world: World) -> VerificationReport:
    """The log shows this verifier a different receipt 1 (the wipe, rewritten
    as a small refund) under a root it signs with its real key. The proofs
    all check out; only the witness record shows the fork."""
    rewritten = replace(world.receipts[1], issuer="a quieter history").sign(ISSUER)
    leaves = [world.receipts[0], rewritten, world.receipts[2]]
    tree = MerkleTree(r.leaf_hash() for r in leaves)
    checkpoint = Checkpoint(LOG_ID, 3, tree.root().hex(), datetime.now(UTC)).sign(ISSUER)
    proof = InclusionProof(1, 3, tuple(p.hex() for p in tree.inclusion_proof(1)))
    return world.verify(ReceiptBundle(rewritten, proof, checkpoint))


def never_witnessed(world: World) -> VerificationReport:
    world.log.issue(replace(world.second_refund.draft, receipt_id=str(uuid.uuid4())))
    checkpoint = world.log.checkpoint()  # signed, but never published
    return world.verify(world.log.bundle(3, checkpoint))


def forged_cosignature(world: World) -> VerificationReport:
    bundle = world.bundle(0)
    assert bundle.checkpoint is not None
    world.witness_path.write_bytes(b"")
    forged = Cosignature(
        "notary-1",
        LOG_ID,
        bundle.checkpoint.tree_size,
        bundle.checkpoint.root_hash,
        datetime.now(UTC),
    ).sign(ATTACKER)
    claimed = replace(forged, signature=replace(_signature(forged), key_id=WITNESS.key_id))
    world.witness_path.write_bytes(canonical_bytes(claimed.to_json()) + b"\n")
    return world.verify(bundle)


def witness_record_without_a_checkpoint(world: World) -> VerificationReport:
    return world.verify(ReceiptBundle(world.receipts[0]))


def witness_record_without_its_key(world: World) -> VerificationReport:
    return verify_bundle(
        world.bundle(0),
        issuer_key=ISSUER.public_key(),
        cosignatures=world.cosignatures(),
    )


def cost_understated(world: World) -> VerificationReport:
    draft = world.refund.draft
    return world.verify(
        world.issue(replace(draft, cost=replace(draft.cost, settled_usd=Decimal("0.00001000"))))
    )


def cost_claims_a_transaction_the_ledger_never_saw(world: World) -> VerificationReport:
    draft = world.refund.draft
    ids = (*draft.cost.ledger_txn_ids, "00000000-0000-4000-8000-000000000000")
    return world.verify(world.issue(replace(draft, cost=replace(draft.cost, ledger_txn_ids=ids))))


def cost_claims_a_later_transaction(world: World) -> VerificationReport:
    """Receipt 0 anchors to the ledger before the second refund paid for its
    calls; claiming those calls is claiming something that had not happened."""
    draft = world.refund.draft
    later = world.second_refund.draft.cost
    cost = replace(
        draft.cost,
        ledger_txn_ids=(*draft.cost.ledger_txn_ids, *later.ledger_txn_ids),
        settled_usd=draft.cost.settled_usd + later.settled_usd,
    )
    return world.verify(world.issue(replace(draft, cost=cost)))


def anchored_past_the_ledgers_end(world: World) -> VerificationReport:
    draft = world.refund.draft
    assert draft.anchors.agentgov is not None
    anchor = ChainAnchor(seq=10_000, head=draft.anchors.agentgov.head)
    return world.verify(
        world.issue(replace(draft, anchors=replace(draft.anchors, agentgov=anchor)))
    )


def anchored_to_a_head_the_ledger_never_had(world: World) -> VerificationReport:
    draft = world.refund.draft
    assert draft.anchors.agentgov is not None
    anchor = replace(draft.anchors.agentgov, head="ab" * 32)
    return world.verify(
        world.issue(replace(draft, anchors=replace(draft.anchors, agentgov=anchor)))
    )


def no_ledger_anchor(world: World) -> VerificationReport:
    draft = world.refund.draft
    return world.verify(world.issue(replace(draft, anchors=replace(draft.anchors, agentgov=None))))


def _disclosure(world: World, edit: Callable[[dict[str, Any]], None]) -> RowDisclosure:
    receipt = world.receipts[0]
    doc = world.refund.commitment.disclose([0, 2], receipt_id=receipt.receipt_id).to_json()
    edit(doc)
    return RowDisclosure.from_json(doc)


def disclosed_value_edited(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        after = doc["rows"][0]["row"]["after"]
        after[next(iter(after))] = "edited"

    return world.verify(world.bundle(0), rows=_disclosure(world, edit))


def disclosed_salt_edited(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["rows"][1]["salt"] = "11" * 32

    return world.verify(world.bundle(0), rows=_disclosure(world, edit))


def disclosed_row_moved(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["rows"][1]["index"] = 1

    return world.verify(world.bundle(0), rows=_disclosure(world, edit))


def disclosed_row_path_edited(world: World) -> VerificationReport:
    def edit(doc: dict[str, Any]) -> None:
        doc["rows"][0]["audit_path"][0] = "22" * 32

    return world.verify(world.bundle(0), rows=_disclosure(world, edit))


def rows_of_another_receipt(world: World) -> VerificationReport:
    other = world.second_refund.commitment.disclose([0], receipt_id=world.receipts[2].receipt_id)
    return world.verify(world.bundle(0), rows=other)


def rows_relabelled_for_this_receipt(world: World) -> VerificationReport:
    other = world.second_refund.commitment.disclose([0], receipt_id=world.receipts[0].receipt_id)
    return world.verify(world.bundle(0), rows=other)


TAMPERS: list[tuple[Tamper, Failure, str]] = [
    (field_edited, Failure.SIGNATURE, "does not verify"),
    (refusal_rewritten_as_a_commit, Failure.SIGNATURE, "does not verify"),
    (row_root_swapped, Failure.SIGNATURE, "does not verify"),
    (signed_position_edited, Failure.SIGNATURE, "does not verify"),
    (signature_bit_flipped, Failure.SIGNATURE, "does not verify"),
    (resigned_by_another_key_claiming_the_issuers, Failure.SIGNATURE, "does not verify"),
    (signed_by_a_key_the_verifier_does_not_trust, Failure.SIGNATURE, "key"),
    (alg_confusion, Failure.SIGNATURE, "hmac-sha256"),
    (audit_path_reordered, Failure.INCLUSION, "audit path does not lead"),
    (audit_path_truncated, Failure.INCLUSION, "audit path does not lead"),
    (audit_path_padded, Failure.INCLUSION, "audit path does not lead"),
    (proof_of_another_leaf, Failure.INCLUSION, "the proof is for leaf 1"),
    (receipt_without_a_log_position, Failure.INCLUSION, "names no log position"),
    (checkpoint_root_edited, Failure.INCLUSION, "does not verify"),
    (checkpoint_signed_by_another_key, Failure.INCLUSION, "key"),
    (proof_for_another_tree_size, Failure.INCLUSION, "a tree of 2"),
    (leaves_reordered_by_the_operator, Failure.INCLUSION, "the proof is for leaf 1"),
    (forked_log, Failure.WITNESS, "split view"),
    (never_witnessed, Failure.WITNESS, "never witnessed"),
    (forged_cosignature, Failure.WITNESS, "never witnessed"),
    (witness_record_without_a_checkpoint, Failure.WITNESS, "no checkpoint"),
    (witness_record_without_its_key, Failure.WITNESS, "needs the witness's key"),
    (cost_understated, Failure.LEDGER, "it claims $0.00001000"),
    (cost_claims_a_transaction_the_ledger_never_saw, Failure.LEDGER, "00000000-0000-4000"),
    (cost_claims_a_later_transaction, Failure.LEDGER, "at or before entry"),
    (anchored_past_the_ledgers_end, Failure.LEDGER, "entry 10000"),
    (anchored_to_a_head_the_ledger_never_had, Failure.LEDGER, "anchored to abababab"),
    (no_ledger_anchor, Failure.LEDGER, "no agentgov anchor"),
    (disclosed_value_edited, Failure.ROWS, "were altered"),
    (disclosed_salt_edited, Failure.ROWS, "were altered"),
    (disclosed_row_moved, Failure.ROWS, "were altered"),
    (disclosed_row_path_edited, Failure.ROWS, "were altered"),
    (rows_of_another_receipt, Failure.ROWS, "the disclosure is for receipt"),
    (rows_relabelled_for_this_receipt, Failure.ROWS, "commitment of 3 rows"),
]


@pytest.mark.parametrize(
    ("tamper", "failure", "detail"), TAMPERS, ids=[t.__name__ for t, _, _ in TAMPERS]
)
def test_each_tamper_fails_exactly_the_check_it_should(
    world: World, tamper: Tamper, failure: Failure, detail: str
) -> None:
    report = tamper(world)
    first = report.first_failure
    assert first is not None, report.to_json()
    assert (first.failure, report.exit_code) == (failure, int(failure)), report.to_json()
    assert detail in first.detail, first.detail
    # Everything before the first failure passed or was not asked for: the
    # evidence that failed is the evidence that was touched.
    before = report.checks[: report.checks.index(first)]
    assert all(check.status in ("pass", "skip") for check in before), report.to_json()


def test_the_honest_ledger_money_is_what_the_understated_receipt_hides(world: World) -> None:
    report = cost_understated(world)
    first = report.first_failure
    assert first is not None
    assert f"settled ${world.refund.draft.cost.settled_usd:.8f}" in first.detail
    assert "it claims $0.00001000" in first.detail


def test_the_first_failure_in_order_decides_the_exit_code(world: World) -> None:
    def edit(doc: dict[str, Any]) -> None:
        doc["receipt"]["cost"]["settled_usd"] = "0.00000001"
        doc["inclusion"]["audit_path"].reverse()

    bad_rows = world.second_refund.commitment.disclose([0], receipt_id=world.receipts[2].receipt_id)
    report = world.verify(_edited(world, 0, edit), rows=bad_rows)
    assert report.exit_code == Failure.SIGNATURE
    # The edited cost disagrees with the ledger too; the order still decides.
    assert [c.status for c in report.checks] == ["pass", "fail", "fail", "pass", "fail", "fail"]


def test_malformed_evidence_is_exit_3_and_nothing_else_runs(world: World) -> None:
    def edit(doc: dict[str, Any]) -> None:
        doc["receipt"]["effect"]["confidence"] = "high"

    report = world.verify(_edited(world, 0, edit))
    assert report.exit_code == Failure.MALFORMED and report.receipt is None
    assert _names(report) == ["ARC1 schema"]
    assert "confidence" in report.checks[0].detail
    doubled = world.verify(b'{"v":"ARC1-bundle","v":"ARC1-bundle"}')
    assert doubled.exit_code == Failure.MALFORMED


def test_a_lone_edit_that_breaks_the_receipts_own_rules_is_malformed(world: World) -> None:
    def edit(doc: dict[str, Any]) -> None:
        doc["receipt"]["outcome"]["status"] = "committed"  # while admitted is false

    report = world.verify(_edited(world, 1, edit))
    assert report.exit_code == Failure.MALFORMED


# -- the command line --------------------------------------------------------


@dataclass
class Files:
    bundle: Path
    rows: Path
    issuer: Path
    witness_key: Path
    witness: Path
    ledger: Path


def _files(world: World, bundle: ReceiptBundle | None = None) -> Files:
    work = world.workdir
    (work / "bundle.json").write_text(json.dumps((bundle or world.bundle(0)).to_json()))
    disclosure = world.refund.commitment.disclose([1], receipt_id=world.receipts[0].receipt_id)
    (work / "rows.json").write_text(json.dumps(disclosure.to_json()))
    (work / "issuer.pub").write_text(ISSUER.public_key().spec() + "\n")
    (work / "witness.pub").write_text(WITNESS.public_key().spec() + "\n")
    return Files(
        work / "bundle.json",
        work / "rows.json",
        work / "issuer.pub",
        work / "witness.pub",
        world.witness_path,
        world.desk.ledger_path,
    )


def _cli(*args: object) -> tuple[int, str]:
    out = io.StringIO()
    code = main(["verify-receipt", *map(str, args)], out=out)
    return code, out.getvalue()


def _full(files: Files) -> list[object]:
    return [
        files.bundle,
        "--pubkey",
        files.issuer,
        "--witness",
        files.witness,
        "--witness-pubkey",
        files.witness_key,
        "--ledger",
        files.ledger,
        "--rows",
        files.rows,
    ]


def test_cli_passes_a_real_receipt_against_the_live_ledger(world: World) -> None:
    files = _files(world)
    code, out = _cli(*_full(files))
    assert code == 0, out
    lines = out.splitlines()
    assert [line.split()[0] for line in lines[:6]] == ["ok"] * 6
    assert "agentgov ledger" in lines[4] and "2 settlement transaction(s)" in lines[4]
    assert lines[-1] == f"PASS  {files.bundle}  (receipt {world.receipts[0].receipt_id})"


def test_cli_json_report(world: World) -> None:
    files = _files(world)
    code, out = _cli(*_full(files), "--json")
    doc = json.loads(out)
    assert code == 0 and doc["passed"] and doc["exit_code"] == 0
    assert [c["status"] for c in doc["checks"]] == ["pass"] * 6


def test_cli_names_the_failure_and_exits_with_its_code(world: World) -> None:
    receipt = world.receipts[0]
    forged = replace(receipt, cost=replace(receipt.cost, settled_usd=Decimal(1))).sign(ATTACKER)
    files = _files(world, replace(world.bundle(0), receipt=forged))
    code, out = _cli(*_full(files))
    assert code == 4
    assert "  FAIL  receipt signature" in out
    assert out.splitlines()[-1] == (f"FAIL  {files.bundle}  (receipt signature: exit 4 SIGNATURE)")


def test_cli_accepts_keys_inline(world: World) -> None:
    files = _files(world)
    code, _ = _cli(files.bundle, "--pubkey", ISSUER.public_key().spec())
    assert code == 0


def test_cli_checks_the_log_key_separately_when_given(world: World, tmp_path: Path) -> None:
    log_key = Ed25519Signer(bytes([17]) * 32)
    with ReceiptLog("separate-log", log_key, policy=NEVER) as separate:
        index = separate.append(world.refund.draft.with_log_anchor("separate-log", 0).sign(ISSUER))
        bundle = separate.bundle(index)
    files = _files(world, bundle)
    assert _cli(files.bundle, "--pubkey", files.issuer)[0] == 5
    code, out = _cli(
        files.bundle, "--pubkey", files.issuer, "--log-pubkey", log_key.public_key().spec()
    )
    assert code == 0, out


@pytest.mark.parametrize(
    "args",
    [
        ["{bundle}.missing", "--pubkey", "{issuer}"],
        ["{bundle}", "--pubkey", "{issuer}.missing"],
        ["{bundle}", "--pubkey", "ed25519:abcd"],
        ["{bundle}", "--pubkey", "rsa:00"],
        ["{bundle}", "--pubkey", "{issuer}", "--witness", "{witness}"],
        ["{bundle}", "--pubkey", "{issuer}", "--ledger", "{ledger}.missing"],
        ["{bundle}", "--pubkey", "{issuer}", "--rows", "{rows}.missing"],
        [
            "{bundle}",
            "--pubkey",
            "{issuer}",
            "--witness",
            "{witness}.missing",
            "--witness-pubkey",
            "{witness_key}",
        ],
    ],
    ids=[
        "missing-bundle",
        "missing-key-file",
        "short-key",
        "unknown-alg",
        "witness-without-key",
        "missing-ledger",
        "missing-rows",
        "missing-witness-record",
    ],
)
def test_cli_usage_and_io_errors_exit_2(world: World, args: list[str]) -> None:
    files = _files(world)
    paths = {name: str(getattr(files, name)) for name in files.__dataclass_fields__}
    code, out = _cli(*(arg.format(**paths) for arg in args))
    assert code == 2 and out.startswith("error: "), out


def test_cli_an_unreadable_witness_record_fails_in_the_witness_slot(world: World) -> None:
    files = _files(world)
    files.witness.write_bytes(b'{"v":"ARC1-cosignature"}\n')
    code, out = _cli(*_full(files), "--json")
    doc = json.loads(out)
    assert code == 3
    assert [c["check"] for c in doc["checks"]][3] == "witnessed"
    assert doc["checks"][3]["failure"] == "malformed"
    assert [c["status"] for c in doc["checks"]] == ["pass", "pass", "pass", "fail", "pass", "pass"]


def test_cli_an_unreadable_disclosure_does_not_hide_a_forged_signature(world: World) -> None:
    receipt = world.receipts[0]
    files = _files(world, replace(world.bundle(0), receipt=receipt.sign(ATTACKER)))
    files.rows.write_text("{not json")
    code, out = _cli(*_full(files), "--json")
    doc = json.loads(out)
    assert code == 4, "the forged signature comes first in the order"
    assert doc["checks"][5]["check"] == "disclosed rows"
    assert doc["checks"][5]["failure"] == "malformed"


def test_cli_a_malformed_bundle_still_reports_the_unreadable_inputs(world: World) -> None:
    files = _files(world)
    files.bundle.write_text('{"v": "ARC1-bundle"}')
    files.rows.write_text("[]")
    code, out = _cli(*_full(files), "--json")
    doc = json.loads(out)
    assert code == 3
    assert [c["check"] for c in doc["checks"]] == ["ARC1 schema", "disclosed rows"]


def test_cli_an_edited_ledger_fails_the_ledger_check(world: World) -> None:
    files = _files(world)
    world.log.close()
    world.desk.close()
    conn = sqlite3.connect(files.ledger)
    with conn:
        conn.execute("UPDATE entries SET amount = '0.00000001' WHERE entry_type = 'spend'")
    conn.close()
    code, out = _cli(*_full(files))
    assert code == 7, out
    assert "FAIL  agentgov ledger    the ledger does not verify" in out


def test_cli_a_file_that_is_not_a_ledger_fails_the_ledger_check(world: World) -> None:
    files = _files(world)
    not_a_ledger = world.workdir / "notes.db"
    not_a_ledger.write_bytes(b"these are not the entries you are looking for" * 40)
    args = _full(files)
    args[args.index("--ledger") + 1] = not_a_ledger
    code, out = _cli(*args)
    assert code == 7, out
