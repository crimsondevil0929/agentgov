"""Verify a receipt bundle, and say exactly what failed.

:func:`verify_bundle` runs every check the caller gave it the means for, in a
fixed order, and returns a :class:`VerificationReport`. Nothing here raises on
bad evidence: a receipt that does not verify is an answer, not an error. The
report's :attr:`~VerificationReport.exit_code` is the first failure's class,
which is what ``agentgov verify-receipt`` exits with:

=====  ==========  =====================================================
code   failure     meaning
=====  ==========  =====================================================
0      (none)      every requested check passed
3      MALFORMED   not a well-formed ARC1 document
4      SIGNATURE   the receipt's signature does not verify
5      INCLUSION   the checkpoint's signature or the audit path fails
6      WITNESS     the checkpoint is not witnessed, or was forked
7      LEDGER      the receipt disagrees with the AgentGov ledger
8      ROWS        a disclosed row is not one the receipt committed to
9      ATTESTED    a delivery's relay attestation does not verify
10     BINDING     a delivery does not follow from the action receipt given
=====  ==========  =====================================================

A delivery receipt (ARC1 v1.1) is checked for its schema, the log's
signature, its relay's attestation, inclusion and witness, and, given the
action receipt's bundle, the binding between the two.

(``2`` is reserved for usage errors, as with every ``argparse`` program.)
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import IntEnum
from typing import TYPE_CHECKING, Literal

from agentgov.exceptions import (
    AgentGovError,
    MalformedReceiptError,
    ReceiptSignatureError,
    RowDisclosureError,
    WitnessError,
)
from agentgov.receipts.merkle import verify_inclusion
from agentgov.receipts.rows import verify_disclosure
from agentgov.receipts.schema import (
    ActionReceipt,
    Cosignature,
    DeliveryReceipt,
    LogDocument,
    ReceiptBundle,
    RowDisclosure,
    instant,
    money_text,
)
from agentgov.receipts.signing import Verifier
from agentgov.receipts.witness import find_cosignature

if TYPE_CHECKING:
    from agentgov.core import BudgetManager

__all__ = ["Check", "Failure", "VerificationReport", "verify_bundle"]


class Failure(IntEnum):
    """What class of evidence failed. The value is the CLI's exit code."""

    MALFORMED = 3
    SIGNATURE = 4
    INCLUSION = 5
    WITNESS = 6
    LEDGER = 7
    ROWS = 8
    ATTESTED = 9
    BINDING = 10


Status = Literal["pass", "fail", "skip"]


@dataclass(frozen=True)
class Check:
    """One line of a verification report."""

    name: str
    status: Status
    detail: str
    failure: Failure | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "check": self.name,
            "status": self.status,
            "detail": self.detail,
            "failure": self.failure.name.lower() if self.failure else None,
        }


@dataclass(frozen=True)
class VerificationReport:
    """Every check that ran, and the receipt they ran on (if it decoded)."""

    checks: tuple[Check, ...]
    receipt: LogDocument | None

    @property
    def passed(self) -> bool:
        return all(check.status != "fail" for check in self.checks)

    @property
    def first_failure(self) -> Check | None:
        return next((check for check in self.checks if check.status == "fail"), None)

    @property
    def exit_code(self) -> int:
        failure = self.first_failure
        return int(failure.failure) if failure and failure.failure else 0

    def to_json(self) -> dict[str, object]:
        return {
            "receipt_id": self.receipt.receipt_id if self.receipt else None,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "checks": [check.to_json() for check in self.checks],
        }


def verify_bundle(
    bundle: ReceiptBundle | str | bytes,
    *,
    issuer_key: Verifier,
    log_key: Verifier | None = None,
    cosignatures: Sequence[Cosignature] | None = None,
    witness_key: Verifier | None = None,
    ledger: BudgetManager | None = None,
    rows: RowDisclosure | None = None,
    relay_keys: Iterable[Verifier] | None = None,
    action: ReceiptBundle | str | bytes | None = None,
) -> VerificationReport:
    """Verify a receipt bundle against the keys and records the caller trusts.

    :param bundle: A decoded bundle, or its JSON text.
    :param issuer_key: The key that must have signed the receipt.
    :param log_key: The key that must have signed the log checkpoint;
        ``issuer_key`` by default.
    :param cosignatures: A witness's published cosignatures. With
        ``witness_key``, the bundle's checkpoint must be among them.
    :param witness_key: The witness's key; required with ``cosignatures``.
    :param ledger: An AgentGov ledger the receipt's agentgov anchor and cost
        must agree with.
    :param rows: Disclosed rows that must be in the receipt's row commitment.
    :param relay_keys: For a delivery receipt: the relays' keys, one of which
        must have signed its attestation.
    :param action: For a delivery receipt: the bundle of the action receipt it
        follows from, which it must bind.
    """
    checks: list[Check] = []
    if isinstance(bundle, (str, bytes)):
        try:
            bundle = ReceiptBundle.loads(bundle)
        except MalformedReceiptError as exc:
            return VerificationReport(
                (Check("ARC1 schema", "fail", str(exc), Failure.MALFORMED),), None
            )
    receipt = bundle.receipt
    if isinstance(receipt, DeliveryReceipt):
        return _verify_delivery(
            bundle, receipt, issuer_key, log_key, cosignatures, witness_key, relay_keys, action
        )
    checks.append(
        Check(
            "ARC1 schema",
            "pass",
            f"receipt {receipt.receipt_id} ({receipt.outcome.status.value}, issued "
            f"{receipt.body()['issued_at']} by {receipt.issuer})",
        )
    )
    checks.append(_check_signature(receipt, issuer_key))
    checks.append(_check_inclusion(bundle, log_key or issuer_key))
    checks.append(_check_witness(bundle, cosignatures, witness_key))
    checks.append(_check_ledger(receipt, ledger))
    checks.append(_check_rows(receipt, rows))
    return VerificationReport(tuple(checks), receipt)


def _verify_delivery(
    bundle: ReceiptBundle,
    receipt: DeliveryReceipt,
    issuer_key: Verifier,
    log_key: Verifier | None,
    cosignatures: Sequence[Cosignature] | None,
    witness_key: Verifier | None,
    relay_keys: Iterable[Verifier] | None,
    action: ReceiptBundle | str | bytes | None,
) -> VerificationReport:
    delivery = receipt.delivery
    status = "no status" if delivery.status_code is None else f"HTTP {delivery.status_code}"
    checks = [
        Check(
            "ARC1 schema",
            "pass",
            f"delivery {receipt.receipt_id} of message {receipt.request.message_id} "
            f"(attempt {delivery.attempt}, {status}, delivered "
            f"{instant(delivery.delivered_at)}; issued by {receipt.issuer})",
        ),
        _check_signature(receipt, issuer_key),
        _check_attestation(receipt, relay_keys),
        _check_inclusion(bundle, log_key or issuer_key),
        _check_witness(bundle, cosignatures, witness_key),
        _check_binding(bundle, receipt, action, issuer_key, log_key),
    ]
    return VerificationReport(tuple(checks), receipt)


def _check_attestation(receipt: DeliveryReceipt, keys: Iterable[Verifier] | None) -> Check:
    name = "relay attestation"
    if keys is None:
        return Check(name, "skip", "no relay key given")
    claimed = receipt.attestation.key_id
    key = next((k for k in keys if k.key_id == claimed), None)
    if key is None:
        return Check(
            name,
            "fail",
            f"the attestation is signed by key {claimed}, which is none of the relay keys given",
            Failure.ATTESTED,
        )
    try:
        receipt.attested().verify(key)
    except ReceiptSignatureError as exc:
        return Check(name, "fail", str(exc), Failure.ATTESTED)
    return Check(
        name,
        "pass",
        f"the relay's {key.alg} key {key.key_id} attests {receipt.request.sink}."
        f"{receipt.request.operation} answered "
        + ("" if receipt.delivery.status_code is None else f"{receipt.delivery.status_code}"),
    )


def _check_binding(
    bundle: ReceiptBundle,
    receipt: DeliveryReceipt,
    action: ReceiptBundle | str | bytes | None,
    issuer_key: Verifier,
    log_key: Verifier | None,
) -> Check:
    name = "action binding"
    if action is None:
        return Check(name, "skip", "no action receipt given")
    if isinstance(action, (str, bytes)):
        try:
            action = ReceiptBundle.loads(action)
        except MalformedReceiptError as exc:
            return Check(name, "fail", f"the action bundle: {exc}", Failure.MALFORMED)
    committed = action.receipt
    if not isinstance(committed, ActionReceipt):
        return Check(name, "fail", "the action bundle holds no action receipt", Failure.BINDING)
    problem = receipt.action.problem(committed)
    if problem is not None:
        return Check(name, "fail", f"the delivery does not bind: {problem}", Failure.BINDING)
    signed = _check_signature(committed, issuer_key)
    if signed.status == "fail":
        return Check(name, "fail", f"the action receipt: {signed.detail}", Failure.BINDING)
    if action.checkpoint is not None:
        included = _check_inclusion(action, log_key or issuer_key)
        if included.status == "fail":
            return Check(name, "fail", f"the action receipt: {included.detail}", Failure.BINDING)
    if (
        bundle.checkpoint is not None
        and action.checkpoint is not None
        and bundle.checkpoint.log_id == action.checkpoint.log_id
        and bundle.checkpoint.tree_size == action.checkpoint.tree_size
        and bundle.checkpoint.root_hash != action.checkpoint.root_hash
    ):
        return Check(
            name,
            "fail",
            "the two receipts are proven against different roots of one log at one size: "
            "the log was forked",
            Failure.BINDING,
        )
    return Check(
        name,
        "pass",
        f"follows action receipt {committed.receipt_id} at leaf {receipt.action.leaf_index} "
        f"of log {receipt.action.log_id!r} (leaf hash {receipt.action.leaf_hash[:16]})",
    )


def _check_signature(receipt: LogDocument, key: Verifier) -> Check:
    try:
        receipt.verify(key)
    except ReceiptSignatureError as exc:
        return Check("receipt signature", "fail", str(exc), Failure.SIGNATURE)
    return Check("receipt signature", "pass", f"{key.alg}, key {key.key_id}")


def _check_inclusion(bundle: ReceiptBundle, log_key: Verifier) -> Check:
    name = "log inclusion"
    checkpoint, proof = bundle.checkpoint, bundle.inclusion
    if checkpoint is None or proof is None:
        return Check(name, "skip", "the bundle carries no checkpoint")
    try:
        checkpoint.verify(log_key)
    except ReceiptSignatureError as exc:
        return Check(name, "fail", str(exc), Failure.INCLUSION)
    anchor = bundle.receipt.anchors.log
    if anchor is None:
        return Check(name, "fail", "the receipt names no log position to prove", Failure.INCLUSION)
    if anchor.log_id != checkpoint.log_id or anchor.leaf_index != proof.leaf_index:
        return Check(
            name,
            "fail",
            f"the receipt says it is leaf {anchor.leaf_index} of log {anchor.log_id!r}; the "
            f"proof is for leaf {proof.leaf_index} of log {checkpoint.log_id!r}",
            Failure.INCLUSION,
        )
    if proof.tree_size != checkpoint.tree_size:
        return Check(
            name,
            "fail",
            f"the proof is for a tree of {proof.tree_size}; the checkpoint is at "
            f"{checkpoint.tree_size}",
            Failure.INCLUSION,
        )
    included = verify_inclusion(
        bundle.receipt.leaf_hash(),
        proof.leaf_index,
        proof.tree_size,
        proof.path_bytes(),
        bytes.fromhex(checkpoint.root_hash),
    )
    if not included:
        return Check(
            name,
            "fail",
            f"the audit path does not lead from this receipt at leaf {proof.leaf_index} to root "
            f"{checkpoint.root_hash[:16]}: the receipt, the path or the checkpoint was altered",
            Failure.INCLUSION,
        )
    return Check(
        name,
        "pass",
        f"leaf {proof.leaf_index} of {checkpoint.tree_size} in log {checkpoint.log_id!r} "
        f"(root {checkpoint.root_hash[:16]})",
    )


def _check_witness(
    bundle: ReceiptBundle, cosignatures: Sequence[Cosignature] | None, key: Verifier | None
) -> Check:
    name = "witnessed"
    if cosignatures is None:
        return Check(name, "skip", "no witness record given")
    if key is None:
        return Check(name, "fail", "a witness record needs the witness's key", Failure.WITNESS)
    if bundle.checkpoint is None:
        return Check(
            name, "fail", "the bundle carries no checkpoint to find a witness for", Failure.WITNESS
        )
    try:
        cosignature = find_cosignature(bundle.checkpoint, cosignatures, key)
    except WitnessError as exc:
        return Check(name, "fail", str(exc), Failure.WITNESS)
    return Check(
        name,
        "pass",
        f"by {cosignature.witness_id!r} (key {key.key_id}) at {cosignature.body()['witnessed_at']}",
    )


def _check_ledger(receipt: ActionReceipt, ledger: BudgetManager | None) -> Check:
    name = "agentgov ledger"
    if ledger is None:
        return Check(name, "skip", "no ledger given")
    anchor = receipt.anchors.agentgov
    if anchor is None:
        return Check(name, "fail", "the receipt carries no agentgov anchor", Failure.LEDGER)
    try:
        entries = ledger.audit_trail()
    except AgentGovError as exc:  # pragma: no cover - a verified ledger reads cleanly
        return Check(name, "fail", f"the ledger cannot be read: {exc}", Failure.LEDGER)
    from agentgov.core import GENESIS_HASH, EntryType

    if anchor.seq > len(entries):
        return Check(
            name,
            "fail",
            f"the receipt anchors to entry {anchor.seq}; the ledger has {len(entries)}",
            Failure.LEDGER,
        )
    head = entries[anchor.seq - 1].entry_hash if anchor.seq else GENESIS_HASH
    if head != anchor.head:
        return Check(
            name,
            "fail",
            f"ledger entry {anchor.seq} hashes to {head[:16]}; the receipt anchored to "
            f"{anchor.head[:16]}",
            Failure.LEDGER,
        )
    by_txn: dict[str, list[Decimal]] = defaultdict(list)
    for entry in entries[: anchor.seq]:
        spent = entry.amount if entry.entry_type is EntryType.SPEND else Decimal(0)
        by_txn[str(entry.transaction_id)].append(spent)
    missing = [txn for txn in receipt.cost.ledger_txn_ids if txn not in by_txn]
    if missing:
        return Check(
            name,
            "fail",
            f"transaction {missing[0]} is not in the ledger at or before entry {anchor.seq}",
            Failure.LEDGER,
        )
    settled = sum((sum(by_txn[txn], Decimal(0)) for txn in receipt.cost.ledger_txn_ids), Decimal(0))
    if settled != receipt.cost.settled_usd:
        return Check(
            name,
            "fail",
            f"the receipt's transactions settled ${money_text(settled)}; it claims "
            f"${money_text(receipt.cost.settled_usd)}",
            Failure.LEDGER,
        )
    return Check(
        name,
        "pass",
        f"anchored at entry {anchor.seq}; {len(receipt.cost.ledger_txn_ids)} settlement "
        f"transaction(s) totalling ${money_text(settled)}",
    )


def _check_rows(receipt: ActionReceipt, rows: RowDisclosure | None) -> Check:
    name = "disclosed rows"
    if rows is None:
        return Check(name, "skip", "no row disclosure given")
    try:
        verify_disclosure(rows, receipt)
    except RowDisclosureError as exc:
        return Check(name, "fail", str(exc), Failure.ROWS)
    return Check(
        name,
        "pass",
        f"{len(rows.rows)} of {receipt.effect.row_count} committed rows verify under "
        f"row_root {receipt.effect.row_root[:16]}",
    )
