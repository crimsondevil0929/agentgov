"""ARC1 1.2: digest-then-sign, and a log that outlives its key.

Signature version 2 signs ``domain_v2 || SHA-512(canonical document)``: a
message under 100 bytes whatever the receipt's size, so a key service with a
message limit (AWS KMS: 4096 bytes) signs any receipt. The version is in the
signed header, so a signature cannot be passed off as the other version.
Version 1 is unchanged.

A key transition, signed by a log's outgoing key, hands the log to its
incoming key at a tree size: leaves from that index, and checkpoints larger
than that size, are the incoming key's. A log reopens under its schedule,
holding each signature to the key in force for its position, and a verifier
that trusts only the first key follows the transitions to the current one.
"""

from __future__ import annotations

import hashlib
import io
import threading
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agentgov.cli import main
from agentgov.exceptions import (
    MalformedReceiptError,
    ReceiptLogError,
    ReceiptSignatureError,
    SignerUnavailableError,
)
from agentgov.receipts import (
    ActionReceipt,
    Checkpoint,
    CheckpointPolicy,
    Cosignature,
    Ed25519Signer,
    FileWitness,
    HmacKey,
    Keyring,
    KeySchedule,
    KeyTransition,
    ReceiptBundle,
    ReceiptLog,
    Verifier,
    canonical_bytes,
    loads_strict,
    verify_bundle,
)
from agentgov.receipts.schema import Signature

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
TEMPLATE = ReceiptBundle.loads(
    (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
).action_receipt
LOG_ID = "support-eu-1"
A = Ed25519Signer(bytes(range(32)))
B = Ed25519Signer(bytes(range(100, 132)))
C = Ed25519Signer(bytes(range(200, 232)))
WITNESS = Ed25519Signer(bytes(range(32, 64)))
INLINE = CheckpointPolicy(every_receipts=10**6, every_seconds=10**9, background=False)
WHEN = datetime(2026, 10, 11, 12, tzinfo=UTC)


def draft(n: int) -> ActionReceipt:
    return replace(
        TEMPLATE,
        receipt_id=str(uuid.UUID(int=n + 1)),
        anchors=replace(TEMPLATE.anchors, log=None),
        signature=None,
    )


def big_draft(n: int) -> ActionReceipt:
    """A receipt whose canonical form is over 4096 bytes."""
    gaps = tuple(sorted(f"gap {i:02d}: " + "unobserved side effect " * 18 for i in range(10)))
    receipt = replace(draft(n), coverage=replace(TEMPLATE.coverage, known_gaps=gaps))
    assert len(receipt.canonical()) > 4096
    return receipt


class Limited:
    """A key service that signs messages of at most 4096 bytes, as AWS KMS
    does, and prefers signature version 2."""

    signature_version = 2

    def __init__(self, inner: Ed25519Signer) -> None:
        self.inner = inner
        self.longest = 0

    @property
    def alg(self) -> str:
        return self.inner.alg

    @property
    def key_id(self) -> str:
        return self.inner.key_id

    def public_key(self) -> Verifier:
        return self.inner.public_key()

    def sign(self, message: bytes) -> bytes:
        self.longest = max(self.longest, len(message))
        if len(message) > 4096:
            raise SignerUnavailableError(f"a {len(message)}-byte message is over the limit")
        return self.inner.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self.inner.verify(message, signature)


# -- signature version 2 ---------------------------------------------------------


def test_a_version_2_signature_covers_a_digest_and_names_its_version() -> None:
    receipt = draft(0).with_log_anchor(LOG_ID, 0)
    signed = receipt.sign(A, version=2)
    assert signed.signature is not None and signed.signature.version == 2
    assert signed.to_json()["sig"]["sv"] == 2
    message = receipt.signing_input(A.alg, A.key_id, 2)
    header = {"alg": A.alg, "key_id": A.key_id, "sv": 2}
    digest = hashlib.sha512(canonical_bytes({**receipt.body(), "sig": header})).digest()
    assert message == b"ARC1/receipt/v2\n" + digest and len(message) < 100
    signed.verify(A.public_key())
    again = ActionReceipt.loads(signed.canonical())
    assert again == signed
    again.verify(A.public_key())
    v1 = receipt.sign(A)
    assert v1.signature is not None and v1.signature.version == 1
    assert "sv" not in v1.to_json()["sig"], "a version 1 signature is as it always was"


def test_a_signature_cannot_pass_as_the_other_version() -> None:
    signed = draft(0).with_log_anchor(LOG_ID, 0).sign(A, version=2)
    assert signed.signature is not None
    stripped = replace(signed, signature=replace(signed.signature, version=1))
    with pytest.raises(ReceiptSignatureError, match="does not verify"):
        stripped.verify(A.public_key())
    document = signed.to_json()
    for bad in (3, 1, True, "2"):
        document["sig"]["sv"] = bad
        with pytest.raises(MalformedReceiptError, match="sv must be 2"):
            ActionReceipt.from_json(loads_strict(canonical_bytes(document)))


def test_every_signed_document_signs_and_verifies_at_version_2() -> None:
    checkpoint = Checkpoint(LOG_ID, 3, "ab" * 32, WHEN).sign(A, version=2)
    cosignature = Cosignature("w", LOG_ID, 3, "ab" * 32, WHEN).sign(WITNESS, version=2)
    transition = KeyTransition.of(LOG_ID, 3, B.public_key(), WHEN).sign(A, version=2)
    for document, key in ((checkpoint, A), (cosignature, WITNESS), (transition, A)):
        decoded = type(document).from_json(loads_strict(canonical_bytes(document.to_json())))
        assert decoded == document
        decoded.verify(key.public_key())
        assert decoded.signature is not None and decoded.signature.version == 2


def test_a_signer_that_prefers_version_2_gets_it() -> None:
    limited = Limited(A)
    signed = draft(0).with_log_anchor(LOG_ID, 0).sign(limited)
    assert signed.signature is not None and signed.signature.version == 2
    asked = draft(1).with_log_anchor(LOG_ID, 1).sign(limited, version=1)
    assert asked.signature is not None and asked.signature.version == 1
    with pytest.raises(ValueError, match="signature version 3"):
        draft(2).sign(A, version=3)


def test_a_receipt_over_a_key_services_limit_signs_at_version_2(tmp_path: Path) -> None:
    limited = Limited(A)
    with ReceiptLog(LOG_ID, limited, path=tmp_path / "r.jsonl", policy=INLINE) as log:
        receipt = log.issue(big_draft(0))
        bundle = log.bundle(0)
    assert limited.longest < 100
    assert receipt.signature is not None and receipt.signature.version == 2
    assert bundle.checkpoint is not None and bundle.checkpoint.signature is not None
    assert bundle.checkpoint.signature.version == 2
    assert verify_bundle(bundle, issuer_key=A.public_key()).passed
    with pytest.raises(SignerUnavailableError, match="over the limit"):
        big_draft(1).with_log_anchor(LOG_ID, 1).sign(limited, version=1)
    with ReceiptLog(LOG_ID, A, path=tmp_path / "r.jsonl", policy=INLINE) as reopened:
        assert reopened.receipts() == (receipt,)


def test_a_log_and_a_witness_sign_at_the_version_asked(tmp_path: Path) -> None:
    witness = FileWitness(
        tmp_path / "w.jsonl",
        WITNESS,
        witness_id="w",
        logs={LOG_ID: A.public_key()},
        signature_version=2,
    )
    with ReceiptLog(LOG_ID, A, witnesses=[witness], policy=INLINE, signature_version=2) as log:
        receipt = log.issue(draft(0))
        checkpoint = log.publish()
    latest = witness.latest(LOG_ID)
    for signed in (receipt, checkpoint, latest):
        assert signed is not None and signed.signature is not None
        assert signed.signature.version == 2
    with pytest.raises(ValueError, match="signature version 7"):
        ReceiptLog(LOG_ID, A, signature_version=7)


# -- key transitions -------------------------------------------------------------


def _rotated(path: Path, *, before: int = 3, after: int = 2) -> tuple[ReceiptLog, KeyTransition]:
    log = ReceiptLog(LOG_ID, A, path=path, policy=INLINE)
    for n in range(before):
        log.issue(draft(n))
    transition = log.rotate(B)
    for n in range(before, before + after):
        log.issue(draft(n))
    log.publish()
    return log, transition


def test_rotate_hands_the_log_to_the_incoming_key(tmp_path: Path) -> None:
    log, transition = _rotated(tmp_path / "r.jsonl")
    with log:
        assert transition.tree_size == 3 and transition.incoming_key_id == B.key_id
        assert transition.signature is not None and transition.signature.key_id == A.key_id
        transition.verify(A.public_key())
        assert log.transitions() == (transition,)
        signers = [r.signature.key_id for r in log.receipts() if r.signature is not None]
        assert signers == [A.key_id] * 3 + [B.key_id] * 2
        checkpoints = [(c.tree_size, c.signature.key_id) for c in log.checkpoints() if c.signature]
        assert checkpoints == [(3, A.key_id), (5, B.key_id)], "A sealed its era at size 3"
        schedule = log.schedule
        assert schedule is not None and schedule.current.key_id == B.key_id
        assert (schedule.for_leaf(2).key_id, schedule.for_leaf(3).key_id) == (A.key_id, B.key_id)
        assert schedule.for_checkpoint(3).key_id == A.key_id
        assert schedule.for_checkpoint(4).key_id == B.key_id
    lines = (tmp_path / "r.jsonl.transitions").read_bytes().splitlines()
    assert [KeyTransition.loads(line) for line in lines] == [transition]


def test_a_rotated_log_reopens_under_its_schedule_and_only_with_its_key(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    _rotated(path)[0].close()
    with ReceiptLog(LOG_ID, B, path=path, keyring=[A.public_key()], policy=INLINE) as log:
        assert len(log) == 5
        log.issue(draft(5))
    with pytest.raises(ReceiptLogError, match=f"signed by key {B.key_id} since size 3"):
        ReceiptLog(LOG_ID, A, path=path, policy=INLINE)
    with pytest.raises(ReceiptLogError, match=f"signed by key {A.key_id}, which is not among"):
        ReceiptLog(LOG_ID, B, path=path, policy=INLINE)  # trusts B alone: cannot follow A to B


def test_a_log_reopens_with_nothing_issued_since_its_rotation(tmp_path: Path) -> None:
    """A transition at exactly the log's size hands over the leaves still to
    come: the log reopens, and the incoming key signs the next one."""
    path = tmp_path / "r.jsonl"
    _rotated(path, after=0)[0].close()
    with ReceiptLog(LOG_ID, B, path=path, keyring=[A.public_key()], policy=INLINE) as log:
        assert len(log) == 3 and log.transitions()[-1].tree_size == 3
        assert log.issue(draft(3)).signature.key_id == B.key_id  # type: ignore[union-attr]


def test_a_log_handed_on_twice_learns_the_key_between_from_its_transitions(
    tmp_path: Path,
) -> None:
    """Reopened trusting the first key and holding the key in force, the log
    learns the key in between from the transitions, and checks that era
    under it."""
    path = tmp_path / "r.jsonl"
    log, _ = _rotated(path, after=1)
    log.rotate(C)
    log.issue(draft(4))
    log.close()
    with ReceiptLog(LOG_ID, C, path=path, keyring=[A.public_key()], policy=INLINE) as log:
        assert [k for k in (A.key_id, B.key_id, C.key_id) if k in log.keyring] == [
            A.key_id,
            B.key_id,
            C.key_id,
        ]
        bundle = log.bundle(3)  # B's era
    assert bundle.receipt.signature is not None and bundle.receipt.signature.key_id == B.key_id
    assert verify_bundle(bundle, issuer_key=log.keyring).passed


def test_a_reopened_log_holds_each_signature_to_its_era(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    _rotated(path)[0].close()
    checkpoints = path.with_name("r.jsonl.checkpoints")
    with ReceiptLog(LOG_ID, B, path=path, keyring=[A.public_key()], policy=INLINE) as log:
        root = log.root(5)
    forged = Checkpoint(LOG_ID, 5, root, WHEN).sign(A)  # the old key, past its era
    checkpoints.write_bytes(checkpoints.read_bytes() + canonical_bytes(forged.to_json()) + b"\n")
    with pytest.raises(ReceiptLogError, match=f"signed by key {A.key_id}, not by the key given"):
        ReceiptLog(LOG_ID, B, path=path, keyring=[A.public_key()], policy=INLINE)


def test_a_receipt_of_the_new_era_signed_by_the_old_key_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    _rotated(path, after=0)[0].close()
    # The old key signs a receipt for position 3, past its era, and it is
    # appended after the last checkpoint, where only its signature vouches.
    forged = draft(9).with_log_anchor(LOG_ID, 3).sign(A)
    path.write_bytes(path.read_bytes() + forged.canonical() + b"\n")
    with pytest.raises(ReceiptLogError, match=r"line 4: .*the log was edited"):
        ReceiptLog(LOG_ID, B, path=path, keyring=[A.public_key()], policy=INLINE)


def test_a_verifier_trusting_the_first_key_follows_the_transitions(tmp_path: Path) -> None:
    log, transition = _rotated(tmp_path / "r.jsonl")
    with log:
        early, late = log.bundle(1), log.bundle(4)
    for bundle in (early, late):
        report = verify_bundle(bundle, issuer_key=A.public_key(), transitions=[transition])
        assert report.passed, report.to_json()
        assert report.checks[1].name == "key transitions"
    unfollowed = verify_bundle(late, issuer_key=A.public_key())
    assert unfollowed.exit_code == 4
    forged = KeyTransition.of(LOG_ID, 3, C.public_key(), WHEN).sign(C)
    report = verify_bundle(late, issuer_key=A.public_key(), transitions=[forged])
    assert report.exit_code == 4 and report.first_failure is not None
    assert report.first_failure.name == "key transitions"
    # B, in force, hands the log on to C at size 4: leaf 4 and the checkpoint
    # at 5 are C's to sign from then on, and B's signatures of them no longer
    # count. (Whoever holds the key in force can hand the log on: what catches
    # a stolen key is a witness that saw the log go another way.)
    handed_on = KeyTransition.of(LOG_ID, 4, C.public_key(), WHEN).sign(B)
    chain = [transition, handed_on]
    report = verify_bundle(late, issuer_key=A.public_key(), transitions=chain)
    assert report.exit_code == 4 and report.first_failure is not None
    assert report.first_failure.name == "receipt signature"
    report = verify_bundle(early, issuer_key=A.public_key(), transitions=chain)
    assert report.exit_code == 5, "leaf 1 is A's, but the checkpoint at 5 is C's, not B's"


def test_the_cli_follows_a_logs_transitions(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    log, _ = _rotated(path)
    with log:
        bundle = tmp_path / "late.json"
        bundle.write_bytes(canonical_bytes(log.bundle(4).to_json()))
    first = A.public_key().spec()
    transitions = str(path.with_name("r.jsonl.transitions"))
    assert (
        main(
            ["verify-receipt", str(bundle), "--pubkey", first, "--transitions", transitions],
            io.StringIO(),
        )
        == 0
    )
    assert main(["verify-receipt", str(bundle), "--pubkey", first], io.StringIO()) == 4
    garbled = tmp_path / "garbled.transitions"
    garbled.write_bytes(b'{"v":"ARC1-transition"}\n')
    out = io.StringIO()
    code = main(
        ["verify-receipt", str(bundle), "--pubkey", first, "--transitions", str(garbled)], out
    )
    assert code == 4 and "key transitions" in out.getvalue()


def test_a_schedule_refuses_a_broken_chain() -> None:
    first = KeyTransition.of(LOG_ID, 3, B.public_key(), WHEN).sign(A)
    back = KeyTransition.of(LOG_ID, 2, C.public_key(), WHEN).sign(B)
    with pytest.raises(MalformedReceiptError, match="before the size 3"):
        KeySchedule(LOG_ID, Keyring([A.public_key()]), [first, back])
    other_log = KeyTransition.of("another-log", 3, B.public_key(), WHEN).sign(A)
    with pytest.raises(MalformedReceiptError, match="is for log 'another-log'"):
        KeySchedule(LOG_ID, Keyring([A.public_key()]), [other_log])
    skipped = KeyTransition.of(LOG_ID, 5, C.public_key(), WHEN).sign(A)  # A no longer in force
    with pytest.raises(ReceiptSignatureError, match="not signed by the key in force"):
        KeySchedule(LOG_ID, Keyring([A.public_key()]), [first, skipped])
    with pytest.raises(ReceiptSignatureError, match=r"first key transition .* is not signed"):
        KeySchedule(LOG_ID, Keyring([A.public_key()]), [replace(first, signature=None)])
    with pytest.raises(ValueError, match="at least one"):
        KeySchedule(LOG_ID, Keyring([A.public_key()]), [])


def test_an_hmac_incoming_key_is_named_by_id_and_must_be_held() -> None:
    secret = HmacKey(b"s" * 32)
    transition = KeyTransition.of(LOG_ID, 3, secret, WHEN).sign(A)
    assert transition.incoming_public_key is None
    assert transition.to_json()["incoming"] == {
        "alg": "hmac-sha256",
        "key_id": secret.key_id,
        "public_key": None,
    }
    with pytest.raises(ReceiptSignatureError, match=r"HMAC key .* not among the keys trusted"):
        KeySchedule(LOG_ID, Keyring([A.public_key()]), [transition])
    schedule = KeySchedule(LOG_ID, Keyring([A.public_key(), secret]), [transition])
    assert schedule.current is secret


@pytest.mark.parametrize(
    ("change", "match"),
    [
        (lambda d: d["incoming"].update(key_id="0" * 16), "is not the id of the public key"),
        (lambda d: d["incoming"].update(alg="rsa"), "must be 'ed25519' or 'hmac-sha256'"),
        (
            lambda d: d["incoming"].update(alg="hmac-sha256", key_id="0" * 16),
            "must be null: an HMAC key is never published",
        ),
        (lambda d: d.update(tree_size=-1), "tree_size"),
        (lambda d: d.update(extra=1), "extra"),
    ],
)
def test_a_malformed_transition_is_refused(change: Any, match: str) -> None:
    document = KeyTransition.of(LOG_ID, 3, B.public_key(), WHEN).sign(A).to_json()
    change(document)
    with pytest.raises(MalformedReceiptError, match=match):
        KeyTransition.from_json(loads_strict(canonical_bytes(document)))


def test_rotate_waits_for_issues_in_flight_and_refuses_the_same_key(tmp_path: Path) -> None:
    gate = threading.Event()
    entered = threading.Event()

    class Slow:
        alg, key_id = A.alg, A.key_id

        def public_key(self) -> Verifier:
            return A.public_key()

        def sign(self, message: bytes) -> bytes:
            if b"00000000-0000-0000-0000-000000000001" in message:
                entered.set()
                assert gate.wait(10)
            return A.sign(message)

        def verify(self, message: bytes, signature: bytes) -> bool:
            return A.verify(message, signature)

    log = ReceiptLog(LOG_ID, Slow(), path=tmp_path / "r.jsonl", policy=INLINE)
    issuing = threading.Thread(target=log.issue, args=(draft(0),))
    issuing.start()
    assert entered.wait(5)
    rotated: list[KeyTransition] = []
    rotating = threading.Thread(target=lambda: rotated.append(log.rotate(B)))
    rotating.start()
    rotating.join(0.2)
    assert rotating.is_alive(), "rotate waits for the issue in flight"
    gate.set()
    issuing.join(5)
    rotating.join(5)
    assert rotated and rotated[0].tree_size == 1
    assert log.receipt(0).signature.key_id == A.key_id  # type: ignore[union-attr]
    assert log.issue(draft(1)).signature.key_id == B.key_id  # type: ignore[union-attr]
    with pytest.raises(ValueError, match="already signed by key"):
        log.rotate(B)
    assert log.checkpoint().tree_size == 2
    log.close()


def test_rotate_waits_out_an_issue_whose_signature_fails(tmp_path: Path) -> None:
    """The issue in flight gives its position back, which ends the wait."""
    gate, entered = threading.Event(), threading.Event()

    class Refusing:
        alg, key_id = A.alg, A.key_id

        def public_key(self) -> Verifier:
            return A.public_key()

        def sign(self, message: bytes) -> bytes:
            if b"00000000-0000-0000-0000-000000000001" in message:
                entered.set()
                assert gate.wait(10)
                raise SignerUnavailableError("the key service refused")
            return A.sign(message)

        def verify(self, message: bytes, signature: bytes) -> bool:
            return A.verify(message, signature)

    log = ReceiptLog(LOG_ID, Refusing(), path=tmp_path / "r.jsonl", policy=INLINE)
    log.issue(draft(1))
    refused: list[BaseException] = []

    def issue() -> None:
        try:
            log.issue(draft(0))
        except SignerUnavailableError as exc:
            refused.append(exc)

    issuing = threading.Thread(target=issue, daemon=True)
    issuing.start()
    assert entered.wait(5)
    rotated: list[KeyTransition] = []
    rotating = threading.Thread(target=lambda: rotated.append(log.rotate(B)), daemon=True)
    rotating.start()
    rotating.join(0.2)
    assert rotating.is_alive(), "rotate waits for the issue in flight"
    gate.set()
    issuing.join(5)
    rotating.join(5)
    assert refused, "the issue failed"
    assert rotated and rotated[0].tree_size == 1, "and the rotation went on"
    assert log.issue(draft(2)).signature.key_id == B.key_id  # type: ignore[union-attr]
    log.close()


def test_a_checkpoint_with_nothing_new_since_a_rotation_is_the_outgoing_keys(
    tmp_path: Path,
) -> None:
    log = ReceiptLog(LOG_ID, A, path=tmp_path / "r.jsonl", policy=INLINE)
    log.issue(draft(0))
    log.rotate(B)
    sealed = log.checkpoints()[-1]
    assert log.checkpoint() == sealed and log.publish() == sealed
    assert sealed.signature is not None and sealed.signature.key_id == A.key_id
    log.close()


def test_a_rotation_the_outgoing_key_cannot_sign_changes_nothing(tmp_path: Path) -> None:
    class Gone:
        alg, key_id = A.alg, A.key_id

        def public_key(self) -> Verifier:
            return A.public_key()

        def sign(self, message: bytes) -> bytes:
            raise SignerUnavailableError("the old key version was disabled")

        def verify(self, message: bytes, signature: bytes) -> bool:
            return A.verify(message, signature)

    with ReceiptLog(LOG_ID, A, path=tmp_path / "r.jsonl", policy=INLINE) as log:
        log.issue(draft(0))
        log.checkpoint()
        log._signer = Gone()
        with pytest.raises(SignerUnavailableError):
            log.rotate(B)
        assert log.transitions() == () and log.schedule is None
        log._signer = A
        assert log.issue(draft(1)).signature.key_id == A.key_id  # type: ignore[union-attr]


def test_signature_from_json_reads_both_shapes() -> None:
    v1 = Signature("ed25519", A.key_id, b"\x01" * 64)
    v2 = Signature("ed25519", A.key_id, b"\x01" * 64, 2)
    assert list(v1.to_json()) == ["alg", "key_id", "signature"]
    assert v2.to_json()["sv"] == 2


# -- the 1.2 vectors, from first principles ---------------------------------------


def test_the_v12_vectors_verify_as_the_spec_writes_them() -> None:
    """Recompute each version 2 message from the specification's text and
    check it with the RFC 8032 reference verifier, not agentgov's code."""
    import json

    from agentgov.receipts import _ed25519

    v12 = VECTORS / "v12"

    def public(path: Path) -> bytes:
        return bytes.fromhex(path.read_text().strip().removeprefix("ed25519:"))

    def message(domain: bytes, document: dict[str, Any]) -> bytes:
        sig = document["sig"]
        header = {"alg": sig["alg"], "key_id": sig["key_id"], "sv": sig["sv"]}
        body = {**{k: v for k, v in document.items() if k != "sig"}, "sig": header}
        return domain + hashlib.sha512(canonical_bytes(body)).digest()

    issuer, successor = (
        public(VECTORS / "keys" / "issuer.pub"),
        public(v12 / "keys" / "issuer-2.pub"),
    )
    receipts = [
        json.loads(line) for line in (v12 / "log" / "receipts.jsonl").read_text().splitlines()
    ]
    for index, receipt in enumerate(receipts):
        key = issuer if index < 3 else successor
        assert receipt["sig"]["sv"] == 2
        assert _ed25519.verify(
            key, message(b"ARC1/receipt/v2\n", receipt), bytes.fromhex(receipt["sig"]["signature"])
        )
    checkpoints = [
        json.loads(line)
        for line in (v12 / "log" / "receipts.jsonl.checkpoints").read_text().splitlines()
    ]
    assert [c["tree_size"] for c in checkpoints] == [3, 5]
    for checkpoint, key in zip(checkpoints, (issuer, successor), strict=True):
        assert _ed25519.verify(
            key,
            message(b"ARC1/checkpoint/v2\n", checkpoint),
            bytes.fromhex(checkpoint["sig"]["signature"]),
        )
    (transition,) = [
        json.loads(line)
        for line in (v12 / "log" / "receipts.jsonl.transitions").read_text().splitlines()
    ]
    assert transition["tree_size"] == 3 and transition["incoming"]["public_key"] == successor.hex()
    assert _ed25519.verify(
        issuer,
        message(b"ARC1/transition/v2\n", transition),
        bytes.fromhex(transition["sig"]["signature"]),
    )
