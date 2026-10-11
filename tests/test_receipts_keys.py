"""Keys, not signers, check signatures; and a log outlives its key.

- Reopening a receipt log, or a witness, checks every signature under a key
  and never calls a signer: a log whose key a key service holds reopens
  without reaching it.
- A log whose key was rotated reopens with the old key in its keyring and
  goes on under the new one; without the old key it is refused, naming it.
- A witness follows a rotated log through a keyring for it, and a verifier
  checks a bundle against a keyring.
"""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentgov.exceptions import ReceiptLogError, WitnessError
from agentgov.receipts import (
    ActionReceipt,
    CheckpointPolicy,
    Ed25519Signer,
    FileWitness,
    Keyring,
    ReceiptBundle,
    ReceiptLog,
    Signer,
    Verifier,
    canonical_bytes,
    find_cosignature,
    load_cosignatures,
    verify_bundle,
)

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
TEMPLATE = ReceiptBundle.loads(
    (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
).action_receipt
LOG_ID = "support-eu-1"
OLD = Ed25519Signer(bytes(range(32)))
NEW = Ed25519Signer(bytes(range(100, 132)))
WITNESS = Ed25519Signer(bytes(range(32, 64)))
EVERY_TWO = CheckpointPolicy(every_receipts=2, every_seconds=10**9, background=False)


def draft(n: int) -> ActionReceipt:
    return replace(
        TEMPLATE,
        receipt_id=str(uuid.UUID(int=n + 1)),
        anchors=replace(TEMPLATE.anchors, log=None),
        signature=None,
    )


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 11, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


class Spy:
    """A signer that counts what it signs, refuses when told to, and fails
    any call to verify: agentgov verifies with keys."""

    def __init__(self, inner: Ed25519Signer) -> None:
        self.inner = inner
        self.signed = 0
        self.refuse = False

    @property
    def alg(self) -> str:
        return self.inner.alg

    @property
    def key_id(self) -> str:
        return self.inner.key_id

    def public_key(self) -> Verifier:
        return self.inner.public_key()

    def sign(self, message: bytes) -> bytes:
        if self.refuse:
            raise AssertionError("the signer was called")
        self.signed += 1
        return self.inner.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        raise AssertionError("agentgov verified through the signer")


def _write(path: Path, signer: Signer, first: int, count: int, **kwargs: object) -> None:
    with ReceiptLog(
        LOG_ID, signer, path=path, policy=EVERY_TWO, clock=Clock(), fsync=False, **kwargs
    ) as log:
        for n in range(first, first + count):
            log.issue(draft(n))


# -- reopening calls no signer ---------------------------------------------------


def test_a_log_reopens_without_calling_its_signer(tmp_path: Path) -> None:
    path = tmp_path / "receipts.jsonl"
    spy = Spy(OLD)
    _write(path, spy, 0, 5)  # checkpoints at 2 and 4, and one receipt after them
    assert spy.signed == 7
    spy.refuse = True
    with ReceiptLog(LOG_ID, spy, path=path, policy=EVERY_TWO) as log:
        assert len(log) == 5 and len(log.checkpoints()) == 2
    assert spy.signed == 7


def test_a_witness_resumes_without_calling_its_signer(tmp_path: Path) -> None:
    spy = Spy(WITNESS)
    witness = FileWitness(
        tmp_path / "witness.jsonl", spy, witness_id="w", logs={LOG_ID: OLD.public_key()}
    )
    with ReceiptLog(LOG_ID, OLD, witnesses=[witness], policy=EVERY_TWO, clock=Clock()) as log:
        for n in range(4):
            log.issue(draft(n))
    assert spy.signed == 2
    spy.refuse = True
    again = FileWitness(
        tmp_path / "witness.jsonl", spy, witness_id="w", logs={LOG_ID: OLD.public_key()}
    )
    latest = again.latest(LOG_ID)
    assert latest is not None and latest.tree_size == 4


# -- a log outlives its key -------------------------------------------------------


def test_a_log_whose_key_rotated_reopens_with_the_old_key_in_its_keyring(tmp_path: Path) -> None:
    path = tmp_path / "receipts.jsonl"
    _write(path, OLD, 0, 5)
    _write(path, NEW, 5, 4, keyring=[OLD.public_key()])  # rotated: signs on under NEW
    with ReceiptLog(LOG_ID, NEW, path=path, keyring=Keyring([OLD.public_key()])) as log:
        assert len(log) == 9
        assert log.keyring.get(OLD.key_id) is not None and NEW.key_id in log.keyring
        signers = [r.signature.key_id for r in log.receipts() if r.signature is not None]
        assert signers == [OLD.key_id] * 5 + [NEW.key_id] * 4
        keys = [c.signature.key_id for c in log.checkpoints() if c.signature is not None]
        assert keys == [OLD.key_id, OLD.key_id, NEW.key_id, NEW.key_id]
    # The newest checkpoint is NEW's and vouches for the whole log, so it
    # opens; the old key's checkpoints are checked when they are read, and a
    # full verification reads them all at once.
    with ReceiptLog(LOG_ID, NEW, path=path) as unchecked:
        with pytest.raises(ReceiptLogError, match=f"signed by key {OLD.key_id}, which is not"):
            unchecked.checkpoints()
    with pytest.raises(ReceiptLogError, match=f"signed by key {OLD.key_id}, which is not among"):
        ReceiptLog(LOG_ID, NEW, path=path, verify="full")


def test_a_receipt_signed_before_the_rotation_is_still_checked(tmp_path: Path) -> None:
    """The receipts after the last checkpoint are vouched for only by their
    own signatures: one signed by the old key is checked under it."""
    path = tmp_path / "receipts.jsonl"
    _write(path, OLD, 0, 3)  # a checkpoint at 2; receipt 2 after it
    lines = path.read_bytes().splitlines(keepends=True)
    edited = lines[2].replace(b'"head":"5a7a', b'"head":"5a7b', 1)
    assert edited != lines[2]
    path.write_bytes(b"".join([*lines[:2], edited, *lines[3:]]))
    with pytest.raises(ReceiptLogError, match=r"line 3: .*does not verify.*the log was edited"):
        ReceiptLog(LOG_ID, NEW, path=path, keyring=[OLD.public_key()])


def test_a_witness_follows_a_rotated_log_through_a_keyring(tmp_path: Path) -> None:
    both = Keyring([OLD.public_key(), NEW.public_key()])
    witness = FileWitness(tmp_path / "w.jsonl", WITNESS, witness_id="w", logs={LOG_ID: both})
    old_only = FileWitness(
        tmp_path / "w2.jsonl", WITNESS, witness_id="w2", logs={LOG_ID: OLD.public_key()}
    )
    path = tmp_path / "receipts.jsonl"
    _write(path, OLD, 0, 2, witnesses=[witness, old_only])
    _write(path, NEW, 2, 2, keyring=[OLD.public_key()], witnesses=[witness])
    latest = witness.latest(LOG_ID)
    assert latest is not None and latest.tree_size == 4
    with ReceiptLog(LOG_ID, NEW, path=path, keyring=[OLD.public_key()]) as log:
        checkpoint = log.checkpoints()[-1]
        proof = log.consistency_proof(2, 4)
    with pytest.raises(WitnessError, match=f"signed by key {NEW.key_id}, which is not among"):
        old_only.cosign(checkpoint, proof)
    cosignatures = load_cosignatures(tmp_path / "w.jsonl")
    found = find_cosignature(checkpoint, cosignatures, Keyring([WITNESS.public_key()]))
    assert found.tree_size == 4
    with pytest.raises(WitnessError, match="no cosignature from witness keys"):
        find_cosignature(checkpoint, cosignatures, Keyring([NEW.public_key()]))


def test_a_bundle_verifies_against_a_keyring(tmp_path: Path) -> None:
    path = tmp_path / "receipts.jsonl"
    _write(path, OLD, 0, 2)
    _write(path, NEW, 2, 2, keyring=[OLD.public_key()])
    with ReceiptLog(LOG_ID, NEW, path=path, keyring=[OLD.public_key()]) as log:
        early, late = log.bundle(0), log.bundle(3)
    both = Keyring([OLD.public_key(), NEW.public_key()])
    for bundle in (early, late):
        report = verify_bundle(bundle, issuer_key=both)
        assert report.passed, report.to_json()
    signed = verify_bundle(late, issuer_key=both).checks[1]
    assert signed.detail == f"ed25519, key {NEW.key_id}"
    report = verify_bundle(early, issuer_key=Keyring([NEW.public_key()]))
    assert report.exit_code == 4
    assert f"signed by key {OLD.key_id}, which is not among the keys given" in str(
        report.first_failure
    )


def test_the_cli_verifies_against_every_key_given(tmp_path: Path) -> None:
    import io

    from agentgov.cli import main

    path = tmp_path / "receipts.jsonl"
    _write(path, OLD, 0, 2)
    _write(path, NEW, 2, 2, keyring=[OLD.public_key()])
    with ReceiptLog(LOG_ID, NEW, path=path, keyring=[OLD.public_key()]) as log:
        bundle = tmp_path / "early.json"
        bundle.write_bytes(canonical_bytes(log.bundle(0).to_json()))
    old, new = OLD.public_key().spec(), NEW.public_key().spec()
    both = ["verify-receipt", str(bundle), "--pubkey", new, "--pubkey", old]
    assert main(both, io.StringIO()) == 0
    out = io.StringIO()
    assert main(["verify-receipt", str(bundle), "--pubkey", new], out) == 4
    assert f"signed by key {OLD.key_id}, not by the key given" in out.getvalue()
    out = io.StringIO()
    assert main([*both, "--pubkey", "ed25519:" + "00" * 31], out) == 2
