"""Receipt mechanisms the mutation pass found no test of (mutation/phase6-receipts.json).

Each test here pins a mechanism a mutant removed or turned around with every
other test still passing: a check on what a key, a signature version, a
transition or a bundle may be.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from agentgov.exceptions import MalformedReceiptError, ReceiptLogError, ReceiptSignatureError
from agentgov.receipts import (
    ActionReceipt,
    Checkpoint,
    CheckpointPolicy,
    Ed25519Signer,
    FileWitness,
    HmacKey,
    Keyring,
    KeySchedule,
    KeyTransition,
    ReceiptBundle,
    ReceiptLog,
    canonical_bytes,
    loads_strict,
    verify_bundle,
)
from agentgov.receipts.schema import _domain_v2, _signing_input

KEY = Ed25519Signer(bytes(range(32)))
ONE, TWO = bytes(range(32)), bytes(range(1, 33))  # HMAC secrets: 32 bytes at least


class _Custom:
    """A verifier of a kind the keyring knows nothing about."""

    def __init__(self, key_id: str, alg: str = "ed25519") -> None:
        self.key_id = key_id
        self.alg = alg

    def verify(self, data: bytes, signature: bytes) -> bool:
        return False


# -- a key id names one key ---------------------------------------------------------------


def test_a_key_id_names_one_key_whatever_kind_of_key_it_is() -> None:
    ed25519 = KEY.public_key()
    with pytest.raises(ValueError, match="two different keys have id"):
        Keyring([ed25519, HmacKey(ONE, key_id=ed25519.key_id)])
    with pytest.raises(ValueError, match="two different keys have id"):
        Keyring([HmacKey(ONE, key_id="k"), HmacKey(TWO, key_id="k")])
    assert len(Keyring([HmacKey(ONE, key_id="k"), HmacKey(ONE, key_id="k")])) == 1


def test_a_key_of_another_kind_is_the_same_key_only_as_itself() -> None:
    """The keyring cannot compare keys it does not know: the same object is
    the same key; another object with that id is refused."""
    custom = _Custom("c")
    keyring = Keyring([custom])
    assert keyring.add(custom) is custom
    with pytest.raises(ValueError, match="two different keys have id c"):
        keyring.add(_Custom("c"))
    with pytest.raises(ValueError, match="two different keys have id"):
        Keyring([HmacKey(ONE, key_id="h"), _Custom("h", alg="hmac-sha256")])


# -- signature versions ----------------------------------------------------------------------


def test_a_signature_version_is_1_or_2() -> None:
    body: dict[str, Any] = {"v": "ARC1"}
    with pytest.raises(ValueError, match="signature version 3 is not 1 or 2"):
        _signing_input(b"ARC1/receipt/v1\n", body, "ed25519", "k", 3)


def test_only_a_version_1_domain_has_a_version_2() -> None:
    assert _domain_v2(b"example/v1\n") == b"example/v2\n"
    with pytest.raises(ValueError, match="is not a version 1 domain"):
        _domain_v2(b"example/v7\n")


# -- keys named, transitions, schedules -----------------------------------------------------

LOG_ID = "support-eu-1"
A = Ed25519Signer(bytes(range(32)))
B = Ed25519Signer(bytes(range(100, 132)))
WHEN = datetime(2026, 10, 11, 12, tzinfo=UTC)
TEMPLATE = ReceiptBundle.loads(
    (
        Path(__file__).resolve().parent.parent
        / "vectors"
        / "arc1"
        / "valid"
        / "committed-refund.bundle.json"
    ).read_bytes()
).action_receipt
INLINE = CheckpointPolicy(every_receipts=10**6, every_seconds=10**9, background=False)


def _draft(n: int) -> ActionReceipt:
    return replace(
        TEMPLATE,
        receipt_id=str(uuid.UUID(int=n + 1)),
        anchors=replace(TEMPLATE.anchors, log=None),
        signature=None,
    )


def test_a_signature_by_a_key_not_held_names_the_keys_that_are() -> None:
    receipt = _draft(0).sign(B)
    with pytest.raises(ReceiptSignatureError, match=rf"keys given \({A.key_id}\)"):
        receipt.verify(Keyring([A.public_key()]))
    with pytest.raises(ReceiptSignatureError, match=r"keys given \(none\)"):
        receipt.verify(Keyring())


def test_an_ed25519_incoming_key_is_named_by_its_public_key() -> None:
    with pytest.raises(ValueError, match="named by its public key"):
        KeyTransition.of(LOG_ID, 3, _Custom("x"), WHEN)


def test_a_schedule_keeps_its_transitions_and_counts_them_from_one() -> None:
    first = KeyTransition.of(LOG_ID, 0, B.public_key(), WHEN).sign(A)  # an empty log rotates
    again = KeyTransition.of(LOG_ID, 0, A.public_key(), WHEN).sign(B)  # and back, at one size
    schedule = KeySchedule(LOG_ID, Keyring([A.public_key()]), [first, again])
    assert schedule.transitions == (first, again)
    assert schedule.for_leaf(0).key_id == A.key_id
    elsewhere = KeyTransition.of("another-log", 0, B.public_key(), WHEN).sign(A)
    with pytest.raises(MalformedReceiptError, match="key transition 1 is for log 'another-log'"):
        KeySchedule(LOG_ID, Keyring([A.public_key()]), [elsewhere])


def test_a_bundle_with_no_checkpoint_follows_transitions_by_its_receipts_anchor(
    tmp_path: Path,
) -> None:
    log = ReceiptLog(LOG_ID, A, path=tmp_path / "r.jsonl", policy=INLINE)
    with log:
        log.issue(_draft(0))
        transition = log.rotate(B)
        log.issue(_draft(1))
        log.publish()
        bundle = log.bundle(1)
    bare = replace(bundle, checkpoint=None, inclusion=None)
    report = verify_bundle(bare, issuer_key=A.public_key(), transitions=[transition])
    followed = report.checks[1]
    assert followed.name == "key transitions" and followed.status == "pass"
    assert f"from key {A.key_id}" in followed.detail
    # Transitions of another log do not vouch for this one's receipts, even
    # where they would check out on their own.
    elsewhere = KeyTransition.of("another-log", 1, B.public_key(), WHEN).sign(A)
    report = verify_bundle(bare, issuer_key=A.public_key(), transitions=[elsewhere])
    assert report.checks[1].status == "fail" and not report.passed
    # A receipt in no log: the transitions name the log they are followed for.
    unlogged = ReceiptBundle(receipt=_draft(5).sign(A))
    report = verify_bundle(unlogged, issuer_key=A.public_key(), transitions=[transition])
    assert report.checks[1].status == "pass", report.to_json()


def test_a_witness_shown_the_same_tree_again_answers_with_what_it_cosigned(
    tmp_path: Path,
) -> None:
    witness = FileWitness(tmp_path / "w.jsonl", B, witness_id="w", logs={LOG_ID: A.public_key()})
    checkpoint = Checkpoint(LOG_ID, 0, "ab" * 32, WHEN).sign(A)
    first = witness.cosign(checkpoint, [])
    assert witness.cosign(checkpoint, []) == first


# -- a log long enough for its stored subtrees ---------------------------------------------


def test_a_long_log_reopens_with_every_root_and_proof_its_receipts_imply(tmp_path: Path) -> None:
    """The index stores perfect subtrees of 256 leaves and more: a log of
    1,100 receipts, checkpointed along the way, reopened from its index and
    in full, answers every root, inclusion proof and consistency proof as a
    tree built from the receipts themselves does."""
    from agentgov.receipts.merkle import MerkleTree, leaf_hash

    key = HmacKey(ONE)
    path = tmp_path / "long.jsonl"
    sizes = (255, 256, 257, 512, 768, 1024, 1100)
    with ReceiptLog(LOG_ID, key, path=path, policy=INLINE) as log:
        for n in range(1100):
            log.issue(_draft(n))
            if n + 1 in sizes:
                log.checkpoint()
        leaves = [leaf_hash(r.canonical()) for r in log.receipts()]
    tree = MerkleTree(leaves)
    for verify in ("checkpoint", "full"):
        with ReceiptLog(LOG_ID, key, path=path, policy=INLINE, verify=verify) as log:
            assert len(log) == 1100
            assert [c.tree_size for c in log.checkpoints()] == list(sizes)
            for size in (1, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 1100):
                assert log.root(size) == tree.root(size).hex(), (verify, size)
            for index in (0, 255, 256, 511, 512, 1023, 1024, 1099):
                proof = log.inclusion_proof(index, 1100)
                assert proof.path_bytes() == tree.inclusion_proof(index, 1100)
            assert log.consistency_proof(256, 1100) == tree.consistency_proof(256, 1100)
            assert log.consistency_proof(513, 1024) == tree.consistency_proof(513, 1024)
            with pytest.raises(IndexError):
                log.receipt(1100)


# -- a torn file -----------------------------------------------------------------------------


def test_a_torn_line_is_cut_back_to_the_last_newline(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from agentgov.receipts._leaves import complete_length

    path = tmp_path / "f"
    for data, kept in (
        (b"torn", 0),  # no newline at all
        (b"\ntorn", 1),  # the only newline, the first byte
        (b"x\n" + b"y" * 70_000, 2),  # a torn line longer than one read
        (b"whole\ntorn", 6),
    ):
        path.write_bytes(data)
        assert complete_length(path, repair=False) == kept
        assert path.read_bytes() == data, "a read-only look changes nothing"
        caplog.clear()
        with caplog.at_level("WARNING", logger="agentgov.receipts"):
            assert complete_length(path, repair=True) == kept
        assert path.read_bytes() == data[:kept]
        assert f"({len(data) - kept} bytes)" in caplog.text


def _edit_line(path: Path, number: int) -> None:
    """Make line ``number`` one byte longer: the file's size changes too."""
    lines = path.read_bytes().splitlines(keepends=True)
    lines[number - 1] = lines[number - 1][:1] + b" " + lines[number - 1][1:]
    path.write_bytes(b"".join(lines))


@pytest.mark.parametrize(("receipts", "edited"), [(1, 1), (2, 2), (3, 1)])
def test_an_index_whose_last_line_is_not_the_files_is_not_trusted(
    tmp_path: Path, receipts: int, edited: int
) -> None:
    """Every receipt covered by the newest checkpoint, so nothing is re-read
    at reopen: only the index's own check of its last line, against the file,
    sees the edit."""
    path = tmp_path / "r.jsonl"
    with ReceiptLog(LOG_ID, A, path=path, policy=INLINE) as log:
        for n in range(receipts):
            log.issue(_draft(n))
        log.checkpoint()
    _edit_line(path, edited)
    with pytest.raises(ReceiptLogError):
        ReceiptLog(LOG_ID, A, path=path, policy=INLINE).close()


# -- rotating a log's key --------------------------------------------------------------------


class _SlowToSeal:
    """Key A, whose signature of a checkpoint waits to be let go: the seal a
    rotation signs before it hands the log over."""

    def __init__(self) -> None:
        self.alg, self.key_id = A.alg, A.key_id
        self.sealing, self.release = threading.Event(), threading.Event()

    def sign(self, message: bytes) -> bytes:
        if message.startswith(b"ARC1/checkpoint/"):
            self.sealing.set()
            assert self.release.wait(10)
        return A.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return A.verify(message, signature)

    def public_key(self) -> Any:
        return A.public_key()


def test_an_issue_that_arrives_during_a_rotation_waits_and_is_the_incoming_keys(
    tmp_path: Path,
) -> None:
    signer = _SlowToSeal()
    log = ReceiptLog(LOG_ID, signer, path=tmp_path / "r.jsonl", policy=INLINE)
    log.issue(_draft(0))
    log.issue(_draft(1))
    rotated: list[KeyTransition] = []
    issued: list[Any] = []
    rotation = threading.Thread(target=lambda: rotated.append(log.rotate(B)), daemon=True)
    rotation.start()
    assert signer.sealing.wait(10)
    issue = threading.Thread(target=lambda: issued.append(log.issue(_draft(2))), daemon=True)
    issue.start()
    time.sleep(0.2)
    assert not issued, "an issue waits for the rotation in progress"
    signer.release.set()
    rotation.join(10)
    issue.join(10)
    assert not rotation.is_alive() and not issue.is_alive()
    (transition,) = rotated
    (receipt,) = issued
    assert transition.tree_size == 2
    assert receipt.signature.key_id == B.key_id and receipt.anchors.log.leaf_index == 2
    assert B.key_id in log.keyring, "the incoming key is trusted at once"
    log.close()
    with ReceiptLog(LOG_ID, B, path=tmp_path / "r.jsonl", keyring=[A.public_key()]) as reopened:
        assert len(reopened) == 3
        assert {key.key_id for key in reopened.keyring} == {A.key_id, B.key_id}


def test_a_closed_log_does_not_rotate_and_a_log_in_memory_does(tmp_path: Path) -> None:
    log = ReceiptLog(LOG_ID, A, path=tmp_path / "r.jsonl", policy=INLINE)
    log.close()
    with pytest.raises(ReceiptLogError):
        log.rotate(B)
    in_memory = ReceiptLog(LOG_ID, A, policy=INLINE)
    in_memory.issue(_draft(0))
    transition = in_memory.rotate(B)
    assert in_memory.transitions() == (transition,)
    signature = in_memory.issue(_draft(1)).signature
    assert signature is not None and signature.key_id == B.key_id


# -- reopening -------------------------------------------------------------------------------


def _rotated(path: Path) -> KeyTransition:
    with ReceiptLog(LOG_ID, A, path=path, policy=INLINE) as log:
        log.issue(_draft(0))
        transition = log.rotate(B)
        log.issue(_draft(1))
        log.publish()
    return transition


def test_a_log_reopens_through_its_transitions_and_refuses_edited_ones(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    transitions = Path(f"{path}.transitions")
    _rotated(path)
    original = transitions.read_bytes()
    transitions.write_bytes(original + b'{"v":"ARC1-transi')  # torn by a crash: cut off
    with ReceiptLog(LOG_ID, B, path=path, keyring=[A.public_key()]) as log:
        assert len(log.transitions()) == 1
    assert transitions.read_bytes() == original
    transitions.write_bytes(b"not a transition\n")
    with pytest.raises(ReceiptLogError, match=r"\.transitions line 1:"):
        ReceiptLog(LOG_ID, B, path=path, keyring=[A.public_key()])
    # A log A signed throughout, given a transition past its receipts.
    unrotated = tmp_path / "u.jsonl"
    with ReceiptLog(LOG_ID, A, path=unrotated, policy=INLINE) as log:
        log.issue(_draft(0))
        log.issue(_draft(1))
        log.checkpoint()
    beyond = KeyTransition.of(LOG_ID, 9, B.public_key(), WHEN).sign(A)
    Path(f"{unrotated}.transitions").write_bytes(canonical_bytes(beyond.to_json()) + b"\n")
    with pytest.raises(ReceiptLogError, match="hands the log over at size 9, beyond its 2"):
        ReceiptLog(LOG_ID, B, path=unrotated, keyring=[A.public_key()])


def test_a_reopen_cuts_a_torn_checkpoint_and_a_full_one_keeps_the_newest(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    checkpoints = Path(f"{path}.checkpoints")
    with ReceiptLog(LOG_ID, A, path=path, policy=INLINE) as log:
        log.issue(_draft(0))
        log.checkpoint()
        log.issue(_draft(1))
        newest = log.checkpoint()
    whole = checkpoints.read_bytes()
    for verify in ("checkpoint", "full"):
        checkpoints.write_bytes(whole + b'{"v":"ARC1-check')
        with ReceiptLog(LOG_ID, A, path=path, policy=INLINE, verify=verify) as log:
            assert checkpoints.read_bytes() == whole
            assert log.bundle(1).checkpoint == newest
    # An older checkpoint re-signed over another root: its signature is good,
    # so only a check of its root against the receipts finds it.
    lines = whole.splitlines(keepends=True)
    older = Checkpoint.from_json(loads_strict(lines[0]))
    forged = replace(older, root_hash="ab" * 32, signature=None).sign(A)
    checkpoints.write_bytes(canonical_bytes(forged.to_json()) + b"\n" + lines[1])
    with pytest.raises(ReceiptLogError, match="does not match the receipts"):
        ReceiptLog(LOG_ID, A, path=path, policy=INLINE, verify="full")
    with ReceiptLog(LOG_ID, A, path=path, policy=INLINE) as log:
        with pytest.raises(ReceiptLogError, match="does not match the receipts"):
            log.checkpoints()


def test_a_receipt_id_appended_twice_does_not_reopen(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    with ReceiptLog(LOG_ID, A, path=path, policy=INLINE) as log:
        log.issue(_draft(0))
    again = _draft(0).with_log_anchor(LOG_ID, 1).sign(A)
    path.write_bytes(path.read_bytes() + again.canonical() + b"\n")
    with pytest.raises(ReceiptLogError, match="is already in"):
        ReceiptLog(LOG_ID, A, path=path, policy=INLINE)
    # With no index, both lines are new to the reopen that rebuilds it.
    Path(f"{path}.index").unlink()
    with pytest.raises(ReceiptLogError, match="at index 0; a receipt enters a log once"):
        ReceiptLog(LOG_ID, A, path=path, policy=INLINE)


def test_an_index_rebuilt_from_a_long_log_holds_all_of_it_and_the_files_state(
    tmp_path: Path,
) -> None:
    """Rebuilt from the file a few thousand lines at a time, the index holds
    every receipt, and records the file's state: a later rewrite in place,
    the same size, is not trusted."""
    key = HmacKey(ONE)
    path = tmp_path / "r.jsonl"
    with ReceiptLog(LOG_ID, key, path=path, policy=INLINE, fsync=False) as log:
        for n in range(4100):
            log.issue(_draft(n))
        log.checkpoint()
        root = log.root()
    Path(f"{path}.index").unlink()
    with ReceiptLog(LOG_ID, key, path=path, policy=INLINE) as log:
        assert len(log) == 4100 and log.root() == root
        assert log.receipt(4099).receipt_id == _draft(4099).receipt_id
    lines = path.read_bytes().splitlines(keepends=True)
    at = lines[0].index(b'"signature":"') + len(b'"signature":"')
    digit = lines[0][at : at + 1]
    lines[0] = lines[0][:at] + (b"1" if digit == b"0" else b"0") + lines[0][at + 1 :]
    path.write_bytes(b"".join(lines))  # one hex digit of a signature: the same size
    with pytest.raises(ReceiptLogError):
        ReceiptLog(LOG_ID, key, path=path, policy=INLINE).close()


# -- key services ----------------------------------------------------------------------------


def test_a_signing_service_is_asked_in_json_and_given_no_token_it_has_not() -> None:
    from agentgov.exceptions import SignerUnavailableError
    from agentgov.receipts import HttpRemoteSigner
    from tests.fakekms import NOT_AN_OBJECT, FakeKms

    with FakeKms() as kms:
        kms.create("relay", bytes(range(32)))
        signer = HttpRemoteSigner(kms.url, "relay")
        signer.sign(b"message")
        (get, got), (post, posted) = kms.headers[0], kms.headers[-1]
        assert (get, post) == ("GET", "POST")
        assert got["Accept"] == posted["Accept"] == "application/json"
        assert posted["Content-Type"] == "application/json" and "Content-Type" not in got
        assert "Authorization" not in got and "Authorization" not in posted
        kms.misbehave = NOT_AN_OBJECT
        with pytest.raises(SignerUnavailableError, match="no JSON object"):
            signer.sign(b"message")


def test_aws_kms_signs_one_to_4096_bytes_and_wants_a_signature_back() -> None:
    from agentgov.exceptions import SignerUnavailableError
    from agentgov.receipts.kms_aws import MAX_MESSAGE, AwsKmsSigner
    from tests.fakeawskms import FakeAwsKms

    kms = FakeAwsKms()
    signer = AwsKmsSigner(kms.create_key(), client=kms)
    for size in (1, MAX_MESSAGE):
        assert signer.public_key().verify(b"m" * size, signer.sign(b"m" * size))
    for size in (0, MAX_MESSAGE + 1):
        with pytest.raises(SignerUnavailableError, match="KMS signs 1 to 4096 bytes"):
            signer.sign(b"m" * size)

    class Unsigned(FakeAwsKms):
        def sign(self, **request: Any) -> dict[str, Any]:
            return {**super().sign(**request), "Signature": "not bytes"}

    class Silent(FakeAwsKms):
        def sign(self, **request: Any) -> Any:
            return None

    for client, says in (
        (Unsigned(), "answered with no signature"),
        (Silent(), "answered with nothing"),
    ):
        broken = AwsKmsSigner(client.create_key(), client=client)
        with pytest.raises(SignerUnavailableError, match=says):
            broken.sign(b"message")


# -- a delivery and the action it follows, in flight together --------------------------------


def test_a_delivery_appended_while_its_action_is_signed_is_bound_at_its_turn(
    tmp_path: Path,
) -> None:
    """The action receipt holds index 0 while a slow key signs it; its
    delivery, signed elsewhere for index 1, is appended meanwhile. It cannot
    be checked against the action yet, so it waits, and at its turn it is
    checked against the action drained just before it, in the same write."""
    from tests.test_receipts_delivery import LOG_ID as DELIVERY_LOG
    from tests.test_receipts_delivery import LOG_KEY, delivery_draft, template

    release, signing = threading.Event(), threading.Event()

    class Slow:
        alg, key_id = LOG_KEY.alg, LOG_KEY.key_id

        def sign(self, message: bytes) -> bytes:
            if message.startswith(b"ARC1/receipt/"):
                signing.set()
                assert release.wait(10)
            return LOG_KEY.sign(message)

        def verify(self, message: bytes, signature: bytes) -> bool:
            return LOG_KEY.verify(message, signature)

        def public_key(self) -> Any:
            return LOG_KEY.public_key()

    # Ed25519 signs deterministically: the action the log is about to sign.
    action = template().with_log_anchor(DELIVERY_LOG, 0).sign(LOG_KEY)
    delivered = delivery_draft(action).with_log_anchor(DELIVERY_LOG, 1).sign(LOG_KEY)
    log = ReceiptLog(DELIVERY_LOG, Slow(), path=tmp_path / "r.jsonl", policy=INLINE)
    results: dict[str, Any] = {}

    def run(name: str, call: Any) -> None:
        try:
            results[name] = call()
        except BaseException as exc:  # the test inspects it
            results[name] = exc

    issuing = threading.Thread(
        target=run, args=("issue", lambda: log.issue(template())), daemon=True
    )
    issuing.start()
    assert signing.wait(10)
    appending = threading.Thread(
        target=run, args=("append", lambda: log.append(delivered)), daemon=True
    )
    appending.start()
    time.sleep(0.1)
    assert "append" not in results, "the delivery waits for the action before it"
    release.set()
    issuing.join(10)
    appending.join(10)
    assert results["issue"] == action and results["append"] == 1, results
    assert len(log) == 2
    log.close()
    with ReceiptLog(DELIVERY_LOG, LOG_KEY, path=tmp_path / "r.jsonl") as reopened:
        assert len(reopened) == 2
