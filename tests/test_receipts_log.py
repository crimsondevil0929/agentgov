"""The receipt log and its witnesses.

What these prove: a receipt cannot be moved, reordered or edited once it is in
the log; a durable log resumes exactly, survives a torn write, and refuses an
edited file; and a witness refuses to cosign a log that rolled back, forked or
rewrote its history, so an operator who rewrites the log cannot get the new
history witnessed.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentgov.exceptions import (
    MalformedReceiptError,
    ReceiptLogError,
    ReceiptSignatureError,
    WitnessError,
)
from agentgov.receipts import (
    ActionReceipt,
    Checkpoint,
    CheckpointPolicy,
    Cosignature,
    Ed25519Signer,
    FileWitness,
    HmacKey,
    LogAnchor,
    MerkleTree,
    ReceiptBundle,
    ReceiptLog,
    Witness,
    canonical_bytes,
    find_cosignature,
    load_cosignatures,
    loads_strict,
    verify_consistency,
    verify_inclusion,
)
from agentgov.receipts.schema import Signature

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
TEMPLATE = ReceiptBundle.loads(
    (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
).receipt
LOG_ID = "support-eu-1"
NEVER = CheckpointPolicy(every_receipts=10**6, every_seconds=10**9)

LOG_KEY = Ed25519Signer(bytes(range(32)))
WITNESS_KEY = Ed25519Signer(bytes(range(32, 64)))
ATTACKER = Ed25519Signer(bytes(range(64, 96)))


def draft(n: int) -> ActionReceipt:
    """A distinct, unsigned, unplaced receipt."""
    return replace(
        TEMPLATE,
        receipt_id=str(uuid.UUID(int=n + 1)),
        anchors=replace(TEMPLATE.anchors, log=None),
        signature=None,
    )


class Clock:
    """A deterministic clock: each reading one second after the last."""

    def __init__(self) -> None:
        self.now = datetime(2026, 9, 25, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


def witness_at(path: Path, *, witness_id: str = "witness-1") -> FileWitness:
    return FileWitness(
        path,
        WITNESS_KEY,
        witness_id=witness_id,
        logs={LOG_ID: LOG_KEY.public_key()},
        clock=Clock(),
        fsync=False,
    )


@pytest.fixture
def log() -> Iterator[ReceiptLog]:
    with ReceiptLog(LOG_ID, LOG_KEY, policy=NEVER, clock=Clock()) as receipt_log:
        yield receipt_log


# -- placing receipts --------------------------------------------------------


def test_issue_places_signs_and_proves_every_receipt(log: ReceiptLog) -> None:
    assert log.log_id == LOG_ID
    issued = [log.issue(draft(i)) for i in range(5)]
    assert len(log) == 5 and log.receipts() == tuple(issued)
    for index, receipt in enumerate(issued):
        assert receipt.anchors.log == LogAnchor(LOG_ID, index)
        receipt.verify(LOG_KEY.public_key())
        assert log.receipt(index) == receipt
    assert not log.checkpoints()
    bundles = [log.bundle(i) for i in range(5)]
    # The first bundle had to publish; the rest reuse that checkpoint.
    assert len(log.checkpoints()) == 1
    checkpoint = log.checkpoints()[0]
    checkpoint.verify(LOG_KEY.public_key())
    for index, bundle in enumerate(bundles):
        assert bundle.checkpoint == checkpoint and bundle.inclusion is not None
        assert verify_inclusion(
            bundle.receipt.leaf_hash(),
            index,
            checkpoint.tree_size,
            bundle.inclusion.path_bytes(),
            bytes.fromhex(checkpoint.root_hash),
        )


def test_the_log_is_an_rfc9162_tree_of_the_receipts_canonical_bytes(log: ReceiptLog) -> None:
    issued = [log.issue(draft(i)) for i in range(7)]
    tree = MerkleTree(r.leaf_hash() for r in issued)
    for size in range(8):
        assert log.root(size) == tree.root(size).hex()
    assert log.root() == tree.root().hex()
    proof = log.inclusion_proof(3)
    assert proof.tree_size == 7 and list(proof.path_bytes()) == tree.inclusion_proof(3, 7)
    assert log.consistency_proof(3) == tree.consistency_proof(3, 7)
    assert verify_consistency(
        3, 7, bytes.fromhex(log.root(3)), bytes.fromhex(log.root()), log.consistency_proof(3, 7)
    )


def test_a_receipt_can_only_enter_at_the_position_it_signed(log: ReceiptLog) -> None:
    first = log.issue(draft(0))
    with pytest.raises(ReceiptLogError, match="unsigned receipt"):
        log.append(draft(1).with_log_anchor(LOG_ID, 1))
    with pytest.raises(ReceiptLogError, match="claims no log position"):
        log.append(draft(1).sign(LOG_KEY))
    with pytest.raises(ReceiptLogError, match="claims other-log#1"):
        log.append(draft(1).with_log_anchor("other-log", 1).sign(LOG_KEY))
    with pytest.raises(ReceiptLogError, match="already in log 'support-eu-1' at index 0"):
        log.append(first)  # a replay of receipt 0
    with pytest.raises(ReceiptLogError, match="at index 1"):
        log.append(draft(2).with_log_anchor(LOG_ID, 2).sign(LOG_KEY))
    assert len(log) == 1
    # Another issuer's receipt, signed for exactly the next position, enters.
    issuer = HmacKey(b"k" * 32)
    theirs = draft(3).with_log_anchor(LOG_ID, 1).sign(issuer)
    assert log.append(theirs) == 1
    assert log.receipt(1) == theirs


def test_a_receipt_id_enters_the_log_once(tmp_path: Path) -> None:
    path = tmp_path / "receipts.jsonl"
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER) as receipt_log:
        first = receipt_log.issue(draft(0))
        receipt_log.issue(draft(1))
        # A retry of an issue that already landed is refused, not logged twice.
        with pytest.raises(ReceiptLogError, match="a receipt enters a log once"):
            receipt_log.issue(draft(0))
        assert len(receipt_log) == 2
        assert receipt_log.index_of(first.receipt_id) == 0
        assert receipt_log.index_of(draft(1).receipt_id) == 1
        assert receipt_log.index_of(draft(2).receipt_id) is None
    # A file that holds one id twice, each at a valid position, is refused.
    duplicate = draft(0).with_log_anchor(LOG_ID, 2).sign(LOG_KEY)
    path.write_bytes(path.read_bytes() + duplicate.canonical() + b"\n")
    with pytest.raises(ReceiptLogError, match="already in log 'support-eu-1' at index 0"):
        ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER)


def test_moving_a_receipt_breaks_its_signature() -> None:
    receipt = draft(0).with_log_anchor(LOG_ID, 4).sign(LOG_KEY)
    assert receipt.signature is not None
    moved = replace(receipt, anchors=replace(receipt.anchors, log=LogAnchor(LOG_ID, 5)))
    with pytest.raises(ReceiptSignatureError):
        moved.verify(LOG_KEY.public_key())
    elsewhere = replace(receipt, anchors=replace(receipt.anchors, log=LogAnchor("other", 4)))
    with pytest.raises(ReceiptSignatureError):
        elsewhere.verify(LOG_KEY.public_key())


def test_concurrent_issuers_get_distinct_contiguous_positions(tmp_path: Path) -> None:
    receipt_log = ReceiptLog(
        LOG_ID, LOG_KEY, path=tmp_path / "log.jsonl", policy=NEVER, fsync=False
    )
    issued: list[ActionReceipt] = []
    lock = threading.Lock()

    def worker(offset: int) -> None:
        for i in range(25):
            receipt = receipt_log.issue(draft(offset * 100 + i))
            with lock:
                issued.append(receipt)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    positions = sorted(r.anchors.log.leaf_index for r in issued if r.anchors.log)
    assert positions == list(range(200))
    root = receipt_log.root()
    receipt_log.close()
    with ReceiptLog(LOG_ID, LOG_KEY, path=tmp_path / "log.jsonl", policy=NEVER) as reopened:
        assert len(reopened) == 200 and reopened.root() == root


# -- checkpoints and bundles -------------------------------------------------


def test_the_policy_publishes_after_every_n_receipts(tmp_path: Path) -> None:
    witness = witness_at(tmp_path / "cosignatures.jsonl")
    with ReceiptLog(
        LOG_ID,
        LOG_KEY,
        witnesses=[witness],
        policy=CheckpointPolicy(every_receipts=3, every_seconds=10**9),
        clock=Clock(),
    ) as receipt_log:
        for i in range(7):
            receipt_log.issue(draft(i))
        assert [c.tree_size for c in receipt_log.checkpoints()] == [3, 6]
    assert [c.tree_size for c in load_cosignatures(witness.path)] == [3, 6]


def test_the_policy_publishes_when_a_receipt_arrives_late(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [1000.0]
    monkeypatch.setattr("agentgov.receipts.log.time", SimpleNamespace(monotonic=lambda: now[0]))
    with ReceiptLog(
        LOG_ID, LOG_KEY, policy=CheckpointPolicy(every_receipts=100, every_seconds=60)
    ) as receipt_log:
        receipt_log.issue(draft(0))
        now[0] += 59
        receipt_log.issue(draft(1))
        assert not receipt_log.checkpoints()
        now[0] += 2
        receipt_log.issue(draft(2))
        assert [c.tree_size for c in receipt_log.checkpoints()] == [3]
        now[0] += 30
        receipt_log.issue(draft(3))
        assert len(receipt_log.checkpoints()) == 1


@pytest.mark.parametrize(("count", "seconds"), [(0, 1.0), (1, 0.0), (-1, 5.0)])
def test_a_policy_needs_a_positive_count_and_interval(count: int, seconds: float) -> None:
    with pytest.raises(ValueError, match="positive"):
        CheckpointPolicy(every_receipts=count, every_seconds=seconds)


@pytest.mark.parametrize("log_id", ["", "a\nb", "x" * 513])
def test_a_log_id_is_short_printable_text(log_id: str) -> None:
    with pytest.raises(ValueError, match="log_id"):
        ReceiptLog(log_id, LOG_KEY)


def test_bundle_proves_against_the_newest_covering_checkpoint(log: ReceiptLog) -> None:
    for i in range(3):
        log.issue(draft(i))
    first = log.checkpoint()
    log.issue(draft(3))
    assert log.bundle(1).checkpoint == first
    # Nothing covers receipt 3 yet, so asking for it publishes.
    fourth = log.bundle(3)
    assert fourth.checkpoint is not None and fourth.checkpoint.tree_size == 4
    assert log.bundle(1).checkpoint == fourth.checkpoint
    # An older checkpoint that covers the receipt is still a valid choice.
    assert log.bundle(2, first).checkpoint == first
    with pytest.raises(IndexError):
        log.bundle(4)
    with pytest.raises(IndexError):
        log.bundle(-1)


def test_bundle_refuses_a_checkpoint_that_is_not_this_logs(log: ReceiptLog) -> None:
    for i in range(3):
        log.issue(draft(i))
    good = log.checkpoint()
    too_small = replace(good, tree_size=2, root_hash=log.root(2))
    with pytest.raises(ReceiptLogError, match="covers receipt 2"):
        log.bundle(2, too_small)
    with pytest.raises(ReceiptLogError):
        log.bundle(0, replace(good, log_id="another-log"))
    with pytest.raises(ReceiptLogError):
        log.bundle(0, replace(good, root_hash="00" * 32))
    with pytest.raises(ReceiptLogError):
        log.bundle(0, replace(good, tree_size=4))


# -- durability --------------------------------------------------------------


def test_a_durable_log_resumes_exactly(tmp_path: Path) -> None:
    path = tmp_path / "receipts.jsonl"
    policy = CheckpointPolicy(every_receipts=3, every_seconds=10**9)
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=policy, clock=Clock()) as first:
        issued = [first.issue(draft(i)) for i in range(4)]
        root, checkpoints = first.root(), first.checkpoints()
    assert [c.tree_size for c in checkpoints] == [3]
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=policy, clock=Clock()) as second:
        assert second.receipts() == tuple(issued)
        assert second.root() == root and second.checkpoints() == checkpoints
        # One receipt was pending at close; two more make the next checkpoint due.
        second.issue(draft(4))
        assert len(second.checkpoints()) == 1
        second.issue(draft(5))
        assert [c.tree_size for c in second.checkpoints()] == [3, 6]
    lines = path.read_bytes().splitlines()
    assert lines == [ActionReceipt.loads(line).canonical() for line in lines]


def test_one_log_has_one_writer(tmp_path: Path) -> None:
    path = tmp_path / "receipts.jsonl"
    first = ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER)
    with pytest.raises(ReceiptLogError, match="already open for appending"):
        ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER)
    first.close()
    first.close()  # idempotent
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER) as second:
        second.issue(draft(0))


def test_a_log_that_cannot_be_claimed_does_not_open(tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("a file where the log's directory should be")
    with pytest.raises(ReceiptLogError, match="cannot create lock file"):
        ReceiptLog(LOG_ID, LOG_KEY, path=blocker / "receipts.jsonl")


def test_a_closed_log_refuses_to_append(tmp_path: Path) -> None:
    with ReceiptLog(LOG_ID, LOG_KEY, path=tmp_path / "r.jsonl", policy=NEVER) as receipt_log:
        receipt_log.issue(draft(0))
    with pytest.raises(ReceiptLogError, match="is closed"):
        receipt_log.issue(draft(1))
    assert len(receipt_log) == 1


def test_a_torn_final_line_is_cut_off(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = tmp_path / "receipts.jsonl"
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER, clock=Clock()) as receipt_log:
        for i in range(3):
            receipt_log.issue(draft(i))
        receipt_log.checkpoint()
    intact = path.read_bytes()
    torn = draft(3).with_log_anchor(LOG_ID, 3).sign(LOG_KEY).canonical()[:57]
    path.write_bytes(intact + torn)
    checkpoints = tmp_path / "receipts.jsonl.checkpoints"
    checkpoints.write_bytes(checkpoints.read_bytes() + b'{"v":"ARC1-check')
    with caplog.at_level(logging.WARNING, logger="agentgov.receipts"):
        receipt_log = ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER, clock=Clock())
    assert sum("torn line" in r.getMessage() for r in caplog.records) == 2
    assert path.read_bytes() == intact
    with receipt_log:
        assert len(receipt_log) == 3 and len(receipt_log.checkpoints()) == 1
        receipt_log.issue(draft(3))
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER) as reopened:
        assert len(reopened) == 4


def test_a_failed_write_leaves_no_torn_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "receipts.jsonl"
    receipt_log = ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER)
    receipt_log.issue(draft(0))
    intact = path.read_bytes()

    def failing_fsync(fd: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("agentgov.receipts.log.os.fsync", failing_fsync)
    with pytest.raises(OSError, match="No space"):
        receipt_log.issue(draft(1))
    assert path.read_bytes() == intact and len(receipt_log) == 1
    monkeypatch.undo()
    retried = receipt_log.issue(draft(1))
    assert retried.anchors.log == LogAnchor(LOG_ID, 1)
    receipt_log.close()
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER) as reopened:
        assert reopened.receipts()[1] == retried


def _durable_log(tmp_path: Path, receipts: int = 4, checkpoint_at: int = 3) -> Path:
    path = tmp_path / "receipts.jsonl"
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER, clock=Clock()) as receipt_log:
        for i in range(receipts):
            receipt_log.issue(draft(i))
            if i + 1 == checkpoint_at:
                receipt_log.checkpoint()
    return path


def _reopen(path: Path) -> None:
    ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=NEVER).close()


def test_resigning_an_edited_receipt_does_not_get_past_the_checkpoint(tmp_path: Path) -> None:
    """The log operator edits receipt 1, re-signs it with the log's own key,
    and rewrites the file: every position and signature checks out, and the
    signed checkpoint still catches it."""
    path = _durable_log(tmp_path)
    lines = path.read_bytes().splitlines()
    original = ActionReceipt.loads(lines[1])
    edited = replace(
        original, cost=replace(original.cost, settled_usd=original.cost.settled_usd / 2)
    )
    lines[1] = edited.sign(LOG_KEY).canonical()
    path.write_bytes(b"\n".join(lines) + b"\n")
    with pytest.raises(ReceiptLogError, match="the log was edited"):
        _reopen(path)


def test_an_edited_receipt_after_the_last_checkpoint_is_caught_by_its_signature(
    tmp_path: Path,
) -> None:
    path = _durable_log(tmp_path)
    lines = path.read_bytes().splitlines()
    receipt = ActionReceipt.loads(lines[3])
    lines[3] = replace(receipt, issuer="someone else").canonical()
    path.write_bytes(b"\n".join(lines) + b"\n")
    with pytest.raises(ReceiptLogError, match=r"line 4: .*the log was edited"):
        _reopen(path)


def test_swapped_lines_do_not_reopen(tmp_path: Path) -> None:
    path = _durable_log(tmp_path)
    lines = path.read_bytes().splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    path.write_bytes(b"\n".join(lines) + b"\n")
    with pytest.raises(ReceiptLogError, match=r"claims support-eu-1#1; .* at index 0"):
        _reopen(path)


def test_a_line_that_is_not_a_receipt_does_not_reopen(tmp_path: Path) -> None:
    path = _durable_log(tmp_path)
    path.write_bytes(path.read_bytes() + b'{"v":"ARC1"}\n')
    with pytest.raises(ReceiptLogError, match="line 5 is not a receipt"):
        _reopen(path)


def test_a_truncated_log_does_not_match_its_checkpoints(tmp_path: Path) -> None:
    path = _durable_log(tmp_path, receipts=4, checkpoint_at=4)
    lines = path.read_bytes().splitlines()
    path.write_bytes(b"\n".join(lines[:2]) + b"\n")
    with pytest.raises(ReceiptLogError, match=r"checkpoint 1 \(support-eu-1@4\) does not match"):
        _reopen(path)


def test_a_checkpoint_the_log_did_not_sign_does_not_reopen(tmp_path: Path) -> None:
    path = _durable_log(tmp_path)
    checkpoints = tmp_path / "receipts.jsonl.checkpoints"
    checkpoint = Checkpoint.from_json(loads_strict(checkpoints.read_bytes().splitlines()[0]))
    forged = checkpoint.sign(ATTACKER)
    checkpoints.write_bytes(canonical_bytes(forged.to_json()) + b"\n")
    with pytest.raises(ReceiptLogError, match=r"checkpoints line 1: .*key"):
        _reopen(path)


def test_the_log_refuses_to_reopen_under_another_key(tmp_path: Path) -> None:
    path = _durable_log(tmp_path)
    with pytest.raises(ReceiptLogError):
        ReceiptLog(LOG_ID, ATTACKER, path=path, policy=NEVER)
    # The failed open released its claim: the right key opens it at once.
    _reopen(path)


# -- witnesses ---------------------------------------------------------------


def test_file_witness_is_a_witness(tmp_path: Path) -> None:
    assert isinstance(witness_at(tmp_path / "w.jsonl"), Witness)


def test_a_witness_cosigns_a_log_as_it_grows(tmp_path: Path) -> None:
    witness = witness_at(tmp_path / "cosignatures.jsonl")
    with ReceiptLog(LOG_ID, LOG_KEY, witnesses=[witness], policy=NEVER, clock=Clock()) as rlog:
        for i in range(2):
            rlog.issue(draft(i))
        small = rlog.publish()
        for i in range(2, 9):
            rlog.issue(draft(i))
        large = rlog.publish()
    latest = witness.latest(LOG_ID)
    assert latest is not None and (latest.tree_size, latest.root_hash) == (9, large.root_hash)
    assert witness.latest("another-log") is None
    cosignatures = load_cosignatures(witness.path)
    assert [c.tree_size for c in cosignatures] == [2, 9]
    for checkpoint in (small, large):
        found = find_cosignature(checkpoint, cosignatures, WITNESS_KEY.public_key())
        assert found.witness_id == "witness-1"
        found.verify(WITNESS_KEY.public_key())


def test_a_witness_cosigns_the_same_tree_once(tmp_path: Path) -> None:
    witness = witness_at(tmp_path / "cosignatures.jsonl")
    with ReceiptLog(LOG_ID, LOG_KEY, witnesses=[witness], policy=NEVER, clock=Clock()) as rlog:
        rlog.issue(draft(0))
        first = rlog.publish()
        second = rlog.publish()  # same tree, a later checkpoint
    assert first.issued_at != second.issued_at
    cosignatures = load_cosignatures(witness.path)
    assert len(cosignatures) == 1
    assert find_cosignature(second, cosignatures, WITNESS_KEY.public_key()) == cosignatures[0]


def _grown(receipts: int, *, fork_at: int | None = None) -> tuple[Checkpoint, MerkleTree]:
    """A checkpoint of a log of ``receipts`` receipts, signed by the log's key.
    With ``fork_at``, that receipt is replaced: a different history."""
    leaves = []
    for i in range(receipts):
        receipt = draft(i if i != fork_at else 1000 + i)
        leaves.append(receipt.with_log_anchor(LOG_ID, i).sign(LOG_KEY).leaf_hash())
    tree = MerkleTree(leaves)
    checkpoint = Checkpoint(
        LOG_ID, receipts, tree.root().hex(), datetime(2026, 9, 25, tzinfo=UTC)
    ).sign(LOG_KEY)
    return checkpoint, tree


def test_a_witness_refuses_a_rollback(tmp_path: Path) -> None:
    witness = witness_at(tmp_path / "w.jsonl")
    five, _ = _grown(5)
    witness.cosign(five, [])
    two, _ = _grown(2)
    with pytest.raises(WitnessError, match="rolled back from size 5 to 2"):
        witness.cosign(two, [])


def test_a_witness_refuses_a_fork(tmp_path: Path) -> None:
    witness = witness_at(tmp_path / "w.jsonl")
    honest, _ = _grown(5)
    witness.cosign(honest, [])
    forked, _ = _grown(5, fork_at=3)
    with pytest.raises(WitnessError, match=r"two different roots at size 5.*a fork"):
        witness.cosign(forked, [])


def test_a_witness_refuses_a_rewritten_history(tmp_path: Path) -> None:
    witness = witness_at(tmp_path / "w.jsonl")
    honest, _ = _grown(4)
    witness.cosign(honest, [])
    rewritten, tree = _grown(9, fork_at=1)
    # The best proof the rewritten log can offer: consistency with itself.
    with pytest.raises(WitnessError, match="history was rewritten"):
        witness.cosign(rewritten, tree.consistency_proof(4, 9))
    extended, extended_tree = _grown(9)
    with pytest.raises(WitnessError, match="history was rewritten"):
        witness.cosign(extended, [])  # the honest extension, without its proof
    cosigned = witness.cosign(extended, extended_tree.consistency_proof(4, 9))
    assert cosigned.tree_size == 9


def test_a_witness_refuses_what_its_log_did_not_sign(tmp_path: Path) -> None:
    witness = witness_at(tmp_path / "w.jsonl")
    checkpoint, _ = _grown(3)
    with pytest.raises(WitnessError, match="not signed by log"):
        witness.cosign(checkpoint.sign(ATTACKER), [])
    with pytest.raises(WitnessError, match="does not follow log 'other'"):
        witness.cosign(replace(checkpoint, log_id="other").sign(LOG_KEY), [])
    assert witness.latest(LOG_ID) is None
    assert not witness.path.exists()


def test_a_rewritten_log_cannot_get_its_new_history_witnessed(tmp_path: Path) -> None:
    """End to end: the operator rebuilds the log with receipt 1 altered and
    publishes to the same witness. The witness refuses, and the refused
    checkpoint is still on the log's own record."""
    witness = witness_at(tmp_path / "w.jsonl")
    with ReceiptLog(LOG_ID, LOG_KEY, witnesses=[witness], policy=NEVER, clock=Clock()) as rlog:
        for i in range(4):
            rlog.issue(draft(i))
        rlog.publish()
    with ReceiptLog(LOG_ID, LOG_KEY, witnesses=[witness], policy=NEVER, clock=Clock()) as forged:
        for i in range(6):
            forged.issue(draft(i if i != 1 else 999))
        with pytest.raises(WitnessError, match=r"not cosigned by 1 of 1 witnesses.*rewritten"):
            forged.publish()
        assert [c.tree_size for c in forged.checkpoints()] == [6]
    latest = witness.latest(LOG_ID)
    assert latest is not None and latest.tree_size == 4


def test_publish_asks_every_witness_even_after_one_refuses(tmp_path: Path) -> None:
    stale = witness_at(tmp_path / "stale.jsonl", witness_id="stale")
    stale.cosign(_grown(5, fork_at=0)[0], [])  # saw a different history
    fresh = witness_at(tmp_path / "fresh.jsonl", witness_id="fresh")
    with ReceiptLog(LOG_ID, LOG_KEY, witnesses=[stale, fresh], policy=NEVER, clock=Clock()) as rlog:
        for i in range(6):
            rlog.issue(draft(i))
        with pytest.raises(WitnessError, match="1 of 2 witnesses; witness 'stale'"):
            rlog.publish()
    latest = fresh.latest(LOG_ID)
    assert latest is not None and latest.tree_size == 6


class OfflineWitness:
    """A witness that cannot be reached."""

    witness_id = "offline"

    def latest(self, log_id: str) -> Cosignature | None:
        return None

    def cosign(self, checkpoint: Checkpoint, proof: Sequence[bytes]) -> Cosignature:
        raise ConnectionError("witness offline")


def test_an_unreachable_witness_does_not_cost_the_others(tmp_path: Path) -> None:
    offline = OfflineWitness()
    assert isinstance(offline, Witness)
    reachable = witness_at(tmp_path / "w.jsonl")
    with ReceiptLog(
        LOG_ID, LOG_KEY, witnesses=[offline, reachable], policy=NEVER, clock=Clock()
    ) as rlog:
        rlog.issue(draft(0))
        with pytest.raises(WitnessError, match="1 of 2 witnesses; witness 'offline': witness"):
            rlog.publish()
    latest = reachable.latest(LOG_ID)
    assert latest is not None and latest.tree_size == 1


def test_a_failed_automatic_checkpoint_does_not_unissue_the_receipt(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "receipts.jsonl"
    every = CheckpointPolicy(every_receipts=1, every_seconds=10**9)
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=every, clock=Clock()) as rlog:
        blocker = tmp_path / "receipts.jsonl.checkpoints"
        blocker.mkdir()  # the checkpoint cannot be written
        with caplog.at_level(logging.ERROR, logger="agentgov.receipts"):
            receipt = rlog.issue(draft(0))
        assert rlog.receipts() == (receipt,) and rlog.checkpoints() == ()
        assert any("automatic checkpoint failed" in r.getMessage() for r in caplog.records)
        blocker.rmdir()
        rlog.issue(draft(1))
        assert [c.tree_size for c in rlog.checkpoints()] == [2]
    with ReceiptLog(LOG_ID, LOG_KEY, path=path, policy=every) as reopened:
        assert len(reopened) == 2 and len(reopened.checkpoints()) == 1


def test_a_refused_automatic_publish_does_not_unissue_the_receipt(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    stale = witness_at(tmp_path / "stale.jsonl")
    stale.cosign(_grown(9)[0], [])  # already saw a bigger log: every publish is a rollback
    with ReceiptLog(
        LOG_ID,
        LOG_KEY,
        witnesses=[stale],
        policy=CheckpointPolicy(every_receipts=1, every_seconds=10**9),
    ) as rlog:
        with caplog.at_level(logging.ERROR, logger="agentgov.receipts"):
            receipt = rlog.issue(draft(0))
        assert rlog.receipts() == (receipt,) and len(rlog.checkpoints()) == 1
    assert any("rolled back" in r.getMessage() for r in caplog.records)


def test_a_witness_resumes_from_its_file(tmp_path: Path) -> None:
    path = tmp_path / "w.jsonl"
    four, _ = _grown(4)
    witness_at(path).cosign(four, [])
    resumed = witness_at(path)
    latest = resumed.latest(LOG_ID)
    assert latest is not None and latest.tree_size == 4
    # It still remembers: a rollback is refused after a restart, too.
    with pytest.raises(WitnessError, match="rolled back"):
        resumed.cosign(_grown(2)[0], [])
    nine, tree = _grown(9)
    resumed.cosign(nine, tree.consistency_proof(4, 9))
    assert [c.tree_size for c in load_cosignatures(path)] == [4, 9]


def test_a_witness_refuses_a_file_it_did_not_write(tmp_path: Path) -> None:
    path = tmp_path / "w.jsonl"
    four, _ = _grown(4)
    witness_at(path).cosign(four, [])
    forged = Cosignature("witness-1", LOG_ID, 2, "ab" * 32, datetime(2026, 9, 25, tzinfo=UTC))
    with path.open("ab") as handle:
        handle.write(canonical_bytes(forged.sign(ATTACKER).to_json()) + b"\n")
    with pytest.raises(WitnessError, match="did not make"):
        witness_at(path)


@pytest.mark.parametrize("second", [(2, "cd"), (4, "cd")])
def test_a_witness_refuses_a_file_that_goes_backwards(
    tmp_path: Path, second: tuple[int, str]
) -> None:
    path = tmp_path / "w.jsonl"
    at = datetime(2026, 9, 25, tzinfo=UTC)
    size, byte = second
    lines = [
        Cosignature("witness-1", LOG_ID, 4, "ab" * 32, at).sign(WITNESS_KEY),
        Cosignature("witness-1", LOG_ID, size, byte * 32, at).sign(WITNESS_KEY),
    ]
    path.write_bytes(b"".join(canonical_bytes(c.to_json()) + b"\n" for c in lines))
    with pytest.raises(WitnessError, match="out of order"):
        witness_at(path)


def test_reading_a_witness_record(tmp_path: Path) -> None:
    path = tmp_path / "w.jsonl"
    at = datetime(2026, 9, 25, tzinfo=UTC)
    good = Cosignature("witness-1", LOG_ID, 4, "ab" * 32, at).sign(WITNESS_KEY)
    path.write_bytes(b"\n" + canonical_bytes(good.to_json()) + b"\n\n")
    assert load_cosignatures(path) == (good,)
    path.write_bytes(canonical_bytes(good.to_json()) + b"\n" + b'{"v":"ARC1-cosignature"}\n')
    with pytest.raises(MalformedReceiptError, match=r"w\.jsonl: line 2"):
        load_cosignatures(path)


def test_find_cosignature_trusts_only_the_witness_key() -> None:
    checkpoint, _ = _grown(5)
    at = datetime(2026, 9, 25, tzinfo=UTC)
    body = Cosignature("witness-1", LOG_ID, 5, checkpoint.root_hash, at)
    forged = body.sign(ATTACKER)
    assert forged.signature is not None
    # A forgery that claims the witness's key id is ignored, not trusted.
    claimed = replace(
        forged,
        signature=Signature(forged.signature.alg, WITNESS_KEY.key_id, forged.signature.value),
    )
    other_log = replace(body, log_id="other").sign(WITNESS_KEY)
    for record in ([], [forged], [claimed], [other_log]):
        with pytest.raises(WitnessError, match="never witnessed"):
            find_cosignature(checkpoint, record, WITNESS_KEY.public_key())
    split = replace(body, root_hash="ee" * 32).sign(WITNESS_KEY)
    with pytest.raises(WitnessError, match="split view"):
        find_cosignature(checkpoint, [claimed, split], WITNESS_KEY.public_key())
    real = body.sign(WITNESS_KEY)
    assert find_cosignature(checkpoint, [forged, claimed, real], WITNESS_KEY.public_key()) == real
    # The witness signing two roots for one size is proof of a fork, even
    # when one of them is the root presented.
    with pytest.raises(WitnessError, match=r"split view: .* cosigned this root and root eeee"):
        find_cosignature(checkpoint, [real, split], WITNESS_KEY.public_key())
