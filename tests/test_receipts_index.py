"""A receipt log reopens without reading what it holds (Phase 4.7).

The file of JSON lines is the log. Beside it, ``<file>.index`` (SQLite) holds
each receipt's place, id and leaf hash, and the roots of the tree's perfect
subtrees of 256 leaves and more. Reopening checks the newest checkpoint
against the index's tree, indexes and checks what was appended since, and
re-verifies the receipts signed since that checkpoint: its work follows what
is new, not the size of the log, and none of the receipts are held in memory.
Every receipt read is checked against the leaf hash recorded for it.
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from agentgov.exceptions import ReceiptLogError
from agentgov.receipts import (
    ActionReceipt,
    CheckpointPolicy,
    Ed25519Signer,
    MerkleTree,
    ReceiptBundle,
    ReceiptLog,
    _leaves,
    verify_consistency,
    verify_inclusion,
)

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
TEMPLATE = ReceiptBundle.loads(
    (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
).action_receipt
LOG_ID = "support-eu-1"
KEY = Ed25519Signer(bytes(range(32)))
INLINE = CheckpointPolicy(every_receipts=10**6, every_seconds=10**9, background=False)


def draft(n: int) -> ActionReceipt:
    return replace(
        TEMPLATE,
        receipt_id=str(uuid.UUID(int=n + 1)),
        anchors=replace(TEMPLATE.anchors, log=None),
        signature=None,
    )


def _log(path: Path, receipts: int, *, checkpoint_at: int | None = None) -> list[ActionReceipt]:
    issued = []
    with ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE, fsync=False) as log:
        for n in range(receipts):
            issued.append(log.issue(draft(n)))
            if checkpoint_at is not None and n + 1 == checkpoint_at:
                log.checkpoint()
    return issued


def _parses(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Count every receipt parsed from the file from now on."""
    from agentgov.receipts.schema import LogDocument, document_from_json

    count = [0]

    def counting(value: object, path: str = "receipt") -> LogDocument:
        count[0] += 1
        return document_from_json(value, path)

    monkeypatch.setattr(_leaves, "document_from_json", counting)
    monkeypatch.setattr("agentgov.receipts.log.document_from_json", counting)
    return count


def test_reopening_reads_only_what_came_after_the_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "r.jsonl"
    _log(path, 600, checkpoint_at=597)  # three receipts after the newest checkpoint
    parses = _parses(monkeypatch)
    with ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE) as log:
        assert len(log) == 600
        assert log.checkpoints()[-1].tree_size == 597
    assert parses[0] == 3, "only the receipts signed since the checkpoint were read"
    parses[0] = 0
    with ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE, verify="full"):
        pass
    assert parses[0] >= 600, "a full verification reads every one"


def test_the_indexed_tree_is_the_rfc_9162_tree_of_the_file(tmp_path: Path) -> None:
    """Across the 256- and 512-leaf subtrees the index stores, every root and
    proof is the one an in-memory tree of the same leaves gives."""
    path = tmp_path / "r.jsonl"
    issued = _log(path, 600)
    memory = MerkleTree(r.leaf_hash() for r in issued)
    with ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE) as log:
        for size in (1, 2, 255, 256, 257, 511, 512, 513, 599, 600):
            assert log.root(size) == memory.root(size).hex()
        root = bytes.fromhex(log.root())
        for index in (0, 1, 255, 256, 300, 511, 512, 599):
            proof = log.inclusion_proof(index)
            assert list(proof.path_bytes()) == memory.inclusion_proof(index)
            assert verify_inclusion(issued[index].leaf_hash(), index, 600, proof.path_bytes(), root)
        for old in (1, 255, 256, 300, 512, 599):
            proof_bytes = log.consistency_proof(old, 600)
            assert proof_bytes == memory.consistency_proof(old, 600)
            assert verify_consistency(old, 600, memory.root(old), root, proof_bytes)
        assert log.receipt(300) == issued[300] and log.receipt(-1) == issued[-1]
        assert log.index_of(issued[42].receipt_id) == 42
        assert log.receipts() == tuple(issued)


def test_a_rewritten_file_is_rebuilt_from_and_an_edit_is_caught(tmp_path: Path) -> None:
    """An edit in place, keeping every line's length and the file's
    modification time, leaves the index's word standing at open; the edited
    receipt is caught when read, and a full verification refuses the log."""
    path = tmp_path / "r.jsonl"
    _log(path, 5, checkpoint_at=4)
    stat = path.stat()
    data = path.read_bytes()
    edited = data.replace(b'"settled_usd":"0.00549500"', b'"settled_usd":"0.00049500"', 1)
    assert edited != data and len(edited) == len(data)
    path.write_bytes(edited)
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))  # the edit hides its tracks
    with ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE) as log:
        with pytest.raises(ReceiptLogError, match=r"line 1 is not the receipt the log appended"):
            log.receipt(0)
        with pytest.raises(ReceiptLogError, match=r"the log was edited"):
            log.receipts()
    with pytest.raises(
        ReceiptLogError, match=r"does not match the receipts .*: the log was edited"
    ):
        ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE, verify="full")
    path.write_bytes(edited)  # an edit that moves the modification time: rebuilt at open
    with pytest.raises(
        ReceiptLogError, match=r"does not match the receipts .*: the log was edited"
    ):
        ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE)


def test_a_lost_or_stale_index_is_rebuilt_from_the_file(tmp_path: Path) -> None:
    path = tmp_path / "r.jsonl"
    issued = _log(path, 300, checkpoint_at=300)
    index = path.with_name("r.jsonl.index")
    for sidecar in (
        index,
        path.with_name("r.jsonl.index-wal"),
        path.with_name("r.jsonl.index-shm"),
    ):
        if sidecar.exists():
            sidecar.unlink()
    with ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE) as log:
        assert log.receipts() == tuple(issued)
        log.issue(draft(300))
    other = tmp_path / "other.jsonl"
    _log(other, 3)
    # Another log's index, beside this file: it describes other lines.
    for suffix in (".index", ".index-wal", ".index-shm"):
        source = other.with_name("other.jsonl" + suffix)
        if source.exists():
            source.replace(path.with_name("r.jsonl" + suffix))
    with ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE) as log:
        assert len(log) == 301 and log.receipt(300).receipt_id == draft(300).receipt_id


def test_receipts_appended_before_the_index_caught_up_are_indexed(tmp_path: Path) -> None:
    """A crash between the file's write and the index's: the file holds a
    receipt the index does not, and reopening checks and indexes it."""
    path = tmp_path / "r.jsonl"
    _log(path, 3)
    late = draft(3).with_log_anchor(LOG_ID, 3).sign(KEY)
    with path.open("ab") as handle:
        handle.write(late.canonical() + b"\n")
    with ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE) as log:
        assert len(log) == 4 and log.receipt(3) == late
        assert log.index_of(late.receipt_id) == 3
    wrong = draft(4).with_log_anchor(LOG_ID, 9).sign(KEY)
    with path.open("ab") as handle:
        handle.write(wrong.canonical() + b"\n")
    with pytest.raises(ReceiptLogError, match=r"claims support-eu-1#9; .* at index 4"):
        ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE)


def test_an_index_that_cannot_be_written_stops_the_log_until_it_reopens(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "r.jsonl"
    log = ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE)
    log.issue(draft(0))

    def full(self: object, rows: object, file_state: object = None) -> None:
        raise sqlite3.OperationalError("database or disk is full")

    monkeypatch.setattr(_leaves._Index, "add", full)
    issued = log.issue(draft(1))  # durable in the file: issued
    assert issued.anchors.log is not None and issued.anchors.log.leaf_index == 1
    with pytest.raises(ReceiptLogError, match=r"could not index receipts it appended .*reopen it"):
        log.issue(draft(2))
    monkeypatch.undo()
    log.close()
    with ReceiptLog(LOG_ID, KEY, path=path, policy=INLINE) as reopened:
        assert len(reopened) == 2 and reopened.receipt(1) == issued
        reopened.issue(draft(2))


def test_verify_must_be_one_it_knows(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match=r"verify must be"):
        ReceiptLog(LOG_ID, KEY, path=tmp_path / "r.jsonl", verify="some")
