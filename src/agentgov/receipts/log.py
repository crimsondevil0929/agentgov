"""The receipt log: an append-only RFC 9162 Merkle log of ARC1 receipts.

Each leaf is one signed receipt's canonical bytes. The log signs checkpoints
(its size and root) and hands them to witnesses, and hands a verifier a
:class:`~agentgov.receipts.schema.ReceiptBundle`: the receipt, a checkpoint,
and the audit path proving the one is in the other.

A receipt names its own position, ``anchors.log = {log_id, leaf_index}``,
inside its signature. :meth:`ReceiptLog.issue` assigns the position and signs
in one step, so a receipt cannot be moved to another index, or another log,
without its signature failing. A receipt id enters a log once: a retried
issue is refused, never logged twice.

With a ``path``, the log is durable: receipts are appended one per line to a
JSON-lines file and forced to stable storage before :meth:`issue` returns,
and checkpoints go to ``<path>.checkpoints``. Reopening resumes the log,
re-checking every receipt's position, every checkpoint's signature and root
against the receipts, and the signature of every receipt the log signed since
its last checkpoint; and it cuts off a final line torn by a crash mid-append.
One process holds a log for writing at a time; a second is refused.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from agentgov.exceptions import (
    ConcurrentGovernorError,
    MalformedReceiptError,
    ReceiptLogError,
    ReceiptSignatureError,
    StorageError,
    WitnessError,
)
from agentgov.receipts.canonical import canonical_bytes, loads_strict
from agentgov.receipts.merkle import MerkleTree
from agentgov.receipts.schema import (
    ActionReceipt,
    Checkpoint,
    InclusionProof,
    ReceiptBundle,
    _check_text,
)
from agentgov.receipts.signing import Signer
from agentgov.receipts.witness import Witness

__all__ = ["CheckpointPolicy", "ReceiptLog"]

logger = logging.getLogger("agentgov.receipts")


@dataclass(frozen=True)
class CheckpointPolicy:
    """When the log publishes a checkpoint to its witnesses: after
    ``every_receipts`` new receipts, or when a receipt arrives
    ``every_seconds`` after the last checkpoint, whichever comes first."""

    every_receipts: int = 64
    every_seconds: float = 60.0

    def __post_init__(self) -> None:
        if self.every_receipts < 1 or self.every_seconds <= 0:
            raise ValueError("a checkpoint policy needs a positive count and interval")


class ReceiptLog:
    """An append-only, witnessed log of signed receipts.

    :param log_id: The log's name, recorded in every receipt and checkpoint.
    :param signer: Signs the receipts :meth:`issue` places and every
        checkpoint.
    :param path: A JSON-lines file to persist to. ``None`` keeps the log in
        memory.
    :param witnesses: Cosign each published checkpoint.
    :param policy: When to publish; see :class:`CheckpointPolicy`.
    :param clock: Source of ``issued_at``; the current UTC time by default.
    :param fsync: Force each receipt and checkpoint to stable storage.
    :raises ReceiptLogError: If another process holds ``path``, or the
        existing file does not check out.
    """

    def __init__(
        self,
        log_id: str,
        signer: Signer,
        *,
        path: str | Path | None = None,
        witnesses: Sequence[Witness] = (),
        policy: CheckpointPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
        fsync: bool = True,
    ) -> None:
        try:
            self._log_id = _check_text(log_id, "log_id")
        except MalformedReceiptError as exc:
            raise ValueError(str(exc)) from exc
        self._signer = signer
        self._witnesses = tuple(witnesses)
        self._policy = policy if policy is not None else CheckpointPolicy()
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._fsync = fsync
        self._lock = threading.RLock()
        self._tree = MerkleTree()
        self._receipts: list[ActionReceipt] = []
        self._index_of: dict[str, int] = {}
        self._checkpoints: list[Checkpoint] = []
        self._pending = 0
        self._published_at = time.monotonic()
        self._path = Path(path) if path is not None else None
        self._claim: _Claim | None = None
        if self._path is not None:
            claim = _Claim(self._path)
            try:
                self._resume(self._path)
            except BaseException:
                claim.release()
                raise
            self._claim = claim

    # -- reading ----------------------------------------------------------

    @property
    def log_id(self) -> str:
        return self._log_id

    def __len__(self) -> int:
        with self._lock:
            return len(self._receipts)

    def receipt(self, index: int) -> ActionReceipt:
        with self._lock:
            return self._receipts[index]

    def receipts(self) -> tuple[ActionReceipt, ...]:
        with self._lock:
            return tuple(self._receipts)

    def index_of(self, receipt_id: str) -> int | None:
        """The position of the receipt with this id, or ``None``."""
        with self._lock:
            return self._index_of.get(receipt_id)

    def checkpoints(self) -> tuple[Checkpoint, ...]:
        with self._lock:
            return tuple(self._checkpoints)

    def root(self, size: int | None = None) -> str:
        """The hex root of the first ``size`` receipts (all by default)."""
        with self._lock:
            return self._tree.root(size).hex()

    def inclusion_proof(self, index: int, size: int | None = None) -> InclusionProof:
        with self._lock:
            n = len(self._receipts) if size is None else size
            path = self._tree.inclusion_proof(index, n)
            return InclusionProof(
                leaf_index=index, tree_size=n, audit_path=tuple(p.hex() for p in path)
            )

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        with self._lock:
            return self._tree.consistency_proof(old_size, new_size)

    # -- writing ----------------------------------------------------------

    def issue(self, draft: ActionReceipt) -> ActionReceipt:
        """Place ``draft`` as the next leaf, sign it, and append it.

        If the append makes a checkpoint due under the log's policy, the log
        publishes one. A failure there (a witness refusing, or the checkpoint
        not being written) is logged, not raised: the receipt is already
        durable, so it is issued either way, and the next publish tries again.

        :returns: The signed receipt, naming this log and its index.
        :raises ReceiptLogError: If a receipt with this id is already in the
            log, or the log is closed.
        """
        with self._lock:
            self._check_new(draft)
            receipt = draft.with_log_anchor(self._log_id, len(self._receipts)).sign(self._signer)
            self._append(receipt)
            return receipt

    def append(self, receipt: ActionReceipt) -> int:
        """Append a receipt someone else signed for this log's next index.

        :raises ReceiptLogError: If it is unsigned, names another log or
            another index, or is already in the log.
        """
        with self._lock:
            self._check_position(receipt, len(self._receipts))
            self._append(receipt)
            return len(self._receipts) - 1

    def checkpoint(self) -> Checkpoint:
        """Sign and record a checkpoint of the log as it stands."""
        with self._lock:
            checkpoint = Checkpoint(
                log_id=self._log_id,
                tree_size=len(self._receipts),
                root_hash=self._tree.root().hex(),
                issued_at=self._clock(),
            ).sign(self._signer)
            if self._path is not None:
                self._write(_checkpoint_path(self._path), canonical_bytes(checkpoint.to_json()))
            self._checkpoints.append(checkpoint)
            return checkpoint

    def publish(self) -> Checkpoint:
        """Checkpoint the log and have every witness cosign it.

        Every witness is asked, even after one refuses or cannot be reached,
        so one witness never costs the log the others' cosignatures.

        :raises WitnessError: If any witness refuses or fails, naming each.
            The checkpoint is still recorded: the log did sign it, and a
            refusal is the evidence.
        :raises OSError: If the checkpoint itself cannot be written; nothing
            is recorded then, and the next publish tries again.
        """
        with self._lock:
            checkpoint = self.checkpoint()
            self._pending = 0
            self._published_at = time.monotonic()
            refusals: list[str] = []
            for witness in self._witnesses:
                try:
                    seen = witness.latest(self._log_id)
                    old_size = seen.tree_size if seen is not None else 0
                    proof = (
                        self._tree.consistency_proof(old_size, checkpoint.tree_size)
                        if old_size <= checkpoint.tree_size
                        else []
                    )
                    witness.cosign(checkpoint, proof)
                except (WitnessError, OSError) as exc:
                    refusals.append(f"witness {witness.witness_id!r}: {exc}")
            if refusals:
                raise WitnessError(
                    f"checkpoint {self._log_id}@{checkpoint.tree_size} was not cosigned by "
                    f"{len(refusals)} of {len(self._witnesses)} witnesses; " + "; ".join(refusals)
                )
            return checkpoint

    def bundle(self, index: int, checkpoint: Checkpoint | None = None) -> ReceiptBundle:
        """The receipt at ``index`` with the proof that it is in the log.

        :param checkpoint: The checkpoint to prove against. The most recent
            one that covers ``index`` by default, publishing a new one if
            none does.
        :raises IndexError: If there is no receipt at ``index``.
        :raises ReceiptLogError: If ``checkpoint`` is not one of this log's.
        :raises WitnessError: If a new checkpoint had to be published and a
            witness refused it.
        """
        with self._lock:
            if not 0 <= index < len(self._receipts):
                raise IndexError(f"the log has no receipt {index}")
            if checkpoint is None:
                checkpoint = next(
                    (c for c in reversed(self._checkpoints) if c.tree_size > index), None
                )
                if checkpoint is None:
                    checkpoint = self.publish()
            elif (
                checkpoint.log_id != self._log_id
                or not index < checkpoint.tree_size <= len(self._receipts)
                or checkpoint.root_hash != self._tree.root(checkpoint.tree_size).hex()
            ):
                raise ReceiptLogError(
                    f"checkpoint {checkpoint.log_id}@{checkpoint.tree_size} is not a checkpoint "
                    f"of this log that covers receipt {index}"
                )
            return ReceiptBundle(
                receipt=self._receipts[index],
                inclusion=self.inclusion_proof(index, checkpoint.tree_size),
                checkpoint=checkpoint,
            )

    def close(self) -> None:
        """Release the claim on the log file. Idempotent."""
        with self._lock:
            claim, self._claim = self._claim, None
        if claim is not None:
            claim.release()

    def __enter__(self) -> ReceiptLog:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- internals --------------------------------------------------------

    def _check_new(self, receipt: ActionReceipt) -> None:
        seen = self._index_of.get(receipt.receipt_id)
        if seen is not None:
            raise ReceiptLogError(
                f"receipt {receipt.receipt_id} is already in log {self._log_id!r} at index "
                f"{seen}; a receipt enters a log once"
            )

    def _check_position(self, receipt: ActionReceipt, index: int) -> None:
        self._check_new(receipt)
        if receipt.signature is None:
            raise ReceiptLogError("an unsigned receipt cannot enter a log")
        anchor = receipt.anchors.log
        if anchor is None or anchor.log_id != self._log_id or anchor.leaf_index != index:
            claimed = f"{anchor.log_id}#{anchor.leaf_index}" if anchor else "no log position"
            raise ReceiptLogError(
                f"receipt {receipt.receipt_id} claims {claimed}; this is log "
                f"{self._log_id!r} at index {index}"
            )

    def _append(self, receipt: ActionReceipt) -> None:
        if self._claim is None and self._path is not None:
            raise ReceiptLogError(f"receipt log {self._path} is closed")
        if self._path is not None:
            self._write(self._path, receipt.canonical())
        self._tree.append(receipt.leaf_hash())
        self._index_of[receipt.receipt_id] = len(self._receipts)
        self._receipts.append(receipt)
        self._pending += 1
        due = time.monotonic() - self._published_at >= self._policy.every_seconds
        if self._pending >= self._policy.every_receipts or due:
            try:
                self.publish()
            except (WitnessError, OSError) as exc:
                # The receipt is already durable. Raising would tell the
                # caller it was not issued. The next publish tries again.
                logger.error("receipt log %r: automatic checkpoint failed: %s", self._log_id, exc)

    def _write(self, path: Path, line: bytes) -> None:
        with path.open("ab") as handle:
            start = handle.tell()
            try:
                handle.write(line + b"\n")
                handle.flush()
                if self._fsync:
                    os.fsync(handle.fileno())
            except BaseException:
                # Never leave a torn line for the next append to follow.
                handle.truncate(start)
                raise

    def _resume(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        for number, line in enumerate(_complete_lines(path), start=1):
            try:
                receipt = ActionReceipt.from_json(loads_strict(line), f"{path}:{number}")
            except MalformedReceiptError as exc:
                raise ReceiptLogError(f"{path} line {number} is not a receipt: {exc}") from exc
            self._check_position(receipt, len(self._receipts))
            self._tree.append(receipt.leaf_hash())
            self._index_of[receipt.receipt_id] = len(self._receipts)
            self._receipts.append(receipt)
        for number, line in enumerate(_complete_lines(_checkpoint_path(path)), start=1):
            try:
                checkpoint = Checkpoint.from_json(loads_strict(line), f"checkpoint {number}")
                checkpoint.verify(self._signer)
            except (MalformedReceiptError, ReceiptSignatureError) as exc:
                raise ReceiptLogError(f"{path}.checkpoints line {number}: {exc}") from exc
            if (
                checkpoint.log_id != self._log_id
                or checkpoint.tree_size > len(self._receipts)
                or checkpoint.root_hash != self._tree.root(checkpoint.tree_size).hex()
            ):
                raise ReceiptLogError(
                    f"checkpoint {number} ({checkpoint.log_id}@{checkpoint.tree_size}) does not "
                    f"match the receipts in {path}: the log was edited"
                )
            self._checkpoints.append(checkpoint)
        covered = self._checkpoints[-1].tree_size if self._checkpoints else 0
        # A signed root vouches for every receipt it covers. The ones after
        # it are vouched for only by their own signatures, so check the ones
        # this log signed before a checkpoint can sign over an edited one.
        for index in range(covered, len(self._receipts)):
            receipt = self._receipts[index]
            if receipt.signature is not None and receipt.signature.key_id == self._signer.key_id:
                try:
                    receipt.verify(self._signer)
                except ReceiptSignatureError as exc:
                    raise ReceiptLogError(
                        f"{path} line {index + 1}: {exc}; the log was edited"
                    ) from exc
        self._pending = len(self._receipts) - covered


def _checkpoint_path(path: Path) -> Path:
    return path.with_name(path.name + ".checkpoints")


def _complete_lines(path: Path) -> list[bytes]:
    """The file's complete lines, after cutting off a torn final one.

    Every append writes a whole line and a newline, so bytes after the last
    newline are an append that never finished, and was never acknowledged.
    """
    if not path.exists():
        return []
    data = path.read_bytes()
    cut = data.rfind(b"\n") + 1
    if cut < len(data):
        logger.warning(
            "%s ends in a torn line (%d bytes) left by a crash mid-append; cutting it off",
            path,
            len(data) - cut,
        )
        with path.open("r+b") as handle:
            handle.truncate(cut)
            handle.flush()
            os.fsync(handle.fileno())
    return [line for line in data[:cut].split(b"\n") if line.strip()]


class _Claim:
    """The single-writer claim on a log file, held for the log's lifetime."""

    __slots__ = ("_lock",)

    def __init__(self, path: Path) -> None:
        from agentgov.storage import _AdvisoryLock

        self._lock = _AdvisoryLock(str(path))
        try:
            self._lock.acquire()
        except ConcurrentGovernorError as exc:
            raise ReceiptLogError(
                f"receipt log {path} is already open for appending ({exc}); one log has one writer"
            ) from exc
        except StorageError as exc:
            raise ReceiptLogError(str(exc)) from exc

    def release(self) -> None:
        self._lock.release()
