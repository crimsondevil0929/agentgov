"""Witnesses: independent parties that cosign a log's checkpoints.

A receipt log's operator can recompute its own Merkle tree from scratch, so a
checkpoint signed by the log proves nothing about what the log said
*yesterday*. A witness closes that gap. Before it cosigns a checkpoint it
checks three things:

- the checkpoint is signed by the log's key;
- it is not smaller than the last checkpoint the witness cosigned for that
  log (no rollback), nor a different root at the same size (no fork);
- the consistency proof shows the new tree extends the old one, so every
  receipt the witness vouched for before is still in it, unchanged.

A log that rewrites history cannot get it witnessed, and a verifier that
checks for a witness cosignature sees the rewrite.

:class:`FileWitness` is the development witness: an append-only JSON-lines
file of cosignatures, one per line. In production the witness runs somewhere
the log operator cannot write, and publishes that file; RFC 3161 timestamp
authorities and public transparency-log witnesses fit behind the same
:class:`Witness` interface.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from agentgov.exceptions import (
    MalformedReceiptError,
    ReceiptSignatureError,
    WitnessError,
)
from agentgov.receipts._lines import read_complete_lines
from agentgov.receipts.canonical import canonical_bytes, loads_strict
from agentgov.receipts.merkle import verify_consistency
from agentgov.receipts.schema import Checkpoint, Cosignature
from agentgov.receipts.signing import Signer, Verifier

__all__ = ["FileWitness", "Witness", "find_cosignature", "load_cosignatures"]


@runtime_checkable
class Witness(Protocol):
    """Something that cosigns receipt-log checkpoints it has checked."""

    @property
    def witness_id(self) -> str:
        """A stable name for this witness, recorded in its cosignatures."""
        ...

    def latest(self, log_id: str) -> Cosignature | None:
        """The last checkpoint this witness cosigned for ``log_id``."""
        ...

    def cosign(self, checkpoint: Checkpoint, proof: Sequence[bytes]) -> Cosignature:
        """Check ``checkpoint`` against what was cosigned before, then cosign it.

        :param proof: RFC 9162 consistency proof from the size of
            :meth:`latest` to ``checkpoint.tree_size``.
        :raises WitnessError: If the checkpoint is not the log's, rolls the log
            back, forks it, or does not extend what was cosigned before.
        """
        ...


class FileWitness:
    """A witness that keeps its cosignatures in an append-only file.

    :param path: The cosignature file. Existing cosignatures are loaded and
        verified against ``signer`` first, so the witness resumes where it
        left off and cannot be tricked by an edited file.
    :param signer: The witness's own key.
    :param witness_id: The witness's name.
    :param logs: The logs this witness will cosign for, and each log's
        verification key. A checkpoint from any other log is refused.
    :param clock: Source of ``witnessed_at``; the current UTC time by default.
    :param fsync: Force every cosignature to stable storage before returning.
    :raises WitnessError: If the existing file does not verify.
    """

    __slots__ = ("_clock", "_fsync", "_latest", "_lock", "_logs", "_path", "_signer", "_witness_id")

    def __init__(
        self,
        path: str | Path,
        signer: Signer,
        *,
        witness_id: str,
        logs: Mapping[str, Verifier],
        clock: Callable[[], datetime] | None = None,
        fsync: bool = True,
    ) -> None:
        self._path = Path(path)
        self._signer = signer
        self._witness_id = witness_id
        self._logs = dict(logs)
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._fsync = fsync
        self._lock = threading.Lock()
        self._latest: dict[str, Cosignature] = {}
        if self._path.exists():
            # repair=True: this witness owns and appends to this file, so a
            # torn tail left by a crash mid-append must be truncated now, or
            # the next append would concatenate onto it and corrupt the line
            # that follows.
            for cosignature in load_cosignatures(self._path, repair=True):
                try:
                    cosignature.verify(signer)
                except ReceiptSignatureError as exc:
                    raise WitnessError(
                        f"{self._path} holds a cosignature this witness did not make: {exc}"
                    ) from exc
                previous = self._latest.get(cosignature.log_id)
                if previous is not None and (
                    cosignature.tree_size < previous.tree_size
                    or (
                        cosignature.tree_size == previous.tree_size
                        and cosignature.root_hash != previous.root_hash
                    )
                ):
                    raise WitnessError(
                        f"{self._path} is out of order for log {cosignature.log_id!r}: a "
                        f"witness's own record only ever grows"
                    )
                self._latest[cosignature.log_id] = cosignature

    @property
    def witness_id(self) -> str:
        return self._witness_id

    @property
    def path(self) -> Path:
        return self._path

    def latest(self, log_id: str) -> Cosignature | None:
        with self._lock:
            return self._latest.get(log_id)

    def cosign(self, checkpoint: Checkpoint, proof: Sequence[bytes]) -> Cosignature:
        with self._lock:
            key = self._logs.get(checkpoint.log_id)
            if key is None:
                raise WitnessError(f"this witness does not follow log {checkpoint.log_id!r}")
            try:
                checkpoint.verify(key)
            except ReceiptSignatureError as exc:
                raise WitnessError(
                    f"refusing a checkpoint not signed by log {checkpoint.log_id!r}: {exc}"
                ) from exc
            root = bytes.fromhex(checkpoint.root_hash)
            previous = self._latest.get(checkpoint.log_id)
            if previous is not None:
                if checkpoint.tree_size < previous.tree_size:
                    raise WitnessError(
                        f"log {checkpoint.log_id!r} rolled back from size {previous.tree_size} "
                        f"to {checkpoint.tree_size}; a log only grows"
                    )
                if checkpoint.tree_size == previous.tree_size:
                    if checkpoint.root_hash != previous.root_hash:
                        raise WitnessError(
                            f"log {checkpoint.log_id!r} presented two different roots at size "
                            f"{checkpoint.tree_size} ({previous.root_hash[:16]} and "
                            f"{checkpoint.root_hash[:16]}): a fork"
                        )
                    return previous
                if not verify_consistency(
                    previous.tree_size,
                    checkpoint.tree_size,
                    bytes.fromhex(previous.root_hash),
                    root,
                    proof,
                ):
                    raise WitnessError(
                        f"log {checkpoint.log_id!r} at size {checkpoint.tree_size} does not "
                        f"extend the size {previous.tree_size} this witness cosigned: history "
                        f"was rewritten"
                    )
            cosignature = Cosignature(
                witness_id=self._witness_id,
                log_id=checkpoint.log_id,
                tree_size=checkpoint.tree_size,
                root_hash=checkpoint.root_hash,
                witnessed_at=self._clock(),
            ).sign(self._signer)
            self._append(cosignature)
            self._latest[checkpoint.log_id] = cosignature
            return cosignature

    def _append(self, cosignature: Cosignature) -> None:
        line = canonical_bytes(cosignature.to_json()) + b"\n"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("ab") as handle:
            handle.write(line)
            handle.flush()
            if self._fsync:
                os.fsync(handle.fileno())


def load_cosignatures(path: str | Path, *, repair: bool = False) -> tuple[Cosignature, ...]:
    """Read a witness's published cosignature file.

    Signatures are not checked here: a verifier checks the one it relies on
    against the witness key it trusts, with :func:`find_cosignature`.

    A file torn by a crash mid-append (bytes after the last newline, never
    acknowledged as a completed write) is tolerated: the incomplete final
    line is ignored rather than raising. Previously it was not -- reopening
    a witness file crashed mid-write raised ``MalformedReceiptError`` on the
    torn tail and the file could never be reopened at all, unlike
    :class:`~agentgov.receipts.log.ReceiptLog`, which has always cut off a
    torn line the same way.

    :param repair: When true, also truncate the file in place to drop the
        torn tail, so a subsequent append does not concatenate onto it. Only
        :class:`FileWitness` resuming its own file passes this; a caller
        inspecting someone else's published file should never mutate it and
        must leave this false (the default).
    :raises OSError: If ``path`` does not exist or cannot be read. A missing
        witness file is a plain I/O error, the same as it always was --
        :func:`read_complete_lines`'s "missing means no records yet" reading
        is for a resuming *owner* (:class:`FileWitness`'s own ``__init__``
        already guards its call with an existence check), not for a
        standalone read that a caller like the ``verify-receipt`` CLI treats
        as a usage error distinct from "never witnessed."
    :raises MalformedReceiptError: If any complete line is not a cosignature.
    """
    p = Path(path)
    if not p.exists():
        p.read_bytes()  # raises the natural FileNotFoundError/OSError
    cosignatures = []
    for number, line in enumerate(read_complete_lines(p, repair=repair), start=1):
        try:
            cosignatures.append(Cosignature.from_json(loads_strict(line), f"line {number}"))
        except MalformedReceiptError as exc:
            raise MalformedReceiptError(f"{path}: {exc}") from exc
    return tuple(cosignatures)


def find_cosignature(
    checkpoint: Checkpoint, cosignatures: Sequence[Cosignature], witness_key: Verifier
) -> Cosignature:
    """The witness's cosignature of exactly this checkpoint.

    Only cosignatures that verify under ``witness_key`` count; anything else
    in the file is ignored, so a forged line cannot vouch for a checkpoint.

    :raises WitnessError: If the witness never cosigned this checkpoint, or
        cosigned a *different* root at the same size, which proves the log
        showed two histories. That holds even when the witness also cosigned
        this one: two signed roots for one size are a fork, whichever is
        presented.
    """
    match: Cosignature | None = None
    conflict: Cosignature | None = None
    for cosignature in cosignatures:
        if cosignature.log_id != checkpoint.log_id or cosignature.tree_size != checkpoint.tree_size:
            continue
        try:
            cosignature.verify(witness_key)
        except ReceiptSignatureError:
            continue
        if cosignature.root_hash == checkpoint.root_hash:
            match = match or cosignature
        else:
            conflict = conflict or cosignature
    if conflict is not None:
        also = "this root and " if match is not None else ""
        raise WitnessError(
            f"split view: witness {conflict.witness_id!r} cosigned {also}root "
            f"{conflict.root_hash[:16]} for log {checkpoint.log_id!r} at size "
            f"{checkpoint.tree_size}, and this checkpoint claims {checkpoint.root_hash[:16]}; "
            f"the log showed two different histories"
        )
    if match is None:
        raise WitnessError(
            f"no cosignature from witness key {witness_key.key_id} for log "
            f"{checkpoint.log_id!r} at size {checkpoint.tree_size}: the checkpoint was never "
            f"witnessed"
        )
    return match
