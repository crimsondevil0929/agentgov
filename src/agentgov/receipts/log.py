"""The receipt log: an append-only RFC 9162 Merkle log of ARC1 receipts.

Each leaf is one signed document's canonical bytes: an action receipt, or
(ARC1 v1.1) a delivery receipt. A delivery receipt that names an action
receipt of the same log is accepted only after it, bound to its exact bytes.
The log signs checkpoints (its size and root) and hands them to witnesses,
and hands a verifier a
:class:`~agentgov.receipts.schema.ReceiptBundle`: the receipt, a checkpoint,
and the audit path proving the one is in the other.

A receipt names its own position, ``anchors.log = {log_id, leaf_index}``,
inside its signature. :meth:`ReceiptLog.issue` assigns the position and signs
in one step, so a receipt cannot be moved to another index, or another log,
without its signature failing. A receipt id enters a log once: a retried
issue is refused, never logged twice.

With a ``path``, the log is durable: receipts are appended one per line to a
JSON-lines file and forced to stable storage before :meth:`issue` returns,
and checkpoints go to ``<path>.checkpoints``. An index of the file in SQLite,
``<path>.index``, derived from it and rebuilt from it when needed, lets the
log reopen without reading its receipts and hold none of them in memory:
reopening checks the newest checkpoint's signature, and its root against the
index's tree; every older checkpoint's signature (one per many receipts), so
a forged checkpoint stops the log at its line; indexes, checks and verifies
any receipts appended since the index last saw the file; re-verifies the
receipts the log signed since its last checkpoint; and cuts off a final line
torn by a crash mid-append. An older checkpoint's root is checked against
the receipts when the checkpoint is first read, and each receipt read
against the leaf hash recorded for it. ``verify="full"`` rebuilds the index,
re-checking every receipt and every checkpoint, as every reopen did before.
Every signature is checked under the log's keyring, never by the signer, so
reopening a log whose key is held by a key service makes no calls to it.

A log outlives its key (ARC1 1.2). :meth:`ReceiptLog.rotate` has the outgoing
key sign a :class:`~agentgov.receipts.schema.KeyTransition` to the incoming
one, kept in ``<path>.transitions``; from then on the log holds each leaf and
checkpoint to the key in force for its position, and a verifier who trusts
only the first key follows the transitions to the current one.
One process holds a log for writing at a time; a second is refused.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from agentgov._aio import off_loop
from agentgov.exceptions import (
    AgentGovError,
    ConcurrentGovernorError,
    MalformedReceiptError,
    ReceiptLogError,
    ReceiptSignatureError,
    StorageError,
    WitnessError,
)
from agentgov.receipts._leaves import (
    FileLeaves,
    IndexWriteError,
    MemoryLeaves,
    complete_length,
    lines_from,
    write_lines,
)
from agentgov.receipts._lines import read_complete_lines
from agentgov.receipts.canonical import canonical_bytes, loads_strict
from agentgov.receipts.schema import (
    ActionReceipt,
    Checkpoint,
    DeliveryReceipt,
    InclusionProof,
    KeySchedule,
    KeyTransition,
    LogDocument,
    ReceiptBundle,
    _check_text,
    _signature_version,
    document_from_json,
)
from agentgov.receipts.signing import Keyring, Signer, Verifier, as_async, verifier_of
from agentgov.receipts.witness import Witness

__all__ = ["CheckpointPolicy", "ReceiptLog"]

logger = logging.getLogger("agentgov.receipts")

D = TypeVar("D", ActionReceipt, DeliveryReceipt)


@dataclass(frozen=True)
class CheckpointPolicy:
    """When the log publishes a checkpoint to its witnesses: after
    ``every_receipts`` new receipts, or when a receipt arrives
    ``every_seconds`` after the last checkpoint, whichever comes first.

    With ``background`` (the default) a publisher thread signs the checkpoint
    and collects the witnesses' cosignatures, and :meth:`ReceiptLog.issue`
    returns as soon as the receipt is durable. Without it, the issue that
    makes a checkpoint due publishes it before returning (outside the log's
    lock, so other issues go on).
    """

    every_receipts: int = 64
    every_seconds: float = 60.0
    background: bool = True

    def __post_init__(self) -> None:
        if self.every_receipts < 1 or self.every_seconds <= 0:
            raise ValueError("a checkpoint policy needs a positive count and interval")


class _Reservation:
    """A position in the log, held while a receipt for it is signed."""

    __slots__ = ("_done", "_wakeups", "error", "index", "receipt", "receipt_id")

    def __init__(self, index: int, receipt_id: str) -> None:
        self.index = index
        self.receipt_id = receipt_id
        self.receipt: LogDocument | None = None
        """The receipt as appended; ``None`` if the position was taken back."""
        self.error: BaseException | None = None
        self._done = threading.Event()
        self._wakeups: list[Callable[[], None]] = []

    @property
    def settled(self) -> bool:
        return self._done.is_set()

    def settle(
        self, *, receipt: LogDocument | None = None, error: BaseException | None = None
    ) -> None:
        """Appended, failed, or taken back (neither). Log lock held."""
        self.receipt, self.error = receipt, error
        self._done.set()
        for wake in self._wakeups:
            wake()

    def wait(self) -> None:
        self._done.wait()

    async def wait_async(self) -> None:
        loop = asyncio.get_running_loop()
        future: asyncio.Future[None] = loop.create_future()

        def wake() -> None:
            loop.call_soon_threadsafe(_resolve, future)

        self._wakeups.append(wake)
        if self._done.is_set():
            return
        await future


def _resolve(future: asyncio.Future[None]) -> None:
    if not future.done():
        future.set_result(None)


class ReceiptLog:
    """An append-only, witnessed log of signed receipts.

    Issuing is pipelined: :meth:`issue` takes the next position under the
    log's lock, signs outside it, and a sequencer appends signed receipts in
    position order, as many at a time as are ready, with one write and one
    fsync. So callers waiting on a slow key service sign concurrently, and
    readers never wait on it. If the signature for a position fails, that
    position and every later one held are taken back, and their callers sign
    again for their new positions: every receipt signs its own position, and
    the log has no gaps.

    :param log_id: The log's name, recorded in every receipt and checkpoint.
    :param signer: Signs the receipts :meth:`issue` places and every
        checkpoint.
    :param keyring: The keys, besides ``signer``'s own, that the log's
        existing checkpoints and receipts may be signed with: the keys it was
        signed with before a rotation. Reopening checks each signature under
        the key it names, and never calls the signer.
    :param path: A JSON-lines file to persist to. ``None`` keeps the log in
        memory.
    :param witnesses: Cosign each published checkpoint.
    :param policy: When to publish; see :class:`CheckpointPolicy`.
    :param clock: Source of ``issued_at``; the current UTC time by default.
    :param fsync: Force each receipt and checkpoint to stable storage.
    :param signature_version: 2 signs digests (ARC1 1.2), so any receipt fits
        a key service's message limit; 1 signs as ARC1 1.0 and 1.1 do. The
        signer's own ``signature_version``, or 1, by default.
    :param verify: What to check when a durable log reopens: ``"checkpoint"``
        (the default) the newest checkpoint, every checkpoint's signature,
        and what was appended since, without reading the receipts the
        checkpoints cover; ``"full"`` every receipt and every checkpoint,
        rebuilding the index.
    :raises ReceiptLogError: If another process holds ``path``, the existing
        file does not check out, or the log's key in force (after its
        transitions) is not ``signer``'s.
    """

    def __init__(
        self,
        log_id: str,
        signer: Signer,
        *,
        keyring: Keyring | Verifier | Iterable[Verifier | str] | None = None,
        path: str | Path | None = None,
        witnesses: Sequence[Witness] = (),
        policy: CheckpointPolicy | None = None,
        clock: Callable[[], datetime] | None = None,
        fsync: bool = True,
        signature_version: int | None = None,
        verify: str = "checkpoint",
    ) -> None:
        try:
            self._log_id = _check_text(log_id, "log_id")
        except MalformedReceiptError as exc:
            raise ValueError(str(exc)) from exc
        if verify not in ("checkpoint", "full"):
            raise ValueError(f"verify must be 'checkpoint' or 'full', got {verify!r}")
        self._verify = verify
        self._signer = signer
        self._signature_version = signature_version
        _signature_version(signer, signature_version)  # refuse a version that is no version
        trusted = list(Keyring.of(keyring)) if keyring is not None else []
        self._keyring = Keyring([*trusted, verifier_of(signer)])
        self._witnesses = tuple(witnesses)
        self._policy = policy if policy is not None else CheckpointPolicy()
        self._clock = clock if clock is not None else (lambda: datetime.now(UTC))
        self._fsync = fsync
        # Lock order: _publish_lock, then _lock; never the reverse.
        self._lock = threading.RLock()
        self._turn = threading.Condition(self._lock)  # positions handed back, rotations ended
        self._publish_lock = threading.Lock()
        self._leaves: MemoryLeaves | FileLeaves = MemoryLeaves()
        self._latest: Checkpoint | None = None  # the newest checkpoint, always known
        self._checkpoint_list: list[Checkpoint] | None = []  # all of them, read when asked for
        self._broken: BaseException | None = None
        self._transitions: list[KeyTransition] = []
        self._schedule: KeySchedule | None = None
        self._rotating = False
        self._next = 0  # the next position to hand out
        self._held: dict[int, _Reservation] = {}  # positions handed out, not yet appended
        self._held_ids: dict[str, int] = {}
        self._signed: dict[int, tuple[_Reservation, LogDocument]] = {}  # waiting their turn
        self._pending = 0
        self._published_at = time.monotonic()
        self._due = False
        self._publisher: threading.Thread | None = None
        self._wake = threading.Event()
        self._stopping = False
        self._path = Path(path) if path is not None else None
        self._claim: _Claim | None = None
        if self._path is not None:
            claim = _Claim(self._path)
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._leaves = FileLeaves(self._path, fsync=fsync)
                self._checkpoint_list = None
                self._resume(self._path)
            except BaseException:
                self._leaves.close()
                claim.release()
                raise
            self._claim = claim
        self._next = len(self._leaves)
        if (
            self._schedule is not None
            and verifier_of(signer).key_id != self._schedule.current.key_id
        ):
            self.close()
            raise ReceiptLogError(
                f"log {self._log_id!r} has been signed by key {self._schedule.current.key_id} "
                f"since size {self._schedule.boundary}, and this signer holds key "
                f"{signer.key_id}: open it with the key in force, and hand it over with rotate()"
            )

    # -- reading ----------------------------------------------------------

    @property
    def log_id(self) -> str:
        return self._log_id

    @property
    def keyring(self) -> Keyring:
        """The keys this log's signatures are checked under: the signer's,
        any it was given, and each key its transitions handed it to."""
        return self._keyring

    def transitions(self) -> tuple[KeyTransition, ...]:
        """The log's key transitions, in order (ARC1 1.2)."""
        with self._lock:
            return tuple(self._transitions)

    @property
    def schedule(self) -> KeySchedule | None:
        """Which key signs which part of the log, once a transition has
        handed it from one key to another; ``None`` before."""
        with self._lock:
            return self._schedule

    def __len__(self) -> int:
        with self._lock:
            return len(self._leaves)

    def receipt(self, index: int) -> LogDocument:
        """The receipt at ``index`` (negative counts from the end).

        :raises IndexError: If there is none.
        """
        with self._lock:
            self._check_readable()
            if index < 0:
                index += len(self._leaves)
            if not 0 <= index < len(self._leaves):
                raise IndexError(f"the log has no receipt {index}")
            return self._leaves.get(index)

    def receipts(self) -> tuple[LogDocument, ...]:
        """Every leaf, in order: action receipts and delivery receipts."""
        with self._lock:
            self._check_readable()
            return self._leaves.all()

    def deliveries(self) -> tuple[DeliveryReceipt, ...]:
        """The delivery receipts alone, in order."""
        with self._lock:
            self._check_readable()
            return tuple(r for r in self._leaves.all() if isinstance(r, DeliveryReceipt))

    def index_of(self, receipt_id: str) -> int | None:
        """The position of the receipt with this id, or ``None``."""
        with self._lock:
            self._check_readable()
            return self._leaves.index_of(receipt_id)

    def checkpoints(self) -> tuple[Checkpoint, ...]:
        """Every checkpoint the log has signed, oldest first. A durable log
        reads and checks them the first time they are asked for."""
        with self._lock:
            self._check_readable()
            return tuple(self._all_checkpoints())

    def root(self, size: int | None = None) -> str:
        """The hex root of the first ``size`` receipts (all by default)."""
        with self._lock:
            self._check_readable()
            return self._leaves.tree.root(size).hex()

    def inclusion_proof(self, index: int, size: int | None = None) -> InclusionProof:
        with self._lock:
            self._check_readable()
            n = len(self._leaves) if size is None else size
            path = self._leaves.tree.inclusion_proof(index, n)
            return InclusionProof(
                leaf_index=index, tree_size=n, audit_path=tuple(p.hex() for p in path)
            )

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        with self._lock:
            self._check_readable()
            return self._leaves.tree.consistency_proof(old_size, new_size)

    # -- writing ----------------------------------------------------------

    def issue(self, draft: D) -> D:
        """Place ``draft`` as the next leaf, sign it, and append it.

        The log's lock is held only to take a position and to append, never
        while signing. If the append makes a checkpoint due, the log publishes
        one, in the background or before returning (see
        :class:`CheckpointPolicy`). A failure there (a witness refusing, the
        checkpoint not being written or signed) is logged, not raised: the
        receipt is already durable, so it is issued either way, and the next
        publish tries again.

        :returns: The signed receipt, naming this log and its index.
        :raises ReceiptLogError: If a receipt with this id is already in the
            log, or being issued, the log is closed, or a delivery receipt
            names an action receipt of this log that is not the one at the
            place it names.
        :raises SignerUnavailableError: If the signer cannot sign it.
        """
        while True:
            reservation, unsigned, signer = self._reserve(draft)
            try:
                receipt = unsigned.sign(signer, version=self._version_for(signer))
            except BaseException:
                self._abandon(reservation)
                raise
            self._deliver(reservation, receipt)
            reservation.wait()
            issued = self._outcome(reservation)
            if issued is not None:
                self._publish_if_due()
                return issued  # type: ignore[return-value]

    async def issue_async(self, draft: D) -> D:
        """:meth:`issue` for a coroutine: the signer is awaited (an
        :class:`~agentgov.receipts.signing.AsyncSigner`, or any signer on a
        worker thread), and the log's lock and its writes run off the event
        loop."""
        while True:
            reservation, unsigned, signer = await off_loop(self._reserve, draft)
            try:
                version = self._version_for(signer)
                receipt = await unsigned.sign_async(as_async(signer), version=version)
            except BaseException:
                self._abandon(reservation)
                raise
            await off_loop(self._deliver, reservation, receipt)
            await reservation.wait_async()
            issued = self._outcome(reservation)
            if issued is not None:
                await off_loop(self._publish_if_due)
                return issued  # type: ignore[return-value]

    def append(self, receipt: LogDocument) -> int:
        """Append a receipt someone else signed for this log's next index.

        :raises ReceiptLogError: If it is unsigned, names another log or
            another index, or is already in the log, or a receipt before it
            fails to be issued (it signs its index, so it cannot move).
        """
        with self._lock:
            self._check_open()
            self._check_position(
                receipt, self._next, staged={}, bind=self._next == len(self._leaves)
            )
            reservation = self._hold(receipt.receipt_id)
        self._deliver(reservation, receipt)
        reservation.wait()
        if self._outcome(reservation) is None:
            raise ReceiptLogError(
                f"receipt {receipt.receipt_id} signs index {reservation.index}, and a receipt "
                f"before it was not issued: sign it again for index {len(self)}"
            )
        self._publish_if_due()
        return reservation.index

    def checkpoint(self) -> Checkpoint:
        """Sign and record a checkpoint of the log as it stands."""
        with self._publish_lock:
            return self._checkpoint()

    def publish(self) -> Checkpoint:
        """Checkpoint the log and have every witness cosign it.

        Every witness is asked, even after one refuses or cannot be reached,
        so one witness never costs the log the others' cosignatures. One
        publication runs at a time; issuing goes on meanwhile.

        :raises WitnessError: If any witness refuses or fails, naming each.
            The checkpoint is still recorded: the log did sign it, and a
            refusal is the evidence.
        :raises OSError: If the checkpoint itself cannot be written; nothing
            is recorded then, and the next publish tries again.
        """
        with self._publish_lock:
            checkpoint = self._checkpoint()
            with self._lock:
                self._pending = len(self._leaves) - checkpoint.tree_size
                self._published_at = time.monotonic()
            refusals: list[str] = []
            for witness in self._witnesses:
                try:
                    seen = witness.latest(self._log_id)
                    old_size = seen.tree_size if seen is not None else 0
                    proof = (
                        self.consistency_proof(old_size, checkpoint.tree_size)
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

    def flush(self) -> None:
        """Publish now any checkpoint the policy has made due, after one being
        published in the background, if any, finishes.

        :raises WitnessError: As :meth:`publish`.
        """
        with self._publish_lock:
            with self._lock:
                due, self._due = self._due, False
        if due:
            self.publish()

    def rotate(self, signer: Signer) -> KeyTransition:
        """Hand the log to ``signer``'s key.

        Issues in flight finish first, and new ones wait. The outgoing key
        signs a checkpoint at the current size, if the last one is not there
        already, and a transition naming the incoming key at that size; from
        then on the incoming key signs every leaf and every larger checkpoint.
        Witnesses need the incoming key in their keyring for this log.

        :returns: The signed transition, also kept in ``<path>.transitions``.
        :raises ValueError: If ``signer`` holds the key the log is signed by.
        :raises SignerUnavailableError: If the outgoing key cannot sign; the
            log is unchanged and still signed by it.
        """
        incoming = verifier_of(signer)
        with self._publish_lock:
            with self._lock:
                self._check_open()
                if incoming.key_id == self._key_in_force().key_id:
                    raise ValueError(
                        f"log {self._log_id!r} is already signed by key {incoming.key_id}"
                    )
                self._rotating = True
                while self._held:
                    self._turn.wait()
            try:
                with self._lock:
                    outgoing = self._signer
                    size = len(self._leaves)
                    sealed = self._latest is not None and self._latest.tree_size == size
                if not sealed:
                    self._checkpoint()  # the outgoing key vouches for all it signed
                transition = KeyTransition.of(self._log_id, size, incoming, self._clock()).sign(
                    outgoing, version=self._version_for(outgoing)
                )
                if self._path is not None:
                    self._write_lines(
                        _transitions_path(self._path), [canonical_bytes(transition.to_json())]
                    )
                with self._lock:
                    self._transitions.append(transition)
                    self._keyring.add(incoming)
                    self._schedule = KeySchedule(self._log_id, self._keyring, self._transitions)
                    self._signer = signer
                return transition
            finally:
                with self._lock:
                    self._rotating = False
                    self._turn.notify_all()

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
            self._check_readable()
            if not 0 <= index < len(self._leaves):
                raise IndexError(f"the log has no receipt {index}")
            if checkpoint is None:
                latest = self._latest
                checkpoint = latest if latest is not None and latest.tree_size > index else None
            elif (
                checkpoint.log_id != self._log_id
                or not index < checkpoint.tree_size <= len(self._leaves)
                or checkpoint.root_hash != self._leaves.tree.root(checkpoint.tree_size).hex()
            ):
                raise ReceiptLogError(
                    f"checkpoint {checkpoint.log_id}@{checkpoint.tree_size} is not a checkpoint "
                    f"of this log that covers receipt {index}"
                )
        if checkpoint is None:
            checkpoint = self.publish()  # never under the log's lock: it signs
        with self._lock:
            return ReceiptBundle(
                receipt=self._leaves.get(index),
                inclusion=self.inclusion_proof(index, checkpoint.tree_size),
                checkpoint=checkpoint,
            )

    def close(self) -> None:
        """Publish what is due, stop the publisher, and release the claim on
        the log file. Idempotent."""
        with self._lock:
            self._stopping = True
            publisher = self._publisher
            self._wake.set()
        if publisher is not None:
            publisher.join()
        with self._lock:
            claim, self._claim = self._claim, None
            if claim is not None:
                self._leaves.close()
        if claim is not None:
            claim.release()

    def __enter__(self) -> ReceiptLog:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- the sequencer ----------------------------------------------------

    def _check_readable(self) -> None:
        """A durable log reads its file, so a closed one refuses, as a closed
        file does. Lock held."""
        if self._claim is None and self._path is not None:
            raise ReceiptLogError(f"receipt log {self._path} is closed")

    def _check_open(self) -> None:
        if self._claim is None and self._path is not None:
            raise ReceiptLogError(f"receipt log {self._path} is closed")
        if self._broken is not None:
            raise ReceiptLogError(
                f"receipt log {self._path} could not index receipts it appended "
                f"({self._broken}); reopen it, which indexes them from the file"
            )

    def _hold(self, receipt_id: str) -> _Reservation:
        """Hand out the next position. Lock held."""
        reservation = _Reservation(self._next, receipt_id)
        self._next += 1
        self._held[reservation.index] = reservation
        self._held_ids[receipt_id] = reservation.index
        return reservation

    def _reserve(self, draft: D) -> tuple[_Reservation, D, Signer]:
        with self._lock:
            while self._rotating:
                self._turn.wait()
            self._check_open()
            self._check_new(draft)
            # Placing it may refuse it (a delivery placed before its action):
            # only a draft that takes the position holds it.
            unsigned = draft.with_log_anchor(self._log_id, self._next)
            return self._hold(draft.receipt_id), unsigned, self._signer

    def _abandon(self, reservation: _Reservation) -> None:
        """Signing failed: give the position back."""
        with self._lock:
            if not reservation.settled:
                self._take_back(reservation)

    def _deliver(self, reservation: _Reservation, receipt: LogDocument) -> None:
        with self._lock:
            if reservation.settled:  # taken back while it was being signed
                return
            self._signed[reservation.index] = (reservation, receipt)
            self._drain()

    @staticmethod
    def _outcome(reservation: _Reservation) -> LogDocument | None:
        """The appended receipt, ``None`` if its position was taken back, or
        the error that kept it out."""
        if reservation.error is not None:
            raise reservation.error
        return reservation.receipt

    def _take_back(self, reservation: _Reservation, error: BaseException | None = None) -> None:
        """Release ``reservation`` (with ``error``, for its caller) and take
        back every later position, whose callers sign again. Lock held."""
        for index in sorted(i for i in self._held if i >= reservation.index):
            held = self._held.pop(index)
            self._signed.pop(index, None)
            self._held_ids.pop(held.receipt_id, None)
            held.settle(error=error if held is reservation else None)
        self._next = reservation.index
        self._turn.notify_all()

    def _drain(self) -> None:
        """Append every signed receipt whose turn has come, in order, with one
        write. The first is always the caller's own. Lock held."""
        start = len(self._leaves)
        batch: list[tuple[_Reservation, LogDocument]] = []
        staged: dict[int, LogDocument] = {}
        refused: tuple[_Reservation, ReceiptLogError] | None = None
        while start + len(batch) in self._signed:
            reservation, receipt = self._signed[start + len(batch)]
            try:
                self._check_open()
                self._check_binding(receipt, staged)
            except ReceiptLogError as exc:
                refused = (reservation, exc)
                break
            staged[reservation.index] = receipt
            batch.append((reservation, receipt))
        if batch:
            try:
                self._leaves.extend([receipt for _, receipt in batch])
            except IndexWriteError as exc:
                # Durable in the file, which is the log: issued. The index
                # lags, so nothing more is appended until a reopen catches up.
                self._broken = exc
                logger.error("receipt log %r: %s", self._log_id, exc)
            except BaseException as exc:
                # Nothing was written. The caller whose turn it was learns
                # why; the others in the batch learn that it failed.
                first = batch[0][0]
                for reservation, _ in batch[1:]:
                    self._held.pop(reservation.index, None)
                    self._signed.pop(reservation.index, None)
                    self._held_ids.pop(reservation.receipt_id, None)
                    failed = ReceiptLogError(
                        f"receipt {reservation.receipt_id} was not issued: the log could not "
                        f"be written ({exc})"
                    )
                    failed.__cause__ = exc
                    reservation.settle(error=failed)
                self._take_back(first, exc)
                return
            for reservation, receipt in batch:
                del self._signed[reservation.index]
                del self._held[reservation.index]
                self._held_ids.pop(reservation.receipt_id, None)
                reservation.settle(receipt=receipt)
            self._pending += len(batch)
            self._note_due()
            self._turn.notify_all()
        if refused is not None:
            self._take_back(*refused)

    # -- publishing -------------------------------------------------------

    def _note_due(self) -> None:
        """After an append: is a checkpoint due? Lock held."""
        overdue = time.monotonic() - self._published_at >= self._policy.every_seconds
        if not (self._pending >= self._policy.every_receipts or overdue):
            return
        self._due = True
        if self._policy.background:
            if self._publisher is None:
                self._publisher = threading.Thread(
                    target=self._run_publisher, name=f"receipt-log-{self._log_id}", daemon=True
                )
                self._publisher.start()
            self._wake.set()

    def _publish_if_due(self) -> None:
        """Without a background publisher, the issue that made a checkpoint
        due publishes it, outside the log's lock."""
        if self._policy.background:
            return
        with self._lock:
            due, self._due = self._due, False
        if due:
            self._publish_quietly()

    def _run_publisher(self) -> None:
        while True:
            self._wake.wait()
            with self._lock:
                self._wake.clear()
                stopping = self._stopping
                due, self._due = self._due, False
            if due:
                self._publish_quietly()
            if stopping:
                return

    def _publish_quietly(self) -> None:
        try:
            self.publish()
        except (AgentGovError, OSError) as exc:
            # The receipts are already durable; the next publish tries again.
            logger.error("receipt log %r: automatic checkpoint failed: %s", self._log_id, exc)

    def _checkpoint(self) -> Checkpoint:
        """Sign and record a checkpoint at the current size. Publish lock held."""
        with self._lock:
            size = len(self._leaves)
            if self._schedule is not None and size <= self._schedule.boundary:
                # Nothing new since the hand-over: the outgoing key's last
                # checkpoint is the log's latest word at this size.
                last = self._latest
                if last is None or last.tree_size != size:
                    raise ReceiptLogError(
                        f"log {self._log_id!r} changed keys at size {self._schedule.boundary} "
                        f"and has no checkpoint there to stand on"
                    )
                return last
            root = self._leaves.tree.root(size).hex()
            signer = self._signer
            issued_at = self._clock()
        checkpoint = Checkpoint(
            log_id=self._log_id, tree_size=size, root_hash=root, issued_at=issued_at
        ).sign(signer, version=self._version_for(signer))
        if self._path is not None:
            self._write_lines(_checkpoint_path(self._path), [canonical_bytes(checkpoint.to_json())])
        with self._lock:
            self._latest = checkpoint
            if self._checkpoint_list is not None:
                self._checkpoint_list.append(checkpoint)
        return checkpoint

    def _all_checkpoints(self) -> list[Checkpoint]:
        """Every checkpoint, read and checked from the file the first time.
        Lock held."""
        if self._checkpoint_list is None:
            assert self._path is not None
            self._checkpoint_list = [
                self._checked_checkpoint(line, number)
                for number, line in enumerate(
                    read_complete_lines(_checkpoint_path(self._path)), start=1
                )
            ]
        return self._checkpoint_list

    def _checked_checkpoint(self, line: bytes, number: int) -> Checkpoint:
        """A checkpoint line, checked: signed by the key in force at its size,
        this log's, and the root of the receipts up to it. Lock held."""
        checkpoint = self._signed_checkpoint(line, number)
        if checkpoint.root_hash != self._leaves.tree.root(checkpoint.tree_size).hex():
            raise self._edited(checkpoint, number)
        return checkpoint

    def _signed_checkpoint(self, line: bytes, number: int) -> Checkpoint:
        """A checkpoint line, signed by the key in force at its size, this
        log's, and of no more receipts than it holds. Lock held."""
        try:
            checkpoint = Checkpoint.from_json(loads_strict(line), f"checkpoint {number}")
            if self._schedule is not None:
                checkpoint.verify(self._schedule.for_checkpoint(checkpoint.tree_size))
            else:
                checkpoint.verify(self._keyring)
        except (MalformedReceiptError, ReceiptSignatureError) as exc:
            raise ReceiptLogError(f"{self._path}.checkpoints line {number}: {exc}") from exc
        if checkpoint.log_id != self._log_id or checkpoint.tree_size > len(self._leaves):
            raise self._edited(checkpoint, number)
        return checkpoint

    def _edited(self, checkpoint: Checkpoint, number: int) -> ReceiptLogError:
        return ReceiptLogError(
            f"checkpoint {number} ({checkpoint.log_id}@{checkpoint.tree_size}) does not "
            f"match the receipts in {self._path}: the log was edited"
        )

    # -- internals --------------------------------------------------------

    def _version_for(self, signer: Signer) -> int:
        return _signature_version(signer, self._signature_version)

    def _key_in_force(self) -> Verifier:
        """The key that signs the next leaf. Lock held."""
        return self._schedule.current if self._schedule is not None else verifier_of(self._signer)

    def _check_new(self, receipt: LogDocument) -> None:
        seen = self._leaves.index_of(receipt.receipt_id)
        if seen is not None:
            raise ReceiptLogError(
                f"receipt {receipt.receipt_id} is already in log {self._log_id!r} at index "
                f"{seen}; a receipt enters a log once"
            )
        held = self._held_ids.get(receipt.receipt_id)
        if held is not None:
            raise ReceiptLogError(
                f"receipt {receipt.receipt_id} is being issued in log {self._log_id!r} at index "
                f"{held}; a receipt enters a log once"
            )

    def _check_position(
        self,
        receipt: LogDocument,
        index: int,
        staged: Mapping[int, LogDocument],
        *,
        bind: bool = True,
    ) -> None:
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
        if bind:
            self._check_binding(receipt, staged)

    def _check_binding(self, receipt: LogDocument, staged: Mapping[int, LogDocument]) -> None:
        """A delivery that names an action receipt of this log follows it,
        bound to its exact bytes."""
        if not isinstance(receipt, DeliveryReceipt) or receipt.action.log_id != self._log_id:
            return
        index = receipt.action.leaf_index
        action = staged.get(index)
        if action is None and index < len(self._leaves):
            action = self._leaves.get(index)
        if not isinstance(action, ActionReceipt):
            raise ReceiptLogError(
                f"delivery {receipt.receipt_id} follows from leaf {index} of log "
                f"{self._log_id!r}, which is not an action receipt this log holds"
            )
        problem = receipt.action.problem(action)
        if problem is not None:
            raise ReceiptLogError(f"delivery {receipt.receipt_id} does not bind: {problem}")

    def _write_lines(self, path: Path, lines: Sequence[bytes]) -> None:
        write_lines(path, lines, fsync=self._fsync)

    def _resume(self, path: Path) -> None:
        """Pick up a durable log where it was left. Constructor only."""
        for number, line in enumerate(
            read_complete_lines(_transitions_path(path), repair=True), start=1
        ):
            try:
                transition = KeyTransition.from_json(loads_strict(line), f"transition {number}")
            except MalformedReceiptError as exc:
                raise ReceiptLogError(f"{path}.transitions line {number}: {exc}") from exc
            self._transitions.append(transition)
        if self._transitions:
            try:
                self._schedule = KeySchedule(self._log_id, self._keyring, self._transitions)
            except (MalformedReceiptError, ReceiptSignatureError) as exc:
                raise ReceiptLogError(f"{path}.transitions: {exc}") from exc
            for handed_to in self._schedule.keyring():
                self._keyring.add(handed_to)

        leaves = self._leaves
        assert isinstance(leaves, FileLeaves)
        size = complete_length(path, repair=True)
        if self._verify == "full" or not leaves.trustworthy(size):
            leaves.reset()
        self._index_appended(path, leaves, size)

        checkpoints = _checkpoint_path(path)
        if self._verify == "full":
            complete_length(checkpoints, repair=True)
            found = self._all_checkpoints()
            self._latest = found[-1] if found else None
        else:
            complete_length(checkpoints, repair=True)
            # The newest checkpoint in full; every older one's signature, which
            # costs one signature per many receipts, so a forged checkpoint
            # stops the log at its line. The older ones' roots are checked
            # against the receipts when first read: the newest's covers them.
            lines = list(read_complete_lines(checkpoints))
            for number, line in enumerate(lines[:-1], start=1):
                self._signed_checkpoint(line, number)
            if not lines:
                self._checkpoint_list = []  # none yet: every later one is appended here
            else:
                self._latest = self._checked_checkpoint(lines[-1], len(lines))
        count = len(leaves)
        if self._schedule is not None and self._transitions[-1].tree_size > count:
            raise ReceiptLogError(
                f"{path}.transitions hands the log over at size "
                f"{self._transitions[-1].tree_size}, beyond its {count} receipts: "
                f"the log was edited"
            )
        covered = self._latest.tree_size if self._latest is not None else 0
        # A signed root vouches for every receipt it covers. The ones after
        # it are vouched for only by their own signatures, so check the ones
        # this log signed before a checkpoint can sign over an edited one.
        for index in range(covered, count):
            receipt = leaves.get(index)
            if receipt.signature is not None and receipt.signature.key_id in self._keyring:
                key: Verifier | Keyring = (
                    self._schedule.for_leaf(index) if self._schedule is not None else self._keyring
                )
                try:
                    receipt.verify(key)
                except ReceiptSignatureError as exc:
                    raise ReceiptLogError(
                        f"{path} line {index + 1}: {exc}; the log was edited"
                    ) from exc
        self._pending = count - covered

    def _index_appended(self, path: Path, leaves: FileLeaves, size: int) -> None:
        """Check and index the receipts in the file after what the index
        holds: all of them, when it was rebuilt. Constructor only."""
        staged: dict[int, LogDocument] = {}
        ids: dict[str, int] = {}
        found: list[tuple[int, bytes, LogDocument]] = []
        index = len(leaves)
        for offset, line in lines_from(path, leaves.end, size):
            number = index + 1
            try:
                receipt = document_from_json(loads_strict(line), f"{path}:{number}")
            except MalformedReceiptError as exc:
                raise ReceiptLogError(f"{path} line {number} is not a receipt: {exc}") from exc
            seen = ids.get(receipt.receipt_id)
            if seen is not None:
                raise ReceiptLogError(
                    f"receipt {receipt.receipt_id} is already in log {self._log_id!r} at index "
                    f"{seen}; a receipt enters a log once"
                )
            self._check_position(receipt, index, staged=staged)
            staged[index] = receipt
            ids[receipt.receipt_id] = index
            found.append((offset, line, receipt))
            index += 1
            if len(found) >= 4096:
                leaves.adopt(found, last=False)
                found, staged, ids = [], {}, {}
        leaves.adopt(found, last=True)


def _checkpoint_path(path: Path) -> Path:
    return path.with_name(path.name + ".checkpoints")


def _transitions_path(path: Path) -> Path:
    return path.with_name(path.name + ".transitions")


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
