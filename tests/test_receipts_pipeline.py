"""Pipelined issuance: callers sign concurrently, the log stays gapless.

- Receipts signed by a slow key service overlap: a log holds its lock only to
  take a position and to append, never while signing, and readers never wait
  on the signer.
- Signed receipts are appended in position order, as many as are ready with
  one write and one fsync.
- A signature that fails gives its position back and takes back every later
  one: their callers sign again for their new positions, so every receipt
  signs its own position and the log has no gaps. A write that fails is an
  error for every receipt it carried, and nothing of it is left in the file.
- A checkpoint the policy makes due is published in the background: a slow
  witness never holds up an issue, and closing the log publishes what is due.
"""

from __future__ import annotations

import asyncio
import functools
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from agentgov.exceptions import ReceiptLogError, SignerUnavailableError
from agentgov.receipts import (
    ActionReceipt,
    Checkpoint,
    CheckpointPolicy,
    Cosignature,
    Ed25519Signer,
    FileWitness,
    LogAnchor,
    ReceiptBundle,
    ReceiptLog,
    Verifier,
    load_cosignatures,
)

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
TEMPLATE = ReceiptBundle.loads(
    (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
).action_receipt
LOG_ID = "support-eu-1"
KEY = Ed25519Signer(bytes(range(32)))
WITNESS_KEY = Ed25519Signer(bytes(range(32, 64)))
NEVER = CheckpointPolicy(every_receipts=10**6, every_seconds=10**9)


def draft(n: int) -> ActionReceipt:
    return replace(
        TEMPLATE,
        receipt_id=str(uuid.UUID(int=n + 1)),
        anchors=replace(TEMPLATE.anchors, log=None),
        signature=None,
    )


def position(receipt: object) -> int:
    assert isinstance(receipt, ActionReceipt) and receipt.anchors.log is not None
    return receipt.anchors.log.leaf_index


def wait_until(condition: Callable[[], bool], seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError("timed out")
        time.sleep(0.002)


class GatedSigner:
    """Signs as ``KEY`` does. A message naming a held receipt id waits at its
    gate, and fails there if told to; any message waits ``latency``."""

    def __init__(self, latency: float = 0.0) -> None:
        self.latency = latency
        self.gates: dict[str, tuple[threading.Event, threading.Event]] = {}
        self.failing: set[str] = set()
        self.calls = 0
        self._lock = threading.Lock()

    @property
    def alg(self) -> str:
        return KEY.alg

    @property
    def key_id(self) -> str:
        return KEY.key_id

    def public_key(self) -> Verifier:
        return KEY.public_key()

    def verify(self, message: bytes, signature: bytes) -> bool:
        return KEY.verify(message, signature)

    def hold(
        self, receipt_id: str, *, fail: bool = False
    ) -> tuple[threading.Event, threading.Event]:
        """``(entered, release)`` for signatures of ``receipt_id``."""
        entered, release = threading.Event(), threading.Event()
        self.gates[receipt_id] = (entered, release)
        if fail:
            self.failing.add(receipt_id)
        return entered, release

    def sign(self, message: bytes) -> bytes:
        with self._lock:
            self.calls += 1
        for receipt_id, (entered, release) in self.gates.items():
            if receipt_id.encode() in message:
                entered.set()
                assert release.wait(10)
                if receipt_id in self.failing:
                    self.failing.discard(receipt_id)
                    raise SignerUnavailableError("the key service refused")
        if self.latency:
            time.sleep(self.latency)
        return KEY.sign(message)


class Run(threading.Thread):
    """``issue`` (or any call) on its own thread, keeping what it returned or raised."""

    def __init__(self, call: Callable[[], object]) -> None:
        super().__init__(daemon=True)
        self._call = call
        self.result: object = None
        self.error: BaseException | None = None
        self.start()

    def run(self) -> None:
        try:
            self.result = self._call()
        except BaseException as exc:  # the test inspects it
            self.error = exc

    def outcome(self) -> object:
        self.join(10)
        assert not self.is_alive()
        return self.error if self.error is not None else self.result


# -- signing overlaps --------------------------------------------------------------


def test_slow_signatures_overlap(tmp_path: Path) -> None:
    signer = GatedSigner(latency=0.05)
    with ReceiptLog(LOG_ID, signer, path=tmp_path / "r.jsonl", policy=NEVER) as log:
        began = time.monotonic()

        def four(n: int) -> list[ActionReceipt]:
            return [log.issue(draft(n * 4 + i)) for i in range(4)]

        runs = [Run(functools.partial(four, n)) for n in range(16)]
        issued = [r for run in runs for r in run.outcome()]  # type: ignore[attr-defined]
        took = time.monotonic() - began
        # 64 signatures of 50 ms, 16 at a time: about 0.2 s, against 3.2 s in turn.
        assert took < 1.2, f"64 receipts took {took:.2f}s"
        assert sorted(position(r) for r in issued) == list(range(64))
        assert log.receipts() == tuple(sorted(issued, key=position))
        assert not (log._held or log._held_ids or log._signed), "nothing held once issued"
    for receipt in issued:
        receipt.verify(KEY.public_key())
    with ReceiptLog(LOG_ID, KEY, path=tmp_path / "r.jsonl", policy=NEVER) as reopened:
        assert len(reopened) == 64


def test_readers_never_wait_on_the_signer() -> None:
    signer = GatedSigner()
    with ReceiptLog(LOG_ID, signer, policy=NEVER) as log:
        first = log.issue(draft(0))
        checkpoint = log.checkpoint()
        entered, release = signer.hold(draft(1).receipt_id)
        slow = Run(lambda: log.issue(draft(1)))
        assert entered.wait(5)
        began = time.monotonic()
        assert log.receipts() == (first,) and len(log) == 1
        assert log.bundle(0).checkpoint == checkpoint
        assert log.root() == checkpoint.root_hash
        assert log.index_of(first.receipt_id) == 0
        assert time.monotonic() - began < 1.0
        release.set()
        second = slow.outcome()
        assert isinstance(second, ActionReceipt) and second.anchors.log == LogAnchor(LOG_ID, 1)


def test_a_receipt_id_is_issued_once_even_while_it_is_being_signed() -> None:
    signer = GatedSigner()
    with ReceiptLog(LOG_ID, signer, policy=NEVER) as log:
        entered, release = signer.hold(draft(0).receipt_id)
        slow = Run(lambda: log.issue(draft(0)))
        assert entered.wait(5)
        with pytest.raises(ReceiptLogError, match=r"is being issued .* at index 0"):
            log.issue(draft(0))
        release.set()
        assert isinstance(slow.outcome(), ActionReceipt)
        with pytest.raises(ReceiptLogError, match="already in log"):
            log.issue(draft(0))


# -- in order, gapless -------------------------------------------------------------


def test_a_failed_signature_gives_back_its_position_and_later_ones_sign_again() -> None:
    signer = GatedSigner()
    with ReceiptLog(LOG_ID, signer, policy=NEVER) as log:
        entered, release = signer.hold(draft(0).receipt_id, fail=True)
        first = Run(lambda: log.issue(draft(0)))  # holds position 0, then fails
        assert entered.wait(5)
        second = Run(lambda: log.issue(draft(1)))  # signs position 1 and waits its turn
        wait_until(lambda: 1 in log._signed)
        release.set()
        assert isinstance(first.outcome(), SignerUnavailableError)
        moved = second.outcome()
        assert isinstance(moved, ActionReceipt)
        assert moved.anchors.log == LogAnchor(LOG_ID, 0), "it signed again for position 0"
        moved.verify(KEY.public_key())
        assert log.receipts() == (moved,)
        assert log.issue(draft(2)).anchors.log == LogAnchor(LOG_ID, 1)


def test_a_signature_that_fails_after_its_position_was_taken_back_gives_back_nothing_more() -> None:
    """0 and 1 sign at once and both fail, 0 first. 0's failure took back 1's
    position already, so 1's gives back nothing, and the next receipt takes 0."""
    signer = GatedSigner()
    with ReceiptLog(LOG_ID, signer, policy=NEVER) as log:
        entered_0, release_0 = signer.hold(draft(0).receipt_id, fail=True)
        entered_1, release_1 = signer.hold(draft(1).receipt_id, fail=True)
        first = Run(lambda: log.issue(draft(0)))
        assert entered_0.wait(5)
        second = Run(lambda: log.issue(draft(1)))
        assert entered_1.wait(5)
        release_0.set()
        assert isinstance(first.outcome(), SignerUnavailableError)
        release_1.set()
        assert isinstance(second.outcome(), SignerUnavailableError)
        assert position(Run(lambda: log.issue(draft(2))).outcome()) == 0


def test_a_signature_that_returns_after_its_position_was_taken_back_is_dropped() -> None:
    """1 is still signing when 0 fails and takes back 1's position: the
    signature for position 1 is dropped when it returns, and 1 signs again for
    position 0. The log holds it once."""
    signer = GatedSigner()
    with ReceiptLog(LOG_ID, signer, policy=NEVER) as log:
        entered_0, release_0 = signer.hold(draft(0).receipt_id, fail=True)
        entered_1, release_1 = signer.hold(draft(1).receipt_id)
        first = Run(lambda: log.issue(draft(0)))
        assert entered_0.wait(5)
        second = Run(lambda: log.issue(draft(1)))
        assert entered_1.wait(5)
        release_0.set()
        assert isinstance(first.outcome(), SignerUnavailableError)
        release_1.set()
        moved = second.outcome()
        assert position(moved) == 0
        assert log.receipts() == (moved,)
        assert signer.calls == 3, "0 once; 1 for position 1, then for position 0"


def test_a_receipt_signed_while_its_log_closes_is_not_appended(tmp_path: Path) -> None:
    """Closing releases the file to the next process to claim it: a signature
    that returns after that is refused, and the file is left as it was."""
    path = tmp_path / "r.jsonl"
    signer = GatedSigner()
    log = ReceiptLog(LOG_ID, signer, path=path, policy=NEVER)
    log.issue(draft(0))
    intact = path.read_bytes()
    entered, release = signer.hold(draft(1).receipt_id)
    late = Run(lambda: log.issue(draft(1)))
    assert entered.wait(5)
    log.close()
    release.set()
    refused = late.outcome()
    assert isinstance(refused, ReceiptLogError) and "is closed" in str(refused)
    assert path.read_bytes() == intact


def test_appended_receipts_share_one_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    syncs: list[int] = []
    real = os.fsync

    def counting(fd: int) -> None:
        syncs.append(fd)
        real(fd)

    monkeypatch.setattr("agentgov.receipts._leaves.os.fsync", counting)
    signer = GatedSigner()
    with ReceiptLog(LOG_ID, signer, path=tmp_path / "r.jsonl", policy=NEVER) as log:
        before = len(syncs)  # (opening the log synced its lock file)
        entered, release = signer.hold(draft(0).receipt_id)
        runs = [Run(lambda: log.issue(draft(0)))]
        assert entered.wait(5)
        runs += [Run(functools.partial(log.issue, draft(n))) for n in (1, 2, 3)]
        wait_until(lambda: len(log._signed) == 3)
        assert len(syncs) == before, "1 to 3 wait for 0, and write nothing"
        release.set()
        issued = [run.outcome() for run in runs]
        assert len(syncs) - before == 1, "four receipts, one fsync"
        assert [position(r) for r in issued] == [0, 1, 2, 3]


def test_a_failed_write_fails_every_receipt_it_carried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "r.jsonl"
    signer = GatedSigner()
    log = ReceiptLog(LOG_ID, signer, path=path, policy=NEVER)
    entered, release = signer.hold(draft(0).receipt_id)
    first = Run(lambda: log.issue(draft(0)))
    assert entered.wait(5)
    second = Run(lambda: log.issue(draft(1)))
    wait_until(lambda: 1 in log._signed)

    def failing(fd: int) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("agentgov.receipts._leaves.os.fsync", failing)
    release.set()
    own, carried = first.outcome(), second.outcome()
    assert isinstance(own, OSError) and "No space" in str(own)
    assert isinstance(carried, ReceiptLogError) and isinstance(carried.__cause__, OSError)
    assert "was not issued: the log could not be written" in str(carried)
    assert len(log) == 0 and path.read_bytes() == b""
    monkeypatch.undo()
    assert [position(log.issue(draft(n))) for n in (0, 1)] == [0, 1]
    log.close()


def test_a_receipt_signed_elsewhere_cannot_move_when_a_position_before_it_fails() -> None:
    signer = GatedSigner()
    with ReceiptLog(LOG_ID, signer, policy=NEVER) as log:
        entered, release = signer.hold(draft(0).receipt_id, fail=True)
        first = Run(lambda: log.issue(draft(0)))
        assert entered.wait(5)
        signed_elsewhere = draft(1).with_log_anchor(LOG_ID, 1).sign(KEY)
        appended = Run(lambda: log.append(signed_elsewhere))
        wait_until(lambda: 1 in log._signed)
        release.set()
        assert isinstance(first.outcome(), SignerUnavailableError)
        refused = appended.outcome()
        assert isinstance(refused, ReceiptLogError)
        assert "sign it again for index 0" in str(refused)
        assert len(log) == 0


# -- publishing in the background --------------------------------------------------


class SlowWitness:
    """A witness whose cosignature waits for a gate."""

    def __init__(self, inner: FileWitness) -> None:
        self.inner = inner
        self.gate = threading.Event()
        self.asked = threading.Event()

    @property
    def witness_id(self) -> str:
        return self.inner.witness_id

    def latest(self, log_id: str) -> Cosignature | None:
        return self.inner.latest(log_id)

    def cosign(self, checkpoint: Checkpoint, proof: Sequence[bytes]) -> Cosignature:
        self.asked.set()
        assert self.gate.wait(10)
        return self.inner.cosign(checkpoint, proof)


def test_a_slow_witness_never_holds_up_an_issue(tmp_path: Path) -> None:
    inner = FileWitness(
        tmp_path / "w.jsonl", WITNESS_KEY, witness_id="w", logs={LOG_ID: KEY.public_key()}
    )
    witness = SlowWitness(inner)
    every_two = CheckpointPolicy(every_receipts=2, every_seconds=10**9)
    with ReceiptLog(LOG_ID, KEY, witnesses=[witness], policy=every_two) as log:
        began = time.monotonic()
        for n in range(2):
            log.issue(draft(n))
        assert witness.asked.wait(5), "the publisher asked the witness"
        log.issue(draft(2))
        assert time.monotonic() - began < 1.0, "no issue waited for the witness"
        witness.gate.set()
        log.flush()
        assert [c.tree_size for c in log.checkpoints()][:1] == [2]
    assert [c.tree_size for c in load_cosignatures(tmp_path / "w.jsonl")][:1] == [2]


def test_closing_a_log_publishes_what_is_due(tmp_path: Path) -> None:
    witness = FileWitness(
        tmp_path / "w.jsonl", WITNESS_KEY, witness_id="w", logs={LOG_ID: KEY.public_key()}
    )
    every_two = CheckpointPolicy(every_receipts=2, every_seconds=10**9)
    log = ReceiptLog(LOG_ID, KEY, path=tmp_path / "r.jsonl", witnesses=[witness], policy=every_two)
    for n in range(4):
        log.issue(draft(n))
    log.close()
    log.close()  # idempotent
    assert load_cosignatures(tmp_path / "w.jsonl")[-1].tree_size == 4
    with pytest.raises(ReceiptLogError, match="is closed"):
        log.checkpoints()  # a closed durable log reads nothing, as a closed file does
    with ReceiptLog(LOG_ID, KEY, path=tmp_path / "r.jsonl", policy=every_two) as reopened:
        assert reopened.checkpoints()[-1].tree_size == 4


def test_flush_publishes_a_due_checkpoint_now() -> None:
    every_two = CheckpointPolicy(every_receipts=2, every_seconds=10**9)
    with ReceiptLog(LOG_ID, KEY, policy=every_two) as log:
        for n in range(2):
            log.issue(draft(n))
        log.flush()
        assert log.checkpoints()[-1].tree_size == 2
        log.flush()  # nothing due: nothing published
        assert len(log.checkpoints()) == 1


def test_a_flush_finds_the_checkpoint_due_or_waits_for_its_publication() -> None:
    """The publisher takes a due checkpoint under the publish lock. Taken
    before it, a flush in between would find nothing due and nothing being
    published, and return before the checkpoint existed."""
    every_two = CheckpointPolicy(every_receipts=2, every_seconds=10**9)
    with ReceiptLog(LOG_ID, KEY, policy=every_two) as log:
        with log._publish_lock:  # a publication in progress, to the publisher
            for n in range(2):
                log.issue(draft(n))
            time.sleep(0.2)  # the publisher has woken, and waits
            assert log._due, "the publisher took the checkpoint it could not yet publish"
        log.flush()
        assert log.checkpoints()[-1].tree_size == 2


def test_an_issue_that_made_nothing_due_does_not_wait_on_a_publication() -> None:
    """One publication runs at a time, and issuing goes on meanwhile: without
    a background publisher, an issue publishes only what it made due."""
    inline = CheckpointPolicy(every_receipts=10, every_seconds=10**9, background=False)
    with ReceiptLog(LOG_ID, KEY, policy=inline) as log:
        with log._publish_lock:  # a publication in progress
            issuer = threading.Thread(target=log.issue, args=(draft(0),))
            issuer.start()
            issuer.join(5)
            assert not issuer.is_alive(), "the issue waited on the publication"
        assert len(log) == 1 and log.checkpoints() == ()


def test_issues_that_find_their_checkpoint_published_publish_nothing_more() -> None:
    """Two issues that each made a checkpoint due wait for the publication in
    progress. The first to follow it publishes both; the second finds nothing
    left to publish."""
    inline = CheckpointPolicy(every_receipts=1, every_seconds=10**9, background=False)
    with ReceiptLog(LOG_ID, KEY, policy=inline) as log:
        with log._publish_lock:  # a publication in progress
            issuers = [threading.Thread(target=log.issue, args=(draft(n),)) for n in range(2)]
            for issuer in issuers:
                issuer.start()
            for _ in range(500):
                if len(log) == 2:
                    break
                time.sleep(0.01)
            time.sleep(0.2)  # both appended, and both waiting to publish
        for issuer in issuers:
            issuer.join(5)
        assert [c.tree_size for c in log.checkpoints()] == [2]


# -- from a coroutine --------------------------------------------------------------


class AsyncKey:
    """An async signer: 50 ms a signature, awaited; its sync path is never used."""

    alg = KEY.alg
    key_id = KEY.key_id

    def public_key(self) -> Verifier:
        return KEY.public_key()

    def sign(self, message: bytes) -> bytes:
        raise AssertionError("issue_async signed synchronously")

    def verify(self, message: bytes, signature: bytes) -> bool:
        return KEY.verify(message, signature)

    async def sign_async(self, message: bytes) -> bytes:
        await asyncio.sleep(0.05)
        return KEY.sign(message)


def test_issue_async_signs_without_blocking_the_loop(tmp_path: Path) -> None:
    log = ReceiptLog(LOG_ID, AsyncKey(), path=tmp_path / "r.jsonl", policy=NEVER)

    async def main() -> tuple[float, int, list[ActionReceipt]]:
        ticks = 0
        done = asyncio.Event()

        async def tick() -> None:
            nonlocal ticks
            while not done.is_set():
                ticks += 1
                await asyncio.sleep(0.005)

        ticker = asyncio.create_task(tick())
        began = time.monotonic()
        issued = await asyncio.gather(*(log.issue_async(draft(n)) for n in range(32)))
        took = time.monotonic() - began
        done.set()
        await ticker
        return took, ticks, list(issued)

    try:
        took, ticks, issued = asyncio.run(main())
    finally:
        log.close()
    assert took < 1.0, f"32 receipts took {took:.2f}s"  # about 0.05 s; 1.6 s in turn
    assert ticks >= 5
    assert sorted(position(r) for r in issued) == list(range(32))
    for receipt in issued:
        receipt.verify(KEY.public_key())


def test_issue_async_gives_back_a_position_when_signing_fails() -> None:
    class Refusing(AsyncKey):
        async def sign_async(self, message: bytes) -> bytes:
            raise SignerUnavailableError("the key service refused")

    with ReceiptLog(LOG_ID, Refusing(), policy=NEVER) as log:
        with pytest.raises(SignerUnavailableError):
            asyncio.run(log.issue_async(draft(0)))
        assert log._held == {} and log._next == 0
