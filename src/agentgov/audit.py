"""The auditor: the whole chain replayed from genesis, off the hot path.

A governor opens from its ledger's newest checkpoint: it verifies that
checkpoint's snapshot by digest and replays only the entries after it, so
opening costs time bounded by the entries since that checkpoint, however long
the ledger. What came before the snapshot it does not replay. That is the
auditor's work, and this is the auditor.

It replays the chain from genesis, a chunk at a time and holding no lock, by
exactly the rules every write and replay follows (``agentgov.core``), and at
every checkpoint it checks that the snapshot stored there is the state the
chain implies at that sequence. Each checkpoint it verifies, and the head it
reaches, it records as a mark in the ledger's own database
(:class:`~agentgov.storage.AuditMark`). The next run resumes from the newest
verified mark, so the replay from genesis is paid once per ledger, not once
per process.

A mismatch, or any entry that does not verify, is recorded as a failure. Every
governor of the ledger then refuses to open for writing, and a governor whose
auditor found it stops writing at once: the same fail-closed behaviour an
unverifiable catch-up has. A later run that verifies the chain past the
failure supersedes it.

Run it beside a fleet as ``agentgov audit --follow <ledger>``; a governor that
opened from a checkpoint also runs one in a thread of its own (see
:class:`~agentgov.core.BudgetManager`), throttled to a fraction of one core.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from agentgov.core import (
    CheckpointSigning,
    _ChainState,
    _decode_snapshot,
    _encode_snapshot,
    _Overlay,
    _snapshot_digest,
)
from agentgov.exceptions import LedgerIntegrityError
from agentgov.storage import AuditMark

__all__ = ["AuditReport", "Auditor", "AuditorThread"]


class _StoppedError(Exception):
    """The run was asked to stop part-way; nothing is recorded for it."""


logger = logging.getLogger("agentgov.audit")


@dataclass(frozen=True, slots=True)
class AuditReport:
    """What one run of the auditor did.

    :ivar resumed_from: The sequence the run started after: a mark an earlier
        run verified, or 0 (genesis).
    :ivar verified_to: The last sequence it verified.
    :ivar head: That entry's hash.
    :ivar entries: How many entries it replayed.
    :ivar checkpoints: How many checkpoint snapshots it checked.
    :ivar failure: Why the chain did not verify, if it did not.
    """

    resumed_from: int
    verified_to: int
    head: str
    entries: int
    checkpoints: int
    failure: str | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None


class Auditor:
    """Replays a ledger's chain from genesis and records what it finds.

    :param store: The ledger's store. It needs the history interface
        (``iter_entries``, ``checkpoints``, ``snapshot_at``) and somewhere to
        record marks (``record_audit``), which both bundled stores have.
    :param name: Who is auditing, recorded in every mark; host and process by
        default.
    :param chunk: Entries read from the store at a time.
    :param duty: The share of one core to use, between 0 (exclusive) and 1.
        Below 1 the auditor sleeps between chunks, so a thread inside a busy
        governor takes no more than its share of the interpreter.
    :param record: Record marks in the store. Off for a one-off check that
        should leave the database exactly as it found it.
    :param signing: Check each snapshot's signed statement too (see
        :class:`~agentgov.core.CheckpointSigning`).
    """

    def __init__(
        self,
        store: Any,
        *,
        name: str | None = None,
        chunk: int = 10_000,
        duty: float = 1.0,
        record: bool = True,
        signing: CheckpointSigning | None = None,
    ) -> None:
        if not 0 < duty <= 1:
            raise ValueError(f"duty must be in (0, 1], got {duty}")
        if chunk < 1:
            raise ValueError(f"chunk must be positive, got {chunk}")
        self._store = store
        self._name = name or f"{socket.gethostname()}:{os.getpid()}"
        self._chunk = chunk
        self._duty = duty
        self._record = record
        self._signing = signing
        self._first: str | None = None
        self._stop: threading.Event | None = None

    # -- one run ------------------------------------------------------------

    def run(self, *, from_genesis: bool = False) -> AuditReport:
        """Verify the chain from the newest trusted mark (or genesis) to the
        head, and every checkpoint snapshot on the way.

        :param from_genesis: Ignore earlier marks and replay everything.
        """
        store = self._store
        length, head = store.head()
        checkpoints = {s: digest for _, s, digest in store.checkpoints() if s <= length}
        legacy = tuple(e for e in store.control_events() if e.entry_id is None)
        if from_genesis:
            state, start = _ChainState(legacy=legacy), 0
        else:
            state, start = self._resume(checkpoints, legacy)
        position, verified, replayed = start, 0, 0
        try:
            view = _Overlay(state, resolve=store.entry_by_id)
            for entry in self._entries(start, length):
                view.apply(entry)
                position = entry.sequence
                replayed += 1
                if position in checkpoints:
                    # A checkpoint is written between units of work, so its
                    # sequence ends a transaction: fold the view in and check.
                    view.end_transaction()
                    view.merge()
                    self._check_snapshot(state, checkpoints[position])
                    verified += 1
                    self._mark(state, "verified", f"checkpoint at {position} matches the chain")
                    view = _Overlay(state, resolve=store.entry_by_id)
            view.end_transaction()
            view.merge()
            if state.length != length or state.head != head:
                raise LedgerIntegrityError(
                    f"the chain ends at {state.length} ({state.head[:16]}), not at the head the "
                    f"store reported ({length}, {head[:16]})"
                )
        except _StoppedError:
            return AuditReport(start, position, state.head, replayed, verified)
        except LedgerIntegrityError as exc:
            detail = f"at sequence {position + 1}: {exc}"
            self._mark(state, "failed", detail, sequence=position + 1)
            logger.error("audit of the ledger failed %s", detail)
            return AuditReport(start, position, state.head, replayed, verified, failure=detail)
        if replayed:
            self._mark(state, "verified", f"replayed {replayed} entries from {start}")
        return AuditReport(start, state.length, state.head, replayed, verified)

    def _entries(self, start: int, until: int) -> Iterator[Any]:
        """The entries after ``start``, a chunk at a time, throttled to the duty."""
        began = time.monotonic()
        count = 0
        for entry in self._store.iter_entries(after=start, until=until, chunk=self._chunk):
            yield entry
            count += 1
            if count % self._chunk == 0 and self._stop is not None and self._stop.is_set():
                raise _StoppedError
            if self._duty < 1 and count % self._chunk == 0:
                busy = time.monotonic() - began
                time.sleep(busy * (1 / self._duty - 1))
                began = time.monotonic()

    def _resume(
        self, checkpoints: dict[int, str], legacy: tuple[Any, ...]
    ) -> tuple[_ChainState, int]:
        """The state to start from: the snapshot at the newest checkpoint an
        earlier run verified, or nothing (genesis)."""
        for mark in reversed(self._store.audit_marks()):
            if mark.status != "verified" or checkpoints.get(mark.sequence) != mark.state_digest:
                continue
            snapshot = self._store.snapshot_at(mark.sequence)
            if snapshot is None or _snapshot_digest(snapshot.body) != mark.state_digest:
                continue
            try:
                return _decode_snapshot(snapshot.body), mark.sequence
            except LedgerIntegrityError:
                continue
        return _ChainState(legacy=legacy), 0

    def _check_snapshot(self, state: _ChainState, digest: str) -> None:
        """The snapshot a checkpoint names must be the state the chain implies."""
        body = _encode_snapshot(state)
        derived = _snapshot_digest(body)
        if derived != digest:
            raise LedgerIntegrityError(
                f"the checkpoint of sequence {state.length} commits to snapshot {digest[:16]}, "
                f"but the state the chain implies there is {derived[:16]}"
            )
        stored = self._store.snapshot_at(state.length)
        if stored is None or stored.body != body or stored.digest != digest:
            raise LedgerIntegrityError(
                f"the snapshot stored for sequence {state.length} is not the state the chain "
                f"implies there"
            )
        if self._signing is not None:
            if self._first is None:
                first = self._store.entry_at(1)
                self._first = first.entry_hash if first is not None else ""
            self._signing.check(stored, state, self._first)

    def _mark(
        self, state: _ChainState, status: str, detail: str, *, sequence: int | None = None
    ) -> None:
        if not self._record:
            return
        digest = _snapshot_digest(_encode_snapshot(state)) if status == "verified" else ""
        try:
            self._store.record_audit(
                AuditMark(
                    sequence=state.length if sequence is None else sequence,
                    head=state.head,
                    state_digest=digest,
                    status=status,
                    detail=detail,
                    auditor=self._name,
                    recorded_at=datetime.now(UTC),
                )
            )
        except Exception:
            logger.warning("could not record an audit mark", exc_info=True)

    # -- following ----------------------------------------------------------

    def follow(
        self,
        *,
        interval: float = 5.0,
        stop: threading.Event | None = None,
        on_failure: Callable[[str], None] | None = None,
    ) -> AuditReport:
        """Audit, then keep auditing what is written, every ``interval``
        seconds, until ``stop`` is set or the chain fails to verify.

        :returns: The last run's report: a failure, or the run in progress
            when ``stop`` was set.
        """
        stop = stop if stop is not None else threading.Event()
        self._stop = stop
        report = self.run()
        while report.ok and not stop.wait(interval):
            report = self.run()
        if not report.ok and on_failure is not None and report.failure is not None:
            on_failure(report.failure)
        return report


class AuditorThread:
    """An :class:`Auditor` following a ledger from a daemon thread.

    :param store: A store of the ledger's own, on its own connection (see the
        stores' ``fork()``); closed when the thread stops.
    :param on_failure: Called, from the thread, with what failed to verify.
    """

    def __init__(
        self,
        store: Any,
        *,
        interval: float = 5.0,
        duty: float = 0.25,
        on_failure: Callable[[str], None] | None = None,
        signing: CheckpointSigning | None = None,
    ) -> None:
        self._store = store
        self._stop = threading.Event()
        self._auditor = Auditor(store, duty=duty, signing=signing)
        self._interval = interval
        self._on_failure = on_failure
        self._thread = threading.Thread(target=self._run, name="agentgov-auditor", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        try:
            self._auditor.follow(
                interval=self._interval, stop=self._stop, on_failure=self._on_failure
            )
        except Exception:  # an auditor that cannot run reports, never kills the governor
            logger.warning("the in-process auditor stopped", exc_info=True)
        finally:
            try:
                self._store.close()
            except Exception:  # pragma: no cover - best effort
                logger.debug("closing the auditor's store failed", exc_info=True)

    def stop(self, timeout: float = 10.0) -> None:
        """Stop following and wait for the thread to end."""
        self._stop.set()
        self._thread.join(timeout)

    @property
    def alive(self) -> bool:
        return self._thread.is_alive()
