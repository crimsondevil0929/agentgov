"""Durable backends for the ledger and budget topology.

Phase 1's :class:`~agentgov.core.Ledger` and :class:`~agentgov.core.BudgetManager`
hold their state in memory, guarded by one mutex — correct, but gone the instant
the process exits. This module adds a write-through persistence layer behind
that same lock, so a governor's ledger, topology, control events, and open
authorizations survive a restart without changing any of the concurrency or
atomicity guarantees the in-memory design already provides.

:class:`PersistenceStore` is the seam: :class:`SqliteStore` is the only
implementation today, built on the standard library's ``sqlite3`` (so
persistence adds zero runtime dependencies), but the interface is the natural
place a future distributed backend — the multi-node consensus store the
project roadmap describes — would plug in instead.

Every write happens *before* the corresponding in-memory mutation in
:mod:`agentgov.core`, and every reader-facing figure this file writes has
already been quantized and validated by :mod:`agentgov.core`. This module
does not reinterpret money: amounts round-trip through ``TEXT`` columns as
the exact ``Decimal`` string :mod:`agentgov.core` already produced, never
through a floating-point column type.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import sys
import uuid
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Protocol

from agentgov.core import ControlEvent, Direction, EntryType, LedgerEntry, _iso, _parse_iso
from agentgov.exceptions import (
    ConcurrentGovernorError,
    LedgerIntegrityError,
    ReadOnlyLedgerError,
    StorageError,
)

__all__ = [
    "PersistedAuthorization",
    "PersistedNode",
    "PersistenceStore",
    "SqliteStore",
]

_SCHEMA_VERSION = "1"


@dataclass(frozen=True, slots=True)
class PersistedNode:
    """A budget scope's topology, as read back from a store.

    Mirrors the fields of :class:`~agentgov.core.BudgetNode` that are
    provenance rather than derived — ``child_ids`` is rebuilt by the caller
    by scanning every node's ``parent_id``, not stored redundantly.
    """

    scope_id: str
    parent_id: str | None
    depth: int
    allocated: Decimal
    created_at: datetime


@dataclass(frozen=True, slots=True)
class PersistedAuthorization:
    """An outstanding authorization hold, as read back from a store.

    ``entry_id`` identifies the :attr:`~agentgov.core.EntryType.HOLD` ledger
    entry that encumbered the funds; the caller resolves it against the
    already-loaded ledger to reconstruct a full
    :class:`~agentgov.core.Authorization`.
    """

    authorization_id: uuid.UUID
    scope_id: str
    amount: Decimal
    opened_at: datetime
    entry_id: uuid.UUID


class PersistenceStore(Protocol):
    """The durability seam a :class:`~agentgov.core.Ledger` and
    :class:`~agentgov.core.BudgetManager` write through to.

    Every method here is called with the manager's own lock held, so an
    implementation never needs to provide its own concurrency control — it
    only needs to make each individual call durable. A distributed backend
    (the Phase 2 multi-node consensus store) implements this same interface
    with a replicated write in place of a local file.
    """

    def append_entries(self, entries: Sequence[LedgerEntry]) -> None:
        """Durably append ``entries``. Must be all-or-nothing.

        :raises Exception: Any failure must propagate — a caller that
            catches this and continues would commit to memory a transaction
            that was never made durable.
        """
        ...

    def load_entries(self) -> tuple[LedgerEntry, ...]:
        """Return every previously persisted entry, oldest first."""
        ...

    def upsert_node(
        self,
        scope_id: str,
        parent_id: str | None,
        depth: int,
        allocated: Decimal,
        created_at: datetime,
    ) -> None:
        """Durably record a scope's current topology and lifetime allocation."""
        ...

    def load_nodes(self) -> tuple[PersistedNode, ...]:
        """Return every persisted scope's topology, in no particular order."""
        ...

    def append_control_event(self, event: ControlEvent) -> None:
        """Durably record a circuit-breaker trip or reset."""
        ...

    def load_control_events(self) -> tuple[ControlEvent, ...]:
        """Return every persisted control event, oldest first."""
        ...

    def put_authorization(
        self,
        authorization_id: uuid.UUID,
        scope_id: str,
        amount: Decimal,
        opened_at: datetime,
        entry_id: uuid.UUID,
    ) -> None:
        """Durably record a newly placed authorization hold."""
        ...

    def delete_authorization(self, authorization_id: uuid.UUID) -> None:
        """Remove a settled or voided authorization hold."""
        ...

    def load_open_authorizations(self) -> tuple[PersistedAuthorization, ...]:
        """Return every hold that was never settled or voided, in no
        particular order — a restart-time reconciliation list as much as a
        recovery mechanism: a hold present here after a long-dead process
        exited is a candidate for an operator to void by hand."""
        ...

    def close(self) -> None:
        """Release any underlying connection. Safe to call more than once."""
        ...


class _AdvisoryLock:
    """An OS-level exclusive claim on a governor's database file.

    Uses a sidecar ``<db>.lock`` file rather than locking the database
    itself, so the claim lives in a different lock space from the record
    locks SQLite takes internally and the two can never be confused for one
    another.

    The lock is held by an open file descriptor, which means the kernel
    releases it when the holding process exits — including on ``SIGKILL``.
    A crashed governor therefore leaves a stale *file* but never a stale
    *lock*, so no timeout heuristic or manual cleanup is needed.

    The holder writes its identity into the file so the next process can say
    who is holding it, not merely that someone is.

    :param db_path: Path to the database being claimed.
    """

    __slots__ = ("_fd", "_path")

    def __init__(self, db_path: str) -> None:
        self._path = f"{db_path}.lock"
        self._fd: int | None = None

    def acquire(self) -> None:
        """Claim the database, or raise naming the process that holds it.

        :raises ConcurrentGovernorError: If another process holds the claim.
        :raises StorageError: If the lock file cannot be created at all.
        """
        try:
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError as exc:
            raise StorageError(f"cannot create lock file {self._path!r}: {exc}") from exc

        try:
            _lock_exclusive_nonblocking(fd)
        except BlockingIOError as exc:
            holder = self._read_holder()
            os.close(fd)
            raise ConcurrentGovernorError(self._path[: -len(".lock")], *holder) from exc
        except OSError as exc:
            os.close(fd)
            # A filesystem with no working lock support (some network mounts).
            # Failing loudly beats pretending the claim succeeded.
            raise StorageError(
                f"cannot lock {self._path!r}: {exc}. This filesystem may not support "
                f"advisory locking; run the governor on local storage."
            ) from exc

        self._fd = fd
        self._write_identity(fd)

    def _write_identity(self, fd: int) -> None:
        """Record who holds the lock, for the next process's error message."""
        payload = json.dumps(
            {
                "pid": os.getpid(),
                "host": socket.gethostname(),
                "since": datetime.now(UTC).isoformat(timespec="seconds"),
            }
        )
        with suppress(OSError):
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)

    def _read_holder(self) -> tuple[int | None, str | None, str | None]:
        """Best-effort read of the holder's identity. Never raises."""
        try:
            raw = Path(self._path).read_text(encoding="utf-8")
            record = json.loads(raw)
            pid = record.get("pid")
            return (
                int(pid) if isinstance(pid, int) else None,
                record.get("host"),
                record.get("since"),
            )
        except (OSError, ValueError, TypeError, AttributeError):
            # A holder that has not written yet, or a truncated file. Report
            # the contention without the identity rather than not at all.
            return (None, None, None)

    def release(self) -> None:
        """Drop the claim. Idempotent."""
        if self._fd is None:
            return
        fd, self._fd = self._fd, None
        with suppress(OSError):
            _unlock(fd)
        with suppress(OSError):
            os.close(fd)


if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI only

    def _lock_exclusive_nonblocking(fd: int) -> None:
        import msvcrt

        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            # Windows reports contention as EACCES/EDEADLOCK rather than
            # EWOULDBLOCK; normalise so the caller has one thing to catch.
            raise BlockingIOError(str(exc)) from exc

    def _unlock(fd: int) -> None:
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)

else:

    def _lock_exclusive_nonblocking(fd: int) -> None:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fd: int) -> None:
        import fcntl

        fcntl.flock(fd, fcntl.LOCK_UN)


class SqliteStore:
    """A :class:`PersistenceStore` backed by a local SQLite database file.

    Uses only the standard library's ``sqlite3`` module, so enabling
    persistence adds no runtime dependency. All reads and writes happen with
    the owning :class:`~agentgov.core.Ledger`/:class:`~agentgov.core.BudgetManager`
    lock already held, so this class does no locking of its own — the
    connection is opened with ``check_same_thread=False`` on that basis, not
    because SQLite is safe to share across threads unsupervised.

    :param path: Filesystem path to the database file, or ``":memory:"`` for
        a store that never touches disk (useful in tests; does not survive
        a restart, since there is nothing on disk to restart from).
    :param synchronous: SQLite's ``synchronous`` pragma. ``"FULL"`` (the
        default) fsyncs on every commit, surviving a power loss and not just
        a process crash, at the cost of per-commit write latency.
        ``"NORMAL"`` skips most of those fsyncs — still crash-safe under
        WAL, but a full power loss can lose the most recent commits.
    :raises LedgerIntegrityError: If the file exists but was written by an
        incompatible schema version.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        synchronous: str = "FULL",
        read_only: bool = False,
    ) -> None:
        self._path = str(path)
        self._read_only = read_only
        self._lock: _AdvisoryLock | None = None

        if read_only:
            # No exclusive claim: read-only exists precisely so an operator can
            # look at a database another process is actively governing.
            try:
                self._conn = sqlite3.connect(
                    f"file:{self._path}?mode=ro", uri=True, check_same_thread=False
                )
            except sqlite3.OperationalError as exc:
                raise StorageError(
                    f"cannot open {self._path!r} read-only: {exc}. The file may not "
                    f"exist, or may not be readable by this user."
                ) from exc
            self._verify_schema_version()
            return

        # Claim the database before opening it for writing. Two governors on
        # one file would each cache authoritative balances in memory and
        # diverge; refusing the second at open turns that into an operational
        # error with a remedy, rather than a UNIQUE-constraint failure on its
        # first write that reads like a corrupted audit chain.
        if self._path != ":memory:" and not self._path.startswith("file::memory:"):
            self._lock = _AdvisoryLock(self._path)
            self._lock.acquire()
        try:
            self._conn = sqlite3.connect(self._path, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.execute(f"PRAGMA synchronous = {synchronous}")
            self._conn.execute("PRAGMA foreign_keys = ON")
            self._init_schema()
        except BaseException:
            if self._lock is not None:
                self._lock.release()
            raise

    @property
    def read_only(self) -> bool:
        """Whether this store refuses writes."""
        return self._read_only

    def _require_writable(self, operation: str) -> None:
        """Refuse a mutation up front rather than deep inside a transaction."""
        if self._read_only:
            raise ReadOnlyLedgerError(operation)

    def _verify_schema_version(self) -> None:
        """Check the schema version without creating anything (read-only path)."""
        try:
            row = self._conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.OperationalError as exc:
            raise StorageError(
                f"{self._path!r} is not an agentgov database (or is empty): {exc}"
            ) from exc
        if row is not None and row[0] != _SCHEMA_VERSION:
            raise LedgerIntegrityError(
                f"database schema version {row[0]!r} does not match "
                f"this version of agentgov ({_SCHEMA_VERSION!r}); "
                f"refusing to open a file this version cannot interpret"
            )

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = self._conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
                    (_SCHEMA_VERSION,),
                )
            elif row[0] != _SCHEMA_VERSION:
                raise LedgerIntegrityError(
                    f"database schema version {row[0]!r} does not match "
                    f"this version of agentgov ({_SCHEMA_VERSION!r}); "
                    f"refusing to open a file this version cannot interpret"
                )

            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS entries (
                    sequence        INTEGER PRIMARY KEY,
                    entry_id        TEXT NOT NULL UNIQUE,
                    transaction_id  TEXT NOT NULL,
                    timestamp       TEXT NOT NULL,
                    entry_type      TEXT NOT NULL,
                    direction       TEXT NOT NULL,
                    scope_id        TEXT NOT NULL,
                    counterparty_id TEXT,
                    amount          TEXT NOT NULL,
                    balance_after   TEXT NOT NULL,
                    prev_hash       TEXT NOT NULL,
                    entry_hash      TEXT NOT NULL,
                    memo            TEXT NOT NULL DEFAULT ''
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    scope_id   TEXT PRIMARY KEY,
                    parent_id  TEXT,
                    depth      INTEGER NOT NULL,
                    allocated  TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS control_events (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id          TEXT NOT NULL UNIQUE,
                    timestamp         TEXT NOT NULL,
                    event_type        TEXT NOT NULL,
                    scope_id          TEXT NOT NULL,
                    reason            TEXT NOT NULL,
                    ledger_head_hash  TEXT NOT NULL
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS open_authorizations (
                    authorization_id TEXT PRIMARY KEY,
                    scope_id         TEXT NOT NULL,
                    amount           TEXT NOT NULL,
                    opened_at        TEXT NOT NULL,
                    entry_id         TEXT NOT NULL
                )
                """
            )

    # -- ledger entries -----------------------------------------------------

    def append_entries(self, entries: Sequence[LedgerEntry]) -> None:
        self._require_writable("append ledger entries")
        try:
            with self._conn:
                self._conn.executemany(
                    """
                    INSERT INTO entries (
                        sequence, entry_id, transaction_id, timestamp, entry_type,
                        direction, scope_id, counterparty_id, amount, balance_after,
                        prev_hash, entry_hash, memo
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            e.sequence,
                            str(e.entry_id),
                            str(e.transaction_id),
                            _iso(e.timestamp),
                            e.entry_type.value,
                            e.direction.value,
                            e.scope_id,
                            e.counterparty_id,
                            str(e.amount),
                            str(e.balance_after),
                            e.prev_hash,
                            e.entry_hash,
                            e.memo,
                        )
                        for e in entries
                    ],
                )
        except sqlite3.IntegrityError as exc:
            raise LedgerIntegrityError(
                f"failed to durably append {len(entries)} entr"
                f"{'y' if len(entries) == 1 else 'ies'}: {exc}"
            ) from exc

    def load_entries(self) -> tuple[LedgerEntry, ...]:
        rows = self._conn.execute(
            """
            SELECT sequence, entry_id, transaction_id, timestamp, entry_type,
                   direction, scope_id, counterparty_id, amount, balance_after,
                   prev_hash, entry_hash, memo
            FROM entries ORDER BY sequence ASC
            """
        ).fetchall()
        return tuple(
            LedgerEntry(
                sequence=row[0],
                entry_id=uuid.UUID(row[1]),
                transaction_id=uuid.UUID(row[2]),
                timestamp=_parse_iso(row[3]),
                entry_type=EntryType(row[4]),
                direction=Direction(row[5]),
                scope_id=row[6],
                counterparty_id=row[7],
                amount=Decimal(row[8]),
                balance_after=Decimal(row[9]),
                prev_hash=row[10],
                entry_hash=row[11],
                memo=row[12],
            )
            for row in rows
        )

    # -- topology -------------------------------------------------------

    def upsert_node(
        self,
        scope_id: str,
        parent_id: str | None,
        depth: int,
        allocated: Decimal,
        created_at: datetime,
    ) -> None:
        self._require_writable("record a budget scope")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO nodes (scope_id, parent_id, depth, allocated, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(scope_id) DO UPDATE SET
                    parent_id = excluded.parent_id,
                    depth = excluded.depth,
                    allocated = excluded.allocated
                """,
                (scope_id, parent_id, depth, str(allocated), _iso(created_at)),
            )

    def load_nodes(self) -> tuple[PersistedNode, ...]:
        rows = self._conn.execute(
            "SELECT scope_id, parent_id, depth, allocated, created_at FROM nodes"
        ).fetchall()
        return tuple(
            PersistedNode(
                scope_id=row[0],
                parent_id=row[1],
                depth=row[2],
                allocated=Decimal(row[3]),
                created_at=_parse_iso(row[4]),
            )
            for row in rows
        )

    # -- control events -------------------------------------------------

    def append_control_event(self, event: ControlEvent) -> None:
        self._require_writable("record a control event")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO control_events
                    (event_id, timestamp, event_type, scope_id, reason, ledger_head_hash)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(event.event_id),
                    _iso(event.timestamp),
                    event.event_type,
                    event.scope_id,
                    event.reason,
                    event.ledger_head_hash,
                ),
            )

    def load_control_events(self) -> tuple[ControlEvent, ...]:
        rows = self._conn.execute(
            """
            SELECT event_id, timestamp, event_type, scope_id, reason, ledger_head_hash
            FROM control_events ORDER BY id ASC
            """
        ).fetchall()
        return tuple(
            ControlEvent(
                event_id=uuid.UUID(row[0]),
                timestamp=_parse_iso(row[1]),
                event_type=row[2],
                scope_id=row[3],
                reason=row[4],
                ledger_head_hash=row[5],
            )
            for row in rows
        )

    # -- open authorizations ---------------------------------------------

    def put_authorization(
        self,
        authorization_id: uuid.UUID,
        scope_id: str,
        amount: Decimal,
        opened_at: datetime,
        entry_id: uuid.UUID,
    ) -> None:
        self._require_writable("record an authorization")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO open_authorizations
                    (authorization_id, scope_id, amount, opened_at, entry_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(authorization_id), scope_id, str(amount), _iso(opened_at), str(entry_id)),
            )

    def delete_authorization(self, authorization_id: uuid.UUID) -> None:
        self._require_writable("settle an authorization")
        with self._conn:
            self._conn.execute(
                "DELETE FROM open_authorizations WHERE authorization_id = ?",
                (str(authorization_id),),
            )

    def load_open_authorizations(self) -> tuple[PersistedAuthorization, ...]:
        rows = self._conn.execute(
            "SELECT authorization_id, scope_id, amount, opened_at, entry_id "
            "FROM open_authorizations"
        ).fetchall()
        return tuple(
            PersistedAuthorization(
                authorization_id=uuid.UUID(row[0]),
                scope_id=row[1],
                amount=Decimal(row[2]),
                opened_at=_parse_iso(row[3]),
                entry_id=uuid.UUID(row[4]),
            )
            for row in rows
        )

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        try:
            self._conn.close()
        finally:
            if self._lock is not None:
                self._lock.release()
                self._lock = None
