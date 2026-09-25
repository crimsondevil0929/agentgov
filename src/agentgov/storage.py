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

Two properties every implementation must provide, and :class:`SqliteStore`
does:

**One transaction per unit of work.** :meth:`PersistenceStore.commit` makes a
whole :class:`~agentgov.core.WriteBatch` durable or none of it. A governor
operation touches the ledger and up to three cache tables; writing them in
separate transactions is what let a crash between two of them leave a
released hold behind an open authorization.

**One consistent read.** :meth:`PersistenceStore.load` and
:meth:`PersistenceStore.snapshot` read every table inside a single read
transaction, so a reader following a live writer never sees an entry without
the cache rows committed with it, or the reverse.

Every write happens *before* the corresponding in-memory mutation in
:mod:`agentgov.core`, and every figure this file writes has already been
quantized and validated by :mod:`agentgov.core`. This module does not
reinterpret money: amounts round-trip through ``TEXT`` columns as the exact
``Decimal`` string :mod:`agentgov.core` produced, never through a
floating-point column type.
"""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import sys
import uuid
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Protocol

from agentgov.core import (
    Authorization,
    BudgetNode,
    ControlEvent,
    Direction,
    EntryType,
    LedgerEntry,
    WriteBatch,
    _iso,
    _parse_iso,
)
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
    "StoreDelta",
    "StoreImage",
]

_SCHEMA_VERSION = "2"
"""v0.1.2: entries carry their payload ``version`` and hold ``ref``; control
events name the chain entry that records them."""

_LEGACY_SCHEMA_VERSION = "1"
"""v0.1.0 and v0.1.1. Read as-is when opened read-only; upgraded in place the
first time it is opened for writing."""

_SUPPORTED_VERSIONS = frozenset({_LEGACY_SCHEMA_VERSION, _SCHEMA_VERSION})

_ENTRY_COLUMNS = (
    "sequence, entry_id, transaction_id, timestamp, entry_type, direction, scope_id, "
    "counterparty_id, amount, balance_after, prev_hash, entry_hash, memo"
)


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


@dataclass(frozen=True, slots=True)
class StoreImage:
    """Everything a store holds, read in one transaction.

    :ivar control_high_water: The highest ``control_events`` row id read, so a
        later :meth:`PersistenceStore.snapshot` can continue from it.
    """

    schema_version: str
    entries: tuple[LedgerEntry, ...]
    nodes: tuple[PersistedNode, ...]
    control_events: tuple[ControlEvent, ...]
    authorizations: tuple[PersistedAuthorization, ...]
    control_high_water: int


@dataclass(frozen=True, slots=True)
class StoreDelta:
    """What changed since a reader last looked, read in one transaction.

    :ivar anchor_hash: The ``entry_hash`` stored at the sequence the reader
        last verified, so the reader can tell that history was not rewritten
        under it. ``None`` when it asked from the start, or when that entry no
        longer exists.
    :ivar entries: Entries after that sequence, in chain order.
    :ivar authorizations: Every open authorization, now.
    :ivar legacy_control_events: Control events after the reader's high-water
        mark that no chain entry records — written by a pre-0.1.2 governor.
    """

    schema_version: str
    anchor_hash: str | None
    entries: tuple[LedgerEntry, ...]
    authorizations: tuple[PersistedAuthorization, ...]
    legacy_control_events: tuple[ControlEvent, ...]
    control_high_water: int


class PersistenceStore(Protocol):
    """The durability seam a :class:`~agentgov.core.Ledger` and
    :class:`~agentgov.core.BudgetManager` write through to.

    Every write is called with the manager's own lock held, so an
    implementation never needs to provide its own concurrency control — it
    only needs to make each :meth:`commit` durable as a whole. A distributed
    backend (the Phase 2 multi-node consensus store) implements this same
    interface with a replicated write in place of a local file.
    """

    @property
    def read_only(self) -> bool:
        """Whether every write is refused."""
        ...

    def commit(self, batch: WriteBatch) -> None:
        """Durably apply ``batch``, all of it or none of it.

        :raises Exception: Any failure must propagate — a caller that
            catches this and continues would commit to memory a transaction
            that was never made durable.
        """
        ...

    def load(self) -> StoreImage:
        """Read every table in one consistent read."""
        ...

    def load_entries(self) -> tuple[LedgerEntry, ...]:
        """Return every persisted entry, oldest first."""
        ...

    def snapshot(self, *, after_sequence: int, after_control_row: int) -> StoreDelta:
        """Read what changed after ``after_sequence``, in one consistent read."""
        ...

    def rebuild_caches(
        self,
        *,
        nodes: Sequence[BudgetNode],
        control_events: Sequence[ControlEvent],
        authorizations: Sequence[Authorization],
    ) -> None:
        """Replace the cache tables with rows derived from the chain.

        Leaves the entries, and any pre-0.1.2 control events, untouched.
        """
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

    A database written by v0.1.0 or v0.1.1 (schema version 1) is upgraded in
    place, inside one transaction, the first time it is opened for writing.
    Opened read-only, it is read as it is.

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
            self._read_schema_version()
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

    @property
    def schema_version(self) -> str:
        """The schema version currently on disk."""
        return self._read_schema_version()

    def _require_writable(self, operation: str) -> None:
        """Refuse a mutation up front rather than deep inside a transaction."""
        if self._read_only:
            raise ReadOnlyLedgerError(operation)

    # -- schema -----------------------------------------------------------

    def _read_schema_version(self) -> str:
        """The stored schema version, refusing one this code cannot read."""
        try:
            row = self._conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.OperationalError as exc:
            raise StorageError(
                f"{self._path!r} is not an agentgov database (or is empty): {exc}"
            ) from exc
        if row is None:
            return _SCHEMA_VERSION
        version = str(row[0])
        if version not in _SUPPORTED_VERSIONS:
            raise LedgerIntegrityError(
                f"database schema version {version!r} does not match "
                f"this version of agentgov ({_SCHEMA_VERSION!r}); "
                f"refusing to open a file this version cannot interpret"
            )
        return version

    def _init_schema(self) -> None:
        """Create the schema, or upgrade a version-1 database, in one transaction."""
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'"
            ).fetchone()
            found = None if row is None else str(row[0])
            if found is not None and found not in _SUPPORTED_VERSIONS:
                raise LedgerIntegrityError(
                    f"database schema version {found!r} does not match "
                    f"this version of agentgov ({_SCHEMA_VERSION!r}); "
                    f"refusing to open a file this version cannot interpret"
                )
            conn.execute(
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
                    memo            TEXT NOT NULL DEFAULT '',
                    version         TEXT NOT NULL DEFAULT 'AGOV1',
                    ref             TEXT
                )
                """
            )
            conn.execute(
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS control_events (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id          TEXT NOT NULL UNIQUE,
                    timestamp         TEXT NOT NULL,
                    event_type        TEXT NOT NULL,
                    scope_id          TEXT NOT NULL,
                    reason            TEXT NOT NULL,
                    ledger_head_hash  TEXT NOT NULL,
                    entry_id          TEXT
                )
                """
            )
            conn.execute(
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
            # A version-1 database already had these tables, without the
            # columns v0.1.2 needs. Existing rows keep their meaning: an entry
            # with no version is AGOV1, a control event with no entry_id was
            # written before control events were chained.
            if not self._has_column("entries", "version"):
                conn.execute("ALTER TABLE entries ADD COLUMN version TEXT NOT NULL DEFAULT 'AGOV1'")
            if not self._has_column("entries", "ref"):
                conn.execute("ALTER TABLE entries ADD COLUMN ref TEXT")
            if not self._has_column("control_events", "entry_id"):
                conn.execute("ALTER TABLE control_events ADD COLUMN entry_id TEXT")
            conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (_SCHEMA_VERSION,),
            )
            conn.commit()
        except BaseException:
            with suppress(sqlite3.Error):
                conn.rollback()
            raise

    def _has_column(self, table: str, column: str) -> bool:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        return any(row[1] == column for row in rows)

    # -- writing ----------------------------------------------------------

    def _write(self, operation: str, work: Callable[[sqlite3.Connection], None]) -> None:
        """Run ``work`` as one immediate transaction, committed or rolled back."""
        self._require_writable(operation)
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            work(conn)
            conn.commit()
        except BaseException:
            with suppress(sqlite3.Error):
                conn.rollback()
            raise

    def commit(self, batch: WriteBatch) -> None:
        """Durably apply one unit of work in a single transaction."""
        if not batch:
            return

        def work(conn: sqlite3.Connection) -> None:
            if batch.entries:
                conn.executemany(
                    # Column names are this module's constant, never input.
                    f"INSERT INTO entries ({_ENTRY_COLUMNS}, version, ref) "  # noqa: S608
                    f"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [_entry_row(e) for e in batch.entries],
                )
            for node in batch.nodes:
                _upsert_node(conn, node)
            for event in batch.control_events:
                _insert_control_event(conn, event)
            for auth in batch.opened:
                conn.execute(
                    """
                    INSERT INTO open_authorizations
                        (authorization_id, scope_id, amount, opened_at, entry_id)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        str(auth.authorization_id),
                        auth.scope_id,
                        str(auth.amount),
                        _iso(auth.opened_at),
                        str(auth.entry.entry_id),
                    ),
                )
            for authorization_id in batch.closed:
                conn.execute(
                    "DELETE FROM open_authorizations WHERE authorization_id = ?",
                    (str(authorization_id),),
                )

        count = len(batch.entries)
        try:
            self._write("commit a transaction", work)
        except sqlite3.IntegrityError as exc:
            raise LedgerIntegrityError(
                f"failed to durably append {count} entr{'y' if count == 1 else 'ies'}: {exc}"
            ) from exc

    def rebuild_caches(
        self,
        *,
        nodes: Sequence[BudgetNode],
        control_events: Sequence[ControlEvent],
        authorizations: Sequence[Authorization],
    ) -> None:
        """Replace the topology, chained control events and open authorizations."""

        def work(conn: sqlite3.Connection) -> None:
            conn.execute("DELETE FROM nodes")
            for node in nodes:
                _upsert_node(conn, node)
            conn.execute("DELETE FROM control_events WHERE entry_id IS NOT NULL")
            for event in control_events:
                _insert_control_event(conn, event)
            conn.execute("DELETE FROM open_authorizations")
            for auth in authorizations:
                conn.execute(
                    """
                    INSERT INTO open_authorizations
                        (authorization_id, scope_id, amount, opened_at, entry_id)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        str(auth.authorization_id),
                        auth.scope_id,
                        str(auth.amount),
                        _iso(auth.opened_at),
                        str(auth.entry.entry_id),
                    ),
                )

        self._write("repair cache tables", work)

    # -- single-purpose writes, kept for direct callers --------------------

    def append_entries(self, entries: Sequence[LedgerEntry]) -> None:
        """Durably append ``entries`` as one transaction."""
        self.commit(WriteBatch(entries=list(entries)))

    def upsert_node(
        self,
        scope_id: str,
        parent_id: str | None,
        depth: int,
        allocated: Decimal,
        created_at: datetime,
    ) -> None:
        """Durably record a scope's current topology and lifetime allocation."""
        node = BudgetNode(scope_id, parent_id, depth, allocated, created_at=created_at)
        self.commit(WriteBatch(nodes=[node]))

    def append_control_event(self, event: ControlEvent) -> None:
        """Durably record a circuit-breaker trip or reset."""
        self.commit(WriteBatch(control_events=[event]))

    def put_authorization(
        self,
        authorization_id: uuid.UUID,
        scope_id: str,
        amount: Decimal,
        opened_at: datetime,
        entry_id: uuid.UUID,
    ) -> None:
        """Durably record a newly placed authorization hold."""

        def work(conn: sqlite3.Connection) -> None:
            conn.execute(
                """
                INSERT INTO open_authorizations
                    (authorization_id, scope_id, amount, opened_at, entry_id)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(authorization_id), scope_id, str(amount), _iso(opened_at), str(entry_id)),
            )

        self._write("record an authorization", work)

    def delete_authorization(self, authorization_id: uuid.UUID) -> None:
        """Remove a settled or voided authorization hold."""
        self.commit(WriteBatch(closed=[authorization_id]))

    # -- reading ----------------------------------------------------------

    @contextmanager
    def _read_transaction(self) -> Iterator[None]:
        """Hold one read transaction, so several SELECTs see one snapshot."""
        conn = self._conn
        if conn.in_transaction:
            yield
            return
        conn.execute("BEGIN")
        try:
            yield
        finally:
            with suppress(sqlite3.Error):
                conn.rollback()

    def load(self) -> StoreImage:
        """Read every table in one consistent read."""
        with self._read_transaction():
            version = self._read_schema_version()
            entries = self._select_entries("", ())
            nodes = self._select_nodes()
            rows = self._select_control_rows(after=0)
            authorizations = self._select_authorizations()
        return StoreImage(
            schema_version=version,
            entries=entries,
            nodes=nodes,
            control_events=tuple(event for _, event in rows),
            authorizations=authorizations,
            control_high_water=max((row_id for row_id, _ in rows), default=0),
        )

    def snapshot(self, *, after_sequence: int, after_control_row: int) -> StoreDelta:
        """Read what changed after ``after_sequence``, in one consistent read."""
        with self._read_transaction():
            version = self._read_schema_version()
            anchor: str | None = None
            if after_sequence > 0:
                row = self._conn.execute(
                    "SELECT entry_hash FROM entries WHERE sequence = ?", (after_sequence,)
                ).fetchone()
                anchor = None if row is None else str(row[0])
            entries = self._select_entries("WHERE sequence > ?", (after_sequence,))
            authorizations = self._select_authorizations()
            rows = self._select_control_rows(after=after_control_row)
        return StoreDelta(
            schema_version=version,
            anchor_hash=anchor,
            entries=entries,
            authorizations=authorizations,
            legacy_control_events=tuple(event for _, event in rows if event.entry_id is None),
            control_high_water=max((row_id for row_id, _ in rows), default=after_control_row),
        )

    def load_entries(self) -> tuple[LedgerEntry, ...]:
        """Return every persisted entry, oldest first."""
        with self._read_transaction():
            return self._select_entries("", ())

    def load_nodes(self) -> tuple[PersistedNode, ...]:
        """Return every persisted scope's topology, in no particular order."""
        with self._read_transaction():
            return self._select_nodes()

    def load_control_events(self) -> tuple[ControlEvent, ...]:
        """Return every persisted control event, oldest first."""
        with self._read_transaction():
            return tuple(event for _, event in self._select_control_rows(after=0))

    def load_open_authorizations(self) -> tuple[PersistedAuthorization, ...]:
        """Return every hold that was never settled or voided, in no
        particular order — a restart-time reconciliation list as much as a
        recovery mechanism: a hold present here after a long-dead process
        exited is a candidate for an operator to void by hand."""
        with self._read_transaction():
            return self._select_authorizations()

    def _select_entries(self, where: str, params: tuple[object, ...]) -> tuple[LedgerEntry, ...]:
        versioned = self._has_column("entries", "version")
        columns = _ENTRY_COLUMNS + (", version, ref" if versioned else "")
        rows = self._conn.execute(
            f"SELECT {columns} FROM entries {where} ORDER BY sequence ASC",  # noqa: S608
            params,
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
                ref=uuid.UUID(row[14]) if versioned and row[14] else None,
                version=row[13] if versioned else "AGOV1",
            )
            for row in rows
        )

    def _select_nodes(self) -> tuple[PersistedNode, ...]:
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

    def _select_control_rows(self, *, after: int) -> tuple[tuple[int, ControlEvent], ...]:
        chained = self._has_column("control_events", "entry_id")
        columns = "id, event_id, timestamp, event_type, scope_id, reason, ledger_head_hash"
        if chained:
            columns += ", entry_id"
        rows = self._conn.execute(
            f"SELECT {columns} FROM control_events WHERE id > ? ORDER BY id ASC",  # noqa: S608
            (after,),
        ).fetchall()
        return tuple(
            (
                int(row[0]),
                ControlEvent(
                    event_id=uuid.UUID(row[1]),
                    timestamp=_parse_iso(row[2]),
                    event_type=row[3],
                    scope_id=row[4],
                    reason=row[5],
                    ledger_head_hash=row[6],
                    entry_id=uuid.UUID(row[7]) if chained and row[7] else None,
                ),
            )
            for row in rows
        )

    def _select_authorizations(self) -> tuple[PersistedAuthorization, ...]:
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


def _entry_row(entry: LedgerEntry) -> tuple[object, ...]:
    return (
        entry.sequence,
        str(entry.entry_id),
        str(entry.transaction_id),
        _iso(entry.timestamp),
        entry.entry_type.value,
        entry.direction.value,
        entry.scope_id,
        entry.counterparty_id,
        str(entry.amount),
        str(entry.balance_after),
        entry.prev_hash,
        entry.entry_hash,
        entry.memo,
        entry.version,
        str(entry.ref) if entry.ref is not None else None,
    )


def _upsert_node(conn: sqlite3.Connection, node: BudgetNode) -> None:
    conn.execute(
        """
        INSERT INTO nodes (scope_id, parent_id, depth, allocated, created_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(scope_id) DO UPDATE SET
            parent_id = excluded.parent_id,
            depth = excluded.depth,
            allocated = excluded.allocated
        """,
        (node.scope_id, node.parent_id, node.depth, str(node.allocated), _iso(node.created_at)),
    )


def _insert_control_event(conn: sqlite3.Connection, event: ControlEvent) -> None:
    conn.execute(
        """
        INSERT INTO control_events
            (event_id, timestamp, event_type, scope_id, reason, ledger_head_hash, entry_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            str(event.event_id),
            _iso(event.timestamp),
            event.event_type,
            event.scope_id,
            event.reason,
            event.ledger_head_hash,
            str(event.entry_id) if event.entry_id is not None else None,
        ),
    )
