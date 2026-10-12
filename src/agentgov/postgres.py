"""A ledger many governors share: the PostgreSQL :class:`~agentgov.storage.SharedStore`.

:class:`~agentgov.storage.SqliteStore` makes one governor process the only
writer of its ledger, and that governor's memory is then the ledger. A fleet
cannot work that way: N workers on N hosts need one authoritative balance,
not N private copies of it. :class:`PostgresStore` puts the ledger in a
database they all write, and the database, not any one process, becomes the
serialization point.

The unit of work
----------------
Every mutation a :class:`~agentgov.core.BudgetManager` makes over this store
runs inside :meth:`PostgresStore.writer`, which is one database transaction:

1. ``BEGIN ISOLATION LEVEL READ COMMITTED`` and ``pg_advisory_xact_lock`` on a
   key derived from the ledger's schema. One governor in the fleet holds it at
   a time; the rest wait (up to ``lock_timeout``).
2. The governor reads everything committed since its last look and verifies
   it, entry by entry, exactly as a fresh open would (hash links, balances,
   hold pairing), then applies it.
3. Only now does it check the balance or the breaker, build its entries on the
   head it just verified, and write them.
4. ``COMMIT`` releases the lock with the transaction.

**Behind a pooler.** The store keeps no state on its session: the lock
wait, the idle bound and read-only are set in the message that begins each
transaction (``SET LOCAL``), the lock is a transaction's, and no statement
is prepared unless ``prepare_threshold`` asks for it. So PgBouncer in
transaction mode may serve each transaction from any server connection; the
test suite runs behind one.

**Why READ COMMITTED.** Under ``REPEATABLE READ`` the transaction's snapshot
is taken by its first statement, which is the lock request itself, *before*
it waits. A governor would then catch up to the ledger as it stood when it
started waiting, blind to every commit it waited for. Under ``READ
COMMITTED`` each statement sees what was committed when it began, and nothing
commits while this governor holds the lock.

**Why a transaction-scoped lock.** The lock ends with the transaction, never
outlives it, and never leaks from a crashed client: the server rolls the
transaction back, and with it the lock. It also keeps the whole unit of work
in one transaction, which is what lets a caller someday run the ledger write
inside a larger transaction of its own.

The chain is the safety net, the lock is for liveness
-----------------------------------------------------
The lock is not what keeps the chain linear. Two triggers are:

- ``extend_chain`` (``BEFORE INSERT``) admits an entry only if it links to the
  entry immediately before it, by sequence and hash. With ``sequence`` the
  primary key, an entry commits only if it extends the committed head. A
  governor whose view is stale builds on an old head and is refused; so is a
  writer that never took the lock. Neither can fork the chain.
- ``append_only`` refuses ``UPDATE``, ``DELETE`` and ``TRUNCATE`` on entries.

The lock turns what would be refusals into waiting. Both triggers are enabled
``ALWAYS``, so ``session_replication_role`` does not switch them off; the
tables' owner or a superuser still can, which is why verification never
assumes they ran.

Memory is provisional until COMMIT
----------------------------------
A governor applies its entries to memory as it writes them, inside the
session. If the session does not commit (a failed write, a lost connection, a
commit whose outcome never arrived), memory may be ahead of the database, and
the governor re-reads the ledger, under the lock, before it acts again. See
:meth:`agentgov.core.BudgetManager.refresh`.

Money round-trips through ``text`` columns as the exact ``Decimal`` string
:mod:`agentgov.core` produced, for the reason :mod:`agentgov.storage` gives:
an entry's hash covers ``str(amount)``, and a ``numeric`` column would hand
back ``0E-8`` for the ``0`` a zero-value entry was hashed with. Timestamps are
the ``_iso`` text the hash covers, for the same reason.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import threading
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from decimal import Decimal
from typing import Any, Final, LiteralString

from agentgov.core import (
    _CHECKPOINT_MEMO,
    GENESIS_HASH,
    Authorization,
    BudgetNode,
    ControlEvent,
    EntryType,
    IdempotencyRecord,
    LedgerEntry,
    SettlementClaim,
    WriteBatch,
    _amount_text,
    _direction,
    _entry_type,
    _iso,
    _parse_iso,
)
from agentgov.exceptions import (
    LedgerConflictError,
    LedgerIntegrityError,
    ReadOnlyLedgerError,
    StorageError,
)
from agentgov.storage import (
    AuditMark,
    PersistedAuthorization,
    PersistedNode,
    Snapshot,
    StoreDelta,
    StoreImage,
    _guarded,
)

try:
    import psycopg
    from psycopg import sql
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "agentgov.postgres needs psycopg; install it with: pip install 'agentgov[postgres]'"
    ) from exc

__all__ = ["DEFAULT_SCHEMA", "PostgresStore"]

DEFAULT_SCHEMA: Final = "agentgov"
"""The PostgreSQL schema a ledger lives in unless another is named."""

_SCHEMA_VERSION: Final = "pg2"
"""The PostgreSQL layout. The same logical tables as SQLite's version 3:
checkpoint snapshots, the auditor's marks, idempotency records, and indexes
on history."""

_PG1: Final = "pg1"
"""v0.3 and v0.4. Read as it is when opened read-only; upgraded in place,
under the writer lock, the first time a writer opens it."""

_SUPPORTED_VERSIONS: Final = frozenset({_PG1, _SCHEMA_VERSION})

_SCHEMA_NAME: Final = re.compile(r"\A[a-z_][a-z0-9_]{0,62}\Z")

_ENTRY_COLUMNS: Final[LiteralString] = (
    "sequence, entry_id, transaction_id, timestamp, entry_type, direction, scope_id, "
    "counterparty_id, amount, balance_after, prev_hash, entry_hash, memo, version, ref"
)


def _lock_keys(schema: str) -> tuple[int, int]:
    """The two 32-bit keys of the schema's writer lock.

    Advisory locks are per database, so two ledgers in two schemas of one
    database never contend, and nothing else is likely to use these keys.
    """
    digest = hashlib.sha256(f"agentgov.ledger:{schema}".encode()).digest()
    return (
        int.from_bytes(digest[:4], "big", signed=True),
        int.from_bytes(digest[4:8], "big", signed=True),
    )


def _millis(seconds: float, label: str) -> int:
    if seconds <= 0:
        raise ValueError(f"{label} must be positive, got {seconds}")
    return max(1, round(seconds * 1000))


_REFUSED: Final = "; the database admits only entries that extend the committed head"
"""A duplicate sequence and a broken link are the same event: the entries were
built on a head that is no longer the committed one."""


def _appending(count: int) -> str:
    return f"durably append {count} {'entry' if count == 1 else 'entries'}"


def _mapped(exc: psycopg.Error, operation: str, refused: str = "") -> Exception:
    """The package's own error for a driver's."""
    if isinstance(exc, psycopg.errors.SerializationFailure):
        return LedgerConflictError(f"cannot {operation}: {exc}")
    if isinstance(exc, psycopg.errors.IntegrityError):
        return LedgerIntegrityError(f"cannot {operation}{refused}: {exc}")
    return StorageError(f"cannot {operation}: {exc}")


def _selected(cursor: psycopg.Cursor[Any]) -> list[list[tuple[Any, ...]]]:
    """The rows of every statement of a message that returned rows, in order."""
    selected: list[list[tuple[Any, ...]]] = []
    while True:
        if cursor.description is not None:
            selected.append(cursor.fetchall())
        if not cursor.nextset():
            return selected


def _control_rows(rows: Sequence[tuple[Any, ...]]) -> tuple[tuple[int, ControlEvent], ...]:
    """``control_events`` rows as ``(row id, event)``."""
    return tuple(
        (
            int(row[0]),
            ControlEvent(
                event_id=row[1],
                timestamp=_parse_iso(row[2]),
                event_type=row[3],
                scope_id=row[4],
                reason=row[5],
                ledger_head_hash=row[6],
                entry_id=row[7],
            ),
        )
        for row in rows
    )


class _Session:
    """One writer session. See :class:`~agentgov.storage.WriterSession`.

    :ivar conn: The connection the session's writes go to: this store's own,
        or, for a joined session, the caller's.
    :ivar token: For a joined session, what proves to the database that a
        governor of this ledger joined that transaction. ``None`` otherwise.
    :ivar head: The committed length and head, read with the lock; ``None``
        once the session has written, or when they were not read.
    :ivar delta: What was committed after ``after``, read with the lock, for
        the governor's catch-up; ``None`` once used.
    :ivar batches: The session's writes, sent in one message with the
        ``COMMIT``: at most one statement per table, however many batches.
    """

    __slots__ = (
        "after",
        "batches",
        "committed",
        "conn",
        "delta",
        "failed",
        "head",
        "pending",
        "token",
        "wrote",
    )

    def __init__(self, conn: psycopg.Connection[Any], *, token: bytes | None = None) -> None:
        self.conn = conn
        self.token = token
        self.committed = False
        self.wrote = False
        self.failed = False
        self.head: tuple[int, str] | None = None
        self.delta: StoreDelta | None = None
        self.after: tuple[int, int] | None = None
        self.batches: list[WriteBatch] = []
        self.pending = 0

    def abandon(self) -> None:
        """Roll the session back when it ends, whatever it wrote."""
        self.failed = True


class PostgresStore:
    """A :class:`~agentgov.storage.SharedStore` in a PostgreSQL schema.

    Open it through :meth:`agentgov.core.BudgetManager.open_postgres`. Every
    governor in a fleet opens its own store, on its own connection, against
    the same database and schema.

    Opened for writing, the store creates its schema the first time, under the
    writer lock so that governors starting together cannot race the DDL. A
    schema that is already installed is only read, so a role granted DML on
    the ledger's tables, and nothing more, can run a governor.

    Every write is refused outside :meth:`writer`: a write that skipped the
    writer lock and the catch-up in front of it would be checked against a
    balance another governor may already have spent.

    :param conninfo: A libpq connection string or URI.
    :param schema: The schema holding the ledger's tables. Lowercase letters,
        digits and underscores.
    :param read_only: Open for audit. No DDL, no writer lock, every write
        refused, and every transaction declared read-only.
    :param lock_timeout: Seconds to wait for the writer lock before giving up
        with :class:`~agentgov.exceptions.StorageError`.
    :param idle_timeout: Seconds the server lets this governor sit idle inside
        an open transaction before ending its session. A governor that hangs
        while it holds the writer lock (a stopped process, a stalled host)
        would otherwise stall the whole fleet; this bounds that, and the
        governor finds out, and re-reads the ledger, at its next operation.
        Set in every transaction, with the message that begins it, never on
        the session: behind a pooler in transaction mode a session setting
        lands on whichever server connection served it.
    :param prepare_threshold: psycopg's: after how many executions a query
        is prepared on the server, or ``None`` (the default) for never. A
        prepared statement belongs to one server connection, which a pooler
        in transaction mode does not keep: leave it ``None`` behind one that
        does not track prepared statements (PgBouncer before 1.21, or with
        ``max_prepared_statements = 0``). The messages a unit of work sends
        are simple queries, prepared either way never.
    :raises StorageError: If the database cannot be reached, or holds no
        ledger when opened read-only.
    :raises LedgerIntegrityError: If the schema was written by a layout this
        version cannot interpret.
    """

    def __init__(
        self,
        conninfo: str,
        *,
        schema: str = DEFAULT_SCHEMA,
        read_only: bool = False,
        lock_timeout: float = 30.0,
        idle_timeout: float = 60.0,
        prepare_threshold: int | None = None,
    ) -> None:
        if not _SCHEMA_NAME.match(schema):
            raise ValueError(
                f"schema name {schema!r} must be lowercase letters, digits and underscores, "
                f"starting with a letter or underscore"
            )
        self._conninfo = conninfo
        self._schema = schema
        self._read_only = read_only
        self._lock_timeout_ms = _millis(lock_timeout, "lock_timeout")
        self._idle_timeout_ms = _millis(idle_timeout, "idle_timeout")
        if prepare_threshold is not None and prepare_threshold < 0:
            raise ValueError(f"prepare_threshold must be None or >= 0, got {prepare_threshold}")
        self._prepare_threshold = prepare_threshold
        self._session: _Session | None = None
        self._rendered: dict[str, str] | None = None  # see _templates
        self._key: bytes | None = None
        self._sql = _Statements(
            schema, _lock_keys(schema), self._lock_timeout_ms, self._idle_timeout_ms
        )
        self._guard = threading.RLock()  # one transaction on the connection at a time
        self._conn = self._connect()
        try:
            self._version = self._open()
        except BaseException:
            self._conn.close()
            raise

    # -- connection -------------------------------------------------------

    def _connect(self) -> psycopg.Connection[tuple[Any, ...]]:
        """A connection with no session state of its own: everything a
        transaction needs (the idle bound, the lock wait, read-only) is set in
        the message that begins it, so a pooler may hand it any server
        connection."""
        try:
            conn = psycopg.connect(self._conninfo, autocommit=True)
        except psycopg.Error as exc:
            raise StorageError(f"cannot connect to the ledger database: {exc}") from exc
        conn.prepare_threshold = self._prepare_threshold
        return conn

    def _live(self) -> psycopg.Connection[tuple[Any, ...]]:
        """The connection, reopened if the server ended the last one.

        Never under a session of its own: a session whose connection died is
        over, and its governor re-reads the ledger rather than carrying on. A
        joined session writes on the caller's connection, not this one.
        """
        if self._conn.closed and not self._in_own_session():
            self._conn = self._connect()
        return self._conn

    def _in_own_session(self) -> bool:
        """Whether a session's transaction is open on this store's connection."""
        return self._session is not None and self._session.conn is self._conn

    # -- properties -------------------------------------------------------

    @property
    def read_only(self) -> bool:
        """Whether this store refuses writes."""
        return self._read_only

    @property
    def schema(self) -> str:
        """The PostgreSQL schema the ledger lives in."""
        return self._schema

    @property
    def schema_version(self) -> str:
        """The installed layout's version."""
        return self._version

    def _require_writable(self, operation: str) -> None:
        if self._read_only:
            raise ReadOnlyLedgerError(operation)

    def _require_session(self, operation: str) -> _Session:
        session = self._session
        if session is None:
            raise StorageError(
                f"cannot {operation} outside a writer session: a shared ledger is written "
                f"only while holding its writer lock, after catching up with every other "
                f"writer (write through a BudgetManager)"
            )
        if session.failed:
            raise StorageError(
                f"cannot {operation}: an earlier write in this session failed, and the "
                f"session will be rolled back"
            )
        return session

    # -- schema -----------------------------------------------------------

    def _open(self) -> str:
        # The version is read without the writer lock: an installed schema is
        # only ever read here, and taking the fleet's lock just to look would
        # make every governor that opens wait on, and stall, every writer.
        with self._reading():
            version = self._installed_version()
        if version == _SCHEMA_VERSION:
            return version
        if self._read_only:
            if version is None:
                raise StorageError(
                    f"schema {self._schema!r} holds no agentgov ledger; open it for writing "
                    f"once to create one"
                )
            return version  # an older layout, read as it is: a reader never upgrades
        # Not installed, or an older layout: install or upgrade under the
        # writer lock, re-checking under it, so governors starting together
        # cannot race the DDL.
        with self.writer():
            version = self._installed_version()
            conn = self._conn
            if version is None:
                with self._errors(f"create the ledger schema {self._schema!r}"):
                    for statement in self._sql.install:
                        conn.execute(statement, prepare=False)
                    # The secret joined transactions are authorized by. From
                    # the OS's CSPRNG, not the server's random(); readable by
                    # the ledger's owner and the governors it grants, never by
                    # a role that only carries joined writes.
                    conn.execute(self._sql.set_join_key, (secrets.token_bytes(32),))
                    conn.execute(self._sql.set_version, (_SCHEMA_VERSION,))
            elif version != _SCHEMA_VERSION:
                with self._errors(
                    f"upgrade ledger schema {self._schema!r} from {version} to "
                    f"{_SCHEMA_VERSION} (an upgrade needs the schema's owner, or a role "
                    f"that may create tables and indexes in it)"
                ):
                    for statement in self._sql.upgrade:
                        conn.execute(statement, prepare=False)
                    conn.execute(self._sql.set_version, (_SCHEMA_VERSION,))
            version = _SCHEMA_VERSION
        return version

    def _installed_version(self) -> str | None:
        conn = self._conn
        with self._errors("read the ledger's schema version"):
            # A plain scan of the catalog, not to_regclass(): name lookups go
            # through the session's catalog cache, which keeps a "no such
            # relation" answer until it processes invalidations, and waiting
            # on an advisory lock does not process them. A governor that
            # looked before another installed the schema would then still see
            # nothing under the lock, and run the DDL a second time.
            row = conn.execute(self._sql.has_schema_meta, (self._schema,)).fetchone()
            if row is None:
                return None
            found = conn.execute(self._sql.get_version).fetchone()
        version = None if found is None else str(found[0])
        if version not in _SUPPORTED_VERSIONS:
            raise LedgerIntegrityError(
                f"ledger schema {self._schema!r} has layout version {version!r}; this version "
                f"of agentgov reads {sorted(_SUPPORTED_VERSIONS)} and refuses to interpret "
                f"anything else"
            )
        return version

    # -- sessions ---------------------------------------------------------

    prefetches = True
    """:meth:`writer` reads what a governor needs to catch up in the message
    that takes the lock."""

    @contextmanager
    def writer(
        self, *, after_sequence: int | None = None, after_control_row: int | None = None
    ) -> Iterator[_Session]:
        """Take the writer lock for one unit of work. See
        :meth:`agentgov.storage.SharedStore.writer`.

        A unit of work costs two round trips. The message that begins the
        transaction and takes the lock also reads the head and, given the
        caller's ``after_sequence`` and ``after_control_row``, everything
        committed after them, which :meth:`head` and :meth:`snapshot` then
        answer from. The session's writes go in one message with the
        ``COMMIT``.

        :raises ReadOnlyLedgerError: If this store was opened read-only.
        :raises StorageError: If the lock was not granted within
            ``lock_timeout``, or the database could not be reached.
        """
        self._require_writable("write the ledger")
        with self._guard:  # held for the session: its transaction is the connection's
            if self._session is not None:
                if self._session.token is not None:
                    raise StorageError(
                        "cannot open a writer session inside a joined transaction: the joined "
                        "transaction holds the writer lock, so this would wait on itself"
                    )
                yield self._session
                return
            after = None if after_sequence is None else (after_sequence, after_control_row or 0)
            head, delta = self._begin(after)
            session = _Session(self._conn)
            session.head, session.delta, session.after = head, delta, after
            self._session = session
            try:
                yield session
            except BaseException:
                self._session = None
                self._end(session)
                raise
            self._session = None
            self._end(session)

    @_guarded
    def writer_lock_held(self, timeout: float = 0.1) -> bool:
        """Whether another transaction holds this schema's writer lock: it is
        not granted within ``timeout`` seconds.

        Writes nothing: the lock, if granted, is released at once. Opening a
        governor never waits for the writer lock (it reads a snapshot), so an
        open is no test of whether a writer is in the middle of one; this is.

        :raises ValueError: If ``timeout`` is not positive.
        :raises StorageError: If the database cannot be reached, or this store
            is inside a session of its own, which may hold the lock itself.
        """
        millis = _millis(timeout, "timeout")
        if self._session is not None:
            raise StorageError(
                "cannot probe the writer lock from inside a session: it may be this one's"
            )
        conn = self._live()
        try:
            conn.execute(self._sql.probe_lock(millis), prepare=False)
        except psycopg.errors.LockNotAvailable:
            self._rollback_quietly()
            return True
        except psycopg.Error as exc:
            self._rollback_quietly()
            raise StorageError(f"cannot probe the writer lock: {exc}") from exc
        self._rollback_quietly()
        return False

    def _begin(
        self, after: tuple[int, int] | None = None
    ) -> tuple[tuple[int, str] | None, StoreDelta | None]:
        """Open the transaction and take the lock, reconnecting once if the
        server ended an idle connection since the last session; with
        ``after``, read the head and what was committed after it, too.

        :returns: The head and that delta, or ``(None, None)`` without ``after``.
        """
        for attempt in (1, 2):
            conn = self._live()
            try:
                if after is None:
                    conn.execute(self._sql.begin_locked, prepare=False)
                    return None, None
                return self._begin_reading(conn, *after)
            except psycopg.errors.LockNotAvailable as exc:
                self._rollback_quietly()
                raise StorageError(
                    f"timed out after {self._lock_timeout_ms / 1000:g}s waiting for the "
                    f"writer lock of ledger schema {self._schema!r}; another governor holds "
                    f"it"
                ) from exc
            except psycopg.OperationalError as exc:
                self._rollback_quietly()
                if attempt == 1 and conn.closed:
                    continue
                raise StorageError(f"cannot open a ledger transaction: {exc}") from exc
            except psycopg.Error as exc:
                self._rollback_quietly()
                raise StorageError(f"cannot open a ledger transaction: {exc}") from exc
        raise AssertionError("unreachable")  # pragma: no cover

    def _begin_reading(
        self, conn: psycopg.Connection[Any], after_sequence: int, after_control_row: int
    ) -> tuple[tuple[int, str], StoreDelta]:
        """One message: begin, take the lock, and read the entry at
        ``after_sequence``, every entry after it (the last is the head) and the
        control rows after ``after_control_row``."""
        template = self._templates(conn)["begin"]
        message = template.replace("<AFTER>", str(int(after_sequence))).replace(
            "<CONTROL>", str(int(after_control_row))
        )
        selected = _selected(conn.execute(message, prepare=False))
        entry_rows, control_rows = selected[-2:]  # after the lock's
        found = [_entry(row) for row in entry_rows]
        if after_sequence > 0 and (not found or found[0].sequence != after_sequence):
            # Shorter than this view: the ledger was cut back under it. Its
            # real head, for the caller's catch-up to refuse.
            row = conn.execute(self._sql.head).fetchone()
            head = (int(row[0]), str(row[1])) if row is not None else (0, GENESIS_HASH)
            return head, self._delta(None, [], control_rows, after_control_row)
        anchor = found[0].entry_hash if after_sequence > 0 else None
        entries = found[1:] if after_sequence > 0 else found
        last = found[-1] if found else None
        head = (last.sequence, last.entry_hash) if last is not None else (0, GENESIS_HASH)
        return head, self._delta(anchor, entries, control_rows, after_control_row)

    def _delta(
        self,
        anchor: str | None,
        entries: Sequence[LedgerEntry],
        control_rows: Sequence[tuple[Any, ...]],
        after_control_row: int,
    ) -> StoreDelta:
        rows = _control_rows(control_rows)
        return StoreDelta(
            schema_version=self._version,
            anchor_hash=anchor,
            entries=tuple(entries),
            authorizations=(),
            legacy_control_events=tuple(event for _, event in rows if event.entry_id is None),
            control_high_water=max((row_id for row_id, _ in rows), default=after_control_row),
        )

    def _templates(self, conn: psycopg.Connection[Any]) -> dict[str, str]:
        """The messages this store sends most, rendered once."""
        if self._rendered is None:
            entries = self._sql.select_entries_from.as_string(conn)
            control = self._sql.select_control.as_string(conn).replace("%s", "<CONTROL>")
            # What is read after a sequence is the tail of the chain, in
            # order: the primary key's index scan, which streams it sorted.
            # A ledger the server has not yet analyzed (a new one, under
            # load, for up to autovacuum's minute) has no statistics to say
            # the tail is short, and the planner's default guess is a third
            # of the table: a scan of all of it and a sort, under the writer
            # lock. So, in this transaction only, nothing else is offered.
            index_only = "SET LOCAL enable_seqscan = off; SET LOCAL enable_bitmapscan = off"
            self._rendered = {
                "begin": "; ".join(
                    (
                        self._sql.begin_locked.as_string(conn),
                        index_only,
                        entries.replace("%s", "<AFTER>"),
                        control,
                    )
                ),
                "read": "; ".join(
                    (
                        self._sql.begin_reading.as_string(conn),
                        index_only,
                        entries.replace("%s", "<AFTER>"),
                        control,
                        "ROLLBACK",
                    )
                ),
                **{name: part.as_string(conn) for name, part in self._sql.writes.items()},
            }
        return self._rendered

    def _flush(self) -> None:
        """Send what this session wrote, without committing: a read inside the
        session then sees its writes. Inside the session."""
        session = self._session
        if session is None or not session.batches:
            return
        statements, count = self._render(session.batches), session.pending
        session.batches, session.pending = [], 0
        with self._errors(_appending(count), refused=_REFUSED):
            self._conn.execute("; ".join(statements), prepare=False)

    def _render(self, batches: Sequence[WriteBatch]) -> list[str]:
        """A session's writes as at most one statement per table: every entry,
        in chain order, in one INSERT (a row trigger sees the rows the
        statement inserted before it, so the chain check holds within it);
        each node's last state; the control rows; and the open holds, less
        those opened and closed again within the session."""
        text = self._templates(self._conn)
        entries = [entry for batch in batches for entry in batch.entries]
        nodes: dict[str, BudgetNode] = {}
        controls: list[ControlEvent] = []
        opened: dict[Any, Authorization] = {}
        closed: list[Any] = []
        calls: list[IdempotencyRecord] = []
        for batch in batches:
            for node in batch.nodes:
                nodes[node.scope_id] = node
            controls.extend(batch.control_events)
            calls.extend(batch.idempotency)
            for auth in batch.opened:
                opened[auth.authorization_id] = auth
            for authorization_id in batch.closed:
                if opened.pop(authorization_id, None) is None:
                    closed.append(authorization_id)
        statements = []
        if entries:
            rows = ", ".join([_values(_entry_row(entry)) for entry in entries])
            statements.append(text["entries"] + rows)
        if nodes:
            rows = ", ".join([_values(_node_row(node)) for node in nodes.values()])
            statements.append(text["nodes"] + rows + text["nodes_conflict"])
        if controls:
            rows = ", ".join([_values(_control_row(event)) for event in controls])
            statements.append(text["controls"] + rows)
        if opened:
            rows = ", ".join([_values(_authorization_row(auth)) for auth in opened.values()])
            statements.append(text["authorizations"] + rows)
        if closed:
            ids = ", ".join([_literal(authorization_id) for authorization_id in closed])
            statements.append(text["close"] + ids + ")")
        if calls:
            rows = ", ".join([_values(_idempotency_row(record)) for record in calls])
            statements.append(text["keys"] + rows)
        return statements

    def _end(self, session: _Session) -> None:
        conn = self._conn
        # PostgreSQL answers COMMIT in an aborted transaction with a ROLLBACK,
        # not an error. So a failure this store did not see (an error raised
        # through some path other than _errors) is caught here, by the
        # transaction's own status, and again by what COMMIT reports it did.
        if session.failed or conn.info.transaction_status is psycopg.pq.TransactionStatus.INERROR:
            session.failed = True
            self._rollback_quietly()
            return
        if session.batches:
            # The writes and the COMMIT, in one message: a write the database
            # refuses skips the rest, COMMIT included.
            message = "; ".join([*self._render(session.batches), "COMMIT"])
            count = session.pending
            session.batches, session.pending = [], 0
            try:
                cursor = conn.execute(message, prepare=False)
                while cursor.nextset():
                    pass
                status = cursor.statusmessage
            except psycopg.OperationalError as exc:
                session.failed = True
                self._rollback_quietly()
                raise StorageError(
                    f"the ledger transaction did not commit, or its outcome was lost with the "
                    f"connection: {exc}"
                ) from exc
            except psycopg.Error as exc:
                session.failed = True
                self._rollback_quietly()
                raise _mapped(exc, _appending(count), _REFUSED) from exc
            if status != "COMMIT":  # pragma: no cover - an error above comes first
                raise StorageError(
                    f"the ledger transaction did not commit: the server answered {status}"
                )
            session.committed = True
            return
        try:
            status = conn.execute("COMMIT").statusmessage
        except psycopg.Error as exc:
            self._rollback_quietly()
            raise StorageError(
                f"the ledger transaction did not commit, or its outcome was lost with the "
                f"connection: {exc}"
            ) from exc
        if status != "COMMIT":  # pragma: no cover - the INERROR check above catches it first
            raise StorageError(
                f"the ledger transaction did not commit: the server answered {status}"
            )
        session.committed = True

    def _rollback_quietly(self) -> None:
        with suppress(psycopg.Error):
            if not self._conn.closed:
                self._conn.execute("ROLLBACK")

    @contextmanager
    def _errors(self, operation: str, *, refused: str = "") -> Iterator[None]:
        """Map a driver error to the package's own, and poison a session it hit.

        Any error aborts a PostgreSQL transaction, so a session that saw one
        can only roll back.

        :param refused: What a refusal by the database's own constraints
            means, for the integrity error's message.
        """
        try:
            yield
        except psycopg.Error as exc:
            if self._session is not None:
                self._session.failed = True
            raise _mapped(exc, operation, refused) from exc
        except BaseException:
            if self._session is not None:
                self._session.failed = True
            raise

    @contextmanager
    def _reading(self) -> Iterator[None]:
        """One consistent read.

        Inside a writer session on this store's connection the reads are the
        session's own: no other writer can commit while it holds the lock.
        Otherwise, including under a joined session, whose transaction is the
        caller's and whose snapshot may be older than the ledger, a read-only
        ``REPEATABLE READ`` transaction on this store's own connection, so
        several SELECTs see one snapshot of what is committed.
        """
        with self._guard:
            if self._in_own_session():
                self._flush()
                yield
                return
            conn = self._live()
            with self._errors("begin a read"):
                conn.execute(self._sql.begin_reading, prepare=False)
            try:
                yield
            finally:
                self._rollback_quietly()

    # -- writing ----------------------------------------------------------

    @_guarded
    def commit(self, batch: WriteBatch) -> None:
        """Write one unit of work into the open session's transaction.

        Durable when the session commits. A write the database refuses (an
        entry that does not extend the committed head, say) fails the whole
        session.

        :raises StorageError: Outside a writer session.
        :raises LedgerIntegrityError: If the database refused an entry.
        """
        if not batch:
            return
        self._require_writable("commit a transaction")
        session = self._require_session("commit a transaction")
        if session.token is not None:
            raise StorageError(
                "the chain is not written inside a joined transaction, whose snapshot may be "
                "older than the ledger: record a settlement claim there, and redeem it after "
                "the transaction commits"
            )
        session.wrote = True
        session.head = None  # the head is the session's own now
        session.delta = None
        conn = self._conn
        count = len(batch.entries)
        if not batch.redeemed:
            # Kept, and sent with the COMMIT: plain statements in one simple
            # query, never pipeline mode (nor executemany, which uses it).
            # After a pipeline the server shows the session idle in
            # transaction without having armed
            # idle_in_transaction_session_timeout, so a governor that stalled
            # right after writing would hold the writer lock forever; a message
            # that ends in COMMIT leaves no transaction open.
            session.batches.append(batch)
            session.pending += count
            return
        # Claims to book: each must still be pending, which only the count of
        # rows deleted shows, before the COMMIT. What is queued goes first.
        self._flush()
        with self._errors(_appending(count), refused=_REFUSED), conn.cursor() as cur:
            if batch.entries:
                cur.execute(
                    self._sql.insert_entries(len(batch.entries)),
                    [value for e in batch.entries for value in _entry_row(e)],
                )
            for node in batch.nodes:
                cur.execute(self._sql.upsert_node, _node_row(node))
            for event in batch.control_events:
                cur.execute(self._sql.insert_control, _control_row(event))
            for auth in batch.opened:
                cur.execute(self._sql.insert_authorization, _authorization_row(auth))
            for authorization_id in batch.closed:
                cur.execute(self._sql.delete_authorization, (authorization_id,))
            for record in batch.idempotency:
                cur.execute(self._sql.insert_idempotency, _idempotency_row(record))
            if batch.redeemed:
                # Booked exactly once: the claims leave in the same
                # transaction as the entries that book them, and every one of
                # them must still be pending.
                cur.execute(self._sql.delete_claims, (list(batch.redeemed),))
                if cur.rowcount != len(batch.redeemed):
                    session.failed = True
                    raise LedgerIntegrityError(
                        f"cannot book {len(batch.redeemed)} settlement claim(s): only "
                        f"{cur.rowcount} were still pending; a claim is booked once"
                    )

    @_guarded
    def rebuild_caches(
        self,
        *,
        nodes: Sequence[BudgetNode],
        control_events: Sequence[ControlEvent],
        authorizations: Sequence[Authorization],
    ) -> None:
        """Replace the topology, chained control events and open authorizations.

        Only inside a writer session: caches rebuilt from a view another
        governor has since moved past would erase what it wrote.
        """
        self._require_writable("repair cache tables")
        session = self._require_session("repair cache tables")
        if session.token is not None:
            raise StorageError("cannot repair cache tables inside a joined transaction")
        self._flush()
        session.wrote = True
        conn = self._conn
        with self._errors("repair cache tables"), conn.cursor() as cur:
            cur.execute(self._sql.clear_nodes)
            for node in nodes:
                cur.execute(self._sql.upsert_node, _node_row(node))
            cur.execute(self._sql.clear_chained_control)
            for event in control_events:
                cur.execute(self._sql.insert_control, _control_row(event))
            cur.execute(self._sql.clear_authorizations)
            for auth in authorizations:
                cur.execute(self._sql.insert_authorization, _authorization_row(auth))

    # -- joined transactions ----------------------------------------------

    @contextmanager
    def join(self, connection: psycopg.Connection[Any]) -> Iterator[_Session]:
        """Take part in ``connection``'s open transaction.

        See :meth:`agentgov.core.BudgetManager.joined`, which is how a
        governor joins. The writer lock is taken *inside* that transaction,
        so it is held until the caller commits or rolls back, and the block's
        settlement claims (:meth:`claim`) are written into it. This never
        commits or rolls back, and never writes the chain there.

        ``connection`` needs no privilege on the ledger's tables, only
        ``EXECUTE`` on the claim function (:meth:`grant_join`). That function
        is ``SECURITY DEFINER`` and admits a claim only with a token derived
        from a secret the caller's role cannot read and from that
        transaction's own id, so nothing else that runs in the caller's
        transaction can claim anything, and no token outlives it.

        :raises StorageError: If a session is already open on this store, or
            ``connection`` has no open transaction.
        :raises LedgerConflictError: If the writer lock was not granted within
            the transaction's own ``lock_timeout``.
        """
        self._require_writable("join a transaction")
        with self._guard:
            if self._session is not None:
                raise StorageError("cannot join a transaction inside another writer session")
            status = connection.info.transaction_status
            if status is not psycopg.pq.TransactionStatus.INTRANS:
                raise StorageError(
                    f"a governor joins an open transaction, and this connection's is {status.name}"
                )
            key = self._join_key()
            try:
                connection.execute(self._sql.lock_in_transaction)
                row = connection.execute("SELECT pg_current_xact_id()::text").fetchone()
            except psycopg.errors.LockNotAvailable as exc:
                raise LedgerConflictError(
                    f"the joined transaction was not granted the writer lock of ledger schema "
                    f"{self._schema!r} within its lock_timeout; another governor holds it"
                ) from exc
            except psycopg.Error as exc:
                raise StorageError(f"cannot join the transaction: {exc}") from exc
            assert row is not None
            token = hashlib.sha256(key + str(row[0]).encode()).digest()
            session = _Session(connection, token=token)
            self._session = session
            try:
                yield session
            finally:
                self._session = None

    def claim(self, claim: SettlementClaim) -> None:
        """Record ``claim`` in the joined transaction.

        The claim function reads nothing of the chain, only the join key
        (written at install), so the transaction's snapshot, however old,
        makes no difference to it: no conflict with any other governor.

        :raises StorageError: Outside a joined transaction.
        """
        session = self._session
        if session is None or session.token is None:
            raise StorageError("a settlement claim is written in a joined transaction only")
        with self._errors("record a settlement claim in the joined transaction"):
            session.conn.execute(
                self._sql.claim,
                (
                    session.token,
                    claim.claim_id,
                    claim.hold_id,
                    claim.scope_id,
                    str(claim.amount),
                    claim.memo,
                ),
            )
        session.wrote = True

    @_guarded
    def pending_claims(self) -> tuple[SettlementClaim, ...]:
        """Every committed claim not yet booked into the chain, oldest first."""
        with self._reading(), self._errors("read the pending settlement claims"):
            rows = self._conn.execute(self._sql.select_claims).fetchall()
        return tuple(
            SettlementClaim(
                claim_id=row[0],
                hold_id=row[1],
                scope_id=row[2],
                amount=Decimal(row[3]),
                memo=row[4],
            )
            for row in rows
        )

    @_guarded
    def grant_join(self, *roles: str) -> None:
        """Let ``roles`` settle with the ledger in transactions of their own.

        Grants ``USAGE`` on the schema and ``EXECUTE`` on the claim function,
        and nothing on any table: those roles can neither read nor write the
        ledger, and can record a claim only through a governor that joins
        their transaction. Run as the ledger's owner.

        :raises ValueError: On a role name that is not a plain identifier.
        """
        for role in roles:
            if not _SCHEMA_NAME.match(role):
                raise ValueError(f"role name {role!r} is not a plain lowercase identifier")
        with self._errors("grant joined writes"):
            for role in roles:
                for statement in self._sql.grant_join(role):
                    self._live().execute(statement)

    def _join_key(self) -> bytes:
        if self._key is None:
            with self._errors("read the ledger's join key"):
                row = self._live().execute(self._sql.get_join_key).fetchone()
            if row is None:
                raise StorageError(f"ledger schema {self._schema!r} has no join key")
            self._key = bytes(row[0])
        return self._key

    # -- reading ----------------------------------------------------------

    @_guarded
    def head(self) -> tuple[int, str]:
        """The committed length and head hash. See
        :meth:`agentgov.storage.SharedStore.head`."""
        session = self._session
        if session is not None and session.token is None and session.head is not None:
            return session.head
        self._flush()
        with self._errors("read the ledger head"):
            row = self._live().execute(self._sql.head).fetchone()
        if row is None:
            return 0, GENESIS_HASH
        return int(row[0]), str(row[1])

    @_guarded
    def load(self, *, from_checkpoint: bool = False) -> StoreImage:
        """Read every table in one consistent read.

        :param from_checkpoint: Start from the snapshot the newest CHECKPOINT
            entry names: the image then carries that snapshot and only the
            entries after it, so the read costs the entries since the
            checkpoint and the state, not the length of history.
        """
        with self._reading(), self._errors("load the ledger"):
            version = self._installed_version() or _SCHEMA_VERSION
            snapshot = (
                self._newest_snapshot() if from_checkpoint and version == _SCHEMA_VERSION else None
            )
            base = snapshot.sequence if snapshot is not None else 0
            entries = self._select_entries(after=base)
            nodes = self._select_nodes()
            if base:
                rows = self._select_control_rows(after=0, after_entry=base)
            else:
                rows = self._select_control_rows(after=0)
            authorizations = self._select_authorizations()
            found = self._conn.execute(self._sql.control_high_water).fetchone()
        return StoreImage(
            schema_version=version,
            entries=entries,
            nodes=nodes,
            control_events=tuple(event for _, event in rows),
            authorizations=authorizations,
            control_high_water=int(found[0]) if found and found[0] is not None else 0,
            snapshot=snapshot,
            base=base,
        )

    @_guarded
    def snapshot(
        self, *, after_sequence: int, after_control_row: int, authorizations: bool = True
    ) -> StoreDelta:
        """Read what changed after ``after_sequence``, in one consistent read.

        :param authorizations: Read every open authorization too. A reader
            that follows holds from the entries themselves need not.
        """
        session = self._session
        if (
            session is not None
            and session.token is None
            and session.delta is not None
            and session.after == (after_sequence, after_control_row)
            and not authorizations
        ):
            delta, session.delta = session.delta, None
            return delta
        if session is None and not authorizations and self._version == _SCHEMA_VERSION:
            return self._read_after(after_sequence, after_control_row)
        with self._reading(), self._errors("read the ledger"):
            version = self._installed_version() or _SCHEMA_VERSION
            anchor: str | None = None
            if after_sequence > 0:
                row = self._conn.execute(self._sql.entry_hash_at, (after_sequence,)).fetchone()
                anchor = None if row is None else str(row[0])
            entries = self._select_entries(after=after_sequence)
            auths = self._select_authorizations() if authorizations else ()
            rows = self._select_control_rows(after=after_control_row)
        return StoreDelta(
            schema_version=version,
            anchor_hash=anchor,
            entries=entries,
            authorizations=auths,
            legacy_control_events=tuple(event for _, event in rows if event.entry_id is None),
            control_high_water=max((row_id for row_id, _ in rows), default=after_control_row),
        )

    @_guarded
    def idempotency(self, keys: Sequence[str]) -> dict[str, IdempotencyRecord]:
        """The calls recorded under ``keys``: those of them that were made.

        Inside a writer session, read in its transaction, under the writer
        lock: no other governor can record one meanwhile. What the session
        has written itself is not sent before it commits, and not read here:
        the governor keeps the calls of its own unit of work.
        """
        if not keys:
            return {}
        conn = self._conn if self._session is not None else self._live()
        with self._errors("read the calls recorded under keys"):
            rows = conn.execute(self._sql.select_idempotency, (list(keys),)).fetchall()
        return {
            str(row[0]): IdempotencyRecord(
                key=str(row[0]),
                request=str(row[1]),
                outcome=str(row[2]),
                sequence=int(row[3]),
                created_at=_parse_iso(str(row[4])),
            )
            for row in rows
        }

    @_guarded
    def _read_after(self, after_sequence: int, after_control_row: int) -> StoreDelta:
        """What was committed after ``after_sequence`` and ``after_control_row``,
        in one message: a read-only transaction around the reads."""
        conn = self._live()
        template = self._templates(conn)["read"]
        message = template.replace("<AFTER>", str(int(after_sequence))).replace(
            "<CONTROL>", str(int(after_control_row))
        )
        with self._errors("read the ledger"):
            try:
                selected = _selected(conn.execute(message, prepare=False))
            except BaseException:
                self._rollback_quietly()
                raise
        entry_rows, control_rows = selected
        found = [_entry(row) for row in entry_rows]
        if after_sequence > 0:
            if not found or found[0].sequence != after_sequence:
                return self._delta(None, [], control_rows, after_control_row)
            return self._delta(found[0].entry_hash, found[1:], control_rows, after_control_row)
        return self._delta(None, found, control_rows, after_control_row)

    # -- checkpoints ------------------------------------------------------

    def _newest_snapshot(self) -> Snapshot | None:
        """The snapshot the newest CHECKPOINT entry names, or ``None`` when no
        entry is a checkpoint. A newest checkpoint whose snapshot is missing,
        or whose memo does not parse, comes back empty for the caller to
        refuse; it is never skipped for an older one. Inside a read."""
        row = self._conn.execute(self._sql.newest_checkpoint).fetchone()
        if row is None:
            return None
        found = _CHECKPOINT_MEMO.match(str(row[0]))
        if found is None:
            return Snapshot(sequence=0, digest="", body=b"")
        sequence = int(found.group(1))
        stored = self._conn.execute(self._sql.select_snapshot, (sequence,)).fetchone()
        if stored is None:
            return Snapshot(sequence=sequence, digest="", body=b"")
        return Snapshot(
            sequence=int(stored[0]),
            digest=str(stored[1]),
            body=bytes(stored[2]),
            signature=stored[3],
        )

    @_guarded
    def put_snapshot(self, snapshot: Snapshot) -> None:
        """Store a snapshot, once, in a transaction of its own and without the
        writer lock: the state as of a sequence never changes, so an identical
        second snapshot is a no-op and a different one is refused.

        :raises LedgerIntegrityError: If a different snapshot of the same
            sequence is already stored: two derivations of one chain disagree.
        """
        self._require_writable("store a checkpoint snapshot")
        if self._in_own_session():
            raise StorageError("a snapshot is stored outside a writer session, never inside one")
        conn = self._live()
        with self._errors("store a checkpoint snapshot"):
            conn.execute(
                self._sql.insert_snapshot,
                (snapshot.sequence, snapshot.digest, snapshot.body, snapshot.signature),
            )
            row = conn.execute(self._sql.select_snapshot, (snapshot.sequence,)).fetchone()
        if row is None or str(row[1]) != snapshot.digest:
            raise LedgerIntegrityError(
                f"a different snapshot of sequence {snapshot.sequence} is already stored: two "
                f"derivations of the same chain disagree"
            )

    @_guarded
    def snapshot_at(self, sequence: int) -> Snapshot | None:
        """The stored snapshot of ``sequence``, if any."""
        with self._reading(), self._errors("read a checkpoint snapshot"):
            row = self._conn.execute(self._sql.select_snapshot, (sequence,)).fetchone()
        if row is None:
            return None
        return Snapshot(
            sequence=int(row[0]), digest=str(row[1]), body=bytes(row[2]), signature=row[3]
        )

    @_guarded
    def checkpoints(self) -> tuple[tuple[int, int, str], ...]:
        """Every well-formed CHECKPOINT entry: its own sequence, the sequence
        its snapshot is of, and the snapshot's digest, oldest first."""
        with self._reading(), self._errors("read the ledger's checkpoints"):
            rows = self._conn.execute(self._sql.checkpoint_memos).fetchall()
        found = []
        for sequence, memo in rows:
            match = _CHECKPOINT_MEMO.match(str(memo))
            if match is not None:
                found.append((int(sequence), int(match.group(1)), match.group(2)))
        return tuple(found)

    # -- history ----------------------------------------------------------

    @_guarded
    def entry_at(self, sequence: int) -> LedgerEntry | None:
        """The entry at ``sequence``, if there is one."""
        with self._reading(), self._errors("read an entry"):
            row = self._conn.execute(self._sql.select_entry_at, (sequence,)).fetchone()
        return None if row is None else _entry(row)

    @_guarded
    def entry_by_id(self, entry_id: uuid.UUID) -> LedgerEntry | None:
        """The entry with this ``entry_id``, if there is one."""
        with self._reading(), self._errors("read an entry"):
            row = self._conn.execute(self._sql.select_entry_by_id, (entry_id,)).fetchone()
        return None if row is None else _entry(row)

    def iter_entries(
        self, *, after: int = 0, until: int | None = None, chunk: int = 10_000
    ) -> Iterator[LedgerEntry]:
        """Entries after ``after``, up to and including ``until``, oldest
        first, read ``chunk`` at a time so memory stays bounded."""
        position = after
        while until is None or position < until:
            with self._reading(), self._errors("read the ledger"):
                batch = self._select_entries(after=position, until=until, limit=chunk)
            if not batch:
                return
            yield from batch
            position = batch[-1].sequence

    @_guarded
    def find_entries(
        self,
        *,
        scope_id: str | None = None,
        entry_type: EntryType | None = None,
        memo: str | None = None,
        transaction_id: uuid.UUID | None = None,
        ref: uuid.UUID | None = None,
        after: int = 0,
        limit: int | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """Entries matching every criterion given, oldest first, by index."""
        criteria: dict[str, object] = {"after": after}
        if scope_id is not None:
            criteria["scope_id"] = scope_id
        if entry_type is not None:
            criteria["entry_type"] = entry_type.value
        if memo is not None:
            criteria["memo"] = memo
        if transaction_id is not None:
            criteria["transaction_id"] = transaction_id
        if ref is not None:
            criteria["ref"] = ref
        if limit is not None:
            criteria["limit"] = limit
        with self._reading(), self._errors("search the ledger"):
            rows = self._conn.execute(self._sql.find_entries(criteria), criteria).fetchall()
        return tuple(_entry(row) for row in rows)

    @_guarded
    def released(self, hold_id: uuid.UUID) -> bool:
        """Whether an entry released the hold ``hold_id`` by name."""
        with self._reading(), self._errors("read the ledger"):
            row = self._conn.execute(self._sql.released, (hold_id,)).fetchone()
        return row is not None

    @_guarded
    def control_events(self) -> tuple[ControlEvent, ...]:
        """Every circuit-breaker trip and reset recorded, oldest first."""
        with self._reading(), self._errors("read the control events"):
            return tuple(event for _, event in self._select_control_rows(after=0))

    # -- the auditor's marks ----------------------------------------------

    @_guarded
    def record_audit(self, mark: AuditMark) -> None:
        """Record how far an auditor verified the chain, and what it found.

        In a transaction of its own and without the writer lock: a mark is
        evidence about the chain, not part of it.
        """
        self._require_writable("record an audit mark")
        with self._errors("record an audit mark"):
            self._live().execute(
                self._sql.insert_audit_mark,
                (
                    mark.sequence,
                    mark.head,
                    mark.state_digest,
                    mark.status,
                    mark.detail,
                    mark.auditor,
                    _iso(mark.recorded_at),
                    mark.signature,
                ),
            )

    @_guarded
    def audit_marks(self) -> tuple[AuditMark, ...]:
        """Every audit mark, oldest first."""
        if self._version != _SCHEMA_VERSION:
            return ()
        with self._reading(), self._errors("read the audit marks"):
            rows = self._conn.execute(self._sql.select_audit_marks).fetchall()
        return tuple(_audit_mark(row) for row in rows)

    @_guarded
    def audit_failure(self) -> AuditMark | None:
        """The newest audit mark, if it is a failure. A later mark that
        verified the chain supersedes an earlier failure."""
        if self._version != _SCHEMA_VERSION:
            return None
        with self._reading(), self._errors("read the audit marks"):
            row = self._conn.execute(self._sql.select_newest_audit_mark).fetchone()
        mark = None if row is None else _audit_mark(row)
        return mark if mark is not None and mark.status == "failed" else None

    def fork(self) -> PostgresStore:
        """Another store over the same ledger, on a connection of its own (for
        an auditor beside this governor). Writable, so it can record audit
        marks; it never takes the writer lock."""
        return PostgresStore(
            self._conninfo,
            schema=self._schema,
            lock_timeout=self._lock_timeout_ms / 1000,
            idle_timeout=self._idle_timeout_ms / 1000,
        )

    @_guarded
    def load_entries(self) -> tuple[LedgerEntry, ...]:
        """Return every persisted entry, oldest first."""
        with self._reading(), self._errors("load the ledger's entries"):
            return self._select_entries(after=0)

    def _select_entries(
        self, *, after: int, until: int | None = None, limit: int | None = None
    ) -> tuple[LedgerEntry, ...]:
        if until is None and limit is None:
            rows = self._conn.execute(self._sql.select_entries, (after,)).fetchall()
        else:
            rows = self._conn.execute(
                self._sql.select_entries_range,
                (after, until if until is not None else 2**62, limit or 2**62),
            ).fetchall()
        return tuple(_entry(row) for row in rows)

    def _select_nodes(self) -> tuple[PersistedNode, ...]:
        rows = self._conn.execute(self._sql.select_nodes).fetchall()
        return tuple(
            PersistedNode(
                scope_id=row[0],
                parent_id=row[1],
                depth=int(row[2]),
                allocated=Decimal(row[3]),
                created_at=_parse_iso(row[4]),
            )
            for row in rows
        )

    def _select_control_rows(
        self, *, after: int, after_entry: int | None = None
    ) -> tuple[tuple[int, ControlEvent], ...]:
        if after_entry is None:
            rows = self._conn.execute(self._sql.select_control, (after,)).fetchall()
        else:
            rows = self._conn.execute(
                self._sql.select_control_after_entry, (after_entry,)
            ).fetchall()
        return _control_rows(rows)

    def _select_authorizations(self) -> tuple[PersistedAuthorization, ...]:
        rows = self._conn.execute(self._sql.select_authorizations).fetchall()
        return tuple(
            PersistedAuthorization(
                authorization_id=row[0],
                scope_id=row[1],
                amount=Decimal(row[2]),
                opened_at=_parse_iso(row[3]),
                entry_id=row[4],
            )
            for row in rows
        )

    # -- lifecycle --------------------------------------------------------

    @_guarded
    def close(self) -> None:
        """Close the connection. An open session is rolled back by the server.
        Safe to call more than once."""
        with suppress(psycopg.Error):
            self._conn.close()


def _entry(row: Any) -> LedgerEntry:
    return LedgerEntry(
        sequence=int(row[0]),
        entry_id=row[1],
        transaction_id=row[2],
        timestamp=_parse_iso(row[3]),
        entry_type=_entry_type(row[4]),
        direction=_direction(row[5]),
        scope_id=row[6],
        counterparty_id=row[7],
        amount=Decimal(row[8]),
        balance_after=Decimal(row[9]),
        prev_hash=row[10],
        entry_hash=row[11],
        memo=row[12],
        version=row[13],
        ref=row[14],
    )


def _audit_mark(row: Any) -> AuditMark:
    return AuditMark(
        sequence=int(row[0]),
        head=str(row[1]),
        state_digest=str(row[2]),
        status=str(row[3]),
        detail=str(row[4]),
        auditor=str(row[5]),
        recorded_at=_parse_iso(str(row[6])),
        signature=row[7],
    )


def _literal(value: object) -> str:
    """``value`` (an int, a UUID, text or ``None``) as an SQL literal.

    For the writes a unit of work sends with its COMMIT, as one simple query.
    Text is escaped as Unicode, before psycopg encodes the message, so no
    client encoding can split a quote; with a backslash in it, it takes the
    ``E''`` form, so it reads the same whatever ``standard_conforming_strings``
    says. PostgreSQL text cannot hold NUL, nor a simple query carry one.
    """
    if value is None:
        return "NULL"
    if isinstance(value, str):
        if "\x00" in value:
            raise StorageError("PostgreSQL text cannot hold a NUL (0x00) character")
        if "\\" in value:
            return "E'" + value.replace("\\", "\\\\").replace("'", "''") + "'"
        return "'" + value.replace("'", "''") + "'"
    if isinstance(value, uuid.UUID):
        return f"'{value}'::uuid"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise TypeError(f"no SQL literal for {type(value).__name__}")


def _values(row: Sequence[object]) -> str:
    return "(" + ", ".join([_literal(value) for value in row]) + ")"


def _entry_row(entry: LedgerEntry) -> tuple[object, ...]:
    return (
        entry.sequence,
        entry.entry_id,
        entry.transaction_id,
        _iso(entry.timestamp),
        entry.entry_type.value,
        entry.direction.value,
        entry.scope_id,
        entry.counterparty_id,
        _amount_text(entry, entry.amount),
        _amount_text(entry, entry.balance_after),
        entry.prev_hash,
        entry.entry_hash,
        entry.memo,
        entry.version,
        entry.ref,
    )


def _idempotency_row(record: IdempotencyRecord) -> tuple[object, ...]:
    return (
        record.key,
        record.request,
        record.outcome,
        record.sequence,
        _iso(record.created_at),
    )


def _node_row(node: BudgetNode) -> tuple[object, ...]:
    return (node.scope_id, node.parent_id, node.depth, str(node.allocated), _iso(node.created_at))


def _control_row(event: ControlEvent) -> tuple[object, ...]:
    return (
        event.event_id,
        _iso(event.timestamp),
        event.event_type,
        event.scope_id,
        event.reason,
        event.ledger_head_hash,
        event.entry_id,
    )


def _authorization_row(auth: Authorization) -> tuple[object, ...]:
    return (
        auth.authorization_id,
        auth.scope_id,
        str(auth.amount),
        _iso(auth.opened_at),
        auth.entry.entry_id,
    )


class _Statements:
    """Every statement the store runs, composed once for its schema.

    Identifiers are composed with :class:`psycopg.sql.Identifier`, never
    interpolated, and the schema name is validated before it gets here.
    """

    def __init__(
        self, schema: str, keys: tuple[int, int], lock_timeout_ms: int, idle_timeout_ms: int
    ) -> None:
        def table(name: str) -> sql.Identifier:
            return sql.Identifier(schema, name)

        entries, nodes = table("entries"), table("nodes")
        control, auths, meta = (
            table("control_events"),
            table("open_authorizations"),
            table("schema_meta"),
        )
        columns = sql.SQL(_ENTRY_COLUMNS)

        # No parameters, so psycopg sends this as one simple query: one round
        # trip to open the transaction, bound the wait, and take the lock.
        self.begin_locked = sql.SQL(
            "BEGIN ISOLATION LEVEL READ COMMITTED; "
            "SET LOCAL lock_timeout = {timeout}; "
            "SET LOCAL idle_in_transaction_session_timeout = {idle}; "
            "SELECT pg_advisory_xact_lock({k1}, {k2})"
        ).format(
            timeout=sql.Literal(lock_timeout_ms),
            idle=sql.Literal(idle_timeout_ms),
            k1=sql.Literal(keys[0]),
            k2=sql.Literal(keys[1]),
        )
        # A read: read-only by its own declaration, not a session default a
        # pooler could leave on a connection another client then writes on.
        self.begin_reading = sql.SQL(
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; "
            "SET LOCAL idle_in_transaction_session_timeout = {idle}"
        ).format(idle=sql.Literal(idle_timeout_ms))
        self._idle_timeout_ms = idle_timeout_ms
        self.get_version = sql.SQL("SELECT value FROM {} WHERE key = 'schema_version'").format(meta)
        self.has_schema_meta = sql.SQL(
            "SELECT 1 FROM pg_catalog.pg_class c "
            "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
            "WHERE n.nspname = %s AND c.relname = 'schema_meta'"
        )
        self.set_version = sql.SQL(
            "INSERT INTO {} (key, value) VALUES ('schema_version', %s) "
            "ON CONFLICT (key) DO UPDATE SET value = excluded.value"
        ).format(meta)
        self.head = sql.SQL(
            "SELECT sequence, entry_hash FROM {} ORDER BY sequence DESC LIMIT 1"
        ).format(entries)
        self.entry_hash_at = sql.SQL("SELECT entry_hash FROM {} WHERE sequence = %s").format(
            entries
        )
        self._entries_table = entries
        self._columns = columns
        self.select_entries = sql.SQL(
            "SELECT {} FROM {} WHERE sequence > %s ORDER BY sequence ASC"
        ).format(columns, entries)
        self.select_entries_from = sql.SQL(
            "SELECT {} FROM {} WHERE sequence >= %s ORDER BY sequence ASC"
        ).format(columns, entries)
        self.select_entries_range = sql.SQL(
            "SELECT {} FROM {} WHERE sequence > %s AND sequence <= %s "
            "ORDER BY sequence ASC LIMIT %s"
        ).format(columns, entries)
        self.select_entry_at = sql.SQL("SELECT {} FROM {} WHERE sequence = %s").format(
            columns, entries
        )
        self.select_entry_by_id = sql.SQL("SELECT {} FROM {} WHERE entry_id = %s").format(
            columns, entries
        )
        self.newest_checkpoint = sql.SQL(
            "SELECT memo FROM {} WHERE entry_type = 'checkpoint' ORDER BY sequence DESC LIMIT 1"
        ).format(entries)
        self.checkpoint_memos = sql.SQL(
            "SELECT sequence, memo FROM {} WHERE entry_type = 'checkpoint' ORDER BY sequence ASC"
        ).format(entries)
        self.released = sql.SQL(
            "SELECT 1 FROM {} WHERE entry_type = 'hold_void' AND ref = %s LIMIT 1"
        ).format(entries)
        snapshots, marks = table("snapshots"), table("audit_marks")
        self.insert_snapshot = sql.SQL(
            "INSERT INTO {} (sequence, digest, body, signature) VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (sequence) DO NOTHING"
        ).format(snapshots)
        self.select_snapshot = sql.SQL(
            "SELECT sequence, digest, body, signature FROM {} WHERE sequence = %s"
        ).format(snapshots)
        self.insert_audit_mark = sql.SQL(
            "INSERT INTO {} (sequence, head, state_digest, status, detail, auditor, "
            "recorded_at, signature) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        ).format(marks)
        self.select_audit_marks = sql.SQL(
            "SELECT sequence, head, state_digest, status, detail, auditor, recorded_at, "
            "signature FROM {} ORDER BY id ASC"
        ).format(marks)
        self.select_newest_audit_mark = sql.SQL(
            "SELECT sequence, head, state_digest, status, detail, auditor, recorded_at, "
            "signature FROM {} ORDER BY id DESC LIMIT 1"
        ).format(marks)
        self.control_high_water = sql.SQL("SELECT max(id) FROM {}").format(control)
        self._entries_columns = columns
        self.upsert_node = sql.SQL(
            "INSERT INTO {} (scope_id, parent_id, depth, allocated, created_at) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT (scope_id) DO UPDATE SET parent_id = excluded.parent_id, "
            "depth = excluded.depth, allocated = excluded.allocated"
        ).format(nodes)
        self.select_nodes = sql.SQL(
            "SELECT scope_id, parent_id, depth, allocated, created_at FROM {}"
        ).format(nodes)
        self.clear_nodes = sql.SQL("DELETE FROM {}").format(nodes)
        self.insert_control = sql.SQL(
            "INSERT INTO {} "
            "(event_id, timestamp, event_type, scope_id, reason, ledger_head_hash, entry_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)"
        ).format(control)
        self.select_control = sql.SQL(
            "SELECT id, event_id, timestamp, event_type, scope_id, reason, ledger_head_hash, "
            "entry_id FROM {} WHERE id > %s ORDER BY id ASC"
        ).format(control)
        self.select_control_after_entry = sql.SQL(
            "SELECT c.id, c.event_id, c.timestamp, c.event_type, c.scope_id, c.reason, "
            "c.ledger_head_hash, c.entry_id FROM {} AS c WHERE c.entry_id IS NULL OR "
            "c.entry_id IN (SELECT e.entry_id FROM {} AS e WHERE e.sequence > %s) "
            "ORDER BY c.id ASC"
        ).format(control, entries)
        self.clear_chained_control = sql.SQL("DELETE FROM {} WHERE entry_id IS NOT NULL").format(
            control
        )
        self.insert_authorization = sql.SQL(
            "INSERT INTO {} (authorization_id, scope_id, amount, opened_at, entry_id) "
            "VALUES (%s, %s, %s, %s, %s)"
        ).format(auths)
        self.delete_authorization = sql.SQL("DELETE FROM {} WHERE authorization_id = %s").format(
            auths
        )
        # What a unit of work's writes are made of: each is completed with
        # rows of literals (see _literal) and sent with its COMMIT.
        self.writes: dict[str, sql.Composable] = {
            "entries": sql.SQL("INSERT INTO {} ({}) VALUES ").format(entries, columns),
            "nodes": sql.SQL(
                "INSERT INTO {} (scope_id, parent_id, depth, allocated, created_at) VALUES "
            ).format(nodes),
            "nodes_conflict": sql.SQL(
                " ON CONFLICT (scope_id) DO UPDATE SET parent_id = excluded.parent_id, "
                "depth = excluded.depth, allocated = excluded.allocated"
            ),
            "controls": sql.SQL(
                "INSERT INTO {} "
                "(event_id, timestamp, event_type, scope_id, reason, ledger_head_hash, entry_id) "
                "VALUES "
            ).format(control),
            "authorizations": sql.SQL(
                "INSERT INTO {} (authorization_id, scope_id, amount, opened_at, entry_id) VALUES "
            ).format(auths),
            "close": sql.SQL("DELETE FROM {} WHERE authorization_id IN (").format(auths),
            "keys": sql.SQL(
                "INSERT INTO {} (key, request, outcome, sequence, created_at) VALUES "
            ).format(table("idempotency")),
        }
        self.insert_idempotency = sql.SQL(
            "INSERT INTO {} (key, request, outcome, sequence, created_at) "
            "VALUES (%s, %s, %s, %s, %s)"
        ).format(table("idempotency"))
        self.select_idempotency = sql.SQL(
            "SELECT key, request, outcome, sequence, created_at FROM {} WHERE key = ANY(%s)"
        ).format(table("idempotency"))
        self.select_authorizations = sql.SQL(
            "SELECT authorization_id, scope_id, amount, opened_at, entry_id FROM {}"
        ).format(auths)
        self.clear_authorizations = sql.SQL("DELETE FROM {}").format(auths)
        self.install = (*_install_statements(schema), *_pg2_statements(schema))
        self.upgrade = _pg2_statements(schema)
        self._insert_entries: dict[int, sql.Composed] = {}

        self._keys = keys

        # Joined transactions. The lock is the same key as begin_locked's,
        # taken inside a transaction the caller opened.
        self.lock_in_transaction = sql.SQL("SELECT pg_advisory_xact_lock({k1}, {k2})").format(
            k1=sql.Literal(keys[0]), k2=sql.Literal(keys[1])
        )
        join_key = table("join_key")
        self.get_join_key = sql.SQL("SELECT k FROM {}").format(join_key)
        self.set_join_key = sql.SQL("INSERT INTO {} (k) VALUES (%s)").format(join_key)
        claims = table("claims")
        self.claim = sql.SQL("SELECT {}(%s, %s, %s, %s, %s, %s)").format(table("claim"))
        self.select_claims = sql.SQL(
            "SELECT claim_id, hold_id, scope_id, amount, memo FROM {} ORDER BY seq"
        ).format(claims)
        self.delete_claims = sql.SQL("DELETE FROM {} WHERE claim_id = ANY(%s)").format(claims)
        self._schema = sql.Identifier(schema)
        self._claim_fn = table("claim")

    def grant_join(self, role: str) -> tuple[sql.Composed, ...]:
        """What :meth:`PostgresStore.grant_join` grants ``role``, and no more."""
        who = sql.Identifier(role)
        return (
            sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(self._schema, who),
            sql.SQL(
                "GRANT EXECUTE ON FUNCTION {}(bytea, uuid, uuid, text, text, text) TO {}"
            ).format(self._claim_fn, who),
        )

    def probe_lock(self, timeout_ms: int) -> sql.Composed:
        """A transaction that only tries for the writer lock, for ``timeout_ms``."""
        return sql.SQL(
            "BEGIN; SET LOCAL lock_timeout = {timeout}; "
            "SET LOCAL idle_in_transaction_session_timeout = {idle}; "
            "SELECT pg_advisory_xact_lock({k1}, {k2})"
        ).format(
            timeout=sql.Literal(timeout_ms),
            idle=sql.Literal(self._idle_timeout_ms),
            k1=sql.Literal(self._keys[0]),
            k2=sql.Literal(self._keys[1]),
        )

    def find_entries(self, criteria: dict[str, object]) -> sql.Composed:
        """A SELECT of the entries matching ``criteria``, by index."""
        clauses = [sql.SQL("sequence > %(after)s")]
        if "scope_id" in criteria:
            clauses.append(sql.SQL("scope_id = %(scope_id)s"))
        if "entry_type" in criteria:
            clauses.append(sql.SQL("entry_type = %(entry_type)s"))
        if "memo" in criteria:
            # Through the (entry_type, md5(memo)) index, then exactly.
            clauses.append(sql.SQL("md5(memo) = md5(%(memo)s) AND memo = %(memo)s"))
        if "transaction_id" in criteria:
            clauses.append(sql.SQL("transaction_id = %(transaction_id)s"))
        if "ref" in criteria:
            clauses.append(sql.SQL("ref = %(ref)s"))
        limit = sql.SQL(" LIMIT %(limit)s") if "limit" in criteria else sql.SQL("")
        return sql.SQL("SELECT {} FROM {} WHERE {} ORDER BY sequence ASC{}").format(
            self._entries_columns, self._entries_table, sql.SQL(" AND ").join(clauses), limit
        )

    def insert_entries(self, count: int) -> sql.Composed:
        """One INSERT of ``count`` entries, in chain order. Composed once per size."""
        statement = self._insert_entries.get(count)
        if statement is None:
            row = sql.SQL("({})").format(sql.SQL(", ").join([sql.Placeholder()] * 15))
            statement = sql.SQL("INSERT INTO {} ({}) VALUES {}").format(
                self._entries_table, self._columns, sql.SQL(", ").join([row] * count)
            )
            self._insert_entries[count] = statement
        return statement


def _install_statements(schema: str) -> tuple[sql.Composed, ...]:
    """The DDL for a new ledger. Run once, in one transaction, under the lock."""

    def table(name: str) -> sql.Identifier:
        return sql.Identifier(schema, name)

    entries = table("entries")
    extend, append_only = table("extend_chain"), table("append_only")
    return (
        sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema)),
        sql.SQL("CREATE TABLE {} (key text PRIMARY KEY, value text NOT NULL)").format(
            table("schema_meta")
        ),
        sql.SQL(
            """
            CREATE TABLE {} (
                sequence        bigint PRIMARY KEY CHECK (sequence > 0),
                entry_id        uuid NOT NULL UNIQUE,
                transaction_id  uuid NOT NULL,
                timestamp       text NOT NULL,
                entry_type      text NOT NULL,
                direction       text NOT NULL,
                scope_id        text NOT NULL,
                counterparty_id text,
                amount          text NOT NULL,
                balance_after   text NOT NULL,
                prev_hash       text NOT NULL,
                entry_hash      text NOT NULL,
                memo            text NOT NULL DEFAULT '',
                version         text NOT NULL,
                ref             uuid
            )
            """
        ).format(entries),
        sql.SQL(
            """
            CREATE TABLE {} (
                scope_id   text PRIMARY KEY,
                parent_id  text,
                depth      integer NOT NULL,
                allocated  text NOT NULL,
                created_at text NOT NULL
            )
            """
        ).format(table("nodes")),
        sql.SQL(
            """
            CREATE TABLE {} (
                id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                event_id         uuid NOT NULL UNIQUE,
                timestamp        text NOT NULL,
                event_type       text NOT NULL,
                scope_id         text NOT NULL,
                reason           text NOT NULL,
                ledger_head_hash text NOT NULL,
                entry_id         uuid
            )
            """
        ).format(table("control_events")),
        sql.SQL(
            """
            CREATE TABLE {} (
                authorization_id uuid PRIMARY KEY,
                scope_id         text NOT NULL,
                amount           text NOT NULL,
                opened_at        text NOT NULL,
                entry_id         uuid NOT NULL
            )
            """
        ).format(table("open_authorizations")),
        # An entry is admitted only if it links to the one before it. With
        # `sequence` the primary key, that makes an insert succeed only on the
        # committed head: a stale or lock-skipping writer is refused, never
        # forked. The message names no hash, so a refusal leaks nothing.
        sql.SQL(
            """
            CREATE FUNCTION {fn}() RETURNS trigger LANGUAGE plpgsql
            SET search_path = pg_catalog, pg_temp AS $agentgov$
            BEGIN
                IF NEW.sequence = 1 THEN
                    IF NEW.prev_hash <> {genesis} THEN
                        RAISE EXCEPTION 'agentgov: entry 1 does not link to the genesis hash'
                            USING ERRCODE = 'integrity_constraint_violation';
                    END IF;
                ELSIF NOT EXISTS (
                    SELECT 1 FROM {entries} AS e
                    WHERE e.sequence = NEW.sequence - 1 AND e.entry_hash = NEW.prev_hash
                ) THEN
                    RAISE EXCEPTION 'agentgov: entry % does not extend the committed chain',
                        NEW.sequence
                        USING ERRCODE = 'integrity_constraint_violation',
                              HINT = 'a writer must hold the ledger writer lock and build on '
                                     'the committed head';
                END IF;
                RETURN NEW;
            END
            $agentgov$
            """
        ).format(fn=extend, entries=entries, genesis=sql.Literal(GENESIS_HASH)),
        sql.SQL(
            """
            CREATE FUNCTION {fn}() RETURNS trigger LANGUAGE plpgsql
            SET search_path = pg_catalog, pg_temp AS $agentgov$
            BEGIN
                RAISE EXCEPTION 'agentgov: ledger entries are append-only; % refused', TG_OP
                    USING ERRCODE = 'integrity_constraint_violation';
            END
            $agentgov$
            """
        ).format(fn=append_only),
        sql.SQL(
            "CREATE TRIGGER extend_chain BEFORE INSERT ON {} FOR EACH ROW EXECUTE FUNCTION {}()"
        ).format(entries, extend),
        sql.SQL(
            "CREATE TRIGGER append_only BEFORE UPDATE OR DELETE ON {} "
            "FOR EACH ROW EXECUTE FUNCTION {}()"
        ).format(entries, append_only),
        sql.SQL(
            "CREATE TRIGGER append_only_truncate BEFORE TRUNCATE ON {} "
            "FOR EACH STATEMENT EXECUTE FUNCTION {}()"
        ).format(entries, append_only),
        # ALWAYS: session_replication_role = replica does not switch them off.
        sql.SQL(
            "ALTER TABLE {} ENABLE ALWAYS TRIGGER extend_chain, "
            "ENABLE ALWAYS TRIGGER append_only, ENABLE ALWAYS TRIGGER append_only_truncate"
        ).format(entries),
        *_join_statements(schema),
    )


def _pg2_statements(schema: str) -> tuple[sql.Composed, ...]:
    """What layout pg2 adds to pg1. Each statement is idempotent, so the same
    list both completes a fresh install and upgrades a pg1 schema in place,
    under the writer lock. Building the indexes over a long ledger takes a
    while, once."""

    def table(name: str) -> sql.Identifier:
        return sql.Identifier(schema, name)

    entries, control = table("entries"), table("control_events")
    snapshots, marks = table("snapshots"), table("audit_marks")
    frozen = table("append_only_rows")
    return (
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {} (
                sequence   bigint PRIMARY KEY CHECK (sequence > 0),
                digest     text NOT NULL,
                body       bytea NOT NULL,
                signature  text,
                created_at timestamptz NOT NULL DEFAULT now()
            )
            """
        ).format(snapshots),
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {} (
                id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                sequence     bigint NOT NULL,
                head         text NOT NULL,
                state_digest text NOT NULL,
                status       text NOT NULL CHECK (status IN ('verified', 'failed')),
                detail       text NOT NULL,
                auditor      text NOT NULL,
                recorded_at  text NOT NULL,
                signature    text
            )
            """
        ).format(marks),
        sql.SQL(
            """
            CREATE TABLE IF NOT EXISTS {} (
                key        text PRIMARY KEY,
                request    text NOT NULL,
                outcome    text NOT NULL,
                sequence   bigint NOT NULL,
                created_at text NOT NULL
            )
            """
        ).format(table("idempotency")),
        # History is looked up by scope and by type, never by transaction_id
        # or ref (random values: an index would cost every commit a page).
        sql.SQL("CREATE INDEX IF NOT EXISTS entries_by_scope ON {} (scope_id, sequence)").format(
            entries
        ),
        # md5, not the memo itself: a btree entry is limited to about 2.7 kB.
        sql.SQL(
            "CREATE INDEX IF NOT EXISTS entries_by_type_memo ON {} (entry_type, md5(memo))"
        ).format(entries),
        sql.SQL(
            "CREATE INDEX IF NOT EXISTS entries_checkpoints ON {} (sequence) "
            "WHERE entry_type = 'checkpoint'"
        ).format(entries),
        sql.SQL("CREATE INDEX IF NOT EXISTS control_events_by_entry ON {} (entry_id)").format(
            control
        ),
        # Snapshots and audit marks are evidence: never edited, never deleted.
        sql.SQL(
            """
            CREATE OR REPLACE FUNCTION {fn}() RETURNS trigger LANGUAGE plpgsql
            SET search_path = pg_catalog, pg_temp AS $agentgov$
            BEGIN
                RAISE EXCEPTION 'agentgov: % refused: % is append-only', TG_OP, TG_TABLE_NAME
                    USING ERRCODE = 'integrity_constraint_violation';
            END
            $agentgov$
            """
        ).format(fn=frozen),
        *(
            statement
            for name, target in (("snapshots", snapshots), ("audit_marks", marks))
            for statement in (
                sql.SQL(
                    "CREATE OR REPLACE TRIGGER {} BEFORE UPDATE OR DELETE ON {} "
                    "FOR EACH ROW EXECUTE FUNCTION {}()"
                ).format(sql.Identifier(f"{name}_append_only"), target, frozen),
                sql.SQL(
                    "CREATE OR REPLACE TRIGGER {} BEFORE TRUNCATE ON {} "
                    "FOR EACH STATEMENT EXECUTE FUNCTION {}()"
                ).format(sql.Identifier(f"{name}_append_only_truncate"), target, frozen),
                sql.SQL("ALTER TABLE {} ENABLE ALWAYS TRIGGER {}, ENABLE ALWAYS TRIGGER {}").format(
                    target,
                    sql.Identifier(f"{name}_append_only"),
                    sql.Identifier(f"{name}_append_only_truncate"),
                ),
            )
        ),
    )


def _join_statements(schema: str) -> tuple[sql.Composed, ...]:
    """What lets a caller's transaction owe the ledger, and nothing more.

    That transaction runs as the caller's role, and so does everything else
    in it (an agent's statements, for an escrow), so the role gets no
    privilege on the ledger's tables at all: only ``EXECUTE`` on ``claim``, a
    ``SECURITY DEFINER`` function that records one settlement claim. It admits
    it only with ``sha256(key || the transaction's own id)``. The key is
    readable by the ledger's owner and governors, never by the caller's role,
    so nothing but a governor can compute a token, and a token is good for one
    transaction.

    ``claim`` reads nothing of the chain: only the key, written at install.
    So a caller whose ``REPEATABLE READ`` snapshot is older than the ledger
    records its claim all the same, whatever other governors committed
    since. A hold is claimed at most once (``hold_id`` is unique).
    """

    def table(name: str) -> sql.Identifier:
        return sql.Identifier(schema, name)

    key, claims, fn = table("join_key"), table("claims"), table("claim")
    return (
        sql.SQL(
            "CREATE TABLE {} (singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), "
            "k bytea NOT NULL CHECK (length(k) >= 32))"
        ).format(key),
        sql.SQL(
            """
            CREATE TABLE {} (
                seq        bigint GENERATED ALWAYS AS IDENTITY UNIQUE,
                claim_id   uuid PRIMARY KEY,
                hold_id    uuid UNIQUE,
                scope_id   text NOT NULL,
                amount     text NOT NULL,
                memo       text NOT NULL,
                claimed_by xid8 NOT NULL DEFAULT pg_current_xact_id(),
                claimed_at timestamptz NOT NULL DEFAULT now()
            )
            """
        ).format(claims),
        sql.SQL(
            """
            CREATE FUNCTION {fn}(
                p_token bytea, p_claim uuid, p_hold uuid, p_scope text, p_amount text,
                p_memo text
            ) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
            SET search_path = pg_catalog, pg_temp AS $agentgov$
            DECLARE
                expected bytea;
            BEGIN
                SELECT sha256(j.k || convert_to(pg_current_xact_id()::text, 'UTF8'))
                  INTO expected FROM {key} AS j;
                IF expected IS NULL OR p_token IS DISTINCT FROM expected THEN
                    RAISE EXCEPTION 'agentgov: no governor of this ledger joined this transaction'
                        USING ERRCODE = 'insufficient_privilege';
                END IF;
                INSERT INTO {claims} (claim_id, hold_id, scope_id, amount, memo)
                VALUES (p_claim, p_hold, p_scope, p_amount, p_memo);
            END
            $agentgov$
            """
        ).format(fn=fn, key=key, claims=claims),
        # Functions are EXECUTE-able by PUBLIC unless revoked; this one is
        # granted only to the roles grant_join() names.
        sql.SQL(
            "REVOKE ALL ON FUNCTION {}(bytea, uuid, uuid, text, text, text) FROM PUBLIC"
        ).format(fn),
    )
