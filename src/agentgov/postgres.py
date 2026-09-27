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
from collections.abc import Iterator, Sequence
from contextlib import contextmanager, suppress
from decimal import Decimal
from typing import Any, Final, LiteralString

from agentgov.core import (
    GENESIS_HASH,
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
from agentgov.exceptions import LedgerIntegrityError, ReadOnlyLedgerError, StorageError
from agentgov.storage import PersistedAuthorization, PersistedNode, StoreDelta, StoreImage

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

_SCHEMA_VERSION: Final = "pg1"
"""The PostgreSQL layout. The same logical tables as SQLite's version 2."""

_SUPPORTED_VERSIONS: Final = frozenset({_SCHEMA_VERSION})

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


class _Session:
    """One writer session. See :class:`~agentgov.storage.WriterSession`."""

    __slots__ = ("committed", "failed", "wrote")

    def __init__(self) -> None:
        self.committed = False
        self.wrote = False
        self.failed = False


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
        refused, and the session itself set read-only.
    :param lock_timeout: Seconds to wait for the writer lock before giving up
        with :class:`~agentgov.exceptions.StorageError`.
    :param idle_timeout: Seconds the server lets this governor sit idle inside
        an open transaction before ending its session. A governor that hangs
        while it holds the writer lock (a stopped process, a stalled host)
        would otherwise stall the whole fleet; this bounds that, and the
        governor finds out, and re-reads the ledger, at its next operation.
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
        self._session: _Session | None = None
        self._sql = _Statements(schema, _lock_keys(schema), self._lock_timeout_ms)
        self._conn = self._connect()
        try:
            self._version = self._open()
        except BaseException:
            self._conn.close()
            raise

    # -- connection -------------------------------------------------------

    def _connect(self) -> psycopg.Connection[tuple[Any, ...]]:
        try:
            conn = psycopg.connect(self._conninfo, autocommit=True)
        except psycopg.Error as exc:
            raise StorageError(f"cannot connect to the ledger database: {exc}") from exc
        try:
            conn.execute(
                sql.SQL("SET idle_in_transaction_session_timeout = {}").format(
                    sql.Literal(self._idle_timeout_ms)
                )
            )
            if self._read_only:
                conn.execute("SET default_transaction_read_only = on")
        except psycopg.Error as exc:
            conn.close()
            raise StorageError(f"cannot configure the ledger connection: {exc}") from exc
        return conn

    def _live(self) -> psycopg.Connection[tuple[Any, ...]]:
        """The connection, reopened if the server ended the last one.

        Only ever between sessions: a session whose connection died is over,
        and its governor re-reads the ledger rather than carrying on.
        """
        if self._conn.closed and self._session is None:
            self._conn = self._connect()
        return self._conn

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
        if self._read_only:
            with self._reading():
                version = self._installed_version()
            if version is None:
                raise StorageError(
                    f"schema {self._schema!r} holds no agentgov ledger; open it for writing "
                    f"once to create one"
                )
            return version
        with self.writer():
            version = self._installed_version()
            if version is None:
                conn = self._conn
                with self._errors(f"create the ledger schema {self._schema!r}"):
                    for statement in self._sql.install:
                        conn.execute(statement)
                    conn.execute(self._sql.set_version, (_SCHEMA_VERSION,))
                version = _SCHEMA_VERSION
        return version

    def _installed_version(self) -> str | None:
        conn = self._conn
        with self._errors("read the ledger's schema version"):
            row = conn.execute(
                "SELECT to_regclass(%s)", (f"{self._schema}.schema_meta",)
            ).fetchone()
            if row is None or row[0] is None:
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

    @contextmanager
    def writer(self) -> Iterator[_Session]:
        """Take the writer lock for one unit of work. See
        :meth:`agentgov.storage.SharedStore.writer`.

        :raises ReadOnlyLedgerError: If this store was opened read-only.
        :raises StorageError: If the lock was not granted within
            ``lock_timeout``, or the database could not be reached.
        """
        self._require_writable("write the ledger")
        if self._session is not None:
            yield self._session
            return
        session = _Session()
        self._begin()
        self._session = session
        try:
            yield session
        except BaseException:
            self._session = None
            self._end(session)
            raise
        self._session = None
        self._end(session)

    def _begin(self) -> None:
        """Open the transaction and take the lock, reconnecting once if the
        server ended an idle connection since the last session."""
        for attempt in (1, 2):
            conn = self._live()
            try:
                conn.execute(self._sql.begin_locked)
                return
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
        except psycopg.errors.IntegrityError as exc:
            if self._session is not None:
                self._session.failed = True
            raise LedgerIntegrityError(f"cannot {operation}{refused}: {exc}") from exc
        except psycopg.Error as exc:
            if self._session is not None:
                self._session.failed = True
            raise StorageError(f"cannot {operation}: {exc}") from exc
        except BaseException:
            if self._session is not None:
                self._session.failed = True
            raise

    @contextmanager
    def _reading(self) -> Iterator[None]:
        """One consistent read.

        Inside a writer session the reads are the session's own: no other
        writer can commit while it holds the lock. Outside one, a read-only
        ``REPEATABLE READ`` transaction, so several SELECTs see one snapshot.
        """
        if self._session is not None:
            yield
            return
        conn = self._live()
        with self._errors("begin a read"):
            conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        try:
            yield
        finally:
            self._rollback_quietly()

    # -- writing ----------------------------------------------------------

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
        session.wrote = True
        conn = self._conn
        count = len(batch.entries)
        noun = "entry" if count == 1 else "entries"
        # A duplicate sequence and a broken link are the same event: these
        # entries were built on a head that is no longer the committed one.
        refused = "; the database admits only entries that extend the committed head"
        # Plain statements, never pipeline mode (nor executemany, which uses
        # it): after a pipeline the server shows the session idle in
        # transaction but has not armed idle_in_transaction_session_timeout,
        # so a governor that stalled right after writing would hold the writer
        # lock forever. The entries go in as one multi-row INSERT, so a batch
        # is still one round trip; a row trigger sees the rows the same
        # statement inserted before it, so the chain check holds within it.
        with self._errors(f"durably append {count} {noun}", refused=refused), conn.cursor() as cur:
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

    # -- reading ----------------------------------------------------------

    def head(self) -> tuple[int, str]:
        """The committed length and head hash. See
        :meth:`agentgov.storage.SharedStore.head`."""
        with self._errors("read the ledger head"):
            row = self._live().execute(self._sql.head).fetchone()
        if row is None:
            return 0, GENESIS_HASH
        return int(row[0]), str(row[1])

    def load(self) -> StoreImage:
        """Read every table in one consistent read."""
        with self._reading(), self._errors("load the ledger"):
            version = self._installed_version() or _SCHEMA_VERSION
            entries = self._select_entries(after=0)
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
        with self._reading(), self._errors("read the ledger"):
            version = self._installed_version() or _SCHEMA_VERSION
            anchor: str | None = None
            if after_sequence > 0:
                row = self._conn.execute(self._sql.entry_hash_at, (after_sequence,)).fetchone()
                anchor = None if row is None else str(row[0])
            entries = self._select_entries(after=after_sequence)
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
        with self._reading(), self._errors("load the ledger's entries"):
            return self._select_entries(after=0)

    def _select_entries(self, *, after: int) -> tuple[LedgerEntry, ...]:
        rows = self._conn.execute(self._sql.select_entries, (after,)).fetchall()
        return tuple(
            LedgerEntry(
                sequence=int(row[0]),
                entry_id=row[1],
                transaction_id=row[2],
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
                version=row[13],
                ref=row[14],
            )
            for row in rows
        )

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

    def _select_control_rows(self, *, after: int) -> tuple[tuple[int, ControlEvent], ...]:
        rows = self._conn.execute(self._sql.select_control, (after,)).fetchall()
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

    def close(self) -> None:
        """Close the connection. An open session is rolled back by the server.
        Safe to call more than once."""
        with suppress(psycopg.Error):
            self._conn.close()


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
        str(entry.amount),
        str(entry.balance_after),
        entry.prev_hash,
        entry.entry_hash,
        entry.memo,
        entry.version,
        entry.ref,
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

    def __init__(self, schema: str, keys: tuple[int, int], lock_timeout_ms: int) -> None:
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
            "SELECT pg_advisory_xact_lock({k1}, {k2})"
        ).format(
            timeout=sql.Literal(lock_timeout_ms),
            k1=sql.Literal(keys[0]),
            k2=sql.Literal(keys[1]),
        )
        self.get_version = sql.SQL("SELECT value FROM {} WHERE key = 'schema_version'").format(meta)
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
        self.select_authorizations = sql.SQL(
            "SELECT authorization_id, scope_id, amount, opened_at, entry_id FROM {}"
        ).format(auths)
        self.clear_authorizations = sql.SQL("DELETE FROM {}").format(auths)
        self.install = _install_statements(schema)
        self._insert_entries: dict[int, sql.Composed] = {}

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
    )
