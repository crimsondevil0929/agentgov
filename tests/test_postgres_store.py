"""The PostgreSQL shared ledger: what the store and the database guarantee.

The concurrency proofs are in ``test_fleet_concurrency.py``. This file pins the
store's own contract: what it installs, what survives a restart, what the
database refuses on its own (a forked, gapped or edited chain), and how a
governor recovers when a session fails, hangs or loses its connection.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import suppress
from decimal import Decimal
from typing import Any, LiteralString

import psycopg
import pytest
from psycopg import sql

from agentgov.core import (
    GENESIS_HASH,
    BudgetManager,
    EntryType,
    GovernancePolicy,
    Ledger,
    LedgerEntry,
    WriteBatch,
    money,
)
from agentgov.exceptions import (
    CircuitOpenError,
    DoubleSpendError,
    LedgerIntegrityError,
    ReadOnlyLedgerError,
    StorageError,
)
from agentgov.postgres import PostgresStore
from agentgov.storage import SharedStore

pytestmark = pytest.mark.usefixtures("pg_dsn")

ADVISORY = GovernancePolicy(trip_on_overdraft=False, trip_on_exhaustion=False)


def admin(dsn: str) -> psycopg.Connection[tuple[Any, ...]]:
    """An autocommit connection as the database's owner."""
    return psycopg.connect(dsn, autocommit=True)


def seeded(dsn: str, **kwargs: Any) -> BudgetManager:
    """A governor over a ledger with ``org`` (10.00) and ``agent`` (2.00)."""
    gov = BudgetManager.open_postgres(dsn, **kwargs)
    if "org" not in gov.scopes():
        gov.open_root("org", "10.00")
        gov.delegate("org", "agent", "2.00")
    return gov


@pytest.fixture
def gov(pg_dsn: str) -> Iterator[BudgetManager]:
    manager = seeded(pg_dsn)
    try:
        yield manager
    finally:
        manager.close()


# --------------------------------------------------------------------------
# Install and restart
# --------------------------------------------------------------------------


def test_the_store_is_a_shared_store_and_sqlite_is_not(pg_dsn: str) -> None:
    from agentgov.storage import SqliteStore

    store = PostgresStore(pg_dsn)
    try:
        assert isinstance(store, SharedStore)
        assert store.schema == "agentgov"
        assert store.schema_version == "pg1"
    finally:
        store.close()
    single = SqliteStore(":memory:")
    try:
        assert not isinstance(single, SharedStore)
    finally:
        single.close()


def test_a_fresh_database_starts_empty_and_installs_its_schema(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn) as gov:
        assert len(gov.ledger) == 0
        assert gov.scopes() == ()
    with admin(pg_dsn) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema = 'agentgov'"
            )
        }
    assert tables == {"schema_meta", "entries", "nodes", "control_events", "open_authorizations"}


def test_state_survives_every_governor_closing(pg_dsn: str) -> None:
    with seeded(pg_dsn) as gov:
        auth = gov.authorize("agent", "0.40")
        gov.capture(auth, "0.25")
        held = gov.authorize("agent", "0.10")
        gov.trip("agent", "operator halt")
        head, length = gov.ledger.head_hash, len(gov.ledger)

    with BudgetManager.open_postgres(pg_dsn) as reopened:
        assert (reopened.ledger.head_hash, len(reopened.ledger)) == (head, length)
        assert reopened.available("agent") == money("1.65")
        assert reopened.is_halted("agent")
        assert [a.authorization_id for a in reopened.stale_authorizations(0)] == [
            held.authorization_id
        ]
        reopened.verify_integrity()
        # The hold placed before the restart settles after it, on the governor
        # that restored it.
        reopened.capture(held, "0.05")
        assert reopened.available("agent") == money("1.70")


def test_governors_starting_together_do_not_race_the_install(pg_dsn: str) -> None:
    """The DDL runs under the writer lock, so N first opens make one schema."""
    barrier = threading.Barrier(8)
    errors: list[BaseException] = []

    def open_one() -> None:
        barrier.wait()
        try:
            BudgetManager.open_postgres(pg_dsn).close()
        except BaseException as exc:  # pragma: no cover - the failure being tested for
            errors.append(exc)

    threads = [threading.Thread(target=open_one) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []


def test_two_schemas_are_two_independent_ledgers(pg_dsn: str) -> None:
    with (
        BudgetManager.open_postgres(pg_dsn, schema="fleet_a") as a,
        BudgetManager.open_postgres(pg_dsn, schema="fleet_b") as b,
    ):
        a.open_root("org", "1.00")
        b.open_root("org", "2.00")  # not a duplicate: another ledger
        assert (a.available("org"), b.available("org")) == (money("1.00"), money("2.00"))


def test_a_schema_name_that_is_not_a_plain_identifier_is_refused(pg_dsn: str) -> None:
    for bad in ("Agentgov", "agent-gov", "1agentgov", 'x"; DROP TABLE y; --', ""):
        with pytest.raises(ValueError, match="schema name"):
            PostgresStore(pg_dsn, schema=bad)


def test_an_unreachable_database_is_a_storage_error() -> None:
    with pytest.raises(StorageError, match="cannot connect"):
        PostgresStore("postgresql://nobody@127.0.0.1:1/none?connect_timeout=1")


def test_an_incompatible_layout_version_refuses_to_open(pg_dsn: str, gov: BudgetManager) -> None:
    with admin(pg_dsn) as conn:
        conn.execute("UPDATE agentgov.schema_meta SET value = 'pg99'")
    with pytest.raises(LedgerIntegrityError, match="pg99"):
        BudgetManager.open_postgres(pg_dsn)


def test_timeouts_must_be_positive(pg_dsn: str) -> None:
    with pytest.raises(ValueError, match="lock_timeout"):
        PostgresStore(pg_dsn, lock_timeout=0)


# --------------------------------------------------------------------------
# What the database refuses on its own
# --------------------------------------------------------------------------


def _row(entry: LedgerEntry, **changes: object) -> tuple[object, ...]:
    from agentgov.postgres import _entry_row

    row = list(_entry_row(entry))
    order = [
        "sequence", "entry_id", "transaction_id", "timestamp", "entry_type", "direction",
        "scope_id", "counterparty_id", "amount", "balance_after", "prev_hash", "entry_hash",
        "memo", "version", "ref",
    ]  # fmt: skip
    for name, value in changes.items():
        row[order.index(name)] = value
    return tuple(row)


INSERT = (
    "INSERT INTO agentgov.entries (sequence, entry_id, transaction_id, timestamp, entry_type, "
    "direction, scope_id, counterparty_id, amount, balance_after, prev_hash, entry_hash, memo, "
    "version, ref) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)


@pytest.mark.parametrize(
    ("offset", "link"),
    [
        (0, "prev"),  # a fork: a second entry at the head's sequence, on its parent
        (2, "head"),  # a gap: skips a sequence
        (1, "wrong"),  # a broken link: the next sequence, on a hash that is not the head
    ],
    ids=["fork", "gap", "broken-link"],
)
def test_the_database_admits_only_an_entry_that_extends_the_committed_head(
    pg_dsn: str, gov: BudgetManager, offset: int, link: str
) -> None:
    """Enforced by the database, not by the writer: a writer that skipped the
    lock, or built on a stale head, cannot fork, gap or relink the chain."""
    head = gov.ledger.entries()[-1]
    prev_hash = {"prev": head.prev_hash, "head": head.entry_hash, "wrong": "f" * 64}[link]
    forged = _row(head, entry_id=uuid.uuid4(), sequence=head.sequence + offset, prev_hash=prev_hash)
    with admin(pg_dsn) as conn, pytest.raises(psycopg.errors.IntegrityError):
        conn.execute(INSERT, forged)
    assert _store(gov).head() == (len(gov.ledger), gov.ledger.head_hash)


def test_the_first_entry_must_link_to_genesis(pg_dsn: str) -> None:
    PostgresStore(pg_dsn).close()
    amount, bogus = "1.00000000", "e" * 64
    row = (
        1, uuid.uuid4(), uuid.uuid4(), "2026-01-01T00:00:00.000000Z", "funding", "CR", "org",
        None, amount, amount, bogus, bogus, "", "AGOV2", None,
    )  # fmt: skip
    with admin(pg_dsn) as conn, pytest.raises(psycopg.errors.IntegrityError, match="genesis"):
        conn.execute(INSERT, row)
    with admin(pg_dsn) as conn:
        conn.execute(INSERT, (*row[:10], GENESIS_HASH, *row[11:]))  # the right link is admitted


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE agentgov.entries SET memo = 'edited' WHERE sequence = 1",
        "DELETE FROM agentgov.entries WHERE sequence > 1",
        "TRUNCATE agentgov.entries",
    ],
    ids=["update", "delete", "truncate"],
)
def test_entries_are_append_only_even_for_their_owner(
    pg_dsn: str, gov: BudgetManager, statement: LiteralString
) -> None:
    with (
        admin(pg_dsn) as conn,
        pytest.raises(psycopg.errors.IntegrityError, match="append-only"),
    ):
        conn.execute(statement)


def test_the_triggers_survive_replication_role(pg_dsn: str, gov: BudgetManager) -> None:
    """ENABLE ALWAYS: switching a session to replica mode does not lift them."""
    with admin(pg_dsn) as conn:
        conn.execute("SET session_replication_role = replica")
        with pytest.raises(psycopg.errors.IntegrityError, match="append-only"):
            conn.execute("DELETE FROM agentgov.entries")


def _disable_append_only(conn: psycopg.Connection[tuple[Any, ...]]) -> None:
    conn.execute("ALTER TABLE agentgov.entries DISABLE TRIGGER append_only")


def test_an_entry_edited_behind_the_triggers_refuses_to_load(
    pg_dsn: str, gov: BudgetManager
) -> None:
    """The triggers are a guard, not the proof: their owner can lift them, and
    verification never assumes they ran."""
    gov.spend("agent", "0.10")
    with admin(pg_dsn) as conn:
        _disable_append_only(conn)
        conn.execute("UPDATE agentgov.entries SET amount = '0.01000000' WHERE entry_type = 'spend'")
    with pytest.raises(LedgerIntegrityError, match="tampered"):
        BudgetManager.open_postgres(pg_dsn)


def test_a_cache_row_that_disagrees_refuses_to_load_and_repairs(
    pg_dsn: str, gov: BudgetManager
) -> None:
    held = gov.authorize("agent", "0.10")
    with admin(pg_dsn) as conn:
        conn.execute("DELETE FROM agentgov.open_authorizations")
    with pytest.raises(LedgerIntegrityError, match="no authorization names it"):
        BudgetManager.open_postgres(pg_dsn)
    with BudgetManager.open_postgres(pg_dsn, repair=True) as repaired:
        assert repaired.repairs
        repaired.capture(held, "0.10")
    with BudgetManager.open_postgres(pg_dsn) as clean:
        clean.verify_integrity()


# --------------------------------------------------------------------------
# Writes happen only in a writer session
# --------------------------------------------------------------------------


def test_a_write_outside_a_writer_session_is_refused(pg_dsn: str, gov: BudgetManager) -> None:
    from agentgov.core import Direction, LedgerLine

    store = PostgresStore(pg_dsn)
    try:
        ledger = Ledger(store=store)
        with pytest.raises(StorageError, match="outside a writer session"):
            ledger.post([LedgerLine(EntryType.FUNDING, Direction.CREDIT, "rogue", money("1"))])
        with pytest.raises(StorageError, match="outside a writer session"):
            store.rebuild_caches(nodes=(), control_events=(), authorizations=())
        assert len(ledger) == len(gov.ledger), "nothing reached memory either"
    finally:
        store.close()


def test_writer_sessions_nest_and_only_the_outermost_commits(pg_dsn: str) -> None:
    store = PostgresStore(pg_dsn)
    try:
        with store.writer() as outer:
            with store.writer() as inner:
                assert inner is outer
            assert not outer.committed
        assert outer.committed
    finally:
        store.close()


def test_a_failure_the_store_did_not_see_still_rolls_the_session_back(pg_dsn: str) -> None:
    """PostgreSQL answers COMMIT in an aborted transaction with ROLLBACK, not an
    error; the session must not report that as committed."""
    store = PostgresStore(pg_dsn)
    try:
        with store.writer() as session:
            with suppress(psycopg.Error):
                store._conn.execute("SELECT 1 / 0")
        assert not session.committed
    finally:
        store.close()


def test_a_write_the_database_refuses_fails_the_whole_session(pg_dsn: str) -> None:
    store = PostgresStore(pg_dsn)
    try:
        with store.writer() as session:
            with pytest.raises(LedgerIntegrityError, match="durably append"):
                store.commit(WriteBatch(entries=[_forged_first_entry()]))
            with pytest.raises(StorageError, match="earlier write in this session failed"):
                store.commit(WriteBatch(entries=[_forged_first_entry()]))
        assert session.wrote and not session.committed
        assert store.head() == (0, GENESIS_HASH)
    finally:
        store.close()


def _forged_first_entry() -> LedgerEntry:
    from datetime import UTC, datetime

    from agentgov.core import Direction

    return LedgerEntry(
        sequence=1, entry_id=uuid.uuid4(), transaction_id=uuid.uuid4(),
        timestamp=datetime.now(UTC), entry_type=EntryType.FUNDING, direction=Direction.CREDIT,
        scope_id="org", counterparty_id=None, amount=money("1"), balance_after=money("1"),
        prev_hash="a" * 64, entry_hash="b" * 64, version="AGOV2",
    )  # fmt: skip


# --------------------------------------------------------------------------
# Read-only views
# --------------------------------------------------------------------------


def test_a_read_only_view_refuses_writes_and_follows_writers(
    pg_dsn: str, gov: BudgetManager
) -> None:
    with BudgetManager.open_postgres(pg_dsn, read_only=True) as reader:
        with pytest.raises(ReadOnlyLedgerError):
            reader.spend("agent", "0.01")
        gov.spend("agent", "0.30")
        assert reader.available("agent") == money("2.00")
        assert reader.refresh() == 3  # the hold, its release, the spend
        assert reader.available("agent") == money("1.70")
        reader.verify_integrity()
        store = _store(reader)
        with pytest.raises(ReadOnlyLedgerError), store.writer():
            pass  # pragma: no cover - refused on entry


def test_read_only_on_a_database_with_no_ledger_is_a_storage_error(pg_dsn: str) -> None:
    with pytest.raises(StorageError, match="holds no agentgov ledger"):
        BudgetManager.open_postgres(pg_dsn, read_only=True)


def test_a_read_only_view_refuses_history_rewritten_under_it(
    pg_dsn: str, gov: BudgetManager
) -> None:
    with BudgetManager.open_postgres(pg_dsn, read_only=True) as reader:
        with admin(pg_dsn) as conn:
            _disable_append_only(conn)
            conn.execute(
                "UPDATE agentgov.entries SET entry_hash = repeat('f', 64) "
                "WHERE sequence = (SELECT max(sequence) FROM agentgov.entries)"
            )
        with pytest.raises(LedgerIntegrityError, match="rewritten"):
            reader.refresh()
        with pytest.raises(LedgerIntegrityError, match="stopped following"):
            reader.refresh()


# --------------------------------------------------------------------------
# Least privilege
# --------------------------------------------------------------------------


def test_a_role_with_only_dml_grants_can_run_a_governor(pg_admin_dsn: str, pg_dsn: str) -> None:
    """Install once as the owner; run the fleet as a role that cannot alter the
    schema, lift the triggers, or edit history."""
    from psycopg.conninfo import make_conninfo

    seeded(pg_dsn).close()
    role = f"gov_{uuid.uuid4().hex[:10]}"
    with admin(pg_admin_dsn) as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD 'governor'").format(sql.Identifier(role))
        )
    try:
        grants: tuple[LiteralString, ...] = (
            "GRANT USAGE ON SCHEMA agentgov TO {r}",
            "GRANT SELECT ON agentgov.schema_meta TO {r}",
            "GRANT SELECT, INSERT ON agentgov.entries TO {r}",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON agentgov.nodes TO {r}",
            "GRANT SELECT, INSERT ON agentgov.control_events TO {r}",
            "GRANT SELECT, INSERT, DELETE ON agentgov.open_authorizations TO {r}",
        )
        with admin(pg_dsn) as conn:
            for grant in grants:
                conn.execute(sql.SQL(grant).format(r=sql.Identifier(role)))
        dsn = make_conninfo(pg_dsn, user=role, password="governor")  # noqa: S106
        with BudgetManager.open_postgres(dsn) as fleet:
            fleet.spend("agent", "0.10")
            fleet.verify_integrity()
            store = fleet.store
            assert isinstance(store, PostgresStore)
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                store._conn.execute("ALTER TABLE agentgov.entries DISABLE TRIGGER append_only")
    finally:
        with admin(pg_dsn) as conn:
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        with admin(pg_admin_dsn) as conn:
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


# --------------------------------------------------------------------------
# When a session fails, hangs, or loses its connection
# --------------------------------------------------------------------------


def _store(gov: BudgetManager) -> PostgresStore:
    store = gov.store
    assert isinstance(store, PostgresStore)
    return store


def test_a_governor_with_a_stale_view_is_refused_not_forked_and_recovers(
    pg_dsn: str, gov: BudgetManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Skip the catch-up and write on an old head: the database refuses the
    entry, the session rolls back, and the next write re-reads the ledger."""
    with BudgetManager.open_postgres(pg_dsn) as other:
        other.spend("agent", "0.50")
        committed = other.ledger.entries()

    with monkeypatch.context() as patch:
        patch.setattr(BudgetManager, "_follow", lambda self, store: None)
        with pytest.raises(LedgerIntegrityError, match="extend the committed head"):
            gov.spend("agent", "0.10")
    assert gov._dirty, "a session that wrote and did not commit leaves memory suspect"
    assert _store(gov).load_entries() == committed, "the refused entries never landed"

    gov.spend("agent", "0.10")  # re-reads, then writes on the real head
    with BudgetManager.open_postgres(pg_dsn, read_only=True) as audit:
        spends = [e.amount for e in audit.audit_trail("agent") if e.entry_type is EntryType.SPEND]
        assert spends == [money("0.50"), money("0.10")]
        assert audit.ledger.entries()[: len(committed)] == committed
        audit.verify_integrity()
    assert gov.ledger.head_hash == _store(gov).head()[1]
    gov.verify_integrity()


def test_a_connection_lost_before_commit_rolls_back_and_is_re_read(
    pg_dsn: str, gov: BudgetManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server ends the session after the writes and before COMMIT: the
    caller is told the write did not commit, and it did not; the governor,
    whose memory already held it, re-reads before acting again."""
    store = _store(gov)
    original = store.commit

    def write_then_lose_the_connection(batch: WriteBatch) -> None:
        original(batch)
        with admin(pg_dsn) as conn:
            conn.execute("SELECT pg_terminate_backend(%s)", (store._conn.info.backend_pid,))

    with monkeypatch.context() as patch:
        patch.setattr(store, "commit", write_then_lose_the_connection)
        with pytest.raises(StorageError, match="did not commit"):
            gov.authorize("agent", "0.30")
    assert gov._dirty
    assert gov.available("agent") == money("1.70"), "memory ran ahead of the database"

    gov.spend("agent", "0.10")  # reconnects, re-reads, and the phantom hold is gone
    assert gov.available("agent") == money("1.90")
    assert gov.stale_authorizations(0) == ()
    gov.verify_integrity()


def test_a_commit_whose_outcome_is_lost_is_re_read_not_retried(
    pg_dsn: str, gov: BudgetManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server committed; the answer never arrived. The caller is told, the
    governor re-reads, and the ledger holds the spend exactly once."""
    original = PostgresStore._end

    def commit_then_lose_the_answer(self: PostgresStore, session: Any) -> None:
        original(self, session)
        session.committed = False
        raise StorageError("connection lost after COMMIT was sent")

    with monkeypatch.context() as patch:
        patch.setattr(PostgresStore, "_end", commit_then_lose_the_answer)
        with pytest.raises(StorageError, match="connection lost"):
            gov.spend("agent", "0.25")
    assert gov._dirty

    assert gov.refresh() == 0  # re-read in full; nothing new beyond what it held
    assert not gov._dirty
    assert gov.available("agent") == money("1.75")
    spends = [e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]
    assert len(spends) == 1
    gov.verify_integrity()


def test_a_domain_error_after_a_write_still_commits_the_write(gov: BudgetManager) -> None:
    """An overdraft trips the breaker and then raises; the trip is durable."""
    from agentgov.exceptions import DenialOfWalletError

    with pytest.raises(DenialOfWalletError):
        gov.authorize("agent", "5.00")
    assert not gov._dirty
    assert _store(gov).head() == (len(gov.ledger), gov.ledger.head_hash)
    with pytest.raises(CircuitOpenError):
        gov.authorize("agent", "0.01")


def test_a_lock_wait_that_times_out_is_a_storage_error_and_changes_nothing(
    pg_dsn: str, gov: BudgetManager, monkeypatch: pytest.MonkeyPatch
) -> None:
    holding, release = threading.Event(), threading.Event()
    store = _store(gov)
    original = store.commit

    def hold_the_lock(batch: WriteBatch) -> None:
        original(batch)
        holding.set()
        release.wait(10)

    with BudgetManager.open_postgres(pg_dsn, lock_timeout=0.3) as waiter:
        monkeypatch.setattr(store, "commit", hold_the_lock)
        holder = threading.Thread(target=gov.spend, args=("agent", "0.10"))
        holder.start()
        assert holding.wait(10)
        before = (len(waiter.ledger), waiter.available("agent"))
        started = time.monotonic()
        with pytest.raises(StorageError, match="waiting for the writer lock"):
            waiter.spend("agent", "0.10")
        assert time.monotonic() - started < 5
        assert (len(waiter.ledger), waiter.available("agent")) == before
        assert not waiter._dirty, "it never wrote, so its memory is still the ledger's"
        release.set()
        holder.join()
        waiter.spend("agent", "0.10")  # the lock is free again
        assert waiter.available("agent") == money("1.80")


def test_a_governor_that_hangs_holding_the_lock_is_cut_off_by_the_server(
    pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stalled lock holder cannot stall the fleet: after ``idle_timeout`` the
    server ends its session, rolls its writes back, and frees the lock. The
    stalled governor learns at its commit and re-reads before acting again."""
    seeded(pg_dsn).close()
    hung = BudgetManager.open_postgres(pg_dsn, idle_timeout=0.5)
    stalled = threading.Event()
    original = _store(hung).commit

    def write_then_stall(batch: WriteBatch) -> None:
        original(batch)
        stalled.set()
        time.sleep(2.0)

    outcome: list[BaseException] = []

    def run() -> None:
        try:
            hung.spend("agent", "0.40")
        except BaseException as exc:
            outcome.append(exc)

    try:
        monkeypatch.setattr(_store(hung), "commit", write_then_stall)
        thread = threading.Thread(target=run)
        thread.start()
        assert stalled.wait(10)
        with BudgetManager.open_postgres(pg_dsn, lock_timeout=10) as healthy:
            healthy.spend("agent", "0.20")  # waits out the stalled holder, then writes
        thread.join()
        assert len(outcome) == 1 and isinstance(outcome[0], StorageError)
        assert hung._dirty

        monkeypatch.undo()
        hung.spend("agent", "0.30")  # reconnects, re-reads, writes on the real head
        assert hung.available("agent") == money("1.50"), "0.20 + 0.30; the stalled 0.40 is gone"
        hung.verify_integrity()
    finally:
        hung.close()


def test_a_connection_the_server_ended_between_writes_is_reopened(
    pg_dsn: str, gov: BudgetManager
) -> None:
    pid = _store(gov)._conn.info.backend_pid
    with admin(pg_dsn) as conn:
        conn.execute("SELECT pg_terminate_backend(%s)", (pid,))
    gov.spend("agent", "0.10")
    assert _store(gov)._conn.info.backend_pid != pid
    assert gov.available("agent") == money("1.90")


def test_a_governor_that_cannot_follow_the_ledger_stops_writing(
    pg_dsn: str, gov: BudgetManager
) -> None:
    """An entry another writer appended that does not verify (it links to the
    head, so the database admitted it, but its own hash is forged) halts every
    governor that reads it. Reads keep serving what was verified."""
    head = gov.ledger.entries()[-1]
    forged = _row(
        head,
        sequence=head.sequence + 1,
        entry_id=uuid.uuid4(),
        prev_hash=head.entry_hash,
        entry_type="anchor",
        direction="--",
        amount="0",
        memo="forged",
    )
    with admin(pg_dsn) as conn:
        conn.execute(INSERT, forged)
    before = gov.available("agent")
    with pytest.raises(LedgerIntegrityError, match="tampered"):
        gov.spend("agent", "0.10")
    with pytest.raises(LedgerIntegrityError, match="governor stopped following"):
        gov.spend("agent", "0.10")
    with pytest.raises(LedgerIntegrityError, match="governor stopped following"):
        gov.refresh()
    assert gov.available("agent") == before


def test_refresh_on_a_writer_follows_other_governors(pg_dsn: str, gov: BudgetManager) -> None:
    with BudgetManager.open_postgres(pg_dsn) as other:
        other.spend("agent", "0.10")
        other.trip("agent", "halted elsewhere")
    assert not gov.is_halted("agent"), "reads are served from the last look"
    assert gov.refresh() == 4  # the spend's hold, release and spend; the trip
    assert gov.is_halted("agent")
    assert gov.halted_by("agent") == "agent"
    assert gov.refresh() == 0


def test_a_capture_after_another_governor_voided_the_hold_is_a_double_spend(
    pg_dsn: str, gov: BudgetManager
) -> None:
    held = gov.authorize("agent", "0.30")
    with BudgetManager.open_postgres(pg_dsn) as operator:
        assert operator.void_stale(0) == (held,)
    with pytest.raises(DoubleSpendError):
        gov.capture(held, "0.30")
    assert gov.available("agent") == money("2.00")
    gov.verify_integrity()


def test_money_round_trips_exactly(pg_dsn: str, gov: BudgetManager) -> None:
    """Text columns, not numeric: a zero-value entry's amount comes back as
    the ``0`` it was hashed with, not ``0E-8``."""
    gov.anchor("agent", "digest")
    gov.spend("agent", Decimal("0.00000001"))
    with BudgetManager.open_postgres(pg_dsn, read_only=True) as reader:
        # Decimal("0") == Decimal("0E-8"), so compare the rendered records,
        # which are what the hashes cover.
        loaded = [e.to_audit_record() for e in reader.ledger.entries()]
        assert loaded == [e.to_audit_record() for e in gov.ledger.entries()]
        assert any(r["amount"] == "0" for r in loaded)
