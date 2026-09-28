"""Joined transactions: settlement claims commit with someone else's writes.

A caller (an escrow committing a plan's effects) opens a transaction in the
ledger's own database. A governor places a hold beforehand, joins the
transaction at its end, and records a settlement claim in it; after the
caller commits, the claim is redeemed into the chain. The claim commits
exactly when the caller's writes do, and reads nothing of the chain, so no
caller, however old its snapshot and however busy the ledger, conflicts with
another governor.

The caller's role is untrusted by construction: everything else that runs in
its transaction runs as it. So this file also pins that the role cannot
write the ledger, or claim anything, by any other route.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Iterator
from decimal import Decimal
from typing import Any

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from agentgov.core import (
    BudgetManager,
    EntryType,
    LedgerEntry,
    SettlementClaim,
    WriteBatch,
    money,
)
from agentgov.exceptions import LedgerConflictError, StorageError, UnknownScopeError
from agentgov.postgres import PostgresStore

pytestmark = pytest.mark.usefixtures("pg_dsn")

PASSWORD = "caller"  # noqa: S105 - a throwaway role in a throwaway database


@pytest.fixture
def caller_role(pg_admin_dsn: str, pg_dsn: str) -> Iterator[str]:
    """A login role granted joined settlement, and nothing else on the ledger."""
    role = f"caller_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(pg_admin_dsn, autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(PASSWORD)
            )
        )
    try:
        with BudgetManager.open_postgres(pg_dsn) as gov:
            gov.open_root("org", "10.00")
            gov.delegate("org", "agent", "2.00")
            store = gov.store
            assert isinstance(store, PostgresStore)
            store.grant_join(role)
        yield role
    finally:
        with psycopg.connect(pg_dsn, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
        with psycopg.connect(pg_admin_dsn, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def open_caller(pg_dsn: str, role: str) -> psycopg.Connection[Any]:
    """The caller's connection, with a REPEATABLE READ transaction open whose
    snapshot is already taken, as an escrow stage's is."""
    conn = psycopg.connect(make_conninfo(pg_dsn, user=role, password=PASSWORD), autocommit=True)
    conn.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
    conn.execute("SELECT 1")
    return conn


@pytest.fixture
def caller(pg_dsn: str, caller_role: str) -> Iterator[psycopg.Connection[Any]]:
    conn = open_caller(pg_dsn, caller_role)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def gov(pg_dsn: str, caller_role: str) -> Iterator[BudgetManager]:
    manager = BudgetManager.open_postgres(pg_dsn)
    try:
        yield manager
    finally:
        manager.close()


def spends(dsn: str) -> list[LedgerEntry]:
    with BudgetManager.open_postgres(dsn, read_only=True) as reader:
        reader.verify_integrity()
        return [e for e in reader.audit_trail("agent") if e.entry_type is EntryType.SPEND]


# --------------------------------------------------------------------------
# Claim, commit, redeem
# --------------------------------------------------------------------------


def test_a_claim_commits_with_the_callers_transaction_and_is_redeemed_once(
    pg_dsn: str, gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    hold = gov.authorize("agent", "0.40", memo="reserved before the caller's writes")
    with gov.joined(caller) as txn:
        claim = txn.claim("agent", "0.25", memo="settles the caller's writes", hold=hold)
        assert gov.pending_claims() == (), "nothing is owed before the caller commits"
        caller.execute("COMMIT")
    assert gov.pending_claims() == (claim,)
    assert spends(pg_dsn) == [], "owed, not yet booked"

    (spend,) = gov.redeem(claim)
    assert spend.entry_type is EntryType.SPEND and spend.amount == money("0.25")
    assert spend.ref == hold.entry.entry_id and spend.memo == "settles the caller's writes"
    assert gov.pending_claims() == ()
    assert gov.redeem(claim) == (), "a claim is booked once"
    assert gov.stale_authorizations(0) == (), "the hold was released by the settlement"
    assert gov.available("agent") == money("1.75")
    assert [s.entry_hash for s in spends(pg_dsn)] == [spend.entry_hash]
    gov.verify_integrity()


def test_a_claim_rolls_back_with_the_callers_transaction(
    pg_dsn: str, gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    hold = gov.authorize("agent", "0.40")
    with gov.joined(caller) as txn:
        txn.claim("agent", "0.25", memo="settles", hold=hold)
        caller.execute("ROLLBACK")
    assert gov.pending_claims() == ()
    assert gov.stale_authorizations(0) == (hold,), "the hold is still reserved"
    gov.void(hold)
    assert gov.available("agent") == money("2.00")
    assert spends(pg_dsn) == []


def test_an_old_snapshot_claims_without_conflict_however_busy_the_ledger(
    pg_dsn: str, gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    """The claim reads nothing of the chain, so a REPEATABLE READ snapshot
    taken before hundreds of other governors' commits makes no difference."""
    hold = gov.authorize("agent", "0.25")
    stop, written = threading.Event(), threading.Event()

    def meter() -> None:
        with BudgetManager.open_postgres(pg_dsn) as other:
            while not stop.is_set():
                other.spend("org", "0.001")
                written.set()

    thread = threading.Thread(target=meter)
    thread.start()
    try:
        assert written.wait(10)
        for _ in range(20):  # commits keep landing after the caller's snapshot
            with gov.joined(caller) as txn:
                claim = txn.claim("agent", "0.25", memo="settles", hold=hold)
                caller.execute("ROLLBACK")
            caller.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
            caller.execute("SELECT 1")
        with gov.joined(caller) as txn:
            claim = txn.claim("agent", "0.25", memo="settles", hold=hold)
            caller.execute("COMMIT")
    finally:
        stop.set()
        thread.join()
    (spend,) = gov.redeem(claim)
    assert spend.amount == money("0.25")
    gov.verify_integrity()


def test_the_writer_lock_is_held_until_the_caller_commits(
    pg_dsn: str, gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    """From the check to the commit no governor anywhere can write the ledger,
    so a trip cannot land between them."""
    with BudgetManager.open_postgres(pg_dsn, lock_timeout=0.3) as other:
        with gov.joined(caller):
            with pytest.raises(StorageError, match="waiting for the writer lock"):
                other.trip("agent", "too late")
            caller.execute("COMMIT")
        other.trip("agent", "free once the caller committed")
    assert gov.refresh() == 1


def test_a_breaker_check_inside_the_block_is_current(
    pg_dsn: str, gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    with BudgetManager.open_postgres(pg_dsn) as other:
        other.trip("agent", "halted elsewhere")
    with gov.joined(caller):  # the caller's snapshot predates the trip; the check does not
        assert gov.is_halted("agent")
        caller.execute("ROLLBACK")


def test_a_caller_that_cannot_get_the_lock_in_time_is_a_conflict(
    pg_dsn: str, gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    holding, release = threading.Event(), threading.Event()
    with BudgetManager.open_postgres(pg_dsn) as holder:
        store = holder.store
        assert isinstance(store, PostgresStore)
        original = store.commit

        def hold(batch: WriteBatch) -> None:
            original(batch)
            holding.set()
            release.wait(10)

        store.commit = hold  # type: ignore[method-assign]
        thread = threading.Thread(target=holder.anchor, args=("agent", "holding"))
        thread.start()
        try:
            assert holding.wait(10)
            caller.execute("SET LOCAL lock_timeout = 200")
            with pytest.raises(LedgerConflictError, match="lock_timeout"), gov.joined(caller):
                pytest.fail("the block must not run")  # pragma: no cover
        finally:
            release.set()
            thread.join()


# --------------------------------------------------------------------------
# Redemption books what happened, whatever happened since
# --------------------------------------------------------------------------


def commit_claim(
    gov: BudgetManager,
    caller: psycopg.Connection[Any],
    amount: str,
    *,
    hold: Any = None,
    memo: str = "settles",
) -> Any:
    with gov.joined(caller) as txn:
        claim = txn.claim("agent", amount, memo=memo, hold=hold)
        caller.execute("COMMIT")
    return claim


def test_a_claim_whose_hold_was_voided_is_still_booked(
    pg_dsn: str, gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    hold = gov.authorize("agent", "0.40")
    claim = commit_claim(gov, caller, "0.25", hold=hold)
    with BudgetManager.open_postgres(pg_dsn) as operator:
        assert operator.void_stale(0) == (hold,)
    (spend,) = gov.redeem(claim)
    assert spend.ref is None, "a spend on its own: the hold is gone"
    assert gov.available("agent") == money("1.75")
    gov.verify_integrity()


def test_a_claim_that_overdraws_is_booked_and_trips_the_breaker(
    gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    """What it pays for already happened: the ledger records it, and halts."""
    claim = commit_claim(gov, caller, "5.00")
    (spend,) = gov.redeem(claim)
    assert spend.balance_after == money("-3.00")
    assert gov.is_halted("agent")
    gov.verify_integrity()


def test_a_zero_claim_books_a_zero_value_anchor(
    gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    claim = commit_claim(gov, caller, "0", memo="interlock:digest")
    (anchor,) = gov.redeem(claim)
    assert anchor.entry_type is EntryType.ANCHOR and anchor.memo == "interlock:digest"
    assert gov.available("agent") == money("2.00")


def test_governors_racing_to_redeem_book_each_claim_once(
    pg_dsn: str, gov: BudgetManager, caller_role: str
) -> None:
    claims = []
    for _ in range(12):
        conn = open_caller(pg_dsn, caller_role)
        try:
            claims.append(commit_claim(gov, conn, "0.01"))
        finally:
            conn.close()
    booked: list[LedgerEntry] = []
    lock = threading.Lock()
    barrier = threading.Barrier(4)

    def redeem() -> None:
        with BudgetManager.open_postgres(pg_dsn) as other:
            barrier.wait()
            for claim in claims:
                found = other.redeem(claim)
                with lock:
                    booked.extend(found)

    threads = [threading.Thread(target=redeem) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(booked) == len(claims)
    assert len(spends(pg_dsn)) == len(claims)
    assert gov.pending_claims() == ()


def test_the_store_refuses_to_book_a_claim_that_is_not_pending(gov: BudgetManager) -> None:
    store = gov.store
    assert isinstance(store, PostgresStore)
    with store.writer() as session:
        with pytest.raises(Exception, match="booked once"):
            store.commit(WriteBatch(redeemed=[uuid.uuid4()]))
    assert not session.committed


# --------------------------------------------------------------------------
# The caller's role cannot touch the ledger any other way
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT count(*) FROM agentgov.entries",
        "SELECT k FROM agentgov.join_key",
        "SELECT count(*) FROM agentgov.claims",
        "INSERT INTO agentgov.claims (claim_id, scope_id, amount, memo) "
        "VALUES (gen_random_uuid(), 'agent', '1000', 'forged')",
        "DELETE FROM agentgov.open_authorizations",
    ],
    ids=["read-entries", "read-key", "read-claims", "forge-a-claim", "drop-holds"],
)
def test_the_callers_role_has_no_privilege_on_the_ledgers_tables(
    caller: psycopg.Connection[Any], statement: Any
) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        caller.execute(statement)


def test_the_claim_function_refuses_a_caller_no_governor_joined(
    caller: psycopg.Connection[Any],
) -> None:
    """The role may execute it, and it does nothing for it: the token proves
    a governor joined, and only a governor can compute one."""
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="no governor"):
        caller.execute(
            "SELECT agentgov.claim(%s, gen_random_uuid(), NULL, 'agent', '1000', 'forged')",
            (b"\x00" * 32,),
        )


def test_a_token_is_good_for_its_own_transaction_only(
    gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    store = gov.store
    assert isinstance(store, PostgresStore)
    with gov.joined(caller):
        session = store._session
        assert session is not None and session.token is not None
        token = session.token
        caller.execute("COMMIT")
    caller.execute("BEGIN")
    with pytest.raises(psycopg.errors.InsufficientPrivilege, match="no governor"):
        caller.execute(
            "SELECT agentgov.claim(%s, gen_random_uuid(), NULL, 'agent', '1000', 'replayed')",
            (token,),
        )
    caller.execute("ROLLBACK")
    assert gov.pending_claims() == ()


def test_only_the_named_roles_may_call_the_claim_function(pg_admin_dsn: str, pg_dsn: str) -> None:
    PostgresStore(pg_dsn).close()
    role = f"stranger_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(pg_admin_dsn, autocommit=True) as conn:
        conn.execute(
            sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(PASSWORD)
            )
        )
    try:
        dsn = make_conninfo(pg_dsn, user=role, password=PASSWORD)
        with (
            psycopg.connect(dsn, autocommit=True) as conn,
            pytest.raises(psycopg.errors.InsufficientPrivilege),
        ):
            conn.execute(
                "SELECT agentgov.claim(%s, gen_random_uuid(), NULL, 'agent', '1', 'x')",
                (b"\x00" * 32,),
            )
    finally:
        with psycopg.connect(pg_admin_dsn, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_grant_join_refuses_a_role_name_that_is_not_an_identifier(pg_dsn: str) -> None:
    store = PostgresStore(pg_dsn)
    try:
        with pytest.raises(ValueError, match="role name"):
            store.grant_join('x"; DROP SCHEMA agentgov; --')
    finally:
        store.close()


# --------------------------------------------------------------------------
# Misuse
# --------------------------------------------------------------------------


def test_the_chain_is_not_written_inside_a_joined_transaction(
    gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    store = gov.store
    assert isinstance(store, PostgresStore)
    with gov.joined(caller):
        with pytest.raises(StorageError, match="not written inside a joined transaction"):
            gov.anchor("agent", "digest")
        assert gov.refresh() == 0
        with pytest.raises(RuntimeError, match="inside its own mutation"), gov.joined(caller):
            pytest.fail("the block must not run")  # pragma: no cover
        with pytest.raises(StorageError, match="inside a joined transaction"), store.writer():
            pytest.fail("the block must not run")  # pragma: no cover
        with pytest.raises(StorageError, match="inside a joined transaction"):
            store.rebuild_caches(nodes=(), control_events=(), authorizations=())
        caller.execute("ROLLBACK")
    gov.anchor("agent", "digest")  # and outside, as ever


def test_a_claim_must_be_well_formed(gov: BudgetManager, caller: psycopg.Connection[Any]) -> None:
    other = gov.authorize("org", "0.10")
    with gov.joined(caller) as txn:
        with pytest.raises(ValueError, match="negative"):
            txn.claim("agent", Decimal("-1"), memo="x")
        with pytest.raises(ValueError, match="memo"):
            txn.claim("agent", "1", memo="")
        with pytest.raises(ValueError, match="not 'agent'"):
            txn.claim("agent", "1", memo="x", hold=other)
        with pytest.raises(UnknownScopeError):
            txn.claim("nobody", "1", memo="x")
        caller.execute("ROLLBACK")


def test_a_claim_is_written_in_a_joined_transaction_only(gov: BudgetManager) -> None:
    store = gov.store
    assert isinstance(store, PostgresStore)
    with pytest.raises(StorageError, match="joined transaction only"):
        store.claim(SettlementClaim(uuid.uuid4(), None, "agent", money("1"), "x"))


def test_joining_needs_an_open_transaction(
    gov: BudgetManager, caller: psycopg.Connection[Any]
) -> None:
    caller.execute("ROLLBACK")
    with pytest.raises(StorageError, match="joins an open transaction"), gov.joined(caller):
        pytest.fail("the block must not run")  # pragma: no cover


def test_only_a_postgres_governor_holds_claims(
    caller: psycopg.Connection[Any], tmp_path: Any
) -> None:
    with pytest.raises(TypeError, match="can join"), BudgetManager().joined(caller):
        pytest.fail("the block must not run")  # pragma: no cover
    with BudgetManager.open_sqlite(str(tmp_path / "gov.db")) as local:
        with pytest.raises(TypeError, match="settlement claims"):
            local.redeem()
        store = local.store
        assert store is not None
        with pytest.raises(StorageError, match="holds no settlement claims"):
            store.commit(WriteBatch(redeemed=[uuid.uuid4()]))
