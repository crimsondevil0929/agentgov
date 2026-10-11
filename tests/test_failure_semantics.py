"""Failure semantics (Phase 5.5): rollbacks, the fleet-wide velocity window,
and checkpoints whose signer is down.

A ledger cut back under a governor (a failover to a replica that had not
received the last commits, a file restored from a backup) is told apart from
one rewritten: ``LedgerRollbackError`` when what is left is the chain the
governor verified, ``LedgerIntegrityError`` when it is not. Either way the
governor stops following it. ``fleet_velocity`` counts a scope's holds by
every governor. A checkpoint that cannot be signed never holds up a write:
the next tries back off, and ``checkpoint_lag()`` shows the gap.
"""

from __future__ import annotations

import shutil
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

import psycopg
import pytest

from agentgov import BudgetManager, CheckpointSigning, GovernancePolicy, money
from agentgov.exceptions import (
    LedgerIntegrityError,
    LedgerRollbackError,
    RunawayLoopDetectedError,
    SignerUnavailableError,
)
from agentgov.receipts import Ed25519Signer
from agentgov.storage import SqliteStore

POLICY = GovernancePolicy(max_calls_per_window=0, checkpoint_every=0)
_REARM = (
    "ALTER TABLE agentgov.entries ENABLE ALWAYS TRIGGER append_only, "
    "ENABLE ALWAYS TRIGGER append_only_truncate, ENABLE ALWAYS TRIGGER extend_chain"
)


def _spend(gov: BudgetManager, times: int) -> None:
    for _ in range(times):
        gov.spend("agent", money("0.01"))


def _backup(source: Path, target: Path) -> None:
    """A consistent copy of a SQLite ledger, as a backup would take: closed,
    so the copy's pages are in its file, not its write-ahead log."""
    with closing(sqlite3.connect(source)) as src, closing(sqlite3.connect(target)) as dst:
        src.backup(dst)


# -- rollbacks ---------------------------------------------------------------------


def test_a_sqlite_ledger_restored_from_a_backup_is_a_rollback(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    writer = BudgetManager.open_sqlite(str(path), policy=POLICY, auditor=False)
    writer.open_root("root", money("10"))
    writer.delegate("root", "agent", money("5"))
    _spend(writer, 3)
    _backup(path, tmp_path / "backup.db")
    restored_length = len(writer.ledger)
    view = BudgetManager.open_sqlite(str(path), read_only=True)
    _spend(writer, 4)
    view.refresh()
    verified = len(view.ledger)
    writer.close()
    assert view.store is not None
    view.store.close()
    shutil.copyfile(tmp_path / "backup.db", path)  # the file goes back
    for sidecar in ("ledger.db-wal", "ledger.db-shm"):
        (tmp_path / sidecar).unlink(missing_ok=True)
    # The view reads the restored file through a connection opened on it.
    view._store = SqliteStore(path, read_only=True)
    with pytest.raises(LedgerRollbackError) as caught:
        view.refresh()
    assert caught.value.confirmed
    assert (caught.value.verified_length, caught.value.ledger_length) == (
        verified,
        restored_length,
    )
    with pytest.raises(LedgerIntegrityError, match="stopped following"):
        view.refresh()  # it serves nothing more
    view.close()


def _cut_back(dsn: str, keep: int) -> None:
    """Leave the ledger as a replica that stopped at entry ``keep`` would:
    every table as it stood then (they were copied then, by the caller)."""
    with psycopg.connect(dsn, autocommit=True, prepare_threshold=None) as conn:
        conn.execute("ALTER TABLE agentgov.entries DISABLE TRIGGER USER")
        conn.execute("DELETE FROM agentgov.entries WHERE sequence > %s", (keep,))
        conn.execute(_REARM)
        for table in ("nodes", "open_authorizations", "control_events"):
            conn.execute(f"DELETE FROM agentgov.{table}")  # noqa: S608 - fixed names
            conn.execute(
                f"INSERT INTO agentgov.{table} OVERRIDING SYSTEM VALUE "  # noqa: S608
                f"SELECT * FROM public.copy_{table}"
            )


def _copy_tables(dsn: str) -> None:
    with psycopg.connect(dsn, autocommit=True, prepare_threshold=None) as conn:
        for table in ("nodes", "open_authorizations", "control_events"):
            conn.execute(
                f"CREATE TABLE public.copy_{table} AS SELECT * FROM agentgov.{table}"  # noqa: S608
            )


def test_a_failover_that_lost_commits_is_a_rollback_not_a_rewrite(pg_dsn: str) -> None:
    writer = BudgetManager.open_postgres(pg_dsn, policy=POLICY, auditor=False)
    follower = BudgetManager.open_postgres(pg_dsn, policy=POLICY, auditor=False)
    try:
        writer.open_root("root", money("10"))
        writer.delegate("root", "agent", money("5"))
        _spend(writer, 3)
        follower.refresh()
        kept = len(follower.ledger)
        _copy_tables(pg_dsn)  # what a lagging replica holds
        _spend(writer, 5)
        follower.refresh()
        assert len(follower.ledger) > kept
        _cut_back(pg_dsn, kept)  # the failover
        with pytest.raises(LedgerRollbackError, match=r"rolled back.*lost, not rewritten"):
            follower.spend("agent", money("0.01"))
        with pytest.raises(LedgerIntegrityError, match="stopped following"):
            follower.spend("agent", money("0.01"))
        with BudgetManager.open_postgres(pg_dsn, auditor=False) as reopened:
            assert len(reopened.ledger) == kept, "a governor opened anew follows what is left"
            reopened.spend("agent", money("0.01"))
    finally:
        writer.close()
        follower.close()


def test_a_ledger_rewritten_to_a_shorter_chain_is_not_a_rollback(pg_dsn: str) -> None:
    writer = BudgetManager.open_postgres(pg_dsn, policy=POLICY, auditor=False)
    follower = BudgetManager.open_postgres(pg_dsn, policy=POLICY, auditor=False)
    try:
        writer.open_root("root", money("10"))
        writer.delegate("root", "agent", money("5"))
        _spend(writer, 3)
        follower.refresh()
        kept = len(follower.ledger)
        _copy_tables(pg_dsn)
        _spend(writer, 5)
        follower.refresh()
        _cut_back(pg_dsn, kept)
        with psycopg.connect(pg_dsn, autocommit=True, prepare_threshold=None) as conn:
            conn.execute("ALTER TABLE agentgov.entries DISABLE TRIGGER USER")
            conn.execute(
                "UPDATE agentgov.entries SET entry_hash = repeat('e', 64) WHERE sequence = %s",
                (kept,),
            )
            conn.execute(_REARM)
        with pytest.raises(LedgerIntegrityError) as caught:
            follower.refresh()
        assert not isinstance(caught.value, LedgerRollbackError)
        assert "rewritten" in str(caught.value)
    finally:
        writer.close()
        follower.close()


# -- the fleet-wide velocity window ----------------------------------------------------


def test_the_fleet_wide_window_counts_every_governors_holds(pg_dsn: str) -> None:
    fleet = GovernancePolicy(
        max_calls_per_window=5, window_seconds=60, checkpoint_every=0, fleet_velocity=True
    )
    local = GovernancePolicy(max_calls_per_window=5, window_seconds=60, checkpoint_every=0)
    one = BudgetManager.open_postgres(pg_dsn, policy=fleet, auditor=False)
    two = BudgetManager.open_postgres(pg_dsn, policy=fleet, auditor=False)
    alone = BudgetManager.open_postgres(pg_dsn, policy=local, auditor=False)
    try:
        one.open_root("root", money("10"))
        for scope in ("agent", "other"):
            one.delegate("root", scope, money("5"))
        for _ in range(3):
            one.authorize("agent", money("0.01"))
        for _ in range(2):
            two.authorize("agent", money("0.01"))  # five on the scope, fleet-wide
        with pytest.raises(RunawayLoopDetectedError):
            two.authorize("agent", money("0.01"))
        assert one.is_halted("agent", fresh=True), "the trip is in the chain"
        for _ in range(5):
            alone.authorize("other", money("0.01"))  # its own count: five of its own
        with pytest.raises(RunawayLoopDetectedError):
            alone.authorize("other", money("0.01"))
    finally:
        for gov in (one, two, alone):
            gov.close()


# -- a checkpoint signer that is down ----------------------------------------------------


class _DownSigner:
    """An Ed25519 signer whose key service can be taken down."""

    def __init__(self) -> None:
        self.inner = Ed25519Signer(bytes(range(32)))
        self.down = True
        self.calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def sign(self, message: bytes) -> bytes:
        self.calls += 1
        if self.down:
            raise SignerUnavailableError("the key service cannot be reached")
        return self.inner.sign(message)


def test_writes_never_wait_on_a_checkpoint_signer_that_is_down(tmp_path: Path) -> None:
    signer = _DownSigner()
    policy = GovernancePolicy(max_calls_per_window=0, checkpoint_every=5)
    gov = BudgetManager.open_sqlite(
        str(tmp_path / "l.db"),
        policy=policy,
        auditor=False,
        signing=CheckpointSigning(signer=signer),
    )
    try:
        gov.open_root("root", money("10"))
        gov.delegate("root", "agent", money("5"))
        _spend(gov, 20)  # sixty entries: twelve checkpoints due, all failing
        assert signer.calls == 1, "after a failure, the next tries back off"
        assert gov.checkpoint_lag() == len(gov.ledger)
        signer.down = False
        gov._checkpoint_retry_at = 0.0  # the backoff has run out
        _spend(gov, 1)
        assert gov.checkpoint_lag() <= 1, "the next due checkpoint was written"
        assert gov._checkpoint_backoff == 0.0
    finally:
        gov.close()
