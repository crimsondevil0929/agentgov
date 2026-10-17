"""Ledgers of a given size, built quickly, for tests that need history.

Built through the public API on SQLite with ``synchronous=OFF``: one root,
``scopes`` delegated children, then ``spend()`` calls spread across them,
three entries each. :func:`copy_to_postgres` installs a ledger schema and
copies a SQLite ledger's rows into it with ``COPY``; every row still passes
the ``extend_chain`` trigger.
"""

from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.core import Ledger, LedgerEntry

UNLIMITED = GovernancePolicy(max_calls_per_window=0)


def build_sqlite(path: str | Path, *, spends: int, scopes: int = 8) -> Path:
    """A SQLite ledger at ``path`` of ``1 + 2 * scopes + 3 * spends`` entries."""
    path = Path(path)
    with BudgetManager.open_sqlite(str(path), synchronous="OFF", policy=UNLIMITED) as gov:
        gov.open_root("root", money("1000000000"))
        for i in range(scopes):
            gov.delegate("root", f"agent-{i}", money("1000000"))
        for n in range(spends):
            gov.spend(f"agent-{n % scopes}", money("0.00001"))
    return path


_TABLES = {
    "entries": (
        "sequence, entry_id, transaction_id, timestamp, entry_type, direction, scope_id, "
        "counterparty_id, amount, balance_after, prev_hash, entry_hash, memo, version, ref"
    ),
    "nodes": "scope_id, parent_id, depth, allocated, created_at",
    "control_events": (
        "event_id, timestamp, event_type, scope_id, reason, ledger_head_hash, entry_id"
    ),
    "open_authorizations": "authorization_id, scope_id, amount, opened_at, entry_id",
    "snapshots": "sequence, digest, body, signature",
}


def copy_to_postgres(sqlite_path: str | Path, dsn: str, *, schema: str = "agentgov") -> int:
    """Install a ledger schema at ``dsn`` and copy a SQLite ledger's rows into it.

    :returns: The number of entries copied.
    """
    import psycopg
    from psycopg import sql

    BudgetManager.open_postgres(dsn, schema=schema).close()
    source = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    copied = 0
    try:
        with psycopg.connect(dsn, prepare_threshold=None) as conn, conn.cursor() as cur:
            present = {
                row[0]
                for row in source.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            for table, columns in _TABLES.items():
                if table not in present:
                    continue
                rows = source.execute(f"SELECT {columns} FROM {table}").fetchall()  # noqa: S608
                if table == "entries":
                    rows.sort(key=lambda row: row[0])
                    copied = len(rows)
                statement = sql.SQL("COPY {} ({}) FROM STDIN").format(
                    sql.Identifier(schema, table), sql.SQL(columns)
                )
                with cur.copy(statement) as copy:
                    for row in rows:
                        copy.write_row(row)
            conn.commit()
    finally:
        source.close()
    return copied


def open_after_its_holder_died(path: str) -> BudgetManager:
    """Open the SQLite ledger at ``path`` whose governor's process has died.

    At once, as POSIX releases a dead process's lock with its exit. Windows
    releases it a moment later, "depending upon available system resources"
    (``LockFileEx``), so there an open is retried for a few seconds.
    """
    from agentgov.exceptions import ConcurrentGovernorError

    deadline = time.monotonic() + (10.0 if sys.platform == "win32" else 0.0)
    while True:
        try:
            return BudgetManager.open_sqlite(path)
        except ConcurrentGovernorError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def memory_history(ledger: Ledger) -> list[LedgerEntry]:
    """The entry list of a ledger that keeps its history in memory (one with
    no store), for tests that rewrite history in place."""
    entries = ledger._entries
    assert entries is not None, "only a ledger without a store keeps its entries in memory"
    return entries
