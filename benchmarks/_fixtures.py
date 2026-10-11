"""Ledgers of a given length, built quickly, for the benchmarks and scale tests.

A ledger is built through the public API on SQLite with ``synchronous=OFF``:
one root, ``scopes`` delegated children, then ``spend()`` calls spread across
the children (three entries each: the hold, its release, the spend). A
PostgreSQL ledger of the same shape is made by copying a SQLite one's rows
into a freshly installed schema with ``COPY``, which is how a 150,000-entry
shared ledger is built in seconds rather than minutes: every row still passes
the ``extend_chain`` trigger on the way in.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from agentgov import BudgetManager, GovernancePolicy, money

UNLIMITED = GovernancePolicy(max_calls_per_window=0)
"""No runaway-loop detector: a fixture spends far faster than any agent."""


def entries_for(spends: int, scopes: int) -> int:
    """How many entries :func:`build_sqlite` writes for these arguments."""
    return 1 + 2 * scopes + 3 * spends


def spends_for(entries: int, scopes: int) -> int:
    """The ``spends`` that make a ledger of at least ``entries`` entries."""
    return max(0, -(-(entries - 1 - 2 * scopes) // 3))


def build_sqlite(path: str | Path, *, spends: int, scopes: int = 8) -> Path:
    """Build (or reuse) a SQLite ledger at ``path``; see the module docstring."""
    path = Path(path)
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(path.name + ".partial")
    for leftover in path.parent.glob(partial.name + "*"):
        leftover.unlink()
    with BudgetManager.open_sqlite(str(partial), synchronous="OFF", policy=UNLIMITED) as gov:
        gov.open_root("root", money("1000000000"))
        for i in range(scopes):
            gov.delegate("root", f"agent-{i}", money("1000000"))
        for n in range(spends):
            gov.spend(f"agent-{n % scopes}", money("0.00001"))
    for suffix in ("-wal", "-shm", ".lock"):
        sidecar = partial.with_name(partial.name + suffix)
        if sidecar.exists():
            sidecar.unlink()
    partial.rename(path)
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
}


def copy_to_postgres(sqlite_path: str | Path, dsn: str, *, schema: str = "agentgov") -> int:
    """Install a ledger schema at ``dsn`` and copy a SQLite ledger's rows into it.

    :returns: The number of entries copied.
    """
    import psycopg
    from psycopg import sql

    BudgetManager.open_postgres(dsn, schema=schema).close()  # installs the schema
    source = sqlite3.connect(f"file:{sqlite_path}?mode=ro", uri=True)
    copied = 0
    try:
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            for table, columns in _TABLES.items():
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
