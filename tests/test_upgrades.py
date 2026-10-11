"""Every database a released version wrote opens, upgrades, and keeps working.

``tests/fixtures/upgrades/`` holds a ledger as each release wrote it (written
by that release's own code; see ``scripts/generate_upgrade_fixtures.sh``),
and what that release itself read back. This checkout must read each one
back the same, read-only without changing it, and writable after upgrading
it in place, then write, checkpoint and reopen it like any other ledger.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

import psycopg
import pytest

from agentgov import BudgetManager, money
from agentgov.core import EntryType

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "upgrades"
RELEASES = sorted(p.stem for p in FIXTURES.glob("v*.json"))
WITH_POSTGRES = sorted(p.name.removesuffix(".pg.sql") for p in FIXTURES.glob("*.pg.sql"))
SCOPES = ("orchestrator", "researcher", "writer")


def _expected(release: str) -> dict[str, Any]:
    found: dict[str, Any] = json.loads((FIXTURES / f"{release}.json").read_text())
    return found


def _schema(path: Path) -> str:
    conn = sqlite3.connect(path)
    try:
        return str(conn.execute("SELECT value FROM schema_meta").fetchone()[0])
    finally:
        conn.close()


def _reads_back(gov: BudgetManager, expected: dict[str, Any]) -> None:
    assert {s: str(gov.available(s)) for s in SCOPES} == expected["balances"]
    assert sorted(s for s in SCOPES if gov.is_halted(s)) == expected["halted"]
    assert len(gov.stale_authorizations(0)) == expected["open_holds"]


def test_every_release_is_covered() -> None:
    assert RELEASES == [f"v0.{v}" for v in ("1.0", "1.1", "1.2", "2.0", "2.1", "3.0", "4.0")]
    assert WITH_POSTGRES == ["v0.3.0", "v0.4.0"]


@pytest.mark.parametrize("release", RELEASES)
def test_a_release_database_reads_back_unchanged_read_only(release: str, tmp_path: Path) -> None:
    path = tmp_path / f"{release}.db"
    shutil.copyfile(FIXTURES / f"{release}.db", path)
    schema = _schema(path)
    for verify in ("checkpoint", "full"):
        with BudgetManager.open_sqlite(str(path), read_only=True, verify=verify) as view:
            _reads_back(view, _expected(release))
            view.verify_integrity()
    assert _schema(path) == schema, "a read-only open never upgrades"


@pytest.mark.parametrize("release", RELEASES)
def test_a_release_database_upgrades_and_keeps_working(release: str, tmp_path: Path) -> None:
    path = tmp_path / f"{release}.db"
    shutil.copyfile(FIXTURES / f"{release}.db", path)
    expected = _expected(release)
    with BudgetManager.open_sqlite(str(path)) as gov:
        assert _schema(path) == "3"
        _reads_back(gov, expected)
        trail = gov.audit_trail()
        if release in ("v0.1.0", "v0.1.1"):
            assert trail[expected["entries"]].entry_type is EntryType.SEAL
        gov.reset("writer")
        entry = gov.spend("researcher", money("0.01"))
        assert entry.version == "AGOV3"
        gov.checkpoint()
        gov.verify_integrity()
    with BudgetManager.open_sqlite(str(path)) as reopened:
        assert reopened.ledger._state.last_checkpoint is not None
        assert reopened.available("researcher") == money(
            expected["balances"]["researcher"]
        ) - money("0.01")
        reopened.verify_integrity()


def _restore(dsn: str, release: str) -> None:
    script = (FIXTURES / f"{release}.pg.sql").read_text()
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(script)


@pytest.mark.usefixtures("pg_dsn")
@pytest.mark.parametrize("release", WITH_POSTGRES)
def test_a_release_postgres_schema_upgrades_and_keeps_working(release: str, pg_dsn: str) -> None:
    _restore(pg_dsn, release)
    expected = _expected(release)["postgres"]
    with BudgetManager.open_postgres(pg_dsn, schema="fixture", read_only=True) as view:
        _reads_back(view, expected)
        assert view.store is not None and view.store.schema_version == "pg1"  # type: ignore[attr-defined]
    with BudgetManager.open_postgres(pg_dsn, schema="fixture") as gov:
        assert gov.store is not None and gov.store.schema_version == "pg2"  # type: ignore[attr-defined]
        _reads_back(gov, expected)
        gov.reset("writer")
        assert gov.spend("researcher", money("0.01")).version == "AGOV3"
        gov.checkpoint()
        gov.verify_integrity()
    with BudgetManager.open_postgres(pg_dsn, schema="fixture") as reopened:
        assert reopened.ledger._state.last_checkpoint is not None
        reopened.verify_integrity()
