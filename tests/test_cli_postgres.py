"""The CLI on PostgreSQL (Phase 6.2): every ledger command takes a URL.

``inspect``, ``verify``, ``export`` and ``audit`` read a shared ledger without
the writer lock, as a live fleet writes it; ``checkpoint`` and ``repair`` write
it as one more governor would.
"""

from __future__ import annotations

import io
import json

import psycopg
import pytest

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.cli import main

pytestmark = pytest.mark.usefixtures("pg_dsn")
POLICY = GovernancePolicy(max_calls_per_window=0, checkpoint_every=0)


def _url(dsn: str) -> str:
    from psycopg.conninfo import conninfo_to_dict

    p = conninfo_to_dict(dsn)
    return f"postgresql://{p['user']}:{p['password']}@{p['host']}:{p['port']}/{p['dbname']}"


def _run(*args: str) -> tuple[int, str]:
    out = io.StringIO()
    return main(list(args), out), out.getvalue()


@pytest.fixture
def url(pg_dsn: str) -> str:
    with BudgetManager.open_postgres(pg_dsn, policy=POLICY, auditor=False) as gov:
        gov.open_root("root", money("10"))
        gov.delegate("root", "agent", money("4"))
        for _ in range(3):
            gov.spend("agent", money("0.5"))
    return _url(pg_dsn) + "?schema=agentgov"


def test_inspect_verify_and_export_read_a_shared_ledger(url: str) -> None:
    code, output = _run("inspect", url)
    assert code == 0 and "agent" in output, output
    code, output = _run("verify", url)
    assert code == 0 and "\nPASS  postgresql://" in output, output
    code, output = _run("export", url, "--from-seq", "3")
    lines = [json.loads(line) for line in output.splitlines()]
    assert code == 0 and lines[0]["sequence"] == "3"
    assert [int(r["sequence"]) for r in lines] == list(range(3, 3 + len(lines)))


def test_checkpoint_and_audit_by_url(url: str, pg_dsn: str) -> None:
    code, output = _run("checkpoint", url)
    assert code == 0 and output.startswith("checkpointed"), output
    with BudgetManager.open_postgres(pg_dsn, read_only=True, auditor=False) as view:
        assert view.checkpoint_lag() <= 1
    code, output = _run("audit", url)
    assert code == 0 and output.startswith("PASS"), output


def test_repair_rebuilds_a_shared_ledgers_cache_tables(url: str, pg_dsn: str) -> None:
    code, output = _run("repair", url)
    assert code == 0 and output.startswith("nothing to repair"), output
    with psycopg.connect(pg_dsn, autocommit=True, prepare_threshold=None) as conn:
        conn.execute("UPDATE agentgov.nodes SET allocated = '999' WHERE scope_id = 'agent'")
    code, output = _run("repair", url)
    assert code == 0 and output.startswith("REPAIRED"), output
    code, output = _run("verify", url)
    assert code == 0, output
