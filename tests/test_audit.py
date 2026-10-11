"""The auditor replays what an open from a checkpoint did not (D1).

A governor opening from a checkpoint trusts the snapshot for everything
before it. The auditor is what verifies that history: a replay from genesis,
off the hot path, that checks every checkpoint snapshot against the chain,
records how far it verified, and fails every governor closed when the chain
does not verify.
"""

from __future__ import annotations

import io
import json
import sqlite3
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.audit import Auditor
from agentgov.cli import main
from agentgov.core import EntryType
from agentgov.exceptions import LedgerIntegrityError
from agentgov.opening import open_url, parse_url
from agentgov.storage import SqliteStore

POLICY = GovernancePolicy(max_calls_per_window=0, checkpoint_every=40)


@pytest.fixture
def ledger(tmp_path: Path) -> Iterator[str]:
    path = str(tmp_path / "audited.db")
    with BudgetManager.open_sqlite(path, policy=POLICY, auditor=False) as gov:
        gov.open_root("root", money("100"))
        gov.delegate("root", "agent", money("10"))
        for _ in range(60):
            gov.spend("agent", money("0.01"))
    yield path


def _store(path: str) -> SqliteStore:
    return SqliteStore(path, read_only=True)


def _tamper_before_the_checkpoint(path: str) -> None:
    """Rewrite one old spend, consistently enough that only a replay sees it."""
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            "UPDATE entries SET memo = 'rewritten' WHERE sequence = "
            "(SELECT min(sequence) FROM entries WHERE entry_type = 'spend')"
        )
        conn.commit()
    finally:
        conn.close()


def test_a_clean_ledger_audits_from_genesis_checking_every_checkpoint(ledger: str) -> None:
    store = _store(ledger)
    try:
        report = Auditor(store).run()
        assert report.ok and report.resumed_from == 0
        assert report.verified_to == store.head()[0]
        assert report.checkpoints == len(store.checkpoints()) >= 3
        marks = store.audit_marks()
        assert [m.status for m in marks] == ["verified"] * len(marks)
        assert {m.sequence for m in marks} >= {s for _, s, _ in store.checkpoints()}
    finally:
        store.close()


def test_a_later_run_resumes_from_the_newest_verified_checkpoint(ledger: str) -> None:
    store = _store(ledger)
    try:
        first = Auditor(store).run()
        with BudgetManager.open_sqlite(ledger, policy=POLICY, auditor=False) as gov:
            gov.spend("agent", money("0.01"))
        second = Auditor(store).run()
        newest = max(s for _, s, _ in store.checkpoints())
        assert second.ok and second.resumed_from == newest
        assert second.entries < first.entries
    finally:
        store.close()


def test_an_edit_before_the_checkpoint_is_found_by_the_auditor(ledger: str) -> None:
    _tamper_before_the_checkpoint(ledger)
    # An open from the checkpoint trusts the snapshot for that history...
    with BudgetManager.open_sqlite(ledger, read_only=True) as view:
        assert view.available("agent") > 0
    # ...and the auditor does not.
    store = _store(ledger)
    try:
        report = Auditor(store).run()
        assert not report.ok and report.failure is not None
        assert "tampered" in report.failure
        failure = store.audit_failure()
        assert failure is not None and failure.status == "failed"
    finally:
        store.close()
    # Every writer then refuses to open, and a read-only view still opens.
    with pytest.raises(LedgerIntegrityError, match="does not verify"):
        BudgetManager.open_sqlite(ledger)
    BudgetManager.open_sqlite(ledger, read_only=True).close()


def test_a_later_clean_audit_supersedes_a_failure(ledger: str) -> None:
    conn = sqlite3.connect(ledger)
    (original,) = conn.execute(
        "SELECT memo FROM entries WHERE sequence = "
        "(SELECT min(sequence) FROM entries WHERE entry_type = 'spend')"
    ).fetchone()
    conn.close()
    _tamper_before_the_checkpoint(ledger)
    store = _store(ledger)
    try:
        assert not Auditor(store).run().ok
    finally:
        store.close()
    conn = sqlite3.connect(ledger)
    conn.execute(
        "UPDATE entries SET memo = ? WHERE sequence = "
        "(SELECT min(sequence) FROM entries WHERE entry_type = 'spend')",
        (original,),
    )
    conn.commit()
    conn.close()
    store = _store(ledger)
    try:
        assert Auditor(store).run(from_genesis=True).ok
        assert store.audit_failure() is None
    finally:
        store.close()
    BudgetManager.open_sqlite(ledger).close()


def test_a_governor_opened_from_a_checkpoint_audits_in_a_thread_and_stops_writing(
    ledger: str,
) -> None:
    _tamper_before_the_checkpoint(ledger)
    gov = BudgetManager.open_sqlite(ledger, policy=POLICY)
    try:
        assert gov._auditor is not None, "an open from a checkpoint audits by default"
        deadline = time.monotonic() + 30
        while gov._unusable is None and time.monotonic() < deadline:
            time.sleep(0.05)
        with pytest.raises(LedgerIntegrityError, match="auditor found the chain does not verify"):
            gov.spend("agent", money("0.01"))
    finally:
        gov.close()
    assert gov._auditor is None, "closing stops the auditor"


def test_an_open_that_replayed_everything_runs_no_auditor(tmp_path: Path) -> None:
    path = str(tmp_path / "small.db")
    with BudgetManager.open_sqlite(path) as gov:
        gov.open_root("root", money("1"))
        assert gov._auditor is None
    with BudgetManager.open_sqlite(path, auditor=True) as forced:
        assert forced._auditor is not None


def test_the_auditor_checks_its_arguments(ledger: str) -> None:
    store = _store(ledger)
    try:
        with pytest.raises(ValueError, match="duty"):
            Auditor(store, duty=0)
        with pytest.raises(ValueError, match="chunk"):
            Auditor(store, chunk=0)
        report = Auditor(store, record=False, chunk=7, duty=0.5).run()
        assert report.ok and store.audit_marks() == ()
    finally:
        store.close()


# -- the command line ------------------------------------------------------------


def _run(*args: str) -> tuple[int, str]:
    out = io.StringIO()
    code = main(list(args), out)
    return code, out.getvalue()


def test_the_audit_command_passes_and_fails_with_its_exit_code(ledger: str) -> None:
    code, output = _run("audit", ledger)
    assert code == 0 and output.startswith("PASS"), output
    _tamper_before_the_checkpoint(ledger)
    code, output = _run("audit", ledger, "--from-genesis")
    assert code == 1 and output.startswith("FAIL"), output


def test_verify_checks_every_checkpoint_snapshot(ledger: str) -> None:
    code, output = _run("verify", f"sqlite:///{ledger}")
    assert code == 0, output
    assert "checkpoint snapshots" in output


def test_the_checkpoint_and_export_commands(tmp_path: Path) -> None:
    path = str(tmp_path / "cli.db")
    with BudgetManager.open_sqlite(path) as gov:
        gov.open_root("root", money("1"))
        gov.spend("root", money("0.1"))
    code, output = _run("checkpoint", path)
    assert code == 0 and "sequence 4" in output, output
    code, output = _run("export", path, "--from-seq", "3")
    records = [json.loads(line) for line in output.splitlines()]
    assert [r["sequence"] for r in records] == ["3", "4", "5"]
    assert records[-1]["entry_type"] == EntryType.CHECKPOINT.value


# -- opening by URL ---------------------------------------------------------------


def test_urls_name_every_kind_of_ledger(tmp_path: Path) -> None:
    assert parse_url("memory:") == ("memory", "", {})
    assert parse_url("sqlite:///abs/ledger.db") == ("sqlite", "/abs/ledger.db", {})
    assert parse_url("sqlite:rel/ledger.db") == ("sqlite", "rel/ledger.db", {})
    assert parse_url("ledger.db") == ("sqlite", "ledger.db", {})
    kind, dsn, options = parse_url(
        "postgresql://gov:pw@db:5432/fleet?schema=ledger&lock_timeout=5&sslmode=require"
    )
    assert kind == "postgres"
    assert options == {"schema": "ledger", "lock_timeout": 5.0}
    assert dsn == "postgresql://gov:pw@db:5432/fleet?sslmode=require"
    with pytest.raises(ValueError, match="not a float"):
        parse_url("postgresql://db/fleet?idle_timeout=soon")
    assert parse_url("postgresql://db/fleet?prepare_threshold=none")[2] == {
        "prepare_threshold": None
    }
    assert parse_url("postgresql://db/fleet?prepare_threshold=5")[2] == {"prepare_threshold": 5}
    with pytest.raises(ValueError, match="not an integer, or none"):
        parse_url("postgresql://db/fleet?prepare_threshold=often")
    with pytest.raises(ValueError, match="no kind of ledger"):
        parse_url("mysql://db/fleet")
    with pytest.raises(ValueError):
        parse_url("sqlite://host/path")
    with open_url("memory:") as gov:
        gov.open_root("root", money("1"))
    path = tmp_path / "by-url.db"
    with open_url(f"sqlite:///{path}") as gov:
        gov.open_root("root", money("1"))
    with open_url(str(path), read_only=True) as view:
        assert view.available("root") == money("1")


def test_a_conninfo_string_is_postgres_never_a_file() -> None:
    kind, dsn, options = parse_url("host=db port=5432 dbname=fleet user=gov")
    assert (kind, dsn, options) == ("postgres", "host=db port=5432 dbname=fleet user=gov", {})


@pytest.mark.usefixtures("pg_dsn")
def test_a_postgres_url_opens_and_audits(pg_dsn: str) -> None:
    from psycopg.conninfo import conninfo_to_dict

    params = conninfo_to_dict(pg_dsn)
    url = (
        f"postgresql://{params['user']}:{params['password']}@{params['host']}:{params['port']}"
        f"/{params['dbname']}?schema=urlled"
    )
    with open_url(url, policy=POLICY) as gov:
        gov.open_root("root", money("10"))
        for _ in range(45):
            gov.spend("root", money("0.01"))
        assert gov.store is not None and gov.store.schema == "urlled"  # type: ignore[attr-defined]
    with open_url(pg_dsn, schema="urlled", read_only=True) as view:
        assert view.available("root") == money("9.55")
    code, output = _run("audit", url)
    assert code == 0, output
