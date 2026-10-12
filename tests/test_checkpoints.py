"""Checkpoints: open in time bounded by the entries since the last one (F1, F2, F7).

A checkpoint is a canonical snapshot of the chain state as of a sequence,
stored once, and a zero-value CHECKPOINT entry that commits to it by digest.
A governor opens from the newest checkpoint: it verifies the snapshot against
that digest and replays only the entries after it, by the same rules as a
full replay, so what it serves is exactly what a replay from genesis gives.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing
from decimal import Decimal
from pathlib import Path
from typing import Any

import psycopg
import pytest

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.core import (
    Direction,
    EntryType,
    LedgerLine,
    _decode_snapshot,
    _encode_snapshot,
    _frontier_root,
    _Overlay,
    _replay,
    _snapshot_digest,
)
from agentgov.exceptions import LedgerIntegrityError, ReadOnlyLedgerError

EVERY = GovernancePolicy(max_calls_per_window=0, checkpoint_every=50)
NEVER = GovernancePolicy(max_calls_per_window=0, checkpoint_every=0)


def _populate(gov: BudgetManager, *, spends: int = 60) -> None:
    gov.open_root("root", money("1000"))
    gov.delegate("root", "a", money("100"))
    gov.delegate("a", "bé", money("10"))
    gov.authorize("bé", money("0.5"))  # stays open across checkpoints
    for n in range(spends):
        gov.spend("a" if n % 2 else "bé", money("0.01"))
    spend = gov.spend("a", money("0.30"))
    gov.refund("a", money("0.10"), reverses=spend)
    gov.trip("bé", "halted for review")


def _served(gov: BudgetManager) -> tuple[object, ...]:
    state = gov.ledger._state
    return (
        len(gov.ledger),
        gov.ledger.head_hash,
        gov.ledger.balances(),
        state.totals,
        {
            s: (n.parent_id, n.depth, n.allocated, tuple(n.child_ids))
            for s, n in state.nodes.items()
        },
        sorted(state.tripped),
        sorted(gov._open_auths, key=str),
        state.spent,
        state.refunded,
        state.spend_refunds,
        state.frontier,
    )


@pytest.fixture
def ledger_db(tmp_path: Path) -> Iterator[str]:
    path = str(tmp_path / "ledger.db")
    with BudgetManager.open_sqlite(path, policy=EVERY) as gov:
        _populate(gov)
    yield path


# -- the snapshot ----------------------------------------------------------------


def test_a_snapshot_round_trips_and_is_canonical() -> None:
    gov = BudgetManager()
    _populate(gov, spends=5)
    state = gov.ledger._state
    body = _encode_snapshot(state)
    decoded = _decode_snapshot(body)
    assert _encode_snapshot(decoded) == body
    assert decoded.balances == state.balances
    assert decoded.holds == state.holds
    assert decoded.frontier == state.frontier
    assert _frontier_root(decoded.frontier) == _frontier_root(state.frontier)
    assert len(_snapshot_digest(body)) == 64


def test_a_snapshot_that_is_not_canonical_is_refused() -> None:
    gov = BudgetManager()
    _populate(gov, spends=2)
    document = json.loads(_encode_snapshot(gov.ledger._state))
    pretty = json.dumps(document, indent=1, sort_keys=True).encode("utf-8")
    with pytest.raises(LedgerIntegrityError, match="not the canonical encoding"):
        _decode_snapshot(pretty)


@pytest.mark.parametrize(
    "damage",
    [
        lambda d: d.update(format="agentgov-snapshot/0"),
        lambda d: d.update(head="00"),
        lambda d: d["frontier"].pop(),
        lambda d: d["nodes"][0].pop(),
        lambda d: d.update(roots=["nowhere"]),
        lambda d: d["balances"].update(root="1E+3"),
        lambda d: d.update(sequence=-1),
    ],
    ids=["format", "head", "frontier", "node", "root", "amount", "sequence"],
)
def test_a_malformed_snapshot_is_refused(damage: Any) -> None:
    gov = BudgetManager()
    _populate(gov, spends=2)
    document = json.loads(_encode_snapshot(gov.ledger._state))
    damage(document)
    from agentgov.receipts.canonical import canonical_bytes

    with pytest.raises(LedgerIntegrityError):
        _decode_snapshot(canonical_bytes(document))


# -- writing checkpoints -----------------------------------------------------------


def test_checkpoints_are_written_every_n_entries(ledger_db: str) -> None:
    from agentgov.storage import SqliteStore

    store = SqliteStore(ledger_db, read_only=True)
    try:
        checkpoints = store.checkpoints()
        assert len(checkpoints) >= 3
        for entry_sequence, snapshot_sequence, digest in checkpoints:
            assert snapshot_sequence < entry_sequence
            snapshot = store.snapshot_at(snapshot_sequence)
            assert snapshot is not None and snapshot.digest == digest
            assert _snapshot_digest(snapshot.body) == digest
        gaps = [b[1] - a[1] for a, b in itertools.pairwise(checkpoints)]
        assert all(gap >= 50 for gap in gaps)
    finally:
        store.close()


def test_a_checkpoint_commits_to_the_state_at_its_sequence(tmp_path: Path) -> None:
    path = str(tmp_path / "manual.db")
    with BudgetManager.open_sqlite(path, policy=NEVER) as gov:
        _populate(gov, spends=4)
        before = _encode_snapshot(gov.ledger._state)
        sequence = gov.checkpoint()
        assert sequence == len(gov.ledger) - 1
        (entry,) = gov.find_entries(entry_type=EntryType.CHECKPOINT)
        assert (
            entry.memo == f"agentgov-checkpoint v1 seq={sequence} sha256={_snapshot_digest(before)}"
        )
        assert gov.checkpoint() == sequence, "nothing new since: the same checkpoint"
        gov.verify_integrity()


def test_checkpointing_needs_a_durable_writable_store(ledger_db: str) -> None:
    with pytest.raises(TypeError):
        BudgetManager().checkpoint()
    with (
        BudgetManager.open_sqlite(ledger_db, read_only=True) as reader,
        pytest.raises(ReadOnlyLedgerError),
    ):
        reader.checkpoint()


def test_an_empty_ledger_has_nothing_to_checkpoint(tmp_path: Path) -> None:
    with BudgetManager.open_sqlite(str(tmp_path / "empty.db")) as gov, pytest.raises(ValueError):
        gov.checkpoint()


# -- opening from a checkpoint ---------------------------------------------------------


def test_opening_from_a_checkpoint_serves_what_a_full_replay_serves(ledger_db: str) -> None:
    with BudgetManager.open_sqlite(ledger_db, verify="full") as full:
        expected = _served(full)
    with BudgetManager.open_sqlite(ledger_db) as fast:
        assert _served(fast) == expected
        fast.verify_integrity()  # still a full verification, from the store
        assert fast.ledger._entries is None, "history stays in the store"


def test_opening_from_a_checkpoint_replays_only_the_entries_after_it(
    ledger_db: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    applied: list[int] = []
    original = _Overlay.apply

    def counting(self: _Overlay, entry: Any, **kwargs: Any) -> None:
        applied.append(entry.sequence)
        original(self, entry, **kwargs)

    monkeypatch.setattr(_Overlay, "apply", counting)
    with BudgetManager.open_sqlite(ledger_db, read_only=True) as gov:
        length = len(gov.ledger)
        newest = gov.find_entries(entry_type=EntryType.CHECKPOINT)[-1]
    snapshot_sequence = int(newest.memo.split("seq=")[1].split()[0])
    assert applied == list(range(snapshot_sequence + 1, length + 1))
    assert len(applied) < length / 2


def test_an_altered_snapshot_is_refused_and_a_full_replay_still_opens(ledger_db: str) -> None:
    conn = sqlite3.connect(ledger_db)
    try:
        sequence, body = conn.execute(
            "SELECT sequence, body FROM snapshots ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        forged = bytes(body)[:-2] + b"0}"  # one byte of the state changed
        conn.execute("UPDATE snapshots SET body = ? WHERE sequence = ?", (forged, sequence))
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(LedgerIntegrityError, match="altered after it was written"):
        BudgetManager.open_sqlite(ledger_db, read_only=True)
    with BudgetManager.open_sqlite(ledger_db, read_only=True, verify="full") as full:
        full.verify_integrity()


def test_a_missing_snapshot_is_refused_not_skipped(ledger_db: str) -> None:
    conn = sqlite3.connect(ledger_db)
    try:
        conn.execute("DELETE FROM snapshots WHERE sequence = (SELECT max(sequence) FROM snapshots)")
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(LedgerIntegrityError, match="verify='full'"):
        BudgetManager.open_sqlite(ledger_db, read_only=True)


def test_the_verify_policy_is_validated() -> None:
    with pytest.raises(ValueError, match="verify must be one of"):
        BudgetManager(verify="none")


# -- the CHECKPOINT entry's own rules ------------------------------------------------------


@pytest.mark.parametrize(
    ("memo", "message"),
    [
        ("not a checkpoint", "malformed checkpoint"),
        (f"agentgov-checkpoint v1 seq=99 sha256={'0' * 64}", "not before it"),
    ],
)
def test_a_checkpoint_entry_must_name_an_earlier_snapshot(memo: str, message: str) -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1"))
    with pytest.raises(LedgerIntegrityError, match=message):
        gov.ledger._post(
            [LedgerLine(EntryType.CHECKPOINT, Direction.NONE, "", Decimal(0), memo=memo)]
        )


def test_checkpoints_name_strictly_later_snapshots() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1"))
    gov.spend("root", money("0.1"))
    line = LedgerLine(
        EntryType.CHECKPOINT,
        Direction.NONE,
        "",
        Decimal(0),
        memo=f"agentgov-checkpoint v1 seq=2 sha256={'0' * 64}",
    )
    gov.ledger._post([line])
    with pytest.raises(LedgerIntegrityError, match="not after the previous"):
        gov.ledger._post([line])
    with pytest.raises(LedgerIntegrityError, match="belongs to no scope"):
        gov.ledger._post([dataclasses.replace(line, scope_id="root")])


# -- history, by index ----------------------------------------------------------------------


def test_history_queries_agree_with_the_chain(ledger_db: str) -> None:
    with BudgetManager.open_sqlite(ledger_db, read_only=True) as gov:
        trail = gov.audit_trail()
        assert [e.sequence for e in trail] == list(range(1, len(gov.ledger) + 1))
        assert list(gov.iter_audit_trail()) == list(trail)
        assert gov.entry(7) == trail[6]
        assert gov.entries(after=10, limit=5) == trail[10:15]
        with pytest.raises(IndexError):
            gov.entry(len(gov.ledger) + 1)
        assert gov.find_entries(scope_id="a") == tuple(e for e in trail if e.scope_id == "a")
        assert gov.audit_trail("a") == gov.find_entries(scope_id="a")
        (trip,) = gov.find_entries(entry_type=EntryType.CIRCUIT_TRIPPED, memo="halted for review")
        assert trip.scope_id == "bé"
        (refund,) = gov.find_entries(entry_type=EntryType.REVERSAL)
        assert refund.ref is not None
        (spend,) = gov.find_entries(
            entry_type=EntryType.SPEND, transaction_id=_txn(trail, refund.ref)
        )
        assert spend.entry_id == refund.ref
        assert gov.find_entries(ref=refund.ref) == (refund,)
        assert len(gov.find_entries(scope_id="a", limit=3)) == 3
        assert gov.control_events[0].reason == "halted for review"


def _txn(trail: tuple[Any, ...], entry_id: Any) -> Any:
    return next(e.transaction_id for e in trail if e.entry_id == entry_id)


def test_history_is_indexed_by_scope_and_type_only(tmp_path: Path) -> None:
    """Every index on entries is a page written by every commit, and the
    random keys of transaction_id and ref would land each on a page of its
    own: about a fifth of a SQLite governor's writes. Lookups by them filter
    instead, and what settled a hold is found within its scope."""
    path = str(tmp_path / "l.db")
    with BudgetManager.open_sqlite(path, auditor=False) as gov:
        gov.open_root("root", money("10"))
        gov.delegate("root", "a", money("5"))
        hold = gov.authorize("a", money("1"))
        spend = gov.capture(hold, money("0.4"))
        settled = gov.find_entries(scope_id=hold.scope_id, ref=hold.authorization_id)
        assert spend in settled and all(e.ref == hold.authorization_id for e in settled)
        assert {e.entry_type for e in settled} == {EntryType.HOLD_VOID, EntryType.SPEND}
    with closing(sqlite3.connect(path)) as conn:
        indexed = {
            name
            for (name,) in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'entries'"
            )
        }
    assert indexed == {"sqlite_autoindex_entries_1", "entries_by_scope", "entries_by_type_memo"}


def test_a_named_refund_still_bounds_after_a_reopen(ledger_db: str) -> None:
    with BudgetManager.open_sqlite(ledger_db) as gov:
        (refund,) = gov.find_entries(entry_type=EntryType.REVERSAL)
        assert refund.ref is not None
        with pytest.raises(ValueError, match="left to refund"):
            gov.refund("a", money("0.21"), reverses=refund.ref)
        gov.refund("a", money("0.20"), reverses=refund.ref)
        gov.verify_integrity()


def test_a_full_replay_from_the_store_reproduces_the_served_state(ledger_db: str) -> None:
    with BudgetManager.open_sqlite(ledger_db, read_only=True) as gov:
        replayed = _replay(list(gov.iter_audit_trail()))
        assert replayed.balances == gov.ledger.balances()
        assert replayed.frontier == gov.ledger._state.frontier


# -- PostgreSQL ------------------------------------------------------------------------------


@pytest.mark.usefixtures("pg_dsn")
def test_governors_checkpointing_together_converge(pg_dsn: str) -> None:
    import threading

    with BudgetManager.open_postgres(pg_dsn, policy=NEVER) as setup:
        _populate(setup, spends=10)
    governors = [BudgetManager.open_postgres(pg_dsn, policy=NEVER) for _ in range(4)]
    results: list[int] = []
    errors: list[BaseException] = []

    def run(gov: BudgetManager) -> None:
        try:
            results.append(gov.checkpoint())
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(g,)) for g in governors]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for gov in governors:
        gov.close()
    assert errors == []
    with (
        BudgetManager.open_postgres(pg_dsn) as fast,
        BudgetManager.open_postgres(pg_dsn, verify="full", read_only=True) as full,
    ):
        assert _served(fast) == _served(full)
        assert len(fast.find_entries(entry_type=EntryType.CHECKPOINT)) == 1


@pytest.mark.usefixtures("pg_dsn")
def test_snapshots_and_audit_marks_are_append_only_in_postgres(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, policy=NEVER) as gov:
        _populate(gov, spends=2)
        gov.checkpoint()
    with psycopg.connect(pg_dsn, autocommit=True, prepare_threshold=None) as conn:
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
            conn.execute("UPDATE agentgov.snapshots SET digest = 'x'")
        with pytest.raises(psycopg.errors.IntegrityConstraintViolation, match="append-only"):
            conn.execute("DELETE FROM agentgov.snapshots")


@pytest.mark.usefixtures("pg_dsn")
def test_history_queries_on_postgres_match_sqlite(pg_dsn: str, ledger_db: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, policy=EVERY) as gov:
        _populate(gov)
        assert len(gov.find_entries(entry_type=EntryType.CHECKPOINT)) >= 3
    with (
        BudgetManager.open_postgres(pg_dsn) as pg,
        BudgetManager.open_sqlite(ledger_db, read_only=True) as lite,
    ):
        for gov in (pg, lite):
            (trip,) = gov.find_entries(
                entry_type=EntryType.CIRCUIT_TRIPPED, memo="halted for review"
            )
            assert trip.scope_id == "bé"
            assert gov.entries(after=0, limit=3) == gov.audit_trail()[:3]
        assert len(pg.find_entries(scope_id="a")) == len(lite.find_entries(scope_id="a"))
        pg.verify_integrity()
