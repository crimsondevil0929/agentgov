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
import threading
import time
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


def _full_snapshot(tmp_path: Path) -> dict[str, Any]:
    """A snapshot with every part a snapshot holds: a migration seal and the
    pre-0.1.2 events it folded in, an ambiguous hold key, open holds, trips,
    refunds and an earlier checkpoint."""
    from tests.test_core_guarantees import _legacy_database

    path = str(tmp_path / "v1.db")
    _legacy_database(path)
    with BudgetManager.open_sqlite(path, policy=NEVER) as gov:  # sealed on this open
        gov.delegate("worker", "sub", money("0.10"))
        gov.authorize("sub", money("0.01"))
        spend = gov.spend("worker", money("0.02"))
        gov.refund("worker", money("0.01"), reverses=spend)
        gov.checkpoint()
        gov.anchor("worker", "after the checkpoint")
        document: dict[str, Any] = json.loads(_encode_snapshot(gov.ledger._state))
    for part in ("seal", "legacy", "ambiguous", "holds", "tripped", "last_checkpoint"):
        assert document[part], part
    return document


def _parts(value: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[tuple[Any, ...], Any]]:
    yield path, value
    children = (
        value.items()
        if isinstance(value, dict)
        else enumerate(value)
        if isinstance(value, list)
        else ()
    )
    for key, child in children:
        yield from _parts(child, (*path, key))


def _of_another_type(value: Any) -> list[Any]:
    """Values of a JSON type no field holding ``value`` admits."""
    if isinstance(value, bool):
        return [1, "true", None, [], {}]
    if isinstance(value, int):
        return ["1", True, None, [], {}]
    if isinstance(value, str):
        return [1, True, [], {}]
    if isinstance(value, list):
        return ["x", 1, None, {}]
    if isinstance(value, dict):
        return ["x", 1, None, []]
    return [1, True, [], {}]  # null: a nullable text, id, entry or checkpoint


_KEYED_BY_SCOPE = {"balances", "spent", "refunded", "tripped"}  # any key may be absent
_NULLABLE = {"seal", "last_checkpoint", "last_timestamp", "counterparty_id", "ref", "entry_id"}


def test_every_part_of_a_snapshot_must_have_its_type(tmp_path: Path) -> None:
    """A checkpoint's digest is taken over whatever its writer stored, so an
    open from it must refuse a document of the wrong shape, part by part, as
    malformed: never take it, and never fail some other way."""
    from agentgov.receipts.canonical import canonical_bytes

    document = _full_snapshot(tmp_path)
    _decode_snapshot(canonical_bytes(document))
    wrong: list[str] = []

    def refused(changed: dict[str, Any], what: str) -> None:
        try:
            _decode_snapshot(canonical_bytes(changed))
        except LedgerIntegrityError:
            return
        except Exception as exc:  # any other failure is the defect
            wrong.append(f"{what}: {type(exc).__name__}: {exc}")
        else:
            wrong.append(f"{what}: decoded")

    for path, value in _parts(document):
        if not path:
            continue
        *above, last = path
        nullable = last in _NULLABLE or (len(above) == 2 and above[0] == "nodes" and last == 1)
        for other in _of_another_type(value):
            if other is None and nullable:
                continue
            changed = json.loads(json.dumps(document))
            parent = changed
            for key in above:
                parent = parent[key]
            parent[last] = other
            refused(changed, f"{'.'.join(map(str, path))} = {other!r}")
        if isinstance(last, str) and (not above or above[-1] not in _KEYED_BY_SCOPE):
            changed = json.loads(json.dumps(document))
            parent = changed
            for key in above:
                parent = parent[key]
            del parent[last]
            refused(changed, f"{'.'.join(map(str, path))} removed")
    assert not wrong, "\n".join(wrong)


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("format",), "agentgov-snapshot/0", "is not agentgov-snapshot/1"),
        (("totals", "funded"), "a lot", r"\$\.totals\.funded is not an amount: 'a lot'"),
        (("totals", "funded"), "NaN", r"\$\.totals\.funded is not an amount: 'NaN'"),
        (("totals", "spent"), "Infinity", r"\$\.totals\.spent is not an amount: 'Infinity'"),
        (("last_timestamp",), "yesterday", r"\$\.last_timestamp is not a timestamp: 'yesterday'"),
        (("holds", 0, "entry_id"), "a hold", r"\$\.holds\[0\]\.entry_id is not an id: 'a hold'"),
    ],
    ids=["format", "amount", "not a number", "infinite", "timestamp", "id"],
)
def test_every_text_part_of_a_snapshot_must_have_its_form(
    tmp_path: Path, path: tuple[Any, ...], value: str, message: str
) -> None:
    from agentgov.receipts.canonical import canonical_bytes

    document = _full_snapshot(tmp_path)
    parent = document
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(LedgerIntegrityError, match=message):
        _decode_snapshot(canonical_bytes(document))


def test_a_snapshot_that_is_not_json_is_refused() -> None:
    with pytest.raises(LedgerIntegrityError, match="is not canonical JSON"):
        _decode_snapshot(b'{"format": ')


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
    instead, and what settled a hold is found within its scope. Only refunds
    are indexed by the spend they name, which few writes are."""
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
    assert indexed == {
        "sqlite_autoindex_entries_1",
        "entries_by_scope",
        "entries_by_type_memo",
        "entries_reversals",
    }


@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
def test_a_refund_after_a_checkpoint_of_a_spend_before_it_opens(
    backend: str, tmp_path: Path, request: pytest.FixtureRequest
) -> None:
    """Found by scripts/soak.py: an open from a checkpoint replays the entries
    after it, and a refund among them may name a spend from before it, which
    only the store holds. It must be found there, and still bound the refunds
    of that spend, across the checkpoint, at open and after."""

    def open_governor() -> BudgetManager:
        if backend == "sqlite":
            return BudgetManager.open_sqlite(str(tmp_path / "l.db"), policy=NEVER, auditor=False)
        return BudgetManager.open_postgres(request.getfixturevalue("pg_dsn"), policy=NEVER)

    with open_governor() as gov:
        gov.open_root("root", money("10"))
        gov.delegate("root", "a", money("5"))
        spend = gov.spend("a", money("1"))
        gov.checkpoint()
        gov.refund("a", money("0.4"), reverses=spend)
    with open_governor() as gov:
        assert gov.ledger._state.last_checkpoint is not None, "opened from the checkpoint"
        assert gov.available("a") == money("4.4")
        with pytest.raises(ValueError, match="left to refund"):
            gov.refund("a", money("0.7"), reverses=spend)
        gov.refund("a", money("0.6"), reverses=spend)
        gov.verify_integrity()


def test_a_snapshot_does_not_grow_with_every_spend_refunded(tmp_path: Path) -> None:
    """Found by scripts/soak.py: the state kept every refunded spend's total,
    so each snapshot carried all of them (1.7 MB at 31,559, written again at
    every checkpoint). A store that keeps history answers for them instead,
    by an index of refunds by the spend they name, and the bound holds."""

    def snapshot_after(refunds: int) -> int:
        path = str(tmp_path / f"l{refunds}.db")
        with BudgetManager.open_sqlite(path, policy=NEVER, auditor=False) as gov:
            gov.open_root("root", money("1000"))
            gov.delegate("root", "a", money("500"))
            spends = [gov.spend("a", money("1")) for _ in range(refunds)]
            for spend in spends:
                gov.refund("a", money("0.5"), reverses=spend)
            assert not gov.ledger._state.spend_refunds, "the store answers for them"
            gov.checkpoint()
            with pytest.raises(ValueError, match="left to refund"):
                gov.refund("a", money("0.6"), reverses=spends[-1])
        with closing(sqlite3.connect(path)) as conn:
            (size,) = conn.execute("SELECT max(length(body)) FROM snapshots").fetchone()
        with BudgetManager.open_sqlite(path, policy=NEVER, auditor=False) as gov:
            assert gov.ledger._state.last_checkpoint is not None
            with pytest.raises(ValueError, match="left to refund"):
                gov.refund("a", money("0.6"), reverses=spends[0])
            gov.refund("a", money("0.5"), reverses=spends[0])
        return int(size)

    # The same state but for longer numbers and a longer Merkle frontier:
    # 200 spends' refund totals would add some 11 KB.
    assert snapshot_after(200) < snapshot_after(2) + 512


def test_a_spends_refunds_are_bounded_across_governors(pg_dsn: str) -> None:
    """One governor refunds part of a spend another made; neither can then
    refund more than is left of it, whichever catches up with whom."""
    with (
        BudgetManager.open_postgres(pg_dsn, policy=NEVER) as one,
        BudgetManager.open_postgres(pg_dsn, policy=NEVER) as other,
    ):
        one.open_root("root", money("10"))
        one.delegate("root", "a", money("5"))
        spend = one.spend("a", money("1"))
        other.refund("a", money("0.7"), reverses=spend)
        with pytest.raises(ValueError, match="left to refund"):
            one.refund("a", money("0.4"), reverses=spend)
        one.refund("a", money("0.3"), reverses=spend)
        with pytest.raises(ValueError, match="left to refund"):
            other.refund("a", money("0.01"), reverses=spend)
        one.verify_integrity()
        other.verify_integrity()


def test_a_fleet_writes_one_snapshot_for_each_checkpoint(
    pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Found by scripts/soak.py: every governor whose view reached the next
    checkpoint wrote a snapshot, and only one became a checkpoint; the rest
    stayed, never read and never deleted (881 of 2,240, 734 MB in 25
    minutes). The checkpoint is now written by the governor whose own writes
    crossed the line. Storing a snapshot is slowed here as a large one's is,
    which is what leaves the others time to try."""
    from agentgov.postgres import PostgresStore

    put_snapshot = PostgresStore.put_snapshot

    def slow(self: PostgresStore, snapshot: Any) -> None:
        time.sleep(0.05)
        put_snapshot(self, snapshot)

    monkeypatch.setattr(PostgresStore, "put_snapshot", slow)
    policy = GovernancePolicy(max_calls_per_window=0, checkpoint_every=200)
    governors = [
        BudgetManager.open_postgres(pg_dsn, policy=policy, auditor=False) for _ in range(4)
    ]
    try:
        governors[0].open_root("root", money("100000"))
        for i in range(8):
            governors[0].delegate("root", f"s{i}", money("1000"))

        def spend(gov: BudgetManager, scope: str) -> None:
            for _ in range(150):
                gov.spend(scope, money("0.01"))

        runs = [
            threading.Thread(target=spend, args=(gov, f"s{2 * g + t}"))
            for g, gov in enumerate(governors)
            for t in range(2)
        ]
        for run in runs:
            run.start()
        for run in runs:
            run.join(120)
    finally:
        for gov in governors:
            gov.close()
    with psycopg.connect(pg_dsn, autocommit=True, prepare_threshold=None) as conn:
        (checkpoints,) = conn.execute(
            "SELECT count(*) FROM agentgov.entries WHERE entry_type = 'checkpoint'"
        ).fetchone()  # type: ignore[misc]
        (snapshots,) = conn.execute("SELECT count(*) FROM agentgov.snapshots").fetchone()  # type: ignore[misc]
    assert checkpoints >= 4, "1,209 entries, a checkpoint every 200"
    assert snapshots - checkpoints <= checkpoints // 10, (snapshots, checkpoints)


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


def _checkpointed_as(path: Path, forge: Any) -> None:
    """A ledger at ``path`` whose newest checkpoint commits to a snapshot of
    the state ``forge`` changed: what the chain implies, said otherwise, with
    its digest in the chain. Only a replay from genesis shows it is not the
    chain's; an open takes it, and checks what a state must be on its own."""
    from agentgov.storage import Snapshot

    with BudgetManager.open_sqlite(str(path), policy=NEVER, auditor=False) as gov:
        gov.open_root("root", money("1"))
        gov.delegate("root", "child", money("0.5"))
        state = gov.ledger._state.copy()
        forge(state)
        body = _encode_snapshot(state)
        digest = _snapshot_digest(body)
        store: Any = gov.store
        store.put_snapshot(Snapshot(sequence=state.length, digest=digest, body=body))
        memo = f"agentgov-checkpoint v1 seq={state.length} sha256={digest}"
        gov.ledger._post(
            [LedgerLine(EntryType.CHECKPOINT, Direction.NONE, "", Decimal(0), memo=memo)]
        )


def test_an_open_from_a_snapshot_that_creates_money_is_refused(tmp_path: Path) -> None:
    def ten_cents_from_nowhere(state: Any) -> None:
        state.balances["root"] = money("0.6")

    _checkpointed_as(tmp_path / "ledger.db", ten_cents_from_nowhere)
    with pytest.raises(LedgerIntegrityError, match="conservation violated"):
        BudgetManager.open_sqlite(str(tmp_path / "ledger.db"), read_only=True)


def test_an_open_from_a_snapshot_whose_tree_is_not_one_is_refused(tmp_path: Path) -> None:
    def disowned(state: Any) -> None:
        state.nodes["root"] = dataclasses.replace(state.nodes["root"], child_ids=[])

    _checkpointed_as(tmp_path / "ledger.db", disowned)
    with pytest.raises(LedgerIntegrityError, match="not listed as a child of 'root'"):
        BudgetManager.open_sqlite(str(tmp_path / "ledger.db"), read_only=True)
