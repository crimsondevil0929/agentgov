"""Ledger mechanisms the mutation pass found no test of (mutation/phase6-ledger.json).

Each test here pins a mechanism a mutant removed or turned around with every
other test still passing: a rule a forged chain could break, a bound on what a
caller may pass, the identity a call is recorded under, the hash of an entry
as the format specifies it, when a governor writes a checkpoint and what it
does when it cannot, how a transaction that did not commit is undone, history
read from memory as from a store, and a store with only 0.4's interface.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import logging
import re
import shutil
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agentgov import BudgetManager, CheckpointSigning, GovernancePolicy, money
from agentgov.audit import Auditor, AuditorThread
from agentgov.core import (
    GENESIS_HASH,
    MAX_ID_BYTES,
    MAX_MEMO_BYTES,
    Direction,
    EntryType,
    Ledger,
    LedgerEntry,
    LedgerLine,
    WriteBatch,
    _CheckpointStatement,
    _encode_snapshot,
    _frontier_root,
    _hash_entry,
    _request_text,
    _snapshot_digest,
)
from agentgov.exceptions import (
    DenialOfWalletError,
    DoubleSpendError,
    IdempotencyConflictError,
    LedgerIntegrityError,
    LedgerRollbackError,
    MalformedReceiptError,
    ReadOnlyLedgerError,
    StorageError,
)
from agentgov.postgres import PostgresStore
from agentgov.receipts import Ed25519Signer
from agentgov.storage import Snapshot, SqliteStore

_Line = tuple[EntryType, Direction, str, str, int | None]
_FUND: _Line = (EntryType.FUNDING, Direction.CREDIT, "root", "1", None)
KEY = Ed25519Signer(bytes(range(32)))
NEVER = GovernancePolicy(max_calls_per_window=0, checkpoint_every=0)
EVERY_FOUR = GovernancePolicy(max_calls_per_window=0, checkpoint_every=4)


def _v3(
    lines: list[_Line],
    *,
    memos: dict[int, str] | None = None,
    counterparties: dict[int, str] | None = None,
) -> list[LedgerEntry]:
    """AGOV3 entries with valid hashes and links, however wrong their content.
    A line's last element names, by index, the entry it refers to."""
    entries: list[LedgerEntry] = []
    head, balances = GENESIS_HASH, dict[str, Decimal]()
    began = datetime.now(UTC)
    for index, (kind, direction, scope, amount, target) in enumerate(lines):
        value = money(amount)
        sign = {Direction.CREDIT: 1, Direction.DEBIT: -1, Direction.NONE: 0}[direction]
        balances[scope] = balances.get(scope, Decimal(0)) + sign * value
        fields: dict[str, object] = dict(
            sequence=index + 1,
            entry_id=uuid.uuid4(),
            transaction_id=uuid.uuid4(),
            timestamp=began + timedelta(microseconds=index),
            entry_type=kind,
            direction=direction,
            scope_id=scope,
            counterparty_id=(counterparties or {}).get(index),
            amount=value,
            balance_after=balances[scope],
            memo=(memos or {}).get(index, ""),
            ref=entries[target].entry_id if target is not None else None,
            version="AGOV3",
        )
        digest = _hash_entry(prev_hash=head, **fields)  # type: ignore[arg-type]
        entries.append(LedgerEntry(prev_hash=head, entry_hash=digest, **fields))  # type: ignore[arg-type]
        head = digest
    return entries


def _traced(record: logging.LogRecord) -> bool:
    """Whether a log record carries the exception it reports, traceback and all."""
    return isinstance(record.exc_info, tuple) and record.exc_info[0] is not None


def _load(entries: list[LedgerEntry]) -> Ledger:
    ledger = Ledger()
    ledger._adopt(entries)
    return ledger


def _checkpoint(sequence: int) -> str:
    return f"agentgov-checkpoint v1 seq={sequence} sha256={'0' * 64}"


# -- what a forged chain cannot get past ------------------------------------------------


def test_a_checkpoint_entry_names_a_sequence_before_its_own() -> None:
    marker = (EntryType.CHECKPOINT, Direction.NONE, "", "0", None)
    with pytest.raises(
        LedgerIntegrityError, match="checkpoints sequence 2, which is not before it"
    ):
        _load(_v3([_FUND, marker], memos={1: _checkpoint(2)}))
    with pytest.raises(
        LedgerIntegrityError, match="sequence 1, which is not after the previous checkpoint's 1"
    ):
        _load(_v3([_FUND, marker, marker], memos={1: _checkpoint(1), 2: _checkpoint(1)}))
    _load(_v3([_FUND, marker, marker], memos={1: _checkpoint(1), 2: _checkpoint(2)}))


def test_a_refund_reverses_a_spend_of_its_own_scope() -> None:
    other: _Line = (EntryType.FUNDING, Direction.CREDIT, "other", "1", None)
    spend: _Line = (EntryType.SPEND, Direction.DEBIT, "root", "0.10", None)
    refund: _Line = (EntryType.REVERSAL, Direction.CREDIT, "other", "0.05", 2)
    with pytest.raises(LedgerIntegrityError, match="of scope 'root' into 'other'"):
        _load(_v3([_FUND, other, spend, refund]))


def test_a_replay_refunds_a_spend_at_most_its_amount() -> None:
    """Two spends, so the scope's own bound would allow more: the bound that
    refuses is the spend's, across every refund that names it."""
    spends: list[_Line] = [(EntryType.SPEND, Direction.DEBIT, "root", "0.10", None)] * 2
    over: _Line = (EntryType.REVERSAL, Direction.CREDIT, "root", "0.15", 1)
    with pytest.raises(LedgerIntegrityError, match=r"more than the 0\.10000000 it spent"):
        _load(_v3([_FUND, *spends, over]))
    part: _Line = (EntryType.REVERSAL, Direction.CREDIT, "root", "0.06", 1)
    with pytest.raises(LedgerIntegrityError, match=r"bringing its refunds to 0\.12000000"):
        _load(_v3([_FUND, *spends, part, part]))
    _load(_v3([_FUND, *spends, part]))


def test_an_agov3_counterparty_id_is_an_identifier() -> None:
    with pytest.raises(LedgerIntegrityError, match="counterparty id holds a control character"):
        _load(_v3([_FUND], counterparties={0: "a\nb"}))


# -- the format ------------------------------------------------------------------------


def test_agov2_hashes_text_beyond_ascii_escaped() -> None:
    """docs/LEDGER_FORMAT.md 2.2: the AGOV2 hash input escapes every character
    beyond ASCII as \\uXXXX."""
    entry = LedgerEntry(
        sequence=1,
        entry_id=uuid.UUID(int=1),
        transaction_id=uuid.UUID(int=2),
        timestamp=datetime(2026, 1, 2, 3, 4, 5, 600000, tzinfo=UTC),
        entry_type=EntryType.FUNDING,
        direction=Direction.CREDIT,
        scope_id="équipe",
        counterparty_id=None,
        amount=Decimal("1.00000000"),
        balance_after=Decimal("1.00000000"),
        prev_hash="0" * 64,
        entry_hash="",
        memo="café",
        ref=None,
        version="AGOV2",
    )
    text = (
        '["AGOV2","' + "0" * 64 + '",1,"00000000-0000-0000-0000-000000000001",'
        '"00000000-0000-0000-0000-000000000002","2026-01-02T03:04:05.600000Z",'
        '"funding","CR","\\u00e9quipe",null,"1.00000000","1.00000000","caf\\u00e9",null]'
    )
    assert entry.recompute_hash() == hashlib.sha256(text.encode("ascii")).hexdigest()


def test_an_entry_of_an_unknown_version_has_no_hash() -> None:
    (funding,) = _v3([_FUND])
    with pytest.raises(ValueError, match="unknown audit version 'AGOV9'"):
        dataclasses.replace(funding, version="AGOV9").recompute_hash()


def test_the_root_of_no_entries_is_the_hash_of_nothing() -> None:
    """RFC 9162 2.1.1: the root of an empty tree is SHA-256 of the empty string."""
    assert _frontier_root(()) == hashlib.sha256(b"").digest()


# -- what a caller may pass -----------------------------------------------------------


def test_text_is_bounded_in_utf8_bytes() -> None:
    gov = BudgetManager()
    at_limit = "é" * (MAX_ID_BYTES // 2)  # two bytes each
    gov.open_root(at_limit, money("1"))
    with pytest.raises(
        ValueError, match=f"{MAX_ID_BYTES + 2} bytes of UTF-8; at most {MAX_ID_BYTES}"
    ):
        gov.open_root(at_limit + "é", money("1"))
    gov.anchor(at_limit, "m" * MAX_MEMO_BYTES)
    with pytest.raises(ValueError, match=f"at most {MAX_MEMO_BYTES} are allowed"):
        gov.anchor(at_limit, "m" * (MAX_MEMO_BYTES + 1))


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ("", "a non-empty string"),
        (7, "a non-empty string"),
        ("retry\nme", "holds a control character"),
        ("k" * 256, "256 bytes of UTF-8; at most 255"),
    ],
    ids=["empty", "not text", "a control character", "too long"],
)
def test_an_idempotency_key_is_a_short_line_of_text(key: object, message: str) -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1"))
    with pytest.raises(ValueError, match=message):
        gov.spend("root", money("0.01"), idempotency_key=key)  # type: ignore[arg-type]
    assert gov.available("root") == money("1")
    gov.spend("root", money("0.01"), idempotency_key="k" * 255)


def test_a_call_is_recorded_under_its_canonical_request() -> None:
    """What a key names, stored with its result and compared on every retry,
    by every governor and every release: canonical JSON, sorted keys, amounts
    fixed-point, ids as text, text as it is, nothing as null."""
    assert _request_text(
        "refund",
        scope_id="équipe",
        amount=money("0.5"),
        memo=None,
        reverses=uuid.UUID(int=3),
    ) == (
        '{"amount":"0.50000000","memo":null,"op":"refund",'
        '"reverses":"00000000-0000-0000-0000-000000000003","scope_id":"équipe"}'
    )


def test_a_call_with_no_memo_is_not_the_call_with_memo_none() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1"))
    gov.spend("root", money("0.01"), idempotency_key="k")
    with pytest.raises(IdempotencyConflictError):
        gov.spend("root", money("0.01"), memo="None", idempotency_key="k")


# -- checkpoints a governor writes ------------------------------------------------------


def _sqlite(tmp_path: Path, policy: GovernancePolicy = NEVER, **kwargs: Any) -> BudgetManager:
    return BudgetManager.open_sqlite(
        str(tmp_path / "ledger.db"), policy=policy, auditor=False, **kwargs
    )


def _checkpointed(gov: BudgetManager) -> list[int]:
    """The sequences the ledger's checkpoints are of, oldest first."""
    store: Any = gov.store
    return [of for _, of, _ in store.checkpoints()]


def test_checkpoints_fall_every_n_entries_from_the_last(tmp_path: Path) -> None:
    with _sqlite(tmp_path, EVERY_FOUR) as gov:
        gov.open_root("root", money("10"))
        for n in range(9):
            gov.anchor("root", f"tick {n}")
        assert _checkpointed(gov) == [4, 8, 12]  # each checkpoint entry follows its own


def test_a_checkpoint_every_entry_checkpoints_after_every_write(tmp_path: Path) -> None:
    every = GovernancePolicy(max_calls_per_window=0, checkpoint_every=1)
    with _sqlite(tmp_path, every) as gov:
        gov.open_root("root", money("10"))
        gov.anchor("root", "a")
        gov.anchor("root", "b")
        assert _checkpointed(gov) == [1, 3, 5]


def test_a_checkpoint_after_one_more_entry_is_a_new_checkpoint(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        assert gov.checkpoint() == 1
        assert gov.checkpoint() == 1, "nothing since but its own entry"
        gov.anchor("root", "one more")
        assert gov.checkpoint() == 3
        assert _checkpointed(gov) == [1, 3]


def test_a_failed_automatic_checkpoint_backs_off_doubling_and_says_why(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def unwritable(self: SqliteStore, snapshot: object) -> None:
        raise StorageError("the disk is full")

    gov = _sqlite(tmp_path, EVERY_FOUR)
    gov.open_root("root", money("10"))
    monkeypatch.setattr(SqliteStore, "put_snapshot", unwritable)
    with caplog.at_level(logging.WARNING):
        for n in range(3):
            gov.anchor("root", f"tick {n}")
    (failed,) = [r for r in caplog.records if "automatic checkpoint failed" in r.getMessage()]
    assert _traced(failed) and "the next try is in 1 s" in failed.getMessage()
    assert gov._checkpoint_backoff == 1.0
    gov._checkpoint_retry_at = 0.0  # a second has passed
    with caplog.at_level(logging.WARNING):
        gov.anchor("root", "still owed")
    assert "the next try is in 2 s" in caplog.records[-1].getMessage()
    assert gov._checkpoint_backoff == 2.0
    monkeypatch.undo()
    gov._checkpoint_retry_at = 0.0
    gov.anchor("root", "and written")
    assert _checkpointed(gov) == [6] and gov._checkpoint_backoff == 0.0
    gov.close()


def test_a_governor_that_stopped_following_its_ledger_writes_no_snapshot(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov._unusable = "the auditor found the chain does not verify"
        with pytest.raises(LedgerIntegrityError, match="stopped following"):
            gov.checkpoint()
        store: Any = gov.store
        assert store.snapshot_at(1) is None


def test_a_governor_that_only_checks_signatures_checkpoints_unsigned(tmp_path: Path) -> None:
    trusting = CheckpointSigning(keys=[KEY.public_key()])
    with _sqlite(tmp_path, signing=trusting) as gov:
        gov.open_root("root", money("1"))
        assert gov.checkpoint() == 1
        store: Any = gov.store
        assert store.snapshot_at(1).signature is None
    with _sqlite(tmp_path, signing=trusting) as reopened:
        assert reopened.available("root") == money("1")


def test_publishing_a_checkpoint_needs_one(tmp_path: Path) -> None:
    with _sqlite(tmp_path, signing=CheckpointSigning(signer=KEY)) as gov:
        gov.open_root("root", money("1"))
        with pytest.raises(ValueError, match="no checkpoint to publish"):
            gov.publish_checkpoint([])


def test_a_checkpoint_statement_is_of_its_own_kind(tmp_path: Path) -> None:
    with _sqlite(tmp_path, signing=CheckpointSigning(signer=KEY)) as gov:
        gov.open_root("root", money("1"))
        gov.checkpoint()
        store: Any = gov.store
        text = store.snapshot_at(1).signature
    assert _CheckpointStatement.loads(text).sequence == 1  # the first entry is a sequence
    with pytest.raises(MalformedReceiptError):
        _CheckpointStatement.loads(text.replace('"v":"agentgov-checkpoint"', '"v":"other"'))


# -- what a transaction that did not commit leaves -------------------------------------


def test_a_transaction_does_not_open_inside_a_mutation() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1"))
    with gov._mutating():
        with pytest.raises(RuntimeError, match="does not nest"):
            with gov.transaction():
                pass
    with gov.transaction() as txn:
        txn.anchor("root", "outside one")


def test_a_ledger_that_cannot_be_read_after_a_rolled_back_transaction_stops_the_governor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def unreadable(self: SqliteStore, **kwargs: object) -> object:
        raise StorageError("the disk went away")

    gov = _sqlite(tmp_path)
    gov.open_root("root", money("1"))
    with caplog.at_level(logging.WARNING), pytest.raises(RuntimeError, match="abandoned"):
        with gov.transaction() as txn:
            txn.spend("root", money("0.10"))
            monkeypatch.setattr(SqliteStore, "load", unreadable)
            raise RuntimeError("abandoned")
    assert "could not re-read the ledger after a rolled-back transaction" in caplog.text
    monkeypatch.undo()
    with pytest.raises(LedgerIntegrityError, match="a transaction did not commit"):
        gov.spend("root", money("0.10"))
    gov.close()


def test_a_trip_a_rolled_back_transaction_recorded_and_could_not_write_is_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    gov = BudgetManager(policy=NEVER)
    gov.open_root("root", money("1"))

    def unrecorded(scope_id: str, reason: str) -> None:
        raise StorageError("the trip could not be written")

    with caplog.at_level(logging.WARNING), pytest.raises(RuntimeError, match="abandoned"):
        with gov.transaction() as txn:
            with pytest.raises(DenialOfWalletError):
                txn.authorize("root", money("5"))
            monkeypatch.setattr(gov, "_trip", unrecorded)
            raise RuntimeError("abandoned")
    (logged,) = [r for r in caplog.records if "could not record the breaker trip" in r.getMessage()]
    assert "'root'" in logged.getMessage() and _traced(logged)


def test_a_call_recorded_just_before_a_rolled_back_transaction_is_kept() -> None:
    gov = BudgetManager(policy=NEVER)
    gov.open_root("root", money("1"))
    spent = gov.spend("root", money("0.10"), idempotency_key="k")
    with pytest.raises(RuntimeError, match="abandoned"):
        with gov.transaction() as txn:
            txn.spend("root", money("0.10"))
            raise RuntimeError("abandoned")
    assert gov.spend("root", money("0.10"), idempotency_key="k") == spent
    assert gov.available("root") == money("0.90")


# -- history ---------------------------------------------------------------------------


def _answers_history_alike(gov: BudgetManager) -> None:
    gov.open_root("root", money("10"))
    held = gov.authorize("root", money("1"))
    captured = gov.capture(held, money("0.5"), memo="paid")
    gov.anchor("root", "paid")
    spend = gov.spend("root", money("0.2"), memo="other")
    refund = gov.refund("root", money("0.1"), reverses=spend)
    trail = gov.audit_trail()
    assert gov.find_entries(memo="paid") == tuple(e for e in trail if e.memo == "paid")
    assert len(gov.find_entries(memo="paid")) == 2
    same = captured.transaction_id
    assert gov.find_entries(transaction_id=same) == tuple(
        e for e in trail if e.transaction_id == same
    )
    assert gov.find_entries(ref=held.entry.entry_id) == tuple(
        e for e in trail if e.ref == held.entry.entry_id
    )
    assert gov.find_entries(ref=spend.entry_id) == (refund,)
    spends = [e for e in trail if e.entry_type is EntryType.SPEND]
    assert gov.find_entries(entry_type=EntryType.SPEND, limit=1) == (spends[0],)
    assert gov.ledger.entry(0) is None and gov.ledger.entry(len(trail) + 1) is None
    with pytest.raises(IndexError):
        gov.entry(0)
    assert gov.entries(after=len(trail) - 2) == trail[-2:]
    store: Any = gov.store
    if store is not None:
        assert [e.sequence for e in store.iter_entries()] == [e.sequence for e in trail]
        assert list(store.iter_entries(after=len(trail))) == []


@pytest.mark.parametrize("stored", [False, True], ids=["in memory", "over sqlite"])
def test_history_is_answered_alike_from_memory_and_from_a_store(
    stored: bool, tmp_path: Path
) -> None:
    gov = _sqlite(tmp_path) if stored else BudgetManager(policy=NEVER)
    _answers_history_alike(gov)
    gov.close()


def test_history_is_answered_alike_over_postgres(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False) as gov:
        _answers_history_alike(gov)


# -- a governor over PostgreSQL, among others ---------------------------------------------


def test_a_governor_left_dirty_re_reads_before_it_checkpoints(
    pg_dsn: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A write that did not commit, and a re-read that failed, leave memory
    ahead of the ledger: a checkpoint then reads the ledger again first, and
    snapshots what committed."""

    def never_committed(self: PostgresStore, session: Any) -> None:
        session.failed = True
        self._rollback_quietly()
        raise StorageError("the connection dropped before COMMIT")

    def unreadable(self: PostgresStore, **kwargs: object) -> object:
        raise StorageError("the database is unreachable")

    gov = BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False)
    gov.open_root("org", money("100"))
    with monkeypatch.context() as patch, caplog.at_level(logging.WARNING):
        patch.setattr(PostgresStore, "_end", never_committed)
        patch.setattr(PostgresStore, "load", unreadable)
        with pytest.raises(StorageError, match="dropped before COMMIT"):
            gov.spend("org", money("1"))
    (logged,) = [r for r in caplog.records if "write that did not commit" in r.getMessage()]
    assert _traced(logged) and gov._dirty
    assert gov.checkpoint() == 1
    gov.close()
    with BudgetManager.open_postgres(pg_dsn, auditor=False) as reopened:
        assert reopened.available("org") == money("100")


def _hold_snapshots_of(
    store: Any, monkeypatch: pytest.MonkeyPatch, gate: threading.Event, entered: threading.Event
) -> None:
    """Hold ``store``'s snapshot writes at ``gate``; other stores write theirs."""
    real = PostgresStore.put_snapshot

    def held(self: PostgresStore, snapshot: Snapshot) -> None:
        if self is store:
            entered.set()
            assert gate.wait(10)
        real(self, snapshot)

    monkeypatch.setattr(PostgresStore, "put_snapshot", held)


def test_a_checkpoint_another_governor_wrote_meanwhile_is_the_one_returned(
    pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    one = BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False)
    two = BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False)
    try:
        one.open_root("org", money("100"))
        gate, entered = threading.Event(), threading.Event()
        _hold_snapshots_of(one.store, monkeypatch, gate, entered)
        result: list[int] = []
        writing = threading.Thread(target=lambda: result.append(one.checkpoint()), daemon=True)
        writing.start()
        assert entered.wait(5)
        assert two.checkpoint() == 1  # first to the ledger
        gate.set()
        writing.join(10)
        assert result == [1], "the checkpoint the other governor wrote"
        assert _checkpointed(two) == [1]
    finally:
        one.close()
        two.close()


def test_a_checkpoint_another_governor_wrote_pays_this_ones_debt(
    pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unwritable(self: PostgresStore, snapshot: Snapshot) -> None:
        raise StorageError("the disk is full")

    one = BudgetManager.open_postgres(pg_dsn, policy=EVERY_FOUR, auditor=False)
    two = BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False)
    try:
        one.open_root("org", money("100"))
        with monkeypatch.context() as patch:
            patch.setattr(PostgresStore, "put_snapshot", unwritable)
            for n in range(3):
                one.anchor("org", f"tick {n}")  # crosses 4; its checkpoint fails
        assert one._checkpoint_owed
        assert two.checkpoint() == 4
        one._checkpoint_retry_at = 0.0  # its backoff has passed
        one.anchor("org", "after")
        assert _checkpointed(one) == [4], "no second checkpoint so soon after the first"
    finally:
        one.close()
        two.close()


def test_a_governor_owes_a_checkpoint_only_for_a_boundary_its_own_writes_crossed(
    pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The governor whose write crossed a multiple of checkpoint_every writes
    the checkpoint, however slowly; one that writes right after the boundary
    owes none, so a fleet writes one snapshot, not one each."""
    one = BudgetManager.open_postgres(pg_dsn, policy=EVERY_FOUR, auditor=False)
    two = BudgetManager.open_postgres(pg_dsn, policy=EVERY_FOUR, auditor=False)
    try:
        one.open_root("org", money("100"))
        one.anchor("org", "2")
        one.anchor("org", "3")
        gate, entered = threading.Event(), threading.Event()
        _hold_snapshots_of(two.store, monkeypatch, gate, entered)
        crossing = threading.Thread(target=lambda: two.anchor("org", "4"), daemon=True)
        crossing.start()
        assert entered.wait(5)  # two crossed 4 and is storing its snapshot
        one.anchor("org", "5")
        gate.set()
        crossing.join(10)
        assert _checkpointed(one) == [4]
    finally:
        one.close()
        two.close()


# -- a ledger moved under a view -----------------------------------------------------------


def _backup(source: Path, target: Path) -> None:
    with closing(sqlite3.connect(source)) as src, closing(sqlite3.connect(target)) as dst:
        src.backup(dst)


def _moved_under(view: BudgetManager, path: Path, replacement: Path) -> None:
    """Put ``replacement`` where the view's ledger file was."""
    store: Any = view.store
    store.close()
    shutil.copyfile(replacement, path)
    for sidecar in ("-wal", "-shm"):
        Path(f"{path}{sidecar}").unlink(missing_ok=True)
    view._store = SqliteStore(path, read_only=True)


def test_a_ledger_cut_back_to_its_first_entry_is_a_rollback(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    writer = _sqlite(tmp_path)
    writer.open_root("root", money("10"))
    _backup(path, tmp_path / "first.db")
    view = BudgetManager.open_sqlite(str(path), read_only=True)
    writer.anchor("root", "2")
    writer.anchor("root", "3")
    view.refresh()
    writer.close()
    _moved_under(view, path, tmp_path / "first.db")
    with pytest.raises(LedgerRollbackError) as caught:
        view.refresh()
    assert (caught.value.verified_length, caught.value.ledger_length) == (3, 1)
    view.close()


@pytest.mark.parametrize("instead", ["an empty ledger", "a longer, other ledger"])
def test_a_ledger_replaced_by_one_that_is_not_its_prefix_is_rewritten(
    instead: str, tmp_path: Path
) -> None:
    path = tmp_path / "ledger.db"
    writer = _sqlite(tmp_path)
    writer.open_root("root", money("10"))
    writer.anchor("root", "2")
    writer.close()
    other = tmp_path / "other"
    other.mkdir()
    with _sqlite(other) as elsewhere:
        if instead != "an empty ledger":
            elsewhere.open_root("another", money("10"))
            for n in range(4):
                elsewhere.anchor("another", f"tick {n}")
    view = BudgetManager.open_sqlite(str(path), read_only=True)
    _moved_under(view, path, other / "ledger.db")
    with pytest.raises(LedgerIntegrityError, match="rewritten") as caught:
        view.refresh()
    assert not isinstance(caught.value, LedgerRollbackError)
    view.close()


# -- what an open from a checkpoint checks -------------------------------------------


def _appended(last: LedgerEntry, **fields: Any) -> LedgerEntry:
    """The entry after ``last``, valid in hash and link, whatever it says."""
    entry: dict[str, Any] = dict(
        sequence=last.sequence + 1,
        entry_id=uuid.uuid4(),
        transaction_id=uuid.uuid4(),
        timestamp=last.timestamp + timedelta(microseconds=1),
        counterparty_id=None,
        memo="",
        ref=None,
        version="AGOV3",
    )
    entry.update(fields)
    digest = _hash_entry(prev_hash=last.entry_hash, **entry)
    return LedgerEntry(prev_hash=last.entry_hash, entry_hash=digest, **entry)


def test_a_snapshot_whose_stored_digest_was_edited_is_refused(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.checkpoint()
    with closing(sqlite3.connect(tmp_path / "ledger.db")) as conn:
        conn.execute("UPDATE snapshots SET digest = ?", ("0" * 64,))
        conn.commit()
    with pytest.raises(LedgerIntegrityError, match="does not match the digest"):
        _sqlite(tmp_path)


def test_a_snapshot_filed_under_another_sequence_is_refused(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.anchor("root", "2")
        body = _encode_snapshot(gov.ledger._state)  # of sequence 2
        digest = _snapshot_digest(body)
        store: Any = gov.store
        store.put_snapshot(Snapshot(sequence=3, digest=digest, body=body))
        gov.anchor("root", "3")
        memo = f"agentgov-checkpoint v1 seq=3 sha256={digest}"
        gov.ledger._post(
            [LedgerLine(EntryType.CHECKPOINT, Direction.NONE, "", Decimal(0), memo=memo)]
        )
    with pytest.raises(LedgerIntegrityError, match="stored as sequence 3 is of sequence 2"):
        _sqlite(tmp_path)


def test_entries_that_do_not_follow_their_checkpoint_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _sqlite(tmp_path) as gov:  # a checkpoint of 2, whose entry another write preceded
        gov.open_root("root", money("1"))
        gov.anchor("root", "2")
        body = _encode_snapshot(gov.ledger._state)
        digest = _snapshot_digest(body)
        store: Any = gov.store
        store.put_snapshot(Snapshot(sequence=2, digest=digest, body=body))
        gov.anchor("root", "3")
        memo = f"agentgov-checkpoint v1 seq=2 sha256={digest}"
        gov.ledger._post(
            [LedgerLine(EntryType.CHECKPOINT, Direction.NONE, "", Decimal(0), memo=memo)]
        )
    real = SqliteStore.load

    def skipping(self: SqliteStore, **kwargs: Any) -> Any:
        image = real(self, **kwargs)
        if image.snapshot is None:
            return image
        return dataclasses.replace(image, entries=image.entries[1:])

    monkeypatch.setattr(SqliteStore, "load", skipping)
    with pytest.raises(LedgerIntegrityError, match="do not follow it"):
        _sqlite(tmp_path)


def test_legacy_rows_edited_after_a_checkpoint_are_refused(tmp_path: Path) -> None:
    from tests.test_core_guarantees import _legacy_database

    path = str(tmp_path / "ledger.db")
    _legacy_database(path)
    with BudgetManager.open_sqlite(path, policy=NEVER, auditor=False) as gov:  # sealed
        gov.checkpoint()
        gov.anchor("worker", "after the checkpoint")
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("UPDATE control_events SET reason = 'edited' WHERE entry_id IS NULL")
        conn.commit()
    with pytest.raises(LedgerIntegrityError, match="not the ones the checkpoint folded in"):
        BudgetManager.open_sqlite(path, auditor=False)


def test_a_transfer_after_a_checkpoint_must_balance(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.delegate("root", "child", money("0.5"))
        gov.checkpoint()
        last = gov.audit_trail()[-1]
    unbalanced = _appended(
        last,
        entry_type=EntryType.RELEASE,
        direction=Direction.DEBIT,
        scope_id="child",
        counterparty_id="root",
        amount=money("0.1"),
        balance_after=money("0.4"),
    )
    store = SqliteStore(tmp_path / "ledger.db")
    store.commit(WriteBatch(entries=[unbalanced]))
    store.close()
    with pytest.raises(LedgerIntegrityError, match="does not balance"):
        _sqlite(tmp_path)


def test_a_full_replay_refuses_a_checkpoint_whose_snapshot_is_of_another_chain(
    tmp_path: Path,
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    with _sqlite(elsewhere) as other:
        other.open_root("root", money("2"))
        other.anchor("root", "2")
        body = _encode_snapshot(other.ledger._state)
    digest = _snapshot_digest(body)
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.anchor("root", "2")
        store: Any = gov.store
        store.put_snapshot(Snapshot(sequence=2, digest=digest, body=body))
        memo = f"agentgov-checkpoint v1 seq=2 sha256={digest}"
        gov.ledger._post(
            [LedgerLine(EntryType.CHECKPOINT, Direction.NONE, "", Decimal(0), memo=memo)]
        )
    trusting = CheckpointSigning(keys=[KEY.public_key()])
    with pytest.raises(LedgerIntegrityError, match="is not of the chain it is stored with"):
        _sqlite(tmp_path, verify="full", signing=trusting)


def test_a_read_only_view_of_a_ledger_an_auditor_failed_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with _sqlite(tmp_path, EVERY_FOUR) as gov:
        gov.open_root("root", money("1"))
        for n in range(8):
            gov.anchor("root", f"tick {n}")
    with closing(sqlite3.connect(tmp_path / "ledger.db")) as conn:
        conn.execute("UPDATE entries SET memo = 'rewritten' WHERE sequence = 2")
        conn.commit()
    store = SqliteStore(tmp_path / "ledger.db")
    assert not Auditor(store).run().ok
    store.close()
    with caplog.at_level(logging.WARNING):
        BudgetManager.open_sqlite(str(tmp_path / "ledger.db"), read_only=True).close()
    assert "an auditor found this ledger does not verify" in caplog.text
    with pytest.raises(LedgerIntegrityError, match="an auditor found"):
        _sqlite(tmp_path)


def test_a_governor_opened_from_a_checkpoint_counts_the_holds_open_there(tmp_path: Path) -> None:
    """Exhaustion trips a scope only once its last hold settles: the count of
    holds open in each scope comes back from the snapshot."""
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.delegate("root", "child", money("0.5"))
        first = gov.authorize("child", money("0.25"))
        second = gov.authorize("child", money("0.25"))
        gov.checkpoint()
    with _sqlite(tmp_path) as reopened:
        held = [reopened.authorization(a.authorization_id) for a in (first, second)]
        assert all(a is not None for a in held)
        reopened.capture(held[0], money("0.25"))  # type: ignore[arg-type]
        assert not reopened.is_halted("child"), "a hold is still open"
        reopened.capture(held[1], money("0.25"))  # type: ignore[arg-type]
        assert reopened.halted_by("child") == "child"


# -- a store with 0.4's interface ----------------------------------------------------------


class _StoreOf04:
    """A store with 0.4's interface and nothing more: no history, snapshots,
    units or idempotency, and load() and snapshot() as 0.4 called them."""

    def __init__(self, path: Path) -> None:
        self._inner = SqliteStore(path)

    @property
    def read_only(self) -> bool:
        return self._inner.read_only

    def commit(self, batch: WriteBatch) -> None:
        self._inner.commit(batch)

    def load(self) -> Any:
        return self._inner.load()

    def load_entries(self) -> tuple[LedgerEntry, ...]:
        return self._inner.load_entries()

    def snapshot(self, *, after_sequence: int, after_control_row: int) -> Any:
        return self._inner.snapshot(
            after_sequence=after_sequence, after_control_row=after_control_row
        )

    def rebuild_caches(self, **caches: Any) -> None:
        self._inner.rebuild_caches(**caches)

    def close(self) -> None:
        self._inner.close()


def test_a_store_with_only_04s_interface_still_keeps_a_ledger(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    gov = BudgetManager(store=_StoreOf04(path), policy=EVERY_FOUR)  # type: ignore[arg-type]
    gov.open_root("root", money("1"))
    held = gov.authorize("root", money("0.5"))
    gov.capture(held, money("0.2"))
    for n in range(5):
        gov.anchor("root", f"tick {n}")
    assert [e.memo for e in gov.find_entries(entry_type=EntryType.ANCHOR)][:1] == ["tick 0"]
    with pytest.raises(TypeError, match="holds snapshots"):
        gov.checkpoint()
    gov.close()
    reopened = BudgetManager(store=_StoreOf04(path))  # type: ignore[arg-type]
    assert reopened.available("root") == money("0.8")
    reopened.verify_integrity()
    reopened.close()


# -- callers of one governor -------------------------------------------------------------


def _until(condition: Callable[[], bool], seconds: float = 5.0) -> None:
    deadline = time.monotonic() + seconds
    while not condition():
        assert time.monotonic() < deadline, "timed out"
        time.sleep(0.002)


def test_the_caller_queued_behind_a_unit_of_work_leads_the_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gov = _sqlite(tmp_path)
    gov.open_root("root", money("10"))
    entered, release = threading.Event(), threading.Event()
    real = SqliteStore._commit_unit
    held: list[bool] = []

    def commit_once_held(self: SqliteStore) -> None:
        if not held:
            held.append(True)
            entered.set()
            assert release.wait(10)
        real(self)

    monkeypatch.setattr(SqliteStore, "_commit_unit", commit_once_held)
    first = threading.Thread(target=lambda: gov.anchor("root", "first"), daemon=True)
    first.start()
    assert entered.wait(5)  # its unit of work is committing
    second = threading.Thread(target=lambda: gov.anchor("root", "second"), daemon=True)
    second.start()
    _until(lambda: len(gov._queue) == 1)  # queued behind it
    release.set()
    first.join(10)
    second.join(10)
    assert not first.is_alive() and not second.is_alive()
    assert [e.memo for e in gov.audit_trail()[-2:]] == ["first", "second"]
    gov.close()


class _UnitSizes:
    def __init__(self) -> None:
        self.sizes: list[float] = []

    def record(self, name: str, value: float) -> None:
        if name == "agentgov.unit.size":
            self.sizes.append(value)

    def add(self, name: str, value: int = 1) -> None:
        pass

    def set(self, name: str, value: float) -> None:
        pass


def test_a_unit_of_work_carries_at_most_its_batch(tmp_path: Path) -> None:
    """Callers that queue while a unit runs ride along with it, up to 256."""
    metrics = _UnitSizes()
    gov = _sqlite(tmp_path, metrics=metrics)
    gov.open_root("root", money("10"))
    running, queued = threading.Event(), threading.Event()

    def first() -> None:  # runs inside the first unit until 300 more queue behind it
        running.set()
        assert queued.wait(10)

    leader = threading.Thread(target=lambda: gov._submit(first), daemon=True)
    leader.start()
    assert running.wait(5)
    behind = [
        threading.Thread(target=lambda: gov._submit(lambda: None), daemon=True) for _ in range(300)
    ]
    for thread in behind:
        thread.start()
    _until(lambda: len(gov._queue) == 300, seconds=30)
    queued.set()
    for thread in [leader, *behind]:
        thread.join(10)
    assert sum(metrics.sizes[1:]) == 301 and max(metrics.sizes) == 256
    gov.close()


# -- settling, and calls made under a key ------------------------------------------------


def test_a_settlement_that_overdraws_halts_its_scope_for_that(tmp_path: Path) -> None:
    """With another hold open the scope is not spent out, so the halt is the
    overdraft's, and says so."""
    gov = BudgetManager(policy=NEVER)
    gov.open_root("root", money("1"))
    held = gov.authorize("root", money("0.50"))
    gov.authorize("root", money("0.40"))
    with pytest.raises(DenialOfWalletError):
        gov.capture(held, money("0.70"))
    (trip,) = [e for e in gov.audit_trail() if e.entry_type is EntryType.CIRCUIT_TRIPPED]
    assert trip.memo.startswith("settled cost 0.70000000 overran authorization 0.50000000")


def test_a_settlement_at_no_cost_keeps_its_memo() -> None:
    gov = BudgetManager(policy=NEVER)
    gov.open_root("root", money("1"))
    lifted = gov.capture(gov.authorize("root", money("0.5")), money("0"), memo="cancelled")
    assert lifted.entry_type is EntryType.HOLD_VOID and lifted.memo == "cancelled"
    lifted = gov.capture(gov.authorize("root", money("0.5")), money("0"))
    assert lifted.memo == "captured at zero cost"


@pytest.mark.parametrize("stored", [False, True], ids=["in memory", "over sqlite"])
def test_a_call_retried_within_its_transaction_returns_what_it_returned(
    stored: bool, tmp_path: Path
) -> None:
    gov = _sqlite(tmp_path) if stored else BudgetManager(policy=NEVER)
    gov.open_root("root", money("1"))
    held = gov.authorize("root", money("0.5"))
    with gov.transaction() as txn:
        first = txn.capture(held, money("0.2"), idempotency_key="settle")
        assert txn.capture(held, money("0.2"), idempotency_key="settle") == first
    with pytest.raises(DoubleSpendError):
        gov.capture(held, money("0.2"))
    assert gov.available("root") == money("0.8")
    gov.close()


def test_a_call_recorded_before_a_restart_is_found_inside_a_transaction(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        spent = gov.spend("root", money("0.1"), idempotency_key="k")
    with _sqlite(tmp_path) as reopened:
        with reopened.transaction() as txn:
            assert txn.spend("root", money("0.1"), idempotency_key="k") == spent
        assert reopened.available("root") == money("0.9")


@pytest.mark.parametrize(
    ("outcome", "sequence"),
    [("authorization", 1), ("node", 2), ("authorization", 99)],
    ids=["a hold that is a funding", "a node that is a hold", "an entry beyond the head"],
)
def test_a_call_record_that_names_no_such_result_is_refused(
    tmp_path: Path, outcome: str, sequence: int
) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.authorize("root", money("0.1"), idempotency_key="k")
    with closing(sqlite3.connect(tmp_path / "ledger.db")) as conn:
        conn.execute(
            "UPDATE idempotency SET outcome = ?, sequence = ? WHERE key = 'k'", (outcome, sequence)
        )
        conn.commit()
    with _sqlite(tmp_path) as reopened:
        with pytest.raises(LedgerIntegrityError, match=f"names entry {sequence} as its {outcome}"):
            reopened.authorize("root", money("0.1"), idempotency_key="k")


class _Lookups:
    """Counts the store's reads of recorded calls."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.calls: list[list[str]] = []
        real = SqliteStore.idempotency

        def counted(store: SqliteStore, keys: Any) -> Any:
            self.calls.append(list(keys))
            return real(store, keys)

        monkeypatch.setattr(SqliteStore, "idempotency", counted)


def test_a_unit_of_work_reads_its_calls_records_in_one_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Callers queued behind a unit of work share the next one, and their
    keys are read together; calls without a key read nothing."""
    gov = _sqlite(tmp_path)
    gov.open_root("root", money("10"))
    lookups = _Lookups(monkeypatch)
    entered, release = threading.Event(), threading.Event()
    real = SqliteStore._commit_unit
    held: list[bool] = []

    def commit_once_held(self: SqliteStore) -> None:
        if not held:
            held.append(True)
            entered.set()
            assert release.wait(10)
        real(self)

    monkeypatch.setattr(SqliteStore, "_commit_unit", commit_once_held)
    first = threading.Thread(target=lambda: gov.anchor("root", "no key"), daemon=True)
    first.start()
    assert entered.wait(5)
    keyed = [
        threading.Thread(
            target=lambda n=n: gov.spend("root", money("0.01"), idempotency_key=f"k{n}"),
            daemon=True,
        )
        for n in range(4)
    ]
    for thread in keyed:
        thread.start()
    _until(lambda: len(gov._queue) == 4)
    release.set()
    for thread in [first, *keyed]:
        thread.join(10)
    assert [sorted(c) for c in lookups.calls] == [["k0", "k1", "k2", "k3"]]
    gov.close()


def test_a_store_that_keeps_no_calls_refuses_a_key(tmp_path: Path) -> None:
    gov = BudgetManager(store=_StoreOf04(tmp_path / "ledger.db"))  # type: ignore[arg-type]
    gov.open_root("root", money("1"))
    with pytest.raises(StorageError, match="keeps no record of calls made under a key"):
        gov.spend("root", money("0.1"), idempotency_key="k")
    gov.close()


def test_a_read_only_view_finds_a_hold_placed_since_it_last_looked(tmp_path: Path) -> None:
    writer = _sqlite(tmp_path)
    writer.open_root("root", money("1"))
    view = BudgetManager.open_sqlite(str(tmp_path / "ledger.db"), read_only=True)
    held = writer.authorize("root", money("0.5"))
    found = view.authorization(held.authorization_id)
    assert found is not None and found.amount == money("0.5")
    view.close()
    writer.close()


# -- the SQLite store's own word ------------------------------------------------------


def _entry_row_copy(entry: LedgerEntry) -> LedgerEntry:
    """Another entry at the same sequence: a write the store must refuse."""
    return dataclasses.replace(entry, entry_id=uuid.uuid4())


def test_a_unit_of_work_commits_all_of_it_or_none(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        first = gov.audit_trail()[0]
    store = SqliteStore(tmp_path / "ledger.db")
    later = _appended(
        first,
        entry_type=EntryType.ANCHOR,
        direction=Direction.NONE,
        scope_id="root",
        amount=Decimal(0),
        balance_after=money("1"),
        memo="a",
    )
    with store.unit() as unit:
        store.commit(WriteBatch(entries=[later]))
    assert unit.committed and store.head()[0] == 2
    again = _appended(
        later,
        entry_type=EntryType.ANCHOR,
        direction=Direction.NONE,
        scope_id="root",
        amount=Decimal(0),
        balance_after=money("1"),
        memo="b",
    )
    with store.unit() as unit:
        store.commit(WriteBatch(entries=[again]))
        unit.abandon()
    assert not unit.committed and store.head()[0] == 2, "abandoned: rolled back"
    with pytest.raises(StorageError, match="does not nest"), store.unit():
        with store.unit():
            pass
    with pytest.raises(StorageError, match="none of it was committed"), store.unit():
        with pytest.raises(LedgerIntegrityError, match="failed to durably append 1 entry:"):
            store.commit(WriteBatch(entries=[_entry_row_copy(later)]))
        with pytest.raises(StorageError, match="an earlier write in this transaction failed"):
            store.commit(WriteBatch(entries=[again]))
    assert store.head()[0] == 2
    store.commit(WriteBatch(entries=[again]))  # the store is not left inside a transaction
    assert store.head()[0] == 3
    store.close()
    read_only = SqliteStore(tmp_path / "ledger.db", read_only=True)
    with pytest.raises(ReadOnlyLedgerError), read_only.unit():
        pass
    read_only.close()


def test_a_failed_write_leaves_nothing_and_the_store_writable(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        first = gov.audit_trail()[0]
    store = SqliteStore(tmp_path / "ledger.db")
    fine = _appended(
        first,
        entry_type=EntryType.ANCHOR,
        direction=Direction.NONE,
        scope_id="root",
        amount=Decimal(0),
        balance_after=money("1"),
        memo="a",
    )
    with pytest.raises(LedgerIntegrityError, match="failed to durably append 2 entries"):
        store.commit(WriteBatch(entries=[fine, _entry_row_copy(fine)]))
    assert store.head() == (1, first.entry_hash), "nothing of the batch"
    store.commit(WriteBatch(entries=[fine]))
    assert store.head()[0] == 2
    store.close()


def test_a_snapshot_of_a_sequence_is_stored_once(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "ledger.db")
    snapshot = Snapshot(sequence=7, digest="a" * 64, body=b"{}")
    store.put_snapshot(snapshot)
    store.put_snapshot(snapshot)  # the same again: nothing to do
    with pytest.raises(LedgerIntegrityError, match="a different snapshot of sequence 7"):
        store.put_snapshot(dataclasses.replace(snapshot, digest="b" * 64))
    assert store.snapshot_at(7) == snapshot
    store.close()


def test_an_empty_store_answers_as_empty(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "ledger.db")
    assert store.head() == (0, GENESIS_HASH)
    assert store.idempotency([]) == {}
    assert list(store.iter_entries()) == []
    store.close()


def test_history_is_read_to_its_end_and_no_further(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        for n in range(4):
            gov.anchor("root", f"tick {n}")
        assert [e.sequence for e in gov.entries(after=2)] == [3, 4, 5]
        store: Any = gov.store
        assert [e.sequence for e in store.iter_entries()] == [1, 2, 3, 4, 5]
        assert [e.sequence for e in store.iter_entries(after=2, chunk=2)] == [3, 4, 5]
        assert list(store.iter_entries(after=5)) == []


def test_a_checkpoint_entry_whose_memo_was_edited_names_no_snapshot(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.checkpoint()
    with closing(sqlite3.connect(tmp_path / "ledger.db")) as conn:
        conn.execute("UPDATE entries SET memo = 'edited' WHERE entry_type = 'checkpoint'")
        conn.commit()
    store = SqliteStore(tmp_path / "ledger.db", read_only=True)
    assert store.checkpoints() == (), "only well-formed checkpoints"
    store.close()
    with pytest.raises(LedgerIntegrityError, match="names a snapshot this store does not hold"):
        _sqlite(tmp_path)


def test_a_control_row_whose_entry_the_chain_lacks_is_refused(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.trip("root", "halted")
    with closing(sqlite3.connect(tmp_path / "ledger.db")) as conn:
        conn.execute(
            "INSERT INTO control_events (event_id, timestamp, event_type, scope_id, reason, "
            "ledger_head_hash, entry_id) SELECT ?, timestamp, event_type, scope_id, reason, "
            "ledger_head_hash, ? FROM control_events LIMIT 1",
            (str(uuid.uuid4()), str(uuid.uuid4())),
        )
        conn.commit()
    with pytest.raises(LedgerIntegrityError):
        _sqlite(tmp_path)


def test_a_store_of_the_first_schema_answers_what_it_cannot_hold_as_empty(tmp_path: Path) -> None:
    fixture = Path(__file__).resolve().parent / "fixtures" / "upgrades" / "v0.1.0.db"
    shutil.copyfile(fixture, tmp_path / "v0.1.0.db")
    store = SqliteStore(tmp_path / "v0.1.0.db", read_only=True)
    assert store.find_entries(ref=uuid.uuid4()) == ()
    assert store.snapshot_at(1) is None
    store.close()


def test_a_probe_the_server_cancels_is_an_error_and_the_store_still_probes(pg_dsn: str) -> None:
    """A server whose statement timeout is shorter than the probe's wait
    cancels it: that is no answer, so it is an error, and the store's
    connection is left out of the aborted transaction for the next probe."""
    from psycopg.conninfo import make_conninfo

    from tests.test_lock_free_open import _hold_writer_lock

    with BudgetManager.open_postgres(pg_dsn, auditor=False) as gov:
        gov.open_root("org", money("1"))
    store = PostgresStore(make_conninfo(pg_dsn, options="-c statement_timeout=50"), read_only=True)
    holder = _hold_writer_lock(pg_dsn)
    try:
        with pytest.raises(StorageError, match="cannot probe the writer lock"):
            store.writer_lock_held(5)
    finally:
        holder.close()
    assert store.writer_lock_held(0.5) is False
    store.close()


# -- the PostgreSQL store's own word --------------------------------------------------------

_ENTRIES_REARM = (
    "ALTER TABLE agentgov.entries ENABLE ALWAYS TRIGGER append_only, "
    "ENABLE ALWAYS TRIGGER append_only_truncate, ENABLE ALWAYS TRIGGER extend_chain"
)


def _admin(dsn: str, *statements: str) -> None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True, prepare_threshold=None) as conn:
        for statement in statements:
            conn.execute(statement)


def test_a_postgres_store_keeps_its_word_as_the_sqlite_store_does(pg_dsn: str) -> None:
    import psycopg

    store = PostgresStore(pg_dsn)
    assert store.head() == (0, GENESIS_HASH)
    assert store.idempotency([]) == {}
    snapshot = Snapshot(sequence=7, digest="a" * 64, body=b"{}")
    store.put_snapshot(snapshot)
    store.put_snapshot(snapshot)
    with pytest.raises(LedgerIntegrityError, match="a different snapshot of sequence 7"):
        store.put_snapshot(dataclasses.replace(snapshot, digest="b" * 64))
    with store.writer():
        with pytest.raises(StorageError, match="outside a writer session"):
            store.put_snapshot(dataclasses.replace(snapshot, sequence=8))
        with psycopg.connect(pg_dsn, prepare_threshold=None) as conn:
            conn.execute("SELECT 1")
            with pytest.raises(StorageError, match="inside another writer session"):
                with store.join(conn):
                    pass
    with psycopg.connect(pg_dsn, prepare_threshold=None) as conn:
        conn.execute("SELECT 1")
        conn.close()
        with pytest.raises(StorageError, match=r"joins an open transaction|cannot join"):
            with store.join(conn):
                pass
    store.close()
    read_only = PostgresStore(pg_dsn, read_only=True)
    with pytest.raises(ReadOnlyLedgerError):
        read_only.put_snapshot(dataclasses.replace(snapshot, sequence=9))
    with pytest.raises(ReadOnlyLedgerError):
        read_only.record_audit(None)  # type: ignore[arg-type]
    with psycopg.connect(pg_dsn, prepare_threshold=None) as conn:
        conn.execute("SELECT 1")
        with pytest.raises(ReadOnlyLedgerError), read_only.join(conn):
            pass
    read_only.close()


def test_a_postgres_store_reads_on_a_new_connection_after_the_server_ended_one(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False) as gov:
        gov.open_root("org", money("1"))
        gov.spend("org", money("0.1"), idempotency_key="k")
    store = PostgresStore(pg_dsn, read_only=True)
    pid = store._conn.info.backend_pid
    _admin(pg_dsn, f"SELECT pg_terminate_backend({pid})")
    _until(lambda: _backend_gone(pg_dsn, pid))
    with pytest.raises(StorageError):
        store.idempotency(["k"])  # its first use finds the connection gone
    (record,) = store.idempotency(["k"]).values()  # and the next opens a new one
    assert record.key == "k" and record.outcome == "entry"
    store.close()


def _backend_gone(dsn: str, pid: int) -> bool:
    import psycopg

    with psycopg.connect(dsn, autocommit=True, prepare_threshold=None) as conn:
        row = conn.execute("SELECT count(*) FROM pg_stat_activity WHERE pid = %s", (pid,))
        return row.fetchone() == (0,)


def test_an_open_from_a_postgres_checkpoint_replays_only_what_came_after(
    pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentgov.core import _Overlay

    with BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False) as gov:
        gov.open_root("org", money("1"))
        for n in range(5):
            gov.anchor("org", f"tick {n}")
        gov.checkpoint()  # of 6; its entry is 7
        gov.trip("org", "after the checkpoint")  # the first control row, after it
    applied: list[int] = []
    real = _Overlay.apply

    def counting(self: _Overlay, entry: LedgerEntry, **kwargs: Any) -> None:
        applied.append(entry.sequence)
        real(self, entry, **kwargs)

    monkeypatch.setattr(_Overlay, "apply", counting)
    with BudgetManager.open_postgres(pg_dsn, auditor=False) as reopened:
        assert applied == [7, 8] and reopened.is_halted("org")
    applied.clear()
    with BudgetManager.open_postgres(pg_dsn, verify="full", auditor=False) as replayed:
        assert applied == list(range(1, 9)) and replayed.is_halted("org")


def test_a_full_open_of_postgres_finds_an_edit_before_the_checkpoint(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False) as gov:
        gov.open_root("org", money("1"))
        gov.anchor("org", "before")
        gov.checkpoint()
    _admin(
        pg_dsn,
        "ALTER TABLE agentgov.entries DISABLE TRIGGER USER",
        "UPDATE agentgov.entries SET memo = 'edited' WHERE sequence = 2",
        _ENTRIES_REARM,
    )
    with BudgetManager.open_postgres(pg_dsn, auditor=False, read_only=True):
        pass  # from the checkpoint: the edit is before it, the auditor's to find
    with pytest.raises(LedgerIntegrityError, match="tampered"):
        BudgetManager.open_postgres(pg_dsn, verify="full", auditor=False)


def test_a_postgres_checkpoint_that_names_no_snapshot_is_refused(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False) as gov:
        gov.open_root("org", money("1"))
        gov.checkpoint()
    _admin(
        pg_dsn,
        "ALTER TABLE agentgov.snapshots DISABLE TRIGGER USER",
        "DELETE FROM agentgov.snapshots",
        "ALTER TABLE agentgov.snapshots ENABLE ALWAYS TRIGGER snapshots_append_only, "
        "ENABLE ALWAYS TRIGGER snapshots_append_only_truncate",
    )
    with pytest.raises(LedgerIntegrityError, match="names a snapshot this store does not hold"):
        BudgetManager.open_postgres(pg_dsn, auditor=False)


def test_a_postgres_checkpoint_whose_memo_was_edited_names_no_snapshot(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False) as gov:
        gov.open_root("org", money("1"))
        gov.checkpoint()
        gov.anchor("org", "after")
        gov.checkpoint()
    _admin(
        pg_dsn,
        "ALTER TABLE agentgov.entries DISABLE TRIGGER USER",
        "UPDATE agentgov.entries SET memo = 'edited' WHERE sequence = 4",
        _ENTRIES_REARM,
    )
    store = PostgresStore(pg_dsn, read_only=True)
    assert [of for _, of, _ in store.checkpoints()] == [1], "only well-formed checkpoints"
    store.close()
    with pytest.raises(LedgerIntegrityError, match="names a snapshot this store does not hold"):
        BudgetManager.open_postgres(pg_dsn, auditor=False)


def test_a_postgres_control_row_whose_entry_the_chain_lacks_is_refused(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False) as gov:
        gov.open_root("org", money("1"))
        gov.trip("org", "halted")
    _admin(
        pg_dsn,
        "INSERT INTO agentgov.control_events (event_id, timestamp, event_type, scope_id, "
        "reason, ledger_head_hash, entry_id) SELECT gen_random_uuid(), timestamp, event_type, "
        "scope_id, reason, ledger_head_hash, gen_random_uuid() FROM agentgov.control_events "
        "LIMIT 1",
    )
    with pytest.raises(LedgerIntegrityError):
        BudgetManager.open_postgres(pg_dsn, auditor=False)


def test_a_postgres_ledger_an_auditor_failed_is_written_by_no_governor(pg_dsn: str) -> None:
    every = GovernancePolicy(max_calls_per_window=0, checkpoint_every=4)
    with BudgetManager.open_postgres(pg_dsn, policy=every, auditor=False) as gov:
        gov.open_root("org", money("1"))
        for n in range(8):
            gov.anchor("org", f"tick {n}")
    store = PostgresStore(pg_dsn)
    assert Auditor(store).run().ok
    assert [m.status for m in store.audit_marks()][:1] == ["verified"]
    store.close()
    _admin(
        pg_dsn,
        "ALTER TABLE agentgov.entries DISABLE TRIGGER USER",
        "UPDATE agentgov.entries SET memo = 'rewritten' WHERE sequence = 2",
        _ENTRIES_REARM,
    )
    store = PostgresStore(pg_dsn)
    assert not Auditor(store).run(from_genesis=True).ok
    store.close()
    with pytest.raises(LedgerIntegrityError, match="an auditor found"):
        BudgetManager.open_postgres(pg_dsn, auditor=False)


def test_a_postgres_ledger_of_the_first_layout_says_so(pg_dsn: str) -> None:
    from tests.test_upgrades import WITH_POSTGRES, _restore

    _restore(pg_dsn, WITH_POSTGRES[0])
    store = PostgresStore(pg_dsn, schema="fixture", read_only=True)
    assert store.load(from_checkpoint=True).schema_version == "pg1"
    store.close()


# -- the auditor ------------------------------------------------------------------------


def _auditable(tmp_path: Path) -> Path:
    """A ledger of 11 entries with checkpoints of 4 and 8 (their entries are 5 and 9)."""
    with _sqlite(tmp_path, EVERY_FOUR) as gov:
        gov.open_root("root", money("1"))
        for n in range(8):
            gov.anchor("root", f"tick {n}")
        assert _checkpointed(gov) == [4, 8] and len(gov.ledger) == 11
    return tmp_path / "ledger.db"


class _Delegating:
    """A store that answers as ``inner`` does, but for what is given."""

    def __init__(self, inner: Any, **overrides: Any) -> None:
        self._inner = inner
        self.__dict__.update(overrides)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _sql(path: Path, statement: str, params: tuple[object, ...] = ()) -> None:
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(statement, params)
        conn.commit()


def test_an_audit_counts_what_it_replayed_and_marks_where_it_stopped(tmp_path: Path) -> None:
    path = _auditable(tmp_path)
    store = SqliteStore(path)
    first = Auditor(store).run()
    assert (first.resumed_from, first.verified_to, first.entries, first.checkpoints) == (
        0,
        11,
        11,
        2,
    )
    marks = store.audit_marks()
    assert [(m.sequence, m.status) for m in marks] == [
        (4, "verified"),
        (8, "verified"),
        (11, "verified"),
    ]
    assert marks[-1].detail == "replayed 11 entries from 0"
    second = Auditor(store).run()
    assert (second.resumed_from, second.entries, second.checkpoints) == (8, 3, 0)
    store.close()
    empty = SqliteStore(tmp_path / "empty.db")
    assert Auditor(empty).run().entries == 0
    assert len(empty.audit_marks()) == 0, "nothing replayed, nothing to mark"
    empty.close()


def test_an_audit_names_the_entry_it_failed_at(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = _auditable(tmp_path)
    _sql(path, "UPDATE entries SET memo = 'rewritten' WHERE sequence = 3")
    store = SqliteStore(path)
    with caplog.at_level(logging.ERROR, logger="agentgov.audit"):
        report = Auditor(store).run()
    assert report.failure is not None and report.failure.startswith("at sequence 3: ")
    assert report.verified_to == 2
    assert [(m.sequence, m.status) for m in store.audit_marks()] == [(3, "failed")]
    assert "audit of the ledger failed at sequence 3" in caplog.text
    store.close()


def test_an_audit_fails_when_the_chain_does_not_end_at_the_head_reported(tmp_path: Path) -> None:
    inner = SqliteStore(_auditable(tmp_path), read_only=True)
    length, head = inner.head()
    lying = _Delegating(inner, head=lambda: (length, "f" * 64))
    report = Auditor(lying, record=False).run()
    assert report.failure is not None
    assert (
        f"the chain ends at {length} ({head[:16]}), not at the head the store reported "
        f"({length}, {'f' * 16})"
    ) in report.failure
    inner.close()


def test_an_audit_checks_each_checkpoint_against_the_state_the_chain_implies(
    tmp_path: Path,
) -> None:
    forged, missing = tmp_path / "forged", tmp_path / "missing"
    forged.mkdir()
    missing.mkdir()
    with _sqlite(forged) as gov:
        gov.open_root("root", money("1"))
        gov.anchor("root", "2")
        memo = f"agentgov-checkpoint v1 seq=2 sha256={'0' * 64}"
        gov.ledger._post(
            [LedgerLine(EntryType.CHECKPOINT, Direction.NONE, "", Decimal(0), memo=memo)]
        )
    store = SqliteStore(forged / "ledger.db", read_only=True)
    report = Auditor(store, record=False).run()
    assert report.failure is not None
    pattern = r"commits to snapshot 0{16}, but the state the chain implies there is [0-9a-f]{16}$"
    assert re.search(pattern, report.failure), report.failure
    store.close()
    with _sqlite(missing) as gov:
        gov.open_root("root", money("1"))
        gov.anchor("root", "2")
        gov.checkpoint()
    _sql(missing / "ledger.db", "DELETE FROM snapshots")
    store = SqliteStore(missing / "ledger.db", read_only=True)
    report = Auditor(store, record=False).run()
    assert report.failure is not None
    assert "the snapshot stored for sequence 2 is not the state the chain implies" in report.failure
    store.close()


def test_an_audit_resumes_only_from_a_snapshot_the_chain_commits_to(tmp_path: Path) -> None:
    """It resumes from the newest checkpoint whose stored snapshot is the one
    its mark verified and the one the chain names; replaying from an older
    one, it then finds the altered snapshot."""
    path = _auditable(tmp_path)
    store = SqliteStore(path)
    assert Auditor(store).run().ok
    store.close()
    # The snapshot of 8 replaced by the one of 4: its mark no longer matches it.
    _sql(
        path,
        "UPDATE snapshots SET body = (SELECT body FROM snapshots WHERE sequence = 4) "
        "WHERE sequence = 8",
    )
    store = SqliteStore(path)
    report = Auditor(store).run()
    assert report.resumed_from == 4 and report.failure is not None
    assert "the snapshot stored for sequence 8 is not the state" in report.failure
    store.close()
    # And its mark rewritten to match: the chain's checkpoint still names another.
    with closing(sqlite3.connect(path)) as conn:
        (digest,) = conn.execute("SELECT digest FROM snapshots WHERE sequence = 4").fetchone()
        conn.execute("UPDATE snapshots SET digest = ? WHERE sequence = 8", (digest,))
        conn.execute("UPDATE audit_marks SET state_digest = ? WHERE sequence = 8", (digest,))
        conn.commit()
    store = SqliteStore(path)
    report = Auditor(store).run()
    assert report.resumed_from == 4 and report.failure is not None
    assert "the snapshot stored for sequence 8 is not the state" in report.failure
    store.close()


def test_an_audit_told_to_stop_stops_at_the_end_of_a_chunk(tmp_path: Path) -> None:
    store = SqliteStore(_auditable(tmp_path), read_only=True)
    stop = threading.Event()
    stop.set()
    called: list[str] = []
    report = Auditor(store, chunk=2, record=False).follow(stop=stop, on_failure=called.append)
    assert report.ok and report.verified_to == 2
    assert called == [], "a stop is no failure"
    store.close()


@pytest.mark.parametrize(("duty", "sleeps"), [(0.25, [3.0, 3.0]), (1.0, [])])
def test_an_audit_at_a_share_of_a_core_rests_in_proportion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, duty: float, sleeps: list[float]
) -> None:
    """Every chunk of entries, the auditor rests so it works ``duty`` of the
    time: at a quarter, three times as long as the chunk took."""
    import agentgov.audit as audit_module

    store = SqliteStore(_auditable(tmp_path), read_only=True)
    ticks = itertools.count()
    slept: list[float] = []
    clock = SimpleNamespace(monotonic=lambda: float(next(ticks)), sleep=slept.append)
    monkeypatch.setattr(audit_module, "time", clock)
    Auditor(store, chunk=4, duty=duty, record=False).run()
    assert slept == sleeps
    store.close()


def test_an_audit_that_cannot_record_its_marks_says_so(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    inner = SqliteStore(_auditable(tmp_path))

    def refused(mark: object) -> None:
        raise StorageError("the disk is full")

    with caplog.at_level(logging.WARNING, logger="agentgov.audit"):
        assert Auditor(_Delegating(inner, record_audit=refused)).run().ok
    logged = [r for r in caplog.records if "could not record an audit mark" in r.getMessage()]
    assert logged and all(_traced(r) for r in logged)
    inner.close()


def test_an_auditor_thread_that_cannot_audit_says_so_and_closes_its_store(
    caplog: pytest.LogCaptureFixture,
) -> None:
    closed: list[bool] = []

    class Unreachable:
        def head(self) -> tuple[int, str]:
            raise RuntimeError("the database is unreachable")

        def close(self) -> None:
            closed.append(True)
            raise OSError("already gone")

    with caplog.at_level(logging.DEBUG, logger="agentgov.audit"):
        thread = AuditorThread(Unreachable(), interval=0.01)
        thread.stop()
    assert closed == [True] and not thread.alive
    (stopped,) = [r for r in caplog.records if "the in-process auditor stopped" in r.getMessage()]
    (closing_,) = [
        r for r in caplog.records if "closing the auditor's store failed" in r.getMessage()
    ]
    assert _traced(stopped) and _traced(closing_)


def test_an_audit_balances_each_transaction_up_to_a_checkpoint(tmp_path: Path) -> None:
    """A transfer forged just before a checkpoint, with the checkpoint forged
    to match: the transaction it ends must still balance."""
    from agentgov.core import _ChainState, _Overlay

    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.delegate("root", "child", money("0.5"))
        last = gov.audit_trail()[-1]
    unbalanced = _appended(
        last,
        entry_type=EntryType.RELEASE,
        direction=Direction.DEBIT,
        scope_id="child",
        counterparty_id="root",
        amount=money("0.1"),
        balance_after=money("0.4"),
    )
    store = SqliteStore(tmp_path / "ledger.db")
    store.commit(WriteBatch(entries=[unbalanced]))
    state = _ChainState()
    view = _Overlay(state)
    for entry in store.iter_entries():
        view.apply(entry)
    view.merge()  # as the chain implies it, unbalanced and all
    body = _encode_snapshot(state)
    digest = _snapshot_digest(body)
    store.put_snapshot(Snapshot(sequence=unbalanced.sequence, digest=digest, body=body))
    marker = _appended(
        unbalanced,
        entry_type=EntryType.CHECKPOINT,
        direction=Direction.NONE,
        scope_id="",
        amount=Decimal(0),
        balance_after=Decimal(0),
        memo=f"agentgov-checkpoint v1 seq={unbalanced.sequence} sha256={digest}",
    )
    store.commit(WriteBatch(entries=[marker]))
    report = Auditor(store, record=False).run()
    assert report.failure is not None and "does not balance" in report.failure
    store.close()


def test_a_sqlite_url_names_a_path_and_a_scheme_a_kind() -> None:
    from agentgov.opening import parse_url

    with pytest.raises(ValueError, match="needs a path"):
        parse_url("sqlite:")
    with pytest.raises(ValueError, match="names no kind of ledger"):
        parse_url("pg://host/ledger")
    assert parse_url("//server/ledger.db") == ("sqlite", "//server/ledger.db", {})
    assert parse_url("C://ledgers/a.db") == ("sqlite", "C://ledgers/a.db", {})
    _, dsn, options = parse_url("postgresql://h/db?prepare_threshold=&application_name=")
    assert options == {"prepare_threshold": None} and "application_name=" in dsn


def test_a_refund_of_no_spend_this_ledger_holds_is_refused(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.spend("root", money("0.5"))
        with pytest.raises(ValueError, match="is not a spend this ledger holds"):
            gov.refund("root", money("0.1"), reverses=uuid.uuid4())


# -- a PostgreSQL store's sessions, and its 0.4 interface -------------------------------------


def test_a_session_the_server_cancels_is_an_error_and_the_next_one_begins(pg_dsn: str) -> None:
    """A statement timeout shorter than the wait for the writer lock cancels
    the message that begins a session: no session, an error, and the store's
    connection out of the aborted transaction for the next one."""
    from psycopg.conninfo import make_conninfo

    from tests.test_lock_free_open import _hold_writer_lock

    with BudgetManager.open_postgres(pg_dsn, auditor=False) as gov:
        gov.open_root("org", money("1"))
    store = PostgresStore(make_conninfo(pg_dsn, options="-c statement_timeout=50"))
    holder = _hold_writer_lock(pg_dsn)
    try:
        with pytest.raises(StorageError, match="cannot open a ledger transaction"):
            with store.writer():
                pass
    finally:
        holder.close()
    with store.writer() as session:
        pass
    assert session.committed
    store.close()


def test_a_session_whose_lock_is_not_granted_says_how_long_it_waited(pg_dsn: str) -> None:
    from tests.test_lock_free_open import _hold_writer_lock

    with BudgetManager.open_postgres(pg_dsn, auditor=False) as gov:
        gov.open_root("org", money("1"))
    store = PostgresStore(pg_dsn, lock_timeout=0.2)
    holder = _hold_writer_lock(pg_dsn)
    try:
        with pytest.raises(StorageError, match=r"timed out after 0\.2s waiting for the writer"):
            with store.writer():
                pass
    finally:
        holder.close()
    store.close()


def test_a_session_whose_read_fails_leaves_the_store_able_to_begin_again(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, auditor=False) as gov:
        gov.open_root("org", money("1"))
    store = PostgresStore(pg_dsn)
    _admin(pg_dsn, "ALTER TABLE agentgov.control_events RENAME TO control_events_away")
    try:
        with pytest.raises(StorageError, match="cannot open a ledger transaction"):
            with store.writer(after_sequence=1, after_control_row=0):
                pass
    finally:
        _admin(pg_dsn, "ALTER TABLE agentgov.control_events_away RENAME TO control_events")
    with store.writer(after_sequence=1, after_control_row=0) as session:
        pass
    assert session.committed
    store.close()


def test_a_session_whose_connection_ends_before_its_commit_did_not_commit(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, auditor=False) as gov:
        gov.open_root("org", money("1"))
    store = PostgresStore(pg_dsn)
    with pytest.raises(StorageError, match="did not commit, or its outcome was lost"):
        with store.writer() as session:
            pid = store._conn.info.backend_pid
            _admin(pg_dsn, f"SELECT pg_terminate_backend({pid})")
            _until(lambda: _backend_gone(pg_dsn, pid))
    assert not session.committed
    store.close()


class _SharedStoreOf04:
    """A shared store with 0.4's interface and nothing more."""

    def __init__(self, dsn: str) -> None:
        self._inner = PostgresStore(dsn)

    @property
    def read_only(self) -> bool:
        return self._inner.read_only

    def commit(self, batch: WriteBatch) -> None:
        self._inner.commit(batch)

    def load(self) -> Any:
        return self._inner.load()

    def load_entries(self) -> tuple[LedgerEntry, ...]:
        return self._inner.load_entries()

    def snapshot(self, *, after_sequence: int, after_control_row: int) -> Any:
        return self._inner.snapshot(
            after_sequence=after_sequence, after_control_row=after_control_row
        )

    def rebuild_caches(self, **caches: Any) -> None:
        self._inner.rebuild_caches(**caches)

    def writer(self) -> Any:
        return self._inner.writer()

    def head(self) -> tuple[int, str]:
        return self._inner.head()

    def close(self) -> None:
        self._inner.close()


def test_governors_share_a_ledger_through_a_store_with_only_04s_interface(pg_dsn: str) -> None:
    one = BudgetManager(store=_SharedStoreOf04(pg_dsn), policy=NEVER)  # type: ignore[arg-type]
    two = BudgetManager(store=_SharedStoreOf04(pg_dsn), policy=NEVER)  # type: ignore[arg-type]
    try:
        one.open_root("org", money("1"))
        two.spend("org", money("0.1"))  # catching up with one's funding first
        one.spend("org", money("0.2"))  # and one with two's spend
        one.anchor("org", "nothing new since its own write")
        assert one.available("org") == two.available("org", fresh=True) == money("0.7")
        one.verify_integrity()
        two.verify_integrity()
    finally:
        one.close()
        two.close()


def test_a_ledger_rewritten_at_the_same_length_is_rewritten_not_current(pg_dsn: str) -> None:
    writer = BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False)
    follower = BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False)
    try:
        writer.open_root("org", money("1"))
        writer.anchor("org", "2")
        follower.anchor("org", "3")  # catches up with the writer's entries
        follower.anchor("org", "4")  # finds itself current: no longer contended
        assert not follower._contended
        _admin(
            pg_dsn,
            "ALTER TABLE agentgov.entries DISABLE TRIGGER USER",
            "UPDATE agentgov.entries SET entry_hash = repeat('e', 64) WHERE sequence = 4",
            _ENTRIES_REARM,
        )
        with pytest.raises(LedgerIntegrityError, match="rewritten"):
            follower.anchor("org", "5")
    finally:
        writer.close()
        follower.close()


class _RecordingWitness:
    """A witness that cosigns whatever it is asked, keeping the proofs."""

    witness_id = "recorder"

    def __init__(self) -> None:
        self.proofs: list[list[bytes]] = []
        self.seen: Any = None

    def latest(self, log_id: str) -> Any:
        return self.seen

    def cosign(self, checkpoint: Any, proof: Any) -> None:
        self.proofs.append(list(proof))
        self.seen = checkpoint


def test_a_witness_is_given_a_proof_from_the_size_it_cosigned(tmp_path: Path) -> None:
    """RFC 9162 consistency, from the size of the witness's latest
    cosignature: none at all for a witness that has cosigned nothing."""
    witness = _RecordingWitness()
    with _sqlite(tmp_path, signing=CheckpointSigning(signer=KEY)) as gov:
        gov.open_root("root", money("1"))
        gov.anchor("root", "2")
        gov.checkpoint()
        assert gov.publish_checkpoint([witness]).tree_size == 2
        gov.anchor("root", "4")
        gov.checkpoint()
        assert gov.publish_checkpoint([witness]).tree_size == 4
        gov.publish_checkpoint([witness])  # the same size again: nothing between
    assert witness.proofs[0] == [] and len(witness.proofs[1]) > 0 and witness.proofs[2] == []


class _BeginRefused:
    """A connection on which another process holds the write lock too long."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def execute(self, statement: str, *args: Any) -> Any:
        if statement == "BEGIN IMMEDIATE":
            raise sqlite3.OperationalError("database is locked")
        return self._conn.execute(statement, *args)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


def test_a_sqlite_unit_that_cannot_begin_is_an_error_and_leaves_no_unit(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "ledger.db")
    real = store._conn
    store._conn = _BeginRefused(real)  # type: ignore[assignment]
    with pytest.raises(StorageError, match="cannot begin a ledger transaction: database is locked"):
        with store.unit():
            pass
    store._conn = real
    with store.unit() as unit:
        pass
    assert unit.committed
    store.close()


def test_a_sqlite_store_that_cannot_read_its_calls_says_so(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "ledger.db")
    _sql(tmp_path / "ledger.db", "DROP TABLE idempotency")
    with pytest.raises(StorageError, match="cannot read the calls recorded under keys"):
        store.idempotency(["k"])
    store.close()


def test_an_audit_balances_the_last_transaction_too(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        gov.delegate("root", "child", money("0.5"))
        last = gov.audit_trail()[-1]
    unbalanced = _appended(
        last,
        entry_type=EntryType.RELEASE,
        direction=Direction.DEBIT,
        scope_id="child",
        counterparty_id="root",
        amount=money("0.1"),
        balance_after=money("0.4"),
    )
    store = SqliteStore(tmp_path / "ledger.db")
    store.commit(WriteBatch(entries=[unbalanced]))
    report = Auditor(store, record=False).run()
    assert report.failure is not None and "does not balance" in report.failure
    store.close()


def test_a_refund_past_its_spend_is_refused_by_the_rules_over_a_store_too(tmp_path: Path) -> None:
    """The rules count the refunds a store holds of a spend, not only those
    its own unit of work stages: a raw refund gets no further than refund()."""
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        spend = gov.spend("root", money("0.20"))
        gov.spend("root", money("0.20"))
        gov.refund("root", money("0.15"), reverses=spend)
        over = LedgerLine(
            EntryType.REVERSAL, Direction.CREDIT, "root", money("0.10"), ref=spend.entry_id
        )
        with pytest.raises(LedgerIntegrityError, match=r"bringing its refunds to 0\.25000000"):
            gov.ledger._post([over])


def test_a_commit_the_server_cancels_leaves_the_store_able_to_begin_again(pg_dsn: str) -> None:
    with BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False) as gov:
        gov.open_root("org", money("1"))
        last = gov.audit_trail()[-1]
    many: list[LedgerEntry] = []
    for n in range(500):
        many.append(
            _appended(
                many[-1] if many else last,
                entry_type=EntryType.ANCHOR,
                direction=Direction.NONE,
                scope_id="org",
                amount=Decimal(0),
                balance_after=money("1"),
                memo=f"tick {n}",
            )
        )
    store = PostgresStore(pg_dsn)
    with pytest.raises(StorageError, match="did not commit"):
        with store.writer():
            store._conn.execute("SET statement_timeout = 1")  # undone with the transaction
            store.commit(WriteBatch(entries=many))
    with store.writer() as session:
        pass
    assert session.committed and store.head()[0] == 1
    store.close()


def test_a_join_whose_wait_the_server_cancels_is_an_error(pg_dsn: str) -> None:
    import psycopg

    from tests.test_lock_free_open import _hold_writer_lock

    with BudgetManager.open_postgres(pg_dsn, auditor=False) as gov:
        gov.open_root("org", money("1"))
    store = PostgresStore(pg_dsn)
    holder = _hold_writer_lock(pg_dsn)
    try:
        with psycopg.connect(pg_dsn, prepare_threshold=None) as conn:
            conn.execute("SET LOCAL statement_timeout = 50")
            with pytest.raises(StorageError, match="cannot join the transaction"):
                with store.join(conn):
                    pass
    finally:
        holder.close()
    store.close()


def test_a_governor_given_a_ledger_serves_that_ledger(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "ledger.db")
    ledger = Ledger(store=store)
    gov = BudgetManager(ledger=ledger, store=store, policy=NEVER)
    assert gov.ledger is ledger
    gov.open_root("root", money("1"))
    assert len(ledger) == 1
    gov.close()


def test_a_ledger_read_before_a_shared_store_moved_on_is_brought_up_to_it(pg_dsn: str) -> None:
    """A ledger read from a shared store before other governors wrote is
    behind the snapshot the constructor reads: the governor serves the
    snapshot, which the store's caches match."""
    store = PostgresStore(pg_dsn)
    ledger = Ledger(store=store)
    assert len(ledger) == 0
    with BudgetManager.open_postgres(pg_dsn, policy=NEVER, auditor=False) as other:
        other.open_root("org", money("1"))
        other.trip("org", "halted meanwhile")
    gov = BudgetManager(ledger=ledger, store=store, policy=NEVER)
    assert len(gov.ledger) == 2 and gov.is_halted("org")
    gov.verify_integrity()
    gov.close()


def test_a_ledger_opened_a_checkpoints_worth_past_its_last_is_checkpointed_at_once(
    tmp_path: Path,
) -> None:
    """Written without checkpoints (or by a governor that died owing one), it
    is checkpointed after the first write, not at the next multiple."""
    with _sqlite(tmp_path) as gov:  # checkpoint_every=0: none written
        gov.open_root("root", money("1"))
        for n in range(9):
            gov.anchor("root", f"tick {n}")
    with _sqlite(tmp_path, EVERY_FOUR) as reopened:
        assert _checkpointed(reopened) == []
        reopened.anchor("root", "the first write")
        assert _checkpointed(reopened) == [11]


def test_a_ledger_reopened_just_after_a_checkpoint_owes_none(tmp_path: Path) -> None:
    with _sqlite(tmp_path, EVERY_FOUR) as gov:
        gov.open_root("root", money("1"))
        for n in range(3):
            gov.anchor("root", f"tick {n}")
        assert _checkpointed(gov) == [4]
    with _sqlite(tmp_path, EVERY_FOUR) as reopened:
        reopened.anchor("root", "6")
        assert _checkpointed(reopened) == [4], "two entries since the checkpoint"


def test_a_ledger_of_exactly_a_checkpoints_worth_owes_one(tmp_path: Path) -> None:
    with _sqlite(tmp_path) as gov:
        gov.open_root("root", money("1"))
        for n in range(3):
            gov.anchor("root", f"tick {n}")  # 4 entries, no checkpoint
    with _sqlite(tmp_path, EVERY_FOUR) as reopened:
        reopened.anchor("root", "5")
        assert _checkpointed(reopened) == [5]


class _Recorded:
    def __init__(self) -> None:
        self.values: dict[str, list[float]] = {}

    def record(self, name: str, value: float) -> None:
        self.values.setdefault(name, []).append(value)

    def add(self, name: str, value: int = 1) -> None:
        pass

    def set(self, name: str, value: float) -> None:
        pass


def test_an_open_reports_how_long_it_took(tmp_path: Path) -> None:
    metrics = _Recorded()
    with _sqlite(tmp_path, metrics=metrics) as gov:
        gov.open_root("root", money("1"))
    (took,) = metrics.values["agentgov.open.duration"]
    assert 0 <= took < 60


def _halted_twice(tmp_path: Path) -> Path:
    with _sqlite(tmp_path) as gov:
        gov.open_root("one", money("1"))
        gov.open_root("two", money("1"))
        gov.trip("one", "halted")
        gov.trip("two", "halted")
    return tmp_path / "ledger.db"


def test_a_cache_that_disagrees_with_the_chain_is_named_and_counted(tmp_path: Path) -> None:
    path = _halted_twice(tmp_path)
    _sql(path, "DELETE FROM control_events WHERE scope_id = 'one'")
    with pytest.raises(LedgerIntegrityError) as one:
        _sqlite(tmp_path)
    assert "missing from the control_events table" in str(one.value)
    assert "more)" not in str(one.value)
    _sql(path, "DELETE FROM control_events")
    with pytest.raises(LedgerIntegrityError, match=r"\(and 1 more\)"):
        _sqlite(tmp_path)


def test_a_repair_is_made_only_where_it_can_be_written_and_is_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = _halted_twice(tmp_path)
    _sql(path, "DELETE FROM control_events")
    with pytest.raises(LedgerIntegrityError, match="a read-only store cannot be repaired") as read:
        BudgetManager.open_sqlite(str(path), read_only=True, repair=True)
    assert "'one'" in str(read.value) and "(and 1 more)" in str(read.value), "the first named"
    with caplog.at_level(logging.WARNING, logger="agentgov.audit"):
        with _sqlite(tmp_path, repair=True) as repaired:
            assert repaired.is_halted("one") and repaired.is_halted("two")
    logged = [r.getMessage() for r in caplog.records if "|repair|" in r.getMessage()]
    assert len(logged) == 2
    with _sqlite(tmp_path) as reopened:  # repaired for good
        assert reopened.is_halted("one")
