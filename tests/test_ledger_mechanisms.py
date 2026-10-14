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
import logging
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
from typing import Any

import pytest

from agentgov import BudgetManager, CheckpointSigning, GovernancePolicy, money
from agentgov.audit import Auditor
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
    assert failed.exc_info is not None and "the next try is in 1 s" in failed.getMessage()
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
    assert "'root'" in logged.getMessage() and logged.exc_info is not None


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


@pytest.mark.parametrize("stored", [False, True], ids=["in memory", "over sqlite"])
def test_history_is_answered_alike_from_memory_and_from_a_store(
    stored: bool, tmp_path: Path
) -> None:
    gov = _sqlite(tmp_path) if stored else BudgetManager(policy=NEVER)
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
    gov.close()


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
    assert logged.exc_info is not None and gov._dirty
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


def test_a_call_retried_within_its_transaction_returns_what_it_returned() -> None:
    gov = BudgetManager(policy=NEVER)
    gov.open_root("root", money("1"))
    held = gov.authorize("root", money("0.5"))
    with gov.transaction() as txn:
        first = txn.capture(held, money("0.2"), idempotency_key="settle")
        assert txn.capture(held, money("0.2"), idempotency_key="settle") == first
    with pytest.raises(DoubleSpendError):
        gov.capture(held, money("0.2"))
    assert gov.available("root") == money("0.8")


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
