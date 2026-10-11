"""One rule engine for writes, catch-up and replay (F4, F5).

Whatever a write commits, a replay accepts: the money rules (links, balances,
hold pairing, balanced transfers) and the governance rules (who may be
funded, delegated to, released between, halted) are one engine,
:class:`agentgov.core._Overlay`, and the cache rows a write makes are the
ones its entries imply.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from agentgov import BudgetManager, money
from agentgov.core import (
    GENESIS_HASH,
    BudgetNode,
    Direction,
    EntryType,
    LedgerEntry,
    LedgerLine,
    WriteBatch,
    _hash_entry,
    _Overlay,
    _replay,
)
from agentgov.exceptions import LedgerIntegrityError
from agentgov.storage import SqliteStore

ROOT_FUNDING = LedgerLine(EntryType.FUNDING, Direction.CREDIT, "root", money("1"))


def _tree(path: Path | None = None) -> BudgetManager:
    gov = BudgetManager.open_sqlite(str(path)) if path is not None else BudgetManager()
    gov.open_root("root", money("1"))
    gov.delegate("root", "child", money("0.5"))
    return gov


REFUSED = {
    "funding a child": (
        [LedgerLine(EntryType.FUNDING, Direction.CREDIT, "child", money("1000"))],
        "funds a scope that is not a root",
    ),
    "delegating to an existing scope": (
        [
            LedgerLine(EntryType.ALLOCATION, Direction.DEBIT, "root", money("0.1"), "child"),
            LedgerLine(EntryType.ALLOCATION, Direction.CREDIT, "child", money("0.1"), "root"),
        ],
        "a second time",
    ),
    "delegating from a scope that does not exist": (
        [
            LedgerLine(EntryType.ALLOCATION, Direction.DEBIT, "root", money("0.1"), "ghost"),
            LedgerLine(EntryType.ALLOCATION, Direction.CREDIT, "new", money("0.1"), "ghost"),
        ],
        "never created",
    ),
    "releasing between strangers": (
        [
            LedgerLine(EntryType.RELEASE, Direction.DEBIT, "root", money("0.1"), "child"),
            LedgerLine(EntryType.RELEASE, Direction.CREDIT, "child", money("0.1"), "root"),
        ],
        "not child and parent",
    ),
    "holding on a scope that does not exist": (
        [LedgerLine(EntryType.HOLD, Direction.DEBIT, "ghost", money("0.1"))],
        "never created",
    ),
    "tripping a scope that does not exist": (
        [LedgerLine(EntryType.CIRCUIT_TRIPPED, Direction.NONE, "ghost", Decimal(0), memo="x")],
        "unregistered scope",
    ),
    "refunding more than was spent": (
        [LedgerLine(EntryType.REVERSAL, Direction.CREDIT, "child", money("0.01"))],
        "more than the 0 it ever spent",
    ),
}


@pytest.mark.parametrize(("lines", "message"), REFUSED.values(), ids=REFUSED.keys())
def test_a_raw_write_the_rules_refuse_is_refused_before_it_is_durable(
    lines: list[LedgerLine], message: str, tmp_path: Path
) -> None:
    db = tmp_path / "ledger.db"
    gov = _tree(db)
    before = (len(gov.ledger), gov.ledger.head_hash, gov.ledger.balances())
    with pytest.raises(LedgerIntegrityError, match=message):
        gov.ledger._post(lines)
    assert (len(gov.ledger), gov.ledger.head_hash, gov.ledger.balances()) == before
    gov.verify_integrity()
    gov.close()
    with BudgetManager.open_sqlite(str(db)) as reopened:
        reopened.verify_integrity()
        assert len(reopened.ledger) == before[0]


def test_a_raw_write_the_rules_allow_keeps_every_cache_in_step(tmp_path: Path) -> None:
    """Cache rows come from the engine, so even the raw path writes them."""
    db = tmp_path / "ledger.db"
    gov = _tree(db)
    gov.ledger._post([LedgerLine(EntryType.FUNDING, Direction.CREDIT, "second", money("2"))])
    (hold,) = gov.ledger._post([LedgerLine(EntryType.HOLD, Direction.DEBIT, "second", money("1"))])
    gov.ledger._post(
        [LedgerLine(EntryType.CIRCUIT_TRIPPED, Direction.NONE, "child", Decimal(0), memo="x")]
    )
    gov.close()
    with BudgetManager.open_sqlite(str(db)) as reopened:  # no repair needed
        assert reopened.node("second").allocated == money("2")
        assert [a.entry.entry_id for a in reopened.stale_authorizations(0)] == [hold.entry_id]
        assert reopened.is_halted("child")
    conn = sqlite3.connect(db)
    try:
        assert conn.execute("SELECT count(*) FROM open_authorizations").fetchone() == (1,)
        assert conn.execute("SELECT count(*) FROM control_events").fetchone() == (1,)
    finally:
        conn.close()


def _forged(lines: list[tuple[EntryType, Direction, str, str, str | None]]) -> list[LedgerEntry]:
    """Entries with valid hashes and links, one transaction for all of them."""
    entries: list[LedgerEntry] = []
    head, balances = GENESIS_HASH, dict[str, Decimal]()
    txn, now = uuid.uuid4(), datetime.now(UTC)
    for sequence, (kind, direction, scope, amount, counterparty) in enumerate(lines, start=1):
        value = money(amount)
        signed = value if direction is Direction.CREDIT else -value
        balances[scope] = balances.get(scope, Decimal(0)) + signed
        fields = dict(
            sequence=sequence,
            entry_id=uuid.uuid4(),
            transaction_id=txn if kind is not EntryType.FUNDING else uuid.uuid4(),
            timestamp=now,
            entry_type=kind,
            direction=direction,
            scope_id=scope,
            counterparty_id=counterparty,
            amount=value,
            balance_after=balances[scope],
            memo="",
            ref=None,
            version="AGOV2",
        )
        digest = _hash_entry(prev_hash=head, **fields)  # type: ignore[arg-type]
        entries.append(LedgerEntry(prev_hash=head, entry_hash=digest, **fields))  # type: ignore[arg-type]
        head = digest
    return entries


def test_a_replay_refuses_a_transfer_that_does_not_balance() -> None:
    """A forged delegation credit with no matching debit mints money."""
    forged = _forged(
        [
            (EntryType.FUNDING, Direction.CREDIT, "root", "1", None),
            (EntryType.ALLOCATION, Direction.DEBIT, "root", "0.10", "child"),
            (EntryType.ALLOCATION, Direction.CREDIT, "child", "0.50", "root"),
        ]
    )
    with pytest.raises(LedgerIntegrityError, match="does not balance"):
        _replay(forged)
    _replay(
        _forged(
            [
                (EntryType.FUNDING, Direction.CREDIT, "root", "1", None),
                (EntryType.ALLOCATION, Direction.DEBIT, "root", "0.10", "child"),
                (EntryType.ALLOCATION, Direction.CREDIT, "child", "0.10", "root"),
            ]
        )
    )


# -- the refund bound (F5) ---------------------------------------------------


def test_a_scope_can_be_refunded_up_to_what_it_spent_and_no_more() -> None:
    gov = _tree()
    gov.spend("child", money("0.20"))
    gov.refund("child", money("0.15"))
    gov.refund("child", money("0.05"))
    with pytest.raises(ValueError, match="at most 0E-8 remains refundable"):
        gov.refund("child", money("0.00000001"))
    assert gov.available("child") == money("0.5")
    gov.verify_integrity()


def test_a_refund_is_bounded_by_the_scope_that_spent() -> None:
    """A parent is refunded for its own spend, never for a child's."""
    gov = _tree()
    gov.spend("child", money("0.20"))
    with pytest.raises(ValueError, match="cannot refund"):
        gov.refund("root", money("0.01"))


def test_available_never_exceeds_what_a_scope_was_granted() -> None:
    gov = _tree()
    for _ in range(5):
        gov.spend("child", money("0.05"))
        gov.refund("child", money("0.05"))
    assert gov.available("child") <= gov.node("child").allocated


def test_history_written_before_the_bound_still_opens(tmp_path: Path) -> None:
    """A refund 0.4.0 accepted without a spend is history, not a defect."""
    db = tmp_path / "old.db"
    now = datetime.now(UTC)
    funding = dict(
        sequence=1,
        entry_id=uuid.uuid4(),
        transaction_id=uuid.uuid4(),
        timestamp=now,
        entry_type=EntryType.FUNDING,
        direction=Direction.CREDIT,
        scope_id="root",
        counterparty_id=None,
        amount=money("1"),
        balance_after=money("1"),
        memo="root envelope issued",
        ref=None,
        version="AGOV2",
    )
    first_hash = _hash_entry(prev_hash=GENESIS_HASH, **funding)  # type: ignore[arg-type]
    first = LedgerEntry(prev_hash=GENESIS_HASH, entry_hash=first_hash, **funding)  # type: ignore[arg-type]
    # What 0.4.0's refund() wrote: an unbounded REVERSAL, valid in every other way.
    reversal = dict(
        funding,
        sequence=2,
        entry_id=uuid.uuid4(),
        transaction_id=uuid.uuid4(),
        entry_type=EntryType.REVERSAL,
        amount=money("1000"),
        balance_after=money("1001"),
        memo="vendor refund",
    )
    second_hash = _hash_entry(prev_hash=first_hash, **reversal)  # type: ignore[arg-type]
    second = LedgerEntry(prev_hash=first_hash, entry_hash=second_hash, **reversal)  # type: ignore[arg-type]
    store = SqliteStore(db)
    store.commit(
        WriteBatch(
            entries=[first, second],
            nodes=[BudgetNode("root", None, 0, money("1"), created_at=now)],
        )
    )
    store.close()
    with BudgetManager.open_sqlite(str(db)) as reopened:
        reopened.verify_integrity()
        assert reopened.available("root") == money("1001")
        with pytest.raises(ValueError, match="cannot refund"):
            reopened.refund("root", money("0.01"))  # new writes are bounded


def _batch() -> WriteBatch:
    return WriteBatch()


# -- views stacked on views -------------------------------------------------


def test_a_view_on_a_view_merges_into_it_or_is_dropped_without_a_trace() -> None:
    gov = _tree()
    state = gov.ledger._state
    batch = _Overlay(state)
    pending = gov.ledger._begin()
    pending._view = _Overlay(batch)
    pending.post([LedgerLine(EntryType.HOLD, Direction.DEBIT, "child", money("0.1"))])
    pending.view.merge()  # into the batch, not the state
    assert batch.balance("child") == money("0.4")
    assert state.balance("child") == money("0.5")
    assert batch.holds_open_in("child") == 1

    dropped = gov.ledger._begin()
    dropped._view = _Overlay(batch)
    dropped.post([LedgerLine(EntryType.HOLD, Direction.DEBIT, "child", money("0.2"))])
    assert dropped.view.holds_open_in("child") == 2
    del dropped  # never merged: the batch is as it was
    assert batch.holds_open_in("child") == 1
    assert batch.balance("child") == money("0.4")
    assert batch.length == state.length + 1


# -- exhaustion counts holds per scope --------------------------------------


def test_exhaustion_waits_for_the_last_hold_on_the_scope() -> None:
    gov = _tree()
    first = gov.authorize("child", money("0.25"))
    second = gov.authorize("child", money("0.25"))
    gov.capture(first, money("0.25"))
    assert not gov.is_halted("child"), "a hold is still open"
    gov.capture(second, money("0.25"))
    assert gov.halted_by("child") == "child"
    assert gov.ledger._state.holds_open_in("child") == 0
