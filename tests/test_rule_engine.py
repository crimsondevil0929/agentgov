"""One rule engine for writes, catch-up and replay (F4, F5).

Whatever a write commits, a replay accepts: the money rules (links, balances,
hold pairing, balanced transfers) and the governance rules (who may be
funded, delegated to, released between, halted) are one engine,
:class:`agentgov.core._Overlay`, and the cache rows a write makes are the
ones its entries imply.
"""

from __future__ import annotations

import dataclasses
import sqlite3
import uuid
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta, tzinfo
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
    "a transfer that does not balance": (
        [
            LedgerLine(EntryType.RELEASE, Direction.DEBIT, "child", money("0.1"), "root"),
            LedgerLine(EntryType.RELEASE, Direction.CREDIT, "root", money("0.2"), "child"),
        ],
        "does not balance",
    ),
    "debiting a delegation from a scope that does not exist": (
        [
            LedgerLine(EntryType.ALLOCATION, Direction.DEBIT, "ghost", money("0.1"), "new"),
            LedgerLine(EntryType.ALLOCATION, Direction.CREDIT, "new", money("0.1"), "root"),
        ],
        "never created",
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


@pytest.mark.parametrize(
    ("line", "message"),
    [
        (
            LedgerLine(EntryType.ANCHOR, Direction.NONE, "root", money("0.01"), memo="x"),
            "moves no money",
        ),
        (
            LedgerLine(EntryType.ALLOCATION, Direction.DEBIT, "root", money("0.1"), "a\nb"),
            "counterparty id",
        ),
    ],
    ids=["a zero-value line with an amount", "a counterparty id with a line break"],
)
def test_a_raw_line_the_caller_got_wrong_is_the_callers_error(
    line: LedgerLine, message: str
) -> None:
    gov = _tree()
    before = len(gov.ledger)
    with pytest.raises(ValueError, match=message) as raised:
        gov.ledger._post([line])
    assert not isinstance(raised.value, LedgerIntegrityError)
    assert len(gov.ledger) == before


def test_a_governor_whose_clock_is_behind_the_chain_dates_its_entries_at_the_chains_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Time in the chain never runs backwards, whatever this governor's clock
    says: another governor's may be ahead of it."""
    gov = _tree()
    newest = gov.audit_trail()[-1].timestamp

    class Behind(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:  # type: ignore[override]
            return newest - timedelta(minutes=5)

    monkeypatch.setattr("agentgov.core.datetime", Behind)
    spent = gov.spend("child", money("0.01"))
    assert spent.timestamp == newest
    gov.verify_integrity()


def test_a_unit_of_work_built_against_an_older_head_is_refused() -> None:
    """Units of work are built and committed under the ledger's lock. One
    begun before another committed would fork the chain, and is refused."""
    gov = _tree()
    ledger = gov.ledger
    stale, current = ledger._begin(), ledger._begin()
    current.post([ROOT_FUNDING])
    ledger._commit(current)
    stale.post([ROOT_FUNDING])
    with pytest.raises(RuntimeError, match="stale ledger head"):
        ledger._commit(stale)
    gov.verify_integrity()


@pytest.mark.parametrize("stored", [False, True], ids=["in memory", "over sqlite"])
def test_a_spend_is_refunded_at_most_what_it_spent_across_its_refunds(
    stored: bool, tmp_path: Path
) -> None:
    """Each refund that names the spend counts against it, however many units
    of work apart: the scope's own bound (two spends) would allow more."""
    gov = _tree(tmp_path / "ledger.db" if stored else None)
    first = gov.spend("child", money("0.20"))
    gov.spend("child", money("0.20"))
    gov.refund("child", money("0.15"), reverses=first)
    with pytest.raises(ValueError, match=r"0.05000000 of its 0.20000000 is left"):
        gov.refund("child", money("0.10"), reverses=first)
    gov.refund("child", money("0.05"), reverses=first)
    gov.verify_integrity()


def test_a_node_the_caller_holds_stays_current() -> None:
    gov = _tree()
    root = gov.node("root")
    gov.fund("root", money("1"))
    assert gov.node("root") is root and root.allocated == money("2")


def test_a_governor_over_a_store_keeps_its_call_records_there(tmp_path: Path) -> None:
    """Memory does not grow with the calls made under a key: the store
    answers for them."""
    with BudgetManager.open_sqlite(str(tmp_path / "ledger.db")) as gov:
        gov.open_root("root", money("1"))
        for n in range(3):
            gov.spend("root", money("0.01"), idempotency_key=f"call-{n}")
        assert gov.ledger._keys == {}


def _drifted(gov: BudgetManager, drift: str) -> None:
    """Change what this governor holds in memory, and nothing in the chain."""
    state = gov.ledger._state
    if drift == "a scope the chain never created":
        state.nodes["ghost"] = BudgetNode("ghost", None, 0, money("1"), created_at=_NOW)
    elif drift == "an allocation":
        state.nodes["child"].allocated = money("0.9")
    elif drift == "a scope it forgot":
        del state.nodes["child"]
    elif drift == "a breaker":
        state.tripped["child"] = (_NOW, "forged")
    elif drift == "the Merkle frontier":
        state.frontier = ()
    elif drift == "a scope's lifetime spend":
        state.spent["child"] = money("9")
    elif drift == "a balance":
        state.balances["child"] = money("9")
    elif drift == "the boundary totals":
        state.totals = dataclasses.replace(state.totals, funded=money("9"))
    elif drift == "an open hold":
        state.holds.clear()
    else:
        raise AssertionError(drift)


_NOW = datetime.now(UTC)


DRIFTS = {
    "a scope the chain never created": "the chain never created it",
    "an allocation": "topology disagrees",
    "a scope it forgot": "created scope.* that are not registered",
    "a breaker": "breaker state disagrees",
    "the Merkle frontier": "Merkle frontier disagrees",
    "a scope's lifetime spend": "lifetime spend or refunds disagree",
    "a balance": "cached balance",
    "the boundary totals": "boundary totals disagree",
    "an open hold": "open holds disagree",
}


@pytest.mark.parametrize(("drift", "message"), DRIFTS.items(), ids=DRIFTS.keys())
def test_verify_chain_catches_memory_that_drifted_from_the_chain(drift: str, message: str) -> None:
    gov = _tree()
    gov.spend("child", money("0.10"))
    gov.authorize("child", money("0.05"))
    gov.verify_integrity()
    _drifted(gov, drift)
    with pytest.raises(LedgerIntegrityError, match=message):
        gov.ledger.verify_chain()


def test_verify_chain_over_a_store_replays_the_chain_as_it_reads_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It holds a chunk of the chain at a time, never all of it: a broken
    entry stops it before anything after it is read."""
    gov = _tree(tmp_path / "ledger.db")
    for _ in range(3):
        gov.spend("child", money("0.01"))
    entries = list(gov.ledger.iter_entries())
    broken = dataclasses.replace(entries[3], memo="rewritten")

    def reading(*args: object, **kwargs: object) -> Iterator[LedgerEntry]:
        yield from entries[:3]
        yield broken
        raise AssertionError("read past the broken entry")

    monkeypatch.setattr(gov.ledger, "iter_entries", reading)
    with pytest.raises(LedgerIntegrityError, match="tampered with"):
        gov.ledger.verify_chain()
    gov.close()


def _forged(
    lines: list[tuple[EntryType, Direction, str, str, str | None]],
    *,
    transactions: Sequence[int] = (),
    times: Sequence[datetime] = (),
) -> list[LedgerEntry]:
    """Entries with valid hashes and links. Every line but a funding shares
    one transaction, unless ``transactions`` numbers each line's (lines with
    the same number share one); ``times`` dates each line."""
    entries: list[LedgerEntry] = []
    head, balances = GENESIS_HASH, dict[str, Decimal]()
    txn, now = uuid.uuid4(), datetime.now(UTC)
    numbered: dict[int, uuid.UUID] = {}
    for sequence, (kind, direction, scope, amount, counterparty) in enumerate(lines, start=1):
        value = money(amount)
        signed = value if direction is Direction.CREDIT else -value
        balances[scope] = balances.get(scope, Decimal(0)) + signed
        if transactions:
            transaction_id = numbered.setdefault(transactions[sequence - 1], uuid.uuid4())
        else:
            transaction_id = txn if kind is not EntryType.FUNDING else uuid.uuid4()
        fields = dict(
            sequence=sequence,
            entry_id=uuid.uuid4(),
            transaction_id=transaction_id,
            timestamp=times[sequence - 1] if times else now,
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
    for finish in (False, True):
        with pytest.raises(LedgerIntegrityError, match="does not balance"):
            _replay(forged, finish=finish)
    _replay(
        _forged(
            [
                (EntryType.FUNDING, Direction.CREDIT, "root", "1", None),
                (EntryType.ALLOCATION, Direction.DEBIT, "root", "0.10", "child"),
                (EntryType.ALLOCATION, Direction.CREDIT, "child", "0.10", "root"),
            ]
        )
    )


def test_a_replay_balances_each_transaction_on_its_own() -> None:
    """Two transfers that each move money one way, and cancel out: the chain
    nets to zero, but each transaction must, at its own end."""
    lines = [
        (EntryType.FUNDING, Direction.CREDIT, "root", "1", None),
        (EntryType.ALLOCATION, Direction.DEBIT, "root", "0.10", "child"),
        (EntryType.ALLOCATION, Direction.CREDIT, "child", "0.10", "root"),
        (EntryType.RELEASE, Direction.DEBIT, "child", "0.05", "root"),
        (EntryType.RELEASE, Direction.CREDIT, "root", "0.05", "child"),
    ]
    with pytest.raises(LedgerIntegrityError, match="does not balance"):
        _replay(_forged(lines, transactions=[0, 1, 1, 2, 3]))
    _replay(_forged(lines, transactions=[0, 1, 1, 2, 2]))  # one release, both sides


def test_agov2_history_is_held_to_its_own_rules_not_to_agov3s() -> None:
    """AGOV2 entries were written before AGOV3's rules: time that runs back
    (a writer's clock stepped back) is history, not tampering."""
    now = datetime.now(UTC)
    _replay(
        _forged(
            [
                (EntryType.FUNDING, Direction.CREDIT, "root", "1", None),
                (EntryType.SPEND, Direction.DEBIT, "root", "0.10", None),
            ],
            times=[now, now - timedelta(seconds=5)],
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


def test_staging_a_scope_copies_none_of_its_children() -> None:
    """A write to a scope with 100,000 children costs what one to a leaf does."""
    gov = _tree()
    state = gov.ledger._state
    staged = _Overlay(state)._writable("root")
    assert staged is not state.nodes["root"]
    assert staged.child_ids is state.nodes["root"].child_ids


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
