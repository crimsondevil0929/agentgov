"""The v0.1.2 core guarantees, each tested against the failure that broke it.

Every test here reproduces a defect found in v0.1.1 and asserts the property
that now holds:

- **R1.** ``capture()`` wrote its ledger entries and deleted the open
  authorization in two transactions. A crash between them, then the
  documented ``void_stale()`` recovery, returned the same hold twice — and
  every verifier passed. Now one operation is one transaction; a release names
  its hold inside the hash; the ledger refuses a second release; and a store
  whose authorization rows disagree with the chain is refused at open.
- **R2 / R6.** Breaker trips and the delegation tree lived in tables outside
  the chain. Deleting a trip row, or re-parenting a scope, un-halted it with
  every verifier passing. Now both are derived from the chain, and the tables
  are caches that must agree with it.
- **R3.** A streamed call was fingerprinted by a fixed memo string, so the
  third stream on any trajectory tripped as an exact repeat. Now a stream is
  observed by the request it carries.
- **R4 (agentgov side).** A read-only manager was a snapshot taken at open.
  Now :meth:`BudgetManager.refresh` follows the writer, verified.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator, Callable, Iterator, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agentgov.cli import main as cli_main
from agentgov.cognitive import CognitiveBreaker, CognitivePolicy
from agentgov.core import (
    GENESIS_HASH,
    Authorization,
    BudgetManager,
    Direction,
    EntryType,
    Ledger,
    LedgerEntry,
    LedgerLine,
    WriteBatch,
    _hash_entry,
    money,
)
from agentgov.exceptions import (
    AgentGovError,
    AgentThrashingError,
    LedgerIntegrityError,
    ReadOnlyLedgerError,
)
from agentgov.interceptor import Interceptor, TokenUsage, pricing_for
from agentgov.storage import SqliteStore
from agentgov.streaming import MeteredStream

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


class _InjectedFaultError(Exception):
    """A failure injected into a store transaction by a test."""


class _FaultyConnection:
    """A sqlite3 connection that fails the Nth statement of a write transaction.

    Counts from ``BEGIN IMMEDIATE``, and counts the final ``COMMIT`` too, so
    every durable-write boundary of a governor operation can be hit in turn.
    """

    def __init__(self, inner: sqlite3.Connection, fail_at: int) -> None:
        self._inner = inner
        self._fail_at = fail_at
        self._seen = 0
        self._writing = False
        self.statements: list[str] = []

    def _tick(self, sql: str) -> None:
        verb = sql.strip().split(None, 1)[0].upper()
        if sql.strip().upper().startswith("BEGIN IMMEDIATE"):
            self._writing = True
            self._seen = 0
        if not self._writing:
            return
        self._seen += 1
        self.statements.append(verb)
        if self._seen == self._fail_at:
            raise _InjectedFaultError(f"injected failure at statement {self._seen} ({verb})")

    def execute(self, sql: str, params: Any = ()) -> sqlite3.Cursor:
        self._tick(sql)
        return self._inner.execute(sql, params)

    def executemany(self, sql: str, rows: Any) -> sqlite3.Cursor:
        self._tick(sql)
        return self._inner.executemany(sql, rows)

    def commit(self) -> None:
        self._tick("COMMIT")
        self._writing = False
        self._inner.commit()

    def rollback(self) -> None:
        self._writing = False
        self._inner.rollback()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def _faulty(gov: BudgetManager, fail_at: int) -> _FaultyConnection:
    store = gov.store
    assert isinstance(store, SqliteStore)
    connection = _FaultyConnection(store._conn, fail_at)
    store._conn = connection  # type: ignore[assignment]
    return connection


def _tables(path: str) -> dict[str, list[tuple[Any, ...]]]:
    """Every row of every governor table, for byte-for-byte comparison."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {
            table: sorted(conn.execute(f"SELECT * FROM {table}").fetchall(), key=repr)  # noqa: S608
            for table in ("entries", "nodes", "control_events", "open_authorizations")
        }
    finally:
        conn.close()


def _memory(gov: BudgetManager) -> tuple[object, ...]:
    """What a governor serves, for comparison before and after a failure."""
    return (
        len(gov.ledger),
        gov.ledger.head_hash,
        gov.ledger.balances(),
        tuple(sorted(gov._open_auths, key=str)),
        tuple((s, gov.is_halted(s)) for s in gov.scopes()),
        len(gov.control_events),
    )


def _governor(path: str) -> tuple[BudgetManager, Authorization, Authorization]:
    """A durable governor with every kind of state a later operation can touch."""
    gov = BudgetManager.open_sqlite(path)
    gov.open_root("root", money("1.00"))
    gov.delegate("root", "worker", money("0.50"))
    gov.delegate("root", "tight", money("0.05"))
    gov.delegate("root", "halted", money("0.05"))
    gov.trip("halted", "operator halt")
    open_hold = gov.authorize("worker", money("0.05"))
    exhausting = gov.authorize("tight", money("0.05"))
    return gov, open_hold, exhausting


Operation = Callable[[BudgetManager, Authorization, Authorization], object]

OPERATIONS: dict[str, Operation] = {
    "open_root": lambda g, a, t: g.open_root("fresh", money("1.00")),
    "fund": lambda g, a, t: g.fund("root", money("0.10")),
    "delegate": lambda g, a, t: g.delegate("root", "kid", money("0.10")),
    "release": lambda g, a, t: g.release("worker", money("0.10")),
    "authorize": lambda g, a, t: g.authorize("worker", money("0.05")),
    "capture": lambda g, a, t: g.capture(a, money("0.02")),
    "capture that exhausts and trips": lambda g, a, t: g.capture(t, money("0.05")),
    "void": lambda g, a, t: g.void(a),
    "refund": lambda g, a, t: g.refund("worker", money("0.01")),
    "trip": lambda g, a, t: g.trip("worker", "halt"),
    "reset": lambda g, a, t: g.reset("halted"),
    "anchor": lambda g, a, t: g.anchor("worker", "digest:abc"),
}


# --------------------------------------------------------------------------
# 0.1  One governor operation is one durable transaction (R1's window)
# --------------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(OPERATIONS))
def test_every_operation_is_exactly_one_store_transaction(tmp_path: Path, name: str) -> None:
    gov, open_hold, exhausting = _governor(str(tmp_path / "g.db"))
    recorder = _faulty(gov, fail_at=10**9)

    OPERATIONS[name](gov, open_hold, exhausting)

    assert recorder.statements.count("BEGIN") == 1, recorder.statements
    assert recorder.statements.count("COMMIT") == 1, recorder.statements
    gov.close()


@pytest.mark.parametrize("name", sorted(OPERATIONS))
def test_a_failure_at_any_write_boundary_leaves_the_state_before_the_operation(
    tmp_path: Path, name: str
) -> None:
    """Fail every statement of the operation's transaction in turn, including
    its COMMIT. Each time, disk and memory must both be exactly as before."""
    probe_path = str(tmp_path / "probe.db")
    gov, open_hold, exhausting = _governor(probe_path)
    recorder = _faulty(gov, fail_at=10**9)
    OPERATIONS[name](gov, open_hold, exhausting)
    boundaries = len(recorder.statements)
    gov.close()
    assert boundaries >= 3, "BEGIN, at least one write, COMMIT"

    for fail_at in range(1, boundaries + 1):
        path = str(tmp_path / f"{fail_at}.db")
        gov, open_hold, exhausting = _governor(path)
        disk_before, memory_before = _tables(path), _memory(gov)

        _faulty(gov, fail_at=fail_at)
        with pytest.raises(_InjectedFaultError):
            OPERATIONS[name](gov, open_hold, exhausting)

        assert _tables(path) == disk_before, f"disk moved when statement {fail_at} failed"
        assert _memory(gov) == memory_before, f"memory moved when statement {fail_at} failed"
        gov.verify_integrity()
        gov.close()

        with BudgetManager.open_sqlite(path) as reopened:
            reopened.verify_integrity()
            assert _memory(reopened) == memory_before


_CRASHING_CHILD = r"""
import os, sys
from agentgov import BudgetManager, money

path, fail_at = sys.argv[1], int(sys.argv[2])
gov = BudgetManager.open_sqlite(path)
gov.open_root("root", money("1.00"))
auth = gov.authorize("root", money("0.50"))

# Counts every statement capture() sends, across however many transactions
# it opens, and dies at the Nth without rolling back.
class Crash:
    def __init__(self, inner):
        self._inner, self.seen = inner, []
    def _tick(self, sql):
        self.seen.append(sql.strip().split(None, 1)[0].upper())
        if len(self.seen) == fail_at:
            os._exit(3)  # SIGKILL-equivalent: no rollback, no cleanup
    def execute(self, sql, params=()):
        self._tick(sql)
        return self._inner.execute(sql, params)
    def executemany(self, sql, rows):
        self._tick(sql)
        return self._inner.executemany(sql, rows)
    def commit(self):
        self._tick("COMMIT")
        self._inner.commit()
    def __getattr__(self, name):
        return getattr(self._inner, name)

crash = gov.store._conn = Crash(gov.store._conn)
gov.capture(auth, money("0.10"))
print(" ".join(crash.seen), flush=True)
os._exit(0)
"""


def _crash_capture(path: str, fail_at: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-c", _CRASHING_CHILD, path, str(fail_at)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_a_process_killed_inside_capture_restarts_consistent_and_cannot_mint_money(
    tmp_path: Path,
) -> None:
    """R1, the real thing: kill the process before every statement capture
    sends, reopen, and run the documented stale-hold recovery.

    v0.1.1 committed the settlement, then deleted the authorization in a second
    transaction. Killed between the two, it restarted with a released hold
    behind an open authorization, and ``void_stale()`` returned $0.50 a second
    time on a $1.00 envelope with every verifier passing.
    """
    probe = _crash_capture(str(tmp_path / "probe.db"), 10**9)
    assert probe.returncode == 0, probe.stderr
    statements = probe.stdout.split()
    assert statements == ["BEGIN", "INSERT", "DELETE", "COMMIT"], "one transaction"

    for fail_at in range(1, len(statements) + 1):
        path = str(tmp_path / f"crash-{fail_at}.db")
        child = _crash_capture(path, fail_at)
        assert child.returncode == 3, child.stderr

        with BudgetManager.open_sqlite(path) as gov:
            gov.verify_integrity()
            spends = [e for e in gov.audit_trail() if e.entry_type is EntryType.SPEND]
            assert spends == [], "the capture never committed"
            assert len(gov._open_auths) == 1, "the hold is still open, and still named"
            assert gov.available("root") == money("0.50")

            gov.void_stale(0)
            assert gov.available("root") == money("1.00"), "released exactly once"
            gov.void_stale(0)
            assert gov.available("root") == money("1.00"), "nothing left to release"
            gov.verify_integrity()


# --------------------------------------------------------------------------
# 0.2  A release names its hold, inside the hash
# --------------------------------------------------------------------------


def test_an_authorization_is_its_hold_and_its_settlement_names_it() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1.00"))
    auth = gov.authorize("root", money("0.30"))
    spend = gov.capture(auth, money("0.10"))
    release = gov.audit_trail()[-2]

    assert auth.authorization_id == auth.entry.entry_id
    assert release.entry_type is EntryType.HOLD_VOID
    assert release.ref == auth.entry.entry_id
    assert spend.ref == auth.entry.entry_id
    assert release.version == spend.version == "AGOV2"


def test_the_reference_is_covered_by_the_hash() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1.00"))
    gov.capture(gov.authorize("root", money("0.30")), money("0.10"))
    released = gov.ledger._entries[-2]
    gov.ledger._entries[-2] = replace(released, ref=uuid.uuid4())

    with pytest.raises(LedgerIntegrityError, match="tampered with"):
        gov.verify_integrity()


def _raw_ledger_with_hold() -> tuple[Ledger, LedgerEntry]:
    ledger = Ledger()
    ledger.post([LedgerLine(EntryType.FUNDING, Direction.CREDIT, "root", money("1.00"))])
    (hold,) = ledger.post([LedgerLine(EntryType.HOLD, Direction.DEBIT, "root", money("0.30"))])
    return ledger, hold


def _release(hold: LedgerEntry, **changes: Any) -> LedgerLine:
    line = LedgerLine(
        EntryType.HOLD_VOID, Direction.CREDIT, "root", money("0.30"), ref=hold.entry_id
    )
    return replace(line, **changes)


def test_the_ledger_refuses_to_release_a_hold_twice() -> None:
    ledger, hold = _raw_ledger_with_hold()
    ledger.post([_release(hold)])
    head, balance = ledger.head_hash, ledger.balance("root")

    with pytest.raises(LedgerIntegrityError, match="not an open hold"):
        ledger.post([_release(hold)])

    assert ledger.head_hash == head and ledger.balance("root") == balance
    ledger.verify_chain()


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"amount": money("0.29")}, "which encumbered"),
        ({"scope_id": "elsewhere"}, "of scope 'root'"),
        ({"ref": None}, "without naming it"),
        ({"ref": uuid.uuid4()}, "not an open hold"),
    ],
)
def test_a_release_must_name_an_open_hold_of_its_scope_and_amount(
    changes: dict[str, Any], message: str
) -> None:
    ledger, hold = _raw_ledger_with_hold()
    with pytest.raises(LedgerIntegrityError, match=message):
        ledger.post([_release(hold, **changes)])
    assert len(ledger) == 2


def test_a_spend_can_only_settle_a_hold_its_own_transaction_released() -> None:
    ledger, hold = _raw_ledger_with_hold()
    settling = LedgerLine(
        EntryType.SPEND, Direction.DEBIT, "root", money("0.10"), ref=hold.entry_id
    )
    with pytest.raises(LedgerIntegrityError, match="did not release"):
        ledger.post([settling])
    ledger.post([_release(hold), settling])  # the capture shape is accepted
    ledger.verify_chain()


def test_only_releases_and_spends_may_name_a_hold() -> None:
    ledger, hold = _raw_ledger_with_hold()
    with pytest.raises(ValueError, match="names no hold"):
        ledger.post(
            [
                LedgerLine(
                    EntryType.REVERSAL, Direction.CREDIT, "root", money("0.01"), ref=hold.entry_id
                )
            ]
        )


_Line = tuple[EntryType, Direction, str, str, uuid.UUID | int | None]


def _chain(lines: list[_Line], *, versions: Sequence[str] = ()) -> list[LedgerEntry]:
    """Entries with valid hashes and links, however wrong their content:
    what a full rewrite by someone able to compute SHA-256 would produce.

    A ``ref`` given as an int names the entry at that index of this chain.
    ``versions`` sets each entry's audit version; the rest are ``AGOV2``.
    """
    entries: list[LedgerEntry] = []
    head, balances = GENESIS_HASH, {"root": Decimal(0)}
    for index, (kind, direction, scope, amount, target) in enumerate(lines, start=1):
        ref = entries[target].entry_id if isinstance(target, int) else target
        version = versions[index - 1] if index <= len(versions) else "AGOV2"
        value = money(amount) if amount not in ("0", "-0.01") else Decimal(amount)
        sign = {Direction.CREDIT: 1, Direction.DEBIT: -1, Direction.NONE: 0}[direction]
        balances[scope] = balances.get(scope, Decimal(0)) + sign * value
        entry_id, txn, now = uuid.uuid4(), uuid.uuid4(), datetime.now(UTC)
        entry_hash = _hash_entry(
            prev_hash=head,
            sequence=index,
            entry_id=entry_id,
            transaction_id=txn,
            timestamp=now,
            entry_type=kind,
            direction=direction,
            scope_id=scope,
            counterparty_id=None,
            amount=value,
            balance_after=balances[scope],
            memo="",
            ref=ref,
            version=version,
        )
        entries.append(
            LedgerEntry(
                sequence=index,
                entry_id=entry_id,
                transaction_id=txn,
                timestamp=now,
                entry_type=kind,
                direction=direction,
                scope_id=scope,
                counterparty_id=None,
                amount=value,
                balance_after=balances[scope],
                prev_hash=head,
                entry_hash=entry_hash,
                ref=ref,
                version=version,
            )
        )
        head = entry_hash
    return entries


def _load(entries: list[LedgerEntry]) -> Ledger:
    ledger = Ledger()
    ledger._adopt(entries)
    return ledger


def test_verification_catches_a_rewritten_chain_that_releases_a_hold_twice() -> None:
    """Every hash and link is valid; only the pairing is wrong."""
    doubled = _chain(
        [
            (EntryType.FUNDING, Direction.CREDIT, "root", "1.00", None),
            (EntryType.HOLD, Direction.DEBIT, "root", "0.50", None),
            (EntryType.HOLD_VOID, Direction.CREDIT, "root", "0.50", 1),
            (EntryType.HOLD_VOID, Direction.CREDIT, "root", "0.50", 1),
        ]
    )
    with pytest.raises(LedgerIntegrityError, match="a second time"):
        _load(doubled)
    _load(doubled[:3]).verify_chain()  # one release is fine

    unnamed = _chain(
        [
            (EntryType.FUNDING, Direction.CREDIT, "root", "1.00", None),
            (EntryType.HOLD, Direction.DEBIT, "root", "0.50", None),
            (EntryType.HOLD_VOID, Direction.CREDIT, "root", "0.50", None),
        ]
    )
    with pytest.raises(LedgerIntegrityError, match="without naming it"):
        _load(unnamed)


_FUND: _Line = (EntryType.FUNDING, Direction.CREDIT, "root", "1.00", None)
_V1 = ("AGOV1",)


@pytest.mark.parametrize(
    ("lines", "versions", "message"),
    [
        ([(EntryType.FUNDING, Direction.DEBIT, "root", "1.00", None)], (), "may not be a"),
        ([_FUND, (EntryType.SPEND, Direction.DEBIT, "root", "0", None)], (), "must be positive"),
        ([_FUND, (EntryType.ANCHOR, Direction.NONE, "root", "-0.01", None)], (), "moves no"),
        ([_FUND, (EntryType.ANCHOR, Direction.NONE, "", "0", None)], (), "needs a scope"),
        ([_FUND, (EntryType.FUNDING, Direction.CREDIT, "root", "0.10", 0)], (), "names no hold"),
        (
            [
                _FUND,
                (EntryType.HOLD, Direction.DEBIT, "root", "0.50", None),
                (EntryType.SPEND, Direction.DEBIT, "root", "0.10", 1),
            ],
            (),
            "did not release",
        ),
        ([_FUND, (EntryType.SEAL, Direction.NONE, "", "0", None)], (), "does not have"),
        ([_FUND, (EntryType.SEAL, Direction.NONE, "root", "0", None)], _V1, "no scope"),
        (
            [_FUND] + [(EntryType.SEAL, Direction.NONE, "", "0", None)] * 2,
            _V1,
            "a second migration seal",
        ),
        (
            [_FUND, (EntryType.SPEND, Direction.DEBIT, "root", "0.10", None)],
            _V1,
            "is not the migration seal",
        ),
        (
            [_FUND, (EntryType.HOLD_VOID, Direction.CREDIT, "root", "0.50", None)],
            ("AGOV1", "AGOV1"),
            "released twice",
        ),
    ],
    ids=[
        "illegal-direction",
        "zero-spend",
        "valued-anchor",
        "scopeless-anchor",
        "stray-ref",
        "spend-of-unreleased-hold",
        "seal-without-history",
        "scoped-seal",
        "second-seal",
        "unsealed-upgrade",
        "unmatched-v1-release",
    ],
)
def test_every_replay_rule_rejects_a_forged_chain(
    lines: list[_Line], versions: tuple[str, ...], message: str
) -> None:
    """What a writer able to compute SHA-256 could forge, the rules still refuse."""
    with pytest.raises(LedgerIntegrityError, match=message):
        _load(_chain(lines, versions=versions))


def test_verification_checks_every_running_balance() -> None:
    entries = _chain(
        [
            (EntryType.FUNDING, Direction.CREDIT, "root", "1.00", None),
            (EntryType.SPEND, Direction.DEBIT, "root", "0.25", None),
        ]
    )
    forged = replace(entries[1], balance_after=money("0.95"))
    forged = replace(forged, entry_hash=forged.recompute_hash())

    with pytest.raises(LedgerIntegrityError, match=r"records a balance of 0\.95"):
        _load([entries[0], forged])


# --------------------------------------------------------------------------
# 0.2  Databases written by v0.1.0 / v0.1.1
# --------------------------------------------------------------------------

_V1_SCHEMA = """
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT INTO schema_meta VALUES ('schema_version', '1');
CREATE TABLE entries (
    sequence INTEGER PRIMARY KEY, entry_id TEXT NOT NULL UNIQUE,
    transaction_id TEXT NOT NULL, timestamp TEXT NOT NULL, entry_type TEXT NOT NULL,
    direction TEXT NOT NULL, scope_id TEXT NOT NULL, counterparty_id TEXT,
    amount TEXT NOT NULL, balance_after TEXT NOT NULL, prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL, memo TEXT NOT NULL DEFAULT ''
);
CREATE TABLE nodes (
    scope_id TEXT PRIMARY KEY, parent_id TEXT, depth INTEGER NOT NULL,
    allocated TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE control_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL, event_type TEXT NOT NULL, scope_id TEXT NOT NULL,
    reason TEXT NOT NULL, ledger_head_hash TEXT NOT NULL
);
CREATE TABLE open_authorizations (
    authorization_id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, amount TEXT NOT NULL,
    opened_at TEXT NOT NULL, entry_id TEXT NOT NULL
);
"""


class _V1Writer:
    """Writes a database exactly as agentgov v0.1.1 laid it out and hashed it."""

    def __init__(self, path: str, *, fresh: bool = True) -> None:
        self.conn = sqlite3.connect(path)
        if fresh:
            self.conn.executescript(_V1_SCHEMA)
            self.head, self.sequence = GENESIS_HASH, 0
        else:
            row = self.conn.execute(
                "SELECT sequence, entry_hash FROM entries ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            self.sequence, self.head = int(row[0]), str(row[1])
        self.balances: dict[str, Decimal] = {}
        for scope, amount, direction in self.conn.execute(
            "SELECT scope_id, amount, direction FROM entries"
        ):
            signed = Decimal(amount) if direction == "CR" else -Decimal(amount)
            self.balances[scope] = self.balances.get(scope, Decimal(0)) + signed

    def post(self, *lines: tuple[EntryType, Direction, str, str, str | None]) -> list[uuid.UUID]:
        txn, now, ids = uuid.uuid4(), datetime.now(UTC), []
        for kind, direction, scope, amount, counterparty in lines:
            value = money(amount)
            signed = value if direction is Direction.CREDIT else -value
            balance = self.balances.get(scope, Decimal(0)) + signed
            self.balances[scope] = balance
            self.sequence += 1
            entry_id = uuid.uuid4()
            entry_hash = _hash_entry(
                prev_hash=self.head,
                sequence=self.sequence,
                entry_id=entry_id,
                transaction_id=txn,
                timestamp=now,
                entry_type=kind,
                direction=direction,
                scope_id=scope,
                counterparty_id=counterparty,
                amount=value,
                balance_after=balance,
                memo="",
                version="AGOV1",
            )
            self.conn.execute(
                "INSERT INTO entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '')",
                (
                    self.sequence,
                    str(entry_id),
                    str(txn),
                    now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    kind.value,
                    direction.value,
                    scope,
                    counterparty,
                    str(value),
                    str(balance),
                    self.head,
                    entry_hash,
                ),
            )
            self.head = entry_hash
            ids.append(entry_id)
        self.conn.commit()
        return ids

    def node(self, scope: str, parent: str | None, depth: int, allocated: str) -> None:
        self.conn.execute(
            "INSERT INTO nodes VALUES (?, ?, ?, ?, ?)",
            (scope, parent, depth, str(money(allocated)), "2026-09-01T00:00:00.000000Z"),
        )
        self.conn.commit()

    def authorization(self, scope: str, amount: str, entry_id: uuid.UUID) -> None:
        self.conn.execute(
            "INSERT INTO open_authorizations VALUES (?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                scope,
                str(money(amount)),
                "2026-09-01T00:00:00.000000Z",
                str(entry_id),
            ),
        )
        self.conn.commit()

    def control(self, event_type: str, scope: str, reason: str) -> None:
        self.conn.execute(
            "INSERT INTO control_events "
            "(event_id, timestamp, event_type, scope_id, reason, ledger_head_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                event_type,
                scope,
                reason,
                self.head,
            ),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


def _legacy_database(path: str) -> None:
    """A v0.1.1 governor's file: a captured hold, an open one, a latched scope."""
    v1 = _V1Writer(path)
    v1.post((EntryType.FUNDING, Direction.CREDIT, "root", "1.00", None))
    v1.node("root", None, 0, "1.00")
    for child, amount in (("worker", "0.50"), ("idle", "0.10")):
        v1.post(
            (EntryType.ALLOCATION, Direction.DEBIT, "root", amount, child),
            (EntryType.ALLOCATION, Direction.CREDIT, child, amount, "root"),
        )
        v1.node(child, "root", 1, amount)
    v1.post((EntryType.HOLD, Direction.DEBIT, "worker", "0.05", None))
    v1.post(
        (EntryType.HOLD_VOID, Direction.CREDIT, "worker", "0.05", None),
        (EntryType.SPEND, Direction.DEBIT, "worker", "0.02", None),
    )
    (open_hold,) = v1.post((EntryType.HOLD, Direction.DEBIT, "worker", "0.05", None))
    v1.authorization("worker", "0.05", open_hold)
    v1.control("circuit_tripped", "idle", "operator halt before the upgrade")
    v1.close()


def _schema_version(path: str) -> str:
    conn = sqlite3.connect(path)
    try:
        row = conn.execute("SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
        return str(row[0])
    finally:
        conn.close()


def test_a_legacy_database_opens_read_only_as_it_is(tmp_path: Path) -> None:
    path = str(tmp_path / "v1.db")
    _legacy_database(path)

    with BudgetManager.open_sqlite(path, read_only=True) as gov:
        gov.verify_integrity()
        assert gov.available("worker") == money("0.43")
        assert gov.is_halted("idle") and not gov.is_halted("worker")
        assert len(gov._open_auths) == 1
        assert {e.version for e in gov.audit_trail()} == {"AGOV1"}
    assert _schema_version(path) == "1", "a read-only open changes nothing"


def test_a_legacy_database_is_upgraded_and_sealed_on_its_first_writable_open(
    tmp_path: Path,
) -> None:
    path = str(tmp_path / "v1.db")
    _legacy_database(path)

    with BudgetManager.open_sqlite(path) as gov:
        seal = gov.audit_trail()[-1]
        assert seal.entry_type is EntryType.SEAL and seal.version == "AGOV2"
        assert seal.scope_id == "" and seal.amount == 0
        assert "n=1" in seal.memo, "the one legacy control event is sealed"
        assert gov.is_halted("idle"), "a pre-upgrade halt still stands"

        # The pre-upgrade hold settles through the new, named path.
        (legacy,) = gov._open_auths.values()
        spend = gov.capture(legacy, money("0.01"))
        assert spend.ref == legacy.entry.entry_id and spend.version == "AGOV2"
        gov.verify_integrity()

    assert _schema_version(path) == "2"
    with BudgetManager.open_sqlite(path) as reopened:
        reopened.verify_integrity()
        assert [e.entry_type for e in reopened.audit_trail()].count(EntryType.SEAL) == 1
        assert reopened.available("worker") == money("0.47")


def test_a_sealed_legacy_control_event_cannot_be_deleted(tmp_path: Path) -> None:
    path = str(tmp_path / "v1.db")
    _legacy_database(path)
    BudgetManager.open_sqlite(path).close()  # upgrade and seal

    conn = sqlite3.connect(path)
    with conn:
        conn.execute("DELETE FROM control_events WHERE entry_id IS NULL")
    conn.close()

    with pytest.raises(LedgerIntegrityError, match="no longer match the seal"):
        BudgetManager.open_sqlite(path)
    with pytest.raises(LedgerIntegrityError, match="no longer match the seal"):
        BudgetManager.open_sqlite(path, repair=True)  # the seal cannot be rebuilt


def test_legacy_crash_state_is_refused_not_served_and_repair_cannot_mint_money(
    tmp_path: Path,
) -> None:
    """R1 exactly as v0.1.1 left it on disk: a capture's release and spend
    committed, its open-authorization row never deleted."""
    path = str(tmp_path / "v1-crashed.db")
    v1 = _V1Writer(path)
    v1.post((EntryType.FUNDING, Direction.CREDIT, "root", "1.00", None))
    v1.node("root", None, 0, "1.00")
    (hold,) = v1.post((EntryType.HOLD, Direction.DEBIT, "root", "0.50", None))
    v1.post(
        (EntryType.HOLD_VOID, Direction.CREDIT, "root", "0.50", None),
        (EntryType.SPEND, Direction.DEBIT, "root", "0.10", None),
    )
    v1.authorization("root", "0.50", hold)  # the row the crash never deleted
    v1.close()

    with pytest.raises(LedgerIntegrityError, match="0 hold"):
        BudgetManager.open_sqlite(path, read_only=True)
    with pytest.raises(LedgerIntegrityError, match="repair=True"):
        BudgetManager.open_sqlite(path)

    with BudgetManager.open_sqlite(path, repair=True) as gov:
        assert gov.repairs, "the stale row was reported"
        assert gov._open_auths == {}
        assert gov.void_stale(0) == ()
        assert gov.available("root") == money("0.90"), "v0.1.1 recovery made this 1.40"
        gov.verify_integrity()
    with BudgetManager.open_sqlite(path) as reopened:
        assert reopened.available("root") == money("0.90")


def test_current_format_crash_state_is_refused_too(tmp_path: Path) -> None:
    path = str(tmp_path / "g.db")
    with BudgetManager.open_sqlite(path) as gov:
        gov.open_root("root", money("1.00"))
        auth = gov.authorize("root", money("0.50"))
        gov.capture(auth, money("0.10"))
    conn = sqlite3.connect(path)
    with conn:  # put back the row v0.1.1's crash window would have left
        conn.execute(
            "INSERT INTO open_authorizations VALUES (?, 'root', '0.50000000', ?, ?)",
            (str(auth.authorization_id), "2026-09-01T00:00:00.000000Z", str(auth.entry.entry_id)),
        )
    conn.close()

    with pytest.raises(LedgerIntegrityError, match="return the same funds twice"):
        BudgetManager.open_sqlite(path)


def test_the_ledger_refuses_a_stale_authorization_even_if_memory_holds_one() -> None:
    """Defence in depth: whatever a cache claims, the chain decides."""
    gov = BudgetManager()
    gov.open_root("root", money("1.00"))
    auth = gov.authorize("root", money("0.50"))
    gov.capture(auth, money("0.10"))
    gov._open_auths[auth.authorization_id] = auth  # a corrupted cache

    with pytest.raises(LedgerIntegrityError, match="not an open hold"):
        gov.void_stale(0)
    assert gov.available("root") == money("0.90")


@pytest.mark.parametrize(
    ("version", "ref", "entry_type", "message"),
    [
        ("AGOV1", uuid.uuid4(), EntryType.SPEND, "hash does not cover"),
        ("AGOV1", None, EntryType.ANCHOR, "a type AGOV1 did not have"),
        ("AGOV9", None, EntryType.FUNDING, "unknown audit version"),
    ],
)
def test_entry_versions_are_enforced(
    version: str, ref: uuid.UUID | None, entry_type: EntryType, message: str
) -> None:
    (entry,) = _chain([(EntryType.FUNDING, Direction.CREDIT, "root", "1.00", None)])
    tampered = replace(entry, version=version, ref=ref, entry_type=entry_type)
    if version != "AGOV9":
        tampered = replace(tampered, entry_hash=tampered.recompute_hash())
    with pytest.raises(LedgerIntegrityError, match=message):
        _load([tampered])


def test_an_agov1_entry_cannot_follow_agov2_entries() -> None:
    first, second = _chain(
        [
            (EntryType.FUNDING, Direction.CREDIT, "root", "1.00", None),
            (EntryType.SPEND, Direction.DEBIT, "root", "0.10", None),
        ]
    )
    downgraded = replace(second, version="AGOV1")
    downgraded = replace(downgraded, entry_hash=downgraded.recompute_hash())
    with pytest.raises(LedgerIntegrityError, match="cannot follow newer ones"):
        _load([first, downgraded])


# --------------------------------------------------------------------------
# 0.3  Governance state lives in the chain (R2, R6)
# --------------------------------------------------------------------------


def test_trips_resets_and_anchors_are_zero_value_chain_entries() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1.00"))
    gov.trip("root", "halt")
    gov.anchor("root", "digest:1")
    gov.reset("root")
    tripped, anchored, reset = gov.audit_trail()[-3:]

    assert [tripped.entry_type, anchored.entry_type, reset.entry_type] == [
        EntryType.CIRCUIT_TRIPPED,
        EntryType.ANCHOR,
        EntryType.CIRCUIT_RESET,
    ]
    assert {e.direction for e in (tripped, anchored, reset)} == {Direction.NONE}
    assert {e.amount for e in (tripped, anchored, reset)} == {Decimal(0)}
    assert gov.available("root") == money("1.00")
    assert [e.entry_id for e in gov.control_events] == [tripped.entry_id, reset.entry_id]
    gov.verify_integrity()


def _halted_database(path: str) -> None:
    with BudgetManager.open_sqlite(path) as gov:
        gov.open_root("root", money("1.00"))
        gov.delegate("root", "team", money("0.50"))
        gov.delegate("team", "agent", money("0.20"))
        gov.open_root("sandbox", money("1.00"))
        gov.trip("team", "cognitive breaker [near_duplicate]: thrashing")


def _run_sql(path: str, sql: str, params: tuple[object, ...] = ()) -> None:
    conn = sqlite3.connect(path)
    with conn:
        conn.execute(sql, params)
    conn.close()


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("DELETE FROM control_events", "missing from the control_events table"),
        ("UPDATE control_events SET event_type = 'circuit_reset'", "disagrees with it"),
        ("UPDATE nodes SET parent_id = 'sandbox', depth = 1 WHERE scope_id = 'agent'", "parent"),
        ("DELETE FROM nodes WHERE scope_id = 'team'", "missing from the nodes table"),
        (
            "INSERT INTO nodes VALUES "
            "('ghost', NULL, 0, '1.00000000', '2026-09-01T00:00:00.000000Z')",
            "never created",
        ),
    ],
)
def test_editing_governance_tables_is_refused_and_repair_restores_the_chains_view(
    tmp_path: Path, tamper: str, message: str
) -> None:
    """R2 and R6: v0.1.1 served each of these with every verifier passing,
    and the first two un-halted the scope."""
    path = str(tmp_path / "g.db")
    _halted_database(path)
    _run_sql(path, tamper)

    with pytest.raises(LedgerIntegrityError, match=message):
        BudgetManager.open_sqlite(path)
    with pytest.raises(LedgerIntegrityError, match=message):
        BudgetManager.open_sqlite(path, read_only=True)

    with BudgetManager.open_sqlite(path, repair=True) as gov:
        assert gov.repairs
        assert gov.is_halted("agent"), "halted by the chain, whatever the table said"
        assert gov.ancestry("agent") == ("agent", "team", "root")
    with BudgetManager.open_sqlite(path) as reopened:  # clean again, no repair needed
        assert reopened.repairs == ()
        assert reopened.is_halted("agent")
        reopened.verify_integrity()


def test_the_repair_command_rebuilds_caches_and_verify_then_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = str(tmp_path / "g.db")
    _halted_database(path)

    assert cli_main(["repair", path]) == 0
    assert "nothing to repair" in capsys.readouterr().out

    _run_sql(path, "DELETE FROM control_events")
    assert cli_main(["verify", path]) == 1
    capsys.readouterr()
    assert cli_main(["repair", path]) == 0
    out = capsys.readouterr().out
    assert "REPAIRED" in out and "control_events" in out
    assert cli_main(["verify", path]) == 0


def test_anchors_move_no_money_and_are_accepted_on_a_halted_scope() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1.00"))
    gov.trip("root", "halted for review")

    entry = gov.anchor("root", "escrow:ab12cd34")

    assert entry.memo == "escrow:ab12cd34"
    assert gov.available("root") == money("1.00")
    gov.verify_conservation()
    with pytest.raises(ValueError, match="must carry"):
        gov.anchor("root", "")
    with pytest.raises(Exception, match="Unknown budget scope"):
        gov.anchor("nobody", "x")


def test_editing_an_anchor_breaks_verification() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1.00"))
    gov.anchor("root", "escrow:1111")
    gov.ledger._entries[-1] = replace(gov.ledger._entries[-1], memo="escrow:2222")
    with pytest.raises(LedgerIntegrityError, match="tampered with"):
        gov.verify_integrity()


def test_a_scope_id_must_not_be_empty() -> None:
    gov = BudgetManager()
    with pytest.raises(ValueError, match="must not be empty"):
        gov.open_root("", money("1.00"))
    gov.open_root("root", money("1.00"))
    with pytest.raises(ValueError, match="must not be empty"):
        gov.delegate("root", "", money("0.10"))


def test_a_manager_over_an_existing_ledger_derives_its_state_from_the_chain() -> None:
    first = BudgetManager()
    first.open_root("root", money("1.00"))
    first.delegate("root", "kid", money("0.25"))
    first.trip("kid", "halt")
    auth = first.authorize("root", money("0.10"))

    second = BudgetManager(ledger=first.ledger)

    assert second.ancestry("kid") == ("kid", "root")
    assert second.is_halted("kid")
    assert set(second._open_auths) == {auth.authorization_id}
    second.verify_integrity()


# --------------------------------------------------------------------------
# 0.4  A stream is observed by the request it carries (R3)
# --------------------------------------------------------------------------


@dataclass
class _Event:
    usage: TokenUsage | None = None
    delta: object = None


def _answering(answer: Callable[[str], str]) -> Callable[..., Iterator[_Event]]:
    def stream(**kwargs: Any) -> Iterator[_Event]:
        prompt = kwargs["messages"][0]["content"]
        yield _Event(delta=SimpleNamespace(text=answer(prompt)))
        yield _Event(usage=TokenUsage(input_tokens=20, output_tokens=10))

    return stream


def _streaming(policy: CognitivePolicy | None = None) -> tuple[BudgetManager, Interceptor]:
    gov = BudgetManager()
    gov.open_root("agent", money("5.00"))
    breaker = CognitiveBreaker(manager=gov, observer=None, policy=policy)
    return gov, Interceptor(gov, "agent", model="claude-sonnet-5", cognitive=breaker)


def _constant(answer: str) -> Callable[[str], str]:
    return lambda _prompt: answer


def _stream_once(metered: Interceptor, fn: Callable[..., Iterator[_Event]], prompt: str) -> None:
    with metered.stream(fn, messages=[{"role": "user", "content": prompt}], max_tokens=64) as s:
        list(s)


def test_different_streamed_requests_are_not_a_loop() -> None:
    """R3: v0.1.1 halted the third of these as an exact repeat, confidence 1.0."""
    gov, metered = _streaming()
    for prompt in (
        "Summarise Q3 revenue by region",
        "Draft the churn memo for EMEA",
        "List open P1 incidents in payments",
        "Reconcile the September invoice",
    ):
        _stream_once(metered, _answering(lambda p: f"an answer about {p}"), prompt)
    assert not gov.is_halted("agent")


def test_identical_streamed_requests_still_trip_the_breaker() -> None:
    gov, metered = _streaming()
    fn = _answering(lambda p: "I cannot find that report.")
    with pytest.raises(AgentThrashingError):
        for _ in range(4):
            _stream_once(metered, fn, "Find the Q3 report")
    assert gov.is_halted("agent")


def test_streamed_results_separate_progress_from_a_soft_loop() -> None:
    """Near-identical prompts: different answers are pagination, same answers
    are thrashing. Only the result the stream produced can tell them apart."""
    pages = [f"Fetch page {n} of the audit log for tenant acme" for n in range(1, 7)]

    gov, metered = _streaming()
    for n, prompt in enumerate(pages):
        answer = f"page {n}: {' '.join(f'row-{n}-{i}-{uuid.uuid4().hex}' for i in range(8))}"
        _stream_once(metered, _answering(_constant(answer)), prompt)
    assert not gov.is_halted("agent"), "different answers are progress"

    gov, metered = _streaming()
    with pytest.raises(AgentThrashingError):
        for prompt in pages:
            _stream_once(metered, _answering(lambda p: "The audit log is unavailable."), prompt)


def test_async_streams_are_observed_by_their_request() -> None:
    gov, metered = _streaming()

    async def events(**kwargs: Any) -> AsyncIterator[_Event]:
        yield _Event(delta=SimpleNamespace(text=f"answer: {kwargs['messages'][0]['content']}"))
        yield _Event(usage=TokenUsage(input_tokens=20, output_tokens=10))

    async def run() -> None:
        for prompt in ("alpha report", "beta memo", "gamma incident list", "delta invoice"):
            async with metered.astream(
                events, messages=[{"role": "user", "content": prompt}]
            ) as stream:
                async for _ in stream:
                    pass

    asyncio.run(run())
    assert not gov.is_halted("agent")


def test_an_opaque_stream_adds_no_evidence_but_respects_a_halt() -> None:
    gov, metered = _streaming()
    breaker = metered.cognitive
    assert breaker is not None
    pricing = pricing_for("claude-sonnet-5")

    def opaque() -> MeteredStream[_Event]:
        return MeteredStream(
            gov,
            "agent",
            money("0.10"),
            pricing,
            metered._extract_usage,
            lambda: iter([_Event(usage=TokenUsage(input_tokens=5, output_tokens=5))]),
            cognitive=breaker,
        )

    for _ in range(5):
        with opaque() as stream:
            list(stream)
    assert not gov.is_halted("agent"), "five indistinguishable thunks are not a loop"

    with pytest.raises(AgentThrashingError):
        for _ in range(3):
            breaker.observe("agent", "search", "same query")
    gov.reset("agent")
    with pytest.raises(AgentThrashingError), opaque():
        pass  # pragma: no cover - entering raises


# --------------------------------------------------------------------------
# 0.5  A read-only view follows the writer (R4, agentgov side)
# --------------------------------------------------------------------------


def test_a_read_only_view_follows_the_writer(tmp_path: Path) -> None:
    path = str(tmp_path / "g.db")
    writer = BudgetManager.open_sqlite(path)
    writer.open_root("root", money("1.00"))
    reader = BudgetManager.open_sqlite(path, read_only=True)

    writer.delegate("root", "kid", money("0.30"))
    auth = writer.authorize("kid", money("0.10"))
    writer.trip("kid", "halted by the writer")
    assert "kid" not in reader.scopes(), "a view is a snapshot until refreshed"

    assert reader.refresh() == 4
    assert reader.is_halted("kid")
    assert reader.available("kid") == money("0.20")
    assert set(reader._open_auths) == {auth.authorization_id}
    reader.verify_integrity()
    assert reader.refresh() == 0

    writer.reset("kid")
    writer.capture(auth, money("0.04"))
    reader.refresh()
    assert not reader.is_halted("kid")
    assert reader._open_auths == {}
    assert reader.available("kid") == money("0.26")
    reader.verify_integrity()

    with pytest.raises(ReadOnlyLedgerError):
        reader.trip("kid", "a reader cannot write")
    writer.close()
    reader.close()


def test_refresh_detects_history_rewritten_under_the_view(tmp_path: Path) -> None:
    path = str(tmp_path / "g.db")
    with BudgetManager.open_sqlite(path) as writer:
        writer.open_root("root", money("1.00"))
        writer.spend("root", money("0.10"))
    reader = BudgetManager.open_sqlite(path, read_only=True)

    _run_sql(
        path, "UPDATE entries SET entry_hash = ? WHERE sequence = ?", ("f" * 64, len(reader.ledger))
    )

    with pytest.raises(LedgerIntegrityError, match="rewritten under this reader"):
        reader.refresh()
    with pytest.raises(LedgerIntegrityError, match="stopped following"):
        reader.refresh()
    reader.close()


def test_refresh_refuses_an_unverifiable_new_entry_and_stops_serving(tmp_path: Path) -> None:
    path = str(tmp_path / "g.db")
    writer = BudgetManager.open_sqlite(path)
    writer.open_root("root", money("1.00"))
    reader = BudgetManager.open_sqlite(path, read_only=True)
    writer.spend("root", money("0.10"))
    writer.close()
    _run_sql(path, "UPDATE entries SET amount = '0.00000001' WHERE entry_type = 'spend'")

    with pytest.raises(LedgerIntegrityError, match="tampered with"):
        reader.refresh()
    assert len(reader.ledger) == 1, "nothing unverified was applied"
    reader.close()


def _served(gov: BudgetManager) -> tuple[object, ...]:
    """Everything a read-only view answers with, for before/after comparison."""
    return (
        _memory(gov),
        tuple(hold.entry_id for hold in gov.ledger.open_holds()),
        tuple(
            (n.scope_id, n.parent_id, n.allocated, tuple(n.child_ids)) for n in gov._nodes.values()
        ),
        gov.ledger._totals,
    )


def _forge_after(last: LedgerEntry, kind: EntryType, scope_id: str) -> LedgerEntry:
    """A zero-value entry with a valid hash and link, written by someone able
    to compute SHA-256: it passes every ledger rule, whatever it claims."""
    entry = LedgerEntry(
        sequence=last.sequence + 1,
        entry_id=uuid.uuid4(),
        transaction_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        entry_type=kind,
        direction=Direction.NONE,
        scope_id=scope_id,
        counterparty_id=None,
        amount=Decimal(0),
        balance_after=Decimal(0),
        prev_hash=last.entry_hash,
        entry_hash="",
        memo="forged",
        version="AGOV2",
    )
    return replace(entry, entry_hash=entry.recompute_hash())


def _fail_on_new_entry(path: str) -> str:
    with BudgetManager.open_sqlite(path) as writer:
        writer.spend("root", money("0.10"))
    _run_sql(path, "UPDATE entries SET amount = '0.00000001' WHERE entry_type = 'spend'")
    return "tampered with"


def _fail_in_governance(path: str) -> str:
    """Every ledger rule passes; only the topology the chain implies does not."""
    with BudgetManager.open_sqlite(path) as writer:
        writer.delegate("root", "kid", money("0.20"))
        last = writer.audit_trail()[-1]
    store = SqliteStore(path)
    store.commit(WriteBatch(entries=[_forge_after(last, EntryType.CIRCUIT_TRIPPED, "ghost")]))
    store.close()
    return "unregistered scope 'ghost'"


def _fail_in_reconciliation(path: str) -> str:
    """The new entries verify; the authorization rows beside them do not."""
    with BudgetManager.open_sqlite(path) as writer:
        writer.delegate("root", "kid", money("0.20"))
        writer.authorize("kid", money("0.05"))
    _run_sql(path, "DELETE FROM open_authorizations")
    return "no authorization names it"


def _fail_in_reload(path: str) -> str:
    """The writer upgrades the schema under the view, and the full re-read fails."""
    with BudgetManager.open_sqlite(path) as writer:
        writer.delegate("root", "kid", money("0.20"))
    _run_sql(path, "DELETE FROM nodes WHERE scope_id = 'kid'")
    return "missing from the nodes table"


@pytest.mark.parametrize(
    "fail",
    [_fail_on_new_entry, _fail_in_governance, _fail_in_reconciliation, _fail_in_reload],
    ids=["entry", "governance", "reconciliation", "reload"],
)
def test_a_failed_refresh_changes_nothing_the_view_serves(
    tmp_path: Path, fail: Callable[[str], str]
) -> None:
    """All or nothing. A refresh that fails at any stage, after any amount of
    staged work, leaves the view serving exactly what it last verified."""
    path = str(tmp_path / "g.db")
    if fail is _fail_in_reload:
        _legacy_database(path)
    else:
        with BudgetManager.open_sqlite(path) as writer:
            writer.open_root("root", money("1.00"))
            writer.delegate("root", "worker", money("0.30"))
            writer.authorize("worker", money("0.10"))
            writer.trip("worker", "halted before the view opened")
    reader = BudgetManager.open_sqlite(path, read_only=True)
    reader.verify_integrity()
    served = _served(reader)

    message = fail(path)

    with pytest.raises(LedgerIntegrityError, match=message):
        reader.refresh()
    assert _served(reader) == served, "a failed refresh must not move the view"
    reader.verify_integrity()
    with pytest.raises(LedgerIntegrityError, match="stopped following"):
        reader.refresh()
    assert _served(reader) == served
    reader.close()


def test_refresh_is_a_no_op_for_a_writer_and_for_an_in_memory_manager(tmp_path: Path) -> None:
    with BudgetManager.open_sqlite(str(tmp_path / "g.db")) as writer:
        writer.open_root("root", money("1.00"))
        assert writer.refresh() == 0
    assert BudgetManager().refresh() == 0


def test_refresh_follows_a_legacy_writer_and_a_schema_upgrade(tmp_path: Path) -> None:
    path = str(tmp_path / "v1.db")
    _legacy_database(path)
    reader = BudgetManager.open_sqlite(path, read_only=True)

    v1 = _V1Writer(path, fresh=False)  # a v0.1.1 governor still writing
    v1.post((EntryType.SPEND, Direction.DEBIT, "root", "0.10", None))
    v1.control("circuit_tripped", "worker", "halted by a v0.1.1 writer")
    v1.close()
    assert reader.refresh() == 1
    assert reader.is_halted("worker")
    assert reader.available("root") == money("0.30")

    with BudgetManager.open_sqlite(path) as upgraded:  # a v0.1.2 writer takes over
        upgraded.open_root("new", money("2.00"))
    reader.refresh()
    assert reader.audit_trail()[-2].entry_type is EntryType.SEAL
    assert reader.available("new") == money("2.00")
    assert reader.is_halted("worker") and reader.is_halted("idle")
    reader.verify_integrity()
    reader.close()


def test_a_store_image_is_one_consistent_read(tmp_path: Path) -> None:
    path = str(tmp_path / "g.db")
    with BudgetManager.open_sqlite(path) as gov:
        gov.open_root("root", money("1.00"))
        gov.authorize("root", money("0.10"))
    store = SqliteStore(path, read_only=True)
    statements: list[str] = []
    original = store._conn

    def execute(sql: str, *args: Any) -> sqlite3.Cursor:
        statements.append(sql.split()[0])
        return original.execute(sql, *args)

    store._conn = SimpleNamespace(  # type: ignore[assignment]
        execute=execute, in_transaction=False, rollback=original.rollback
    )
    image = store.load()
    assert statements[0] == "BEGIN", "every table is read inside one transaction"
    assert len(image.entries) == 2 and len(image.authorizations) == 1
    original.close()


def test_refresh_is_exposed_on_the_raw_ledger_file_too(tmp_path: Path) -> None:
    """``os.replace`` of the whole file is not something a reader can follow;
    it must keep serving what it verified rather than something it did not."""
    path = str(tmp_path / "g.db")
    with BudgetManager.open_sqlite(path) as gov:
        gov.open_root("root", money("1.00"))
    reader = BudgetManager.open_sqlite(path, read_only=True)
    other = str(tmp_path / "other.db")
    with BudgetManager.open_sqlite(other) as gov:
        gov.open_root("different", money("9.00"))
    os.replace(other, path)
    reader.refresh()  # the reader still holds the file it opened
    assert reader.scopes() == ("root",)
    reader.close()


# --------------------------------------------------------------------------
# The store's per-row writers, kept for existing callers
# --------------------------------------------------------------------------


def test_the_per_row_store_writers_still_round_trip(tmp_path: Path) -> None:
    """The core no longer calls these, but callers of v0.1.1's store may."""
    from agentgov.core import ControlEvent

    store = SqliteStore(str(tmp_path / "g.db"))
    now = datetime.now(UTC)
    hold_id, auth_id = uuid.uuid4(), uuid.uuid4()
    store.commit(WriteBatch())  # an empty unit of work writes nothing
    store.upsert_node("root", None, 0, money("1.00"), now)
    store.upsert_node("root", None, 0, money("2.00"), now)
    event = ControlEvent(
        event_id=uuid.uuid4(),
        timestamp=now,
        event_type="circuit_tripped",
        scope_id="root",
        reason="manual",
        ledger_head_hash=GENESIS_HASH,
    )
    store.append_control_event(event)
    store.put_authorization(auth_id, "root", money("0.10"), now, hold_id)

    (node,) = store.load_nodes()
    assert (node.scope_id, node.allocated) == ("root", money("2.00"))
    assert [e.event_id for e in store.load_control_events()] == [event.event_id]
    (auth,) = store.load_open_authorizations()
    assert (auth.authorization_id, auth.entry_id) == (auth_id, hold_id)
    assert store.schema_version == "2"

    store.delete_authorization(auth_id)
    assert store.load_open_authorizations() == ()
    with store._read_transaction(), store._read_transaction():  # nests into one
        assert store.load_entries() == ()
    store.close()


def test_a_database_this_version_cannot_read_is_refused(tmp_path: Path) -> None:
    foreign = str(tmp_path / "foreign.db")
    conn = sqlite3.connect(foreign)
    conn.execute("CREATE TABLE unrelated (x INTEGER)")
    conn.commit()
    conn.close()
    with pytest.raises(AgentGovError, match="not an agentgov database"):
        SqliteStore(foreign, read_only=True)

    future = str(tmp_path / "future.db")
    with BudgetManager.open_sqlite(future) as gov:
        gov.open_root("root", money("1.00"))
    _run_sql(future, "UPDATE schema_meta SET value = '99' WHERE key = 'schema_version'")
    with pytest.raises(LedgerIntegrityError, match="schema version '99'"):
        BudgetManager.open_sqlite(future, read_only=True)

    unversioned = str(tmp_path / "unversioned.db")
    with BudgetManager.open_sqlite(unversioned) as gov:
        gov.open_root("root", money("1.00"))
    _run_sql(unversioned, "DELETE FROM schema_meta WHERE key = 'schema_version'")
    with BudgetManager.open_sqlite(unversioned, read_only=True) as reader:
        assert reader.available("root") == money("1.00"), "read as the current schema"
