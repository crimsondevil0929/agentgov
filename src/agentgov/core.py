"""Core primitives: the hash-chained ledger and the hierarchical budget DAG.

Design brief
------------
This module is the economic control plane. It is written to the standards a
payments engineer would expect of a settlement ledger, not to the standards
of an in-memory counter:

**Append-only, hash-chained.** Every economic event is a :class:`LedgerEntry`
linked to its predecessor by a SHA-256 chain (``prev_hash`` → ``entry_hash``).
Nothing is ever mutated or deleted; a correction is a new compensating entry.
:meth:`Ledger.verify_chain` re-derives every hash and detects any retroactive
edit, which is what makes the audit trail *evidentiary* rather than merely
descriptive.

**Double-entry.** Every line is a DEBIT or a CREDIT against exactly one scope,
and internal transfers (parent → child delegation, child → parent release)
always post balanced pairs within a single transaction. The global identity

    Σ(scope balances) + outstanding_holds + settled_spend - reversals == funded

is checked by :meth:`BudgetManager.verify_integrity`. Money cannot appear or
disappear; it can only move between scopes or out to a vendor.

**Authorize / capture, not fire-and-forget.** A tool call takes an
authorization *hold* against its scope before the call is made, and captures
the true cost afterwards. Concurrent sub-agents therefore contend for the
same encumbered funds at authorization time, which is what makes double-spend
structurally impossible rather than merely unlikely.

**Locking.** All budget state lives behind one re-entrant mutex owned by the
:class:`Ledger` and shared with the :class:`BudgetManager`. A single lock
means there is no lock-ordering question and therefore no deadlock. It is a
:class:`threading.RLock`, deliberately, *not* an :class:`asyncio.Lock`: the
critical sections are a few dict and list operations with no I/O and no
``await``, so the same primitive is correct under threads, under asyncio, and
under both at once. An ``asyncio.Lock`` would be usable from only one event
loop and would not protect against worker threads at all.

**Decimal only.** Monetary amounts are :class:`~decimal.Decimal`, quantized to
1e-8, and :class:`float` is rejected outright at every entry point. Rounding is
always *conservative for the governor*: costs round up, credits round down.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from collections import deque
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, InvalidOperation
from enum import Enum, unique
from typing import TYPE_CHECKING, Final

from agentgov.exceptions import (
    BudgetExceededError,
    CircuitOpenError,
    DenialOfWalletError,
    DoubleSpendError,
    DuplicateScopeError,
    LedgerIntegrityError,
    RunawayLoopDetectedError,
    SubBudgetAllocationError,
    UnknownScopeError,
)

if TYPE_CHECKING:
    # Storage imports core (LedgerEntry, ControlEvent, ...) for its Protocol
    # methods; guarding this import under TYPE_CHECKING avoids the cycle
    # while still giving mypy the real type for the `store=` parameters.
    from agentgov.storage import PersistenceStore

__all__ = [
    "GENESIS_HASH",
    "MAX_AMOUNT",
    "QUANTUM",
    "Authorization",
    "BudgetManager",
    "BudgetNode",
    "ControlEvent",
    "Direction",
    "EntryType",
    "GovernancePolicy",
    "Ledger",
    "LedgerEntry",
    "LedgerLine",
    "format_audit_line",
    "money",
]

audit_log: Final = logging.getLogger("agentgov.audit")

QUANTUM: Final = Decimal("0.00000001")
"""Smallest representable monetary unit: 1e-8 USD.

Sub-cent agent traffic makes cent precision useless — a single Haiku call can
cost well under $0.0001 — so the ledger settles in hundred-millionths and
never in floating point.
"""

ZERO: Final = Decimal("0")
MAX_AMOUNT: Final = Decimal("1000000000000")
"""Hard ceiling on any single amount (1e12 USD). A request above this is
rejected as malformed rather than quantized, which keeps ``Decimal`` well
inside its default 28-digit context and catches unit-confusion bugs."""

GENESIS_HASH: Final = "0" * 64
"""``prev_hash`` of the first entry in a chain."""

_AUDIT_VERSION: Final = "AGOV1"


# --------------------------------------------------------------------------
# Money
# --------------------------------------------------------------------------


def money(value: Decimal | int | str) -> Decimal:
    """Construct a quantized monetary :class:`~decimal.Decimal`.

    ``float`` is rejected: binary floating point cannot represent ``0.1``
    exactly, and a ledger that accepts it will eventually fail to balance.
    Pass a ``str`` or a ``Decimal`` instead.

    :param value: The amount, as a ``Decimal``, ``int``, or decimal ``str``.
    :returns: The amount quantized to :data:`QUANTUM`, rounded down.
    :raises TypeError: If ``value`` is a ``float``.
    :raises ValueError: If ``value`` is not a valid decimal amount, or
        exceeds :data:`MAX_AMOUNT` in magnitude.
    """
    return _coerce(value, rounding=ROUND_FLOOR, label="amount")


def _coerce(
    value: Decimal | int | str,
    *,
    rounding: str,
    label: str,
) -> Decimal:
    """Coerce ``value`` to a quantized ``Decimal`` with the given rounding."""
    if isinstance(value, float):
        raise TypeError(
            f"{label} must not be a float (binary floating point cannot "
            f"represent decimal money exactly); pass a Decimal or str"
        )
    if not isinstance(value, Decimal):
        try:
            value = Decimal(value)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError(f"{label} is not a valid decimal: {value!r}") from exc
    if not value.is_finite():
        raise ValueError(f"{label} must be finite, got {value}")
    if abs(value) > MAX_AMOUNT:
        raise ValueError(f"{label} exceeds the maximum of {MAX_AMOUNT}: {value}")
    return value.quantize(QUANTUM, rounding=rounding)


def _cost(value: Decimal | int | str) -> Decimal:
    """Quantize an amount the governor pays out, rounding **up**.

    Costs, holds, and spends round toward the ceiling so the ledger can never
    under-record what an agent consumed.
    """
    return _coerce(value, rounding=ROUND_CEILING, label="cost")


def _credit(value: Decimal | int | str) -> Decimal:
    """Quantize an amount the governor grants, rounding **down**.

    Fundings, allocations, and refunds round toward the floor so the governor
    can never over-issue spending power.
    """
    return _coerce(value, rounding=ROUND_FLOOR, label="credit")


# --------------------------------------------------------------------------
# Ledger vocabulary
# --------------------------------------------------------------------------


@unique
class Direction(Enum):
    """Which way a ledger line moves a scope's available balance."""

    DEBIT = "DR"
    """Decreases the scope's available balance."""

    CREDIT = "CR"
    """Increases the scope's available balance."""


@unique
class EntryType(Enum):
    """The economic event a :class:`LedgerEntry` records."""

    FUNDING = "funding"
    """External treasury issuing a spend envelope to a root scope. CREDIT."""

    ALLOCATION = "allocation"
    """Parent delegating budget to a child. Posts a balanced DEBIT (parent)
    and CREDIT (child) pair in one transaction."""

    RELEASE = "release"
    """Child returning unused budget to its parent. Posts a balanced DEBIT
    (child) and CREDIT (parent) pair in one transaction."""

    HOLD = "hold"
    """Authorization hold placed before a call. DEBIT: the funds are
    encumbered and invisible to concurrent siblings until settled."""

    HOLD_VOID = "hold_void"
    """An authorization hold lifted, on capture or cancellation. CREDIT."""

    SPEND = "spend"
    """Settled, irreversible outflow to an external vendor. DEBIT."""

    REVERSAL = "reversal"
    """Refund of a previously settled :attr:`SPEND`. CREDIT."""


_LEGAL_DIRECTIONS: Final[Mapping[EntryType, frozenset[Direction]]] = {
    EntryType.FUNDING: frozenset({Direction.CREDIT}),
    EntryType.ALLOCATION: frozenset({Direction.DEBIT, Direction.CREDIT}),
    EntryType.RELEASE: frozenset({Direction.DEBIT, Direction.CREDIT}),
    EntryType.HOLD: frozenset({Direction.DEBIT}),
    EntryType.HOLD_VOID: frozenset({Direction.CREDIT}),
    EntryType.SPEND: frozenset({Direction.DEBIT}),
    EntryType.REVERSAL: frozenset({Direction.CREDIT}),
}

_BALANCED_TYPES: Final = frozenset({EntryType.ALLOCATION, EntryType.RELEASE})
"""Entry types that move money *between* scopes and must therefore post
equal debits and credits within a single transaction."""


@dataclass(frozen=True, slots=True)
class LedgerLine:
    """An unposted instruction: one leg of a transaction, before it is written.

    :ivar entry_type: The economic event this leg belongs to.
    :ivar direction: Whether this leg debits or credits ``scope_id``.
    :ivar scope_id: The scope whose balance this leg moves.
    :ivar amount: Strictly positive amount; direction carries the sign.
    :ivar counterparty_id: The other side of the movement — the parent, the
        child, or ``None`` for the external boundary (treasury or vendor).
    :ivar memo: Free-form audit context. Never affects balances.
    """

    entry_type: EntryType
    direction: Direction
    scope_id: str
    amount: Decimal
    counterparty_id: str | None = None
    memo: str = ""


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """A single, immutable, hash-chained record of one economic event.

    Entries are only ever constructed by :meth:`Ledger.post`, which computes
    the hash chain. Every field participates in ``entry_hash``, so altering
    any of them after the fact is detectable by :meth:`Ledger.verify_chain`.

    :ivar sequence: Strictly increasing position in the chain, starting at 1.
    :ivar entry_id: Globally unique identifier for this line.
    :ivar transaction_id: Shared by every line posted atomically together.
    :ivar timestamp: UTC instant the entry was committed.
    :ivar entry_type: The economic event recorded.
    :ivar direction: Whether this line debits or credits ``scope_id``.
    :ivar scope_id: The scope whose balance this line moves.
    :ivar counterparty_id: The other side, or ``None`` at the external boundary.
    :ivar amount: Strictly positive amount, quantized to :data:`QUANTUM`.
    :ivar balance_after: ``scope_id``'s running balance once this line was
        applied. Attested by the hash, so the chain proves the balance history
        and not merely the movement history.
    :ivar prev_hash: ``entry_hash`` of the preceding entry, or
        :data:`GENESIS_HASH`.
    :ivar entry_hash: SHA-256 over ``prev_hash`` and every field above.
    :ivar memo: Free-form audit context.
    """

    sequence: int
    entry_id: uuid.UUID
    transaction_id: uuid.UUID
    timestamp: datetime
    entry_type: EntryType
    direction: Direction
    scope_id: str
    counterparty_id: str | None
    amount: Decimal
    balance_after: Decimal
    prev_hash: str
    entry_hash: str
    memo: str = ""

    @property
    def signed_amount(self) -> Decimal:
        """The amount as applied to ``scope_id``'s balance (negative for a
        :attr:`Direction.DEBIT`)."""
        return self.amount if self.direction is Direction.CREDIT else -self.amount

    def recompute_hash(self) -> str:
        """Re-derive this entry's hash from its own fields.

        :returns: The SHA-256 hex digest this entry *should* carry.
        """
        return _hash_entry(
            prev_hash=self.prev_hash,
            sequence=self.sequence,
            entry_id=self.entry_id,
            transaction_id=self.transaction_id,
            timestamp=self.timestamp,
            entry_type=self.entry_type,
            direction=self.direction,
            scope_id=self.scope_id,
            counterparty_id=self.counterparty_id,
            amount=self.amount,
            balance_after=self.balance_after,
            memo=self.memo,
        )

    def to_audit_record(self) -> dict[str, str]:
        """Render this entry as a flat, machine-readable audit record.

        Suitable for emitting as JSON Lines into a compliance archive; every
        value is a string so the record survives any downstream transport
        without numeric coercion.
        """
        return {
            "version": _AUDIT_VERSION,
            "sequence": str(self.sequence),
            "entry_id": str(self.entry_id),
            "transaction_id": str(self.transaction_id),
            "timestamp": _iso(self.timestamp),
            "entry_type": self.entry_type.value,
            "direction": self.direction.value,
            "scope_id": self.scope_id,
            "counterparty_id": self.counterparty_id or "",
            "amount": str(self.amount),
            "balance_after": str(self.balance_after),
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "memo": self.memo,
        }


def _iso(moment: datetime) -> str:
    """Format a UTC datetime as a fixed-width ISO-8601 instant."""
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _parse_iso(text: str) -> datetime:
    """Inverse of :func:`_iso`.

    Exact round-trip precision matters here: a persisted entry's hash was
    computed over ``_iso(timestamp)``, so reloading it from storage and
    reformatting a *different* datetime representation would make
    :meth:`LedgerEntry.recompute_hash` disagree with the stored hash even
    though nothing was tampered with.
    """
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _hash_entry(
    *,
    prev_hash: str,
    sequence: int,
    entry_id: uuid.UUID,
    transaction_id: uuid.UUID,
    timestamp: datetime,
    entry_type: EntryType,
    direction: Direction,
    scope_id: str,
    counterparty_id: str | None,
    amount: Decimal,
    balance_after: Decimal,
    memo: str,
) -> str:
    """Compute the chain hash for one entry.

    The payload is JSON with a fixed field order, which gives unambiguous
    escaping for scope ids and memos that contain arbitrary text — a
    delimiter-joined payload could be forged by embedding the delimiter.
    """
    payload = json.dumps(
        [
            _AUDIT_VERSION,
            prev_hash,
            sequence,
            str(entry_id),
            str(transaction_id),
            _iso(timestamp),
            entry_type.value,
            direction.value,
            scope_id,
            counterparty_id,
            str(amount),
            str(balance_after),
            memo,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def format_audit_line(entry: LedgerEntry) -> str:
    """Render an entry as a single fixed-field audit log line.

    The shape is deliberately grep-friendly and column-stable, in the spirit
    of a wire-transfer journal::

        AGOV1|seq=0000000007|txn=<uuid>|ts=...Z|type=spend|dir=DR
              |scope=agent.research|cpty=-|amt=0.00004500|bal=0.09991000|h=1a2b3c4d

    :param entry: The entry to render.
    :returns: One line of audit output, with no trailing newline.
    """
    return (
        f"{_AUDIT_VERSION}"
        f"|seq={entry.sequence:010d}"
        f"|txn={entry.transaction_id}"
        f"|ts={_iso(entry.timestamp)}"
        f"|type={entry.entry_type.value}"
        f"|dir={entry.direction.value}"
        f"|scope={entry.scope_id}"
        f"|cpty={entry.counterparty_id or '-'}"
        f"|amt={entry.amount}"
        f"|bal={entry.balance_after}"
        f"|h={entry.entry_hash[:16]}" + (f"|memo={entry.memo}" if entry.memo else "")
    )


@dataclass(frozen=True, slots=True)
class _Totals:
    """Boundary totals used to verify the conservation identity."""

    funded: Decimal = ZERO
    spent: Decimal = ZERO
    reversed_: Decimal = ZERO
    holds_open: Decimal = ZERO


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------


class Ledger:
    """An append-only, hash-chained, double-entry store of ledger entries.

    The ledger is the single source of truth for every dollar in the system.
    It guarantees:

    - **Append-only** — entries are frozen and never removed.
    - **Atomic** — :meth:`post` validates every line of a transaction before
      writing any of them, so a transaction is all-or-nothing even under
      concurrent writers.
    - **Tamper-evident** — :meth:`verify_chain` re-derives the SHA-256 chain
      and catches any retroactive edit, including edits to running balances.
    - **Reconcilable** — cached balances are maintained incrementally for
      O(1) reads, and :meth:`replay` recomputes them from the raw chain so
      the two can be checked against each other.

    All state is guarded by :attr:`lock`, a re-entrant mutex that the owning
    :class:`BudgetManager` shares rather than nesting its own beneath.
    """

    def __init__(self, *, store: PersistenceStore | None = None) -> None:
        self._entries: list[LedgerEntry] = []
        self._balances: dict[str, Decimal] = {}
        self._totals = _Totals()
        self._head_hash: str = GENESIS_HASH
        self._lock = threading.RLock()
        self._store: PersistenceStore | None = store

        if store is not None:
            loaded = store.load_entries()
            self._entries = list(loaded)
            for entry in self._entries:
                self._balances[entry.scope_id] = (
                    self._balances.get(entry.scope_id, ZERO) + entry.signed_amount
                )
            self._totals = _apply_totals(_Totals(), self._entries)
            self._head_hash = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
            # Fail closed: a database that has been tampered with, or that
            # was corrupted by a crash mid-write, must never be trusted
            # silently. Refuse to start rather than serve a wrong balance.
            self.verify_chain()

    # -- introspection ----------------------------------------------------

    @property
    def lock(self) -> threading.RLock:
        """The mutex guarding all ledger state.

        Exposed so a :class:`BudgetManager` can make a check-then-post
        sequence atomic without introducing a second lock (and with it, a
        lock-ordering hazard).
        """
        return self._lock

    @property
    def store(self) -> PersistenceStore | None:
        """The durable backend this ledger writes through to, if any."""
        return self._store

    def close(self) -> None:
        """Close the underlying store's connection, if this ledger has one.

        A no-op when this ledger has no store. Safe to call more than once.
        """
        if self._store is not None:
            self._store.close()

    @property
    def head_hash(self) -> str:
        """``entry_hash`` of the most recent entry, or :data:`GENESIS_HASH`.

        This value commits to the entire history: quoting it in an external
        system anchors that system's records to this ledger.
        """
        with self._lock:
            return self._head_hash

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def entries(self) -> tuple[LedgerEntry, ...]:
        """Return every entry, oldest first."""
        with self._lock:
            return tuple(self._entries)

    def entries_for_scope(self, scope_id: str) -> tuple[LedgerEntry, ...]:
        """Return every entry touching ``scope_id``, oldest first.

        :param scope_id: The scope to retrieve history for.
        """
        with self._lock:
            return tuple(e for e in self._entries if e.scope_id == scope_id)

    def balance(self, scope_id: str) -> Decimal:
        """Return ``scope_id``'s current available balance.

        Served from the incrementally maintained cache; use :meth:`replay`
        to recompute it from the chain instead.

        :param scope_id: The scope to read.
        :returns: The available balance, or zero for an unseen scope.
        """
        with self._lock:
            return self._balances.get(scope_id, ZERO)

    def balances(self) -> dict[str, Decimal]:
        """Return a snapshot of every scope's balance."""
        with self._lock:
            return dict(self._balances)

    # -- writing ----------------------------------------------------------

    def post(
        self,
        lines: Sequence[LedgerLine],
        *,
        transaction_id: uuid.UUID | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """Atomically commit ``lines`` as one transaction.

        Validation happens in full before anything is appended, so a rejected
        transaction leaves no partial trace. Balances are threaded through the
        transaction, which lets a single transaction both credit and debit the
        same scope (as a capture does: void the hold, post the spend).

        :param lines: One or more legs to commit together.
        :param transaction_id: Optional caller-supplied transaction id;
            generated when omitted.
        :returns: The committed entries, in the order given.
        :raises ValueError: If ``lines`` is empty, an amount is non-positive
            or out of range, or a ``(entry_type, direction)`` pair is illegal.
        :raises LedgerIntegrityError: If a transfer transaction's debits and
            credits do not balance.
        """
        if not lines:
            raise ValueError("a transaction must contain at least one line")

        with self._lock:
            txn_id = transaction_id or uuid.uuid4()
            now = datetime.now(UTC)

            # -- phase 1: validate and build. Nothing is committed yet, so
            #    any raise below leaves the ledger exactly as it was.
            transfer_net = ZERO
            working_balances: dict[str, Decimal] = {}
            prev_hash = self._head_hash
            sequence = len(self._entries)
            built: list[LedgerEntry] = []

            for line in lines:
                legal = _LEGAL_DIRECTIONS[line.entry_type]
                if line.direction not in legal:
                    raise ValueError(
                        f"{line.entry_type.value} may not be a {line.direction.value} line"
                    )
                amount = _coerce(line.amount, rounding=ROUND_FLOOR, label="line amount")
                if amount != line.amount:
                    raise ValueError(f"line amount {line.amount} is not quantized to {QUANTUM}")
                if amount <= ZERO:
                    raise ValueError(f"line amount must be positive, got {amount}")

                if line.entry_type in _BALANCED_TYPES:
                    transfer_net += amount if line.direction is Direction.CREDIT else -amount

                signed = amount if line.direction is Direction.CREDIT else -amount
                current = working_balances.get(
                    line.scope_id, self._balances.get(line.scope_id, ZERO)
                )
                balance_after = current + signed
                working_balances[line.scope_id] = balance_after

                sequence += 1
                entry_id = uuid.uuid4()
                entry_hash = _hash_entry(
                    prev_hash=prev_hash,
                    sequence=sequence,
                    entry_id=entry_id,
                    transaction_id=txn_id,
                    timestamp=now,
                    entry_type=line.entry_type,
                    direction=line.direction,
                    scope_id=line.scope_id,
                    counterparty_id=line.counterparty_id,
                    amount=amount,
                    balance_after=balance_after,
                    memo=line.memo,
                )
                built.append(
                    LedgerEntry(
                        sequence=sequence,
                        entry_id=entry_id,
                        transaction_id=txn_id,
                        timestamp=now,
                        entry_type=line.entry_type,
                        direction=line.direction,
                        scope_id=line.scope_id,
                        counterparty_id=line.counterparty_id,
                        amount=amount,
                        balance_after=balance_after,
                        prev_hash=prev_hash,
                        entry_hash=entry_hash,
                        memo=line.memo,
                    )
                )
                prev_hash = entry_hash

            if transfer_net != ZERO:
                raise LedgerIntegrityError(
                    f"transfer transaction does not balance: net {transfer_net}"
                )

            # -- phase 2: durable write, then commit to memory. Writing
            #    through to the store *before* mutating in-memory state means
            #    a store failure (disk full, I/O error) leaves the ledger
            #    exactly as it was — the same all-or-nothing guarantee as an
            #    in-memory-only rejection, just extended across the disk.
            if self._store is not None:
                self._store.append_entries(built)

            self._entries.extend(built)
            self._balances.update(working_balances)
            self._head_hash = prev_hash
            self._totals = _apply_totals(self._totals, built)

        for entry in built:
            audit_log.info(
                format_audit_line(entry),
                extra={"agentgov_entry": entry.to_audit_record()},
            )
        return tuple(built)

    # -- verification -----------------------------------------------------

    def replay(self) -> tuple[dict[str, Decimal], _Totals]:
        """Recompute balances and boundary totals from the raw chain.

        :returns: A ``(balances, totals)`` pair derived from nothing but the
            entries themselves.
        """
        with self._lock:
            balances: dict[str, Decimal] = {}
            for entry in self._entries:
                balances[entry.scope_id] = balances.get(entry.scope_id, ZERO) + entry.signed_amount
            return balances, _apply_totals(_Totals(), self._entries)

    def verify_chain(self) -> None:
        """Verify the hash chain, sequence numbering, and balance cache.

        :raises LedgerIntegrityError: On the first inconsistency found —
            a broken link, a re-derived hash that does not match, a sequence
            gap, or a cached balance that disagrees with a full replay.
        """
        with self._lock:
            prev_hash = GENESIS_HASH
            for index, entry in enumerate(self._entries, start=1):
                if entry.sequence != index:
                    raise LedgerIntegrityError(
                        f"sequence gap at position {index}: entry claims {entry.sequence}",
                        entry.scope_id,
                    )
                if entry.prev_hash != prev_hash:
                    raise LedgerIntegrityError(
                        f"broken chain link at sequence {entry.sequence}",
                        entry.scope_id,
                    )
                if entry.recompute_hash() != entry.entry_hash:
                    raise LedgerIntegrityError(
                        f"entry {entry.sequence} has been tampered with (hash mismatch)",
                        entry.scope_id,
                    )
                prev_hash = entry.entry_hash

            if prev_hash != self._head_hash:
                raise LedgerIntegrityError("head hash does not match the chain")

            replayed, totals = self.replay()
            for scope_id, cached in self._balances.items():
                if replayed.get(scope_id, ZERO) != cached:
                    raise LedgerIntegrityError(
                        f"cached balance {cached} disagrees with replayed "
                        f"balance {replayed.get(scope_id, ZERO)}",
                        scope_id,
                    )
            if totals != self._totals:
                raise LedgerIntegrityError("cached boundary totals disagree with replay")

    def verify_conservation(self) -> None:
        """Verify that money is neither created nor destroyed.

        Checks the identity::

            Σ(balances) + holds_open + spent - reversed == funded

        Allocations and releases net to zero across scopes and so drop out;
        what remains is the boundary with the outside world.

        :raises LedgerIntegrityError: If the identity does not hold exactly.
        """
        with self._lock:
            total_balance = sum(self._balances.values(), ZERO)
            t = self._totals
            left = total_balance + t.holds_open + t.spent - t.reversed_
            if left != t.funded:
                raise LedgerIntegrityError(
                    f"conservation violated: balances {total_balance} + holds "
                    f"{t.holds_open} + spent {t.spent} - reversed {t.reversed_} "
                    f"= {left}, but funded = {t.funded}"
                )


def _apply_totals(totals: _Totals, entries: Sequence[LedgerEntry]) -> _Totals:
    """Fold ``entries`` into the running boundary totals."""
    funded, spent, reversed_, holds = (
        totals.funded,
        totals.spent,
        totals.reversed_,
        totals.holds_open,
    )
    for entry in entries:
        match entry.entry_type:
            case EntryType.FUNDING:
                funded += entry.amount
            case EntryType.SPEND:
                spent += entry.amount
            case EntryType.REVERSAL:
                reversed_ += entry.amount
            case EntryType.HOLD:
                holds += entry.amount
            case EntryType.HOLD_VOID:
                holds -= entry.amount
            case _:
                pass
    return _Totals(funded=funded, spent=spent, reversed_=reversed_, holds_open=holds)


# --------------------------------------------------------------------------
# Budget topology
# --------------------------------------------------------------------------


@dataclass(slots=True)
class BudgetNode:
    """One scope in the hierarchical spend-delegation tree.

    A node is an agent, sub-agent, or tool-call scope. It carries *structure*
    only — the authoritative balance lives in the :class:`Ledger`, so there is
    exactly one place a dollar can be counted.

    :ivar scope_id: Unique, permanent identifier for this scope.
    :ivar parent_id: The delegating parent, or ``None`` for a root.
    :ivar depth: Distance from the root; a root is depth 0.
    :ivar allocated: Lifetime total ever credited to this node. Monotonic;
        it is a provenance record, not a balance.
    :ivar child_ids: Scopes this node has delegated budget to.
    :ivar created_at: UTC instant the scope was opened.
    """

    scope_id: str
    parent_id: str | None
    depth: int
    allocated: Decimal
    child_ids: list[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class Authorization:
    """An outstanding hold placed against a scope before a call is made.

    Between :meth:`BudgetManager.authorize` and its settlement the held funds
    are encumbered: they are already debited from the scope's available
    balance, so a concurrent sibling cannot also spend them. This is the
    mechanism that makes double-spend structurally impossible rather than
    merely improbable.

    :ivar authorization_id: Unique identifier for this hold.
    :ivar scope_id: The scope whose funds are encumbered.
    :ivar amount: The encumbered amount.
    :ivar opened_at: UTC instant the hold was placed.
    :ivar entry: The :attr:`EntryType.HOLD` entry that recorded it.
    """

    authorization_id: uuid.UUID
    scope_id: str
    amount: Decimal
    opened_at: datetime
    entry: LedgerEntry


@dataclass(frozen=True, slots=True)
class ControlEvent:
    """A non-financial governance event, recorded alongside the ledger.

    Circuit-breaker trips and resets move no money, so they do not belong in
    a financial ledger — but they must still be auditable. Each event pins
    :attr:`ledger_head_hash`, anchoring it to an exact position in the
    financial chain.

    :ivar event_id: Unique identifier for this event.
    :ivar timestamp: UTC instant the event occurred.
    :ivar event_type: ``"circuit_tripped"`` or ``"circuit_reset"``.
    :ivar scope_id: The scope the control action applied to.
    :ivar reason: Human-readable justification.
    :ivar ledger_head_hash: The ledger's head hash at the time of the event.
    """

    event_id: uuid.UUID
    timestamp: datetime
    event_type: str
    scope_id: str
    reason: str
    ledger_head_hash: str


@dataclass(slots=True)
class _BreakerState:
    """Per-scope circuit-breaker and velocity state."""

    tripped_at: datetime | None = None
    reason: str = ""
    call_times: deque[float] = field(default_factory=deque)


@dataclass(frozen=True, slots=True)
class GovernancePolicy:
    """Tunable limits enforced by the :class:`BudgetManager`.

    :ivar max_calls_per_window: Authorizations a single scope may make within
        ``window_seconds`` before the runaway-loop detector trips it. This
        catches a tight loop *before* it converts into spend.

        The default of 1000/s is deliberately far above any human-paced
        workload: this is a backstop against a tight machine loop, not a rate
        limiter. A legitimately high-throughput fleet should never meet it —
        an earlier default of 200/s tripped on this project's own benchmarks,
        which is exactly the false positive a safety control must not have.
    :ivar window_seconds: Length of the velocity detection window.
    :ivar max_depth: Maximum delegation depth below a root. Bounds recursive
        sub-agent spawning independently of the dollar budget.
    :ivar trip_on_overdraft: Trip the breaker when a scope attempts to spend
        more than it has, raising
        :class:`~agentgov.exceptions.DenialOfWalletError`. Leave enabled: this
        is the denial-of-wallet backstop. Disabling it puts the governor in
        advisory mode — the overdraw is still refused, with a plain
        :class:`~agentgov.exceptions.BudgetExceededError`, but siblings keep
        running. A *realized* overdraft at capture time always halts the
        scope regardless of this flag, because that money is already gone.
    :ivar trip_on_exhaustion: Trip the breaker when a scope's balance reaches
        exactly zero with no holds outstanding, so the next call fails fast
        instead of racing to the same conclusion.
    """

    max_calls_per_window: int = 1000
    window_seconds: float = 1.0
    max_depth: int = 8
    trip_on_overdraft: bool = True
    trip_on_exhaustion: bool = True


# --------------------------------------------------------------------------
# BudgetManager
# --------------------------------------------------------------------------


class BudgetManager:
    """The spend governor: a hierarchical budget DAG over an immutable ledger.

    Enforces the delegation invariant — no scope may spend or sub-delegate
    more than its ancestors granted it — and backstops the whole tree with a
    latching circuit breaker.

    The topology is a rooted tree (a DAG in which every node has at most one
    parent). Phase 1 does not support a scope with multiple parents: shared
    envelopes make the conservation identity ambiguous, and getting that wrong
    is precisely the double-spend this component exists to prevent.

    Typical use::

        manager = BudgetManager()
        manager.open_root("orchestrator", money("1.00"))
        manager.delegate("orchestrator", "researcher", money("0.25"))

        auth = manager.authorize("researcher", money("0.01"))
        response = call_the_model()          # no lock held across I/O
        manager.capture(auth, actual_cost)

    For a durable governor whose ledger and topology survive a process
    restart, use :meth:`open_sqlite` instead of constructing this directly.

    :param ledger: The ledger to record against; a fresh one is created when
        omitted. Its mutex becomes this manager's mutex.
    :param policy: Governance limits; defaults to :class:`GovernancePolicy`.
    :param store: A durable backend for topology, control events, and open
        authorizations. Pass the *same* store given to ``ledger`` (or omit
        ``ledger`` and let this constructor build one) — mismatched stores
        leave the ledger and the topology recovering from different
        histories. :meth:`open_sqlite` sets this up correctly in one call.
    """

    def __init__(
        self,
        *,
        ledger: Ledger | None = None,
        policy: GovernancePolicy | None = None,
        store: PersistenceStore | None = None,
    ) -> None:
        self._ledger = ledger if ledger is not None else Ledger(store=store)
        self._policy = policy if policy is not None else GovernancePolicy()
        # One mutex for the whole control plane. Sharing the ledger's lock
        # (rather than nesting a second one under it) removes any possibility
        # of a lock-ordering deadlock.
        self._lock = self._ledger.lock
        self._store: PersistenceStore | None = store
        self._nodes: dict[str, BudgetNode] = {}
        self._roots: list[str] = []
        self._breakers: dict[str, _BreakerState] = {}
        self._open_auths: dict[uuid.UUID, Authorization] = {}
        self._control_events: list[ControlEvent] = []

        if store is not None:
            self._restore_from_store(store)

    @classmethod
    def open_sqlite(
        cls,
        path: str,
        *,
        policy: GovernancePolicy | None = None,
        synchronous: str = "FULL",
        read_only: bool = False,
    ) -> BudgetManager:
        """Open (or create) a durable, SQLite-backed governor in one call.

        The ledger, topology, control events, and any open authorizations
        are restored from ``path`` if it already contains a governor's
        state, and freshly created otherwise. The returned manager owns the
        underlying connection — call :meth:`close` (or use it as a context
        manager) when you are done with it.

        :param path: Filesystem path to the SQLite database file. Use
            ``":memory:"`` for a store that never touches disk (tests only —
            it does not survive a restart).
        :param policy: Governance limits; defaults to :class:`GovernancePolicy`.
        :param synchronous: SQLite's ``synchronous`` pragma. ``"FULL"``
            (the default) fsyncs on every commit and survives a power loss,
            not just a process crash, at the cost of write latency.
            ``"NORMAL"`` is safe against a process crash but can lose the
            most recent commits on a full power loss; pass it only when a
            slower write path is the actual bottleneck.
        :param read_only: Open for audit without claiming the database, so
            a ledger another process is actively governing can still be
            inspected and verified. Every mutating call then raises
            :class:`~agentgov.exceptions.ReadOnlyLedgerError`.
        :returns: A restored or freshly created :class:`BudgetManager`.
        :raises agentgov.exceptions.ConcurrentGovernorError: If another
            process already holds this database for writing. Two governors
            would each cache authoritative balances in memory and diverge,
            so the second is refused at open rather than on its first write.
        :raises agentgov.exceptions.LedgerIntegrityError: If the database's
            chain, balances, or topology are inconsistent — a corrupted or
            tampered file is refused rather than trusted.
        """
        from agentgov.storage import SqliteStore

        store = SqliteStore(path, synchronous=synchronous, read_only=read_only)
        try:
            return cls(policy=policy, store=store)
        except BaseException:
            # Never leak the advisory claim if restore-and-verify rejects the
            # file: the next process to try must not be told it is contended.
            store.close()
            raise

    def __enter__(self) -> BudgetManager:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying durable store, if this manager has one.

        A no-op for a manager with no store. Safe to call more than once.
        """
        self._ledger.close()

    def _restore_from_store(self, store: PersistenceStore) -> None:
        """Rebuild topology, breaker state, and open holds from ``store``.

        Called once, from the constructor, before this manager is visible to
        any other code — no lock is needed yet.

        :raises LedgerIntegrityError: If the persisted topology references a
            scope or ledger entry that does not exist. A corrupted or
            partially written database is refused, never trusted.
        """
        for pnode in store.load_nodes():
            self._nodes[pnode.scope_id] = BudgetNode(
                scope_id=pnode.scope_id,
                parent_id=pnode.parent_id,
                depth=pnode.depth,
                allocated=pnode.allocated,
                created_at=pnode.created_at,
            )
            self._breakers[pnode.scope_id] = _BreakerState()

        for scope_id, node in self._nodes.items():
            if node.parent_id is None:
                self._roots.append(scope_id)
                continue
            parent = self._nodes.get(node.parent_id)
            if parent is None:
                raise LedgerIntegrityError(f"parent {node.parent_id!r} is not registered", scope_id)
            parent.child_ids.append(scope_id)

        # Control events are appended in chronological order, and each one
        # represents a genuine trip/reset transition (agentgov never records
        # a no-op trip or reset) — so replaying them in that order and simply
        # applying each one is sufficient to reconstruct final breaker state.
        self._control_events = list(store.load_control_events())
        for event in self._control_events:
            state = self._breakers.get(event.scope_id)
            if state is None:
                raise LedgerIntegrityError(
                    f"control event references unregistered scope {event.scope_id!r}"
                )
            if event.event_type == "circuit_tripped":
                state.tripped_at = event.timestamp
                state.reason = event.reason
            elif event.event_type == "circuit_reset":
                state.tripped_at = None
                state.reason = ""

        for pauth in store.load_open_authorizations():
            hold_entry = next(
                (
                    e
                    for e in self._ledger.entries_for_scope(pauth.scope_id)
                    if e.entry_id == pauth.entry_id
                ),
                None,
            )
            if hold_entry is None:
                raise LedgerIntegrityError(
                    f"open authorization {pauth.authorization_id} references "
                    f"missing hold entry {pauth.entry_id}",
                    pauth.scope_id,
                )
            self._open_auths[pauth.authorization_id] = Authorization(
                authorization_id=pauth.authorization_id,
                scope_id=pauth.scope_id,
                amount=pauth.amount,
                opened_at=pauth.opened_at,
                entry=hold_entry,
            )

        # Fail closed: the same standard the ledger's own chain check holds
        # itself to. A restored governor that does not check out is refused,
        # not served with degraded confidence.
        self.verify_integrity()

    # -- accessors --------------------------------------------------------

    @property
    def ledger(self) -> Ledger:
        """The immutable ledger backing this manager."""
        return self._ledger

    @property
    def policy(self) -> GovernancePolicy:
        """The governance limits in force."""
        return self._policy

    @property
    def store(self) -> PersistenceStore | None:
        """The durable backend this manager writes through to, if any."""
        return self._store

    @property
    def control_events(self) -> tuple[ControlEvent, ...]:
        """Every circuit-breaker trip and reset, oldest first."""
        with self._lock:
            return tuple(self._control_events)

    def node(self, scope_id: str) -> BudgetNode:
        """Return the :class:`BudgetNode` for ``scope_id``.

        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            return self._require_node(scope_id)

    def scopes(self) -> tuple[str, ...]:
        """Every registered scope id, in registration order."""
        with self._lock:
            return tuple(self._nodes)

    def available(self, scope_id: str) -> Decimal:
        """Return ``scope_id``'s spendable balance, net of outstanding holds.

        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            self._require_node(scope_id)
            return self._ledger.balance(scope_id)

    def subtree_available(self, scope_id: str) -> Decimal:
        """Return the total spendable balance of ``scope_id`` and everything
        delegated beneath it.

        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            total = self._ledger.balance(scope_id)
            for node in self.descendants(scope_id):
                total += self._ledger.balance(node.scope_id)
            return total

    def descendants(self, scope_id: str) -> Iterator[BudgetNode]:
        """Yield every node beneath ``scope_id``, breadth-first.

        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            frontier = list(self._require_node(scope_id).child_ids)
            order: list[BudgetNode] = []
            while frontier:
                child = self._nodes[frontier.pop(0)]
                order.append(child)
                frontier.extend(child.child_ids)
        yield from order

    def ancestry(self, scope_id: str) -> tuple[str, ...]:
        """Return ``scope_id`` and each ancestor above it, nearest first.

        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            chain: list[str] = []
            cursor: str | None = self._require_node(scope_id).scope_id
            while cursor is not None:
                chain.append(cursor)
                cursor = self._nodes[cursor].parent_id
            return tuple(chain)

    def audit_trail(self, scope_id: str | None = None) -> tuple[LedgerEntry, ...]:
        """Return the ledger entries for one scope, or the whole ledger.

        :param scope_id: Restrict to this scope, or ``None`` for everything.
        """
        if scope_id is None:
            return self._ledger.entries()
        return self._ledger.entries_for_scope(scope_id)

    # -- topology ---------------------------------------------------------

    def open_root(
        self,
        scope_id: str,
        envelope: Decimal | int | str,
        *,
        memo: str = "",
    ) -> BudgetNode:
        """Open a root scope and fund it with a spend envelope.

        :param scope_id: Identifier for the root agent.
        :param envelope: The total the agent and its whole subtree may spend.
        :param memo: Free-form audit context.
        :returns: The newly created root node.
        :raises DuplicateScopeError: If ``scope_id`` is already registered.
        :raises ValueError: If ``envelope`` is not positive.
        """
        amount = _credit(envelope)
        if amount <= ZERO:
            raise ValueError(f"envelope must be positive, got {amount}")

        with self._lock:
            if scope_id in self._nodes:
                raise DuplicateScopeError(scope_id)
            # Ledger truth before topology: if the durable write fails, no
            # node is registered for money that was never actually funded.
            entries = self._ledger.post(
                [
                    LedgerLine(
                        entry_type=EntryType.FUNDING,
                        direction=Direction.CREDIT,
                        scope_id=scope_id,
                        amount=amount,
                        counterparty_id=None,
                        memo=memo or "root envelope issued",
                    )
                ]
            )
            node = BudgetNode(
                scope_id=scope_id,
                parent_id=None,
                depth=0,
                allocated=amount,
                created_at=entries[0].timestamp,
            )
            self._nodes[scope_id] = node
            self._roots.append(scope_id)
            self._breakers[scope_id] = _BreakerState()
            if self._store is not None:
                self._store.upsert_node(scope_id, None, 0, amount, node.created_at)
            return node

    def fund(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
    ) -> LedgerEntry:
        """Top up an existing root scope from the external treasury.

        Only roots may be funded; a non-root scope receives money exclusively
        through :meth:`delegate`, which is what keeps the delegation invariant
        meaningful.

        :param scope_id: The root scope to credit.
        :param amount: The amount to add to its envelope.
        :param memo: Free-form audit context.
        :returns: The committed funding entry.
        :raises UnknownScopeError: If no such scope is registered.
        :raises ValueError: If ``scope_id`` is not a root or ``amount`` is
            not positive.
        """
        credited = _credit(amount)
        if credited <= ZERO:
            raise ValueError(f"funding must be positive, got {credited}")

        with self._lock:
            node = self._require_node(scope_id)
            if node.parent_id is not None:
                raise ValueError(f"scope {scope_id!r} is not a root; use delegate() to fund it")
            # Ledger truth before the provenance field: a failed durable
            # write must not leave `allocated` overstating what was funded.
            entries = self._ledger.post(
                [
                    LedgerLine(
                        entry_type=EntryType.FUNDING,
                        direction=Direction.CREDIT,
                        scope_id=scope_id,
                        amount=credited,
                        counterparty_id=None,
                        memo=memo or "envelope topped up",
                    )
                ]
            )
            node.allocated += credited
            if self._store is not None:
                self._store.upsert_node(
                    scope_id, node.parent_id, node.depth, node.allocated, node.created_at
                )
            return entries[0]

    def delegate(
        self,
        parent_id: str,
        child_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
    ) -> BudgetNode:
        """Sub-delegate part of ``parent_id``'s budget to a new child scope.

        The transfer is a balanced pair of ledger lines, so the parent's
        available balance drops by exactly what the child gains. A parent can
        never delegate money it does not hold, at any depth.

        :param parent_id: The delegating scope.
        :param child_id: Identifier for the new sub-agent scope.
        :param amount: The sub-limit to grant.
        :param memo: Free-form audit context.
        :returns: The newly created child node.
        :raises UnknownScopeError: If ``parent_id`` is not registered.
        :raises DuplicateScopeError: If ``child_id`` is already registered.
        :raises CircuitOpenError: If the parent's subtree is halted.
        :raises SubBudgetAllocationError: If the parent lacks the funds, or
            the delegation would exceed :attr:`GovernancePolicy.max_depth`.
        :raises ValueError: If ``amount`` is not positive.
        """
        granted = _credit(amount)
        if granted <= ZERO:
            raise ValueError(f"delegated amount must be positive, got {granted}")

        with self._lock:
            parent = self._require_node(parent_id)
            if child_id in self._nodes:
                raise DuplicateScopeError(child_id)
            self._assert_not_halted(parent_id)

            depth = parent.depth + 1
            if depth > self._policy.max_depth:
                raise SubBudgetAllocationError(
                    granted,
                    self._ledger.balance(parent_id),
                    parent_id,
                    f"delegation depth {depth} exceeds max_depth {self._policy.max_depth}",
                )

            available = self._ledger.balance(parent_id)
            if granted > available:
                raise SubBudgetAllocationError(granted, available, parent_id)

            # Ledger truth before topology: a failed durable write must not
            # leave a child scope registered for money that never moved.
            note = memo or f"sub-budget delegated to {child_id}"
            self._ledger.post(
                [
                    LedgerLine(
                        entry_type=EntryType.ALLOCATION,
                        direction=Direction.DEBIT,
                        scope_id=parent_id,
                        amount=granted,
                        counterparty_id=child_id,
                        memo=note,
                    ),
                    LedgerLine(
                        entry_type=EntryType.ALLOCATION,
                        direction=Direction.CREDIT,
                        scope_id=child_id,
                        amount=granted,
                        counterparty_id=parent_id,
                        memo=note,
                    ),
                ]
            )
            child = BudgetNode(
                scope_id=child_id, parent_id=parent_id, depth=depth, allocated=granted
            )
            self._nodes[child_id] = child
            self._breakers[child_id] = _BreakerState()
            parent.child_ids.append(child_id)
            if self._store is not None:
                self._store.upsert_node(child_id, parent_id, depth, granted, child.created_at)
            return child

    def release(
        self,
        scope_id: str,
        amount: Decimal | int | str | None = None,
        *,
        memo: str = "",
    ) -> Decimal:
        """Return unused budget from ``scope_id`` to its parent.

        Call this when a sub-agent finishes so its unspent allowance becomes
        available to its siblings instead of being stranded.

        :param scope_id: The child scope returning funds.
        :param amount: How much to return; defaults to everything available.
        :param memo: Free-form audit context.
        :returns: The amount actually returned (zero if nothing was left).
        :raises UnknownScopeError: If no such scope is registered.
        :raises ValueError: If ``scope_id`` is a root, or ``amount`` exceeds
            what is available.
        """
        with self._lock:
            node = self._require_node(scope_id)
            if node.parent_id is None:
                raise ValueError(f"root scope {scope_id!r} has no parent to release to")

            available = self._ledger.balance(scope_id)
            returned = available if amount is None else _credit(amount)
            if returned <= ZERO:
                return ZERO
            if returned > available:
                raise ValueError(
                    f"cannot release {returned} from {scope_id!r}: only {available} available"
                )

            note = memo or f"unused budget returned to {node.parent_id}"
            self._ledger.post(
                [
                    LedgerLine(
                        entry_type=EntryType.RELEASE,
                        direction=Direction.DEBIT,
                        scope_id=scope_id,
                        amount=returned,
                        counterparty_id=node.parent_id,
                        memo=note,
                    ),
                    LedgerLine(
                        entry_type=EntryType.RELEASE,
                        direction=Direction.CREDIT,
                        scope_id=node.parent_id,
                        amount=returned,
                        counterparty_id=scope_id,
                        memo=note,
                    ),
                ]
            )
            return returned

    # -- authorize / capture ---------------------------------------------

    def authorize(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
    ) -> Authorization:
        """Place an authorization hold before a billable call is made.

        This is the enforcement point. Under one lock acquisition it checks
        the breaker, records call velocity, verifies funds, and encumbers
        them — so two sub-agents racing for the last cent cannot both win.

        The hold amount rounds **up**, so an estimate can never under-reserve.

        :param scope_id: The scope that will make the call.
        :param amount: The estimated maximum cost of the call.
        :param memo: Free-form audit context.
        :returns: The :class:`Authorization` to settle with :meth:`capture`
            or :meth:`void`.
        :raises UnknownScopeError: If no such scope is registered.
        :raises CircuitOpenError: If this scope or an ancestor is halted.
        :raises RunawayLoopDetectedError: If call velocity exceeded the
            policy limit. Trips the breaker.
        :raises DenialOfWalletError: If ``amount`` exceeds the available
            balance. Trips the breaker; nothing is written to the ledger.
        :raises BudgetExceededError: Instead of the above, when
            :attr:`GovernancePolicy.trip_on_overdraft` is disabled — the spend
            is still refused, but the subtree keeps running.
        :raises ValueError: If ``amount`` is not positive.
        """
        held = _cost(amount)
        if held <= ZERO:
            raise ValueError(f"authorization amount must be positive, got {held}")

        with self._lock:
            self._require_node(scope_id)
            self._assert_not_halted(scope_id)
            self._record_velocity(scope_id)

            available = self._ledger.balance(scope_id)
            if held > available:
                if not self._policy.trip_on_overdraft:
                    # Advisory mode: refuse the spend but leave siblings running.
                    raise BudgetExceededError(held, available, scope_id)
                self._trip(
                    scope_id,
                    f"overdraft attempt: requested {held}, available {available}",
                )
                raise DenialOfWalletError(held, available, scope_id)

            entries = self._ledger.post(
                [
                    LedgerLine(
                        entry_type=EntryType.HOLD,
                        direction=Direction.DEBIT,
                        scope_id=scope_id,
                        amount=held,
                        counterparty_id=None,
                        memo=memo or "authorization hold",
                    )
                ]
            )
            auth = Authorization(
                authorization_id=uuid.uuid4(),
                scope_id=scope_id,
                amount=held,
                opened_at=datetime.now(UTC),
                entry=entries[0],
            )
            self._open_auths[auth.authorization_id] = auth
            if self._store is not None:
                self._store.put_authorization(
                    auth.authorization_id,
                    scope_id,
                    held,
                    auth.opened_at,
                    entries[0].entry_id,
                )
            return auth

    def capture(
        self,
        authorization: Authorization,
        actual_cost: Decimal | int | str,
        *,
        memo: str = "",
    ) -> LedgerEntry:
        """Settle an authorization at its true cost.

        Posts the hold's release and the real spend as one atomic transaction,
        so the scope's balance never transiently misrepresents its position.
        The settled cost rounds **up**.

        If ``actual_cost`` overruns what the hold covered *and* the scope
        cannot absorb the difference, the overage is still recorded — money
        that was really spent cannot be un-spent, and a ledger that hides it
        is worse than useless. The balance goes negative, the breaker trips,
        and :class:`DenialOfWalletError` is raised with ``overspent=True``.

        :param authorization: The hold returned by :meth:`authorize`.
        :param actual_cost: The true cost incurred.
        :param memo: Free-form audit context.
        :returns: The committed :attr:`EntryType.SPEND` entry.
        :raises DoubleSpendError: If this authorization was already settled.
        :raises DenialOfWalletError: If the settled cost overdrew the scope.
        :raises ValueError: If ``actual_cost`` is negative.
        """
        settled = _cost(actual_cost)
        if settled < ZERO:
            raise ValueError(f"actual cost must not be negative, got {settled}")

        with self._lock:
            self._require_open_authorization(authorization, "was already settled")

            if settled == ZERO:
                # Nothing was billed; the hold is simply lifted.
                return self._void_locked(authorization, memo or "captured at zero cost")

            note = memo or "settled call cost"
            entries = self._ledger.post(
                [
                    LedgerLine(
                        entry_type=EntryType.HOLD_VOID,
                        direction=Direction.CREDIT,
                        scope_id=authorization.scope_id,
                        amount=authorization.amount,
                        counterparty_id=None,
                        memo="authorization captured",
                    ),
                    LedgerLine(
                        entry_type=EntryType.SPEND,
                        direction=Direction.DEBIT,
                        scope_id=authorization.scope_id,
                        amount=settled,
                        counterparty_id=None,
                        memo=note,
                    ),
                ]
            )
            spend_entry = entries[1]
            # Only remove the hold from the open set once its settlement is
            # actually durable: a failed post() above leaves it open for a
            # retry or an operator to reconcile, instead of orphaning it.
            self._finalize_authorization(authorization)

            if spend_entry.balance_after < ZERO:
                overdraft = -spend_entry.balance_after
                self._trip(
                    authorization.scope_id,
                    f"settled cost {settled} overran authorization "
                    f"{authorization.amount}; overdrawn by {overdraft}",
                )
                raise DenialOfWalletError(
                    settled,
                    settled - overdraft,
                    authorization.scope_id,
                    overspent=True,
                )

            self._maybe_trip_on_exhaustion(authorization.scope_id)
            return spend_entry

    def void(self, authorization: Authorization, *, memo: str = "") -> LedgerEntry:
        """Cancel an authorization without spending, returning the held funds.

        :param authorization: The hold to cancel.
        :param memo: Free-form audit context.
        :returns: The committed :attr:`EntryType.HOLD_VOID` entry.
        :raises DoubleSpendError: If this authorization was already settled.
        """
        with self._lock:
            self._require_open_authorization(authorization, "was already settled")
            return self._void_locked(authorization, memo or "authorization voided")

    def spend(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
    ) -> LedgerEntry:
        """Authorize and capture a known cost in one step.

        Convenience for costs known before the call (a fixed per-call tool
        fee, say). When the cost is only known afterwards — as with token
        billing — use :meth:`authorize` and :meth:`capture` so the funds are
        encumbered while the call is in flight.

        :param scope_id: The spending scope.
        :param amount: The exact cost.
        :param memo: Free-form audit context.
        :returns: The committed spend entry.
        """
        with self._lock:
            auth = self.authorize(scope_id, amount, memo=memo)
            return self.capture(auth, amount, memo=memo)

    def refund(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
    ) -> LedgerEntry:
        """Record a vendor refund of previously settled spend.

        Posts a compensating credit. History is never rewritten: the original
        spend stays in the chain and the refund sits beside it.

        :param scope_id: The scope receiving the credit.
        :param amount: The refunded amount.
        :param memo: Free-form audit context.
        :returns: The committed :attr:`EntryType.REVERSAL` entry.
        :raises UnknownScopeError: If no such scope is registered.
        :raises ValueError: If ``amount`` is not positive.
        """
        credited = _credit(amount)
        if credited <= ZERO:
            raise ValueError(f"refund must be positive, got {credited}")

        with self._lock:
            self._require_node(scope_id)
            entries = self._ledger.post(
                [
                    LedgerLine(
                        entry_type=EntryType.REVERSAL,
                        direction=Direction.CREDIT,
                        scope_id=scope_id,
                        amount=credited,
                        counterparty_id=None,
                        memo=memo or "vendor refund",
                    )
                ]
            )
            return entries[0]

    # -- reconciliation ---------------------------------------------------

    def stale_authorizations(
        self, older_than: timedelta | float, *, scope_id: str | None = None
    ) -> tuple[Authorization, ...]:
        """Return holds that have been open longer than ``older_than``.

        A hold encumbers funds from the moment a call is authorized until it
        settles. A process that dies mid-call, or an HTTP request that hangs
        forever, leaves that encumbrance in place with nothing left to settle
        it — the money is neither spent nor available. This is how an operator
        finds those.

        Read-only and safe to call on a live governor; nothing is released.

        :param older_than: Age threshold, as a :class:`~datetime.timedelta`
            or a number of seconds.
        :param scope_id: Restrict to one scope, or ``None`` for every scope.
        :returns: Matching authorizations, oldest first.
        :raises UnknownScopeError: If ``scope_id`` is given but not registered.
        """
        window = older_than if isinstance(older_than, timedelta) else timedelta(seconds=older_than)
        cutoff = datetime.now(UTC) - window
        with self._lock:
            if scope_id is not None:
                self._require_node(scope_id)
            matching = [
                auth
                for auth in self._open_auths.values()
                if auth.opened_at <= cutoff and (scope_id is None or auth.scope_id == scope_id)
            ]
        return tuple(sorted(matching, key=lambda auth: auth.opened_at))

    def void_stale(
        self,
        older_than: timedelta | float,
        *,
        scope_id: str | None = None,
        memo: str = "",
    ) -> tuple[Authorization, ...]:
        """Release holds older than ``older_than``, returning the funds.

        Deliberately an explicit operator action rather than a background
        timer. Voiding a hold asserts that the call it was reserving funds for
        will never settle — and AgentGov cannot know that. If the call *is*
        still in flight and later completes, its capture will find the
        authorization already settled and raise
        :class:`~agentgov.exceptions.DoubleSpendError`, which is the correct
        outcome: the ledger refuses to book the same encumbrance twice.

        Every release is an ordinary :attr:`EntryType.HOLD_VOID` entry, so the
        reconciliation is as auditable as the spend would have been.

        :param older_than: Age threshold, as a :class:`~datetime.timedelta`
            or a number of seconds.
        :param scope_id: Restrict to one scope, or ``None`` for every scope.
        :param memo: Audit context for the releases.
        :returns: The authorizations that were voided, oldest first.
        :raises UnknownScopeError: If ``scope_id`` is given but not registered.
        """
        note = memo or "stale hold released by operator"
        voided: list[Authorization] = []
        for auth in self.stale_authorizations(older_than, scope_id=scope_id):
            with self._lock:
                # Re-check under the lock: a settlement may have landed
                # between the survey above and this release.
                if auth.authorization_id not in self._open_auths:
                    continue
                self._void_locked(auth, note)
                voided.append(auth)
        return tuple(voided)

    # -- circuit breaker --------------------------------------------------

    def is_halted(self, scope_id: str) -> bool:
        """Whether ``scope_id`` is halted by its own breaker or an ancestor's.

        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            self._require_node(scope_id)
            return self._halted_by(scope_id) is not None

    def halted_by(self, scope_id: str) -> str | None:
        """Return the scope whose open breaker halts ``scope_id``, if any.

        :returns: The tripped scope id — possibly ``scope_id`` itself — or
            ``None`` when the subtree is running.
        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            self._require_node(scope_id)
            return self._halted_by(scope_id)

    def trip(self, scope_id: str, reason: str) -> None:
        """Manually trip the breaker for ``scope_id`` and its whole subtree.

        :param scope_id: The scope to halt.
        :param reason: Why it was halted; recorded in the audit trail.
        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            self._require_node(scope_id)
            self._trip(scope_id, reason)

    def reset(self, scope_id: str) -> None:
        """Clear a tripped breaker so the scope may spend again.

        The breaker latches deliberately: a denial-of-wallet halt must not
        clear itself on a timer, because the loop that caused it usually has
        not stopped. Reset is an explicit operator action and is recorded.

        :param scope_id: The scope to re-arm.
        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            self._require_node(scope_id)
            state = self._breakers[scope_id]
            if state.tripped_at is None:
                return
            state.tripped_at = None
            state.reason = ""
            state.call_times.clear()
            self._record_control_event("circuit_reset", scope_id, "operator reset")

    # -- verification -----------------------------------------------------

    def verify_chain(self) -> None:
        """Re-derive the ledger's SHA-256 hash chain.

        A pass-through to :meth:`Ledger.verify_chain`. It lives here because
        the README names ``verify_chain()`` alongside ``verify_integrity()``
        and a reader has no reason to guess that one is on the manager and the
        other is a level down on ``manager.ledger``.

        :raises LedgerIntegrityError: If any entry's hash does not re-derive,
            or the chain's links do not match.
        """
        with self._lock:
            self._ledger.verify_chain()

    def verify_conservation(self) -> None:
        """Check that no money was created, destroyed, or double-counted.

        A pass-through to :meth:`Ledger.verify_conservation`, verifying::

            sum(scope balances) + outstanding_holds + settled_spend
                - reversals == funded

        Narrower than :meth:`verify_integrity`, which also re-derives the hash
        chain and the delegation topology. Use this when you want the
        accounting identity on its own.

        :raises LedgerIntegrityError: If the identity does not hold.
        """
        with self._lock:
            self._ledger.verify_conservation()

    def verify_integrity(self) -> None:
        """Run every invariant check over the ledger and the budget tree.

        Verifies the hash chain, the balance cache, the conservation identity,
        and the structural consistency of the delegation tree. Cheap enough to
        call in tests and at shutdown; the right thing to call before trusting
        a ledger you did not just build.

        :raises LedgerIntegrityError: On the first violation found.
        """
        with self._lock:
            self._ledger.verify_chain()
            self._ledger.verify_conservation()

            for scope_id, node in self._nodes.items():
                if node.parent_id is None:
                    if scope_id not in self._roots:
                        raise LedgerIntegrityError("parentless scope is not a root", scope_id)
                    continue
                parent = self._nodes.get(node.parent_id)
                if parent is None:
                    raise LedgerIntegrityError(
                        f"parent {node.parent_id!r} is not registered", scope_id
                    )
                if scope_id not in parent.child_ids:
                    raise LedgerIntegrityError(
                        f"not listed as a child of {node.parent_id!r}", scope_id
                    )
                if node.depth != parent.depth + 1:
                    raise LedgerIntegrityError(
                        f"depth {node.depth} is inconsistent with parent depth {parent.depth}",
                        scope_id,
                    )
                # Walking to a root also proves the graph is acyclic.
                seen = {scope_id}
                cursor: str | None = node.parent_id
                while cursor is not None:
                    if cursor in seen:
                        raise LedgerIntegrityError("delegation cycle detected", scope_id)
                    seen.add(cursor)
                    cursor = self._nodes[cursor].parent_id

    # -- internals --------------------------------------------------------

    def _require_node(self, scope_id: str) -> BudgetNode:
        """Return the node for ``scope_id`` or raise. Caller holds the lock."""
        node = self._nodes.get(scope_id)
        if node is None:
            raise UnknownScopeError(scope_id)
        return node

    def _halted_by(self, scope_id: str) -> str | None:
        """Nearest tripped scope at or above ``scope_id``. Caller holds the lock."""
        cursor: str | None = scope_id
        while cursor is not None:
            if self._breakers[cursor].tripped_at is not None:
                return cursor
            cursor = self._nodes[cursor].parent_id
        return None

    def _assert_not_halted(self, scope_id: str) -> None:
        """Raise if ``scope_id`` is halted. Caller holds the lock."""
        tripped = self._halted_by(scope_id)
        if tripped is not None:
            raise CircuitOpenError(scope_id, tripped, self._breakers[tripped].reason)

    def _record_velocity(self, scope_id: str) -> None:
        """Record an authorization and trip on runaway loops. Lock held."""
        limit = self._policy.max_calls_per_window
        window = self._policy.window_seconds
        if limit <= 0 or window <= 0:
            return

        now = time.monotonic()
        times = self._breakers[scope_id].call_times
        times.append(now)
        cutoff = now - window
        while times and times[0] < cutoff:
            times.popleft()

        if len(times) > limit:
            count = len(times)
            self._trip(scope_id, f"runaway loop: {count} authorizations in {window}s")
            raise RunawayLoopDetectedError(scope_id, count, window)

    def _trip(self, scope_id: str, reason: str) -> None:
        """Latch the breaker for ``scope_id``. Caller holds the lock."""
        state = self._breakers[scope_id]
        if state.tripped_at is not None:
            return
        state.tripped_at = datetime.now(UTC)
        state.reason = reason
        self._record_control_event("circuit_tripped", scope_id, reason)

    def _record_control_event(self, event_type: str, scope_id: str, reason: str) -> None:
        """Persist, append, and log a control event. Caller holds the lock."""
        event = ControlEvent(
            event_id=uuid.uuid4(),
            timestamp=datetime.now(UTC),
            event_type=event_type,
            scope_id=scope_id,
            reason=reason,
            ledger_head_hash=self._ledger.head_hash,
        )
        if self._store is not None:
            self._store.append_control_event(event)
        self._control_events.append(event)
        audit_log.warning(
            f"{_AUDIT_VERSION}|ctrl={event_type}|ts={_iso(event.timestamp)}"
            f"|scope={scope_id}|head={event.ledger_head_hash[:16]}|reason={reason}",
            extra={
                "agentgov_control": {
                    "event_id": str(event.event_id),
                    "event_type": event_type,
                    "scope_id": scope_id,
                    "reason": reason,
                    "timestamp": _iso(event.timestamp),
                    "ledger_head_hash": event.ledger_head_hash,
                }
            },
        )

    def _require_open_authorization(self, authorization: Authorization, detail: str) -> None:
        """Raise if this authorization was already settled. Lock held.

        Deliberately does *not* remove it yet — that happens only once the
        settling transaction has actually committed
        (:meth:`_finalize_authorization`), so a durable-write failure during
        settlement leaves the hold open rather than orphaned. Nothing can
        race between this check and that commit: both run under the same
        lock acquisition in :meth:`capture`/:meth:`void`.
        """
        if authorization.authorization_id not in self._open_auths:
            raise DoubleSpendError(
                authorization.scope_id, str(authorization.authorization_id), detail
            )

    def _finalize_authorization(self, authorization: Authorization) -> None:
        """Remove a settled authorization from memory and the store. Lock held."""
        del self._open_auths[authorization.authorization_id]
        if self._store is not None:
            self._store.delete_authorization(authorization.authorization_id)

    def _void_locked(self, authorization: Authorization, memo: str) -> LedgerEntry:
        """Post a hold release and finalize the authorization. Lock held."""
        entries = self._ledger.post(
            [
                LedgerLine(
                    entry_type=EntryType.HOLD_VOID,
                    direction=Direction.CREDIT,
                    scope_id=authorization.scope_id,
                    amount=authorization.amount,
                    counterparty_id=None,
                    memo=memo,
                )
            ]
        )
        self._finalize_authorization(authorization)
        return entries[0]

    def _maybe_trip_on_exhaustion(self, scope_id: str) -> None:
        """Halt a scope that has spent its envelope down to zero. Lock held.

        Only fires once every hold on the scope has settled, so a transient
        zero caused by an in-flight authorization is not mistaken for
        exhaustion.
        """
        if not self._policy.trip_on_exhaustion:
            return
        if self._ledger.balance(scope_id) > ZERO:
            return
        if any(auth.scope_id == scope_id for auth in self._open_auths.values()):
            return
        self._trip(scope_id, "spend envelope exhausted")
