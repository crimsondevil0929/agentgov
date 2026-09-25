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

**Holds are paired inside the hash.** The release of a hold and the spend
that settles it both name the hold they settle (``ref``), and that reference
is part of the entry hash. The ledger refuses to release a hold that is not
open, in the scope and for the amount it was placed, so no stale, replayed or
forged authorization can hand the same funds back twice. Verification
re-derives the pairing from the chain.

**One chain for money and governance.** Circuit-breaker trips and resets,
evidence anchors and the migration seal are zero-value entries
(:attr:`Direction.NONE`) in the same chain as the money. Breaker state, the
delegation tree and the set of open holds are *derived* from the chain. The
tables a durable store keeps for them are caches: they are cross-checked at
open, and a cache that disagrees with the chain refuses to load.

**Unit of work.** A governor operation assembles its entries and every cache
write it implies, makes all of them durable in one store transaction, and
only then changes anything in memory. A crash or a failed write leaves the
state from before the operation or after it, never a mixture.

**Locking.** All budget state lives behind one re-entrant mutex owned by the
:class:`Ledger` and shared with the :class:`BudgetManager`. A single lock
means there is no lock-ordering question and therefore no deadlock. It is a
:class:`threading.RLock`, deliberately, *not* an :class:`asyncio.Lock`: the
critical sections are a few dict and list operations with no ``await``, so
the same primitive is correct under threads, under asyncio, and under both
at once. An ``asyncio.Lock`` would be usable from only one event loop and
would not protect against worker threads at all.

**Decimal only.** Monetary amounts are :class:`~decimal.Decimal`, quantized to
1e-8, and :class:`float` is rejected outright at every entry point. Rounding is
always *conservative for the governor*: costs round up, credits round down.
"""

from __future__ import annotations

import dataclasses
import hashlib
import itertools
import json
import logging
import re
import threading
import time
import uuid
from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
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
    # while still giving mypy the real types for the `store=` parameters.
    from agentgov.storage import (
        PersistedAuthorization,
        PersistedNode,
        PersistenceStore,
        StoreImage,
    )

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
    "WriteBatch",
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

_AUDIT_V1: Final = "AGOV1"
"""Hash payload of v0.1.0 and v0.1.1. Carries no hold reference."""

_AUDIT_V2: Final = "AGOV2"
"""Hash payload from v0.1.2: adds ``ref``, the hold a release or spend settles."""

_AUDIT_VERSION: Final = _AUDIT_V2
"""The payload version new entries are written with."""

_KNOWN_VERSIONS: Final = frozenset({_AUDIT_V1, _AUDIT_V2})


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

    NONE = "--"
    """Moves no money. A governance or evidence record: a breaker trip or
    reset, an external anchor, the migration seal."""


@unique
class EntryType(Enum):
    """The event a :class:`LedgerEntry` records."""

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
    """An authorization hold lifted, on capture or cancellation. CREDIT.
    Names the hold it releases (``ref``)."""

    SPEND = "spend"
    """Settled, irreversible outflow to an external vendor. DEBIT. When it
    settles an authorization, names that authorization's hold (``ref``)."""

    REVERSAL = "reversal"
    """Refund of a previously settled :attr:`SPEND`. CREDIT."""

    CIRCUIT_TRIPPED = "circuit_tripped"
    """A breaker latched on this scope and its subtree. Moves no money;
    ``memo`` is the reason."""

    CIRCUIT_RESET = "circuit_reset"
    """An operator re-armed this scope's breaker. Moves no money."""

    ANCHOR = "anchor"
    """An external record committed into the chain by digest (``memo``), such
    as an escrow chain head. Moves no money."""

    SEAL = "seal"
    """Written once, the first time a pre-0.1.2 database is opened for
    writing. Commits the control-event rows that version kept outside the
    chain, by digest, so they cannot be edited afterwards. Moves no money and
    belongs to no scope (``scope_id == ""``)."""


_LEGAL_DIRECTIONS: Final[Mapping[EntryType, frozenset[Direction]]] = {
    EntryType.FUNDING: frozenset({Direction.CREDIT}),
    EntryType.ALLOCATION: frozenset({Direction.DEBIT, Direction.CREDIT}),
    EntryType.RELEASE: frozenset({Direction.DEBIT, Direction.CREDIT}),
    EntryType.HOLD: frozenset({Direction.DEBIT}),
    EntryType.HOLD_VOID: frozenset({Direction.CREDIT}),
    EntryType.SPEND: frozenset({Direction.DEBIT}),
    EntryType.REVERSAL: frozenset({Direction.CREDIT}),
    EntryType.CIRCUIT_TRIPPED: frozenset({Direction.NONE}),
    EntryType.CIRCUIT_RESET: frozenset({Direction.NONE}),
    EntryType.ANCHOR: frozenset({Direction.NONE}),
    EntryType.SEAL: frozenset({Direction.NONE}),
}

_BALANCED_TYPES: Final = frozenset({EntryType.ALLOCATION, EntryType.RELEASE})
"""Entry types that move money *between* scopes and must therefore post
equal debits and credits within a single transaction."""

_ZERO_VALUE_TYPES: Final = frozenset(
    {EntryType.CIRCUIT_TRIPPED, EntryType.CIRCUIT_RESET, EntryType.ANCHOR, EntryType.SEAL}
)
"""Entry types that record an event without moving money."""

_REFERENCING_TYPES: Final = frozenset({EntryType.HOLD_VOID, EntryType.SPEND})
"""Entry types that may name the hold they settle."""


@dataclass(frozen=True, slots=True)
class LedgerLine:
    """An unposted instruction: one leg of a transaction, before it is written.

    :ivar entry_type: The event this leg belongs to.
    :ivar direction: Whether this leg debits or credits ``scope_id``, or
        :attr:`Direction.NONE` for a zero-value record.
    :ivar scope_id: The scope whose balance this leg moves.
    :ivar amount: Strictly positive amount; direction carries the sign. Zero
        for the zero-value entry types.
    :ivar counterparty_id: The other side of the movement — the parent, the
        child, or ``None`` for the external boundary (treasury or vendor).
    :ivar memo: Free-form audit context. Never affects balances.
    :ivar ref: The ``entry_id`` of the :attr:`EntryType.HOLD` this line
        settles. Required on a :attr:`EntryType.HOLD_VOID`; optional on a
        :attr:`EntryType.SPEND`, where it must name a hold the same
        transaction releases; refused on every other type.
    """

    entry_type: EntryType
    direction: Direction
    scope_id: str
    amount: Decimal
    counterparty_id: str | None = None
    memo: str = ""
    ref: uuid.UUID | None = None


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """A single, immutable, hash-chained record of one event.

    Entries are only ever constructed by :meth:`Ledger.post`, which computes
    the hash chain. Every field participates in ``entry_hash``, so altering
    any of them after the fact is detectable by :meth:`Ledger.verify_chain`.

    :ivar sequence: Strictly increasing position in the chain, starting at 1.
    :ivar entry_id: Globally unique identifier for this line.
    :ivar transaction_id: Shared by every line posted atomically together.
    :ivar timestamp: UTC instant the entry was committed.
    :ivar entry_type: The event recorded.
    :ivar direction: Whether this line debits or credits ``scope_id``.
    :ivar scope_id: The scope whose balance this line moves.
    :ivar counterparty_id: The other side, or ``None`` at the external boundary.
    :ivar amount: Amount, quantized to :data:`QUANTUM`; zero for the
        zero-value types.
    :ivar balance_after: ``scope_id``'s running balance once this line was
        applied. Attested by the hash, so the chain proves the balance history
        and not merely the movement history.
    :ivar prev_hash: ``entry_hash`` of the preceding entry, or
        :data:`GENESIS_HASH`.
    :ivar entry_hash: SHA-256 over ``prev_hash`` and every field above.
    :ivar memo: Free-form audit context.
    :ivar ref: The hold this entry settles, for a release or a spend.
    :ivar version: The hash-payload version the entry was written with.
        ``AGOV1`` entries predate ``ref`` and verify under their own rules.
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
    ref: uuid.UUID | None = None
    version: str = _AUDIT_V1

    @property
    def signed_amount(self) -> Decimal:
        """The amount as applied to ``scope_id``'s balance (negative for a
        :attr:`Direction.DEBIT`, zero for :attr:`Direction.NONE`)."""
        if self.direction is Direction.CREDIT:
            return self.amount
        if self.direction is Direction.DEBIT:
            return -self.amount
        return ZERO

    def recompute_hash(self) -> str:
        """Re-derive this entry's hash from its own fields.

        :returns: The SHA-256 hex digest this entry *should* carry.
        :raises ValueError: If :attr:`version` is not a known payload version.
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
            ref=self.ref,
            version=self.version,
        )

    def to_audit_record(self) -> dict[str, str]:
        """Render this entry as a flat, machine-readable audit record.

        Suitable for emitting as JSON Lines into a compliance archive; every
        value is a string so the record survives any downstream transport
        without numeric coercion.
        """
        return {
            "version": self.version,
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
            "ref": str(self.ref) if self.ref is not None else "",
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
    ref: uuid.UUID | None = None,
    version: str = _AUDIT_V1,
) -> str:
    """Compute the chain hash for one entry.

    The payload is JSON with a fixed field order, which gives unambiguous
    escaping for scope ids and memos that contain arbitrary text — a
    delimiter-joined payload could be forged by embedding the delimiter.
    The version tag leads the payload, so an entry cannot be re-read under
    another version's rules without its hash changing.

    :raises ValueError: If ``version`` is not a known payload version.
    """
    fields: list[object] = [
        version,
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
    ]
    if version == _AUDIT_V2:
        fields.append(str(ref) if ref is not None else None)
    elif version != _AUDIT_V1:
        raise ValueError(f"unknown audit version {version!r}")
    payload = json.dumps(fields, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def format_audit_line(entry: LedgerEntry) -> str:
    """Render an entry as a single fixed-field audit log line.

    The shape is deliberately grep-friendly and column-stable, in the spirit
    of a wire-transfer journal::

        AGOV2|seq=0000000007|txn=<uuid>|ts=...Z|type=spend|dir=DR
              |scope=agent.research|cpty=-|amt=0.00004500|bal=0.09991000|h=1a2b3c4d
              |ref=<uuid>

    :param entry: The entry to render.
    :returns: One line of audit output, with no trailing newline.
    """
    return (
        f"{entry.version}"
        f"|seq={entry.sequence:010d}"
        f"|txn={entry.transaction_id}"
        f"|ts={_iso(entry.timestamp)}"
        f"|type={entry.entry_type.value}"
        f"|dir={entry.direction.value}"
        f"|scope={entry.scope_id}"
        f"|cpty={entry.counterparty_id or '-'}"
        f"|amt={entry.amount}"
        f"|bal={entry.balance_after}"
        f"|h={entry.entry_hash[:16]}"
        + (f"|ref={entry.ref}" if entry.ref is not None else "")
        + (f"|memo={entry.memo}" if entry.memo else "")
    )


@dataclass(frozen=True, slots=True)
class _Totals:
    """Boundary totals used to verify the conservation identity."""

    funded: Decimal = ZERO
    spent: Decimal = ZERO
    reversed_: Decimal = ZERO
    holds_open: Decimal = ZERO


# --------------------------------------------------------------------------
# Chain state: everything that follows from the entries alone
# --------------------------------------------------------------------------

_HoldKey = tuple[str, Decimal]
"""A hold's scope and amount. Pre-0.1.2 releases carry nothing sharper."""


@dataclass(slots=True)
class _ChainState:
    """Balances, totals, head and open holds, as the chain implies them.

    :ivar holds: Open holds, keyed by the ``entry_id`` of the HOLD entry that
        placed them, in the order they were placed.
    :ivar ambiguous: ``(scope, amount)`` keys a pre-0.1.2 release has
        touched. Those releases did not name their hold, so within such a key
        the chain determines *how many* holds are open but not *which*; the
        open authorizations table supplies the identities.
    :ivar saw_v1: The chain contains pre-0.1.2 (``AGOV1``) entries.
    :ivar saw_v2: The chain contains ``AGOV2`` entries.
    :ivar seal: The migration seal, once written.
    """

    balances: dict[str, Decimal] = field(default_factory=dict)
    totals: _Totals = field(default_factory=_Totals)
    head: str = GENESIS_HASH
    length: int = 0
    holds: dict[uuid.UUID, LedgerEntry] = field(default_factory=dict)
    ambiguous: set[_HoldKey] = field(default_factory=set)
    saw_v1: bool = False
    saw_v2: bool = False
    seal: LedgerEntry | None = None

    def copy(self) -> _ChainState:
        """An independent copy, for staging changes that may yet be refused."""
        return dataclasses.replace(
            self,
            balances=dict(self.balances),
            holds=dict(self.holds),
            ambiguous=set(self.ambiguous),
        )


def _hold_key(entry: LedgerEntry) -> _HoldKey:
    return (entry.scope_id, entry.amount)


def _reassign_holds(state: _ChainState, key: _HoldKey, holds: Sequence[LedgerEntry]) -> None:
    """Name which holds of an ambiguous pre-0.1.2 key are the open ones.

    Pre-0.1.2 releases did not say which hold they released, so for such a key
    the chain fixes only how many holds remain open. The caller has checked
    that ``holds`` is that many HOLD entries of the key.
    """
    for hold_id in [h for h, e in state.holds.items() if _hold_key(e) == key]:
        del state.holds[hold_id]
    for hold in holds:
        state.holds[hold.entry_id] = hold


class _Overlay:
    """A copy-on-write view of a :class:`_ChainState`.

    Every entry is verified against the view and folded into it; the base
    state changes only in :meth:`merge`. A unit of work validates its entries
    here before anything is durable, a refresh verifies another process's
    entries here before trusting them, and a full replay is this, started
    from an empty state. One set of rules for all three.
    """

    __slots__ = (
        "_base",
        "_closed",
        "_opened",
        "_settleable",
        "_start_head",
        "_txn",
        "ambiguous",
        "balances",
        "head",
        "length",
        "saw_v1",
        "saw_v2",
        "seal",
        "totals",
    )

    def __init__(self, base: _ChainState) -> None:
        self._base = base
        self._start_head = base.head
        self.balances: dict[str, Decimal] = {}
        self.totals = base.totals
        self.head = base.head
        self.length = base.length
        self.saw_v1 = base.saw_v1
        self.saw_v2 = base.saw_v2
        self.seal = base.seal
        self.ambiguous: set[_HoldKey] = set()
        self._opened: dict[uuid.UUID, LedgerEntry] = {}
        self._closed: set[uuid.UUID] = set()
        self._txn: uuid.UUID | None = None
        self._settleable: set[uuid.UUID] = set()

    @property
    def start_head(self) -> str:
        """The base's head when this view was taken."""
        return self._start_head

    def balance(self, scope_id: str) -> Decimal:
        found = self.balances.get(scope_id)
        return found if found is not None else self._base.balances.get(scope_id, ZERO)

    def open_hold(self, hold_id: uuid.UUID) -> LedgerEntry | None:
        if hold_id in self._closed:
            return None
        found = self._opened.get(hold_id)
        return found if found is not None else self._base.holds.get(hold_id)

    def apply(
        self,
        entry: LedgerEntry,
        *,
        check_hash: bool = True,
        released: set[uuid.UUID] | None = None,
    ) -> None:
        """Verify ``entry`` as the next link of the chain, then fold it in.

        :param check_hash: Recompute the entry hash. Off only for entries this
            process built a moment ago.
        :param released: Every hold released so far, when the caller wants a
            double release reported as such rather than as an unknown hold.
        :raises LedgerIntegrityError: On the first rule the entry breaks.
        """
        index = self.length + 1
        scope = entry.scope_id
        if entry.sequence != index:
            raise LedgerIntegrityError(
                f"sequence gap at position {index}: entry claims {entry.sequence}", scope
            )
        if entry.prev_hash != self.head:
            raise LedgerIntegrityError(f"broken chain link at sequence {entry.sequence}", scope)
        if entry.version not in _KNOWN_VERSIONS:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} carries an unknown audit version {entry.version!r}",
                scope,
            )
        if check_hash and entry.recompute_hash() != entry.entry_hash:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} has been tampered with (hash mismatch)", scope
            )
        self._check_version(entry)
        self._check_shape(entry)

        expected = self.balance(scope) + entry.signed_amount
        if entry.balance_after != expected:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} records a balance of {entry.balance_after}, "
                f"but the chain implies {expected}",
                scope,
            )
        if entry.entry_type not in _ZERO_VALUE_TYPES:
            self.balances[scope] = expected

        self._check_holds(entry, released)
        self.totals = _apply_totals(self.totals, (entry,))
        if entry.entry_type is EntryType.SEAL:
            self.seal = entry
        self.head = entry.entry_hash
        self.length = index

    def merge(self) -> None:
        """Fold every verified change into the base state."""
        base = self._base
        base.balances.update(self.balances)
        base.totals = self.totals
        base.head = self.head
        base.length = self.length
        base.saw_v1 = self.saw_v1
        base.saw_v2 = self.saw_v2
        base.seal = self.seal
        for hold_id in self._closed:
            base.holds.pop(hold_id, None)
        base.holds.update(self._opened)
        base.ambiguous |= self.ambiguous

    # -- rules ------------------------------------------------------------

    def _check_version(self, entry: LedgerEntry) -> None:
        if entry.version == _AUDIT_V1:
            if self.saw_v2:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} is an AGOV1 entry after AGOV2 entries; "
                    f"pre-0.1.2 entries cannot follow newer ones"
                )
            if entry.ref is not None:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} is an AGOV1 entry carrying a hold reference, "
                    f"which its hash does not cover"
                )
            if entry.entry_type in _ZERO_VALUE_TYPES:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} is an AGOV1 {entry.entry_type.value} entry, "
                    f"a type AGOV1 did not have"
                )
            self.saw_v1 = True
            return
        if self.saw_v1 and not self.saw_v2 and entry.entry_type is not EntryType.SEAL:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} is the first entry written after pre-0.1.2 history "
                f"and is not the migration seal; open the ledger with "
                f"BudgetManager.open_sqlite() so it is sealed first"
            )
        self.saw_v2 = True

    def _check_shape(self, entry: LedgerEntry) -> None:
        kind = entry.entry_type
        if entry.direction not in _LEGAL_DIRECTIONS[kind]:
            raise LedgerIntegrityError(
                f"entry {entry.sequence}: {kind.value} may not be a {entry.direction.value} line",
                entry.scope_id,
            )
        if kind not in _ZERO_VALUE_TYPES:
            if entry.amount <= ZERO:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence}: amount must be positive, got {entry.amount}",
                    entry.scope_id,
                )
            return
        if entry.amount != ZERO:
            raise LedgerIntegrityError(
                f"entry {entry.sequence}: a {kind.value} entry moves no money, "
                f"but records {entry.amount}",
                entry.scope_id,
            )
        if kind is EntryType.SEAL:
            if entry.scope_id:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence}: the migration seal belongs to no scope"
                )
            if self.seal is not None:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} is a second migration seal; a ledger is sealed once"
                )
            if not self.saw_v1:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} seals pre-0.1.2 history this ledger does not have"
                )
        elif not entry.scope_id:
            raise LedgerIntegrityError(f"entry {entry.sequence}: a {kind.value} needs a scope")

    def _check_holds(self, entry: LedgerEntry, released: set[uuid.UUID] | None) -> None:
        if entry.transaction_id != self._txn:
            self._txn = entry.transaction_id
            self._settleable = set()
        kind = entry.entry_type
        if entry.ref is not None and kind not in _REFERENCING_TYPES:
            raise LedgerIntegrityError(
                f"entry {entry.sequence}: a {kind.value} entry names no hold", entry.scope_id
            )
        if kind is EntryType.HOLD:
            self._opened[entry.entry_id] = entry
        elif kind is EntryType.HOLD_VOID:
            if entry.version == _AUDIT_V1:
                self._release_unnamed(entry)
            else:
                self._release_named(entry, released)
        elif kind is EntryType.SPEND and entry.ref is not None:
            if entry.ref not in self._settleable:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} settles hold {entry.ref}, which its own "
                    f"transaction did not release",
                    entry.scope_id,
                )

    def _release_named(self, entry: LedgerEntry, released: set[uuid.UUID] | None) -> None:
        ref = entry.ref
        if ref is None:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} releases a hold without naming it; "
                f"a hold release must carry the hold's entry id (ref)",
                entry.scope_id,
            )
        hold = self.open_hold(ref)
        if hold is None:
            if released is not None and ref in released:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} releases hold {ref} a second time; "
                    f"that would return its funds twice",
                    entry.scope_id,
                )
            raise LedgerIntegrityError(
                f"entry {entry.sequence} releases hold {ref}, which is not an open hold "
                f"(it was already released, or never placed)",
                entry.scope_id,
            )
        if hold.scope_id != entry.scope_id:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} releases hold {ref} of scope {hold.scope_id!r} "
                f"into {entry.scope_id!r}",
                entry.scope_id,
            )
        if hold.amount != entry.amount:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} releases {entry.amount} of hold {ref}, "
                f"which encumbered {hold.amount}",
                entry.scope_id,
            )
        self._close(ref)
        self._settleable.add(ref)
        if released is not None:
            released.add(ref)

    def _release_unnamed(self, entry: LedgerEntry) -> None:
        """A pre-0.1.2 release: pair it by scope and amount, which is all it has.

        Any open hold of the same scope and amount is a monetarily identical
        partner. What matters, and what this enforces, is that one exists: a
        second release of the same funds finds none and fails.
        """
        key = _hold_key(entry)
        for hold_id, hold in (*self._base.holds.items(), *self._opened.items()):
            if hold_id not in self._closed and _hold_key(hold) == key:
                self._close(hold_id)
                self.ambiguous.add(key)
                return
        raise LedgerIntegrityError(
            f"entry {entry.sequence} releases {entry.amount}, but no open hold of that "
            f"amount remains; the same funds were released twice",
            entry.scope_id,
        )

    def _close(self, hold_id: uuid.UUID) -> None:
        if self._opened.pop(hold_id, None) is None:
            self._closed.add(hold_id)


def _replay(entries: Iterable[LedgerEntry]) -> _ChainState:
    """Rebuild chain state from nothing but the entries, verifying each."""
    state = _ChainState()
    view = _Overlay(state)
    released: set[uuid.UUID] = set()
    for entry in entries:
        view.apply(entry, released=released)
    view.merge()
    return state


def _apply_totals(totals: _Totals, entries: Iterable[LedgerEntry]) -> _Totals:
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
# Units of work
# --------------------------------------------------------------------------


@dataclass(slots=True)
class WriteBatch:
    """Every durable write one governor operation makes.

    A :class:`~agentgov.storage.PersistenceStore` applies a batch in a single
    transaction: all of it becomes durable, or none of it does. That is the
    property that closes the gap between a ledger entry and the cache row
    that describes it — a crash can no longer leave a released hold behind
    an open authorization, or a funded scope without its topology row.

    :ivar entries: New ledger entries, in chain order.
    :ivar nodes: Topology rows to insert or update.
    :ivar control_events: Breaker trips and resets to record, each mirroring a
        chain entry.
    :ivar opened: Authorizations placed.
    :ivar closed: Authorization ids settled or voided.
    """

    entries: list[LedgerEntry] = field(default_factory=list)
    nodes: list[BudgetNode] = field(default_factory=list)
    control_events: list[ControlEvent] = field(default_factory=list)
    opened: list[Authorization] = field(default_factory=list)
    closed: list[uuid.UUID] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.entries or self.nodes or self.control_events or self.opened or self.closed)


class _Pending:
    """One unit of work: entries and cache writes that become durable together.

    Built and committed with the ledger's lock held. Nothing is visible to
    anyone — memory or disk — until :meth:`Ledger._commit` succeeds, so an
    exception anywhere before then simply abandons the work.
    """

    __slots__ = ("_ledger", "_view", "batch")

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger
        self._view = _Overlay(ledger._state)
        self.batch = WriteBatch()

    @property
    def entries(self) -> list[LedgerEntry]:
        return self.batch.entries

    def balance(self, scope_id: str) -> Decimal:
        """``scope_id``'s balance as of the work posted so far."""
        return self._view.balance(scope_id)

    def post(
        self,
        lines: Sequence[LedgerLine],
        *,
        transaction_id: uuid.UUID | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """Validate ``lines`` as one ledger transaction and add it to this work.

        :raises ValueError: If ``lines`` is empty, an amount is malformed, a
            ``(entry_type, direction)`` pair is illegal, or a line names a hold
            its type cannot settle.
        :raises LedgerIntegrityError: If a transfer does not balance, a release
            names a hold that is not open, or any other rule a replay enforces
            would reject the entries.
        """
        if not lines:
            raise ValueError("a transaction must contain at least one line")

        view = self._view
        txn_id = transaction_id or uuid.uuid4()
        now = datetime.now(UTC)
        transfer_net = ZERO
        running: dict[str, Decimal] = {}
        prev_hash = view.head
        sequence = view.length
        built: list[LedgerEntry] = []

        for line in lines:
            if line.direction not in _LEGAL_DIRECTIONS[line.entry_type]:
                raise ValueError(
                    f"{line.entry_type.value} may not be a {line.direction.value} line"
                )
            if line.entry_type in _ZERO_VALUE_TYPES:
                if line.amount != ZERO:
                    raise ValueError(
                        f"a {line.entry_type.value} line moves no money; its amount "
                        f"must be 0, got {line.amount}"
                    )
                amount = ZERO
            else:
                amount = _coerce(line.amount, rounding=ROUND_FLOOR, label="line amount")
                if amount != line.amount:
                    raise ValueError(f"line amount {line.amount} is not quantized to {QUANTUM}")
                if amount <= ZERO:
                    raise ValueError(f"line amount must be positive, got {amount}")
            if line.ref is not None and line.entry_type not in _REFERENCING_TYPES:
                raise ValueError(
                    f"a {line.entry_type.value} line names no hold; ref is for hold "
                    f"releases and the spends that settle them"
                )

            if line.entry_type in _BALANCED_TYPES:
                transfer_net += amount if line.direction is Direction.CREDIT else -amount

            if line.direction is Direction.CREDIT:
                signed = amount
            elif line.direction is Direction.DEBIT:
                signed = -amount
            else:
                signed = ZERO
            current = running.get(line.scope_id, view.balance(line.scope_id))
            balance_after = current + signed
            if line.entry_type not in _ZERO_VALUE_TYPES:
                running[line.scope_id] = balance_after

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
                ref=line.ref,
                version=_AUDIT_VERSION,
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
                    ref=line.ref,
                    version=_AUDIT_VERSION,
                )
            )
            prev_hash = entry_hash

        if transfer_net != ZERO:
            raise LedgerIntegrityError(f"transfer transaction does not balance: net {transfer_net}")

        # Every rule a replay would enforce, enforced now, before anything is
        # durable: a pairing violation refuses the work instead of being found
        # by the next verification.
        for entry in built:
            view.apply(entry, check_hash=False)
        self.batch.entries.extend(built)
        return tuple(built)


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------


class Ledger:
    """An append-only, hash-chained, double-entry store of ledger entries.

    The ledger is the single source of truth for every dollar in the system.
    It guarantees:

    - **Append-only** — entries are frozen and never removed.
    - **Atomic** — a transaction is validated in full before any of it is
      written, and a unit of work becomes durable in one store transaction
      before memory changes, so failure leaves no partial trace in either.
    - **Tamper-evident** — :meth:`verify_chain` re-derives the SHA-256 chain,
      every running balance and every hold pairing, and catches any
      retroactive edit.
    - **Reconcilable** — cached balances are maintained incrementally for
      O(1) reads, and :meth:`replay` recomputes them from the raw chain so
      the two can be checked against each other.

    All state is guarded by :attr:`lock`, a re-entrant mutex that the owning
    :class:`BudgetManager` shares rather than nesting its own beneath.
    """

    def __init__(self, *, store: PersistenceStore | None = None) -> None:
        self._lock = threading.RLock()
        self._store: PersistenceStore | None = store
        self._entries: list[LedgerEntry] = []
        self._state = _ChainState()
        if store is not None:
            # Fail closed: a database that has been tampered with, or that
            # was corrupted by a crash mid-write, must never be trusted
            # silently. Refuse to start rather than serve a wrong balance.
            self._adopt(store.load_entries())

    @classmethod
    def _from_entries(cls, store: PersistenceStore, entries: Sequence[LedgerEntry]) -> Ledger:
        """A ledger over ``store`` holding ``entries``, already read from it."""
        ledger = cls()
        ledger._store = store
        ledger._adopt(entries)
        return ledger

    def _adopt(self, entries: Iterable[LedgerEntry]) -> None:
        """Replace this ledger's contents with ``entries``, verified first."""
        loaded = list(entries)
        state = _replay(loaded)
        with self._lock:
            self._entries = loaded
            self._state = state

    # -- compatibility views of the chain state ---------------------------

    @property
    def _balances(self) -> dict[str, Decimal]:
        return self._state.balances

    @_balances.setter
    def _balances(self, value: dict[str, Decimal]) -> None:
        self._state.balances = value

    @property
    def _totals(self) -> _Totals:
        return self._state.totals

    @_totals.setter
    def _totals(self, value: _Totals) -> None:
        self._state.totals = value

    @property
    def _head_hash(self) -> str:
        return self._state.head

    @_head_hash.setter
    def _head_hash(self, value: str) -> None:
        self._state.head = value

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
            return self._state.head

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
            return self._state.balances.get(scope_id, ZERO)

    def balances(self) -> dict[str, Decimal]:
        """Return a snapshot of every scope's balance."""
        with self._lock:
            return dict(self._state.balances)

    def open_holds(self) -> tuple[LedgerEntry, ...]:
        """Every HOLD entry not yet released, in the order it was placed."""
        with self._lock:
            return tuple(self._state.holds.values())

    # -- writing ----------------------------------------------------------

    def post(
        self,
        lines: Sequence[LedgerLine],
        *,
        transaction_id: uuid.UUID | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """Atomically commit ``lines`` as one transaction.

        Validation happens in full before anything is written, so a rejected
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
            credits do not balance, or a release names a hold that is not open.
        """
        with self._lock:
            pending = self._begin()
            built = pending.post(lines, transaction_id=transaction_id)
            self._commit(pending)
        return built

    def _begin(self) -> _Pending:
        """Start a unit of work. The caller holds :attr:`lock` until commit."""
        return _Pending(self)

    def _commit(self, pending: _Pending) -> None:
        """Make a unit of work durable, then visible.

        The store write comes first and is all-or-nothing, so a store failure
        (disk full, I/O error, a crash) leaves the ledger exactly as it was —
        in memory and on disk. Memory is only touched once the write returns.
        """
        batch = pending.batch
        if not batch:
            return
        with self._lock:
            if pending._view.start_head != self._state.head:
                raise RuntimeError(
                    "unit of work was built against a stale ledger head; "
                    "hold the ledger lock from begin to commit"
                )
            if self._store is not None:
                self._store.commit(batch)
            pending._view.merge()
            self._entries.extend(batch.entries)
            # Formatting a line costs more than hashing it; skip both
            # renderings when nothing is listening.
            if audit_log.isEnabledFor(logging.INFO):
                for entry in batch.entries:
                    audit_log.info(
                        format_audit_line(entry),
                        extra={"agentgov_entry": entry.to_audit_record()},
                    )

    def _ingest(self, entries: Sequence[LedgerEntry]) -> None:
        """Append entries another process wrote, verifying each first.

        All or nothing: a single entry that fails verification leaves this
        ledger exactly as it was.
        """
        with self._lock:
            view = _Overlay(self._state)
            for entry in entries:
                view.apply(entry)
            view.merge()
            self._entries.extend(entries)

    def _reassign_holds(self, key: _HoldKey, holds: Sequence[LedgerEntry]) -> None:
        """Name which holds of an ambiguous pre-0.1.2 key are the open ones."""
        with self._lock:
            _reassign_holds(self._state, key, holds)

    def _publish(self, entries: list[LedgerEntry], state: _ChainState) -> None:
        """Serve ``entries`` and the ``state`` they imply, both already verified.

        The two are swapped in together, under the lock, so a reader never sees
        entries without the balances they produce, or the reverse.
        """
        with self._lock:
            self._entries = entries
            self._state = state

    # -- verification -----------------------------------------------------

    def replay(self) -> tuple[dict[str, Decimal], _Totals]:
        """Recompute balances and boundary totals from the raw chain.

        :returns: A ``(balances, totals)`` pair derived from nothing but the
            entries themselves.
        :raises LedgerIntegrityError: If the entries do not form a valid chain.
        """
        with self._lock:
            state = _replay(self._entries)
            return state.balances, state.totals

    def verify_chain(self) -> None:
        """Verify the hash chain, the running balances, hold pairing and caches.

        :raises LedgerIntegrityError: On the first inconsistency found — a
            broken link, a re-derived hash that does not match, a sequence
            gap, a balance the arithmetic does not produce, a hold released
            twice, or a cached figure that disagrees with a full replay.
        """
        with self._lock:
            replayed = _replay(self._entries)
            live = self._state

            if replayed.head != live.head:
                raise LedgerIntegrityError("head hash does not match the chain")

            for scope_id, cached in live.balances.items():
                if replayed.balances.get(scope_id, ZERO) != cached:
                    raise LedgerIntegrityError(
                        f"cached balance {cached} disagrees with replayed "
                        f"balance {replayed.balances.get(scope_id, ZERO)}",
                        scope_id,
                    )
            if replayed.totals != live.totals:
                raise LedgerIntegrityError("cached boundary totals disagree with replay")
            _compare_holds(replayed, live)

    def verify_conservation(self) -> None:
        """Verify that money is neither created nor destroyed.

        Checks the identity::

            Σ(balances) + holds_open + spent - reversed == funded

        Allocations and releases net to zero across scopes and so drop out;
        what remains is the boundary with the outside world. Zero-value
        entries move nothing and do not appear in it.

        :raises LedgerIntegrityError: If the identity does not hold exactly.
        """
        with self._lock:
            total_balance = sum(self._state.balances.values(), ZERO)
            t = self._state.totals
            left = total_balance + t.holds_open + t.spent - t.reversed_
            if left != t.funded:
                raise LedgerIntegrityError(
                    f"conservation violated: balances {total_balance} + holds "
                    f"{t.holds_open} + spent {t.spent} - reversed {t.reversed_} "
                    f"= {left}, but funded = {t.funded}"
                )


def _compare_holds(replayed: _ChainState, live: _ChainState) -> None:
    """Live open holds must be the ones the chain implies.

    Exact by hold identity, except for keys a pre-0.1.2 release touched, where
    the chain fixes only the count.
    """
    ambiguous = replayed.ambiguous | live.ambiguous
    if Counter(map(_hold_key, replayed.holds.values())) != Counter(
        map(_hold_key, live.holds.values())
    ):
        raise LedgerIntegrityError("open holds disagree with the chain")
    exact_replayed = {h for h, e in replayed.holds.items() if _hold_key(e) not in ambiguous}
    exact_live = {h for h, e in live.holds.items() if _hold_key(e) not in ambiguous}
    if exact_replayed != exact_live:
        raise LedgerIntegrityError("open holds disagree with the chain")


# --------------------------------------------------------------------------
# Budget topology
# --------------------------------------------------------------------------


@dataclass(slots=True)
class BudgetNode:
    """One scope in the hierarchical spend-delegation tree.

    A node is an agent, sub-agent, or tool-call scope. It carries *structure*
    only — the authoritative balance lives in the :class:`Ledger`, so there is
    exactly one place a dollar can be counted. Every field follows from the
    chain's FUNDING and ALLOCATION entries.

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

    :ivar authorization_id: Unique identifier for this hold. From v0.1.2 it is
        the ``entry_id`` of :attr:`entry`, so the chain alone links an
        authorization to its settlement.
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
    """A circuit-breaker trip or reset.

    Moves no money, and is recorded as a zero-value entry in the chain
    (:attr:`EntryType.CIRCUIT_TRIPPED` / :attr:`EntryType.CIRCUIT_RESET`), so
    it cannot be edited or deleted without breaking verification.
    :attr:`ledger_head_hash` pins it to an exact position in the chain.

    :ivar event_id: Unique identifier for this event. The chain entry's id.
    :ivar timestamp: UTC instant the event occurred.
    :ivar event_type: ``"circuit_tripped"`` or ``"circuit_reset"``.
    :ivar scope_id: The scope the control action applied to.
    :ivar reason: Human-readable justification.
    :ivar ledger_head_hash: The ledger's head hash at the time of the event,
        before the event's own entry.
    :ivar entry_id: The chain entry recording this event. ``None`` only for
        events a pre-0.1.2 governor wrote, which were kept outside the chain
        and are vouched for by the migration seal instead.
    """

    event_id: uuid.UUID
    timestamp: datetime
    event_type: str
    scope_id: str
    reason: str
    ledger_head_hash: str
    entry_id: uuid.UUID | None = None


def _event_for(entry: LedgerEntry) -> ControlEvent:
    """The control event a CIRCUIT_TRIPPED or CIRCUIT_RESET entry records."""
    return ControlEvent(
        event_id=entry.entry_id,
        timestamp=entry.timestamp,
        event_type=entry.entry_type.value,
        scope_id=entry.scope_id,
        reason=entry.memo,
        ledger_head_hash=entry.prev_hash,
        entry_id=entry.entry_id,
    )


_SEAL_MEMO: Final = re.compile(r"\Apre-0\.1\.2 control events: n=(\d+) sha256=([0-9a-f]{64})\Z")


def _legacy_digest(events: Sequence[ControlEvent]) -> str:
    """SHA-256 over pre-0.1.2 control-event rows, in the order they were written."""
    payload = json.dumps(
        [
            [
                str(e.event_id),
                _iso(e.timestamp),
                e.event_type,
                e.scope_id,
                e.reason,
                e.ledger_head_hash,
            ]
            for e in events
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _seal_memo(events: Sequence[ControlEvent]) -> str:
    return f"pre-0.1.2 control events: n={len(events)} sha256={_legacy_digest(events)}"


class _Governance:
    """The delegation tree, breaker state and control events the chain implies.

    Nothing here is read from a side table. A scope exists because a FUNDING
    or ALLOCATION entry created it, has the parent that entry names, and is
    halted because its last control entry is a trip.
    """

    __slots__ = (
        "_legacy",
        "_legacy_applied",
        "chain_events",
        "events",
        "nodes",
        "roots",
        "tripped",
    )

    def __init__(self, legacy: Sequence[ControlEvent] = ()) -> None:
        self.nodes: dict[str, BudgetNode] = {}
        self.roots: list[str] = []
        self.tripped: dict[str, tuple[datetime, str]] = {}
        self.events: list[ControlEvent] = []
        self.chain_events: list[ControlEvent] = []
        self._legacy = tuple(legacy)
        self._legacy_applied = False

    @classmethod
    def from_chain(
        cls, entries: Iterable[LedgerEntry], legacy: Sequence[ControlEvent] = ()
    ) -> _Governance:
        governance = cls(legacy)
        for entry in entries:
            governance.apply(entry)
        governance.finish()
        return governance

    def copy(self) -> _Governance:
        """An independent copy, for staging changes that may yet be refused."""
        clone = _Governance(self._legacy)
        clone.nodes = {
            scope_id: dataclasses.replace(node, child_ids=list(node.child_ids))
            for scope_id, node in self.nodes.items()
        }
        clone.roots = list(self.roots)
        clone.tripped = dict(self.tripped)
        clone.events = list(self.events)
        clone.chain_events = list(self.chain_events)
        clone._legacy_applied = self._legacy_applied
        return clone

    def finish(self) -> None:
        """Apply pre-0.1.2 control events to a chain that has no newer entries."""
        if not self._legacy_applied:
            self._apply_legacy()

    def apply_legacy_event(self, event: ControlEvent) -> None:
        """A control event a pre-0.1.2 writer added after this view was built."""
        self._legacy = (*self._legacy, event)
        self._control(event.event_type, event.scope_id, event.timestamp, event.reason)
        self.events.append(event)

    def apply(self, entry: LedgerEntry) -> None:
        if entry.version != _AUDIT_V1 and not self._legacy_applied:
            # Every pre-0.1.2 control event predates the first newer entry.
            if entry.entry_type is EntryType.SEAL:
                self._check_seal(entry)
            elif self._legacy:
                raise LedgerIntegrityError(
                    "control_events holds rows that are not in the chain, and this "
                    "ledger has no migration seal to vouch for them"
                )
            self._apply_legacy()

        kind = entry.entry_type
        scope = entry.scope_id
        if kind is EntryType.FUNDING:
            node = self.nodes.get(scope)
            if node is None:
                self.nodes[scope] = BudgetNode(
                    scope_id=scope,
                    parent_id=None,
                    depth=0,
                    allocated=entry.amount,
                    created_at=entry.timestamp,
                )
                self.roots.append(scope)
            elif node.parent_id is not None:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} funds a scope that is not a root", scope
                )
            else:
                node.allocated += entry.amount
        elif kind is EntryType.ALLOCATION:
            self._allocate(entry)
        elif kind is EntryType.RELEASE:
            self._release(entry)
        elif kind in (EntryType.CIRCUIT_TRIPPED, EntryType.CIRCUIT_RESET):
            self._control(kind.value, scope, entry.timestamp, entry.memo)
            event = _event_for(entry)
            self.events.append(event)
            self.chain_events.append(event)
        elif kind is not EntryType.SEAL:
            self._require(scope, entry)

    def _allocate(self, entry: LedgerEntry) -> None:
        scope, parent_id = entry.scope_id, entry.counterparty_id
        if entry.direction is Direction.DEBIT:
            self._require(scope, entry)
            return
        if scope in self.nodes:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} allocates to {scope!r} a second time; a "
                f"delegation creates a new scope",
                scope,
            )
        parent = self.nodes.get(parent_id or "")
        if parent is None:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} delegates from {parent_id!r}, which the chain "
                f"never created",
                scope,
            )
        self.nodes[scope] = BudgetNode(
            scope_id=scope,
            parent_id=parent.scope_id,
            depth=parent.depth + 1,
            allocated=entry.amount,
            created_at=entry.timestamp,
        )
        parent.child_ids.append(scope)

    def _release(self, entry: LedgerEntry) -> None:
        scope, other = entry.scope_id, entry.counterparty_id or ""
        node = self._require(scope, entry)
        child = node if entry.direction is Direction.DEBIT else self.nodes.get(other)
        parent_id = other if entry.direction is Direction.DEBIT else scope
        if child is None or child.parent_id != parent_id:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} releases between {scope!r} and {other!r}, "
                f"which are not child and parent",
                scope,
            )

    def _control(self, event_type: str, scope_id: str, timestamp: datetime, reason: str) -> None:
        if scope_id not in self.nodes:
            raise LedgerIntegrityError(f"control event references unregistered scope {scope_id!r}")
        if event_type == EntryType.CIRCUIT_TRIPPED.value:
            self.tripped[scope_id] = (timestamp, reason)
        elif event_type == EntryType.CIRCUIT_RESET.value:
            self.tripped.pop(scope_id, None)

    def _require(self, scope_id: str, entry: LedgerEntry) -> BudgetNode:
        node = self.nodes.get(scope_id)
        if node is None:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} ({entry.entry_type.value}) names a scope the "
                f"chain never created",
                scope_id,
            )
        return node

    def _apply_legacy(self) -> None:
        self._legacy_applied = True
        for event in self._legacy:
            self._control(event.event_type, event.scope_id, event.timestamp, event.reason)
            self.events.append(event)

    def _check_seal(self, entry: LedgerEntry) -> None:
        match = _SEAL_MEMO.match(entry.memo)
        if match is None:
            raise LedgerIntegrityError(f"entry {entry.sequence} is a malformed migration seal")
        count, digest = int(match.group(1)), match.group(2)
        if count != len(self._legacy) or digest != _legacy_digest(self._legacy):
            raise LedgerIntegrityError(
                f"the pre-0.1.2 control events no longer match the seal written when "
                f"this ledger was upgraded (entry {entry.sequence}): a legacy trip or "
                f"reset was edited, added or deleted"
            )


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
        omitted. Its mutex becomes this manager's mutex. A ledger that already
        holds entries is not re-read: this manager derives its topology,
        breaker state and open holds from those entries.
    :param policy: Governance limits; defaults to :class:`GovernancePolicy`.
    :param store: A durable backend. Pass the *same* store given to ``ledger``
        (or omit ``ledger`` and let this constructor build one).
        :meth:`open_sqlite` sets this up correctly in one call.
    :param repair: When the store's cache tables (topology, control events,
        open authorizations) disagree with the chain, rebuild them from the
        chain instead of refusing to open. Moves no money.
    """

    def __init__(
        self,
        *,
        ledger: Ledger | None = None,
        policy: GovernancePolicy | None = None,
        store: PersistenceStore | None = None,
        repair: bool = False,
    ) -> None:
        image: StoreImage | None = None
        if ledger is None:
            if store is not None:
                # One consistent read of every table: a live writer in another
                # process cannot slip a commit between the entries and the
                # caches that describe them.
                image = store.load()
                ledger = Ledger._from_entries(store, image.entries)
            else:
                ledger = Ledger()
        self._ledger = ledger
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
        self._legacy_events: tuple[ControlEvent, ...] = ()
        self._governance: _Governance | None = None
        self._repairs: tuple[str, ...] = ()
        self._schema_version = ""
        self._control_high_water = 0
        self._unusable: str | None = None

        if store is not None:
            self._restore_from_store(
                store, image if image is not None else store.load(), repair=repair
            )
        elif len(self._ledger):
            self._adopt_governance(_Governance.from_chain(self._ledger.entries()))
            self._open_auths = {
                hold.entry_id: _authorization_for(hold) for hold in self._ledger.open_holds()
            }

    @classmethod
    def open_sqlite(
        cls,
        path: str,
        *,
        policy: GovernancePolicy | None = None,
        synchronous: str = "FULL",
        read_only: bool = False,
        repair: bool = False,
    ) -> BudgetManager:
        """Open (or create) a durable, SQLite-backed governor in one call.

        The ledger, topology, control events, and any open authorizations
        are restored from ``path`` if it already contains a governor's
        state, and freshly created otherwise. The returned manager owns the
        underlying connection — call :meth:`close` (or use it as a context
        manager) when you are done with it.

        A database written by v0.1.0 or v0.1.1 is upgraded in place the first
        time it is opened for writing: its schema gains the columns v0.1.2
        needs, and a migration seal commits its control events into the chain.
        Opened read-only, it is served as it is.

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
            :class:`~agentgov.exceptions.ReadOnlyLedgerError`; call
            :meth:`refresh` to catch up with the writer.
        :param repair: Rebuild cache tables that disagree with the chain
            instead of refusing to open. See :attr:`repairs`.
        :returns: A restored or freshly created :class:`BudgetManager`.
        :raises agentgov.exceptions.ConcurrentGovernorError: If another
            process already holds this database for writing. Two governors
            would each cache authoritative balances in memory and diverge,
            so the second is refused at open rather than on its first write.
        :raises agentgov.exceptions.LedgerIntegrityError: If the database's
            chain, balances, pairing or topology are inconsistent — a
            corrupted or tampered file is refused rather than trusted.
        """
        from agentgov.storage import SqliteStore

        store = SqliteStore(path, synchronous=synchronous, read_only=read_only)
        try:
            return cls(policy=policy, store=store, repair=repair)
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

    # -- restore ----------------------------------------------------------

    def _restore_from_store(
        self, store: PersistenceStore, image: StoreImage, *, repair: bool
    ) -> None:
        """Derive state from the chain and check the store's caches against it.

        Called once, from the constructor, before this manager is visible to
        any other code.

        :raises LedgerIntegrityError: If a cache table disagrees with the
            chain (unless ``repair``), or the chain's own governance record is
            inconsistent. A corrupted or partially written database is
            refused, never trusted.
        """
        self._schema_version = image.schema_version
        self._control_high_water = image.control_high_water
        legacy = tuple(event for event in image.control_events if event.entry_id is None)
        entries = self._ledger.entries()
        governance = _Governance.from_chain(entries, legacy)

        problems = _node_row_problems(governance, image.nodes)
        problems += _control_row_problems(governance, image.control_events)
        auths, auth_problems, identities = self._reconcile_authorizations(
            image.authorizations, _HoldIndex(lambda: entries), repairing=repair
        )
        problems += auth_problems

        if problems:
            more = f" (and {len(problems) - 1} more)" if len(problems) > 1 else ""
            if not repair:
                raise LedgerIntegrityError(
                    f"{problems[0]}{more}. The chain itself verified; a cache table "
                    f"disagrees with it. Reopen with repair=True (or run `agentgov "
                    f"repair`) to rebuild the caches from the chain. No money moves."
                )
            if store.read_only:
                raise LedgerIntegrityError(
                    f"{problems[0]}{more}; a read-only store cannot be repaired"
                )
            store.rebuild_caches(
                nodes=tuple(governance.nodes.values()),
                control_events=tuple(governance.chain_events),
                authorizations=tuple(auths.values()),
            )
            self._repairs = tuple(problems)
            for problem in problems:
                audit_log.warning(f"{_AUDIT_VERSION}|repair|{problem}")

        for key, chosen in identities.items():
            self._ledger._reassign_holds(key, chosen)
        self._legacy_events = legacy
        self._adopt_governance(governance)
        self._open_auths = auths
        if store.read_only:
            self._governance = governance
        elif self._ledger._state.saw_v1 and not self._ledger._state.saw_v2:
            self._seal(legacy)

        # Fail closed: the same standard the ledger's own chain check holds
        # itself to. A restored governor that does not check out is refused,
        # not served with degraded confidence.
        self.verify_integrity()

    def _adopt_governance(self, governance: _Governance) -> None:
        self._nodes = governance.nodes
        self._roots = governance.roots
        self._control_events = governance.events
        breakers = {scope_id: _BreakerState() for scope_id in governance.nodes}
        for scope_id, (tripped_at, reason) in governance.tripped.items():
            breakers[scope_id].tripped_at = tripped_at
            breakers[scope_id].reason = reason
        self._breakers = breakers

    def _seal(self, legacy: Sequence[ControlEvent]) -> None:
        """Commit a pre-0.1.2 database's unchained control events into the chain."""
        with self._lock:
            pending = self._ledger._begin()
            pending.post(
                [
                    LedgerLine(
                        entry_type=EntryType.SEAL,
                        direction=Direction.NONE,
                        scope_id="",
                        amount=ZERO,
                        memo=_seal_memo(legacy),
                    )
                ]
            )
            self._ledger._commit(pending)

    def _reconcile_authorizations(
        self,
        rows: Sequence[PersistedAuthorization],
        index: _HoldIndex,
        *,
        repairing: bool,
        state: _ChainState | None = None,
    ) -> tuple[dict[uuid.UUID, Authorization], list[str], dict[_HoldKey, list[LedgerEntry]]]:
        """Match stored authorization rows against the chain's open holds.

        Every open hold must be named by exactly one row and every row must
        name an open hold, in the same scope, for the same amount. A row that
        names a hold the chain already released is the state a v0.1.1 crash
        could leave behind, and releasing it again would hand the same funds
        back twice; it is reported, never served.

        :param state: The chain state to match against; this ledger's own
            when omitted.
        :returns: The authorizations to serve (repaired when ``repairing``),
            the disagreements found, and the open-hold identities to adopt for
            ambiguous pre-0.1.2 keys.
        """
        if state is None:
            state = self._ledger._state
        problems: list[str] = []
        result: dict[uuid.UUID, Authorization] = {}
        ambiguous_rows: dict[_HoldKey, list[Authorization]] = {}
        named: set[uuid.UUID] = set()

        for row in rows:
            if row.entry_id in named:
                problems.append(f"two open authorizations name hold {row.entry_id}")
                continue
            named.add(row.entry_id)
            hold = state.holds.get(row.entry_id) or index.hold(row.entry_id)
            if hold is None:
                problems.append(
                    f"open authorization {row.authorization_id} references missing hold "
                    f"entry {row.entry_id}"
                )
                continue
            if hold.scope_id != row.scope_id or hold.amount != row.amount:
                problems.append(
                    f"open authorization {row.authorization_id} records {row.amount} in "
                    f"{row.scope_id!r}, but its hold encumbered {hold.amount} in "
                    f"{hold.scope_id!r}"
                )
                continue
            authorization = Authorization(
                authorization_id=row.authorization_id,
                scope_id=row.scope_id,
                amount=row.amount,
                opened_at=row.opened_at,
                entry=hold,
            )
            key = _hold_key(hold)
            if hold.entry_id not in state.holds and index.released(hold.entry_id):
                problems.append(
                    f"open authorization {row.authorization_id} references hold "
                    f"{hold.entry_id}, which the chain shows was already released; "
                    f"acting on it would return the same funds twice"
                )
            elif key in state.ambiguous:
                ambiguous_rows.setdefault(key, []).append(authorization)
            elif hold.entry_id not in state.holds:
                problems.append(
                    f"open authorization {row.authorization_id} references hold "
                    f"{hold.entry_id}, which the chain shows was already released; "
                    f"acting on it would return the same funds twice"
                )
            else:
                result[row.authorization_id] = authorization

        for hold_id, hold in state.holds.items():
            if _hold_key(hold) in state.ambiguous or hold_id in named:
                continue
            problems.append(
                f"hold {hold_id} of {hold.amount} in {hold.scope_id!r} is open in the chain "
                f"but no authorization names it; its funds would stay encumbered with "
                f"nothing able to release them"
            )
            if repairing:
                result[hold_id] = _authorization_for(hold)

        identities: dict[_HoldKey, list[LedgerEntry]] = {}
        for key in sorted(state.ambiguous, key=repr):
            open_holds = [e for e in state.holds.values() if _hold_key(e) == key]
            candidates = ambiguous_rows.get(key, [])
            if len(candidates) != len(open_holds):
                scope_id, amount = key
                problems.append(
                    f"{len(open_holds)} hold(s) of {amount} are open in {scope_id!r} but "
                    f"{len(candidates)} authorization(s) name one"
                )
            kept = candidates[: len(open_holds)]
            chosen = [authorization.entry for authorization in kept]
            chosen_ids = {hold.entry_id for hold in chosen}
            for authorization in kept:
                result[authorization.authorization_id] = authorization
            for hold in open_holds:
                if len(chosen) == len(open_holds):
                    break
                if hold.entry_id not in chosen_ids:
                    chosen.append(hold)
                    result[hold.entry_id] = _authorization_for(hold)
            identities[key] = chosen
        return result, problems, identities

    # -- refresh ----------------------------------------------------------

    def refresh(self) -> int:
        """Catch a read-only view up with the process writing the ledger.

        A read-only manager is a snapshot of the database at the moment it was
        opened. This reads everything committed since — entries, and any open
        authorizations — in one consistent read, verifies the new entries
        against the head this view already verified (hash links, hashes,
        balances and hold pairing, exactly as a full open would), and applies
        them: balances, topology and breaker state all move forward.

        A writable manager is the only writer of its store, so it is always
        current; for it, and for a manager with no store, this is a no-op.

        All or nothing: every new entry and cache row is verified against a
        staged copy of this view, and the view changes only once all of it
        checks out.

        :returns: How many new entries were applied.
        :raises LedgerIntegrityError: If the ledger was rewritten under this
            view, or anything new fails verification. The view keeps serving
            exactly what it last verified, and every later refresh fails the
            same way: a view that cannot follow the chain never claims to.
        """
        store = self._store
        if store is None or not store.read_only:
            return 0
        with self._lock:
            if self._unusable is not None:
                raise LedgerIntegrityError(
                    f"this read-only view stopped following the ledger: {self._unusable}"
                )
            try:
                return self._catch_up(store)
            except BaseException as exc:
                # The chain moved in a way this view cannot verify. Whatever it
                # holds now may be partly updated, so it serves nothing more:
                # every later refresh fails the same way, and a caller that
                # refreshes before acting (as a pre-commit check does) fails
                # closed.
                self._unusable = str(exc)
                raise

    def _catch_up(self, store: PersistenceStore) -> int:
        ledger = self._ledger
        before = len(ledger)
        delta = store.snapshot(after_sequence=before, after_control_row=self._control_high_water)
        if delta.schema_version != self._schema_version:
            # The writer upgraded the database under this view. Start over
            # from a full, verified read rather than patching across it.
            self._reload(store)
            return len(ledger) - before
        if before and delta.anchor_hash != ledger.head_hash:
            raise LedgerIntegrityError(
                f"the ledger was rewritten under this reader: entry {before} no longer "
                f"carries the head this view verified"
            )
        governance = self._governance
        if governance is None:  # pragma: no cover - set for every read-only restore
            raise RuntimeError("read-only manager has no governance view")
        if delta.legacy_control_events and ledger._state.saw_v2:
            raise LedgerIntegrityError(
                "control_events gained rows outside the chain after the ledger was sealed"
            )

        # Stage: verify everything against copies. Nothing this view serves
        # changes until all of it has checked out.
        state = ledger._state.copy()
        view = _Overlay(state)
        for entry in delta.entries:
            view.apply(entry)
        view.merge()
        if delta.entries or delta.legacy_control_events:
            governance = governance.copy()
            for entry in delta.entries:
                governance.apply(entry)
            for event in delta.legacy_control_events:
                governance.apply_legacy_event(event)
        verified = ledger._entries
        auths, problems, identities = self._reconcile_authorizations(
            delta.authorizations,
            _HoldIndex(lambda: itertools.chain(verified, delta.entries)),
            repairing=False,
            state=state,
        )
        if problems:
            raise LedgerIntegrityError(problems[0])
        for key, chosen in identities.items():
            _reassign_holds(state, key, chosen)

        # Publish. Nothing below can fail.
        if delta.entries:
            ledger._publish([*verified, *delta.entries], state)
        else:
            ledger._publish(verified, state)
        if governance is not self._governance:
            self._governance = governance
            self._nodes, self._roots = governance.nodes, governance.roots
            self._control_events = governance.events
            self._sync_breakers(governance)
        if delta.legacy_control_events:
            self._legacy_events = (*self._legacy_events, *delta.legacy_control_events)
        self._control_high_water = delta.control_high_water
        self._open_auths = auths
        return len(delta.entries)

    def _reload(self, store: PersistenceStore) -> None:
        """Rebuild this read-only view from a fresh, full, verified read.

        The new view is built and verified on its own, exactly as a fresh open
        would, and adopted whole only once it checks out.
        """
        fresh = BudgetManager(policy=self._policy, store=store)
        self._ledger._publish(fresh._ledger._entries, fresh._ledger._state)
        self._nodes, self._roots = fresh._nodes, fresh._roots
        self._control_events = fresh._control_events
        self._breakers = fresh._breakers
        self._open_auths = fresh._open_auths
        self._legacy_events = fresh._legacy_events
        self._governance = fresh._governance
        self._schema_version = fresh._schema_version
        self._control_high_water = fresh._control_high_water

    def _sync_breakers(self, governance: _Governance) -> None:
        for scope_id in governance.nodes:
            state = self._breakers.setdefault(scope_id, _BreakerState())
            tripped = governance.tripped.get(scope_id)
            state.tripped_at, state.reason = tripped if tripped is not None else (None, "")

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
    def repairs(self) -> tuple[str, ...]:
        """What ``repair=True`` rebuilt when this manager opened, if anything."""
        return self._repairs

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
        :raises ValueError: If ``envelope`` is not positive, or ``scope_id``
            is empty.
        """
        amount = _credit(envelope)
        if amount <= ZERO:
            raise ValueError(f"envelope must be positive, got {amount}")
        _require_scope_id(scope_id)

        with self._lock:
            if scope_id in self._nodes:
                raise DuplicateScopeError(scope_id)
            pending = self._ledger._begin()
            (entry,) = pending.post(
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
                created_at=entry.timestamp,
            )
            pending.batch.nodes.append(node)
            self._ledger._commit(pending)

            self._nodes[scope_id] = node
            self._roots.append(scope_id)
            self._breakers[scope_id] = _BreakerState()
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
            pending = self._ledger._begin()
            (entry,) = pending.post(
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
            pending.batch.nodes.append(
                dataclasses.replace(node, allocated=node.allocated + credited)
            )
            self._ledger._commit(pending)
            node.allocated += credited
            return entry

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
        :raises ValueError: If ``amount`` is not positive, or ``child_id``
            is empty.
        """
        granted = _credit(amount)
        if granted <= ZERO:
            raise ValueError(f"delegated amount must be positive, got {granted}")
        _require_scope_id(child_id)

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

            note = memo or f"sub-budget delegated to {child_id}"
            pending = self._ledger._begin()
            entries = pending.post(
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
                scope_id=child_id,
                parent_id=parent_id,
                depth=depth,
                allocated=granted,
                created_at=entries[1].timestamp,
            )
            pending.batch.nodes.append(child)
            self._ledger._commit(pending)

            self._nodes[child_id] = child
            self._breakers[child_id] = _BreakerState()
            parent.child_ids.append(child_id)
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
        The hold's entry and its open-authorization record become durable in
        one transaction.

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
            balance. Trips the breaker; no money moves, and the only entry
            written is the zero-value trip.
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

            pending = self._ledger._begin()
            (entry,) = pending.post(
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
            auth = _authorization_for(entry)
            pending.batch.opened.append(auth)
            self._ledger._commit(pending)
            self._open_auths[auth.authorization_id] = auth
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
        Both name the hold they settle. The settled cost rounds **up**.

        The release, the spend, the removal of the open authorization and —
        when the settlement exhausts or overdraws the scope — the breaker
        trip all become durable together, in one store transaction. A crash
        can no longer leave an authorization open for a hold the chain
        already released.

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

            scope_id = authorization.scope_id
            hold_id = authorization.entry.entry_id
            pending = self._ledger._begin()
            _, spend_entry = pending.post(
                [
                    LedgerLine(
                        entry_type=EntryType.HOLD_VOID,
                        direction=Direction.CREDIT,
                        scope_id=scope_id,
                        amount=authorization.amount,
                        counterparty_id=None,
                        memo="authorization captured",
                        ref=hold_id,
                    ),
                    LedgerLine(
                        entry_type=EntryType.SPEND,
                        direction=Direction.DEBIT,
                        scope_id=scope_id,
                        amount=settled,
                        counterparty_id=None,
                        memo=memo or "settled call cost",
                        ref=hold_id,
                    ),
                ]
            )
            pending.batch.closed.append(authorization.authorization_id)

            overdraft = -spend_entry.balance_after if spend_entry.balance_after < ZERO else None
            trip = None
            if overdraft is not None:
                trip = self._stage_trip(
                    pending,
                    scope_id,
                    f"settled cost {settled} overran authorization "
                    f"{authorization.amount}; overdrawn by {overdraft}",
                )
            elif self._exhausted(pending, scope_id, settling=authorization):
                trip = self._stage_trip(pending, scope_id, "spend envelope exhausted")

            self._ledger._commit(pending)
            # Only now that the settlement is durable does the hold leave the
            # open set: a failed commit above leaves it open for a retry or an
            # operator to reconcile, instead of orphaning it.
            del self._open_auths[authorization.authorization_id]
            if trip is not None:
                self._apply_trip(trip)

            if overdraft is not None:
                raise DenialOfWalletError(
                    settled,
                    settled - overdraft,
                    scope_id,
                    overspent=True,
                )
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

    def anchor(self, scope_id: str, memo: str) -> LedgerEntry:
        """Commit an external record into the chain, moving no money.

        Posts a zero-value :attr:`EntryType.ANCHOR` entry whose ``memo`` — a
        digest, typically another hash chain's head — is thereby covered by
        this chain's hashes: editing it afterwards breaks verification. This
        is how a system that records something other than money, such as an
        escrow of database writes, binds its own history to this one.

        Accepted on a halted scope. An anchor is evidence, not spend, and a
        halt is precisely when the evidence matters.

        :param scope_id: The scope the record belongs to.
        :param memo: The record, or its digest. Must not be empty.
        :returns: The committed anchor entry.
        :raises UnknownScopeError: If no such scope is registered.
        :raises ValueError: If ``memo`` is empty.
        """
        if not memo:
            raise ValueError("an anchor must carry the record it commits to")
        with self._lock:
            self._require_node(scope_id)
            (entry,) = self._ledger.post(
                [
                    LedgerLine(
                        entry_type=EntryType.ANCHOR,
                        direction=Direction.NONE,
                        scope_id=scope_id,
                        amount=ZERO,
                        memo=memo,
                    )
                ]
            )
            return entry

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

        Every release is an ordinary :attr:`EntryType.HOLD_VOID` entry naming
        its hold, so the reconciliation is as auditable as the spend would
        have been, and a hold the chain already released can never be
        released again.

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

        The trip is a zero-value :attr:`EntryType.CIRCUIT_TRIPPED` entry in
        the chain, so it survives a restart and cannot be deleted without
        breaking verification.

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
        not stopped. Reset is an explicit operator action and is recorded as a
        :attr:`EntryType.CIRCUIT_RESET` entry.

        :param scope_id: The scope to re-arm.
        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            self._require_node(scope_id)
            state = self._breakers[scope_id]
            if state.tripped_at is None:
                return
            pending = self._ledger._begin()
            entry = self._stage_control(
                pending, EntryType.CIRCUIT_RESET, scope_id, "operator reset"
            )
            self._ledger._commit(pending)
            state.tripped_at = None
            state.reason = ""
            state.call_times.clear()
            self._control_events.append(_event_for(entry))
            self._log_control(entry)

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

        Verifies the hash chain, running balances and hold pairing, the
        conservation identity, the structural consistency of the delegation
        tree, and that the tree, the breaker states and the open
        authorizations are exactly what the chain implies. Cheap enough to
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

            self._verify_against_chain()

    def _verify_against_chain(self) -> None:
        """The tree, breakers and open holds must be what the chain implies."""
        derived = _Governance.from_chain(self._ledger.entries(), self._legacy_events)
        for scope_id, node in self._nodes.items():
            expected = derived.nodes.get(scope_id)
            if expected is None:
                raise LedgerIntegrityError(
                    "scope is registered but the chain never created it", scope_id
                )
            if (node.parent_id, node.depth, node.allocated) != (
                expected.parent_id,
                expected.depth,
                expected.allocated,
            ):
                raise LedgerIntegrityError(
                    f"topology disagrees with the chain: registered with parent "
                    f"{node.parent_id!r}, depth {node.depth}, allocation {node.allocated}; "
                    f"the chain implies parent {expected.parent_id!r}, depth "
                    f"{expected.depth}, allocation {expected.allocated}",
                    scope_id,
                )
        unregistered = sorted(derived.nodes.keys() - self._nodes.keys())
        if unregistered:
            raise LedgerIntegrityError(
                f"the chain created scope(s) {', '.join(unregistered)} that are not registered"
            )

        halted = {s for s, state in self._breakers.items() if state.tripped_at is not None}
        if halted != set(derived.tripped):
            raise LedgerIntegrityError(
                f"breaker state disagrees with the chain: halted here "
                f"{sorted(halted)}, halted by the chain {sorted(derived.tripped)}"
            )
        if [e.event_id for e in self._control_events] != [e.event_id for e in derived.events]:
            raise LedgerIntegrityError("control events disagree with the chain")

        held = {auth.entry.entry_id for auth in self._open_auths.values()}
        if held != set(self._ledger._state.holds):
            raise LedgerIntegrityError("open authorizations disagree with the chain's open holds")

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
        """Latch the breaker for ``scope_id`` in its own unit of work. Lock held."""
        if self._breakers[scope_id].tripped_at is not None:
            return
        pending = self._ledger._begin()
        entry = self._stage_trip(pending, scope_id, reason)
        self._ledger._commit(pending)
        if entry is not None:
            self._apply_trip(entry)

    def _stage_trip(self, pending: _Pending, scope_id: str, reason: str) -> LedgerEntry | None:
        """Add a trip to a unit of work, unless the scope is already latched."""
        if self._breakers[scope_id].tripped_at is not None:
            return None
        return self._stage_control(pending, EntryType.CIRCUIT_TRIPPED, scope_id, reason)

    def _stage_control(
        self, pending: _Pending, kind: EntryType, scope_id: str, reason: str
    ) -> LedgerEntry:
        (entry,) = pending.post(
            [
                LedgerLine(
                    entry_type=kind,
                    direction=Direction.NONE,
                    scope_id=scope_id,
                    amount=ZERO,
                    memo=reason,
                )
            ]
        )
        pending.batch.control_events.append(_event_for(entry))
        return entry

    def _apply_trip(self, entry: LedgerEntry) -> None:
        """Latch in memory a trip that is already durable. Lock held."""
        state = self._breakers[entry.scope_id]
        state.tripped_at = entry.timestamp
        state.reason = entry.memo
        self._control_events.append(_event_for(entry))
        self._log_control(entry)

    def _log_control(self, entry: LedgerEntry) -> None:
        audit_log.warning(
            f"{entry.version}|ctrl={entry.entry_type.value}|ts={_iso(entry.timestamp)}"
            f"|scope={entry.scope_id}|head={entry.prev_hash[:16]}|reason={entry.memo}",
            extra={
                "agentgov_control": {
                    "event_id": str(entry.entry_id),
                    "event_type": entry.entry_type.value,
                    "scope_id": entry.scope_id,
                    "reason": entry.memo,
                    "timestamp": _iso(entry.timestamp),
                    "ledger_head_hash": entry.prev_hash,
                }
            },
        )

    def _exhausted(self, pending: _Pending, scope_id: str, *, settling: Authorization) -> bool:
        """Whether settling this authorization leaves the scope spent out.

        Only once every other hold on the scope has settled, so a transient
        zero caused by an in-flight authorization is not mistaken for
        exhaustion.
        """
        if not self._policy.trip_on_exhaustion:
            return False
        if pending.balance(scope_id) > ZERO:
            return False
        return not any(
            auth.scope_id == scope_id and auth.authorization_id != settling.authorization_id
            for auth in self._open_auths.values()
        )

    def _require_open_authorization(self, authorization: Authorization, detail: str) -> None:
        """Raise if this authorization was already settled. Lock held.

        Deliberately does *not* remove it yet — that happens only once the
        settling transaction has actually committed, so a durable-write
        failure during settlement leaves the hold open rather than orphaned.
        Nothing can race between this check and that commit: both run under
        the same lock acquisition in :meth:`capture`/:meth:`void`.
        """
        if authorization.authorization_id not in self._open_auths:
            raise DoubleSpendError(
                authorization.scope_id, str(authorization.authorization_id), detail
            )

    def _void_locked(self, authorization: Authorization, memo: str) -> LedgerEntry:
        """Release a hold and close its authorization in one unit of work. Lock held."""
        pending = self._ledger._begin()
        (entry,) = pending.post(
            [
                LedgerLine(
                    entry_type=EntryType.HOLD_VOID,
                    direction=Direction.CREDIT,
                    scope_id=authorization.scope_id,
                    amount=authorization.amount,
                    counterparty_id=None,
                    memo=memo,
                    ref=authorization.entry.entry_id,
                )
            ]
        )
        pending.batch.closed.append(authorization.authorization_id)
        self._ledger._commit(pending)
        del self._open_auths[authorization.authorization_id]
        return entry


def _require_scope_id(scope_id: str) -> None:
    if not scope_id:
        raise ValueError("a scope id must not be empty")


def _authorization_for(hold: LedgerEntry) -> Authorization:
    """The authorization a HOLD entry places, identified by the entry itself."""
    return Authorization(
        authorization_id=hold.entry_id,
        scope_id=hold.scope_id,
        amount=hold.amount,
        opened_at=hold.timestamp,
        entry=hold,
    )


class _HoldIndex:
    """Every HOLD entry by id, and every hold a named release closed.

    Built from the chain on first use: a restore has the entries in hand
    anyway, and a refresh only needs it for a row that is not an open hold,
    which is an error or pre-0.1.2 history.
    """

    __slots__ = ("_holds", "_released", "_source")

    def __init__(self, source: Callable[[], Iterable[LedgerEntry]]) -> None:
        self._source = source
        self._holds: dict[uuid.UUID, LedgerEntry] | None = None
        self._released: set[uuid.UUID] = set()

    def _build(self) -> dict[uuid.UUID, LedgerEntry]:
        if self._holds is None:
            self._holds = {}
            for entry in self._source():
                if entry.entry_type is EntryType.HOLD:
                    self._holds[entry.entry_id] = entry
                elif entry.entry_type is EntryType.HOLD_VOID and entry.ref is not None:
                    self._released.add(entry.ref)
        return self._holds

    def hold(self, entry_id: uuid.UUID) -> LedgerEntry | None:
        return self._build().get(entry_id)

    def released(self, entry_id: uuid.UUID) -> bool:
        self._build()
        return entry_id in self._released


def _node_row_problems(governance: _Governance, rows: Sequence[PersistedNode]) -> list[str]:
    """Stored topology rows that disagree with the chain."""
    problems: list[str] = []
    stored = {row.scope_id: row for row in rows}
    for scope_id, node in governance.nodes.items():
        row = stored.get(scope_id)
        if row is None:
            problems.append(f"scope {scope_id!r} is in the chain but missing from the nodes table")
            continue
        if (row.parent_id, row.depth, row.allocated) != (
            node.parent_id,
            node.depth,
            node.allocated,
        ):
            problems.append(
                f"the nodes table records scope {scope_id!r} with parent {row.parent_id!r}, "
                f"depth {row.depth}, allocation {row.allocated}; the chain implies parent "
                f"{node.parent_id!r}, depth {node.depth}, allocation {node.allocated}"
            )
    for scope_id in sorted(stored.keys() - governance.nodes.keys()):
        problems.append(f"the nodes table lists scope {scope_id!r}, which the chain never created")
    return problems


def _control_row_problems(governance: _Governance, rows: Sequence[ControlEvent]) -> list[str]:
    """Stored control-event rows that disagree with the chain's control entries."""
    problems: list[str] = []
    stored: dict[uuid.UUID, ControlEvent] = {}
    for row in rows:
        if row.entry_id is None:
            continue
        if row.entry_id in stored:
            problems.append(f"control_events records chain entry {row.entry_id} twice")
        stored[row.entry_id] = row
    chained = {e.entry_id: e for e in governance.chain_events if e.entry_id is not None}
    for entry_id, event in chained.items():
        found = stored.get(entry_id)
        if found is None:
            problems.append(
                f"the {event.event_type} of {event.scope_id!r} at chain entry {entry_id} is "
                f"missing from the control_events table"
            )
        elif found != event:
            problems.append(f"the control_events row for chain entry {entry_id} disagrees with it")
    for entry_id in sorted(stored.keys() - chained.keys(), key=str):
        problems.append(
            f"control_events names chain entry {entry_id}, which is not a control entry "
            f"in the chain"
        )
    return problems
