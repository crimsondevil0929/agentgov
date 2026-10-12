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
import functools
import hashlib
import itertools
import json
import logging
import re
import threading
import time
import uuid
import warnings
from collections import Counter, deque
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager, nullcontext
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from decimal import (
    ROUND_CEILING,
    ROUND_FLOOR,
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    Inexact,
    InvalidOperation,
    Overflow,
)
from enum import Enum, unique
from typing import TYPE_CHECKING, Any, Concatenate, Final, NoReturn, ParamSpec, TypeVar

from agentgov.exceptions import (
    BudgetExceededError,
    CircuitOpenError,
    DenialOfWalletError,
    DoubleSpendError,
    DuplicateScopeError,
    IdempotencyConflictError,
    LedgerIntegrityError,
    LedgerRollbackError,
    ReadOnlyLedgerError,
    RunawayLoopDetectedError,
    StorageError,
    SubBudgetAllocationError,
    UnknownScopeError,
)

if TYPE_CHECKING:
    from agentgov.metrics import Metrics

    # Storage imports core (LedgerEntry, ControlEvent, ...) for its Protocol
    # methods; guarding this import under TYPE_CHECKING avoids the cycle
    # while still giving mypy the real types for the `store=` parameters.
    from agentgov.storage import (
        JoinableStore,
        PersistedAuthorization,
        PersistedNode,
        PersistenceStore,
        SharedStore,
        StoreImage,
        WriterSession,
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
    "JoinedTransaction",
    "Ledger",
    "LedgerEntry",
    "LedgerLine",
    "SettlementClaim",
    "WriteBatch",
    "format_audit_line",
    "money",
]

audit_log: Final = logging.getLogger("agentgov.audit")
logger: Final = logging.getLogger("agentgov")

QUANTUM: Final = Decimal("0.00000001")
"""Smallest representable monetary unit: 1e-8 USD.

Sub-cent agent traffic makes cent precision useless — a single Haiku call can
cost well under $0.0001 — so the ledger settles in hundred-millionths and
never in floating point.
"""

ZERO: Final = Decimal("0")
MAX_AMOUNT: Final = Decimal("1000000000000")
"""Hard ceiling on any single amount (1e12 USD). A request above this is
rejected as malformed rather than quantized, which catches unit-confusion
bugs and keeps every total far inside the ledger's own context."""

_ARITHMETIC: Final = Context(
    prec=50,
    rounding=ROUND_HALF_EVEN,
    Emin=-999999,
    Emax=999999,
    traps=[InvalidOperation, DivisionByZero, Overflow, Inexact],
)
"""The context every balance and total is computed in.

Never the calling thread's: :mod:`decimal` contexts are thread-local and
belong to the host application, which may lower the precision for its own
formatting. Ledger arithmetic that followed it could write a rounded balance
that no replay reproduces, and a ledger that cannot be replayed cannot be
opened. Fifty digits hold any sum of amounts under :data:`MAX_AMOUNT` many
times over, and :class:`~decimal.Inexact` is trapped, so an operation that
would round raises instead of being written.
"""

_ROUNDING: Final = Context(
    prec=50,
    rounding=ROUND_HALF_EVEN,
    Emin=-999999,
    Emax=999999,
    traps=[InvalidOperation, DivisionByZero, Overflow],
)
"""The context for the ledger's deliberate rounding: quantizing an amount to
:data:`QUANTUM` (costs up, credits down) and pricing tokens. The same as
:data:`_ARITHMETIC` except that rounding is the point, so it is not trapped."""

_add = _ARITHMETIC.add
_subtract = _ARITHMETIC.subtract

GENESIS_HASH: Final = "0" * 64
"""``prev_hash`` of the first entry in a chain."""

_AUDIT_V1: Final = "AGOV1"
"""Hash payload of v0.1.0 and v0.1.1. Carries no hold reference."""

_AUDIT_V2: Final = "AGOV2"
"""Hash payload from v0.1.2: adds ``ref``, the hold a release or spend settles."""

_AUDIT_V3: Final = "AGOV3"
"""Hash payload from v1.0: RFC 8785 canonical JSON, amounts as fixed-point
strings. Adds the CHECKPOINT entry and lets a REVERSAL name the spend it
reverses. Specified in docs/LEDGER_FORMAT.md, with vectors in vectors/agov/."""

_AUDIT_VERSION: Final = _AUDIT_V3
"""The payload version new entries are written with."""

_KNOWN_VERSIONS: Final = frozenset({_AUDIT_V1, _AUDIT_V2, _AUDIT_V3})

MAX_ID_BYTES: Final = 1024
"""The longest scope id, in UTF-8 bytes, an AGOV3 entry may carry."""

MAX_MEMO_BYTES: Final = 65536
"""The longest memo, in UTF-8 bytes, an AGOV3 entry may carry."""


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
    if value.copy_abs() > MAX_AMOUNT:
        raise ValueError(f"{label} exceeds the maximum of {MAX_AMOUNT}: {value}")
    # In the ledger's own context, never the caller's: a host thread at low
    # precision would otherwise refuse (or round) an exact amount.
    return value.quantize(QUANTUM, rounding=rounding, context=_ROUNDING)


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


_DIRECTIONS: Final = {member.value: member for member in Direction}


def _direction(value: str) -> Direction:
    """``Direction(value)``, without the call's cost: rows decode by the thousand."""
    found = _DIRECTIONS.get(value)
    return found if found is not None else Direction(value)


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

    CHECKPOINT = "checkpoint"
    """Commits a snapshot of the chain state as of an earlier sequence into
    the chain, by digest (``memo``), so a governor can open from the snapshot
    instead of replaying history. AGOV3 only. Moves no money and belongs to
    no scope (``scope_id == ""``)."""


_ENTRY_TYPES: Final = {member.value: member for member in EntryType}


def _entry_type(value: str) -> EntryType:
    """``EntryType(value)``, without the call's cost: rows decode by the thousand."""
    found = _ENTRY_TYPES.get(value)
    return found if found is not None else EntryType(value)


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
    EntryType.CHECKPOINT: frozenset({Direction.NONE}),
}

_BALANCED_TYPES: Final = frozenset({EntryType.ALLOCATION, EntryType.RELEASE})
"""Entry types that move money *between* scopes and must therefore post
equal debits and credits within a single transaction."""

_ZERO_VALUE_TYPES: Final = frozenset(
    {
        EntryType.CIRCUIT_TRIPPED,
        EntryType.CIRCUIT_RESET,
        EntryType.ANCHOR,
        EntryType.SEAL,
        EntryType.CHECKPOINT,
    }
)
"""Entry types that record an event without moving money."""

_SCOPELESS_TYPES: Final = frozenset({EntryType.SEAL, EntryType.CHECKPOINT})
"""Entry types that belong to no scope (``scope_id == ""``)."""

_REFERENCING_TYPES: Final = frozenset({EntryType.HOLD_VOID, EntryType.SPEND})
"""Entry types that may name the hold they settle."""

_V3_REFERENCING_TYPES: Final = frozenset({*_REFERENCING_TYPES, EntryType.REVERSAL})
"""From AGOV3, a REVERSAL may also name the SPEND it reverses."""

_CHECKPOINT_MEMO: Final = re.compile(
    r"\Aagentgov-checkpoint v1 seq=([1-9][0-9]*) sha256=([0-9a-f]{64})\Z"
)
"""A CHECKPOINT entry's memo: the sequence its snapshot is of, and the
snapshot's digest (docs/LEDGER_FORMAT.md, "Checkpoints")."""


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
            # copy_negate is exact; unary minus would round to the caller's context.
            return self.amount.copy_negate()
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
            "amount": _amount_text(self, self.amount),
            "balance_after": _amount_text(self, self.balance_after),
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "memo": self.memo,
            "ref": str(self.ref) if self.ref is not None else "",
        }


def _iso(moment: datetime) -> str:
    """Format a UTC datetime as a fixed-width ISO-8601 instant."""
    if moment.tzinfo is not UTC:
        moment = moment.astimezone(UTC)
    if moment.year < 1000:  # strftime pads these per platform; keep its answer
        return moment.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"
    return moment.isoformat(timespec="microseconds")[:-6] + "Z"  # "+00:00" -> "Z"


def _parse_iso(text: str) -> datetime:
    """Inverse of :func:`_iso`.

    Exact round-trip precision matters here: a persisted entry's hash was
    computed over ``_iso(timestamp)``, so reloading it from storage and
    reformatting a *different* datetime representation would make
    :meth:`LedgerEntry.recompute_hash` disagree with the stored hash even
    though nothing was tampered with.
    """
    if _INSTANT.match(text):  # what _iso writes; fromisoformat reads "Z" as UTC
        return datetime.fromisoformat(text)
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


_INSTANT: Final = re.compile(
    r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z"
)


def _fixed(amount: Decimal) -> str:
    """An amount as AGOV3 writes it: fixed-point, exactly eight decimals.

    ``"0.00000001"``, never ``"1E-8"``; ``"0.00000000"``, never ``"-0.00000000"``.
    The grammar is ``-?(0|[1-9][0-9]*)\\.[0-9]{8}``, which any language can
    produce and parse without reproducing CPython's decimal formatting.

    :raises decimal.Inexact: If ``amount`` carries more than eight decimals.
    """
    quantized = amount.quantize(QUANTUM, context=_ARITHMETIC)
    if quantized.is_zero():
        return "0.00000000"
    return format(quantized, "f")


def _amount_text(entry: LedgerEntry, amount: Decimal) -> str:
    """``amount`` as the entry's own version renders it."""
    return _fixed(amount) if entry.version == _AUDIT_V3 else str(amount)


def _check_text(text: str, label: str, *, limit: int, identifier: bool) -> str | None:
    """Why ``text`` cannot go into an AGOV3 entry, or ``None`` if it can.

    Every string must be Unicode text (no lone surrogates: canonical JSON is
    defined over Unicode, and neither store can hold them), within ``limit``
    UTF-8 bytes, and free of NUL (which PostgreSQL cannot store). A scope id
    is an identifier, so it may hold no control character at all.
    """
    if text.isascii():
        size = len(text)
    else:
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            return f"the {label} is not valid Unicode text (it holds a lone surrogate)"
    if size > limit:
        return f"the {label} is {size} bytes of UTF-8; at most {limit} are allowed"
    if identifier:
        if _CONTROL.search(text):
            return f"the {label} holds a control character"
    elif "\x00" in text:
        return f"the {label} holds a NUL character"
    return None


_CONTROL: Final = re.compile("[\x00-\x1f\x7f-\x9f]")
"""Unicode's control characters, general category ``Cc``: C0, DEL and C1.
The set is closed by Unicode's stability policy."""

_escape_json: Final = json.encoder.encode_basestring


def _quote(text: str | None) -> str:
    """A JSON string as json.dumps(ensure_ascii=False) writes it, or null."""
    return "null" if text is None else str(_escape_json(text))


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

    :raises ValueError: If ``version`` is not a known payload version, or an
        AGOV3 entry's text is not Unicode.
    """
    if version == _AUDIT_V3:
        if _HEX64.fullmatch(prev_hash):
            # The canonical document written out directly: the same bytes as
            # the dict below through json.dumps, without building it. Only the
            # free text needs escaping; every other value is a UUID, an
            # enum's value, a fixed-point amount, an instant or an integer.
            reference = "null" if ref is None else f'"{ref}"'
            text = (
                f'{{"amount":"{_fixed(amount)}","balance_after":"{_fixed(balance_after)}",'
                f'"counterparty_id":{_quote(counterparty_id)},"direction":"{direction.value}",'
                f'"entry_id":"{entry_id}","entry_type":"{entry_type.value}","format":"AGOV3",'
                f'"memo":{_quote(memo)},"prev_hash":"{prev_hash}",'
                f'"ref":{reference},"scope_id":{_quote(scope_id)},'
                f'"sequence":{int(sequence)},"timestamp":"{_iso(timestamp)}",'
                f'"transaction_id":"{transaction_id}"}}'
            )
            try:
                return hashlib.sha256(text.encode("utf-8")).hexdigest()
            except UnicodeEncodeError as exc:
                raise ValueError("an AGOV3 entry's text must be valid Unicode") from exc
        # RFC 8785 canonical JSON of one flat object: the keys below are in
        # canonical (sorted) order, every value is a string, null or a safe
        # integer, and json.dumps with ensure_ascii=False escapes strings
        # exactly as RFC 8785 does. Cross-checked against
        # agentgov.receipts.canonical in tests/test_ledger_format.py.
        document = {
            "amount": _fixed(amount),
            "balance_after": _fixed(balance_after),
            "counterparty_id": counterparty_id,
            "direction": direction.value,
            "entry_id": str(entry_id),
            "entry_type": entry_type.value,
            "format": _AUDIT_V3,
            "memo": memo,
            "prev_hash": prev_hash,
            "ref": str(ref) if ref is not None else None,
            "scope_id": scope_id,
            "sequence": sequence,
            "timestamp": _iso(timestamp),
            "transaction_id": str(transaction_id),
        }
        text = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
        try:
            return hashlib.sha256(text.encode("utf-8")).hexdigest()
        except UnicodeEncodeError as exc:
            raise ValueError("an AGOV3 entry's text must be valid Unicode") from exc
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


_LOG_UNSAFE: Final = re.compile(r"[^\x20-\x5b\x5d-\x7b\x7d\x7e]")
"""Anything but printable ASCII, and the two characters printable ASCII
that the line format itself uses: ``|`` and ``\\``."""


def _escape(text: str) -> str:
    """Make free text safe to place in one field of an audit line (CWE-117).

    Scope ids and memos can come from model output. Unescaped, a newline in a
    memo starts a new line in the log, and that line can be a well-formed
    forgery of an entry that was never written. Text that is printable ASCII
    and contains neither ``|`` nor ``\\`` is placed as it is, which covers
    every ordinary id and memo. Anything else is written as the body of a
    JSON string with every non-ASCII character escaped, and ``|`` escaped as
    ``\\u007c`` and DEL as ``\\u007f``: one token, no control characters, and
    reversible, since a field holds a backslash only when it is escaped this
    way (``json.loads('"' + field + '"')`` recovers the text).
    """
    if _LOG_UNSAFE.search(text) is None:
        return text
    body = json.dumps(text, ensure_ascii=True)[1:-1]
    return body.replace("|", "\\u007c").replace("\x7f", "\\u007f")


def format_audit_line(entry: LedgerEntry) -> str:
    """Render an entry as a single fixed-field audit log line.

    The shape is deliberately grep-friendly and column-stable, in the spirit
    of a wire-transfer journal::

        AGOV2|seq=0000000007|txn=<uuid>|ts=...Z|type=spend|dir=DR
              |scope=agent.research|cpty=-|amt=0.00004500|bal=0.09991000|h=1a2b3c4d
              |ref=<uuid>

    The scope, counterparty and memo are free text, and are escaped so that
    each stays one field of one line whatever it contains (see
    :func:`_escape`); the structured record passed alongside it as ``extra``
    carries them unescaped.

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
        f"|scope={_escape(entry.scope_id)}"
        f"|cpty={_escape(entry.counterparty_id) if entry.counterparty_id else '-'}"
        f"|amt={_amount_text(entry, entry.amount)}"
        f"|bal={_amount_text(entry, entry.balance_after)}"
        f"|h={entry.entry_hash[:16]}"
        + (f"|ref={entry.ref}" if entry.ref is not None else "")
        + (f"|memo={_escape(entry.memo)}" if entry.memo else "")
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

_EMPTY_ROOT: Final = hashlib.sha256(b"").digest()
"""RFC 9162's hash of the empty tree."""


def _frontier_append(
    frontier: tuple[bytes, ...], length: int, entry_hash: str
) -> tuple[bytes, ...]:
    """Add one entry to the Merkle frontier of a chain of ``length`` entries.

    The frontier is the RFC 9162 compact range over every entry hash so far:
    the roots of the perfect subtrees the binary digits of ``length`` give,
    largest first, a logarithmic number of hashes. Each entry hash is a leaf
    (``SHA-256(0x00 || hash)``); two subtrees of a size merge into one
    (``SHA-256(0x01 || left || right)``) as the length carries. A checkpoint
    records the frontier, so the root of every entry up to it, and an
    inclusion proof for any of them, can be given later without replaying.
    """
    node = hashlib.sha256(b"\x00" + bytes.fromhex(entry_hash)).digest()
    stack = list(frontier)
    carry = length
    while carry & 1:
        node = hashlib.sha256(b"\x01" + stack.pop() + node).digest()
        carry >>= 1
    stack.append(node)
    return tuple(stack)


def _frontier_root(frontier: tuple[bytes, ...]) -> bytes:
    """The RFC 9162 root of the entries a frontier covers."""
    if not frontier:
        return _EMPTY_ROOT
    root = frontier[-1]
    for node in reversed(frontier[:-1]):
        root = hashlib.sha256(b"\x01" + node + root).digest()
    return root


_HoldKey = tuple[str, Decimal]
"""A hold's scope and amount. Pre-0.1.2 releases carry nothing sharper."""

_CONTROL_TYPES: Final = frozenset({EntryType.CIRCUIT_TRIPPED, EntryType.CIRCUIT_RESET})


@dataclass(slots=True)
class _ChainState:
    """Everything the chain implies, and nothing else.

    Money (balances, totals, open holds), position (head, length) and
    governance (the delegation tree, breaker state, control events) are one
    state, derived by one set of rules (:class:`_Overlay`): what a write may
    commit is exactly what a replay accepts, so nothing accepted can later
    fail to open.

    :ivar holds: Open holds, keyed by the ``entry_id`` of the HOLD entry that
        placed them, in the order they were placed.
    :ivar ambiguous: ``(scope, amount)`` keys a pre-0.1.2 release has
        touched. Those releases did not name their hold, so within such a key
        the chain determines *how many* holds are open but not *which*; the
        open authorizations table supplies the identities.
    :ivar saw_v1: The chain contains pre-0.1.2 (``AGOV1``) entries.
    :ivar saw_v2: The chain contains entries written from v0.1.2 on.
    :ivar seal: The migration seal, once written.
    :ivar nodes: Every scope, as the FUNDING and ALLOCATION entries that
        created it describe it.
    :ivar roots: The roots, in the order they were created.
    :ivar tripped: Halted scopes: when, and why.
    :ivar legacy: Control events a pre-0.1.2 governor kept outside the chain,
        vouched for by the migration seal.
    :ivar legacy_applied: Whether ``legacy`` is folded into the state yet. It
        is folded at the first entry written from v0.1.2 on (the seal), or by
        :meth:`finish` for a chain that has none.
    :ivar spent: Each scope's lifetime spend.
    :ivar refunded: Each scope's lifetime refunds.
    :ivar hold_counts: How many holds are open in each scope.
    :ivar saw_v3: The chain contains AGOV3 entries.
    :ivar spend_refunds: How much of each spend AGOV3 refunds have named has
        been refunded, for a ledger whose history is kept in memory. A
        ledger whose store keeps history asks the store instead (an index
        of refunds by the spend they name), so its state, and its
        checkpoint snapshots, do not grow with every spend ever refunded.
    :ivar last_timestamp: The newest entry's timestamp.
    :ivar last_checkpoint: The newest CHECKPOINT entry's sequence and
        snapshot digest.
    :ivar frontier: The RFC 9162 compact range over every entry hash.
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
    nodes: dict[str, BudgetNode] = field(default_factory=dict)
    roots: list[str] = field(default_factory=list)
    tripped: dict[str, tuple[datetime, str]] = field(default_factory=dict)
    legacy: tuple[ControlEvent, ...] = ()
    legacy_applied: bool = False
    spent: dict[str, Decimal] = field(default_factory=dict)
    refunded: dict[str, Decimal] = field(default_factory=dict)
    hold_counts: dict[str, int] = field(default_factory=dict)
    saw_v3: bool = False
    spend_refunds: dict[uuid.UUID, Decimal] = field(default_factory=dict)
    last_timestamp: datetime | None = None
    last_checkpoint: tuple[int, str] | None = None
    frontier: tuple[bytes, ...] = ()

    def copy(self) -> _ChainState:
        """An independent copy, nodes included, taken in time proportional
        to the state, never to history."""
        return dataclasses.replace(
            self,
            balances=dict(self.balances),
            holds=dict(self.holds),
            ambiguous=set(self.ambiguous),
            nodes={
                scope_id: dataclasses.replace(node, child_ids=list(node.child_ids))
                for scope_id, node in self.nodes.items()
            },
            roots=list(self.roots),
            tripped=dict(self.tripped),
            spent=dict(self.spent),
            refunded=dict(self.refunded),
            hold_counts=dict(self.hold_counts),
            spend_refunds=dict(self.spend_refunds),
        )

    # -- the lookups an _Overlay layers its staged changes over -----------

    def balance(self, scope_id: str) -> Decimal:
        return self.balances.get(scope_id, ZERO)

    def open_hold(self, hold_id: uuid.UUID) -> LedgerEntry | None:
        return self.holds.get(hold_id)

    def iter_holds(self) -> Iterator[tuple[uuid.UUID, LedgerEntry]]:
        return iter(list(self.holds.items()))

    def is_ambiguous(self, key: _HoldKey) -> bool:
        return key in self.ambiguous

    def ambiguous_keys(self) -> set[_HoldKey]:
        return set(self.ambiguous)

    def node(self, scope_id: str) -> BudgetNode | None:
        return self.nodes.get(scope_id)

    def trip_of(self, scope_id: str) -> tuple[datetime, str] | None:
        return self.tripped.get(scope_id)

    def spent_by(self, scope_id: str) -> Decimal:
        return self.spent.get(scope_id, ZERO)

    def refunded_to(self, scope_id: str) -> Decimal:
        return self.refunded.get(scope_id, ZERO)

    def holds_open_in(self, scope_id: str) -> int:
        return self.hold_counts.get(scope_id, 0)

    def refunded_of_spend(self, spend_id: uuid.UUID) -> Decimal:
        return self.spend_refunds.get(spend_id, ZERO)

    def finish(self) -> None:
        """Fold in pre-0.1.2 control events, for a chain with no newer entry.

        :raises LedgerIntegrityError: If one names a scope the chain never
            created.
        """
        if not self.legacy_applied:
            view = _Overlay(self)
            view.finish()
            view.merge()


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
    """A copy-on-write view of a :class:`_ChainState`: the one rule engine.

    Every entry is verified against the view and folded into it; the state
    below changes only in :meth:`merge`. A unit of work validates its entries
    here before anything is durable, a catch-up verifies another process's
    entries here before trusting them, and a replay is this, started from an
    empty state. One set of rules for all three, covering the money (hash
    links, balances, hold pairing, balanced transfers) and the governance
    (who may be funded, delegated to, released between, halted) alike, so
    whatever a write commits a replay accepts.

    A view may sit on another view (``base``): an operation staged on top of
    a batch merges into the batch, or is dropped without touching it.

    The view also records what its entries change in the store's cache
    tables (:meth:`cache_rows`), so the caches a unit of work writes are the
    ones its entries imply, whichever path wrote them.
    """

    __slots__ = (
        "_base",
        "_children",
        "_closed",
        "_counts",
        "_events",
        "_net",
        "_nodes",
        "_opened",
        "_refunded",
        "_refunds",
        "_resolve",
        "_roots",
        "_row_scopes",
        "_settleable",
        "_spend_refunds",
        "_spent",
        "_start_head",
        "_tripped",
        "_txn",
        "ambiguous",
        "balances",
        "frontier",
        "head",
        "last_checkpoint",
        "last_timestamp",
        "legacy",
        "legacy_applied",
        "length",
        "saw_v1",
        "saw_v2",
        "saw_v3",
        "seal",
        "totals",
    )

    def __init__(
        self,
        base: _ChainState | _Overlay,
        *,
        resolve: Callable[[uuid.UUID], LedgerEntry | None] | None = None,
        refunds: Callable[[uuid.UUID, int], Decimal] | None = None,
    ) -> None:
        """:param resolve: Finds a committed entry by its ``entry_id``, for a
            REVERSAL that names the spend it reverses; inherited from a view
            this one is staged on.
        :param refunds: What the refunds naming a spend among the chain's
            first ``n`` entries add up to, for a chain whose store keeps
            history: then the state remembers no spend's refunds, and a view
            merged into it adds none. Inherited like ``resolve``."""
        self._base = base
        if isinstance(base, _Overlay):
            resolve = base._resolve if resolve is None else resolve
            refunds = base._refunds if refunds is None else refunds
        self._resolve: Callable[[uuid.UUID], LedgerEntry | None] | None = resolve
        self._refunds: Callable[[uuid.UUID, int], Decimal] | None = refunds
        self._start_head: str = base.head
        self.balances: dict[str, Decimal] = {}
        self.totals: _Totals = base.totals
        self.head: str = base.head
        self.length: int = base.length
        self.saw_v1: bool = base.saw_v1
        self.saw_v2: bool = base.saw_v2
        self.seal: LedgerEntry | None = base.seal
        self.legacy: tuple[ControlEvent, ...] = base.legacy
        self.legacy_applied: bool = base.legacy_applied
        self.saw_v3: bool = base.saw_v3
        self.last_timestamp: datetime | None = base.last_timestamp
        self.last_checkpoint: tuple[int, str] | None = base.last_checkpoint
        self.frontier: tuple[bytes, ...] = base.frontier
        self._spend_refunds: dict[uuid.UUID, Decimal] = {}
        self.ambiguous: set[_HoldKey] = set()
        self._opened: dict[uuid.UUID, LedgerEntry] = {}
        self._closed: set[uuid.UUID] = set()
        self._nodes: dict[str, BudgetNode] = {}
        self._children: dict[str, list[str]] = {}  # scopes delegated to, by parent, here
        self._row_scopes: set[str] = set()
        self._roots: list[str] = []
        self._tripped: dict[str, tuple[datetime, str] | None] = {}
        self._events: list[ControlEvent] = []
        self._spent: dict[str, Decimal] = {}
        self._refunded: dict[str, Decimal] = {}
        self._counts: dict[str, int] = {}
        self._txn: uuid.UUID | None = None
        self._settleable: set[uuid.UUID] = set()
        self._net = ZERO

    @property
    def start_head(self) -> str:
        """The base's head when this view was taken."""
        return self._start_head

    # -- lookups: staged first, then the base -----------------------------

    def balance(self, scope_id: str) -> Decimal:
        found = self.balances.get(scope_id)
        return found if found is not None else self._base.balance(scope_id)

    def open_hold(self, hold_id: uuid.UUID) -> LedgerEntry | None:
        if hold_id in self._closed:
            return None
        found = self._opened.get(hold_id)
        return found if found is not None else self._base.open_hold(hold_id)

    def iter_holds(self) -> Iterator[tuple[uuid.UUID, LedgerEntry]]:
        for hold_id, hold in self._base.iter_holds():
            if hold_id not in self._closed:
                yield hold_id, hold
        yield from list(self._opened.items())

    def is_ambiguous(self, key: _HoldKey) -> bool:
        return key in self.ambiguous or self._base.is_ambiguous(key)

    def ambiguous_keys(self) -> set[_HoldKey]:
        return self.ambiguous | self._base.ambiguous_keys()

    def node(self, scope_id: str) -> BudgetNode | None:
        found = self._nodes.get(scope_id)
        return found if found is not None else self._base.node(scope_id)

    def trip_of(self, scope_id: str) -> tuple[datetime, str] | None:
        if scope_id in self._tripped:
            return self._tripped[scope_id]
        return self._base.trip_of(scope_id)

    def spent_by(self, scope_id: str) -> Decimal:
        found = self._spent.get(scope_id)
        return found if found is not None else self._base.spent_by(scope_id)

    def refunded_to(self, scope_id: str) -> Decimal:
        found = self._refunded.get(scope_id)
        return found if found is not None else self._base.refunded_to(scope_id)

    def holds_open_in(self, scope_id: str) -> int:
        found = self._counts.get(scope_id)
        return found if found is not None else self._base.holds_open_in(scope_id)

    def refunded_of_spend(self, spend_id: uuid.UUID) -> Decimal:
        found = self._spend_refunds.get(spend_id)
        if found is not None:
            return found
        base = self._base
        if isinstance(base, _Overlay) or self._refunds is None:
            return base.refunded_of_spend(spend_id)
        return self._refunds(spend_id, base.length) if base.length else ZERO

    # -- what the view stages ---------------------------------------------

    @property
    def opened(self) -> tuple[LedgerEntry, ...]:
        """HOLD entries this view placed that are still open in it."""
        return tuple(self._opened.values())

    @property
    def closed(self) -> tuple[uuid.UUID, ...]:
        """Holds that were open in the base and this view released."""
        return tuple(self._closed)

    @property
    def control_entries(self) -> tuple[ControlEvent, ...]:
        """The trips and resets this view's entries record (not legacy ones)."""
        return tuple(e for e in self._events if e.entry_id is not None)

    def cache_rows(self) -> tuple[list[BudgetNode], list[ControlEvent], list[LedgerEntry]]:
        """The topology rows, control-event rows and placed holds to write
        for what this view staged."""
        nodes = [self._nodes[scope] for scope in self._row_scopes if scope in self._nodes]
        return nodes, list(self.control_entries), list(self._opened.values())

    # -- the rules ----------------------------------------------------------

    def apply(
        self,
        entry: LedgerEntry,
        *,
        check_hash: bool = True,
        released: set[uuid.UUID] | None = None,
        writing: bool = False,
    ) -> None:
        """Verify ``entry`` as the next link of the chain, then fold it in.

        :param check_hash: Recompute the entry hash. Off only for entries this
            process built a moment ago.
        :param released: Every hold released so far, when the caller wants a
            double release reported as such rather than as an unknown hold.
        :param writing: The entry is being written now, not replayed: rules
            that history written before them is exempt from apply too.
        :raises LedgerIntegrityError: On the first rule the entry breaks. The
            view may then hold part of the entry; discard it.
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
        if check_hash:
            try:
                digest = entry.recompute_hash()
            except (ValueError, ArithmeticError) as exc:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} cannot be hashed: {exc}", scope
                ) from exc
            if digest != entry.entry_hash:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} has been tampered with (hash mismatch)", scope
                )
        self._check_version(entry)
        self._check_shape(entry)
        self._begin_transaction(entry)

        expected = _add(self.balance(scope), entry.signed_amount)
        if entry.balance_after != expected:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} records a balance of {entry.balance_after}, "
                f"but the chain implies {expected}",
                scope,
            )
        if entry.entry_type not in _ZERO_VALUE_TYPES:
            self.balances[scope] = expected
        if entry.entry_type in _BALANCED_TYPES:
            self._net = _add(self._net, entry.signed_amount)

        self._check_holds(entry, released)
        self._check_flows(entry, writing=writing)
        self._check_governance(entry)
        self.totals = _apply_totals(self.totals, (entry,))
        if entry.entry_type is EntryType.SEAL:
            self.seal = entry
        self.frontier = _frontier_append(self.frontier, self.length, entry.entry_hash)
        self.head = entry.entry_hash
        self.length = index
        self.last_timestamp = entry.timestamp

    def end_transaction(self) -> None:
        """Close the transaction the last entry belongs to.

        :raises LedgerIntegrityError: If its transfers do not balance: every
            delegation and release moves money between two scopes and must net
            to zero within its transaction.
        """
        if self._net != ZERO:
            raise LedgerIntegrityError(
                f"transaction {self._txn} does not balance: its transfers net {self._net}"
            )
        self._txn = None
        self._settleable = set()

    def finish(self) -> None:
        """End a replay: close the last transaction and fold in any pre-0.1.2
        control events a chain with no newer entry never folded in."""
        self.end_transaction()
        if not self.legacy_applied:
            self._apply_legacy()

    def apply_legacy_event(self, event: ControlEvent) -> None:
        """A control event a pre-0.1.2 writer added after this view was built."""
        self.legacy = (*self.legacy, event)
        self._control(event.event_type, event.scope_id, event.timestamp, event.reason)
        self._events.append(event)

    def merge(self) -> None:
        """Fold every verified change into the state below."""
        base = self._base
        if isinstance(base, _Overlay):
            base._absorb(self)
            return
        base.balances.update(self.balances)
        base.totals = self.totals
        base.head = self.head
        base.length = self.length
        base.saw_v1 = self.saw_v1
        base.saw_v2 = self.saw_v2
        base.seal = self.seal
        base.legacy = self.legacy
        base.legacy_applied = self.legacy_applied
        base.saw_v3 = self.saw_v3
        base.last_timestamp = self.last_timestamp
        base.last_checkpoint = self.last_checkpoint
        base.frontier = self.frontier
        if self._refunds is None:  # otherwise the store answers for them
            base.spend_refunds.update(self._spend_refunds)
        for hold_id in self._closed:
            base.holds.pop(hold_id, None)
        base.holds.update(self._opened)
        base.ambiguous |= self.ambiguous
        for scope_id, node in self._nodes.items():
            current = base.nodes.get(scope_id)
            if current is None:
                base.nodes[scope_id] = node
            else:
                # In place, so a node a caller holds stays current.
                current.allocated = node.allocated
        for scope_id, added in self._children.items():
            base.nodes[scope_id].child_ids.extend(added)
        base.roots.extend(self._roots)
        for scope_id, trip in self._tripped.items():
            if trip is None:
                base.tripped.pop(scope_id, None)
            else:
                base.tripped[scope_id] = trip
        base.spent.update(self._spent)
        base.refunded.update(self._refunded)
        for scope_id, count in self._counts.items():
            if count:
                base.hold_counts[scope_id] = count
            else:
                base.hold_counts.pop(scope_id, None)

    def _absorb(self, child: _Overlay) -> None:
        """Take a view staged on this one as this view's own staged changes."""
        self.balances.update(child.balances)
        self.totals = child.totals
        self.head = child.head
        self.length = child.length
        self.saw_v1 = child.saw_v1
        self.saw_v2 = child.saw_v2
        self.seal = child.seal
        self.legacy = child.legacy
        self.legacy_applied = child.legacy_applied
        self.saw_v3 = child.saw_v3
        self.last_timestamp = child.last_timestamp
        self.last_checkpoint = child.last_checkpoint
        self.frontier = child.frontier
        self._spend_refunds.update(child._spend_refunds)
        for hold_id in child._closed:
            if self._opened.pop(hold_id, None) is None:
                self._closed.add(hold_id)
        self._opened.update(child._opened)
        self.ambiguous |= child.ambiguous
        self._nodes.update(child._nodes)
        for scope_id, added in child._children.items():
            self._children.setdefault(scope_id, []).extend(added)
        self._row_scopes |= child._row_scopes
        self._roots.extend(child._roots)
        self._tripped.update(child._tripped)
        self._events.extend(child._events)
        self._spent.update(child._spent)
        self._refunded.update(child._refunded)
        self._counts.update(child._counts)
        self._txn, self._settleable, self._net = child._txn, child._settleable, child._net

    # -- ledger rules -------------------------------------------------------

    def _check_version(self, entry: LedgerEntry) -> None:
        if entry.version == _AUDIT_V1:
            if self.saw_v2:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} is an AGOV1 entry after newer entries; "
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
        if entry.version == _AUDIT_V3:
            self.saw_v3 = True
        elif self.saw_v3:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} is an AGOV2 entry after AGOV3 entries; "
                f"entries cannot go back to an older format"
            )
        self.saw_v2 = True

    def _check_shape(self, entry: LedgerEntry) -> None:
        kind = entry.entry_type
        if entry.direction not in _LEGAL_DIRECTIONS[kind]:
            raise LedgerIntegrityError(
                f"entry {entry.sequence}: {kind.value} may not be a {entry.direction.value} line",
                entry.scope_id,
            )
        if entry.version == _AUDIT_V3:
            self._check_v3(entry)
        elif kind is EntryType.CHECKPOINT:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} is a {entry.version} checkpoint; checkpoints are "
                f"AGOV3 only"
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
        if kind not in _SCOPELESS_TYPES:
            if not entry.scope_id:
                raise LedgerIntegrityError(f"entry {entry.sequence}: a {kind.value} needs a scope")
            return
        if entry.scope_id:
            raise LedgerIntegrityError(
                f"entry {entry.sequence}: a {kind.value} entry belongs to no scope"
            )
        if kind is EntryType.CHECKPOINT:
            self._check_checkpoint(entry)
            return
        if self.seal is not None:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} is a second migration seal; a ledger is sealed once"
            )
        if not self.saw_v1:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} seals pre-0.1.2 history this ledger does not have"
            )

    def _check_v3(self, entry: LedgerEntry) -> None:
        """What AGOV3 adds to an entry's shape: text a canonical encoding and
        both stores can hold, and time that never runs backwards."""
        texts = (
            ("scope id", entry.scope_id, True, MAX_ID_BYTES),
            ("counterparty id", entry.counterparty_id, True, MAX_ID_BYTES),
            ("memo", entry.memo, False, MAX_MEMO_BYTES),
        )
        for label, text, identifier, limit in texts:
            if text is not None:
                problem = _check_text(text, label, limit=limit, identifier=identifier)
                if problem is not None:
                    raise LedgerIntegrityError(f"entry {entry.sequence}: {problem}", entry.scope_id)
        if self.last_timestamp is not None and entry.timestamp < self.last_timestamp:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} is dated {_iso(entry.timestamp)}, before the entry "
                f"ahead of it ({_iso(self.last_timestamp)}); AGOV3 time never runs backwards",
                entry.scope_id,
            )

    def _check_checkpoint(self, entry: LedgerEntry) -> None:
        match = _CHECKPOINT_MEMO.match(entry.memo)
        if match is None:
            raise LedgerIntegrityError(f"entry {entry.sequence} is a malformed checkpoint")
        sequence, digest = int(match.group(1)), match.group(2)
        if sequence >= entry.sequence:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} checkpoints sequence {sequence}, which is not before it"
            )
        previous = self.last_checkpoint
        if previous is not None and sequence <= previous[0]:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} checkpoints sequence {sequence}, which is not after "
                f"the previous checkpoint's {previous[0]}"
            )
        self.last_checkpoint = (sequence, digest)

    def _begin_transaction(self, entry: LedgerEntry) -> None:
        if entry.transaction_id != self._txn:
            if self._txn is not None:
                self.end_transaction()
            self._txn = entry.transaction_id

    def _check_holds(self, entry: LedgerEntry, released: set[uuid.UUID] | None) -> None:
        kind = entry.entry_type
        referencing = _V3_REFERENCING_TYPES if entry.version == _AUDIT_V3 else _REFERENCING_TYPES
        if entry.ref is not None and kind not in referencing:
            raise LedgerIntegrityError(
                f"entry {entry.sequence}: a {kind.value} entry names no hold", entry.scope_id
            )
        if kind is EntryType.HOLD:
            self._opened[entry.entry_id] = entry
            self._counts[entry.scope_id] = self.holds_open_in(entry.scope_id) + 1
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
        elif kind is EntryType.REVERSAL and entry.ref is not None:
            self._reverse_named(entry, entry.ref)

    def _reverse_named(self, entry: LedgerEntry, ref: uuid.UUID) -> None:
        """An AGOV3 refund that names the spend it reverses: never more than
        that spend, in that spend's scope, across every refund naming it."""
        spend = self._resolve(ref) if self._resolve is not None else None
        if spend is None or spend.entry_type is not EntryType.SPEND:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} reverses {ref}, which is not a spend this ledger holds",
                entry.scope_id,
            )
        if spend.scope_id != entry.scope_id:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} reverses spend {ref} of scope {spend.scope_id!r} "
                f"into {entry.scope_id!r}",
                entry.scope_id,
            )
        refunded = _add(self.refunded_of_spend(ref), entry.amount)
        if refunded > spend.amount:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} refunds {entry.amount} of spend {ref}, bringing its "
                f"refunds to {refunded}, more than the {spend.amount} it spent",
                entry.scope_id,
            )
        self._spend_refunds[ref] = refunded

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
        self._close(ref, hold)
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
        for hold_id, hold in self.iter_holds():
            if _hold_key(hold) == key:
                self._close(hold_id, hold)
                self.ambiguous.add(key)
                return
        raise LedgerIntegrityError(
            f"entry {entry.sequence} releases {entry.amount}, but no open hold of that "
            f"amount remains; the same funds were released twice",
            entry.scope_id,
        )

    def _close(self, hold_id: uuid.UUID, hold: LedgerEntry) -> None:
        if self._opened.pop(hold_id, None) is None:
            self._closed.add(hold_id)
        self._counts[hold.scope_id] = self.holds_open_in(hold.scope_id) - 1

    def _check_flows(self, entry: LedgerEntry, *, writing: bool) -> None:
        """Each scope's lifetime spend and refunds, and the refund bound.

        A refund (REVERSAL) returns money a vendor gave back for something
        the scope bought, so a scope's lifetime refunds never exceed its
        lifetime spend; otherwise a refund would mint spending power the
        delegation tree never granted. Enforced on every write and on every
        AGOV3 entry; AGOV1 and AGOV2 entries, written before the rule, are
        exempt on replay.
        """
        scope = entry.scope_id
        if entry.entry_type is EntryType.SPEND:
            self._spent[scope] = _add(self.spent_by(scope), entry.amount)
        elif entry.entry_type is EntryType.REVERSAL:
            refunded = _add(self.refunded_to(scope), entry.amount)
            spent = self.spent_by(scope)
            if (writing or entry.version == _AUDIT_V3) and refunded > spent:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} refunds {entry.amount} to {scope!r}, bringing its "
                    f"lifetime refunds to {refunded}, more than the {spent} it ever spent",
                    scope,
                )
            self._refunded[scope] = refunded

    # -- governance rules ---------------------------------------------------

    def _check_governance(self, entry: LedgerEntry) -> None:
        if entry.version != _AUDIT_V1 and not self.legacy_applied:
            # Every pre-0.1.2 control event predates the first newer entry.
            if entry.entry_type is EntryType.SEAL:
                self._check_seal(entry)
            elif self.legacy:
                raise LedgerIntegrityError(
                    "control_events holds rows that are not in the chain, and this "
                    "ledger has no migration seal to vouch for them"
                )
            self._apply_legacy()

        kind = entry.entry_type
        scope = entry.scope_id
        if kind is EntryType.FUNDING:
            node = self.node(scope)
            if node is None:
                self._nodes[scope] = BudgetNode(
                    scope_id=scope,
                    parent_id=None,
                    depth=0,
                    allocated=entry.amount,
                    created_at=entry.timestamp,
                )
                self._roots.append(scope)
            elif node.parent_id is not None:
                raise LedgerIntegrityError(
                    f"entry {entry.sequence} funds a scope that is not a root", scope
                )
            else:
                writable = self._writable(scope)
                writable.allocated = _add(writable.allocated, entry.amount)
            self._row_scopes.add(scope)
        elif kind is EntryType.ALLOCATION:
            self._allocate(entry)
        elif kind is EntryType.RELEASE:
            self._release_between(entry)
        elif kind in _CONTROL_TYPES:
            self._control(kind.value, scope, entry.timestamp, entry.memo)
            self._events.append(_event_for(entry))
        elif kind not in _SCOPELESS_TYPES:
            self._require(scope, entry)

    def _writable(self, scope_id: str) -> BudgetNode:
        """This view's own copy of a node, to change without touching the base.

        The copy shares the base's list of children, which no view changes: a
        view records the children it adds in ``_children`` and merge() appends
        them, so staging a scope with many children costs nothing extra.
        """
        staged = self._nodes.get(scope_id)
        if staged is None:
            current = self._base.node(scope_id)
            if current is None:  # callers check first; never trust that silently
                raise LedgerIntegrityError(f"scope {scope_id!r} is not in the chain", scope_id)
            staged = dataclasses.replace(current)
            self._nodes[scope_id] = staged
        return staged

    def _allocate(self, entry: LedgerEntry) -> None:
        scope, parent_id = entry.scope_id, entry.counterparty_id
        if entry.direction is Direction.DEBIT:
            self._require(scope, entry)
            return
        if self.node(scope) is not None:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} allocates to {scope!r} a second time; a "
                f"delegation creates a new scope",
                scope,
            )
        parent = self.node(parent_id or "")
        if parent is None:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} delegates from {parent_id!r}, which the chain "
                f"never created",
                scope,
            )
        self._nodes[scope] = BudgetNode(
            scope_id=scope,
            parent_id=parent.scope_id,
            depth=parent.depth + 1,
            allocated=entry.amount,
            created_at=entry.timestamp,
        )
        self._row_scopes.add(scope)
        self._children.setdefault(parent.scope_id, []).append(scope)

    def _release_between(self, entry: LedgerEntry) -> None:
        scope, other = entry.scope_id, entry.counterparty_id or ""
        node = self._require(scope, entry)
        child = node if entry.direction is Direction.DEBIT else self.node(other)
        parent_id = other if entry.direction is Direction.DEBIT else scope
        if child is None or child.parent_id != parent_id:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} releases between {scope!r} and {other!r}, "
                f"which are not child and parent",
                scope,
            )

    def _control(self, event_type: str, scope_id: str, timestamp: datetime, reason: str) -> None:
        if self.node(scope_id) is None:
            raise LedgerIntegrityError(f"control event references unregistered scope {scope_id!r}")
        if event_type == EntryType.CIRCUIT_TRIPPED.value:
            self._tripped[scope_id] = (timestamp, reason)
        elif event_type == EntryType.CIRCUIT_RESET.value:
            self._tripped[scope_id] = None

    def _require(self, scope_id: str, entry: LedgerEntry) -> BudgetNode:
        node = self.node(scope_id)
        if node is None:
            raise LedgerIntegrityError(
                f"entry {entry.sequence} ({entry.entry_type.value}) names a scope the "
                f"chain never created",
                scope_id,
            )
        return node

    def _apply_legacy(self) -> None:
        self.legacy_applied = True
        for event in self.legacy:
            self._control(event.event_type, event.scope_id, event.timestamp, event.reason)
            self._events.append(event)

    def _check_seal(self, entry: LedgerEntry) -> None:
        match = _SEAL_MEMO.match(entry.memo)
        if match is None:
            raise LedgerIntegrityError(f"entry {entry.sequence} is a malformed migration seal")
        count, digest = int(match.group(1)), match.group(2)
        if count != len(self.legacy) or digest != _legacy_digest(self.legacy):
            raise LedgerIntegrityError(
                f"the pre-0.1.2 control events no longer match the seal written when "
                f"this ledger was upgraded (entry {entry.sequence}): a legacy trip or "
                f"reset was edited, added or deleted"
            )


def _replay(
    entries: Iterable[LedgerEntry],
    legacy: Sequence[ControlEvent] = (),
    *,
    finish: bool = False,
    resolve: Callable[[uuid.UUID], LedgerEntry | None] | None = None,
    refunds: Callable[[uuid.UUID, int], Decimal] | None = None,
) -> _ChainState:
    """Rebuild chain state from nothing but the entries, verifying each.

    :param legacy: Control events a pre-0.1.2 governor kept outside the chain.
    :param finish: Fold ``legacy`` in even if no entry written from v0.1.2 on
        does (a read-only view of an unsealed pre-0.1.2 ledger).
    :param resolve: Finds an earlier entry by id, for a refund that names its
        spend. By default, the spends among ``entries`` themselves.
    :param refunds: For entries whose store keeps history: the state then
        remembers no spend's refunds (see :class:`_Overlay`).
    """
    if resolve is None:
        entries = entries if isinstance(entries, Sequence) else list(entries)
        resolve = _spend_index(entries)
    state = _ChainState(legacy=tuple(legacy))
    view = _Overlay(state, resolve=resolve, refunds=refunds)
    released: set[uuid.UUID] = set()
    for entry in entries:
        view.apply(entry, released=released)
    if finish:
        view.finish()
    else:
        view.end_transaction()
    view.merge()
    return state


def _spend_index(entries: Sequence[LedgerEntry]) -> Callable[[uuid.UUID], LedgerEntry | None]:
    """A resolver over ``entries``, indexing their spends on first use."""
    index: dict[uuid.UUID, LedgerEntry] | None = None

    def resolve(entry_id: uuid.UUID) -> LedgerEntry | None:
        nonlocal index
        if index is None:
            index = {e.entry_id: e for e in entries if e.entry_type is EntryType.SPEND}
        return index.get(entry_id)

    return resolve


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
                funded = _add(funded, entry.amount)
            case EntryType.SPEND:
                spent = _add(spent, entry.amount)
            case EntryType.REVERSAL:
                reversed_ = _add(reversed_, entry.amount)
            case EntryType.HOLD:
                holds = _add(holds, entry.amount)
            case EntryType.HOLD_VOID:
                holds = _subtract(holds, entry.amount)
            case _:
                pass
    return _Totals(funded=funded, spent=spent, reversed_=reversed_, holds_open=holds)


# --------------------------------------------------------------------------
# Snapshots: the chain state as of a sequence, in canonical JSON
# --------------------------------------------------------------------------

_SNAPSHOT_FORMAT: Final = "agentgov-snapshot/1"
_SNAPSHOT_DOMAIN: Final = b"agentgov/snapshot/v1\n"
_HEX64: Final = re.compile(r"\A[0-9a-f]{64}\Z")


def _entry_document(entry: LedgerEntry) -> dict[str, object]:
    """An entry as a snapshot carries it: every field, its amounts in its own
    version's rendering, so it reads back to exactly the entry it was."""
    return {
        "amount": _amount_text(entry, entry.amount),
        "balance_after": _amount_text(entry, entry.balance_after),
        "counterparty_id": entry.counterparty_id,
        "direction": entry.direction.value,
        "entry_hash": entry.entry_hash,
        "entry_id": str(entry.entry_id),
        "entry_type": entry.entry_type.value,
        "memo": entry.memo,
        "prev_hash": entry.prev_hash,
        "ref": str(entry.ref) if entry.ref is not None else None,
        "scope_id": entry.scope_id,
        "sequence": entry.sequence,
        "timestamp": _iso(entry.timestamp),
        "transaction_id": str(entry.transaction_id),
        "version": entry.version,
    }


def _event_document(event: ControlEvent) -> dict[str, object]:
    return {
        "entry_id": str(event.entry_id) if event.entry_id is not None else None,
        "event_id": str(event.event_id),
        "event_type": event.event_type,
        "ledger_head_hash": event.ledger_head_hash,
        "reason": event.reason,
        "scope_id": event.scope_id,
        "timestamp": _iso(event.timestamp),
    }


def _snapshot_document(state: _ChainState) -> dict[str, object]:
    totals = state.totals
    return {
        "ambiguous": sorted([scope, str(amount)] for scope, amount in state.ambiguous),
        "balances": {scope: _fixed(value) for scope, value in state.balances.items()},
        "flags": {
            "legacy_applied": state.legacy_applied,
            "saw_v1": state.saw_v1,
            "saw_v2": state.saw_v2,
            "saw_v3": state.saw_v3,
        },
        "format": _SNAPSHOT_FORMAT,
        "frontier": [node.hex() for node in state.frontier],
        "head": state.head,
        "holds": [_entry_document(hold) for hold in state.holds.values()],
        "last_checkpoint": list(state.last_checkpoint) if state.last_checkpoint else None,
        "last_timestamp": _iso(state.last_timestamp) if state.last_timestamp else None,
        "legacy": [_event_document(event) for event in state.legacy],
        "nodes": [
            [
                node.scope_id,
                node.parent_id,
                node.depth,
                _fixed(node.allocated),
                _iso(node.created_at),
                list(node.child_ids),
            ]
            for node in state.nodes.values()
        ],
        "refunded": {scope: _fixed(value) for scope, value in state.refunded.items()},
        "roots": list(state.roots),
        "seal": _entry_document(state.seal) if state.seal is not None else None,
        "sequence": state.length,
        "spent": {scope: _fixed(value) for scope, value in state.spent.items()},
        "totals": {
            "funded": _fixed(totals.funded),
            "holds_open": _fixed(totals.holds_open),
            "reversed": _fixed(totals.reversed_),
            "spent": _fixed(totals.spent),
        },
        "tripped": {scope: [_iso(at), reason] for scope, (at, reason) in state.tripped.items()},
    }


def _encode_snapshot(state: _ChainState) -> bytes:
    """The canonical (RFC 8785) snapshot of ``state``: one state, one byte
    string, so one digest. Costs time proportional to the state."""
    from agentgov.receipts.canonical import canonical_bytes  # deferred: receipts imports core

    return canonical_bytes(_snapshot_document(state))


def _snapshot_digest(body: bytes) -> str:
    """A snapshot's digest: SHA-256 over a domain prefix and its bytes."""
    return hashlib.sha256(_SNAPSHOT_DOMAIN + body).hexdigest()


_STATEMENT_VERSION: Final = "agentgov-checkpoint"
_STATEMENT_DOMAIN: Final = b"agentgov/checkpoint/v1\n"
_STATEMENT_FIELDS: Final = (
    "v",
    "first",
    "sequence",
    "head",
    "root",
    "snapshot",
    "issued_at",
    "sig",
)


@dataclass(frozen=True)
class _CheckpointStatement:
    """A key's signed word for one checkpoint of a ledger, kept with its
    snapshot: which ledger (the hash of its first entry), which sequence, the
    head and the RFC 9162 root of every entry up to it, and the digest of the
    snapshot of the state there. Signed as ARC1 documents are (canonical JSON,
    ``sig`` reduced to its header, domain ``agentgov/checkpoint/v1``, or
    ``v2`` at signature version 2). See docs/LEDGER_FORMAT.md."""

    first: str
    sequence: int
    head: str
    root: str
    snapshot: str
    issued_at: datetime
    signature: Any = None

    def facts(self) -> tuple[str, int, str, str, str]:
        return (self.first, self.sequence, self.head, self.root, self.snapshot)

    def body(self) -> dict[str, object]:
        return {
            "v": _STATEMENT_VERSION,
            "first": self.first,
            "sequence": self.sequence,
            "head": self.head,
            "root": self.root,
            "snapshot": self.snapshot,
            "issued_at": _iso(self.issued_at),
        }

    def signing_input(self, alg: str, key_id: str, version: int = 1) -> bytes:
        from agentgov.receipts.schema import _signing_input

        return _signing_input(_STATEMENT_DOMAIN, self.body(), alg, key_id, version)

    def sign(self, signer: Any) -> _CheckpointStatement:
        from agentgov.receipts.schema import Signature, _signature_version

        version = _signature_version(signer, None)
        value = signer.sign(self.signing_input(signer.alg, signer.key_id, version))
        return dataclasses.replace(
            self, signature=Signature(signer.alg, signer.key_id, value, version)
        )

    def verify(self, keys: Any) -> None:
        """:raises ReceiptSignatureError: Unless a key of ``keys`` signed this."""
        from agentgov.receipts.schema import _check_signature

        _check_signature("checkpoint statement", self.signature, keys, self.signing_input)

    def text(self) -> str:
        from agentgov.receipts.canonical import canonical_bytes

        sig = self.signature.to_json() if self.signature is not None else None
        return canonical_bytes({**self.body(), "sig": sig}).decode("utf-8")

    @classmethod
    def loads(cls, text: str) -> _CheckpointStatement:
        """:raises MalformedReceiptError: If ``text`` is not a statement."""
        from agentgov.receipts.canonical import loads_strict
        from agentgov.receipts.schema import Signature, _Fields, _sig_fields

        f = _Fields(loads_strict(text), "checkpoint statement", _STATEMENT_FIELDS)
        f.version(_STATEMENT_VERSION)
        sig = f.optional_child("sig", _sig_fields(f.raw("sig")))
        return cls(
            first=f.hex64("first"),
            sequence=f.integer("sequence", minimum=1),
            head=f.hex64("head"),
            root=f.hex64("root"),
            snapshot=f.hex64("snapshot"),
            issued_at=f.instant("issued_at"),
            signature=Signature.from_json(sig) if sig else None,
        )


@dataclass(frozen=True)
class CheckpointSigning:
    """Signed ledger checkpoints: who signs them, whose signatures count, and
    whether a governor may open from one no trusted key signed.

    A checkpoint snapshot is trusted for everything before it, so without a
    signature anyone who can write the database can rewrite that history
    consistently. With one, rewriting it takes the key too: a governor opening
    from a checkpoint checks that a trusted key signed the statement kept
    with its snapshot, which names the ledger, the checkpoint's sequence, the
    head and the Merkle root of every entry up to it, and the snapshot's
    digest. Entries after the newest checkpoint are hash-chained, not signed.

    :ivar signer: Signs every checkpoint this governor writes, automatic or
        not; ``None`` writes them unsigned. A key service's
        :class:`~agentgov.receipts.signing.RemoteSigner` serves.
    :ivar keys: The keys trusted to have signed the ledger's checkpoints, as
        a keyring, one key, or several (a key and its successor); the
        signer's own is always trusted. A signature by any other key is
        refused, as tampering.
    :ivar required: Refuse to open from a checkpoint no trusted key signed.
        Optional in the API, and required in production.
    :raises ValueError: If signatures are required but no key could check one.
    """

    signer: Any = None
    keys: Any = None
    required: bool = False

    def __post_init__(self) -> None:
        if self.required and self.signer is None and self.keys is None:
            raise ValueError("signed checkpoints are required, but no key is trusted to sign them")

    def keyring(self) -> Any:
        """Every key trusted to have signed a checkpoint."""
        from agentgov.receipts.signing import Keyring, verifier_of

        trusted = list(Keyring.of(self.keys)) if self.keys is not None else []
        if self.signer is not None:
            trusted.append(verifier_of(self.signer))
        return Keyring(trusted)

    def statement(
        self, first: str, state: _ChainState, digest: str, issued_at: datetime
    ) -> str | None:
        """The signed statement for a checkpoint of ``state``, or ``None``
        without a signer."""
        if self.signer is None:
            return None
        unsigned = _CheckpointStatement(
            first=first,
            sequence=state.length,
            head=state.head,
            root=_frontier_root(state.frontier).hex(),
            snapshot=digest,
            issued_at=issued_at,
        )
        return unsigned.sign(self.signer).text()

    def check(self, snapshot: Any, state: _ChainState, first: str) -> None:
        """A snapshot's statement, against the state it decodes to.

        :raises LedgerIntegrityError: If it is unsigned when signatures are
            required, signed by no trusted key, or describes another state.
        """
        sequence = snapshot.sequence
        if not snapshot.signature:
            if self.required:
                raise LedgerIntegrityError(
                    f"the checkpoint of sequence {sequence} is not signed, and this governor "
                    f"requires signed checkpoints"
                )
            return
        from agentgov.exceptions import MalformedReceiptError, ReceiptSignatureError

        try:
            statement = _CheckpointStatement.loads(snapshot.signature)
            statement.verify(self.keyring())
        except (MalformedReceiptError, ReceiptSignatureError) as exc:
            raise LedgerIntegrityError(
                f"the checkpoint of sequence {sequence} carries a signed statement that does not "
                f"check out: {exc}"
            ) from exc
        expected = (first, state.length, state.head, _frontier_root(state.frontier).hex())
        if statement.facts() != (*expected, snapshot.digest):
            raise LedgerIntegrityError(
                f"the signed statement of the checkpoint of sequence {sequence} does not "
                f"describe its snapshot: it was made for another state"
            )


class _Reader:
    """Typed, path-reporting reads out of a decoded snapshot document."""

    def __init__(self, value: object, path: str) -> None:
        if not isinstance(value, dict):
            raise LedgerIntegrityError(f"snapshot {path} is not an object")
        self._value = value
        self._path = path

    def raw(self, key: str) -> object:
        if key not in self._value:
            raise LedgerIntegrityError(f"snapshot {self._path}.{key} is missing")
        return self._value[key]

    def text(self, key: str, *, nullable: bool = False) -> str | None:
        value = self.raw(key)
        if value is None and nullable:
            return None
        if not isinstance(value, str):
            raise LedgerIntegrityError(f"snapshot {self._path}.{key} is not a string")
        return value

    def string(self, key: str) -> str:
        value = self.text(key)
        assert value is not None
        return value

    def integer(self, key: str) -> int:
        value = self.raw(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise LedgerIntegrityError(f"snapshot {self._path}.{key} is not a count")
        return value

    def flag(self, key: str) -> bool:
        value = self.raw(key)
        if not isinstance(value, bool):
            raise LedgerIntegrityError(f"snapshot {self._path}.{key} is not a boolean")
        return value

    def mapping(self, key: str) -> dict[str, object]:
        value = self.raw(key)
        if not isinstance(value, dict):
            raise LedgerIntegrityError(f"snapshot {self._path}.{key} is not an object")
        return value

    def items(self, key: str) -> list[object]:
        value = self.raw(key)
        if not isinstance(value, list):
            raise LedgerIntegrityError(f"snapshot {self._path}.{key} is not a list")
        return value


def _money_text(text: object, path: str) -> Decimal:
    if not isinstance(text, str):
        raise LedgerIntegrityError(f"snapshot {path} is not an amount")
    try:
        value = Decimal(text)
    except InvalidOperation as exc:
        raise LedgerIntegrityError(f"snapshot {path} is not an amount: {text!r}") from exc
    if not value.is_finite():
        raise LedgerIntegrityError(f"snapshot {path} is not an amount: {text!r}")
    return value


def _instant(text: object, path: str) -> datetime:
    if not isinstance(text, str):
        raise LedgerIntegrityError(f"snapshot {path} is not a timestamp")
    try:
        return _parse_iso(text)
    except ValueError as exc:
        raise LedgerIntegrityError(f"snapshot {path} is not a timestamp: {text!r}") from exc


def _uuid(text: object, path: str) -> uuid.UUID:
    if not isinstance(text, str):
        raise LedgerIntegrityError(f"snapshot {path} is not an id")
    try:
        return uuid.UUID(text)
    except ValueError as exc:
        raise LedgerIntegrityError(f"snapshot {path} is not an id: {text!r}") from exc


def _entry_from_document(value: object, path: str) -> LedgerEntry:
    r = _Reader(value, path)
    try:
        return LedgerEntry(
            sequence=r.integer("sequence"),
            entry_id=_uuid(r.raw("entry_id"), f"{path}.entry_id"),
            transaction_id=_uuid(r.raw("transaction_id"), f"{path}.transaction_id"),
            timestamp=_instant(r.raw("timestamp"), f"{path}.timestamp"),
            entry_type=EntryType(r.string("entry_type")),
            direction=Direction(r.string("direction")),
            scope_id=r.string("scope_id"),
            counterparty_id=r.text("counterparty_id", nullable=True),
            amount=_money_text(r.raw("amount"), f"{path}.amount"),
            balance_after=_money_text(r.raw("balance_after"), f"{path}.balance_after"),
            prev_hash=r.string("prev_hash"),
            entry_hash=r.string("entry_hash"),
            memo=r.string("memo"),
            ref=(
                _uuid(r.raw("ref"), f"{path}.ref")
                if r.text("ref", nullable=True) is not None
                else None
            ),
            version=r.string("version"),
        )
    except ValueError as exc:
        raise LedgerIntegrityError(f"snapshot {path} is not an entry: {exc}") from exc


def _event_from_document(value: object, path: str) -> ControlEvent:
    r = _Reader(value, path)
    entry_id = r.text("entry_id", nullable=True)
    return ControlEvent(
        event_id=_uuid(r.raw("event_id"), f"{path}.event_id"),
        timestamp=_instant(r.raw("timestamp"), f"{path}.timestamp"),
        event_type=r.string("event_type"),
        scope_id=r.string("scope_id"),
        reason=r.string("reason"),
        ledger_head_hash=r.string("ledger_head_hash"),
        entry_id=_uuid(entry_id, f"{path}.entry_id") if entry_id is not None else None,
    )


def _decode_snapshot(body: bytes) -> _ChainState:
    """The chain state a snapshot holds, refusing anything malformed.

    Strict both ways: the bytes must decode, every field must have its type
    and form, and the state must encode back to exactly these bytes, so the
    digest a checkpoint names is the digest of one state and no other.

    :raises LedgerIntegrityError: On anything else.
    """
    from agentgov.exceptions import MalformedReceiptError
    from agentgov.receipts.canonical import loads_strict

    try:
        document = loads_strict(body)
    except MalformedReceiptError as exc:
        raise LedgerIntegrityError(f"the checkpoint snapshot is not canonical JSON: {exc}") from exc
    r = _Reader(document, "$")
    if r.raw("format") != _SNAPSHOT_FORMAT:
        raise LedgerIntegrityError(f"the checkpoint snapshot is not {_SNAPSHOT_FORMAT}")
    sequence = r.integer("sequence")
    head = r.string("head")
    if not _HEX64.match(head):
        raise LedgerIntegrityError("snapshot $.head is not a hash")
    flags = _Reader(r.raw("flags"), "$.flags")
    totals = _Reader(r.raw("totals"), "$.totals")

    def amounts(key: str) -> dict[str, Decimal]:
        return {
            scope: _money_text(text, f"$.{key}.{scope}") for scope, text in r.mapping(key).items()
        }

    nodes: dict[str, BudgetNode] = {}
    for index, row in enumerate(r.items("nodes")):
        path = f"$.nodes[{index}]"
        if not isinstance(row, list) or len(row) != 6:
            raise LedgerIntegrityError(f"snapshot {path} is not a node")
        scope_id, parent_id, depth, allocated, created_at, children = row
        if (
            not isinstance(scope_id, str)
            or not (parent_id is None or isinstance(parent_id, str))
            or not isinstance(depth, int)
            or isinstance(depth, bool)
            or not isinstance(children, list)
            or not all(isinstance(c, str) for c in children)
        ):
            raise LedgerIntegrityError(f"snapshot {path} is not a node")
        nodes[scope_id] = BudgetNode(
            scope_id=scope_id,
            parent_id=parent_id,
            depth=depth,
            allocated=_money_text(allocated, f"{path}[3]"),
            child_ids=list(children),
            created_at=_instant(created_at, f"{path}[4]"),
        )
    tripped: dict[str, tuple[datetime, str]] = {}
    for scope_id, pair in r.mapping("tripped").items():
        if not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[1], str):
            raise LedgerIntegrityError(f"snapshot $.tripped.{scope_id} is not a trip")
        tripped[scope_id] = (_instant(pair[0], f"$.tripped.{scope_id}"), pair[1])
    holds: dict[uuid.UUID, LedgerEntry] = {}
    counts: dict[str, int] = {}
    for index, value in enumerate(r.items("holds")):
        hold = _entry_from_document(value, f"$.holds[{index}]")
        holds[hold.entry_id] = hold
        counts[hold.scope_id] = counts.get(hold.scope_id, 0) + 1
    ambiguous: set[_HoldKey] = set()
    for index, pair in enumerate(r.items("ambiguous")):
        if not isinstance(pair, list) or len(pair) != 2 or not isinstance(pair[0], str):
            raise LedgerIntegrityError(f"snapshot $.ambiguous[{index}] is not a hold key")
        ambiguous.add((pair[0], _money_text(pair[1], f"$.ambiguous[{index}]")))
    frontier: list[bytes] = []
    for index, node in enumerate(r.items("frontier")):
        if not isinstance(node, str) or not _HEX64.match(node):
            raise LedgerIntegrityError(f"snapshot $.frontier[{index}] is not a hash")
        frontier.append(bytes.fromhex(node))
    if len(frontier) != bin(sequence).count("1"):
        raise LedgerIntegrityError(
            f"the snapshot's Merkle frontier has {len(frontier)} nodes; a chain of "
            f"{sequence} entries has {bin(sequence).count('1')}"
        )
    last = r.raw("last_checkpoint")
    if last is not None and (
        not isinstance(last, list)
        or len(last) != 2
        or not isinstance(last[0], int)
        or not isinstance(last[1], str)
    ):
        raise LedgerIntegrityError("snapshot $.last_checkpoint is not a checkpoint")
    seal = r.raw("seal")
    last_timestamp = r.text("last_timestamp", nullable=True)
    state = _ChainState(
        balances=amounts("balances"),
        totals=_Totals(
            funded=_money_text(totals.raw("funded"), "$.totals.funded"),
            spent=_money_text(totals.raw("spent"), "$.totals.spent"),
            reversed_=_money_text(totals.raw("reversed"), "$.totals.reversed"),
            holds_open=_money_text(totals.raw("holds_open"), "$.totals.holds_open"),
        ),
        head=head,
        length=sequence,
        holds=holds,
        ambiguous=ambiguous,
        saw_v1=flags.flag("saw_v1"),
        saw_v2=flags.flag("saw_v2"),
        seal=_entry_from_document(seal, "$.seal") if seal is not None else None,
        nodes=nodes,
        roots=[_check_root(root, nodes) for root in r.items("roots")],
        tripped=tripped,
        legacy=tuple(
            _event_from_document(e, f"$.legacy[{i}]") for i, e in enumerate(r.items("legacy"))
        ),
        legacy_applied=flags.flag("legacy_applied"),
        spent=amounts("spent"),
        refunded=amounts("refunded"),
        hold_counts=counts,
        saw_v3=flags.flag("saw_v3"),
        last_timestamp=_instant(last_timestamp, "$.last_timestamp") if last_timestamp else None,
        last_checkpoint=(last[0], last[1]) if isinstance(last, list) else None,
        frontier=tuple(frontier),
    )
    if _encode_snapshot(state) != body:
        raise LedgerIntegrityError(
            "the checkpoint snapshot is not the canonical encoding of the state it holds"
        )
    return state


def _check_root(root: object, nodes: dict[str, BudgetNode]) -> str:
    if not isinstance(root, str) or root not in nodes:
        raise LedgerIntegrityError(f"snapshot root {root!r} is not one of its scopes")
    return root


# --------------------------------------------------------------------------
# Units of work
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    """A call made under an idempotency key, and where its result was written.

    Recorded in the same store transaction as the entries the call wrote, so
    a key is recorded exactly when its call took effect. The record is not
    part of the chain: what it vouches for is the entry it names, which is.

    :ivar key: The caller's idempotency key.
    :ivar request: The call: canonical JSON of its operation and arguments.
    :ivar outcome: What the call returned, read back from :attr:`sequence`:
        ``"authorization"`` (the hold placed there), ``"entry"`` (the entry)
        or ``"node"`` (the scope the entry delegated to).
    :ivar sequence: The entry the result is read back from.
    :ivar created_at: When the call was made: that entry's timestamp.
    """

    key: str
    request: str
    outcome: str
    sequence: int
    created_at: datetime


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
    :ivar redeemed: Settlement claims these entries book, removed from the
        pending claims in the same transaction, so a claim is booked exactly
        once. Only a store that holds claims accepts them.
    :ivar idempotency: The calls made under an idempotency key that these
        entries are the result of.
    """

    entries: list[LedgerEntry] = field(default_factory=list)
    nodes: list[BudgetNode] = field(default_factory=list)
    control_events: list[ControlEvent] = field(default_factory=list)
    opened: list[Authorization] = field(default_factory=list)
    closed: list[uuid.UUID] = field(default_factory=list)
    redeemed: list[uuid.UUID] = field(default_factory=list)
    idempotency: list[IdempotencyRecord] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(
            self.entries
            or self.nodes
            or self.control_events
            or self.opened
            or self.closed
            or self.redeemed
            or self.idempotency
        )


@dataclass(frozen=True, slots=True)
class SettlementClaim:
    """A debt a caller's transaction owes the ledger, committed with it.

    Written by :meth:`JoinedTransaction.claim` inside a transaction someone
    else owns, and booked into the chain afterwards by
    :meth:`BudgetManager.redeem`. A claim touches none of the chain, so
    writing one cannot conflict with any other governor's writes; it exists
    exactly when the caller's transaction committed, so redeeming every
    pending claim is always correct, by any governor, at any time.

    :ivar claim_id: Unique id of the claim.
    :ivar hold_id: The hold placed for it beforehand, whose release and
        capture redemption posts. ``None`` for a claim with nothing reserved.
    :ivar scope_id: The scope that pays.
    :ivar amount: What is owed. Zero books a zero-value ``ANCHOR``.
    :ivar memo: The spend's (or anchor's) memo, typically another chain's
        record the settlement names.
    """

    claim_id: uuid.UUID
    hold_id: uuid.UUID | None
    scope_id: str
    amount: Decimal
    memo: str


class _Pending:
    """One unit of work: entries and cache writes that become durable together.

    Built and committed with the ledger's lock held. Nothing is visible to
    anyone — memory or disk — until :meth:`Ledger._commit` succeeds, so an
    exception anywhere before then simply abandons the work.
    """

    __slots__ = ("_ledger", "_view", "batch")

    def __init__(self, ledger: Ledger) -> None:
        self._ledger = ledger
        self._view = _Overlay(
            ledger._state, resolve=ledger._resolve, refunds=ledger._refund_lookup()
        )
        self.batch = WriteBatch()

    @property
    def entries(self) -> list[LedgerEntry]:
        return self.batch.entries

    @property
    def view(self) -> _Overlay:
        """The chain as of the work posted so far."""
        return self._view

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
        # The later of the clock and the newest entry: time in the chain never
        # runs backwards, whatever another governor's clock said.
        now = datetime.now(UTC)
        if view.last_timestamp is not None and now < view.last_timestamp:
            now = view.last_timestamp
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
            if line.ref is not None and line.entry_type not in _V3_REFERENCING_TYPES:
                raise ValueError(
                    f"a {line.entry_type.value} line names no hold; ref is for hold "
                    f"releases, the spends that settle them, and the refunds of a spend"
                )
            for label, text, identifier, limit in (
                ("scope id", line.scope_id, True, MAX_ID_BYTES),
                ("counterparty id", line.counterparty_id, True, MAX_ID_BYTES),
                ("memo", line.memo, False, MAX_MEMO_BYTES),
            ):
                if text is not None:
                    problem = _check_text(text, label, limit=limit, identifier=identifier)
                    if problem is not None:
                        raise ValueError(problem)

            if line.direction is Direction.CREDIT:
                signed = amount
            elif line.direction is Direction.DEBIT:
                signed = amount.copy_negate()
            else:
                signed = ZERO
            if line.entry_type in _BALANCED_TYPES:
                transfer_net = _add(transfer_net, signed)
            current = running.get(line.scope_id, view.balance(line.scope_id))
            balance_after = _add(current, signed)
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

        # Every rule a replay would enforce, and those only new writes are held
        # to, enforced now by the same engine, before anything is durable: a
        # write a replay would refuse is refused here instead of being found by
        # the next open, when it can no longer be taken back.
        for entry in built:
            view.apply(entry, check_hash=False, writing=True)
        view.end_transaction()
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
        # History lives in the store when the store can answer for it, and
        # memory then holds the chain *state*, bounded by scopes and open
        # holds, never the entries. Only a ledger with no store (or with a
        # store that cannot be queried for history) keeps its entries here.
        self._entries: list[LedgerEntry] | None = None if _keeps_history(store) else []
        self._state = _ChainState()
        self._open_auths: dict[uuid.UUID, Authorization] = {}
        self._legacy_auth_ids: dict[uuid.UUID, uuid.UUID] = {}
        # Calls made under an idempotency key, for a ledger with no store to
        # record them in: kept as long as the entries are.
        self._keys: dict[str, IdempotencyRecord] = {}
        if store is not None:
            # Fail closed: a database that has been tampered with, or that
            # was corrupted by a crash mid-write, must never be trusted
            # silently. Refuse to start rather than serve a wrong balance.
            image = store.load()
            self._adopt(image.entries, _legacy_events(image), finish=store.read_only)

    @classmethod
    def _from_entries(
        cls,
        store: PersistenceStore,
        entries: Sequence[LedgerEntry],
        legacy: Sequence[ControlEvent] = (),
        *,
        finish: bool = False,
    ) -> Ledger:
        """A ledger over ``store`` holding ``entries``, already read from it."""
        ledger = cls()
        ledger._store = store
        ledger._entries = None if _keeps_history(store) else []
        ledger._adopt(entries, legacy, finish=finish)
        return ledger

    @classmethod
    def _from_image(
        cls,
        store: PersistenceStore,
        image: StoreImage,
        *,
        finish: bool,
        signing: CheckpointSigning | None = None,
    ) -> Ledger:
        """A ledger over ``store`` from one consistent read of it: replayed in
        full, or from the checkpoint snapshot the image carries, checked
        against ``signing``."""
        if image.snapshot is None:
            replayed = cls._from_entries(store, image.entries, _legacy_events(image), finish=finish)
            if signing is not None:
                replayed._check_newest_statement(signing)
            return replayed
        ledger = cls()
        ledger._store = store
        ledger._entries = None if _keeps_history(store) else []
        ledger._adopt_snapshot(image, signing)
        return ledger

    def _check_newest_statement(self, signing: CheckpointSigning) -> None:
        """After a replay from genesis, the newest checkpoint's signed statement.

        A replay proves the chain links, not who wrote it: a consistent
        rewrite links as well. So the newest checkpoint's statement is checked
        as an open from that checkpoint checks it, and its snapshot must be of
        the chain just replayed: the entry hash at its sequence covers every
        entry before it.

        :raises LedgerIntegrityError: If the statement does not check out, or
            signatures are required and the checkpoint has none, or no
            snapshot that matches its digest.
        """
        store: Any = self._store
        last = self._state.last_checkpoint
        if last is None or store is None or not hasattr(store, "snapshot_at"):
            return
        sequence, digest = last
        snapshot = store.snapshot_at(sequence)
        if (
            snapshot is None
            or snapshot.digest != digest
            or _snapshot_digest(snapshot.body) != digest
        ):
            if signing.required:
                raise LedgerIntegrityError(
                    f"the checkpoint of sequence {sequence} has no snapshot that matches its "
                    f"digest, so no signed statement of it can be checked, and this governor "
                    f"requires signed checkpoints"
                )
            return
        state = _decode_snapshot(snapshot.body)
        at = self.entry(sequence)
        if state.length != sequence or at is None or state.head != at.entry_hash:
            raise LedgerIntegrityError(
                f"the snapshot of sequence {sequence} is not of the chain it is stored with"
            )
        first = self.entry(1)
        signing.check(snapshot, state, first.entry_hash if first is not None else "")

    def _adopt_snapshot(self, image: StoreImage, signing: CheckpointSigning | None = None) -> None:
        """Serve the state a checkpoint snapshot holds, and the entries after it.

        The snapshot must be the one the newest CHECKPOINT entry commits to,
        by digest; every entry after it is verified against it by the same
        rules a full replay applies. What came before the snapshot is not
        replayed here: that is the auditor's work (``agentgov audit``), and
        ``verify="full"`` asks for it at open instead.

        :raises LedgerIntegrityError: If the snapshot is missing, altered, or
            not canonical, or an entry after it does not verify.
        """
        snapshot = image.snapshot
        assert snapshot is not None
        checkpoint = next(
            (e for e in reversed(image.entries) if e.entry_type is EntryType.CHECKPOINT), None
        )
        found = _CHECKPOINT_MEMO.match(checkpoint.memo) if checkpoint is not None else None
        if found is None or not snapshot.body:
            raise LedgerIntegrityError(
                "the newest checkpoint names a snapshot this store does not hold, or names "
                "none it can read; open with verify='full' to replay from genesis"
            )
        named = (int(found.group(1)), found.group(2))
        digest = _snapshot_digest(snapshot.body)
        if named != (snapshot.sequence, digest) or snapshot.digest != digest:
            raise LedgerIntegrityError(
                f"the snapshot of sequence {snapshot.sequence} does not match the digest its "
                f"checkpoint entry commits to: it was altered after it was written"
            )
        state = _decode_snapshot(snapshot.body)
        if state.length != snapshot.sequence:
            raise LedgerIntegrityError(
                f"the snapshot stored as sequence {snapshot.sequence} is of sequence {state.length}"
            )
        if signing is not None:
            assert self._store is not None
            first = self._store.entry_at(1)  # type: ignore[attr-defined]
            signing.check(snapshot, state, first.entry_hash if first is not None else "")
        if image.entries[0].sequence != state.length + 1:
            raise LedgerIntegrityError("the entries after the checkpoint do not follow it")
        legacy = _legacy_events(image)
        if state.legacy_applied and legacy != state.legacy:
            raise LedgerIntegrityError(
                "the pre-0.1.2 control events are not the ones the checkpoint folded in: a "
                "legacy trip or reset was edited, added or deleted"
            )
        # A refund after the checkpoint may name a spend before it: found in
        # the store, up to the snapshot's sequence (this ledger's own state is
        # still empty until the replay is done).
        view = _Overlay(
            state,
            resolve=self._resolver_with(image.entries, through=state.length),
            refunds=self._refund_lookup(),
        )
        for entry in image.entries:
            view.apply(entry)
        view.end_transaction()
        view.merge()
        with self._lock:
            self._state = state
            self._open_auths = {
                hold_id: _authorization_for(hold) for hold_id, hold in state.holds.items()
            }
            self._legacy_auth_ids = {}

    def _adopt(
        self,
        entries: Iterable[LedgerEntry],
        legacy: Sequence[ControlEvent] = (),
        *,
        finish: bool = False,
    ) -> None:
        """Replace this ledger's contents with ``entries``, verified first."""
        loaded = list(entries)
        state = _replay(loaded, legacy, finish=finish, refunds=self._refund_lookup())
        with self._lock:
            self._entries = loaded if self._entries is not None else None
            self._state = state
            self._open_auths = {
                hold_id: _authorization_for(hold) for hold_id, hold in state.holds.items()
            }
            self._legacy_auth_ids = {}

    def _rewind(self, length: int) -> None:
        """Take a ledger with no store back to its first ``length`` entries,
        and forget the calls recorded after them: a transaction that did not
        complete. Replays what is kept, as an open would. Lock held."""
        assert self._store is None and self._entries is not None
        self._adopt(self._entries[:length])
        self._keys = {key: r for key, r in self._keys.items() if r.sequence <= length}

    def _resolve(self, entry_id: uuid.UUID, *, through: int | None = None) -> LedgerEntry | None:
        """The committed entry with this id, within this view (or the first
        ``through`` entries), or ``None``."""
        with self._lock:
            if self._entries is not None:
                for entry in reversed(self._entries):
                    if entry.entry_id == entry_id:
                        return entry
                return None
            length = self._state.length if through is None else through
        assert self._store is not None
        found = self._store.entry_by_id(entry_id)  # type: ignore[attr-defined]
        return found if found is not None and found.sequence <= length else None

    def _chain_control_events(self) -> tuple[ControlEvent, ...]:
        """The trips and resets the chain records, oldest first."""
        entries = [
            *self.find_entries(entry_type=EntryType.CIRCUIT_TRIPPED),
            *self.find_entries(entry_type=EntryType.CIRCUIT_RESET),
        ]
        entries.sort(key=lambda entry: entry.sequence)
        return tuple(_event_for(entry) for entry in entries)

    def _control_events(self) -> tuple[ControlEvent, ...]:
        """Every trip and reset: those a pre-0.1.2 governor kept outside the
        chain, then the chain's own, oldest first."""
        with self._lock:
            legacy = self._state.legacy if self._state.legacy_applied else ()
            return (*legacy, *self._chain_control_events())

    def _authorization_id(self, hold_id: uuid.UUID) -> uuid.UUID:
        """The authorization that names a hold: the hold's own id, except for
        holds a pre-0.1.2 governor placed under ids of its own."""
        return self._legacy_auth_ids.get(hold_id, hold_id)

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

        .. deprecated:: 1.0
           Holding it around a check and the act it decides is atomic in this
           process only, not across a fleet. Use
           :meth:`BudgetManager.transaction` (current reads, one commit,
           atomic everywhere) or :meth:`BudgetManager.try_authorize` (a hold
           only if the scope can pay). It keeps working, warning, through 1.x.
        """
        warnings.warn(
            "Ledger.lock is deprecated: use BudgetManager.transaction(), or try_authorize(), "
            "which are atomic across a fleet as well as within this process",
            DeprecationWarning,
            stacklevel=2,
        )
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
            return self._state.length

    def entries(self) -> tuple[LedgerEntry, ...]:
        """Return every entry, oldest first.

        Over a store this reads all of history into one tuple, a cost that
        grows with the ledger: :meth:`iter_entries` reads it a chunk at a
        time, and :meth:`find_entries` reads only what matches.
        """
        return tuple(self.iter_entries())

    def iter_entries(self, *, after: int = 0, until: int | None = None) -> Iterator[LedgerEntry]:
        """Entries after ``after`` up to ``until`` (this view's head by default),
        oldest first, read from the store a chunk at a time."""
        with self._lock:
            head = self._state.length
            stop = head if until is None else min(until, head)
            if self._entries is not None:
                snapshot = self._entries[after:stop]
        if self._entries is not None:
            yield from snapshot
            return
        assert self._store is not None
        yield from self._store.iter_entries(after=after, until=stop)  # type: ignore[attr-defined]

    def entry(self, sequence: int) -> LedgerEntry | None:
        """The entry at ``sequence``, or ``None`` beyond this view's head."""
        with self._lock:
            if not 0 < sequence <= self._state.length:
                return None
            if self._entries is not None:
                return self._entries[sequence - 1]
        assert self._store is not None
        found: LedgerEntry | None = self._store.entry_at(sequence)  # type: ignore[attr-defined]
        return found

    def find_entries(
        self,
        *,
        scope_id: str | None = None,
        entry_type: EntryType | None = None,
        memo: str | None = None,
        transaction_id: uuid.UUID | None = None,
        ref: uuid.UUID | None = None,
        after: int = 0,
        limit: int | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """Entries matching every criterion given, oldest first, within this
        view. Over a store, ``scope_id`` and ``entry_type`` (with ``memo``)
        are answered by an index; ``transaction_id`` and ``ref`` filter what
        those find, or scan history when given alone."""
        with self._lock:
            head = self._state.length
            if self._entries is not None:
                matches = [
                    e
                    for e in self._entries[after:head]
                    if (scope_id is None or e.scope_id == scope_id)
                    and (entry_type is None or e.entry_type is entry_type)
                    and (memo is None or e.memo == memo)
                    and (transaction_id is None or e.transaction_id == transaction_id)
                    and (ref is None or e.ref == ref)
                ]
                return tuple(matches[:limit] if limit is not None else matches)
        assert self._store is not None
        found: tuple[LedgerEntry, ...] = self._store.find_entries(  # type: ignore[attr-defined]
            scope_id=scope_id,
            entry_type=entry_type,
            memo=memo,
            transaction_id=transaction_id,
            ref=ref,
            after=after,
            limit=limit,
        )
        return tuple(e for e in found if e.sequence <= head)

    def entries_for_scope(self, scope_id: str) -> tuple[LedgerEntry, ...]:
        """Return every entry touching ``scope_id``, oldest first.

        :param scope_id: The scope to retrieve history for.
        """
        return self.find_entries(scope_id=scope_id)

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

    def _post(
        self,
        lines: Sequence[LedgerLine],
        *,
        transaction_id: uuid.UUID | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """Commit ``lines`` as one transaction, in a unit of work of its own."""
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
        view = pending.view
        # The cache rows this work writes are the ones its entries imply,
        # derived by the same engine that checked them, never assembled by
        # hand alongside: a write cannot leave a cache the chain contradicts.
        nodes, controls, opened = view.cache_rows()
        batch.nodes = nodes
        batch.control_events = controls
        batch.opened = [_authorization_for(hold) for hold in opened]
        batch.closed = [self._authorization_id(hold_id) for hold_id in view.closed]
        if not batch:
            return
        with self._lock:
            if view.start_head != self._state.head:
                raise RuntimeError(
                    "unit of work was built against a stale ledger head; "
                    "hold the ledger lock from begin to commit"
                )
            if self._store is not None:
                self._store.commit(batch)
            view.merge()
            self._follow_holds(view)
            if self._entries is not None:
                self._entries.extend(batch.entries)
            if self._store is None:
                for record in batch.idempotency:
                    self._keys[record.key] = record
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
            view = _Overlay(
                self._state, resolve=self._resolver_with(entries), refunds=self._refund_lookup()
            )
            for entry in entries:
                view.apply(entry)
            view.end_transaction()
            view.merge()
            self._follow_holds(view)
            if self._entries is not None:
                self._entries.extend(entries)

    def _refund_lookup(self) -> Callable[[uuid.UUID, int], Decimal] | None:
        """How the refunds of a spend are counted: from the store, when it
        keeps history (the state then remembers none); from the state, when
        history is kept in memory."""
        return _refunds_in(self._store) if self._entries is None else None

    def _refunded_of_spend(self, spend_id: uuid.UUID) -> Decimal:
        """How much of a spend refunds have returned, within this view."""
        with self._lock:
            lookup = self._refund_lookup()
            if lookup is None:
                return self._state.refunded_of_spend(spend_id)
            length = self._state.length
        return lookup(spend_id, length)

    def _resolver_with(
        self, entries: Sequence[LedgerEntry], *, through: int | None = None
    ) -> Callable[[uuid.UUID], LedgerEntry | None]:
        """A resolver over this ledger's entries (or its store's first
        ``through``) and ``entries``, new ones."""
        new = _spend_index(entries)
        return lambda entry_id: new(entry_id) or self._resolve(entry_id, through=through)

    def _follow_holds(self, view: _Overlay) -> None:
        """Open and close authorizations as a merged view's holds did. Lock held.

        Kept here, beside the chain state, so every path that writes the
        chain keeps them in step: what is open is exactly what the chain
        holds open, whoever wrote it.
        """
        for hold_id in view.closed:
            self._open_auths.pop(self._authorization_id(hold_id), None)
            self._legacy_auth_ids.pop(hold_id, None)
        for hold in view.opened:
            self._open_auths[hold.entry_id] = _authorization_for(hold)

    def _reassign_holds(self, key: _HoldKey, holds: Sequence[LedgerEntry]) -> None:
        """Name which holds of an ambiguous pre-0.1.2 key are the open ones."""
        with self._lock:
            _reassign_holds(self._state, key, holds)

    def _publish(self, entries: list[LedgerEntry] | None, state: _ChainState) -> None:
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
        state = self._replayed(self._live())
        return state.balances, state.totals

    def _live(self) -> _ChainState:
        """A copy of the state this ledger serves: what a full replay must
        reproduce. Taken under the lock, in time proportional to the state."""
        with self._lock:
            return self._state.copy()

    def _replayed(self, live: _ChainState) -> _ChainState:
        """The state the entries up to ``live``'s head imply, rebuilt from
        nothing. Over a store, read a chunk at a time and without this
        ledger's lock, so writers keep writing meanwhile."""
        entries = self.iter_entries(until=live.length)
        if self._entries is not None:
            return _replay(list(entries), live.legacy, finish=live.legacy_applied)
        assert self._store is not None
        return _replay(
            entries,
            live.legacy,
            finish=live.legacy_applied,
            resolve=self._store.entry_by_id,  # type: ignore[attr-defined]
        )

    def verify_chain(self) -> None:
        """Verify the hash chain, the running balances, hold pairing and caches.

        :raises LedgerIntegrityError: On the first inconsistency found — a
            broken link, a re-derived hash that does not match, a sequence
            gap, a balance the arithmetic does not produce, a hold released
            twice, or a cached figure that disagrees with a full replay.
        """
        # The state is copied under the lock and the chain replayed outside
        # it, so over a store a full verification never stops writers.
        live = self._live()
        replayed = self._replayed(live)
        if replayed.head != live.head:
            raise LedgerIntegrityError("head hash does not match the chain")
        _compare_governance(replayed, live)
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
            total_balance = ZERO
            for balance in self._state.balances.values():
                total_balance = _add(total_balance, balance)
            t = self._state.totals
            left = _subtract(_add(_add(total_balance, t.holds_open), t.spent), t.reversed_)
            if left != t.funded:
                raise LedgerIntegrityError(
                    f"conservation violated: balances {total_balance} + holds "
                    f"{t.holds_open} + spent {t.spent} - reversed {t.reversed_} "
                    f"= {left}, but funded = {t.funded}"
                )


def _compare_governance(replayed: _ChainState, live: _ChainState) -> None:
    """The live tree, breakers and control events must be what the chain implies."""
    for scope_id, node in live.nodes.items():
        expected = replayed.nodes.get(scope_id)
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
    unregistered = sorted(replayed.nodes.keys() - live.nodes.keys())
    if unregistered:
        raise LedgerIntegrityError(
            f"the chain created scope(s) {', '.join(unregistered)} that are not registered"
        )
    if set(live.tripped) != set(replayed.tripped):
        raise LedgerIntegrityError(
            f"breaker state disagrees with the chain: halted here "
            f"{sorted(live.tripped)}, halted by the chain {sorted(replayed.tripped)}"
        )
    if live.frontier != replayed.frontier:
        raise LedgerIntegrityError("the Merkle frontier disagrees with the chain")
    if (live.spent, live.refunded) != (replayed.spent, replayed.refunded):
        raise LedgerIntegrityError("lifetime spend or refunds disagree with the chain")


def _holds_snapshots(store: PersistenceStore | None) -> bool:
    """Whether ``store`` speaks the v1.0 store interface: checkpoint snapshots,
    and the keyword arguments of ``load`` and ``snapshot`` that go with them."""
    return store is not None and hasattr(store, "put_snapshot")


def _refunds_in(store: Any) -> Callable[[uuid.UUID, int], Decimal]:
    """What the refunds naming a spend among ``store``'s first ``n`` entries
    add up to, read by the index of refunds by the spend they name: no state
    need remember it for every spend ever refunded."""

    def refunded(spend_id: uuid.UUID, through: int) -> Decimal:
        total = ZERO
        for entry in store.find_entries(entry_type=EntryType.REVERSAL, ref=spend_id):
            if entry.sequence <= through:
                total = _add(total, entry.amount)
        return total

    return refunded


def _keeps_history(store: PersistenceStore | None) -> bool:
    """Whether ``store`` can answer for history, so memory need not."""
    return store is not None and all(
        hasattr(store, name) for name in ("iter_entries", "find_entries", "entry_by_id", "entry_at")
    )


def _legacy_events(image: StoreImage) -> tuple[ControlEvent, ...]:
    """The control events in ``image`` that a pre-0.1.2 governor kept outside the chain."""
    return tuple(event for event in image.control_events if event.entry_id is None)


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


class JoinedTransaction:
    """A governor's part in a transaction someone else owns.

    Yielded by :meth:`BudgetManager.joined`. The only thing it writes is a
    :class:`SettlementClaim`, into the caller's transaction: nothing in the
    chain, so nothing that depends on which ledger head the caller's
    transaction can see.
    """

    __slots__ = ("_manager", "_store")

    def __init__(self, manager: BudgetManager, store: JoinableStore) -> None:
        self._manager = manager
        self._store = store

    def claim(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str,
        hold: Authorization | None = None,
    ) -> SettlementClaim:
        """Owe ``amount`` from ``scope_id``, durably if the caller commits.

        :param hold: The authorization placed for this beforehand. Redemption
            releases it and settles against it; without one, redemption posts
            the spend directly.
        :returns: The claim, to redeem once the caller has committed
            (:meth:`BudgetManager.redeem`).
        :raises UnknownScopeError: If the scope is not in the ledger.
        :raises ValueError: If ``amount`` is negative, or ``hold`` belongs to
            another scope.
        """
        owed = _cost(amount)
        if owed < ZERO:
            raise ValueError(f"a claim cannot owe a negative amount, got {owed}")
        if not memo:
            raise ValueError("a claim must carry the memo its settlement will record")
        if hold is not None and hold.scope_id != scope_id:
            raise ValueError(
                f"hold {hold.authorization_id} is on scope {hold.scope_id!r}, not {scope_id!r}"
            )
        with self._manager._lock:
            self._manager._require_node(scope_id)
        claim = SettlementClaim(
            claim_id=uuid.uuid4(),
            hold_id=None if hold is None else hold.authorization_id,
            scope_id=scope_id,
            amount=owed,
            memo=memo,
        )
        self._store.claim(claim)
        return claim


class Transaction:
    """A unit of work held open by :meth:`BudgetManager.transaction`.

    Its methods are the governor's own, run inside the transaction: reads
    are current, and every mutation joins the transaction's one commit. It
    is used by the thread that opened it, inside its ``with`` block only.
    """

    __slots__ = ("_manager", "_open", "_owner", "_trips")

    def __init__(self, manager: BudgetManager) -> None:
        self._manager = manager
        self._owner = threading.get_ident()
        self._open = True
        self._trips: list[tuple[str, str]] = []  # breaker trips recorded inside

    def _governor(self) -> BudgetManager:
        if not self._open:
            raise RuntimeError(
                "this transaction has ended; open another with BudgetManager.transaction()"
            )
        if threading.get_ident() != self._owner:
            raise RuntimeError("a transaction is used only by the thread that opened it")
        return self._manager

    # -- reads, current inside a transaction --------------------------------

    def available(self, scope_id: str) -> Decimal:
        """:meth:`BudgetManager.available`, current."""
        return self._governor().available(scope_id)

    def subtree_available(self, scope_id: str) -> Decimal:
        """:meth:`BudgetManager.subtree_available`, current."""
        return self._governor().subtree_available(scope_id)

    def is_halted(self, scope_id: str) -> bool:
        """:meth:`BudgetManager.is_halted`, current."""
        return self._governor().is_halted(scope_id)

    def authorization(self, authorization_id: uuid.UUID | str) -> Authorization | None:
        """:meth:`BudgetManager.authorization`, current."""
        return self._governor().authorization(authorization_id)

    # -- mutations, joining the transaction's commit ------------------------

    def authorize(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> Authorization:
        """:meth:`BudgetManager.authorize`, in this transaction."""
        return self._governor().authorize(
            scope_id, amount, memo=memo, idempotency_key=idempotency_key
        )

    def try_authorize(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> Authorization | None:
        """:meth:`BudgetManager.try_authorize`, in this transaction."""
        return self._governor().try_authorize(
            scope_id, amount, memo=memo, idempotency_key=idempotency_key
        )

    def capture(
        self,
        authorization: Authorization,
        actual_cost: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """:meth:`BudgetManager.capture`, in this transaction."""
        return self._governor().capture(
            authorization, actual_cost, memo=memo, idempotency_key=idempotency_key
        )

    def void(
        self, authorization: Authorization, *, memo: str = "", idempotency_key: str | None = None
    ) -> LedgerEntry:
        """:meth:`BudgetManager.void`, in this transaction."""
        return self._governor().void(authorization, memo=memo, idempotency_key=idempotency_key)

    def spend(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """:meth:`BudgetManager.spend`, in this transaction."""
        return self._governor().spend(scope_id, amount, memo=memo, idempotency_key=idempotency_key)

    def refund(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        reverses: LedgerEntry | uuid.UUID | None = None,
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """:meth:`BudgetManager.refund`, in this transaction."""
        return self._governor().refund(
            scope_id, amount, memo=memo, reverses=reverses, idempotency_key=idempotency_key
        )

    def fund(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """:meth:`BudgetManager.fund`, in this transaction."""
        return self._governor().fund(scope_id, amount, memo=memo, idempotency_key=idempotency_key)

    def delegate(
        self,
        parent_id: str,
        child_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> BudgetNode:
        """:meth:`BudgetManager.delegate`, in this transaction."""
        return self._governor().delegate(
            parent_id, child_id, amount, memo=memo, idempotency_key=idempotency_key
        )

    def release(
        self, scope_id: str, amount: Decimal | int | str | None = None, *, memo: str = ""
    ) -> Decimal:
        """:meth:`BudgetManager.release`, in this transaction."""
        return self._governor().release(scope_id, amount, memo=memo)

    def anchor(self, scope_id: str, memo: str) -> LedgerEntry:
        """:meth:`BudgetManager.anchor`, in this transaction."""
        return self._governor().anchor(scope_id, memo)

    def trip(self, scope_id: str, reason: str) -> None:
        """:meth:`BudgetManager.trip`, in this transaction."""
        self._governor().trip(scope_id, reason)

    def reset(self, scope_id: str) -> None:
        """:meth:`BudgetManager.reset`, in this transaction."""
        self._governor().reset(scope_id)


@dataclass(slots=True)
class _Velocity:
    """A scope's recent authorizations, for the runaway-loop detector.

    The one piece of breaker state that is this governor's own: whether a
    scope is halted is the chain's, but how fast this process has been
    calling is not.
    """

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
    :ivar checkpoint_every: Over a durable store, write a checkpoint once the
        chain has grown this many entries past the last one, so a governor
        opens by replaying at most about this many entries, however long the
        ledger. The write is made after the mutation that crossed the line,
        in a session of its own, never inside it. ``0`` disables it; a
        deployment with a very large state (many scopes and open holds) can
        raise it, since a snapshot costs time proportional to the state.
    :ivar trip_on_exhaustion: Trip the breaker when a scope's balance reaches
        exactly zero with no holds outstanding, so the next call fails fast
        instead of racing to the same conclusion.
    :ivar fleet_velocity: Count a scope's authorizations across the fleet:
        the holds placed on it in the chain, by every governor, within
        ``window_seconds`` (by their timestamps), rather than this governor's
        own calls. Without it, N governors of one ledger admit N times the
        rate. Only on a shared ledger does it differ.
    """

    max_calls_per_window: int = 1000
    window_seconds: float = 1.0
    max_depth: int = 8
    trip_on_overdraft: bool = True
    trip_on_exhaustion: bool = True
    checkpoint_every: int = 10_000
    fleet_velocity: bool = False


# --------------------------------------------------------------------------
# BudgetManager
# --------------------------------------------------------------------------


_P = ParamSpec("_P")
_R = TypeVar("_R")


class _Request:
    """One caller's mutation, waiting for a unit of work to run it in."""

    __slots__ = ("error", "key", "settled", "value", "wake", "work")

    def __init__(self, work: Callable[[], Any], key: str | None = None) -> None:
        self.work = work
        self.key = key  # its idempotency key, looked up with the others queued
        self.value: Any = None
        self.error: BaseException | None = None
        self.settled = False
        # Released once, to wake its caller alone: when the work is settled,
        # or when the lead is handed to it.
        self.wake = threading.Lock()
        self.wake.acquire()

    def outcome(self) -> Any:
        if self.error is not None:
            raise self.error
        return self.value


def _grouped(
    method: Callable[Concatenate[BudgetManager, _P], _R],
) -> Callable[Concatenate[BudgetManager, _P], _R]:
    """A mutation that may share a unit of work with others (group commit)."""

    @functools.wraps(method)
    def grouped(self: BudgetManager, /, *args: _P.args, **kwargs: _P.kwargs) -> _R:
        key = kwargs.get("idempotency_key")
        work = functools.partial(method, self, *args, **kwargs)
        result: _R = self._submit(work, key if isinstance(key, str) else None)
        return result

    return grouped


_RECENT_HASHES: Final = 4096
"""How many of the newest entries' hashes a governor keeps, to tell a ledger
cut back under it from one rewritten: a failover loses at most the last few
seconds of commits."""

_UNRECORDED: Final[Any] = object()
"""No call was recorded under the key: the call is a new one."""

_KEY_BYTES: Final = 255
"""The most UTF-8 bytes an idempotency key may hold."""


def _request_text(operation: str, **arguments: object) -> str:
    """A call's identity: canonical JSON of its operation and its arguments,
    each as the call used it (an amount as it was rounded to be posted)."""
    document: dict[str, object] = {"op": operation}
    for name, value in arguments.items():
        if isinstance(value, Decimal):
            value = _fixed(value)
        elif isinstance(value, uuid.UUID):
            value = str(value)
        document[name] = value
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _operation_of(request: str) -> str:
    """The operation a recorded request names, for an error message."""
    try:
        return str(json.loads(request)["op"])
    except (ValueError, KeyError, TypeError):
        return "an unreadable request"


def _require_key(key: object) -> str:
    """``key``, if it can be an idempotency key: text, at most 255 bytes of
    UTF-8, with no control character."""
    if not isinstance(key, str) or not key:
        raise ValueError("an idempotency key must be a non-empty string")
    problem = _check_text(key, "idempotency key", limit=_KEY_BYTES, identifier=True)
    if problem is not None:
        raise ValueError(problem)
    return key


@dataclass(slots=True)
class _Call:
    """A call made under an idempotency key, while it runs.

    :ivar replayed: What the call returned when it was first made, if it
        was: then it is not made again.
    :ivar record: Its record, once its entries are committed with it.
    """

    key: str
    request: str
    outcome: str
    replayed: Any = _UNRECORDED
    record: IdempotencyRecord | None = None


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
        holds entries is not re-read: its topology, breaker state and open
        holds are already part of its chain state.
    :param policy: Governance limits; defaults to :class:`GovernancePolicy`.
    :param store: A durable backend. Pass the *same* store given to ``ledger``
        (or omit ``ledger`` and let this constructor build one).
        :meth:`open_sqlite` sets this up correctly in one call.
    :param repair: When the store's cache tables (topology, control events,
        open authorizations) disagree with the chain, rebuild them from the
        chain instead of refusing to open. Moves no money.
    :param signing: Sign the checkpoints this governor writes and check the
        one it opens from (see :class:`CheckpointSigning`).
    :param metrics: Where to report how this governor is doing (lock waits,
        units of work, catch-ups, trips, checkpoint lag): see
        :mod:`agentgov.metrics`. Nothing is measured without it.

    **A shared ledger.** Over a :class:`~agentgov.storage.SharedStore` (see
    :meth:`open_postgres`) this manager is one of several governors writing
    the same ledger, and its memory is a verified cache of it, not the ledger
    itself. Every mutating call then takes the fleet-wide writer lock, reads
    and verifies everything the other governors committed since its last
    look, and only then checks a balance or a breaker and writes. Reads
    (:meth:`available`, :meth:`is_halted`, ...) are served from the view as of
    this governor's last write or :meth:`refresh`; pass ``fresh=True``, or
    read inside :meth:`transaction`, for a current answer. The runaway-loop
    velocity window is counted per governor unless
    :attr:`GovernancePolicy.fleet_velocity` says otherwise.
    """

    def __init__(
        self,
        *,
        ledger: Ledger | None = None,
        policy: GovernancePolicy | None = None,
        store: PersistenceStore | None = None,
        repair: bool = False,
        verify: str = "checkpoint",
        auditor: bool | None = None,
        signing: CheckpointSigning | None = None,
        metrics: Metrics | None = None,
    ) -> None:
        started = time.perf_counter()
        if verify not in _VERIFY_POLICIES:
            raise ValueError(f"verify must be one of {sorted(_VERIFY_POLICIES)}, got {verify!r}")
        shared = _shared_store(store) if store is not None and not store.read_only else None
        # Opened without the fleet's writer lock. The committed prefix of a
        # chain never changes (the append-only triggers see to that on a
        # shared store, the single writer on SQLite), so one consistent
        # snapshot of every table can be verified and served on its own. The
        # first mutation catches up with whatever was committed since, under
        # the lock, as every mutation does. Only a repair takes the lock, and
        # it re-reads under it before writing (_restore_from_store).
        image: StoreImage | None = None
        if store is not None:
            # One consistent read of every table: a live writer in another
            # process cannot slip a commit between the entries and the
            # caches that describe them.
            if _holds_snapshots(store):
                image = store.load(from_checkpoint=verify == "checkpoint" and ledger is None)
            else:
                image = store.load()  # a store written before checkpoints existed
            legacy = _legacy_events(image)
            if ledger is None:
                ledger = Ledger._from_image(store, image, finish=store.read_only, signing=signing)
            elif shared is not None and (len(ledger), ledger.head_hash) != _image_head(image):
                # A ledger read from a shared store before this snapshot may
                # be behind it; serve the snapshot, which the caches match.
                ledger._adopt(image.entries, legacy)
        elif ledger is None:
            ledger = Ledger()
        self._ledger = ledger
        self._policy = policy if policy is not None else GovernancePolicy()
        # One mutex for the whole control plane. Sharing the ledger's lock
        # (rather than nesting a second one under it) removes any possibility
        # of a lock-ordering deadlock.
        self._lock = self._ledger._lock
        self._store: PersistenceStore | None = store
        self._shared: SharedStore | None = shared
        # A single-writer store that can carry many commits in one
        # transaction (SQLite) shares units of work too: one fsync for every
        # caller queued, rather than one each.
        self._grouping = shared is not None or (
            store is not None and not store.read_only and hasattr(store, "unit")
        )
        self._writing = False
        self._dirty = False
        self._depth = 0
        self._checkpointing = False
        self._verify = verify
        self._signing = signing
        self._queue: list[_Request] = []
        self._queue_lock = threading.Lock()
        self._leading = False
        self._contended = False  # the last catch-up found others' entries
        self._transaction: Transaction | None = None
        self._unit_session: WriterSession | None = None  # the shared store's, while one is open
        # Within one unit of work: the calls made under a key and what each
        # returned, and the keys already looked up in the store.
        self._unit_calls: dict[str, tuple[IdempotencyRecord, Any]] = {}
        self._key_cache: dict[str, IdempotencyRecord | None] = {}
        self._metrics = metrics
        self._auditor: Any = None
        self._velocity: dict[str, _Velocity] = {}
        # Every scope's recent holds, by any governor (fleet_velocity), and the
        # hashes of the entries this view verified last: to tell a ledger
        # cut back under it (a failover) from one rewritten.
        self._fleet_holds: dict[str, deque[datetime]] = {}
        self._recent: deque[tuple[int, str]] = deque(maxlen=_RECENT_HASHES)
        self._checkpoint_retry_at = 0.0  # after a failed automatic checkpoint
        self._checkpoint_backoff = 0.0
        self._repairs: tuple[str, ...] = ()
        self._schema_version = ""
        self._control_high_water = 0
        self._unusable: str | None = None

        if store is not None and image is not None:
            self._restore_from_store(store, image, repair=repair)
            self._start_auditing(
                store, opened_from_checkpoint=image.snapshot is not None, want=auditor
            )
        self._remember_head()
        if metrics is not None and store is not None:
            metrics.record("agentgov.open.duration", time.perf_counter() - started)

    def _start_auditing(
        self, store: PersistenceStore, *, opened_from_checkpoint: bool, want: bool | None
    ) -> None:
        """Refuse to write a ledger an auditor found does not verify, and audit
        what this open did not replay.

        A governor that opened from a checkpoint trusted the snapshot for
        everything before it; unless told otherwise it runs an auditor in a
        thread of its own, which replays that history (once per ledger: it
        resumes from the newest mark any auditor verified) and stops this
        governor writing if the chain does not verify.
        """
        holder: Any = store
        failure = holder.audit_failure() if hasattr(holder, "audit_failure") else None
        if failure is not None:
            message = (
                f"an auditor found this ledger does not verify ({failure.detail}); investigate "
                f"with `agentgov verify`. A later audit that verifies the chain clears this"
            )
            if not store.read_only:
                raise LedgerIntegrityError(message)
            logger.warning(message)
            return
        start = want if want is not None else opened_from_checkpoint
        if store.read_only or not start or not hasattr(holder, "fork"):
            return
        from agentgov.audit import AuditorThread

        self._auditor = AuditorThread(
            holder.fork(), on_failure=self._audit_failed, signing=self._signing
        )

    def _audit_failed(self, detail: str) -> None:
        """The auditor found the chain does not verify: write nothing more."""
        with self._lock:
            self._unusable = f"the auditor found the chain does not verify: {detail}"

    @classmethod
    def open_sqlite(
        cls,
        path: str,
        *,
        policy: GovernancePolicy | None = None,
        synchronous: str = "FULL",
        read_only: bool = False,
        repair: bool = False,
        verify: str = "checkpoint",
        auditor: bool | None = None,
        signing: CheckpointSigning | None = None,
        metrics: Metrics | None = None,
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
        :param verify: What to verify at open: ``"checkpoint"`` (the default)
            verifies the newest checkpoint's snapshot and every entry after
            it, in time bounded by the entries since that checkpoint;
            ``"full"`` replays the whole chain from genesis, as
            ``agentgov verify`` does.
        :param auditor: Run an auditor (:mod:`agentgov.audit`) in a thread of
            this governor's, to replay the history an open from a checkpoint
            did not. On by default exactly when this open started from a
            checkpoint; pass ``False`` where a sidecar audits instead.
        :param signing: Sign every checkpoint this governor writes, and check
            the one it opens from: see :class:`CheckpointSigning`.
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
            return cls(
                policy=policy,
                store=store,
                repair=repair,
                verify=verify,
                auditor=auditor,
                signing=signing,
                metrics=metrics,
            )
        except BaseException:
            # Never leak the advisory claim if restore-and-verify rejects the
            # file: the next process to try must not be told it is contended.
            store.close()
            raise

    @classmethod
    def open_postgres(
        cls,
        conninfo: str,
        *,
        schema: str = "agentgov",
        policy: GovernancePolicy | None = None,
        read_only: bool = False,
        repair: bool = False,
        lock_timeout: float = 30.0,
        idle_timeout: float = 60.0,
        prepare_threshold: int | None = None,
        verify: str = "checkpoint",
        auditor: bool | None = None,
        signing: CheckpointSigning | None = None,
        metrics: Metrics | None = None,
    ) -> BudgetManager:
        """Open one governor of a ledger shared through PostgreSQL.

        Unlike :meth:`open_sqlite`, any number of governors, in any number of
        processes on any number of hosts, may open the same ``schema`` for
        writing at once. They share one ledger: a dollar one of them holds is
        a dollar none of the others can spend. Each writes under a fleet-wide
        lock, after verifying everything the others committed; see
        :mod:`agentgov.postgres` for the protocol and what guarantees it.

        The first governor to open a database creates the ledger's tables in
        ``schema``. Requires ``pip install 'agentgov[postgres]'``.

        :param conninfo: A libpq connection string or URI.
        :param schema: The PostgreSQL schema the ledger lives in.
        :param policy: Governance limits; defaults to :class:`GovernancePolicy`.
            Like the SQLite store, the policy is not stored: every governor
            supplies its own.
        :param read_only: Open for audit; call :meth:`refresh` to follow.
        :param repair: Rebuild cache tables that disagree with the chain.
        :param lock_timeout: Seconds to wait for the writer lock before an
            operation fails with :class:`~agentgov.exceptions.StorageError`.
        :param idle_timeout: Seconds the server lets this governor idle inside
            an open transaction, holding the lock, before ending its session.
        :param prepare_threshold: When psycopg prepares a query on the server:
            ``None`` (the default) for never, which any pooler accepts. See
            :class:`~agentgov.postgres.PostgresStore`.
        :param verify: What to verify at open; see :meth:`open_sqlite`.
        :param auditor: Run an auditor thread; see :meth:`open_sqlite`.
        :param signing: Sign checkpoints, and check them; see :meth:`open_sqlite`.
        :raises agentgov.exceptions.StorageError: If the database cannot be
            reached.
        :raises agentgov.exceptions.LedgerIntegrityError: If the shared chain,
            balances, pairing or topology are inconsistent.
        """
        from agentgov.postgres import PostgresStore

        store = PostgresStore(
            conninfo,
            schema=schema,
            read_only=read_only,
            lock_timeout=lock_timeout,
            idle_timeout=idle_timeout,
            prepare_threshold=prepare_threshold,
        )
        try:
            return cls(
                policy=policy,
                store=store,
                repair=repair,
                verify=verify,
                auditor=auditor,
                signing=signing,
                metrics=metrics,
            )
        except BaseException:
            store.close()
            raise

    def __enter__(self) -> BudgetManager:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying durable store, if this manager has one, and
        stop its auditor.

        A no-op for a manager with no store. Safe to call more than once.
        """
        auditor, self._auditor = self._auditor, None
        if auditor is not None:
            auditor.stop()
        self._ledger.close()

    # -- the chain state, as this manager serves it -----------------------

    @property
    def _state(self) -> _ChainState:
        return self._ledger._state

    @property
    def _nodes(self) -> dict[str, BudgetNode]:
        return self._ledger._state.nodes

    @property
    def _roots(self) -> list[str]:
        return self._ledger._state.roots

    @property
    def _open_auths(self) -> dict[uuid.UUID, Authorization]:
        """Open authorizations by id: the chain's open holds, kept by the ledger."""
        return self._ledger._open_auths

    # -- restore ----------------------------------------------------------

    def _restore_from_store(
        self, store: PersistenceStore, image: StoreImage, *, repair: bool
    ) -> None:
        """Check the store's caches against the chain, already verified.

        Called once, from the constructor, before this manager is visible to
        any other code.

        :raises LedgerIntegrityError: If a cache table disagrees with the
            chain (unless ``repair``), or the chain's own governance record is
            inconsistent. A corrupted or partially written database is
            refused, never trusted.
        """
        restored = self._derive(image, repair=repair)
        problems = restored.problems
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
            if self._shared is not None:
                # A repair rewrites cache rows, so on a shared ledger it is
                # made under the writer lock, from a read made under it: rows
                # another governor committed after the snapshot this view was
                # opened from must not be erased.
                with self._shared.writer():
                    image = store.load()
                    self._ledger._adopt(image.entries, _legacy_events(image))
                    restored = self._derive(image, repair=True)
                    if restored.problems:
                        restored.rebuild(store, self._ledger)
            else:
                restored.rebuild(store, self._ledger)
            self._repairs = tuple(restored.problems)
            for problem in restored.problems:
                audit_log.warning(f"{_AUDIT_VERSION}|repair|{_escape(problem)}")

        self._schema_version = restored.schema_version
        self._control_high_water = restored.control_high_water
        self._adopt_authorizations(restored.authorizations, restored.identities)
        if not store.read_only and self._state.saw_v1 and not self._state.saw_v2:
            self._seal()

        # Fail closed. Everything served was just derived from a verified
        # replay of the chain, so replaying it a second time would prove
        # nothing new; what remains is what the derivation does not imply.
        self._verify_derived()

    def _derive(self, image: StoreImage, *, repair: bool) -> _Restored:
        """The authorizations and cache disagreements ``image`` implies,
        against this manager's (already verified) chain state."""
        state = self._state
        problems = _node_row_problems(state, image.nodes)
        chained = [_event_for(e) for e in image.entries if e.entry_type in _CONTROL_TYPES]
        problems += _control_row_problems(chained, image.control_events)
        auths, auth_problems, identities = self._reconcile_authorizations(
            image.authorizations, self._hold_index(), repairing=repair
        )
        problems += auth_problems
        return _Restored(
            authorizations=auths,
            identities=identities,
            problems=problems,
            schema_version=image.schema_version,
            control_high_water=image.control_high_water,
        )

    def _adopt_authorizations(
        self,
        authorizations: dict[uuid.UUID, Authorization],
        identities: dict[_HoldKey, list[LedgerEntry]],
    ) -> None:
        """Serve these open authorizations. Lock held, or not yet shared."""
        for key, chosen in identities.items():
            _reassign_holds(self._state, key, chosen)
        self._ledger._open_auths = authorizations
        self._ledger._legacy_auth_ids = {
            auth.entry.entry_id: auth_id
            for auth_id, auth in authorizations.items()
            if auth_id != auth.entry.entry_id
        }

    def _verify_derived(self) -> None:
        """The checks a fresh derivation from the chain does not already imply.

        Conservation, the tree's own shape, and that every open hold has
        exactly one authorization. Costs time proportional to scopes and open
        holds, not to history.
        """
        self._ledger.verify_conservation()
        self._verify_tree()
        self._verify_authorizations()

    def _seal(self) -> None:
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
                        memo=_seal_memo(self._state.legacy),
                    )
                ]
            )
            self._commit(pending)

    def _reconcile_authorizations(
        self,
        rows: Sequence[PersistedAuthorization],
        index: _HoldIndex,
        *,
        repairing: bool,
        state: _ChainState | _Overlay | None = None,
    ) -> tuple[dict[uuid.UUID, Authorization], list[str], dict[_HoldKey, list[LedgerEntry]]]:
        """Match stored authorization rows against the chain's open holds.

        Every open hold must be named by exactly one row and every row must
        name an open hold, in the same scope, for the same amount. A row that
        names a hold the chain already released is the state a v0.1.1 crash
        could leave behind, and releasing it again would hand the same funds
        back twice; it is reported, never served.

        :param state: The chain to match against: this ledger's own when
            omitted, or a view of it with new entries staged.
        :returns: The authorizations to serve (repaired when ``repairing``),
            the disagreements found, and the open-hold identities to adopt for
            ambiguous pre-0.1.2 keys.
        """
        view: _ChainState | _Overlay = self._state if state is None else state
        problems: list[str] = []
        result: dict[uuid.UUID, Authorization] = {}
        ambiguous_rows: dict[_HoldKey, list[Authorization]] = {}
        named: set[uuid.UUID] = set()

        for row in rows:
            if row.entry_id in named:
                problems.append(f"two open authorizations name hold {row.entry_id}")
                continue
            named.add(row.entry_id)
            hold = view.open_hold(row.entry_id) or index.hold(row.entry_id)
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
            is_open = view.open_hold(hold.entry_id) is not None
            if not is_open and index.released(hold.entry_id):
                problems.append(
                    f"open authorization {row.authorization_id} references hold "
                    f"{hold.entry_id}, which the chain shows was already released; "
                    f"acting on it would return the same funds twice"
                )
            elif view.is_ambiguous(key):
                ambiguous_rows.setdefault(key, []).append(authorization)
            elif not is_open:
                problems.append(
                    f"open authorization {row.authorization_id} references hold "
                    f"{hold.entry_id}, which the chain shows was already released; "
                    f"acting on it would return the same funds twice"
                )
            else:
                result[row.authorization_id] = authorization

        open_holds = list(view.iter_holds())
        for hold_id, hold in open_holds:
            if view.is_ambiguous(_hold_key(hold)) or hold_id in named:
                continue
            problems.append(
                f"hold {hold_id} of {hold.amount} in {hold.scope_id!r} is open in the chain "
                f"but no authorization names it; its funds would stay encumbered with "
                f"nothing able to release them"
            )
            if repairing:
                result[hold_id] = _authorization_for(hold)

        identities: dict[_HoldKey, list[LedgerEntry]] = {}
        for key in sorted(view.ambiguous_keys(), key=repr):
            in_key = [e for _, e in open_holds if _hold_key(e) == key]
            candidates = ambiguous_rows.get(key, [])
            if len(candidates) != len(in_key):
                scope_id, amount = key
                problems.append(
                    f"{len(in_key)} hold(s) of {amount} are open in {scope_id!r} but "
                    f"{len(candidates)} authorization(s) name one"
                )
            kept = candidates[: len(in_key)]
            chosen = [authorization.entry for authorization in kept]
            chosen_ids = {hold.entry_id for hold in chosen}
            for authorization in kept:
                result[authorization.authorization_id] = authorization
            for hold in in_key:
                if len(chosen) == len(in_key):
                    break
                if hold.entry_id not in chosen_ids:
                    chosen.append(hold)
                    result[hold.entry_id] = _authorization_for(hold)
            identities[key] = chosen
        return result, problems, identities

    # -- refresh ----------------------------------------------------------

    def refresh(self) -> int:
        """Catch this view up with the other writers of its ledger.

        A read-only manager is a snapshot of the database at the moment it was
        opened. This reads everything committed since — entries, and any open
        authorizations — in one consistent read, verifies the new entries
        against the head this view already verified (hash links, hashes,
        balances and hold pairing, exactly as a full open would), and applies
        them: balances, topology and breaker state all move forward.

        A writable manager over a shared ledger (:meth:`open_postgres`) is one
        of several writers, and does the same. It already does it, under the
        writer lock, before every mutation; call this for current *reads*. If
        its last write did not commit, it re-reads the whole ledger instead.

        A writable manager over a single-writer store is the only writer, so it
        is always current; for it, and for a manager with no store, this is a
        no-op.

        All or nothing: every new entry and cache row is verified against a
        staged copy of this view, and the view changes only once all of it
        checks out.

        :returns: How many new entries were applied.
        :raises LedgerIntegrityError: If the ledger was rewritten under this
            view, or anything new fails verification. The view keeps serving
            exactly what it last verified, and every later refresh (and, for a
            writer, every later write) fails the same way: a view that cannot
            follow the chain never claims to.
        """
        store = self._store
        if store is None or (not store.read_only and self._shared is None):
            return 0
        with self._lock:
            self._require_following()
            if self._shared is not None:
                if self._writing:
                    # Inside this governor's own mutation, or a transaction it
                    # joined: it caught up when that began, and what it has
                    # written since is not committed, so the ledger would look
                    # shorter than memory. There is nothing to follow yet.
                    return 0
                before = len(self._ledger)
                self._follow(self._shared)
                return max(0, len(self._ledger) - before)
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

    def _require_following(self) -> None:
        """Refuse to act on a view that could not follow its ledger. Lock held."""
        if self._unusable is not None:
            kind = "read-only view" if self._shared is None else "governor"
            raise LedgerIntegrityError(
                f"this {kind} stopped following the ledger: {self._unusable}"
            )

    _BATCH: Final = 256
    """The most mutations one unit of work runs."""

    def _submit(self, work: Callable[[], _R], key: str | None = None) -> _R:
        """Run ``work``, a mutation, in a unit of work it may share.

        On a shared ledger every mutation takes the fleet's writer lock,
        catches up and commits; on SQLite every one commits and syncs the
        file. Callers of one governor that arrive together share that: each
        queues its work and takes this governor's lock, and the first to get
        it runs everything queued, in order, in one unit of work: one lock,
        one catch-up, one commit. Each caller's own failure is its own (a
        breaker trip recorded on the way still commits); a commit that fails
        fails every mutation it carried, and the governor re-reads the
        ledger. No result is returned before the unit of work commits.

        A caller that already holds this governor's lock (``ledger.lock``,
        around a check and the act it decides) runs its work there and then,
        alone: others' work never runs inside its critical section.
        """
        owned = getattr(self._lock, "_is_owned", None)
        if not self._grouping or owned is None or owned():
            return work()
        request = _Request(work, key)
        with self._queue_lock:
            self._queue.append(request)
            led = self._leading
            self._leading = True
        if led:
            # One leader at a time. The others wait, each to be woken alone
            # (never queueing on the governor's lock): when their work is
            # settled, or when the lead is handed to them.
            request.wake.acquire()
            if request.settled:
                result: _R = request.outcome()
                return result
        try:
            with self._lock:
                while not request.settled:
                    self._lead()
        finally:
            with self._queue_lock:
                successor = self._queue[0] if self._queue else None
                self._leading = successor is not None
            if successor is not None:
                successor.wake.release()  # the oldest caller still queued leads next
        # A checkpoint come due, now that the units' callers have their
        # results and the next unit is free to begin.
        self._after_mutation()
        result = request.outcome()
        return result

    def _lead(self) -> None:
        """Run what is queued, in one unit of work. Lock held.

        The queue is drained once the unit of work holds the fleet's writer
        lock, and again until it is empty: every caller that queued while the
        lock was awaited rides along."""
        batch: list[_Request] = []
        unit: Any = None
        try:
            with self._mutating(then=False), self._store_unit() as unit:
                while len(batch) < self._BATCH:
                    with self._queue_lock:
                        room = self._BATCH - len(batch)
                        taken, self._queue = self._queue[:room], self._queue[room:]
                    if not taken:
                        break
                    batch.extend(taken)
                    self._look_up_calls([r.key for r in taken if r.key is not None])
                    for request in taken:
                        try:
                            request.value = request.work()
                        except Exception as exc:  # its own: the others go on
                            request.error = exc
        except BaseException as exc:
            # The unit of work did not commit, or never began: nothing it
            # wrote is durable, and nothing it returned stands. Work that
            # never ran because it could not begin fails the same way.
            self._roll_back(len(self._ledger), unit)
            if not batch:
                with self._queue_lock:
                    batch, self._queue = self._queue[: self._BATCH], self._queue[self._BATCH :]
            for request in batch:
                if request.error is None:
                    request.value, request.error = None, exc
        finally:
            if self._metrics is not None and batch:
                self._metrics.record("agentgov.unit.size", len(batch))
            for request in batch:
                request.settled = True
                request.wake.release()

    @contextmanager
    def _mutating(self, *, then: bool = True) -> Iterator[None]:
        """Hold this manager's lock for a mutation — and, on a shared ledger,
        the fleet's writer lock too, with this view caught up under it.

        Over a single-writer store this is the mutex and nothing else: this
        manager's memory is the ledger. Over a shared one it is not, so the
        writer lock is taken first, everything other governors committed since
        is read and verified, and only then does the mutation check a balance or
        a breaker and build its entries. The lock is held until its writes
        commit, so no other governor can append between the check and the
        write. A nested mutation (``spend`` is ``authorize`` then ``capture``)
        joins the session it is already in.

        A session that wrote and then did not commit may have left memory ahead
        of the database, so the next mutation re-reads the ledger in full. It
        does so before taking the writer lock, from a snapshot, the way a
        governor opens; the lock is then held only to catch up from it.

        :param then: Do the work an outermost mutation makes due (a
            checkpoint) on the way out. A unit of work shared by queued
            callers does it once their results are out, and the lock free.
        """
        with self._lock:
            if self._depth:
                yield
                return
            self._depth += 1
            try:
                shared = self._shared
                if shared is None or self._writing:
                    if self._store is not None and not self._store.read_only:
                        self._require_following()
                    yield
                else:
                    self._require_following()
                    if self._dirty:
                        self._follow(shared)
                    elif self._contended:
                        # Others are writing: verify what they wrote before
                        # taking the fleet's lock, so it is held only for
                        # what they write meanwhile.
                        self._catch_up_ahead(shared)
                    session: WriterSession | None = None
                    self._writing = True
                    metrics = self._metrics
                    asked = time.perf_counter()
                    granted = asked
                    try:
                        with shared.writer(**self._reading_ahead(shared)) as session:
                            granted = time.perf_counter()
                            self._unit_session = session
                            self._follow(shared)
                            yield
                    finally:
                        self._writing = False
                        self._unit_session = None
                        if metrics is not None and session is not None:
                            metrics.record("agentgov.lock.wait", granted - asked)
                            metrics.record("agentgov.lock.hold", time.perf_counter() - granted)
                        if session is not None and session.wrote and not session.committed:
                            self._dirty = True
                            self._recover(shared)
            except StorageError:
                if self._metrics is not None and self._depth == 1:
                    self._metrics.add("agentgov.store.errors")
                raise
            finally:
                self._depth -= 1
                if not self._depth:
                    self._unit_calls.clear()
                    self._key_cache.clear()
        if then:
            self._after_mutation()

    def _catch_up_ahead(self, store: SharedStore) -> None:
        """Catch up from a snapshot, without the writer lock. Lock held."""
        try:
            self._catch_up(store)
        except LedgerIntegrityError as exc:
            self._unusable = str(exc)
            raise

    def _recover(self, store: SharedStore) -> None:
        """A session wrote and did not commit, so its writes are in this view
        and not in the ledger. Re-read the ledger now, still under the lock,
        so no reader is served what never committed; when it cannot be read,
        the next mutation tries again first. Lock held."""
        try:
            self._reload(store)
        except Exception:
            logger.warning(
                "could not re-read the ledger after a write that did not commit; the next "
                "mutation will",
                exc_info=True,
            )
        else:
            self._dirty = False

    def _reading_ahead(self, store: SharedStore) -> dict[str, int]:
        """What a store that reads ahead should read with the writer lock, for
        the catch-up after it: everything after this view. Not for a ledger a
        pre-0.1.2 writer still writes, whose catch-up reads authorization
        rows too. Lock held."""
        if not getattr(store, "prefetches", False):
            return {}
        if (self._state.saw_v1 and not self._state.saw_v2) or not _holds_snapshots(store):
            return {}
        return {"after_sequence": len(self._ledger), "after_control_row": self._control_high_water}

    def _after_mutation(self) -> None:
        """Work an outermost mutation makes due, done once it has committed and
        its session has ended: a checkpoint, when the chain has grown far
        enough past the last one. A failure there is logged, never raised:
        the mutation itself is durable, and the next one tries again."""
        if self._metrics is not None:
            with self._lock:
                held, lag = len(self._open_auths), self._unlocked_checkpoint_lag()
            self._metrics.set("agentgov.holds.open", held)
            self._metrics.set("agentgov.checkpoint.lag", lag)
        every = self._policy.checkpoint_every
        store = self._store
        if every <= 0 or store is None or store.read_only or not hasattr(store, "put_snapshot"):
            return
        with self._lock:
            state = self._state
            last = state.last_checkpoint[0] if state.last_checkpoint is not None else 0
            if self._checkpointing or self._depth or state.length - last < every:
                return
            if time.monotonic() < self._checkpoint_retry_at:
                return  # backing off after a failure: a signer may be down
            self._checkpointing = True
        try:
            self.checkpoint()
        except Exception:
            # Writes never wait on a checkpoint's signer: after a failure the
            # next tries are spaced out, 1 s doubling to a minute, and until
            # one succeeds the chain grows past its last checkpoint, which
            # checkpoint_lag() shows.
            backoff = min(max(1.0, self._checkpoint_backoff * 2), 60.0)
            self._checkpoint_backoff = backoff
            self._checkpoint_retry_at = time.monotonic() + backoff
            logger.warning(
                "an automatic checkpoint failed; the ledger is unaffected, and the next try "
                "is in %.0f s",
                backoff,
                exc_info=True,
            )
        else:
            self._checkpoint_backoff = 0.0
            self._checkpoint_retry_at = 0.0
        finally:
            self._checkpointing = False

    def checkpoint_lag(self) -> int:
        """How many entries the chain holds past its newest checkpoint, in this
        view: about :attr:`GovernancePolicy.checkpoint_every` at most while
        checkpoints succeed. Growing past that, they are failing (a signer
        that cannot be reached, say), and an open replays more."""
        with self._lock:
            return self._unlocked_checkpoint_lag()

    def _unlocked_checkpoint_lag(self) -> int:
        state = self._state
        last = state.last_checkpoint[0] if state.last_checkpoint is not None else 0
        return state.length - last

    def checkpoint(self) -> int:
        """Checkpoint the chain state as of this governor's view.

        Stores the canonical snapshot of the state, outside any writer lock
        (the state as of a sequence never changes, so the write conflicts with
        nothing), then appends a zero-value CHECKPOINT entry that commits to
        it by digest. A governor opens from the newest checkpoint, replaying
        only the entries after it. Done automatically every
        :attr:`GovernancePolicy.checkpoint_every` entries.

        :returns: The sequence the checkpoint is of; the existing one's when
            nothing was written since.
        :raises TypeError: If this governor has no store that holds snapshots.
        :raises ReadOnlyLedgerError: On a read-only view.
        :raises ValueError: If the ledger is empty.
        """
        from agentgov.storage import Snapshot

        store: Any = self._store
        if store is None or not hasattr(store, "put_snapshot"):
            raise TypeError("only a governor over a store that holds snapshots can checkpoint")
        if store.read_only:
            raise ReadOnlyLedgerError("checkpoint the ledger")
        if self._shared is not None:
            self.refresh()  # a view left dirty re-reads first: never snapshot unverified state
        with self._lock:
            self._require_following()
            state = self._state
            if not state.length:
                raise ValueError("an empty ledger has nothing to checkpoint")
            last = state.last_checkpoint
            if last is not None and last[0] >= state.length - 1:
                return last[0]  # nothing since but the checkpoint entry itself
            sequence = state.length
            body = _encode_snapshot(state)
            signed = state.copy() if self._signing is not None else None
        digest = _snapshot_digest(body)
        statement = None
        if signed is not None and self._signing is not None:
            # Signed outside every lock: a key service may take its time.
            first = self._ledger.entry(1)
            assert first is not None
            statement = self._signing.statement(first.entry_hash, signed, digest, datetime.now(UTC))
        store.put_snapshot(
            Snapshot(sequence=sequence, digest=digest, body=body, signature=statement)
        )
        with self._mutating():
            last = self._state.last_checkpoint
            if last is not None and last[0] >= sequence:
                return last[0]  # another governor checkpointed as far, meanwhile
            pending = self._ledger._begin()
            pending.post(
                [
                    LedgerLine(
                        entry_type=EntryType.CHECKPOINT,
                        direction=Direction.NONE,
                        scope_id="",
                        amount=ZERO,
                        memo=f"agentgov-checkpoint v1 seq={sequence} sha256={digest}",
                    )
                ]
            )
            self._commit(pending)
        return sequence

    def publish_checkpoint(self, witnesses: Sequence[Any]) -> Any:
        """Have witnesses cosign the ledger's newest checkpoint.

        The checkpoint is published as an ARC1 checkpoint of the Merkle tree
        of the ledger's entries (§4.3 of the ledger format) up to it, signed by
        the checkpoint signer, under the log id
        ``agentgov-ledger:<hash of entry 1>``; each witness checks it extends
        what it cosigned before, so a rewritten history cannot be witnessed.
        Witnesses need the signer's key for that log id. The consistency
        proofs are computed from every entry hash up to the checkpoint, so
        this costs time in proportion to the ledger: run it from a periodic
        job, not on the write path.

        :returns: The ARC1 checkpoint the witnesses were asked to cosign.
        :raises ValueError: Without a checkpoint signer, or a checkpoint.
        :raises WitnessError: If a witness refuses or fails, naming each; the
            others are still asked.
        """
        from agentgov.exceptions import WitnessError
        from agentgov.receipts.merkle import MerkleTree, leaf_hash
        from agentgov.receipts.schema import Checkpoint

        signing = self._signing
        if signing is None or signing.signer is None:
            raise ValueError(
                "publishing a checkpoint needs a checkpoint signer (CheckpointSigning)"
            )
        last = self._state.last_checkpoint
        if last is None:
            raise ValueError("the ledger has no checkpoint to publish")
        sequence = last[0]
        first = self._ledger.entry(1)
        assert first is not None
        tree = MerkleTree(
            leaf_hash(bytes.fromhex(entry.entry_hash))
            for entry in self._ledger.iter_entries(until=sequence)
        )
        checkpoint = Checkpoint(
            log_id=f"agentgov-ledger:{first.entry_hash}",
            tree_size=sequence,
            root_hash=tree.root().hex(),
            issued_at=datetime.now(UTC),
        ).sign(signing.signer)
        refusals: list[str] = []
        for witness in witnesses:
            try:
                seen = witness.latest(checkpoint.log_id)
                old = seen.tree_size if seen is not None else 0
                proof = tree.consistency_proof(old, sequence) if old <= sequence else []
                witness.cosign(checkpoint, proof)
            except (WitnessError, OSError) as exc:
                refusals.append(f"witness {witness.witness_id!r}: {exc}")
        if refusals:
            raise WitnessError(
                f"ledger checkpoint {sequence} was not cosigned by {len(refusals)} of "
                f"{len(witnesses)} witnesses; " + "; ".join(refusals)
            )
        return checkpoint

    @contextmanager
    def transaction(self) -> Iterator[Transaction]:
        """A unit of work the caller holds: current, atomic, one commit.

        Inside the block, reads are current: on a shared ledger, the fleet's
        writer lock is held and this view caught up under it, so no governor
        writes between a check and the act it decides. Every mutation made
        inside joins one commit, made when the block ends::

            with gov.transaction() as txn:
                if txn.available("researcher") >= cost:
                    hold = txn.authorize("researcher", cost)

        If the block raises, nothing it did is written: the store's
        transaction rolls back and this view is rebuilt as it was. A breaker
        trip recorded on the way (an overdraft attempt, a runaway loop) is the
        breaker's, not the block's: it is then written on its own.

        Other callers of this governor wait while the block runs, and on a
        shared ledger every governor's writes wait too: keep it short, with no
        call to anything slow inside. The governor's other methods may be
        called inside it, from the same thread; they join it.

        :raises ReadOnlyLedgerError: On a read-only view.
        :raises RuntimeError: Inside another transaction of this governor, or
            one of its mutations.
        """
        store = self._store
        if store is not None and store.read_only:
            raise ReadOnlyLedgerError("open a transaction")
        with self._lock:
            if self._depth or self._transaction is not None:
                raise RuntimeError(
                    "a transaction does not nest: not in another, nor in a mutation of this "
                    "governor"
                )
            txn = Transaction(self)
            self._transaction = txn
            mark = len(self._ledger)
            unit: Any = None
            try:
                with self._mutating(), self._store_unit() as unit:
                    try:
                        yield txn
                    except BaseException:
                        # The block failed: nothing it did is written.
                        if unit is not None:
                            unit.abandon()
                        if self._unit_session is not None:
                            self._unit_session.abandon()
                        raise
            except BaseException:
                self._transaction = None
                txn._open = False
                self._roll_back(mark, unit)
                self._retrip(txn._trips)
                raise
            finally:
                self._transaction = None
                txn._open = False

    def _store_unit(self) -> AbstractContextManager[Any]:
        """One store transaction for a whole :meth:`transaction`, from a
        single-writer store that can defer its commits (SQLite). A shared
        store's writer session is one already; a ledger with no store has
        nothing to defer."""
        store = self._store
        if store is None or self._shared is not None or not hasattr(store, "unit"):
            return nullcontext(None)
        unit: AbstractContextManager[Any] = store.unit()
        return unit

    def _roll_back(self, mark: int, unit: Any) -> None:
        """Rebuild this view after a transaction that did not commit. Lock held.

        A shared ledger's view was re-read already, when the writer session
        that wrote and did not commit ended. A single-writer store's is read
        again; a ledger with no store replays what it keeps, to ``mark``."""
        store = self._store
        if store is None:
            if len(self._ledger) > mark:
                self._ledger._rewind(mark)
            return
        if unit is not None and unit.wrote and not unit.committed:
            try:
                self._reload(store)
            except Exception as exc:
                self._unusable = (
                    f"a transaction did not commit, and the ledger could not be read again "
                    f"after it: {exc}"
                )
                logger.warning("could not re-read the ledger after a rolled-back transaction")

    def _retrip(self, trips: Sequence[tuple[str, str]]) -> None:
        """Write the breaker trips a transaction that did not commit had
        recorded, each in its own unit of work. A failure is logged: the
        transaction's own error is the one raised."""
        for scope_id, reason in trips:
            try:
                with self._mutating():
                    self._trip(scope_id, reason)
            except Exception:
                logger.warning(
                    "could not record the breaker trip of %r after the transaction that "
                    "recorded it rolled back",
                    scope_id,
                    exc_info=True,
                )

    @contextmanager
    def joined(self, connection: object) -> Iterator[JoinedTransaction]:
        """Join a transaction the caller owns, to claim what it owes the ledger.

        For a caller whose own writes live in the same PostgreSQL database as
        the ledger (an escrow committing a plan's effects, say) and must be
        paid for exactly when they become durable. Place the hold first, in
        this governor's own transaction; open the caller's transaction; then::

            hold = governor.authorize(scope, cost)
            ...                                   # the caller's own writes
            with governor.joined(conn) as txn:
                if governor.is_halted(scope):     # current, and stays so
                    ...                           # roll back
                claim = txn.claim(scope, cost, memo=digest, hold=hold)
                conn.execute("COMMIT")
            governor.redeem(claim)                # books it into the chain

        On entry the writer lock is taken *inside* ``connection``'s
        transaction, so no governor anywhere can write the ledger (trip a
        breaker, say) until the caller commits or rolls back, and this governor
        catches up, on its own connection, with everything already committed.
        The block writes nothing to the chain: only
        :meth:`JoinedTransaction.claim`, a row in the caller's transaction
        that reads nothing of the chain. So a caller whose snapshot is older
        than the ledger (``REPEATABLE READ``) conflicts with nothing, however
        busy the ledger is. Commit, or roll back, inside the block.

        A committed claim is owed until :meth:`redeem` books it; any governor
        may, and a restarted one should (see :meth:`pending_claims`).

        :param connection: A ``psycopg`` connection with an open transaction,
            whose role was granted joined writes
            (:meth:`agentgov.postgres.PostgresStore.grant_join`).
        :raises TypeError: If this governor's store cannot join a transaction.
        :raises agentgov.exceptions.LedgerConflictError: If the caller's
            transaction did not get the writer lock within its own
            ``lock_timeout``. Nothing was written.
        """
        store = self._joinable()
        with self._lock:
            if self._writing:
                raise RuntimeError("a governor cannot join a transaction inside its own mutation")
            self._require_following()
            if self._dirty:
                # Re-read before the caller's transaction holds the writer
                # lock: the re-read takes it too, on this governor's own
                # connection, and would wait on the caller forever.
                self._follow(store)
            self._writing = True
            try:
                with store.join(connection):
                    self._follow(store)
                    yield JoinedTransaction(self, store)
            finally:
                self._writing = False

    def pending_claims(self) -> tuple[SettlementClaim, ...]:
        """Every committed claim not yet booked into the chain, oldest first.

        Read as committed now, on a writer or a read-only view alike: a claim
        is owed from the moment the transaction that made it commits.

        :raises TypeError: If this governor's store holds no claims.
        """
        from agentgov.storage import JoinableStore

        store = self._store
        if not isinstance(store, JoinableStore):
            raise TypeError("only a ledger shared through PostgreSQL holds settlement claims")
        return store.pending_claims()

    def redeem(self, claim: SettlementClaim | None = None) -> tuple[LedgerEntry, ...]:
        """Book committed settlement claims into the chain: ``claim``, or all.

        Each claim becomes, in one unit of work that also removes it from the
        pending claims: the release of its hold and the spend that settles
        against it, or, when the hold is no longer open (an operator voided
        it), a spend on its own; a zero claim becomes a zero-value ``ANCHOR``.
        The spend is booked whatever the scope's state: what it pays for has
        already happened. An overdraw trips the breaker, as a capture's does,
        and is recorded rather than raised.

        Idempotent and safe to race: under the writer lock, a claim another
        governor has booked is gone, and booking one twice is refused by the
        store.

        :returns: The settling entry for each claim booked now, in claim
            order. A claim already booked yields nothing.
        :raises TypeError: If this governor's store holds no claims.
        """
        store = self._joinable()
        with self._mutating():
            pending = store.pending_claims()
            if claim is not None:
                pending = tuple(c for c in pending if c.claim_id == claim.claim_id)
            return tuple(self._redeem_locked(c) for c in pending)

    def _redeem_locked(self, claim: SettlementClaim) -> LedgerEntry:
        """Book one claim. Writer lock held, view caught up."""
        scope_id = claim.scope_id
        self._require_node(scope_id)
        hold = self._open_auths.get(claim.hold_id) if claim.hold_id is not None else None
        pending = self._ledger._begin()
        if claim.amount == ZERO and hold is None:
            (settling,) = pending.post(
                [LedgerLine(EntryType.ANCHOR, Direction.NONE, scope_id, ZERO, memo=claim.memo)]
            )
        else:
            lines: list[LedgerLine] = []
            ref = None
            if hold is not None:
                ref = hold.entry.entry_id
                lines.append(
                    LedgerLine(
                        EntryType.HOLD_VOID,
                        Direction.CREDIT,
                        scope_id,
                        hold.amount,
                        memo="authorization captured by settlement claim",
                        ref=ref,
                    )
                )
            if claim.amount > ZERO:
                lines.append(
                    LedgerLine(
                        EntryType.SPEND,
                        Direction.DEBIT,
                        scope_id,
                        claim.amount,
                        memo=claim.memo,
                        ref=ref,
                    )
                )
            *_, settling = pending.post(lines)
            if settling.balance_after < ZERO:
                self._stage_trip(
                    pending,
                    scope_id,
                    f"settled claim {claim.amount} overdrew the scope by "
                    f"{settling.balance_after.copy_negate()}",
                )
            elif hold is not None and self._exhausted(pending, scope_id):
                self._stage_trip(pending, scope_id, "spend envelope exhausted")
        pending.batch.redeemed.append(claim.claim_id)
        self._commit(pending)
        return settling

    def _joinable(self) -> JoinableStore:
        from agentgov.storage import JoinableStore

        store = self._shared
        if not isinstance(store, JoinableStore):
            raise TypeError(
                "only a writable governor over a store that can join a transaction "
                "(BudgetManager.open_postgres) can join one or hold settlement claims"
            )
        return store

    def _follow(self, store: SharedStore) -> None:
        """Bring this writer's view up to the shared ledger's head. Lock held.

        A view whose length and head hash match the store's is current, since
        the head hash commits to every entry before it; that is the common case
        and costs one query. Otherwise the new entries are verified and applied
        exactly as :meth:`refresh` does for a reader. A view left dirty by a
        session that did not commit is rebuilt from a full, verified read.

        :raises LedgerIntegrityError: If the ledger cannot be followed. The
            governor then refuses every later write.
        """
        try:
            if self._dirty:
                self._reload(store)
                self._dirty = False
                return
            length, head = store.head()
            if length == len(self._ledger) and head == self._ledger.head_hash:
                self._contended = False
                return
            self._contended = self._catch_up(store) > 0
        except LedgerIntegrityError as exc:
            self._unusable = str(exc)
            raise

    def _catch_up(self, store: PersistenceStore) -> int:
        ledger = self._ledger
        before = len(ledger)
        # A pre-0.1.2 writer still writing pairs releases by scope and amount,
        # and only the authorization rows name which hold it released; every
        # newer entry names its own, so then the rows are not read at all.
        legacy_live = (self._state.saw_v1 and not self._state.saw_v2) or not _holds_snapshots(store)
        if _holds_snapshots(store):
            delta = store.snapshot(
                after_sequence=before,
                after_control_row=self._control_high_water,
                authorizations=legacy_live,
            )
        else:  # a store written before checkpoints existed: rows, and the old call
            delta = store.snapshot(
                after_sequence=before, after_control_row=self._control_high_water
            )
        if delta.schema_version != self._schema_version:
            # The writer upgraded the database under this view. Start over
            # from a full, verified read rather than patching across it.
            self._reload(store)
            return len(ledger) - before
        if before and delta.anchor_hash != ledger.head_hash:
            self._refuse_moved_chain(store, before)
        if delta.legacy_control_events and self._state.saw_v2:
            raise LedgerIntegrityError(
                "control_events gained rows outside the chain after the ledger was sealed"
            )

        # Stage: verify everything in a view over the live state, by the same
        # rules every write and replay follows. Nothing this manager serves
        # changes until all of it has checked out.
        view = _Overlay(
            self._state,
            resolve=ledger._resolver_with(delta.entries),
            refunds=ledger._refund_lookup(),
        )
        for entry in delta.entries:
            view.apply(entry)
        view.end_transaction()
        for event in delta.legacy_control_events:
            view.apply_legacy_event(event)
        if legacy_live:
            auths, problems, identities = self._reconcile_authorizations(
                delta.authorizations,
                self._hold_index(extra=delta.entries),
                repairing=False,
                state=view,
            )
            if problems:
                raise LedgerIntegrityError(problems[0])

        # Publish. Nothing below can fail.
        view.merge()
        if ledger._entries is not None:
            ledger._entries.extend(delta.entries)
        if legacy_live:
            self._adopt_authorizations(auths, identities)
        else:
            ledger._follow_holds(view)
        self._control_high_water = delta.control_high_water
        self._remember(delta.entries)
        if self._metrics is not None:
            self._metrics.record("agentgov.catch_up.entries", len(delta.entries))
        return len(delta.entries)

    def _remember(self, entries: Sequence[LedgerEntry]) -> None:
        """Note entries this view now holds: each one's hash, among the newest
        kept, and, for the fleet-wide velocity window, each hold. Lock held."""
        recent = self._recent
        fleet = self._policy.fleet_velocity
        for entry in entries:
            recent.append((entry.sequence, entry.entry_hash))
            if fleet and entry.entry_type is EntryType.HOLD:
                self._fleet_holds.setdefault(entry.scope_id, deque()).append(entry.timestamp)

    def _remember_head(self) -> None:
        """Start the newest hashes over from this view's head. Lock held."""
        self._recent.clear()
        if len(self._ledger):
            self._recent.append((len(self._ledger), self._ledger.head_hash))

    def _refuse_moved_chain(self, store: PersistenceStore, verified: int) -> NoReturn:
        """The ledger no longer holds, at ``verified``, the head this view
        verified there. Say whether it was cut back to a prefix of what was
        verified (a rollback: a failover, say) or rewritten."""
        length: int | None = None
        try:
            length, head = store.head()  # type: ignore[attr-defined]
        except Exception:
            length = None
        if length is not None and 0 < length < verified:
            known = next((h for sequence, h in self._recent if sequence == length), None)
            if known is None or known == head:
                raise LedgerRollbackError(verified, length, confirmed=known is not None)
        raise LedgerIntegrityError(
            f"the ledger was rewritten under this reader: entry {verified} no longer carries "
            f"the head this view verified"
        )

    def _hold_index(self, extra: Sequence[LedgerEntry] = ()) -> _HoldIndex:
        """Every HOLD entry by id, and which were released, for matching
        authorization rows that name no open hold: by index over a store,
        from memory otherwise; ``extra`` are entries not yet in the view."""
        ledger = self._ledger
        if ledger._entries is None and self._store is not None:
            store: Any = self._store
            extras = {e.entry_id: e for e in extra if e.entry_type is EntryType.HOLD}
            released = {e.ref for e in extra if e.entry_type is EntryType.HOLD_VOID}

            def hold(entry_id: uuid.UUID) -> LedgerEntry | None:
                found = extras.get(entry_id) or store.entry_by_id(entry_id)
                return found if found is not None and found.entry_type is EntryType.HOLD else None

            return _HoldIndex(
                hold=hold, released=lambda hold_id: hold_id in released or store.released(hold_id)
            )
        entries = [*(ledger._entries or ()), *extra]
        return _HoldIndex.over(entries)

    def _reload(self, store: PersistenceStore) -> None:
        """Rebuild this view from a fresh, full, verified read.

        The new view is built and verified on its own, exactly as a fresh open
        would, and adopted whole only once it checks out. A writer keeps its
        velocity windows: they are this process's own count, not the ledger's.
        """
        fresh = BudgetManager(
            policy=self._policy,
            store=store,
            verify=self._verify,
            auditor=False,
            signing=self._signing,
        )
        self._ledger._publish(fresh._ledger._entries, fresh._ledger._state)
        self._ledger._open_auths = fresh._ledger._open_auths
        self._ledger._legacy_auth_ids = fresh._ledger._legacy_auth_ids
        self._schema_version = fresh._schema_version
        self._control_high_water = fresh._control_high_water
        self._remember_head()

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
            return self._ledger._control_events()

    def node(self, scope_id: str) -> BudgetNode:
        """Return the :class:`BudgetNode` for ``scope_id``.

        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            return self._require_node(scope_id)

    def scopes(self) -> tuple[str, ...]:
        """Every registered scope id, in registration order."""
        with self._lock:
            return tuple(self._state.nodes)

    def available(self, scope_id: str, *, fresh: bool = False) -> Decimal:
        """Return ``scope_id``'s spendable balance, net of outstanding holds.

        :param fresh: On a shared ledger, or a read-only view, catch up with
            what other governors committed first. Otherwise the answer is as
            of this view's last write or refresh. Inside :meth:`transaction`
            every read is current.
        :raises UnknownScopeError: If no such scope is registered.
        """
        if fresh:
            self.refresh()
        with self._lock:
            self._require_node(scope_id)
            return self._ledger.balance(scope_id)

    def subtree_available(self, scope_id: str, *, fresh: bool = False) -> Decimal:
        """Return the total spendable balance of ``scope_id`` and everything
        delegated beneath it.

        :param fresh: Catch up first, as for :meth:`available`.
        :raises UnknownScopeError: If no such scope is registered.
        """
        if fresh:
            self.refresh()
        with self._lock:
            total = self._ledger.balance(scope_id)
            for node in self.descendants(scope_id):
                total = _add(total, self._ledger.balance(node.scope_id))
            return total

    def descendants(self, scope_id: str) -> Iterator[BudgetNode]:
        """Yield every node beneath ``scope_id``, breadth-first.

        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            nodes = self._state.nodes
            frontier = deque(self._require_node(scope_id).child_ids)
            order: list[BudgetNode] = []
            while frontier:
                child = nodes[frontier.popleft()]
                order.append(child)
                frontier.extend(child.child_ids)
        yield from order

    def ancestry(self, scope_id: str) -> tuple[str, ...]:
        """Return ``scope_id`` and each ancestor above it, nearest first.

        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            nodes = self._state.nodes
            chain: list[str] = []
            cursor: str | None = self._require_node(scope_id).scope_id
            while cursor is not None:
                chain.append(cursor)
                cursor = nodes[cursor].parent_id
            return tuple(chain)

    def audit_trail(self, scope_id: str | None = None) -> tuple[LedgerEntry, ...]:
        """Return the ledger entries for one scope, or the whole ledger.

        Over a store, the whole ledger is read into one tuple, a cost that
        grows with history: :meth:`iter_audit_trail` reads it a chunk at a
        time, and :meth:`find_entries` reads only what matches, by index.

        :param scope_id: Restrict to this scope, or ``None`` for everything.
        """
        if scope_id is None:
            return self._ledger.entries()
        return self._ledger.entries_for_scope(scope_id)

    def iter_audit_trail(self, scope_id: str | None = None) -> Iterator[LedgerEntry]:
        """:meth:`audit_trail`, a chunk at a time: memory stays bounded."""
        if scope_id is None:
            yield from self._ledger.iter_entries()
        else:
            yield from self._ledger.find_entries(scope_id=scope_id)

    def entry(self, sequence: int) -> LedgerEntry:
        """The entry at ``sequence``.

        :raises IndexError: If this view has no entry there.
        """
        found = self._ledger.entry(sequence)
        if found is None:
            raise IndexError(f"the ledger has no entry {sequence}")
        return found

    def entries(self, *, after: int = 0, limit: int = 1000) -> tuple[LedgerEntry, ...]:
        """At most ``limit`` entries after ``after``, oldest first: history a
        page at a time."""
        if limit < 1:
            raise ValueError(f"limit must be positive, got {limit}")
        return tuple(itertools.islice(self._ledger.iter_entries(after=after), limit))

    def find_entries(
        self,
        *,
        scope_id: str | None = None,
        entry_type: EntryType | None = None,
        memo: str | None = None,
        transaction_id: uuid.UUID | None = None,
        ref: uuid.UUID | None = None,
        after: int = 0,
        limit: int | None = None,
    ) -> tuple[LedgerEntry, ...]:
        """The entries matching every criterion given, oldest first.

        Over a store, ``scope_id`` and ``entry_type`` (with ``memo``) are
        answered by an index, so finding one anchor by its memo, or a scope's
        spends, costs what it finds, not the length of history.
        ``transaction_id`` and ``ref`` are not indexed: they filter what the
        other criteria find, and given alone they scan history. To find what
        settled a hold, give its scope too:
        ``find_entries(scope_id=hold.scope_id, ref=hold.authorization_id)``.
        """
        return self._ledger.find_entries(
            scope_id=scope_id,
            entry_type=entry_type,
            memo=memo,
            transaction_id=transaction_id,
            ref=ref,
            after=after,
            limit=limit,
        )

    # -- topology ---------------------------------------------------------

    @_grouped
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

        with self._mutating():
            if scope_id in self._state.nodes:
                raise DuplicateScopeError(scope_id)
            pending = self._ledger._begin()
            pending.post(
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
            self._commit(pending)
            return self._state.nodes[scope_id]

    @_grouped
    def fund(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """Top up an existing root scope from the external treasury.

        Only roots may be funded; a non-root scope receives money exclusively
        through :meth:`delegate`, which is what keeps the delegation invariant
        meaningful.

        :param scope_id: The root scope to credit.
        :param amount: The amount to add to its envelope.
        :param memo: Free-form audit context.
        :param idempotency_key: Names this call, so a retry of it (after a
            lost answer, say) returns its result and writes nothing; another
            call under the key raises :class:`IdempotencyConflictError`.
        :returns: The committed funding entry.
        :raises UnknownScopeError: If no such scope is registered.
        :raises ValueError: If ``scope_id`` is not a root or ``amount`` is
            not positive.
        """
        credited = _credit(amount)
        if credited <= ZERO:
            raise ValueError(f"funding must be positive, got {credited}")

        with self._mutating():
            call = self._called(
                idempotency_key, "entry", "fund", scope_id=scope_id, amount=credited, memo=memo
            )
            if call is not None and call.replayed is not _UNRECORDED:
                replayed: LedgerEntry = call.replayed
                return replayed
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
            self._commit(pending, call, entry)
            return self._answered(call, entry)

    @_grouped
    def delegate(
        self,
        parent_id: str,
        child_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> BudgetNode:
        """Sub-delegate part of ``parent_id``'s budget to a new child scope.

        The transfer is a balanced pair of ledger lines, so the parent's
        available balance drops by exactly what the child gains. A parent can
        never delegate money it does not hold, at any depth.

        :param parent_id: The delegating scope.
        :param child_id: Identifier for the new sub-agent scope.
        :param amount: The sub-limit to grant.
        :param memo: Free-form audit context.
        :param idempotency_key: Names this call, so a retry of it (after a
            lost answer, say) returns its result and writes nothing; another
            call under the key raises :class:`IdempotencyConflictError`.
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

        with self._mutating():
            call = self._called(
                idempotency_key,
                "node",
                "delegate",
                parent_id=parent_id,
                child_id=child_id,
                amount=granted,
                memo=memo,
            )
            if call is not None and call.replayed is not _UNRECORDED:
                replayed: BudgetNode = call.replayed
                return replayed
            parent = self._require_node(parent_id)
            if child_id in self._state.nodes:
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
            _, credit = pending.post(
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
            self._commit(pending, call, credit)
            return self._answered(call, self._state.nodes[child_id])

    @_grouped
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
        with self._mutating():
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
            pending = self._ledger._begin()
            pending.post(
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
            self._commit(pending)
            return returned

    # -- authorize / capture ---------------------------------------------

    @_grouped
    def authorize(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
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
        :param idempotency_key: Names this call, so a retry of it (after a
            lost answer, say) returns its result and writes nothing; another
            call under the key raises :class:`IdempotencyConflictError`.
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
        hold = self._authorize(scope_id, amount, memo, idempotency_key, trip=True)
        assert hold is not None
        return hold

    @_grouped
    def try_authorize(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> Authorization | None:
        """Place a hold if ``scope_id`` can pay for it; refuse quietly if not.

        :meth:`authorize` without the breaker's answer to an overdraft:
        ``None``, no trip and nothing written when ``amount`` exceeds the
        available balance. The check and the hold are one step, under the
        fleet's writer lock on a shared ledger, so a caller can ask whether
        it can afford a call and hold the funds if so, with no other writer
        between. A halted scope still raises :class:`CircuitOpenError`, and a
        runaway loop still trips, as they do for :meth:`authorize`.

        :param idempotency_key: As for :meth:`authorize`, whose calls it
            shares: under one key, the two are the same call. A refusal
            records nothing, so a retry is decided again.
        :returns: The hold, or ``None`` if the scope cannot pay.
        """
        return self._authorize(scope_id, amount, memo, idempotency_key, trip=False)

    def _authorize(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        memo: str,
        key: str | None,
        *,
        trip: bool,
    ) -> Authorization | None:
        held = _cost(amount)
        if held <= ZERO:
            raise ValueError(f"authorization amount must be positive, got {held}")

        with self._mutating():
            call = self._called(
                key, "authorization", "authorize", scope_id=scope_id, amount=held, memo=memo
            )
            if call is not None and call.replayed is not _UNRECORDED:
                replayed: Authorization = call.replayed
                return replayed
            self._require_node(scope_id)
            self._assert_not_halted(scope_id)
            self._record_velocity(scope_id)

            available = self._ledger.balance(scope_id)
            if held > available:
                if not trip:
                    return None
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
            self._commit(pending, call, entry)
            return self._answered(call, self._open_auths[entry.entry_id])

    @_grouped
    def capture(
        self,
        authorization: Authorization,
        actual_cost: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
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
        :param idempotency_key: Names this call, so a retry of it (after a
            lost answer, say) returns its result and writes nothing; another
            call under the key raises :class:`IdempotencyConflictError`. A capture that overdrew
            raised once, when it was made; its retry returns the spend.
        :returns: The committed :attr:`EntryType.SPEND` entry.
        :raises DoubleSpendError: If this authorization was already settled.
        :raises DenialOfWalletError: If the settled cost overdrew the scope.
        :raises ValueError: If ``actual_cost`` is negative.
        """
        settled = _cost(actual_cost)
        if settled < ZERO:
            raise ValueError(f"actual cost must not be negative, got {settled}")

        with self._mutating():
            call = self._called(
                idempotency_key,
                "entry",
                "capture",
                authorization_id=authorization.authorization_id,
                actual_cost=settled,
                memo=memo,
            )
            if call is not None and call.replayed is not _UNRECORDED:
                replayed: LedgerEntry = call.replayed
                return replayed
            return self._capture(authorization, settled, memo, call)

    def _capture(
        self, authorization: Authorization, settled: Decimal, memo: str, call: _Call | None
    ) -> LedgerEntry:
        """Settle ``authorization`` at ``settled``. Inside a mutation."""
        with self._mutating():
            self._require_open_authorization(authorization, "was already settled")

            if settled == ZERO:
                # Nothing was billed; the hold is simply lifted.
                return self._void_locked(authorization, memo or "captured at zero cost", call)

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

            overdraft = (
                spend_entry.balance_after.copy_negate()
                if spend_entry.balance_after < ZERO
                else None
            )
            if overdraft is not None:
                self._stage_trip(
                    pending,
                    scope_id,
                    f"settled cost {settled} overran authorization "
                    f"{authorization.amount}; overdrawn by {overdraft}",
                )
            elif self._exhausted(pending, scope_id):
                self._stage_trip(pending, scope_id, "spend envelope exhausted")

            # Only once the settlement is durable does the hold leave the open
            # set: a failed commit leaves it open for a retry or an operator to
            # reconcile, instead of orphaning it.
            self._commit(pending, call, spend_entry)
            self._answered(call, spend_entry)

            if overdraft is not None:
                raise DenialOfWalletError(
                    settled,
                    _subtract(settled, overdraft),
                    scope_id,
                    overspent=True,
                )
            return spend_entry

    @_grouped
    def void(
        self,
        authorization: Authorization,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """Cancel an authorization without spending, returning the held funds.

        :param authorization: The hold to cancel.
        :param memo: Free-form audit context.
        :param idempotency_key: Names this call, so a retry of it (after a
            lost answer, say) returns its result and writes nothing; another
            call under the key raises :class:`IdempotencyConflictError`.
        :returns: The committed :attr:`EntryType.HOLD_VOID` entry.
        :raises DoubleSpendError: If this authorization was already settled.
        """
        with self._mutating():
            call = self._called(
                idempotency_key,
                "entry",
                "void",
                authorization_id=authorization.authorization_id,
                memo=memo,
            )
            if call is not None and call.replayed is not _UNRECORDED:
                replayed: LedgerEntry = call.replayed
                return replayed
            self._require_open_authorization(authorization, "was already settled")
            return self._void_locked(authorization, memo or "authorization voided", call)

    @_grouped
    def spend(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """Authorize and capture a known cost in one step.

        Convenience for costs known before the call (a fixed per-call tool
        fee, say). When the cost is only known afterwards — as with token
        billing — use :meth:`authorize` and :meth:`capture` so the funds are
        encumbered while the call is in flight.

        :param scope_id: The spending scope.
        :param amount: The exact cost.
        :param memo: Free-form audit context.
        :param idempotency_key: Names this call, so a retry of it (after a
            lost answer, say) returns its result and writes nothing; another
            call under the key raises :class:`IdempotencyConflictError`.
        :returns: The committed spend entry.
        """
        cost = _cost(amount)
        with self._mutating():
            call = self._called(
                idempotency_key, "entry", "spend", scope_id=scope_id, amount=cost, memo=memo
            )
            if call is not None and call.replayed is not _UNRECORDED:
                replayed: LedgerEntry = call.replayed
                return replayed
            auth = self.authorize(scope_id, cost, memo=memo)
            return self._capture(auth, cost, memo, call)

    @_grouped
    def refund(
        self,
        scope_id: str,
        amount: Decimal | int | str,
        *,
        memo: str = "",
        reverses: LedgerEntry | uuid.UUID | None = None,
        idempotency_key: str | None = None,
    ) -> LedgerEntry:
        """Record a vendor refund of previously settled spend.

        Posts a compensating credit. History is never rewritten: the original
        spend stays in the chain and the refund sits beside it.

        Name the spend the refund returns money for (``reverses``): the
        refund is then bounded by what is left of that spend, across every
        refund that names it, and the chain records which spend it reverses.
        Whether it names one or not, a scope's lifetime refunds can never
        exceed its lifetime spend: a refund larger than that would grant
        spending power its parent never delegated.

        :param scope_id: The scope receiving the credit: the scope that spent.
        :param amount: The refunded amount.
        :param memo: Free-form audit context.
        :param reverses: The SPEND entry (or its ``entry_id``) this refunds.
            Refunds that name no spend are deprecated, and an error in 2.0.
        :param idempotency_key: Names this call, so a retry of it (after a
            lost answer, say) returns its result and writes nothing; another
            call under the key raises :class:`IdempotencyConflictError`.
        :returns: The committed :attr:`EntryType.REVERSAL` entry.
        :raises UnknownScopeError: If no such scope is registered.
        :raises ValueError: If ``amount`` is not positive; if ``reverses`` is
            not a spend of ``scope_id``, or ``amount`` exceeds what is left of
            it; or if ``amount`` exceeds what the scope has spent and not
            already had refunded.
        """
        credited = _credit(amount)
        if credited <= ZERO:
            raise ValueError(f"refund must be positive, got {credited}")
        if reverses is None:
            warnings.warn(
                "a refund that names no spend is deprecated: pass reverses=<the SPEND entry>, "
                "so the refund is bounded by that spend and the chain records which it reverses",
                DeprecationWarning,
                stacklevel=2,
            )

        named = reverses.entry_id if isinstance(reverses, LedgerEntry) else reverses
        with self._mutating():
            call = self._called(
                idempotency_key,
                "entry",
                "refund",
                scope_id=scope_id,
                amount=credited,
                memo=memo,
                reverses=named,
            )
            if call is not None and call.replayed is not _UNRECORDED:
                replayed: LedgerEntry = call.replayed
                return replayed
            self._require_node(scope_id)
            ref: uuid.UUID | None = None
            if named is not None:
                ref = named
                spend = self._ledger._resolve(ref)
                if spend is None or spend.entry_type is not EntryType.SPEND:
                    raise ValueError(f"{ref} is not a spend this ledger holds")
                if spend.scope_id != scope_id:
                    raise ValueError(
                        f"spend {ref} was made by {spend.scope_id!r}, not {scope_id!r}; a refund "
                        f"returns money to the scope that spent it"
                    )
                left = _subtract(spend.amount, self._ledger._refunded_of_spend(ref))
                if credited > left:
                    raise ValueError(
                        f"cannot refund {credited} of spend {ref}: {left} of its "
                        f"{spend.amount} is left to refund"
                    )
            spent = self._state.spent_by(scope_id)
            refunded = self._state.refunded_to(scope_id)
            refundable = _subtract(spent, refunded)
            if credited > refundable:
                raise ValueError(
                    f"cannot refund {credited} to {scope_id!r}: it has spent {spent} and been "
                    f"refunded {refunded}, so at most {refundable} remains refundable; a refund "
                    f"returns money a scope spent and cannot grant more"
                )
            pending = self._ledger._begin()
            (entry,) = pending.post(
                [
                    LedgerLine(
                        entry_type=EntryType.REVERSAL,
                        direction=Direction.CREDIT,
                        scope_id=scope_id,
                        amount=credited,
                        counterparty_id=None,
                        memo=memo or "vendor refund",
                        ref=ref,
                    )
                ]
            )
            self._commit(pending, call, entry)
            return self._answered(call, entry)

    @_grouped
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
        with self._mutating():
            self._require_node(scope_id)
            pending = self._ledger._begin()
            (entry,) = pending.post(
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
            self._commit(pending)
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

    @_grouped
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
            with self._mutating():
                # Re-check under the lock: a settlement may have landed
                # between the survey above and this release — on a shared
                # ledger, by another governor, which the catch-up has read.
                if auth.authorization_id not in self._open_auths:
                    continue
                self._void_locked(auth, note)
                voided.append(auth)
        return tuple(voided)

    # -- circuit breaker --------------------------------------------------

    def is_halted(self, scope_id: str, *, fresh: bool = False) -> bool:
        """Whether ``scope_id`` is halted by its own breaker or an ancestor's.

        :param fresh: Catch up first, as for :meth:`available`.
        :raises UnknownScopeError: If no such scope is registered.
        """
        if fresh:
            self.refresh()
        with self._lock:
            self._require_node(scope_id)
            return self._halted_by(scope_id) is not None

    def authorization(self, authorization_id: uuid.UUID | str) -> Authorization | None:
        """The open authorization with this id: to capture or void a hold
        placed elsewhere (another host, another governor), given its id.

        On a shared ledger, or a read-only view, a hold this view has not
        seen is looked for again after catching up.

        :returns: The hold, or ``None`` if none with this id is open: never
            placed, or already captured or voided.
        :raises ValueError: If ``authorization_id`` is not a UUID.
        """
        wanted = (
            authorization_id
            if isinstance(authorization_id, uuid.UUID)
            else uuid.UUID(authorization_id)
        )
        with self._lock:
            found = self._open_auths.get(wanted)
            if found is not None or self._depth:
                return found
        store = self._store
        if self._shared is None and (store is None or not store.read_only):
            return None
        self.refresh()
        with self._lock:
            return self._open_auths.get(wanted)

    def halted_by(self, scope_id: str) -> str | None:
        """Return the scope whose open breaker halts ``scope_id``, if any.

        :returns: The tripped scope id — possibly ``scope_id`` itself — or
            ``None`` when the subtree is running.
        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._lock:
            self._require_node(scope_id)
            return self._halted_by(scope_id)

    @_grouped
    def trip(self, scope_id: str, reason: str) -> None:
        """Manually trip the breaker for ``scope_id`` and its whole subtree.

        The trip is a zero-value :attr:`EntryType.CIRCUIT_TRIPPED` entry in
        the chain, so it survives a restart and cannot be deleted without
        breaking verification.

        :param scope_id: The scope to halt.
        :param reason: Why it was halted; recorded in the audit trail.
        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._mutating():
            self._require_node(scope_id)
            self._trip(scope_id, reason)

    @_grouped
    def reset(self, scope_id: str) -> None:
        """Clear a tripped breaker so the scope may spend again.

        The breaker latches deliberately: a denial-of-wallet halt must not
        clear itself on a timer, because the loop that caused it usually has
        not stopped. Reset is an explicit operator action and is recorded as a
        :attr:`EntryType.CIRCUIT_RESET` entry.

        :param scope_id: The scope to re-arm.
        :raises UnknownScopeError: If no such scope is registered.
        """
        with self._mutating():
            self._require_node(scope_id)
            if self._state.trip_of(scope_id) is None:
                return
            pending = self._ledger._begin()
            self._stage_control(pending, EntryType.CIRCUIT_RESET, scope_id, "operator reset")
            self._commit(pending)
            velocity = self._velocity.get(scope_id)
            if velocity is not None:
                velocity.call_times.clear()

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
        started = time.perf_counter()
        with self._lock:
            # The tree's own shape first: cheap, and its messages name the
            # exact defect, where a replay could only say the tree differs.
            self._verify_tree()
            self._ledger.verify_conservation()
            self._verify_authorizations()
        # The full replay holds no lock of this manager's: over a store it
        # copies the state, replays from the store and compares, while
        # writers carry on.
        self._ledger.verify_chain()
        if self._metrics is not None:
            self._metrics.record("agentgov.verify.duration", time.perf_counter() - started)

    def _verify_tree(self) -> None:
        """The delegation tree is a tree: parents registered, children listed,
        depths consistent, and no cycles. Lock held."""
        nodes = self._state.nodes
        listed = {
            scope_id: set(node.child_ids) for scope_id, node in nodes.items() if node.child_ids
        }
        rooted: set[str] = set()  # scopes already walked to a root
        for scope_id, node in nodes.items():
            if node.parent_id is None:
                if scope_id not in self._state.roots:
                    raise LedgerIntegrityError("parentless scope is not a root", scope_id)
                continue
            parent = nodes.get(node.parent_id)
            if parent is None:
                raise LedgerIntegrityError(f"parent {node.parent_id!r} is not registered", scope_id)
            if scope_id not in listed.get(node.parent_id, ()):
                raise LedgerIntegrityError(f"not listed as a child of {node.parent_id!r}", scope_id)
            if node.depth != parent.depth + 1:
                raise LedgerIntegrityError(
                    f"depth {node.depth} is inconsistent with parent depth {parent.depth}",
                    scope_id,
                )
            # Walking to a root also proves the graph is acyclic. A walk ends
            # where an earlier one did, so the whole tree is walked once.
            path = {scope_id}
            cursor: str | None = node.parent_id
            while cursor is not None and cursor not in rooted:
                if cursor in path:
                    raise LedgerIntegrityError("delegation cycle detected", scope_id)
                path.add(cursor)
                ancestor = nodes.get(cursor)
                if ancestor is None:
                    raise LedgerIntegrityError(f"ancestor {cursor!r} is not registered", scope_id)
                cursor = ancestor.parent_id
            rooted |= path

    def _verify_authorizations(self) -> None:
        """Every open hold has exactly one authorization, and nothing else does."""
        held = {auth.entry.entry_id for auth in self._open_auths.values()}
        if held != set(self._state.holds):
            raise LedgerIntegrityError("open authorizations disagree with the chain's open holds")

    # -- internals --------------------------------------------------------

    def _commit(
        self, pending: _Pending, call: _Call | None = None, result: LedgerEntry | None = None
    ) -> None:
        """Make a unit of work durable, then visible, here and in the ledger.

        The ledger writes the entries with the cache rows they imply and only
        then merges them; this manager then follows what they opened, closed
        and recorded. With ``call``, the call made under an idempotency key
        is recorded in the same write, its result read back from ``result``.
        Lock held.
        """
        record: IdempotencyRecord | None = None
        if call is not None:
            assert result is not None
            record = IdempotencyRecord(
                key=call.key,
                request=call.request,
                outcome=call.outcome,
                sequence=result.sequence,
                created_at=result.timestamp,
            )
            pending.batch.idempotency.append(record)
        controls = [e for e in pending.entries if e.entry_type in _CONTROL_TYPES]
        self._ledger._commit(pending)
        self._remember(pending.entries)
        if self._metrics is not None and controls:
            trips = sum(e.entry_type is EntryType.CIRCUIT_TRIPPED for e in controls)
            if trips:
                self._metrics.add("agentgov.trips", trips)
        if call is not None:
            call.record = record
        for entry in controls:
            self._log_control(entry)

    # -- idempotency keys -------------------------------------------------

    def _called(
        self, key: str | None, outcome: str, operation: str, **arguments: object
    ) -> _Call | None:
        """The call being made under ``key``, if it has one, with what it
        returned when it was first made, if it was. Inside a mutation.

        :param outcome: What the call returns: ``"authorization"``,
            ``"entry"`` or ``"node"``.
        :raises IdempotencyConflictError: If ``key`` was used for another call.
        :raises ValueError: If ``key`` cannot be an idempotency key.
        """
        if key is None:
            return None
        call = _Call(_require_key(key), _request_text(operation, **arguments), outcome)
        running = self._unit_calls.get(key)
        if running is not None:
            made, result = running
            self._match(call, made)
            call.replayed = result
            return call
        record = self._recorded(key)
        if record is not None:
            self._match(call, record)
            call.replayed = self._result_of(record)
        return call

    @staticmethod
    def _match(call: _Call, record: IdempotencyRecord) -> None:
        if record.request != call.request:
            raise IdempotencyConflictError(call.key, _operation_of(record.request))

    def _answered(self, call: _Call | None, result: _R) -> _R:
        """``result``, as what the call made under its key returned, for a
        retry within the same unit of work. Inside a mutation."""
        if call is not None and call.record is not None:
            self._unit_calls[call.key] = (call.record, result)
        return result

    def _recorded(self, key: str) -> IdempotencyRecord | None:
        """The call recorded under ``key``, if any. Inside a mutation: on a
        shared ledger, under the writer lock, so no other governor is making
        it meanwhile."""
        if key in self._key_cache:
            return self._key_cache[key]
        store = self._store
        if store is None:
            return self._ledger._keys.get(key)
        found = self._recorded_calls(store, [key]).get(key)
        self._key_cache[key] = found
        return found

    def _look_up_calls(self, keys: list[str]) -> None:
        """Read the calls recorded under ``keys``, in one query, for the unit
        of work about to run the calls made under them. Inside a mutation."""
        store = self._store
        wanted = [k for k in dict.fromkeys(keys) if k not in self._unit_calls]
        wanted = [k for k in wanted if k not in self._key_cache]
        if store is None or not wanted:
            return
        found = self._recorded_calls(store, wanted)
        for key in wanted:
            self._key_cache[key] = found.get(key)

    @staticmethod
    def _recorded_calls(store: PersistenceStore, keys: list[str]) -> dict[str, IdempotencyRecord]:
        lookup = getattr(store, "idempotency", None)
        if lookup is None:
            raise StorageError("this ledger's store keeps no record of calls made under a key")
        found: dict[str, IdempotencyRecord] = lookup(keys)
        return found

    def _result_of(self, record: IdempotencyRecord) -> Any:
        """What the call recorded under a key returned, read back from the
        entry its record names, which must be what that call wrote."""
        entry = self._ledger.entry(record.sequence)
        result: Any = None
        if entry is not None:
            if record.outcome == "entry":
                result = entry
            elif record.outcome == "authorization" and entry.entry_type is EntryType.HOLD:
                result = _authorization_for(entry)
            elif record.outcome == "node" and entry.entry_type is EntryType.ALLOCATION:
                result = self._state.nodes.get(entry.scope_id)
        if result is None:
            raise LedgerIntegrityError(
                f"the call recorded under idempotency key {record.key!r} names entry "
                f"{record.sequence} as its {record.outcome}, and this ledger holds no such entry"
            )
        return result

    def _require_node(self, scope_id: str) -> BudgetNode:
        """Return the node for ``scope_id`` or raise. Caller holds the lock."""
        node = self._state.nodes.get(scope_id)
        if node is None:
            raise UnknownScopeError(scope_id)
        return node

    def _halted_by(self, scope_id: str) -> str | None:
        """Nearest tripped scope at or above ``scope_id``. Caller holds the lock."""
        nodes, tripped = self._state.nodes, self._state.tripped
        cursor: str | None = scope_id
        while cursor is not None:
            if cursor in tripped:
                return cursor
            cursor = nodes[cursor].parent_id
        return None

    def _assert_not_halted(self, scope_id: str) -> None:
        """Raise if ``scope_id`` is halted. Caller holds the lock."""
        tripped = self._halted_by(scope_id)
        if tripped is not None:
            raise CircuitOpenError(scope_id, tripped, self._state.tripped[tripped][1])

    def _record_velocity(self, scope_id: str) -> None:
        """Record an authorization and trip on runaway loops. Lock held.

        With :attr:`GovernancePolicy.fleet_velocity`, the count is the holds
        on the scope in the chain within the window, by every governor (this
        view is current: it caught up under the writer lock), and this one."""
        limit = self._policy.max_calls_per_window
        window = self._policy.window_seconds
        if limit <= 0 or window <= 0:
            return
        if self._policy.fleet_velocity:
            held = self._fleet_holds.setdefault(scope_id, deque())
            since = datetime.now(UTC) - timedelta(seconds=window)
            while held and held[0] < since:
                held.popleft()
            count = len(held) + 1
            if count > limit:
                self._trip(
                    scope_id, f"runaway loop: {count} authorizations in {window}s, fleet-wide"
                )
                raise RunawayLoopDetectedError(scope_id, count, window)
            return

        now = time.monotonic()
        times = self._velocity.setdefault(scope_id, _Velocity()).call_times
        times.append(now)
        cutoff = now - window
        while times and times[0] < cutoff:
            times.popleft()

        if len(times) > limit:
            count = len(times)
            self._trip(scope_id, f"runaway loop: {count} authorizations in {window}s")
            raise RunawayLoopDetectedError(scope_id, count, window)

    def _trip(self, scope_id: str, reason: str) -> None:
        """Latch the breaker for ``scope_id`` in its own unit of work. Lock held.

        Inside a transaction, the trip joins its commit; if the transaction
        does not commit, the trip is written on its own afterwards (it is the
        breaker's, not the caller's work)."""
        if self._state.trip_of(scope_id) is not None:
            return
        pending = self._ledger._begin()
        self._stage_trip(pending, scope_id, reason)
        self._commit(pending)
        if self._transaction is not None:
            self._transaction._trips.append((scope_id, reason))

    def _stage_trip(self, pending: _Pending, scope_id: str, reason: str) -> LedgerEntry | None:
        """Add a trip to a unit of work, unless the scope is already latched."""
        if pending.view.trip_of(scope_id) is not None:
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
        return entry

    def _log_control(self, entry: LedgerEntry) -> None:
        audit_log.warning(
            f"{entry.version}|ctrl={entry.entry_type.value}|ts={_iso(entry.timestamp)}"
            f"|scope={_escape(entry.scope_id)}|head={entry.prev_hash[:16]}"
            f"|reason={_escape(entry.memo)}",
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

    def _exhausted(self, pending: _Pending, scope_id: str) -> bool:
        """Whether the work in ``pending`` leaves the scope spent out.

        Only once every hold on the scope has settled, so a transient zero
        caused by an in-flight authorization is not mistaken for exhaustion.
        The count of open holds is kept per scope, so this costs nothing in
        the number of holds elsewhere.
        """
        if not self._policy.trip_on_exhaustion:
            return False
        if pending.balance(scope_id) > ZERO:
            return False
        return pending.view.holds_open_in(scope_id) == 0

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

    def _void_locked(
        self, authorization: Authorization, memo: str, call: _Call | None = None
    ) -> LedgerEntry:
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
        self._commit(pending, call, entry)
        return self._answered(call, entry)


_VERIFY_POLICIES: Final = frozenset({"checkpoint", "full"})
"""How much a governor verifies when it opens: from the newest checkpoint
(the default: the snapshot it names, and every entry after it), or the whole
chain from genesis."""


def _require_scope_id(scope_id: str) -> None:
    if not scope_id:
        raise ValueError("a scope id must not be empty")


def _shared_store(store: PersistenceStore) -> SharedStore | None:
    """``store``, if other governors write it too."""
    from agentgov.storage import SharedStore  # deferred: storage imports this module

    return store if isinstance(store, SharedStore) else None


def _image_head(image: StoreImage) -> tuple[int, str]:
    """The length and head hash of the chain in ``image``."""
    if not image.entries:
        return 0, GENESIS_HASH
    return len(image.entries), image.entries[-1].entry_hash


@dataclass(frozen=True, slots=True)
class _Restored:
    """What a store's image implies, checked against a verified chain."""

    authorizations: dict[uuid.UUID, Authorization]
    identities: dict[_HoldKey, list[LedgerEntry]]
    problems: list[str]
    schema_version: str
    control_high_water: int

    def rebuild(self, store: PersistenceStore, ledger: Ledger) -> None:
        """Replace the store's cache tables with what the chain implies."""
        store.rebuild_caches(
            nodes=tuple(ledger._state.nodes.values()),
            control_events=ledger._chain_control_events(),
            authorizations=tuple(self.authorizations.values()),
        )


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

    Asked only about an authorization row that names no open hold, which is
    an error or pre-0.1.2 history: over a store each question is one indexed
    read; over entries in memory, the index is built on first use.
    """

    __slots__ = ("_hold", "_released")

    def __init__(
        self,
        *,
        hold: Callable[[uuid.UUID], LedgerEntry | None],
        released: Callable[[uuid.UUID], bool],
    ) -> None:
        self._hold = hold
        self._released = released

    @classmethod
    def over(cls, entries: Sequence[LedgerEntry]) -> _HoldIndex:
        holds: dict[uuid.UUID, LedgerEntry] | None = None
        released: set[uuid.UUID] = set()

        def build() -> dict[uuid.UUID, LedgerEntry]:
            nonlocal holds
            if holds is None:
                holds = {}
                for entry in entries:
                    if entry.entry_type is EntryType.HOLD:
                        holds[entry.entry_id] = entry
                    elif entry.entry_type is EntryType.HOLD_VOID and entry.ref is not None:
                        released.add(entry.ref)
            return holds

        def is_released(entry_id: uuid.UUID) -> bool:
            build()
            return entry_id in released

        return cls(hold=lambda entry_id: build().get(entry_id), released=is_released)

    def hold(self, entry_id: uuid.UUID) -> LedgerEntry | None:
        return self._hold(entry_id)

    def released(self, entry_id: uuid.UUID) -> bool:
        return self._released(entry_id)


def _node_row_problems(state: _ChainState, rows: Sequence[PersistedNode]) -> list[str]:
    """Stored topology rows that disagree with the chain."""
    problems: list[str] = []
    stored = {row.scope_id: row for row in rows}
    for scope_id, node in state.nodes.items():
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
    for scope_id in sorted(stored.keys() - state.nodes.keys()):
        problems.append(f"the nodes table lists scope {scope_id!r}, which the chain never created")
    return problems


def _control_row_problems(
    chained: Sequence[ControlEvent], rows: Sequence[ControlEvent]
) -> list[str]:
    """Stored control-event rows that disagree with the chain's control entries.

    :param chained: The control events of the entries the rows should
        describe: every one, or those after the checkpoint an open started from.
    """
    problems: list[str] = []
    stored: dict[uuid.UUID, ControlEvent] = {}
    for row in rows:
        if row.entry_id is None:
            continue
        if row.entry_id in stored:
            problems.append(f"control_events records chain entry {row.entry_id} twice")
        stored[row.entry_id] = row
    by_entry = {e.entry_id: e for e in chained if e.entry_id is not None}
    for entry_id, event in by_entry.items():
        found = stored.get(entry_id)
        if found is None:
            problems.append(
                f"the {event.event_type} of {event.scope_id!r} at chain entry {entry_id} is "
                f"missing from the control_events table"
            )
        elif found != event:
            problems.append(f"the control_events row for chain entry {entry_id} disagrees with it")
    for entry_id in sorted(stored.keys() - by_entry.keys(), key=str):
        problems.append(
            f"control_events names chain entry {entry_id}, which is not a control entry "
            f"in the chain"
        )
    return problems
