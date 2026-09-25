"""The ARC1 documents: receipts, checkpoints, cosignatures, bundles and rows.

Each type serializes to one JSON object and back. :meth:`from_json` is the
only way a document from outside becomes a Python object, and it is strict:
exactly the fields the schema names, each of the right type and format,
set-valued lists sorted and free of duplicates, and fields that agree with
one another. A verifier that silently tolerated an unknown field would be
signing off on content it never read.

Hashes are lowercase hex SHA-256 (64 characters). Instants are UTC, written
``YYYY-MM-DDTHH:MM:SS.ffffffZ``. Money is a decimal string with exactly eight
places, the ledger's quantum. Identifiers from the ledger are canonical UUID
strings. Every string is non-empty, at most 512 characters, and free of
control characters.

The signed bytes of a document are its canonical encoding with ``sig``
reduced to ``{"alg", "key_id"}``, prefixed by the document type's domain
string. The signature therefore covers which key and algorithm are claimed,
and a signature over one kind of document never verifies as another.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, ClassVar, Literal

from agentgov.exceptions import MalformedReceiptError, ReceiptSignatureError
from agentgov.receipts.canonical import (
    MAX_SAFE_INTEGER,
    _utf16_order,
    canonical_bytes,
    loads_strict,
)
from agentgov.receipts.merkle import leaf_hash
from agentgov.receipts.signing import ALG_ED25519, ALG_HMAC_SHA256, Signer, Verifier

__all__ = [
    "ActionReceipt",
    "Anchors",
    "Authority",
    "Capability",
    "ChainAnchor",
    "CheckerRecord",
    "Checkpoint",
    "Cosignature",
    "Cost",
    "Coverage",
    "Decision",
    "DisclosedRow",
    "Effect",
    "EffectSummary",
    "InclusionProof",
    "Intent",
    "LogAnchor",
    "Outcome",
    "OutcomeStatus",
    "ReceiptBundle",
    "RowChange",
    "RowDisclosure",
    "Signature",
    "StatedFootprint",
]

RECEIPT_VERSION = "ARC1"
CHECKPOINT_VERSION = "ARC1-checkpoint"
COSIGNATURE_VERSION = "ARC1-cosignature"
BUNDLE_VERSION = "ARC1-bundle"
ROWS_VERSION = "ARC1-rows"

RECEIPT_DOMAIN = b"ARC1/receipt/v1\n"
CHECKPOINT_DOMAIN = b"ARC1/checkpoint/v1\n"
COSIGNATURE_DOMAIN = b"ARC1/cosignature/v1\n"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[0-9a-f]{16}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
_MONEY = re.compile(r"(0|[1-9][0-9]*)\.[0-9]{8}")
_TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,512}")
_QUANTUM = Decimal("0.00000001")
_SIGNATURE_BYTES = {ALG_ED25519: 64, ALG_HMAC_SHA256: 32}

Scalar = str | int | bool | None


# --------------------------------------------------------------------------
# Field formats
# --------------------------------------------------------------------------


def instant(moment: datetime) -> str:
    """An aware datetime as an ARC1 instant string."""
    if moment.tzinfo is None:
        raise ValueError("ARC1 instants are timezone-aware")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_instant(text: str, path: str) -> datetime:
    if not _INSTANT.fullmatch(text):
        raise MalformedReceiptError(f"{path} is not an ARC1 instant (YYYY-MM-DDTHH:MM:SS.ffffffZ)")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise MalformedReceiptError(f"{path} is not a real instant: {exc}") from exc


def money_text(amount: Decimal) -> str:
    """A non-negative amount as an eight-place decimal string."""
    if amount < 0:
        raise ValueError("ARC1 amounts are not negative")
    quantized = amount.quantize(_QUANTUM)
    if quantized != amount:
        raise ValueError(f"{amount} is not a whole number of ledger quanta (1e-8)")
    return format(quantized, "f")


def _check_text(value: object, path: str) -> str:
    if not isinstance(value, str) or not _TEXT.fullmatch(value):
        raise MalformedReceiptError(
            f"{path} must be a non-empty string of at most 512 characters with no "
            f"control characters"
        )
    return value


def _check_pattern(value: object, pattern: re.Pattern[str], what: str, path: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise MalformedReceiptError(f"{path} must be {what}")
    return value


def _check_int(value: object, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedReceiptError(f"{path} must be an integer")
    if not minimum <= value <= MAX_SAFE_INTEGER:
        raise MalformedReceiptError(f"{path} must be between {minimum} and 2**53 - 1")
    return value


def _check_set(values: Sequence[str], path: str) -> None:
    if list(values) != sorted(set(values), key=_utf16_order):
        raise MalformedReceiptError(
            f"{path} is a set: it must be sorted by UTF-16 code units, as canonical JSON "
            f"sorts object keys, with no duplicates"
        )


def _as_set(values: Iterable[str]) -> tuple[str, ...]:
    # One order for the whole format: the one RFC 8785 sorts object keys in.
    return tuple(sorted(set(values), key=_utf16_order))


class _Fields:
    """One JSON object, read field by field against an exact schema."""

    __slots__ = ("_path", "_value")

    def __init__(self, value: object, path: str, names: Iterable[str]) -> None:
        if not isinstance(value, dict):
            raise MalformedReceiptError(f"{path} must be a JSON object")
        expected = set(names)
        missing = sorted(expected - value.keys())
        unknown = sorted(value.keys() - expected)
        if missing:
            raise MalformedReceiptError(f"{path} is missing {', '.join(missing)}")
        if unknown:
            raise MalformedReceiptError(
                f"{path} has unknown field(s) {', '.join(unknown)}; ARC1 verifiers refuse "
                f"what they do not understand"
            )
        self._value: dict[str, Any] = value
        self._path = path

    def raw(self, key: str) -> Any:
        return self._value[key]

    def path(self, key: str) -> str:
        return f"{self._path}.{key}"

    def version(self, expected: str) -> None:
        if self._value["v"] != expected:
            raise MalformedReceiptError(f"{self.path('v')} must be {expected!r}")

    def text(self, key: str) -> str:
        return _check_text(self._value[key], self.path(key))

    def optional_text(self, key: str) -> str | None:
        value = self._value[key]
        return None if value is None else _check_text(value, self.path(key))

    def pattern(self, key: str, pattern: re.Pattern[str], what: str) -> str:
        return _check_pattern(self._value[key], pattern, what, self.path(key))

    def hex64(self, key: str) -> str:
        return self.pattern(key, _HEX64, "64 lowercase hex characters (a SHA-256)")

    def uuid(self, key: str) -> str:
        return self.pattern(key, _UUID, "a canonical lowercase UUID")

    def optional_uuid(self, key: str) -> str | None:
        value = self._value[key]
        return None if value is None else self.uuid(key)

    def instant(self, key: str) -> datetime:
        value = self._value[key]
        if not isinstance(value, str):
            raise MalformedReceiptError(f"{self.path(key)} must be a string")
        return _parse_instant(value, self.path(key))

    def integer(self, key: str, *, minimum: int = 0) -> int:
        return _check_int(self._value[key], self.path(key), minimum=minimum)

    def optional_integer(self, key: str) -> int | None:
        value = self._value[key]
        return None if value is None else self.integer(key)

    def boolean(self, key: str) -> bool:
        value = self._value[key]
        if not isinstance(value, bool):
            raise MalformedReceiptError(f"{self.path(key)} must be true or false")
        return value

    def array(self, key: str) -> list[Any]:
        value = self._value[key]
        if not isinstance(value, list):
            raise MalformedReceiptError(f"{self.path(key)} must be an array")
        return value

    def texts(self, key: str, *, is_set: bool = True) -> tuple[str, ...]:
        items = self.array(key)
        values = tuple(_check_text(v, f"{self.path(key)}[{i}]") for i, v in enumerate(items))
        if is_set:
            _check_set(values, self.path(key))
        return values

    def hashes(self, key: str) -> tuple[str, ...]:
        items = self.array(key)
        return tuple(
            _check_pattern(v, _HEX64, "a SHA-256 in hex", f"{self.path(key)}[{i}]")
            for i, v in enumerate(items)
        )

    def child(self, key: str, names: Iterable[str]) -> _Fields:
        return _Fields(self._value[key], self.path(key), names)

    def optional_child(self, key: str, names: Iterable[str]) -> _Fields | None:
        value = self._value[key]
        return None if value is None else _Fields(value, self.path(key), names)


# --------------------------------------------------------------------------
# Signatures
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Signature:
    """``sig``: which key signed, with which algorithm, and the signature."""

    alg: str
    key_id: str
    value: bytes

    def to_json(self) -> dict[str, Any]:
        return {"alg": self.alg, "key_id": self.key_id, "signature": self.value.hex()}

    @classmethod
    def from_json(cls, fields: _Fields) -> Signature:
        alg = fields.raw("alg")
        if alg not in _SIGNATURE_BYTES:
            raise MalformedReceiptError(
                f"{fields.path('alg')} must be {ALG_ED25519!r} or {ALG_HMAC_SHA256!r}"
            )
        key_id = fields.pattern("key_id", _KEY_ID, "16 lowercase hex characters")
        signature = fields.raw("signature")
        if not isinstance(signature, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", signature):
            raise MalformedReceiptError(f"{fields.path('signature')} must be lowercase hex")
        value = bytes.fromhex(signature)
        if len(value) != _SIGNATURE_BYTES[alg]:
            raise MalformedReceiptError(
                f"{fields.path('signature')} is {len(value)} bytes; an {alg} signature "
                f"is {_SIGNATURE_BYTES[alg]}"
            )
        return cls(alg=alg, key_id=key_id, value=value)


_SIG_FIELDS = ("alg", "key_id", "signature")


def _signing_input(domain: bytes, body: Mapping[str, Any], alg: str, key_id: str) -> bytes:
    return domain + canonical_bytes({**body, "sig": {"alg": alg, "key_id": key_id}})


def _check_signature(
    what: str,
    signature: Signature | None,
    verifier: Verifier,
    payload: Callable[[str, str], bytes],
) -> None:
    if signature is None:
        raise ReceiptSignatureError(f"the {what} is not signed")
    if signature.alg != verifier.alg:
        raise ReceiptSignatureError(
            f"the {what} claims an {signature.alg} signature but the key given is "
            f"{verifier.alg}; a verifier never switches algorithm on the document's say-so"
        )
    if signature.key_id != verifier.key_id:
        raise ReceiptSignatureError(
            f"the {what} was signed by key {signature.key_id}, not by the key given "
            f"({verifier.key_id})"
        )
    if not verifier.verify(payload(signature.alg, signature.key_id), signature.value):
        raise ReceiptSignatureError(
            f"the {what}'s {signature.alg} signature does not verify under key "
            f"{verifier.key_id}: it was altered after signing, or was never signed by that key"
        )


# --------------------------------------------------------------------------
# The receipt
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Capability:
    """What the agent was allowed to touch: a grant, and its limits."""

    grant: str
    tables: tuple[str, ...] = ()
    tenants: tuple[str, ...] = ()
    row_limit: int | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "tables", _as_set(self.tables))
        object.__setattr__(self, "tenants", _as_set(self.tenants))

    def to_json(self) -> dict[str, Any]:
        return {
            "grant": self.grant,
            "tables": list(self.tables),
            "tenants": list(self.tenants),
            "row_limit": self.row_limit,
        }

    @classmethod
    def from_json(cls, f: _Fields) -> Capability:
        return cls(
            grant=f.text("grant"),
            tables=f.texts("tables"),
            tenants=f.texts("tenants"),
            row_limit=f.optional_integer("row_limit"),
        )


@dataclass(frozen=True)
class Authority:
    """Who delegated what: the scope path from the root, and the capability."""

    scope_path: tuple[str, ...]
    trajectory_id: str
    capability: Capability

    def to_json(self) -> dict[str, Any]:
        return {
            "scope_path": list(self.scope_path),
            "trajectory_id": self.trajectory_id,
            "capability": self.capability.to_json(),
        }

    @classmethod
    def from_json(cls, f: _Fields) -> Authority:
        scope_path = f.texts("scope_path", is_set=False)
        if not scope_path:
            raise MalformedReceiptError(f"{f.path('scope_path')} must name at least one scope")
        if len(set(scope_path)) != len(scope_path):
            raise MalformedReceiptError(f"{f.path('scope_path')} repeats a scope")
        return cls(
            scope_path=scope_path,
            trajectory_id=f.text("trajectory_id"),
            capability=Capability.from_json(
                f.child("capability", ("grant", "tables", "tenants", "row_limit"))
            ),
        )


@dataclass(frozen=True)
class StatedFootprint:
    """What the agent said the plan would touch, before it was measured."""

    rows: int | None = None
    tables: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tables", _as_set(self.tables))

    def to_json(self) -> dict[str, Any]:
        return {"rows": self.rows, "tables": list(self.tables)}


@dataclass(frozen=True)
class Intent:
    """The plan, by digest, and the footprint the agent claimed for it."""

    plan_hash: str
    stated: StatedFootprint = field(default_factory=StatedFootprint)

    def to_json(self) -> dict[str, Any]:
        return {"plan_hash": self.plan_hash, "stated": self.stated.to_json()}

    @classmethod
    def from_json(cls, f: _Fields) -> Intent:
        stated = f.child("stated", ("rows", "tables"))
        return cls(
            plan_hash=f.hex64("plan_hash"),
            stated=StatedFootprint(
                rows=stated.optional_integer("rows"), tables=stated.texts("tables")
            ),
        )


@dataclass(frozen=True)
class EffectSummary:
    """Counts of what the measured diff did, and where."""

    inserted: int = 0
    updated: int = 0
    deleted: int = 0
    tables: tuple[str, ...] = ()
    tenants: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tables", _as_set(self.tables))
        object.__setattr__(self, "tenants", _as_set(self.tenants))

    @property
    def total(self) -> int:
        return self.inserted + self.updated + self.deleted

    def to_json(self) -> dict[str, Any]:
        return {
            "ins": self.inserted,
            "upd": self.updated,
            "del": self.deleted,
            "tables": list(self.tables),
            "tenants": list(self.tenants),
        }

    @classmethod
    def from_json(cls, f: _Fields) -> EffectSummary:
        return cls(
            inserted=f.integer("ins"),
            updated=f.integer("upd"),
            deleted=f.integer("del"),
            tables=f.texts("tables"),
            tenants=f.texts("tenants"),
        )


@dataclass(frozen=True)
class Effect:
    """What actually happened, measured from the substrate.

    :ivar diff_hash: The escrow's digest of the full diff. It is the value the
        escrow chain's ``DIFF_COMPUTED`` record carries, which is what ties the
        two together.
    :ivar row_root: The salted Merkle root over the individual row changes
        (see :mod:`agentgov.receipts.rows`). No row data is in the receipt.
    :ivar row_count: How many row changes ``row_root`` commits to.
    """

    substrate_id: str
    schema_hash: str
    diff_hash: str
    row_root: str
    row_count: int
    summary: EffectSummary
    truncated: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "substrate_id": self.substrate_id,
            "schema_hash": self.schema_hash,
            "diff_hash": self.diff_hash,
            "row_root": self.row_root,
            "row_count": self.row_count,
            "summary": self.summary.to_json(),
            "truncated": self.truncated,
        }

    @classmethod
    def from_json(cls, f: _Fields) -> Effect:
        return cls(
            substrate_id=f.text("substrate_id"),
            schema_hash=f.hex64("schema_hash"),
            diff_hash=f.hex64("diff_hash"),
            row_root=f.hex64("row_root"),
            row_count=f.integer("row_count"),
            summary=EffectSummary.from_json(
                f.child("summary", ("ins", "upd", "del", "tables", "tenants"))
            ),
            truncated=f.boolean("truncated"),
        )


@dataclass(frozen=True)
class Coverage:
    """What the measurement could and could not see. A receipt must never
    promise more than was measured, so its blind spots are part of it."""

    observed_tables: tuple[str, ...]
    cascade_closed: bool
    authorizer_on: bool
    known_gaps: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_tables", _as_set(self.observed_tables))
        object.__setattr__(self, "known_gaps", _as_set(self.known_gaps))

    def to_json(self) -> dict[str, Any]:
        return {
            "observed_tables": list(self.observed_tables),
            "cascade_closed": self.cascade_closed,
            "authorizer_on": self.authorizer_on,
            "known_gaps": list(self.known_gaps),
        }

    @classmethod
    def from_json(cls, f: _Fields) -> Coverage:
        return cls(
            observed_tables=f.texts("observed_tables"),
            cascade_closed=f.boolean("cascade_closed"),
            authorizer_on=f.boolean("authorizer_on"),
            known_gaps=f.texts("known_gaps"),
        )


@dataclass(frozen=True)
class CheckerRecord:
    """One deterministic check that ran, and a digest of its configuration."""

    name: str
    config_hash: str

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "config_hash": self.config_hash}


@dataclass(frozen=True)
class Decision:
    """The verdict, and the policy that reached it."""

    verdict_hash: str
    admitted: bool
    checkers: tuple[CheckerRecord, ...] = ()
    policy_epoch: int = 0
    repair_of: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "verdict_hash": self.verdict_hash,
            "admitted": self.admitted,
            "checkers": [checker.to_json() for checker in self.checkers],
            "policy_epoch": self.policy_epoch,
            "repair_of": self.repair_of,
        }

    @classmethod
    def from_json(cls, f: _Fields) -> Decision:
        checkers = []
        for index, item in enumerate(f.array("checkers")):
            c = _Fields(item, f"{f.path('checkers')}[{index}]", ("name", "config_hash"))
            checkers.append(CheckerRecord(name=c.text("name"), config_hash=c.hex64("config_hash")))
        names = [checker.name for checker in checkers]
        if len(set(names)) != len(names):
            raise MalformedReceiptError(f"{f.path('checkers')} names a checker twice")
        return cls(
            verdict_hash=f.hex64("verdict_hash"),
            admitted=f.boolean("admitted"),
            checkers=tuple(checkers),
            policy_epoch=f.integer("policy_epoch"),
            repair_of=f.optional_uuid("repair_of"),
        )


@dataclass(frozen=True)
class Cost:
    """What the action cost, as the ledger recorded it."""

    ledger_txn_ids: tuple[str, ...] = ()
    settled_usd: Decimal = Decimal("0")
    served_models: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "ledger_txn_ids", _as_set(self.ledger_txn_ids))
        object.__setattr__(self, "served_models", _as_set(self.served_models))

    def to_json(self) -> dict[str, Any]:
        return {
            "ledger_txn_ids": list(self.ledger_txn_ids),
            "settled_usd": money_text(self.settled_usd),
            "served_models": list(self.served_models),
        }

    @classmethod
    def from_json(cls, f: _Fields) -> Cost:
        txns = f.array("ledger_txn_ids")
        txn_ids = tuple(
            _check_pattern(
                t, _UUID, "a canonical lowercase UUID", f"{f.path('ledger_txn_ids')}[{i}]"
            )
            for i, t in enumerate(txns)
        )
        _check_set(txn_ids, f.path("ledger_txn_ids"))
        amount = f.pattern("settled_usd", _MONEY, "a decimal string with exactly 8 places")
        try:
            settled = Decimal(amount)
        except InvalidOperation as exc:  # pragma: no cover - the pattern admits only decimals
            raise MalformedReceiptError(f"{f.path('settled_usd')} is not a decimal") from exc
        return cls(
            ledger_txn_ids=txn_ids, settled_usd=settled, served_models=f.texts("served_models")
        )


class OutcomeStatus(StrEnum):
    """How the action ended."""

    COMMITTED = "committed"
    REFUSED = "refused"
    RECOVERED_COMMITTED = "recovered_committed"
    RECOVERED_ABORTED = "recovered_aborted"


@dataclass(frozen=True)
class Outcome:
    """Whether the effects are durable, and the substrate's own id for it."""

    status: OutcomeStatus
    substrate_txid: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {"status": self.status.value, "substrate_txid": self.substrate_txid}

    @classmethod
    def from_json(cls, f: _Fields) -> Outcome:
        status = f.raw("status")
        try:
            parsed = OutcomeStatus(status)
        except ValueError as exc:
            allowed = ", ".join(s.value for s in OutcomeStatus)
            raise MalformedReceiptError(f"{f.path('status')} must be one of {allowed}") from exc
        return cls(status=parsed, substrate_txid=f.optional_text("substrate_txid"))


@dataclass(frozen=True)
class ChainAnchor:
    """A position in another hash chain: its sequence and head hash then."""

    seq: int
    head: str

    def to_json(self) -> dict[str, Any]:
        return {"seq": self.seq, "head": self.head}

    @classmethod
    def from_json(cls, f: _Fields) -> ChainAnchor:
        return cls(seq=f.integer("seq"), head=f.hex64("head"))


@dataclass(frozen=True)
class LogAnchor:
    """Which receipt log this receipt is a leaf of, and at which index."""

    log_id: str
    leaf_index: int

    def to_json(self) -> dict[str, Any]:
        return {"log_id": self.log_id, "leaf_index": self.leaf_index}


@dataclass(frozen=True)
class Anchors:
    """Where this receipt sits in the AgentGov ledger, the escrow chain and
    the receipt log. Each is optional; a verifier checks those it can."""

    agentgov: ChainAnchor | None = None
    escrow: ChainAnchor | None = None
    log: LogAnchor | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "agentgov": self.agentgov.to_json() if self.agentgov else None,
            "escrow": self.escrow.to_json() if self.escrow else None,
            "log": self.log.to_json() if self.log else None,
        }

    @classmethod
    def from_json(cls, f: _Fields) -> Anchors:
        agentgov = f.optional_child("agentgov", ("seq", "head"))
        escrow = f.optional_child("escrow", ("seq", "head"))
        log = f.optional_child("log", ("log_id", "leaf_index"))
        return cls(
            agentgov=ChainAnchor.from_json(agentgov) if agentgov else None,
            escrow=ChainAnchor.from_json(escrow) if escrow else None,
            log=LogAnchor(log_id=log.text("log_id"), leaf_index=log.integer("leaf_index"))
            if log
            else None,
        )


_RECEIPT_FIELDS = (
    "v",
    "receipt_id",
    "issued_at",
    "issuer",
    "authority",
    "intent",
    "effect",
    "coverage",
    "decision",
    "cost",
    "outcome",
    "anchors",
    "sig",
)


@dataclass(frozen=True)
class ActionReceipt:
    """ARC1: a signed record of one agent action against a system of record.

    Six things, per the specification: who authorized it (``authority``),
    what the agent said it would do (``intent``), what it measurably did
    (``effect``, and what the measurement could not see, ``coverage``), what
    was decided (``decision``), what it cost (``cost``), and how it ended
    (``outcome``); plus where it sits in other chains (``anchors``).
    Refusals get receipts too.

    Construct one unsigned, then :meth:`sign` it, or let
    :meth:`agentgov.receipts.log.ReceiptLog.issue` place it in a log and sign
    it there.

    :raises MalformedReceiptError: If the fields contradict one another: the
        row count differs from the summary's counts, or a refused plan is
        recorded as committed.
    """

    receipt_id: str
    issued_at: datetime
    issuer: str
    authority: Authority
    intent: Intent
    effect: Effect
    coverage: Coverage
    decision: Decision
    cost: Cost
    outcome: Outcome
    anchors: Anchors = field(default_factory=Anchors)
    signature: Signature | None = None

    domain: ClassVar[bytes] = RECEIPT_DOMAIN

    def __post_init__(self) -> None:
        if self.effect.row_count != self.effect.summary.total:
            raise MalformedReceiptError(
                f"effect.row_count is {self.effect.row_count} but the summary counts "
                f"{self.effect.summary.total} row changes"
            )
        committed = (OutcomeStatus.COMMITTED, OutcomeStatus.RECOVERED_COMMITTED)
        if self.outcome.status in committed and not self.decision.admitted:
            raise MalformedReceiptError(
                f"outcome is {self.outcome.status.value} but the decision did not admit "
                f"the plan; a refused plan cannot have committed"
            )

    # -- encoding ---------------------------------------------------------

    def body(self) -> dict[str, Any]:
        """Every field but ``sig``."""
        return {
            "v": RECEIPT_VERSION,
            "receipt_id": self.receipt_id,
            "issued_at": instant(self.issued_at),
            "issuer": self.issuer,
            "authority": self.authority.to_json(),
            "intent": self.intent.to_json(),
            "effect": self.effect.to_json(),
            "coverage": self.coverage.to_json(),
            "decision": self.decision.to_json(),
            "cost": self.cost.to_json(),
            "outcome": self.outcome.to_json(),
            "anchors": self.anchors.to_json(),
        }

    def to_json(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.signature.to_json() if self.signature else None}

    def canonical(self) -> bytes:
        """The canonical encoding of the whole receipt, signature included.

        This is the receipt's leaf data in a receipt log.
        """
        return canonical_bytes(self.to_json())

    def leaf_hash(self) -> bytes:
        """RFC 9162 leaf hash of :meth:`canonical`."""
        return leaf_hash(self.canonical())

    def signing_input(self, alg: str, key_id: str) -> bytes:
        return _signing_input(RECEIPT_DOMAIN, self.body(), alg, key_id)

    # -- signing ----------------------------------------------------------

    def sign(self, signer: Signer) -> ActionReceipt:
        """A copy signed by ``signer``."""
        value = signer.sign(self.signing_input(signer.alg, signer.key_id))
        return replace(self, signature=Signature(signer.alg, signer.key_id, value))

    def verify(self, verifier: Verifier) -> None:
        """:raises ReceiptSignatureError: Unless ``verifier``'s key signed this."""
        _check_signature("receipt", self.signature, verifier, self.signing_input)

    def with_log_anchor(self, log_id: str, leaf_index: int) -> ActionReceipt:
        """An unsigned copy that claims a position in a receipt log."""
        anchors = replace(self.anchors, log=LogAnchor(log_id=log_id, leaf_index=leaf_index))
        return replace(self, anchors=anchors, signature=None)

    # -- decoding ---------------------------------------------------------

    @classmethod
    def from_json(cls, value: object, path: str = "receipt") -> ActionReceipt:
        """Decode and validate one receipt.

        :raises MalformedReceiptError: On anything the schema does not allow.
        """
        f = _Fields(value, path, _RECEIPT_FIELDS)
        f.version(RECEIPT_VERSION)
        sig = f.optional_child("sig", _SIG_FIELDS)
        return cls(
            receipt_id=f.uuid("receipt_id"),
            issued_at=f.instant("issued_at"),
            issuer=f.text("issuer"),
            authority=Authority.from_json(
                f.child("authority", ("scope_path", "trajectory_id", "capability"))
            ),
            intent=Intent.from_json(f.child("intent", ("plan_hash", "stated"))),
            effect=Effect.from_json(
                f.child(
                    "effect",
                    (
                        "substrate_id",
                        "schema_hash",
                        "diff_hash",
                        "row_root",
                        "row_count",
                        "summary",
                        "truncated",
                    ),
                )
            ),
            coverage=Coverage.from_json(
                f.child(
                    "coverage", ("observed_tables", "cascade_closed", "authorizer_on", "known_gaps")
                )
            ),
            decision=Decision.from_json(
                f.child(
                    "decision",
                    ("verdict_hash", "admitted", "checkers", "policy_epoch", "repair_of"),
                )
            ),
            cost=Cost.from_json(
                f.child("cost", ("ledger_txn_ids", "settled_usd", "served_models"))
            ),
            outcome=Outcome.from_json(f.child("outcome", ("status", "substrate_txid"))),
            anchors=Anchors.from_json(f.child("anchors", ("agentgov", "escrow", "log"))),
            signature=Signature.from_json(sig) if sig else None,
        )

    @classmethod
    def loads(cls, text: str | bytes) -> ActionReceipt:
        return cls.from_json(loads_strict(text))


# --------------------------------------------------------------------------
# Log checkpoints and witness cosignatures
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Checkpoint:
    """A receipt log's signed statement of its size and root at one moment."""

    log_id: str
    tree_size: int
    root_hash: str
    issued_at: datetime
    signature: Signature | None = None

    def body(self) -> dict[str, Any]:
        return {
            "v": CHECKPOINT_VERSION,
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "issued_at": instant(self.issued_at),
        }

    def to_json(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.signature.to_json() if self.signature else None}

    def signing_input(self, alg: str, key_id: str) -> bytes:
        return _signing_input(CHECKPOINT_DOMAIN, self.body(), alg, key_id)

    def sign(self, signer: Signer) -> Checkpoint:
        value = signer.sign(self.signing_input(signer.alg, signer.key_id))
        return replace(self, signature=Signature(signer.alg, signer.key_id, value))

    def verify(self, verifier: Verifier) -> None:
        """:raises ReceiptSignatureError: Unless the log's key signed this."""
        _check_signature("checkpoint", self.signature, verifier, self.signing_input)

    @classmethod
    def from_json(cls, value: object, path: str = "checkpoint") -> Checkpoint:
        f = _Fields(value, path, ("v", "log_id", "tree_size", "root_hash", "issued_at", "sig"))
        f.version(CHECKPOINT_VERSION)
        sig = f.optional_child("sig", _SIG_FIELDS)
        return cls(
            log_id=f.text("log_id"),
            tree_size=f.integer("tree_size"),
            root_hash=f.hex64("root_hash"),
            issued_at=f.instant("issued_at"),
            signature=Signature.from_json(sig) if sig else None,
        )


@dataclass(frozen=True)
class Cosignature:
    """A witness's signed statement that it saw a log at a size and root, and
    that this extends everything it saw of that log before."""

    witness_id: str
    log_id: str
    tree_size: int
    root_hash: str
    witnessed_at: datetime
    signature: Signature | None = None

    def body(self) -> dict[str, Any]:
        return {
            "v": COSIGNATURE_VERSION,
            "witness_id": self.witness_id,
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "witnessed_at": instant(self.witnessed_at),
        }

    def to_json(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.signature.to_json() if self.signature else None}

    def signing_input(self, alg: str, key_id: str) -> bytes:
        return _signing_input(COSIGNATURE_DOMAIN, self.body(), alg, key_id)

    def sign(self, signer: Signer) -> Cosignature:
        value = signer.sign(self.signing_input(signer.alg, signer.key_id))
        return replace(self, signature=Signature(signer.alg, signer.key_id, value))

    def verify(self, verifier: Verifier) -> None:
        """:raises ReceiptSignatureError: Unless the witness's key signed this."""
        _check_signature("cosignature", self.signature, verifier, self.signing_input)

    @classmethod
    def from_json(cls, value: object, path: str = "cosignature") -> Cosignature:
        f = _Fields(
            value,
            path,
            ("v", "witness_id", "log_id", "tree_size", "root_hash", "witnessed_at", "sig"),
        )
        f.version(COSIGNATURE_VERSION)
        sig = f.optional_child("sig", _SIG_FIELDS)
        return cls(
            witness_id=f.text("witness_id"),
            log_id=f.text("log_id"),
            tree_size=f.integer("tree_size"),
            root_hash=f.hex64("root_hash"),
            witnessed_at=f.instant("witnessed_at"),
            signature=Signature.from_json(sig) if sig else None,
        )


# --------------------------------------------------------------------------
# Bundles: a receipt with the proof that it is in a log
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class InclusionProof:
    """An RFC 9162 audit path for one leaf of a tree of a given size."""

    leaf_index: int
    tree_size: int
    audit_path: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
            "audit_path": list(self.audit_path),
        }

    def path_bytes(self) -> list[bytes]:
        return [bytes.fromhex(node) for node in self.audit_path]

    @classmethod
    def from_json(cls, f: _Fields) -> InclusionProof:
        leaf_index = f.integer("leaf_index")
        tree_size = f.integer("tree_size", minimum=1)
        if leaf_index >= tree_size:
            raise MalformedReceiptError(
                f"{f.path('leaf_index')} is {leaf_index}, outside a tree of size {tree_size}"
            )
        return cls(leaf_index=leaf_index, tree_size=tree_size, audit_path=f.hashes("audit_path"))


@dataclass(frozen=True)
class ReceiptBundle:
    """What a verifier is handed: a receipt, and optionally the checkpoint and
    audit path proving the receipt is in that log."""

    receipt: ActionReceipt
    inclusion: InclusionProof | None = None
    checkpoint: Checkpoint | None = None

    def __post_init__(self) -> None:
        if (self.inclusion is None) != (self.checkpoint is None):
            raise MalformedReceiptError(
                "a bundle carries an inclusion proof and its checkpoint together, or neither"
            )

    def to_json(self) -> dict[str, Any]:
        return {
            "v": BUNDLE_VERSION,
            "receipt": self.receipt.to_json(),
            "inclusion": self.inclusion.to_json() if self.inclusion else None,
            "checkpoint": self.checkpoint.to_json() if self.checkpoint else None,
        }

    @classmethod
    def from_json(cls, value: object) -> ReceiptBundle:
        f = _Fields(value, "bundle", ("v", "receipt", "inclusion", "checkpoint"))
        f.version(BUNDLE_VERSION)
        inclusion = f.optional_child("inclusion", ("leaf_index", "tree_size", "audit_path"))
        checkpoint = f.raw("checkpoint")
        return cls(
            receipt=ActionReceipt.from_json(f.raw("receipt"), "bundle.receipt"),
            inclusion=InclusionProof.from_json(inclusion) if inclusion else None,
            checkpoint=Checkpoint.from_json(checkpoint, "bundle.checkpoint")
            if checkpoint is not None
            else None,
        )

    @classmethod
    def loads(cls, text: str | bytes) -> ReceiptBundle:
        """Decode a bundle, or a bare receipt as a bundle without a proof."""
        value = loads_strict(text)
        if isinstance(value, dict) and value.get("v") == RECEIPT_VERSION:
            return cls(receipt=ActionReceipt.from_json(value))
        return cls.from_json(value)


# --------------------------------------------------------------------------
# Rows: what the row commitment commits to, and disclosures of it
# --------------------------------------------------------------------------

RowOp = Literal["insert", "update", "delete"]
_ROW_OPS: tuple[RowOp, ...] = ("insert", "update", "delete")


def _check_image(value: object, path: str) -> dict[str, Scalar] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise MalformedReceiptError(f"{path} must be an object of column values or null")
    for column, item in value.items():
        _check_text(column, f"{path} column name")
        if item is not None and not isinstance(item, (str, int, bool)):
            raise MalformedReceiptError(
                f"{path}.{column} must be a string, integer, boolean or null"
            )
        if isinstance(item, int) and not isinstance(item, bool):
            _check_int(item, f"{path}.{column}", minimum=-MAX_SAFE_INTEGER)
    return dict(value)


@dataclass(frozen=True)
class RowChange:
    """One row a plan inserted, updated or deleted, as the substrate measured it.

    Column values are strings, integers, booleans or null, so every verifier
    canonicalizes them identically; :meth:`from_values` converts anything else
    (floats, decimals, bytes, instants) to a string first.
    """

    table: str
    pk: str
    op: RowOp
    tenant: str | None = None
    before: Mapping[str, Scalar] | None = None
    after: Mapping[str, Scalar] | None = None

    def __post_init__(self) -> None:
        if self.op not in _ROW_OPS:
            raise MalformedReceiptError(f"row op must be one of {', '.join(_ROW_OPS)}")
        shape = {"insert": (False, True), "update": (True, True), "delete": (True, False)}
        has_before, has_after = shape[self.op]
        if (self.before is not None) != has_before or (self.after is not None) != has_after:
            article = "an" if self.op in ("insert", "update") else "a"
            raise MalformedReceiptError(
                f"{article} {self.op} has "
                f"{'a' if has_before else 'no'} before-image and "
                f"{'an' if has_after else 'no'} after-image"
            )

    @classmethod
    def from_values(
        cls,
        table: str,
        pk: object,
        *,
        before: Mapping[str, object] | None,
        after: Mapping[str, object] | None,
        tenant: str | None = None,
    ) -> RowChange:
        """Build a row change from raw database values, inferring the op."""
        if before is None and after is None:
            raise MalformedReceiptError("a row change has a before-image, an after-image, or both")
        op: RowOp = (
            "update"
            if before is not None and after is not None
            else "insert"
            if after is not None
            else "delete"
        )
        return cls(
            table=table,
            pk=str(pk),
            op=op,
            tenant=tenant,
            before=_normalize_image(before),
            after=_normalize_image(after),
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "pk": self.pk,
            "op": self.op,
            "tenant": self.tenant,
            "before": dict(self.before) if self.before is not None else None,
            "after": dict(self.after) if self.after is not None else None,
        }

    @classmethod
    def from_json(cls, value: object, path: str) -> RowChange:
        f = _Fields(value, path, ("table", "pk", "op", "tenant", "before", "after"))
        op = f.raw("op")
        if op not in _ROW_OPS:
            raise MalformedReceiptError(f"{f.path('op')} must be one of {', '.join(_ROW_OPS)}")
        return cls(
            table=f.text("table"),
            pk=f.text("pk"),
            op=op,
            tenant=f.optional_text("tenant"),
            before=_check_image(f.raw("before"), f.path("before")),
            after=_check_image(f.raw("after"), f.path("after")),
        )


def _normalize_image(image: Mapping[str, object] | None) -> dict[str, Scalar] | None:
    if image is None:
        return None
    return {str(column): _scalar(value) for column, value in image.items()}


def _scalar(value: object) -> Scalar:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value if abs(value) <= MAX_SAFE_INTEGER else str(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


@dataclass(frozen=True)
class DisclosedRow:
    """One row revealed from a row commitment, with what proves it was there."""

    index: int
    salt: bytes
    row: RowChange
    audit_path: tuple[str, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "salt": self.salt.hex(),
            "row": self.row.to_json(),
            "audit_path": list(self.audit_path),
        }


@dataclass(frozen=True)
class RowDisclosure:
    """Selected rows of one receipt's row commitment, for an auditor.

    The rest of the rows stay hidden: their salts are not revealed, so the
    hashes on the audit paths say nothing about their contents.
    """

    receipt_id: str
    row_root: str
    row_count: int
    rows: tuple[DisclosedRow, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "v": ROWS_VERSION,
            "receipt_id": self.receipt_id,
            "row_root": self.row_root,
            "row_count": self.row_count,
            "rows": [row.to_json() for row in self.rows],
        }

    @classmethod
    def from_json(cls, value: object) -> RowDisclosure:
        f = _Fields(value, "rows", ("v", "receipt_id", "row_root", "row_count", "rows"))
        f.version(ROWS_VERSION)
        disclosed = []
        for index, item in enumerate(f.array("rows")):
            path = f"rows.rows[{index}]"
            r = _Fields(item, path, ("index", "salt", "row", "audit_path"))
            salt = r.hex64("salt")
            disclosed.append(
                DisclosedRow(
                    index=r.integer("index"),
                    salt=bytes.fromhex(salt),
                    row=RowChange.from_json(r.raw("row"), f"{path}.row"),
                    audit_path=r.hashes("audit_path"),
                )
            )
        return cls(
            receipt_id=f.uuid("receipt_id"),
            row_root=f.hex64("row_root"),
            row_count=f.integer("row_count"),
            rows=tuple(disclosed),
        )

    @classmethod
    def loads(cls, text: str | bytes) -> RowDisclosure:
        return cls.from_json(loads_strict(text))
