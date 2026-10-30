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
and a signature over one kind of document never verifies as another. A
version 2 signature (ARC1 1.2) covers the domain and the SHA-512 of that
encoding instead, with ``"sv": 2`` in the header, so the signed message is
under 100 bytes whatever the document's size: a key service that limits the
messages it signs (AWS KMS: 4096 bytes) signs any receipt.

A :class:`KeyTransition` (ARC1 1.2) is signed by a log's outgoing key and
names its incoming key, so a log outlives its key; a :class:`KeySchedule`
follows them from a key the verifier trusts.
"""

from __future__ import annotations

import hashlib
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
from agentgov.receipts.signing import (
    ALG_ED25519,
    ALG_HMAC_SHA256,
    AsyncSigner,
    Ed25519PublicKey,
    Keyring,
    Signer,
    Verifier,
)

__all__ = [
    "ActionBinding",
    "ActionReceipt",
    "Anchors",
    "Attestation",
    "AttestedOutcome",
    "Authority",
    "Capability",
    "ChainAnchor",
    "CheckerRecord",
    "Checkpoint",
    "Cosignature",
    "Cost",
    "Coverage",
    "Decision",
    "DeliveredRequest",
    "Delivery",
    "DeliveryReceipt",
    "DisclosedRow",
    "Effect",
    "EffectSummary",
    "InclusionProof",
    "Intent",
    "KeySchedule",
    "KeyTransition",
    "LogAnchor",
    "LogDocument",
    "Outcome",
    "OutcomeStatus",
    "Quantity",
    "ReceiptBundle",
    "RowChange",
    "RowDisclosure",
    "Signature",
    "StatedFootprint",
    "document_from_json",
]

RECEIPT_VERSION = "ARC1"
DELIVERY_VERSION = "ARC1-delivery"
ATTESTATION_VERSION = "ARC1-attestation"
CHECKPOINT_VERSION = "ARC1-checkpoint"
COSIGNATURE_VERSION = "ARC1-cosignature"
BUNDLE_VERSION = "ARC1-bundle"
ROWS_VERSION = "ARC1-rows"

RECEIPT_DOMAIN = b"ARC1/receipt/v1\n"
DELIVERY_DOMAIN = b"ARC1/delivery/v1\n"
ATTESTATION_DOMAIN = b"ARC1/attestation/v1\n"
CHECKPOINT_DOMAIN = b"ARC1/checkpoint/v1\n"
COSIGNATURE_DOMAIN = b"ARC1/cosignature/v1\n"
TRANSITION_VERSION = "ARC1-transition"
TRANSITION_DOMAIN = b"ARC1/transition/v1\n"

SIGNATURE_VERSIONS = (1, 2)
"""Version 1 signs the domain and the canonical document (ARC1 1.0, 1.1);
version 2 (ARC1 1.2) signs the version 2 domain and the document's SHA-512."""
_DOMAIN_V2 = {
    RECEIPT_DOMAIN: b"ARC1/receipt/v2\n",
    DELIVERY_DOMAIN: b"ARC1/delivery/v2\n",
    ATTESTATION_DOMAIN: b"ARC1/attestation/v2\n",
    CHECKPOINT_DOMAIN: b"ARC1/checkpoint/v2\n",
    COSIGNATURE_DOMAIN: b"ARC1/cosignature/v2\n",
    TRANSITION_DOMAIN: b"ARC1/transition/v2\n",
}

_HEX64 = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"[0-9a-f]{16}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
_MONEY = re.compile(r"(0|[1-9][0-9]*)\.[0-9]{8}")
_TEXT = re.compile(r"[^\x00-\x1f\x7f]{1,512}")
_QUANTUM = Decimal("0.00000001")
_SIGNATURE_BYTES = {ALG_ED25519: 64, ALG_HMAC_SHA256: 32}

Scalar = str | int | bool | None

TRANSACTIONAL = "transactional"
"""What was measured is exactly what committed, or nothing committed: a stage
in a SQL transaction, a Git ref's compare-and-swap. The class of every receipt
that names none."""
PLAN_BOUND = "plan-bound"
"""What was measured is the plan that was applied, and the apply refuses if
the system moved since: a saved Terraform plan, a Kubernetes dry-run applied
under its ``resourceVersion``."""
PREDICTED = "predicted"
"""The before image was read, the after image predicted, the write made
conditional on the version read, and the result read back and compared."""
REQUEST_ONLY = "request-only"
"""Only the request was measured: judged, and delivered at most or exactly
once. Its effect is the remote system's word."""
MEASUREMENTS = (TRANSACTIONAL, PLAN_BOUND, PREDICTED, REQUEST_ONLY)
"""How strongly an action's effect was measured (ARC1 1.3), strongest first."""


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

    def __init__(
        self, value: object, path: str, names: Iterable[str], optional: Iterable[str] = ()
    ) -> None:
        if not isinstance(value, dict):
            raise MalformedReceiptError(f"{path} must be a JSON object")
        expected = set(names)
        allowed = expected | set(optional)
        missing = sorted(expected - value.keys())
        unknown = sorted(value.keys() - allowed)
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

    def has(self, key: str) -> bool:
        return key in self._value

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

    def child(self, key: str, names: Iterable[str], optional: Iterable[str] = ()) -> _Fields:
        return _Fields(self._value[key], self.path(key), names, optional)

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
    version: int = 1
    """1: over the domain and the canonical document; 2 (ARC1 1.2): over the
    version 2 domain and the document's SHA-512, and written ``"sv": 2``."""

    def to_json(self) -> dict[str, Any]:
        sig: dict[str, Any] = {"alg": self.alg, "key_id": self.key_id}
        if self.version != 1:
            sig["sv"] = self.version
        sig["signature"] = self.value.hex()
        return sig

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
        version = 1
        if fields.has("sv"):
            version = fields.raw("sv")
            if type(version) is not int or version != 2:
                raise MalformedReceiptError(
                    f"{fields.path('sv')} must be 2: a version 1 signature has no sv"
                )
        return cls(alg=alg, key_id=key_id, value=value, version=version)


_SIG_FIELDS = ("alg", "key_id", "signature")
_SIG_FIELDS_V2 = ("alg", "key_id", "sv", "signature")


def _sig_fields(value: object) -> tuple[str, ...]:
    """A version 2 signature names its version; a version 1 signature has
    exactly the three members it always had."""
    return _SIG_FIELDS_V2 if isinstance(value, dict) and "sv" in value else _SIG_FIELDS


def _signing_input(
    domain: bytes, body: Mapping[str, Any], alg: str, key_id: str, version: int = 1
) -> bytes:
    if version == 1:
        return domain + canonical_bytes({**body, "sig": {"alg": alg, "key_id": key_id}})
    if version != 2:
        raise ValueError(f"signature version {version!r} is not 1 or 2")
    header = {"alg": alg, "key_id": key_id, "sv": 2}
    return _domain_v2(domain) + hashlib.sha512(canonical_bytes({**body, "sig": header})).digest()


def _domain_v2(domain: bytes) -> bytes:
    """A document type's version 2 domain: its version 1 domain, ``v2`` for ``v1``."""
    found = _DOMAIN_V2.get(domain)
    if found is not None:
        return found
    if not domain.endswith(b"/v1\n"):
        raise ValueError(f"{domain!r} is not a version 1 domain")
    return domain[: -len(b"v1\n")] + b"v2\n"


def _signature_version(signer: object, version: int | None) -> int:
    """The version to sign with: the one asked for, or else the signer's own
    (a key service that limits message size prefers 2), or else 1."""
    chosen = version if version is not None else getattr(signer, "signature_version", 1)
    if chosen not in SIGNATURE_VERSIONS:
        raise ValueError(f"signature version {chosen!r} is not 1 or 2")
    return int(chosen)


def _check_signature(
    what: str,
    signature: Signature | None,
    verifier: Verifier | Keyring,
    payload: Callable[[str, str, int], bytes],
) -> None:
    if signature is None:
        raise ReceiptSignatureError(f"the {what} is not signed")
    if isinstance(verifier, Keyring):
        key = verifier.get(signature.key_id)
        if key is None:
            held = ", ".join(sorted(k.key_id for k in verifier)) or "none"
            raise ReceiptSignatureError(
                f"the {what} was signed by key {signature.key_id}, which is not among the "
                f"keys given ({held})"
            )
        verifier = key
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
    if not verifier.verify(
        payload(signature.alg, signature.key_id, signature.version), signature.value
    ):
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
    measurement: str = TRANSACTIONAL
    """How strongly the effect was measured: one of :data:`MEASUREMENTS`
    (ARC1 1.3). Written only when it is not :data:`TRANSACTIONAL`, so every
    receipt before 1.3 keeps its bytes and reads as transactional, which each
    of them was."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_tables", _as_set(self.observed_tables))
        object.__setattr__(self, "known_gaps", _as_set(self.known_gaps))
        if self.measurement not in MEASUREMENTS:
            raise MalformedReceiptError(
                f"coverage.measurement must be one of {', '.join(MEASUREMENTS)}, "
                f"not {self.measurement!r}"
            )

    def to_json(self) -> dict[str, Any]:
        found: dict[str, Any] = {
            "observed_tables": list(self.observed_tables),
            "cascade_closed": self.cascade_closed,
            "authorizer_on": self.authorizer_on,
            "known_gaps": list(self.known_gaps),
        }
        if self.measurement != TRANSACTIONAL:
            found["measurement"] = self.measurement
        return found

    @classmethod
    def from_json(cls, f: _Fields) -> Coverage:
        measurement = TRANSACTIONAL
        if f.has("measurement"):
            measurement = f.text("measurement")
            if measurement == TRANSACTIONAL:
                raise MalformedReceiptError(
                    f"{f.path('measurement')} is written only when it is not {TRANSACTIONAL!r}: "
                    f"a receipt that names none is transactional"
                )
        return cls(
            observed_tables=f.texts("observed_tables"),
            cascade_closed=f.boolean("cascade_closed"),
            authorizer_on=f.boolean("authorizer_on"),
            known_gaps=f.texts("known_gaps"),
            measurement=measurement,
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


def _txn_ids(f: _Fields, key: str) -> tuple[str, ...]:
    txn_ids = tuple(
        _check_pattern(t, _UUID, "a canonical lowercase UUID", f"{f.path(key)}[{i}]")
        for i, t in enumerate(f.array(key))
    )
    _check_set(txn_ids, f.path(key))
    return txn_ids


def _amount(f: _Fields, key: str) -> Decimal:
    amount = f.pattern(key, _MONEY, "a decimal string with exactly 8 places")
    try:
        return Decimal(amount)
    except InvalidOperation as exc:  # pragma: no cover - the pattern admits only decimals
        raise MalformedReceiptError(f"{f.path(key)} is not a decimal") from exc


_UNIT = re.compile(r"[a-z][a-z0-9_.-]{0,31}")
"""An AgentGov ledger's unit code (``agentgov.core.Unit``)."""


@dataclass(frozen=True)
class Quantity:
    """What the action consumed in a ledger of another unit (ARC1 1.3): a dose
    in ``mme``, capacity in ``vcpu``, seats. One ledger per unit, so the unit
    names the ledger, and ``ledger_txn_ids`` its transactions that settled it."""

    unit: str
    amount: Decimal
    ledger_txn_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _UNIT.fullmatch(self.unit):
            raise MalformedReceiptError(f"{self.unit!r} is not a unit code")
        object.__setattr__(self, "ledger_txn_ids", _as_set(self.ledger_txn_ids))

    def to_json(self) -> dict[str, Any]:
        return {
            "unit": self.unit,
            "amount": money_text(self.amount),
            "ledger_txn_ids": list(self.ledger_txn_ids),
        }

    @classmethod
    def from_json(cls, f: _Fields) -> Quantity:
        return cls(
            unit=f.pattern("unit", _UNIT, "a unit code"),
            amount=_amount(f, "amount"),
            ledger_txn_ids=_txn_ids(f, "ledger_txn_ids"),
        )


@dataclass(frozen=True)
class Cost:
    """What the action cost, as the ledgers recorded it.

    :ivar settled_usd: What the AgentGov ledger of US dollars settled, in its
        transactions ``ledger_txn_ids``: model spend and request prices.
    :ivar served_models: The models that served the action.
    :ivar quantities: What it consumed in ledgers of other units, by unit
        (ARC1 1.3).
    :ivar served_by: The systems other than models that served it: an MCP
        server, a cloud API, a clinical system (ARC1 1.3).

    ``quantities`` and ``served_by`` are written only when not empty, so every
    receipt before 1.3 keeps its bytes.
    """

    ledger_txn_ids: tuple[str, ...] = ()
    settled_usd: Decimal = Decimal("0")
    served_models: tuple[str, ...] = ()
    quantities: tuple[Quantity, ...] = ()
    served_by: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "ledger_txn_ids", _as_set(self.ledger_txn_ids))
        object.__setattr__(self, "served_models", _as_set(self.served_models))
        object.__setattr__(self, "served_by", _as_set(self.served_by))
        quantities = tuple(sorted(self.quantities, key=lambda q: _utf16_order(q.unit)))
        units = [q.unit for q in quantities]
        if len(set(units)) != len(units):
            raise MalformedReceiptError("cost.quantities names a unit twice")
        if any(q.amount < 0 for q in quantities):
            raise MalformedReceiptError("cost.quantities holds a negative amount")
        object.__setattr__(self, "quantities", quantities)

    def to_json(self) -> dict[str, Any]:
        found: dict[str, Any] = {
            "ledger_txn_ids": list(self.ledger_txn_ids),
            "settled_usd": money_text(self.settled_usd),
            "served_models": list(self.served_models),
        }
        if self.quantities:
            found["quantities"] = [q.to_json() for q in self.quantities]
        if self.served_by:
            found["served_by"] = list(self.served_by)
        return found

    @classmethod
    def from_json(cls, f: _Fields) -> Cost:
        quantities: list[Quantity] = []
        if f.has("quantities"):
            items = f.array("quantities")
            if not items:
                raise MalformedReceiptError(
                    f"{f.path('quantities')} is written only when it holds a quantity"
                )
            for index, item in enumerate(items):
                q = _Fields(
                    item, f"{f.path('quantities')}[{index}]", ("unit", "amount", "ledger_txn_ids")
                )
                quantities.append(Quantity.from_json(q))
            units = [q.unit for q in quantities]
            if units != sorted(units, key=_utf16_order):
                raise MalformedReceiptError(f"{f.path('quantities')} must be sorted by unit")
        served_by: tuple[str, ...] = ()
        if f.has("served_by"):
            served_by = f.texts("served_by")
            if not served_by:
                raise MalformedReceiptError(
                    f"{f.path('served_by')} is written only when it names a system"
                )
        return cls(
            ledger_txn_ids=_txn_ids(f, "ledger_txn_ids"),
            settled_usd=_amount(f, "settled_usd"),
            served_models=f.texts("served_models"),
            quantities=tuple(quantities),
            served_by=served_by,
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

    def signing_input(self, alg: str, key_id: str, version: int = 1) -> bytes:
        return _signing_input(RECEIPT_DOMAIN, self.body(), alg, key_id, version)

    # -- signing ----------------------------------------------------------

    async def sign_async(self, signer: AsyncSigner, *, version: int | None = None) -> ActionReceipt:
        """:meth:`sign`, awaiting the signer."""
        version = _signature_version(signer, version)
        message = self.signing_input(signer.alg, signer.key_id, version)
        value = await signer.sign_async(message)
        return replace(self, signature=Signature(signer.alg, signer.key_id, value, version))

    def sign(self, signer: Signer, *, version: int | None = None) -> ActionReceipt:
        """A copy signed by ``signer``."""
        version = _signature_version(signer, version)
        value = signer.sign(self.signing_input(signer.alg, signer.key_id, version))
        return replace(self, signature=Signature(signer.alg, signer.key_id, value, version))

    def verify(self, verifier: Verifier | Keyring) -> None:
        """:raises ReceiptSignatureError: Unless ``verifier``'s key signed this
        (given a keyring, the key the signature names, if the keyring holds it)."""
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
        sig = f.optional_child("sig", _sig_fields(f.raw("sig")))
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
                    "coverage",
                    ("observed_tables", "cascade_closed", "authorizer_on", "known_gaps"),
                    ("measurement",),
                )
            ),
            decision=Decision.from_json(
                f.child(
                    "decision",
                    ("verdict_hash", "admitted", "checkers", "policy_epoch", "repair_of"),
                )
            ),
            cost=Cost.from_json(
                f.child(
                    "cost",
                    ("ledger_txn_ids", "settled_usd", "served_models"),
                    ("quantities", "served_by"),
                )
            ),
            outcome=Outcome.from_json(f.child("outcome", ("status", "substrate_txid"))),
            anchors=Anchors.from_json(f.child("anchors", ("agentgov", "escrow", "log"))),
            signature=Signature.from_json(sig) if sig else None,
        )

    @classmethod
    def loads(cls, text: str | bytes) -> ActionReceipt:
        return cls.from_json(loads_strict(text))


# --------------------------------------------------------------------------
# Deliveries (ARC1 v1.1)
#
# An action receipt proves what was authorized and committed. A delivery
# receipt proves what was then sent to an external system, and what that
# system answered. Two parties see those two things: the relay that made the
# call signs an attestation of the answer the moment it arrives; the log that
# holds the action receipt signs the delivery receipt that carries it.
# --------------------------------------------------------------------------

DELIVERY_RESULTS = ("delivered", "retryable", "permanent", "unknown")


@dataclass(frozen=True)
class DeliveredRequest:
    """The request a relay sent: the outbox row the action receipt's row
    commitment covers, as the relay read it."""

    message_id: str
    effect_id: str
    sink: str
    operation: str
    payload_hash: str
    idempotency_key: str

    def to_json(self) -> dict[str, Any]:
        return {
            "message_id": self.message_id,
            "effect_id": self.effect_id,
            "sink": self.sink,
            "operation": self.operation,
            "payload_hash": self.payload_hash,
            "idempotency_key": self.idempotency_key,
        }

    @classmethod
    def from_json(cls, f: _Fields) -> DeliveredRequest:
        return cls(
            message_id=f.uuid("message_id"),
            effect_id=f.text("effect_id"),
            sink=f.text("sink"),
            operation=f.text("operation"),
            payload_hash=f.hex64("payload_hash"),
            idempotency_key=f.text("idempotency_key"),
        )


_REQUEST_FIELDS = (
    "message_id",
    "effect_id",
    "sink",
    "operation",
    "payload_hash",
    "idempotency_key",
)


def _check_status(value: int | None, path: str) -> int | None:
    if value is not None and not 100 <= value <= 599:
        raise MalformedReceiptError(f"{path} is an HTTP status, 100 to 599")
    return value


@dataclass(frozen=True)
class AttestedOutcome:
    """What a call returned, as the relay that made it saw it."""

    attempt: int
    result: str
    status_code: int | None = None
    response_digest: str | None = None
    remote_ref: str | None = None

    def __post_init__(self) -> None:
        if self.result not in DELIVERY_RESULTS:
            raise MalformedReceiptError(
                f"an outcome's result is one of {', '.join(DELIVERY_RESULTS)}, not {self.result!r}"
            )
        if self.attempt < 1:
            raise MalformedReceiptError("an outcome's attempt counts from 1")
        _check_status(self.status_code, "outcome.status_code")

    def to_json(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "result": self.result,
            "status_code": self.status_code,
            "response_digest": self.response_digest,
            "remote_ref": self.remote_ref,
        }

    @classmethod
    def from_json(cls, f: _Fields) -> AttestedOutcome:
        digest = f.raw("response_digest")
        return cls(
            attempt=f.integer("attempt", minimum=1),
            result=f.text("result"),
            status_code=f.optional_integer("status_code"),
            response_digest=None if digest is None else f.hex64("response_digest"),
            remote_ref=f.optional_text("remote_ref"),
        )


@dataclass(frozen=True)
class Attestation:
    """``ARC1-attestation``: a relay's signed statement of one call's outcome,
    made when the answer arrived, with the relay's own key.

    It travels as its signature alone: a delivery receipt carries the request
    and the outcome it covers, and :meth:`DeliveryReceipt.attested` rebuilds
    it to verify.
    """

    request: DeliveredRequest
    outcome: AttestedOutcome
    signature: Signature | None = None

    def body(self) -> dict[str, Any]:
        return {
            "v": ATTESTATION_VERSION,
            "request": self.request.to_json(),
            "outcome": self.outcome.to_json(),
        }

    def to_json(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.signature.to_json() if self.signature else None}

    def signing_input(self, alg: str, key_id: str, version: int = 1) -> bytes:
        return _signing_input(ATTESTATION_DOMAIN, self.body(), alg, key_id, version)

    def sign(self, signer: Signer, *, version: int | None = None) -> Attestation:
        version = _signature_version(signer, version)
        value = signer.sign(self.signing_input(signer.alg, signer.key_id, version))
        return replace(self, signature=Signature(signer.alg, signer.key_id, value, version))

    def verify(self, verifier: Verifier | Keyring) -> None:
        """:raises ReceiptSignatureError: Unless ``verifier``'s key signed this
        (given a keyring, the key the signature names, if the keyring holds it)."""
        _check_signature("attestation", self.signature, verifier, self.signing_input)

    @classmethod
    def from_json(cls, value: object, path: str = "attestation") -> Attestation:
        f = _Fields(value, path, ("v", "request", "outcome", "sig"))
        f.version(ATTESTATION_VERSION)
        sig = f.optional_child("sig", _sig_fields(f.raw("sig")))
        return cls(
            request=DeliveredRequest.from_json(f.child("request", _REQUEST_FIELDS)),
            outcome=AttestedOutcome.from_json(f.child("outcome", _OUTCOME_FIELDS)),
            signature=Signature.from_json(sig) if sig else None,
        )


_OUTCOME_FIELDS = ("attempt", "result", "status_code", "response_digest", "remote_ref")


@dataclass(frozen=True)
class ActionBinding:
    """The action receipt a delivery follows from: its id, its place in a
    receipt log, and its leaf hash, ``SHA-256(0x00 || canonical(receipt))``,
    which binds its exact signed bytes."""

    receipt_id: str
    log_id: str
    leaf_index: int
    leaf_hash: str

    @classmethod
    def of(cls, receipt: ActionReceipt) -> ActionBinding:
        """The binding to ``receipt``, which must already have its place in a log.

        :raises MalformedReceiptError: If it is unsigned or has no place.
        """
        anchor = receipt.anchors.log
        if anchor is None or receipt.signature is None:
            raise MalformedReceiptError(
                "a delivery binds to a signed action receipt with its place in a log"
            )
        return cls(
            receipt_id=receipt.receipt_id,
            log_id=anchor.log_id,
            leaf_index=anchor.leaf_index,
            leaf_hash=receipt.leaf_hash().hex(),
        )

    def problem(self, receipt: ActionReceipt) -> str | None:
        """Why ``receipt`` is not the one bound, or ``None`` if it is."""
        anchor = receipt.anchors.log
        if receipt.receipt_id != self.receipt_id:
            return f"it binds receipt {self.receipt_id}, not {receipt.receipt_id}"
        if anchor is None or (anchor.log_id, anchor.leaf_index) != (self.log_id, self.leaf_index):
            placed = f"{anchor.log_id}#{anchor.leaf_index}" if anchor else "no place"
            return (
                f"it binds leaf {self.leaf_index} of log {self.log_id!r}; the receipt is at "
                f"{placed}"
            )
        if receipt.leaf_hash().hex() != self.leaf_hash:
            return (
                f"it binds leaf hash {self.leaf_hash[:16]}; the receipt hashes to "
                f"{receipt.leaf_hash().hex()[:16]}: a different or altered receipt"
            )
        return None

    def to_json(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "log_id": self.log_id,
            "leaf_index": self.leaf_index,
            "leaf_hash": self.leaf_hash,
        }

    @classmethod
    def from_json(cls, f: _Fields) -> ActionBinding:
        return cls(
            receipt_id=f.uuid("receipt_id"),
            log_id=f.text("log_id"),
            leaf_index=f.integer("leaf_index"),
            leaf_hash=f.hex64("leaf_hash"),
        )


@dataclass(frozen=True)
class Delivery:
    """The call that delivered: its attempt, the sink's answer, and the row
    of the message's delivery log that recorded it."""

    attempt: int
    status_code: int | None
    response_digest: str | None
    remote_ref: str | None
    delivered_at: datetime
    log_seq: int
    log_hash: str

    def __post_init__(self) -> None:
        if self.attempt < 1 or self.log_seq < 1:
            raise MalformedReceiptError("a delivery's attempt and log_seq count from 1")
        _check_status(self.status_code, "delivery.status_code")

    def outcome(self) -> AttestedOutcome:
        return AttestedOutcome(
            attempt=self.attempt,
            result="delivered",
            status_code=self.status_code,
            response_digest=self.response_digest,
            remote_ref=self.remote_ref,
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "attempt": self.attempt,
            "status_code": self.status_code,
            "response_digest": self.response_digest,
            "remote_ref": self.remote_ref,
            "delivered_at": instant(self.delivered_at),
            "log_seq": self.log_seq,
            "log_hash": self.log_hash,
        }

    @classmethod
    def from_json(cls, f: _Fields) -> Delivery:
        digest = f.raw("response_digest")
        return cls(
            attempt=f.integer("attempt", minimum=1),
            status_code=f.optional_integer("status_code"),
            response_digest=None if digest is None else f.hex64("response_digest"),
            remote_ref=f.optional_text("remote_ref"),
            delivered_at=f.instant("delivered_at"),
            log_seq=f.integer("log_seq", minimum=1),
            log_hash=f.hex64("log_hash"),
        )


_DELIVERY_FIELDS = (
    "v",
    "receipt_id",
    "issued_at",
    "issuer",
    "action",
    "request",
    "delivery",
    "attestation",
    "anchors",
    "sig",
)


@dataclass(frozen=True)
class DeliveryReceipt:
    """``ARC1-delivery``: a signed record that a committed request was
    delivered, bound to the action receipt that committed it.

    :ivar action: The action receipt of the plan that committed the request.
    :ivar request: The request sent, as the outbox committed it.
    :ivar delivery: The call that delivered, and the delivery-log row that
        recorded it.
    :ivar attestation: The relay's signature over ``request`` and the
        delivery's outcome (:meth:`attested`).
    :raises MalformedReceiptError: If it claims a place in the action
        receipt's log at or before the action receipt's.
    """

    receipt_id: str
    issued_at: datetime
    issuer: str
    action: ActionBinding
    request: DeliveredRequest
    delivery: Delivery
    attestation: Signature
    anchors: Anchors = field(default_factory=Anchors)
    signature: Signature | None = None

    domain: ClassVar[bytes] = DELIVERY_DOMAIN

    def __post_init__(self) -> None:
        placed = self.anchors.log
        if (
            placed is not None
            and placed.log_id == self.action.log_id
            and placed.leaf_index <= self.action.leaf_index
        ):
            raise MalformedReceiptError(
                f"a delivery at leaf {placed.leaf_index} cannot follow from the action receipt "
                f"at leaf {self.action.leaf_index} of the same log: it was delivered after it "
                f"was committed"
            )

    def attested(self) -> Attestation:
        """The relay's attestation this receipt carries, rebuilt to verify."""
        return Attestation(
            request=self.request, outcome=self.delivery.outcome(), signature=self.attestation
        )

    # -- encoding ---------------------------------------------------------

    def body(self) -> dict[str, Any]:
        return {
            "v": DELIVERY_VERSION,
            "receipt_id": self.receipt_id,
            "issued_at": instant(self.issued_at),
            "issuer": self.issuer,
            "action": self.action.to_json(),
            "request": self.request.to_json(),
            "delivery": self.delivery.to_json(),
            "attestation": self.attestation.to_json(),
            "anchors": self.anchors.to_json(),
        }

    def to_json(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.signature.to_json() if self.signature else None}

    def canonical(self) -> bytes:
        """The canonical encoding, signature included: its leaf data in a log."""
        return canonical_bytes(self.to_json())

    def leaf_hash(self) -> bytes:
        return leaf_hash(self.canonical())

    def signing_input(self, alg: str, key_id: str, version: int = 1) -> bytes:
        return _signing_input(DELIVERY_DOMAIN, self.body(), alg, key_id, version)

    # -- signing ----------------------------------------------------------

    async def sign_async(
        self, signer: AsyncSigner, *, version: int | None = None
    ) -> DeliveryReceipt:
        """:meth:`sign`, awaiting the signer."""
        version = _signature_version(signer, version)
        message = self.signing_input(signer.alg, signer.key_id, version)
        value = await signer.sign_async(message)
        return replace(self, signature=Signature(signer.alg, signer.key_id, value, version))

    def sign(self, signer: Signer, *, version: int | None = None) -> DeliveryReceipt:
        version = _signature_version(signer, version)
        value = signer.sign(self.signing_input(signer.alg, signer.key_id, version))
        return replace(self, signature=Signature(signer.alg, signer.key_id, value, version))

    def verify(self, verifier: Verifier | Keyring) -> None:
        """:raises ReceiptSignatureError: Unless ``verifier``'s key signed this
        (given a keyring, the key the signature names, if the keyring holds it)."""
        _check_signature("delivery receipt", self.signature, verifier, self.signing_input)

    def with_log_anchor(self, log_id: str, leaf_index: int) -> DeliveryReceipt:
        """An unsigned copy that claims a position in a receipt log."""
        anchors = replace(self.anchors, log=LogAnchor(log_id=log_id, leaf_index=leaf_index))
        return replace(self, anchors=anchors, signature=None)

    # -- decoding ---------------------------------------------------------

    @classmethod
    def from_json(cls, value: object, path: str = "delivery") -> DeliveryReceipt:
        """Decode and validate one delivery receipt.

        :raises MalformedReceiptError: On anything the schema does not allow.
        """
        f = _Fields(value, path, _DELIVERY_FIELDS)
        f.version(DELIVERY_VERSION)
        sig = f.optional_child("sig", _sig_fields(f.raw("sig")))
        return cls(
            receipt_id=f.uuid("receipt_id"),
            issued_at=f.instant("issued_at"),
            issuer=f.text("issuer"),
            action=ActionBinding.from_json(
                f.child("action", ("receipt_id", "log_id", "leaf_index", "leaf_hash"))
            ),
            request=DeliveredRequest.from_json(f.child("request", _REQUEST_FIELDS)),
            delivery=Delivery.from_json(
                f.child(
                    "delivery",
                    (
                        "attempt",
                        "status_code",
                        "response_digest",
                        "remote_ref",
                        "delivered_at",
                        "log_seq",
                        "log_hash",
                    ),
                )
            ),
            attestation=Signature.from_json(
                f.child("attestation", _sig_fields(f.raw("attestation")))
            ),
            anchors=Anchors.from_json(f.child("anchors", ("agentgov", "escrow", "log"))),
            signature=Signature.from_json(sig) if sig else None,
        )

    @classmethod
    def loads(cls, text: str | bytes) -> DeliveryReceipt:
        return cls.from_json(loads_strict(text))


LogDocument = ActionReceipt | DeliveryReceipt
"""What a receipt log's leaves are: action receipts and, from ARC1 v1.1,
delivery receipts."""


def document_from_json(value: object, path: str = "receipt") -> LogDocument:
    """Decode a log leaf of either kind, by its ``v``.

    :raises MalformedReceiptError: If it is neither.
    """
    kind = value.get("v") if isinstance(value, dict) else None
    if kind == DELIVERY_VERSION:
        return DeliveryReceipt.from_json(value, path)
    return ActionReceipt.from_json(value, path)


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

    def signing_input(self, alg: str, key_id: str, version: int = 1) -> bytes:
        return _signing_input(CHECKPOINT_DOMAIN, self.body(), alg, key_id, version)

    def sign(self, signer: Signer, *, version: int | None = None) -> Checkpoint:
        version = _signature_version(signer, version)
        value = signer.sign(self.signing_input(signer.alg, signer.key_id, version))
        return replace(self, signature=Signature(signer.alg, signer.key_id, value, version))

    def verify(self, verifier: Verifier | Keyring) -> None:
        """:raises ReceiptSignatureError: Unless the log's key signed this
        (given a keyring, the key the signature names, if the keyring holds it)."""
        _check_signature("checkpoint", self.signature, verifier, self.signing_input)

    @classmethod
    def from_json(cls, value: object, path: str = "checkpoint") -> Checkpoint:
        f = _Fields(value, path, ("v", "log_id", "tree_size", "root_hash", "issued_at", "sig"))
        f.version(CHECKPOINT_VERSION)
        sig = f.optional_child("sig", _sig_fields(f.raw("sig")))
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

    def signing_input(self, alg: str, key_id: str, version: int = 1) -> bytes:
        return _signing_input(COSIGNATURE_DOMAIN, self.body(), alg, key_id, version)

    def sign(self, signer: Signer, *, version: int | None = None) -> Cosignature:
        version = _signature_version(signer, version)
        value = signer.sign(self.signing_input(signer.alg, signer.key_id, version))
        return replace(self, signature=Signature(signer.alg, signer.key_id, value, version))

    def verify(self, verifier: Verifier | Keyring) -> None:
        """:raises ReceiptSignatureError: Unless the witness's key signed this
        (given a keyring, the key the signature names, if the keyring holds it)."""
        _check_signature("cosignature", self.signature, verifier, self.signing_input)

    @classmethod
    def from_json(cls, value: object, path: str = "cosignature") -> Cosignature:
        f = _Fields(
            value,
            path,
            ("v", "witness_id", "log_id", "tree_size", "root_hash", "witnessed_at", "sig"),
        )
        f.version(COSIGNATURE_VERSION)
        sig = f.optional_child("sig", _sig_fields(f.raw("sig")))
        return cls(
            witness_id=f.text("witness_id"),
            log_id=f.text("log_id"),
            tree_size=f.integer("tree_size"),
            root_hash=f.hex64("root_hash"),
            witnessed_at=f.instant("witnessed_at"),
            signature=Signature.from_json(sig) if sig else None,
        )


# --------------------------------------------------------------------------
# Key transitions (ARC1 1.2): a log outlives its key
# --------------------------------------------------------------------------

_TRANSITION_FIELDS = ("v", "log_id", "tree_size", "incoming", "issued_at", "sig")
_INCOMING_FIELDS = ("alg", "key_id", "public_key")


@dataclass(frozen=True)
class KeyTransition:
    """A log's outgoing key handing the log to its incoming key.

    Signed by the outgoing key, it names the incoming key and the tree size
    ``tree_size`` at which the hand-over happens: the leaves from index
    ``tree_size`` on, and every checkpoint larger than ``tree_size``, are the
    incoming key's to sign; the outgoing key keeps the leaves before and the
    checkpoints up to that size. An Ed25519 incoming key is named with its
    public key, so a verifier who trusts only the outgoing key learns the
    incoming one from the transition; an HMAC key is named by id alone, and a
    verifier must already hold it.
    """

    log_id: str
    tree_size: int
    incoming_alg: str
    incoming_key_id: str
    incoming_public_key: str | None
    issued_at: datetime
    signature: Signature | None = None

    @classmethod
    def of(
        cls, log_id: str, tree_size: int, incoming: Verifier, issued_at: datetime
    ) -> KeyTransition:
        """An unsigned transition to ``incoming`` at ``tree_size``."""
        raw = getattr(incoming, "raw", None)
        public = raw.hex() if incoming.alg == ALG_ED25519 and isinstance(raw, bytes) else None
        if incoming.alg == ALG_ED25519 and public is None:
            raise ValueError("an Ed25519 incoming key is named by its public key")
        return cls(
            log_id=_check_text(log_id, "log_id"),
            tree_size=_check_int(tree_size, "tree_size"),
            incoming_alg=incoming.alg,
            incoming_key_id=incoming.key_id,
            incoming_public_key=public,
            issued_at=issued_at,
        )

    def body(self) -> dict[str, Any]:
        return {
            "v": TRANSITION_VERSION,
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "incoming": {
                "alg": self.incoming_alg,
                "key_id": self.incoming_key_id,
                "public_key": self.incoming_public_key,
            },
            "issued_at": instant(self.issued_at),
        }

    def to_json(self) -> dict[str, Any]:
        return {**self.body(), "sig": self.signature.to_json() if self.signature else None}

    def signing_input(self, alg: str, key_id: str, version: int = 1) -> bytes:
        return _signing_input(TRANSITION_DOMAIN, self.body(), alg, key_id, version)

    def sign(self, signer: Signer, *, version: int | None = None) -> KeyTransition:
        """Signed by the outgoing key."""
        version = _signature_version(signer, version)
        value = signer.sign(self.signing_input(signer.alg, signer.key_id, version))
        return replace(self, signature=Signature(signer.alg, signer.key_id, value, version))

    def verify(self, verifier: Verifier | Keyring) -> None:
        """:raises ReceiptSignatureError: Unless the outgoing key signed this."""
        _check_signature("key transition", self.signature, verifier, self.signing_input)

    def incoming(self, trusted: Keyring | None = None) -> Verifier | None:
        """The incoming key: from its public key, or for an HMAC key, the one
        ``trusted`` holds under its id."""
        if self.incoming_public_key is not None:
            return Ed25519PublicKey(bytes.fromhex(self.incoming_public_key))
        return trusted.get(self.incoming_key_id) if trusted is not None else None

    @classmethod
    def from_json(cls, value: object, path: str = "transition") -> KeyTransition:
        f = _Fields(value, path, _TRANSITION_FIELDS)
        f.version(TRANSITION_VERSION)
        incoming = f.child("incoming", _INCOMING_FIELDS)
        alg = incoming.raw("alg")
        if alg not in _SIGNATURE_BYTES:
            raise MalformedReceiptError(
                f"{incoming.path('alg')} must be {ALG_ED25519!r} or {ALG_HMAC_SHA256!r}"
            )
        key_id = incoming.pattern("key_id", _KEY_ID, "16 lowercase hex characters")
        public = incoming.raw("public_key")
        if alg == ALG_ED25519:
            public = incoming.hex64("public_key")
            if Ed25519PublicKey(bytes.fromhex(public)).key_id != key_id:
                raise MalformedReceiptError(
                    f"{incoming.path('key_id')} is not the id of the public key it names"
                )
        elif public is not None:
            raise MalformedReceiptError(
                f"{incoming.path('public_key')} must be null: an HMAC key is never published"
            )
        sig = f.optional_child("sig", _sig_fields(f.raw("sig")))
        return cls(
            log_id=f.text("log_id"),
            tree_size=f.integer("tree_size"),
            incoming_alg=alg,
            incoming_key_id=key_id,
            incoming_public_key=public,
            issued_at=f.instant("issued_at"),
            signature=Signature.from_json(sig) if sig else None,
        )

    @classmethod
    def loads(cls, text: str | bytes) -> KeyTransition:
        return cls.from_json(loads_strict(text))


class KeySchedule:
    """Which key signs which part of a log: the key a verifier trusts, then
    each key a verified transition hands the log to.

    :param log_id: The log the transitions must be for.
    :param trusted: The keys the verifier trusts. The first transition must
        be signed by one of them; an HMAC incoming key must be one of them.
    :param transitions: The log's transitions, in order. Each is signed by
        the key the one before handed the log to, at a size no smaller.
    :raises ReceiptSignatureError: If a transition is not signed by the key
        in force before it, or hands the log to a key the verifier cannot use.
    :raises MalformedReceiptError: If a transition is for another log, or
        goes back in size.
    """

    __slots__ = ("_eras", "_log_id", "_transitions")

    def __init__(self, log_id: str, trusted: Keyring, transitions: Sequence[KeyTransition]) -> None:
        if not transitions:
            raise ValueError("a key schedule follows at least one transition")
        self._log_id = log_id
        self._transitions = tuple(transitions)
        first = transitions[0]
        if first.signature is None:
            raise ReceiptSignatureError(f"the first key transition of log {log_id!r} is not signed")
        current = trusted.get(first.signature.key_id)
        if current is None:
            raise ReceiptSignatureError(
                f"the first key transition of log {log_id!r} is signed by key "
                f"{first.signature.key_id}, which is not among the keys trusted"
            )
        eras: list[tuple[int, Verifier]] = [(0, current)]
        size = 0
        for number, transition in enumerate(transitions, start=1):
            if transition.log_id != log_id:
                raise MalformedReceiptError(
                    f"key transition {number} is for log {transition.log_id!r}, not {log_id!r}"
                )
            if transition.tree_size < size:
                raise MalformedReceiptError(
                    f"key transition {number} hands the log over at size "
                    f"{transition.tree_size}, before the size {size} of the one before it"
                )
            try:
                transition.verify(current)
            except ReceiptSignatureError as exc:
                raise ReceiptSignatureError(
                    f"key transition {number} of log {log_id!r} is not signed by the key in "
                    f"force before it ({current.key_id}): {exc}"
                ) from exc
            incoming = transition.incoming(trusted)
            if incoming is None:
                raise ReceiptSignatureError(
                    f"key transition {number} hands log {log_id!r} to HMAC key "
                    f"{transition.incoming_key_id}, which is not among the keys trusted"
                )
            size, current = transition.tree_size, incoming
            eras.append((size, current))
        self._eras = tuple(eras)

    @property
    def log_id(self) -> str:
        return self._log_id

    @property
    def transitions(self) -> tuple[KeyTransition, ...]:
        return self._transitions

    @property
    def current(self) -> Verifier:
        """The key that signs the log's next leaves and checkpoints."""
        return self._eras[-1][1]

    @property
    def boundary(self) -> int:
        """The size at which the current key took the log over."""
        return self._eras[-1][0]

    def for_leaf(self, index: int) -> Verifier:
        """The key that signs the leaf at ``index``."""
        key = self._eras[0][1]
        for size, era_key in self._eras[1:]:
            if index >= size:
                key = era_key
        return key

    def for_checkpoint(self, tree_size: int) -> Verifier:
        """The key that signs a checkpoint of ``tree_size`` leaves."""
        key = self._eras[0][1]
        for size, era_key in self._eras[1:]:
            if tree_size > size:
                key = era_key
        return key

    def keyring(self) -> Keyring:
        """Every key of the schedule."""
        return Keyring(key for _, key in self._eras)


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
    """What a verifier is handed: a receipt (an action receipt, or from ARC1
    v1.1 a delivery receipt), and optionally the checkpoint and audit path
    proving the receipt is in that log."""

    receipt: LogDocument
    inclusion: InclusionProof | None = None
    checkpoint: Checkpoint | None = None

    def __post_init__(self) -> None:
        if (self.inclusion is None) != (self.checkpoint is None):
            raise MalformedReceiptError(
                "a bundle carries an inclusion proof and its checkpoint together, or neither"
            )

    @property
    def action_receipt(self) -> ActionReceipt:
        """The receipt, which must be an action receipt.

        :raises MalformedReceiptError: If it is a delivery receipt.
        """
        if not isinstance(self.receipt, ActionReceipt):
            raise MalformedReceiptError(
                "the bundle holds a delivery receipt, not an action receipt"
            )
        return self.receipt

    @property
    def delivery_receipt(self) -> DeliveryReceipt:
        """The receipt, which must be a delivery receipt.

        :raises MalformedReceiptError: If it is an action receipt.
        """
        if not isinstance(self.receipt, DeliveryReceipt):
            raise MalformedReceiptError(
                "the bundle holds an action receipt, not a delivery receipt"
            )
        return self.receipt

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
            receipt=document_from_json(f.raw("receipt"), "bundle.receipt"),
            inclusion=InclusionProof.from_json(inclusion) if inclusion else None,
            checkpoint=Checkpoint.from_json(checkpoint, "bundle.checkpoint")
            if checkpoint is not None
            else None,
        )

    @classmethod
    def loads(cls, text: str | bytes) -> ReceiptBundle:
        """Decode a bundle, or a bare receipt of either kind as a bundle
        without a proof."""
        value = loads_strict(text)
        if isinstance(value, dict) and value.get("v") in (RECEIPT_VERSION, DELIVERY_VERSION):
            return cls(receipt=document_from_json(value))
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
