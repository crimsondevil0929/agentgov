"""Generate the AGOV ledger-format conformance vectors in ``vectors/agov/``.

Everything is deterministic: every identifier is a UUIDv5 of a fixed name,
the clock is fixed, and the chain is built by the ledger's own engine, so
running this twice writes identical bytes. ``tests/test_ledger_format.py``
regenerates the vectors on every CI run and fails if a committed file differs
from what the code produces today; the vectors are what an implementation in
another language checks itself against (docs/LEDGER_FORMAT.md).

- ``entries.json``: single entries of every type and every version, each with
  the exact bytes its hash covers and the hash.
- ``chain.json``: a chain from genesis, with the state it implies, a checkpoint
  snapshot of it, and that snapshot's digest.
- ``invalid.json``: chains that break exactly one rule each, with the rule.

Usage::

    uv run python scripts/generate_agov_vectors.py [--out vectors/agov]
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import shutil
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import agentgov.core as core
from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.core import (
    GENESIS_HASH,
    Direction,
    EntryType,
    LedgerEntry,
    LedgerLine,
    _encode_snapshot,
    _frontier_root,
    _hash_entry,
    _iso,
    _replay,
    _snapshot_digest,
)
from agentgov.exceptions import LedgerIntegrityError

NAMESPACE = uuid.UUID("6f1c5d3e-8a4b-5c2d-9e7f-0a1b2c3d4e5f")
EPOCH = datetime(2026, 10, 11, tzinfo=UTC)


def _id(name: str) -> uuid.UUID:
    return uuid.uuid5(NAMESPACE, name)


@contextmanager
def _deterministic() -> Iterator[None]:
    """Fixed identifiers and a fixed clock for the engine, for the duration."""
    counter = {"id": 0, "tick": 0}
    real_uuid4, real_datetime = core.uuid.uuid4, core.datetime

    def uuid4() -> uuid.UUID:
        counter["id"] += 1
        return _id(f"id-{counter['id']}")

    class Clock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> Any:  # type: ignore[override]
            counter["tick"] += 1
            return EPOCH + timedelta(milliseconds=counter["tick"])

    core.uuid.uuid4 = uuid4  # type: ignore[assignment]
    core.datetime = Clock  # type: ignore[misc]
    try:
        yield
    finally:
        core.uuid.uuid4 = real_uuid4  # type: ignore[assignment]
        core.datetime = real_datetime  # type: ignore[misc]


def _document(entry: LedgerEntry) -> dict[str, Any]:
    return entry.to_audit_record()


def _payload(entry: LedgerEntry) -> str:
    """The exact text the entry's hash covers, per its version."""
    if entry.version == "AGOV3":
        return json.dumps(
            {
                "amount": core._fixed(entry.amount),
                "balance_after": core._fixed(entry.balance_after),
                "counterparty_id": entry.counterparty_id,
                "direction": entry.direction.value,
                "entry_id": str(entry.entry_id),
                "entry_type": entry.entry_type.value,
                "format": "AGOV3",
                "memo": entry.memo,
                "prev_hash": entry.prev_hash,
                "ref": str(entry.ref) if entry.ref is not None else None,
                "scope_id": entry.scope_id,
                "sequence": entry.sequence,
                "timestamp": _iso(entry.timestamp),
                "transaction_id": str(entry.transaction_id),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    fields: list[object] = [
        entry.version,
        entry.prev_hash,
        entry.sequence,
        str(entry.entry_id),
        str(entry.transaction_id),
        _iso(entry.timestamp),
        entry.entry_type.value,
        entry.direction.value,
        entry.scope_id,
        entry.counterparty_id,
        str(entry.amount),
        str(entry.balance_after),
        entry.memo,
    ]
    if entry.version == "AGOV2":
        fields.append(str(entry.ref) if entry.ref is not None else None)
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=True)


def _hashed(**fields: Any) -> LedgerEntry:
    digest = _hash_entry(**{k: v for k, v in fields.items() if k != "entry_hash"})
    return LedgerEntry(**{**fields, "entry_hash": digest})


def _entry_cases() -> list[dict[str, Any]]:
    """Single entries: every type, every version, and the awkward values."""
    base: dict[str, Any] = dict(
        prev_hash=GENESIS_HASH,
        sequence=1,
        transaction_id=_id("txn"),
        timestamp=EPOCH,
        counterparty_id=None,
        memo="",
        ref=None,
        version="AGOV3",
    )

    def case(name: str, **fields: Any) -> dict[str, Any]:
        entry = _hashed(**{**base, "entry_id": _id(name), **fields})
        return {
            "name": name,
            "entry": _document(entry),
            "hashed": _payload(entry),
            "sha256": entry.entry_hash,
        }

    cases = [
        case(
            "funding",
            entry_type=EntryType.FUNDING,
            direction=Direction.CREDIT,
            scope_id="root",
            amount=money("1000"),
            balance_after=money("1000"),
            memo="root envelope issued",
        ),
        case(
            "smallest-amount",
            entry_type=EntryType.SPEND,
            direction=Direction.DEBIT,
            scope_id="agent",
            amount=money("0.00000001"),
            balance_after=money("0.99999999"),
        ),
        case(
            "largest-amount",
            entry_type=EntryType.FUNDING,
            direction=Direction.CREDIT,
            scope_id="treasury",
            amount=money("1000000000000"),
            balance_after=money("1000000000000"),
        ),
        case(
            "negative-balance",
            entry_type=EntryType.SPEND,
            direction=Direction.DEBIT,
            scope_id="agent",
            amount=money("0.5"),
            balance_after=money("-0.25"),
            ref=_id("hold"),
        ),
        case(
            "allocation-credit",
            entry_type=EntryType.ALLOCATION,
            direction=Direction.CREDIT,
            scope_id="researcher",
            counterparty_id="orchestrator",
            amount=money("0.25"),
            balance_after=money("0.25"),
            memo="sub-budget delegated to researcher",
        ),
        case(
            "hold-release",
            entry_type=EntryType.HOLD_VOID,
            direction=Direction.CREDIT,
            scope_id="agent",
            amount=money("0.02"),
            balance_after=money("1"),
            ref=_id("hold"),
        ),
        case(
            "named-refund",
            entry_type=EntryType.REVERSAL,
            direction=Direction.CREDIT,
            scope_id="agent",
            amount=money("0.01"),
            balance_after=money("0.99"),
            ref=_id("spend"),
        ),
        case(
            "trip",
            entry_type=EntryType.CIRCUIT_TRIPPED,
            direction=Direction.NONE,
            scope_id="agent",
            amount=Decimal(0),
            balance_after=money("0.5"),
            memo="overdraft attempt: requested 0.60000000, available 0.50000000",
        ),
        case(
            "checkpoint",
            entry_type=EntryType.CHECKPOINT,
            direction=Direction.NONE,
            scope_id="",
            amount=Decimal(0),
            balance_after=Decimal(0),
            sequence=10_001,
            memo=f"agentgov-checkpoint v1 seq=10000 sha256={'ab' * 32}",
        ),
        case(
            "text-needing-escapes",
            entry_type=EntryType.ANCHOR,
            direction=Direction.NONE,
            scope_id="t\u00e9am/\u4e2d\u6587 \U0001f4b8",
            amount=Decimal(0),
            balance_after=Decimal(0),
            memo='quote " backslash \\ tab \t newline \n bell \x07 del \x7f sep \u2028 end',
        ),
    ]
    legacy = dict(base, version="AGOV2")
    cases.append(
        {
            "name": "agov2-spend",
            **_legacy_case(
                legacy,
                "agov2-spend",
                entry_type=EntryType.SPEND,
                direction=Direction.DEBIT,
                scope_id="agent",
                amount=money("0.00000001"),
                balance_after=money("0.99999999"),
                ref=_id("hold"),
            ),
        }
    )
    oldest = dict(base, version="AGOV1")
    cases.append(
        {
            "name": "agov1-funding",
            **_legacy_case(
                oldest,
                "agov1-funding",
                entry_type=EntryType.FUNDING,
                direction=Direction.CREDIT,
                scope_id="root",
                amount=money("1"),
                balance_after=money("1"),
            ),
        }
    )
    return cases


def _legacy_case(base: dict[str, Any], name: str, **fields: Any) -> dict[str, Any]:
    entry = _hashed(**{**base, "entry_id": _id(name), **fields})
    return {"entry": _document(entry), "hashed": _payload(entry), "sha256": entry.entry_hash}


def _chain() -> tuple[list[LedgerEntry], dict[str, Any]]:
    """A chain with every kind of event, built by the engine itself."""
    with _deterministic():
        gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
        gov.open_root("orchestrator", money("10.00"))
        gov.delegate("orchestrator", "researcher", money("2.50"))
        gov.delegate("orchestrator", "writer", money("1.00"))
        hold = gov.authorize("researcher", money("0.40"))
        gov.capture(hold, money("0.31"))
        spend = gov.spend("writer", money("0.25"))
        gov.refund("writer", money("0.05"), reverses=spend)
        gov.authorize("researcher", money("0.10"))  # left open
        void = gov.authorize("writer", money("0.10"))
        gov.void(void)
        gov.release("writer", money("0.20"))
        gov.fund("orchestrator", money("5.00"))
        gov.trip("writer", "operator halt")
        gov.anchor("orchestrator", "escrow head 9f2c")
        state = gov.ledger._state
        snapshot = _encode_snapshot(state)
        sequence = state.length
        digest = _snapshot_digest(snapshot)
        gov.ledger._post(
            [
                LedgerLine(
                    EntryType.CHECKPOINT,
                    Direction.NONE,
                    "",
                    Decimal(0),
                    memo=f"agentgov-checkpoint v1 seq={sequence} sha256={digest}",
                )
            ]
        )
        gov.reset("writer")
        entries = list(gov.audit_trail())
        final = gov.ledger._state
    summary = {
        "length": final.length,
        "head": final.head,
        "balances": {s: core._fixed(b) for s, b in sorted(final.balances.items())},
        "totals": {
            "funded": core._fixed(final.totals.funded),
            "spent": core._fixed(final.totals.spent),
            "reversed": core._fixed(final.totals.reversed_),
            "holds_open": core._fixed(final.totals.holds_open),
        },
        "open_holds": [str(h) for h in final.holds],
        "halted": sorted(final.tripped),
        "merkle_root": _frontier_root(final.frontier).hex(),
        "checkpoint": {
            "sequence": sequence,
            "snapshot": snapshot.decode("utf-8"),
            "sha256": digest,
        },
    }
    return entries, summary


def _rehashed(prefix: list[LedgerEntry], entry: LedgerEntry) -> list[LedgerEntry]:
    """``prefix`` and ``entry`` relinked and rehashed as the chain's next entry,
    as someone able to compute SHA-256 would forge it."""
    previous = prefix[-1].entry_hash if prefix else GENESIS_HASH
    linked = dataclasses.replace(entry, sequence=len(prefix) + 1, prev_hash=previous)
    return [*prefix, dataclasses.replace(linked, entry_hash=linked.recompute_hash())]


def _invalid_cases(chain: list[LedgerEntry]) -> list[dict[str, Any]]:
    first = {e.entry_type: i for i, e in reversed(list(enumerate(chain)))}
    last = {e.entry_type: i for i, e in enumerate(chain)}

    def at(kind: EntryType) -> int:
        return first[kind]

    def change(index: int, **fields: Any) -> list[LedgerEntry]:
        return _rehashed(chain[:index], dataclasses.replace(chain[index], **fields))

    def balance(index: int, scope: str) -> Decimal:
        """``scope``'s balance just before entry ``index``."""
        return _replay(chain[:index]).balances.get(scope, Decimal(0))

    cases: list[tuple[str, str, list[LedgerEntry]]] = [
        (
            "hash-mismatch",
            "has been tampered with",
            [*chain[:3], dataclasses.replace(chain[3], memo="edited")],
        ),
        (
            "broken-link",
            "broken chain link",
            [*chain[:3], dataclasses.replace(chain[3], prev_hash="0" * 64)],
        ),
        ("sequence-gap", "sequence gap", [*chain[:3], dataclasses.replace(chain[3], sequence=9)]),
        (
            "wrong-balance",
            "records a balance of",
            change(1, balance_after=chain[1].balance_after + 1),
        ),
        (
            "unbalanced-transfer",
            "does not balance",
            change(2, amount=money("2.49"), balance_after=money("2.49")),
        ),
        (
            "funding-a-child",
            "funds a scope that is not a root",
            change(
                last[EntryType.FUNDING],
                scope_id="writer",
                balance_after=balance(last[EntryType.FUNDING], "writer") + money("5.00"),
            ),
        ),
        (
            "release-of-a-hold-never-placed",
            "not an open hold",
            change(at(EntryType.HOLD_VOID), ref=_id("nowhere")),
        ),
        (
            "refund-beyond-the-spend",
            "more than the",
            change(
                at(EntryType.REVERSAL),
                amount=money("0.30"),
                balance_after=chain[at(EntryType.REVERSAL) - 1].balance_after + money("0.30"),
            ),
        ),
        (
            "time-running-backwards",
            "time never runs backwards",
            change(5, timestamp=chain[4].timestamp - timedelta(seconds=1)),
        ),
        (
            "control-character-in-scope",
            "control character",
            change(at(EntryType.ANCHOR), scope_id="orchestrator\nforged"),
        ),
        (
            "checkpoint-of-the-future",
            "not before it",
            change(
                at(EntryType.CHECKPOINT),
                memo=f"agentgov-checkpoint v1 seq={len(chain) + 5} sha256={'0' * 64}",
            ),
        ),
        (
            "older-format-after-newer",
            "AGOV2 entry after AGOV3",
            change(4, version="AGOV2"),
        ),
    ]
    out = []
    for name, error, entries in cases:
        try:
            _replay(entries)
        except LedgerIntegrityError as exc:
            assert error in str(exc), (name, str(exc))
        else:  # pragma: no cover - a vector that does not fail is a broken vector
            raise AssertionError(f"invalid vector {name!r} replays")
        out.append({"name": name, "error": error, "entries": [_document(e) for e in entries]})
    return out


def generate(out: Path) -> None:
    """Write every vector into ``out``, replacing whatever was there."""
    chain, summary = _chain()
    replayed = _replay(chain)
    assert replayed.head == summary["head"], "the chain must replay to the state recorded"
    files: dict[str, Any] = {
        "entries.json": {
            "description": "Single entries: the text each one's SHA-256 covers, and the hash.",
            "cases": _entry_cases(),
        },
        "chain.json": {
            "description": "A valid chain from genesis and the state it implies.",
            "entries": [_document(e) for e in chain],
            "state": summary,
        },
        "invalid.json": {
            "description": "Chains that each break one rule; 'error' is in the refusal.",
            "cases": _invalid_cases(chain),
        },
    }
    staging = Path(tempfile.mkdtemp())
    try:
        for name, content in files.items():
            text = json.dumps(content, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
            (staging / name).write_text(text, encoding="utf-8")
        (staging / "README.md").write_text(_README, encoding="utf-8")
        if out.exists():
            shutil.rmtree(out)
        out.mkdir(parents=True)
        for path in staging.iterdir():
            shutil.copyfile(path, out / path.name)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


_README = """# AGOV conformance vectors

Generated by `scripts/generate_agov_vectors.py`; never edit by hand.
`tests/test_ledger_format.py` regenerates them on every CI run and fails if a
committed file differs. The format they exercise is specified in
`docs/LEDGER_FORMAT.md`.

- `entries.json`: single entries. For each, `hashed` is the exact UTF-8 text
  the entry hash covers and `sha256` is the hash. An implementation that
  renders `hashed` from `entry` byte for byte, and gets `sha256`, hashes
  entries correctly.
- `chain.json`: a chain from genesis with every kind of event, and the state a
  replay must reach: balances, totals, open holds, halted scopes, the RFC 9162
  root of the entry hashes, and a checkpoint's snapshot and digest.
- `invalid.json`: chains that each break exactly one rule; a replay must
  refuse every one (`error` is part of agentgov's own message, for reference).

Every value in `entry` objects is a string, as `LedgerEntry.to_audit_record()`
renders it; an empty `counterparty_id` or `ref` means none.
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default="vectors/agov")
    generate(Path(parser.parse_args().out))


if __name__ == "__main__":
    main()
