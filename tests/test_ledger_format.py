"""The ledger format is specified and frozen: AGOV vectors (docs/LEDGER_FORMAT.md).

1. The committed vectors are exactly what ``scripts/generate_agov_vectors.py``
   writes today, so the format cannot change without the vectors changing.
2. Every entry's hash covers exactly the text the vector shows, and AGOV3's
   is RFC 8785 canonical JSON, byte for byte what the receipts' canonical
   encoder (an independent implementation) produces.
3. The chain replays to the state recorded; every invalid chain is refused.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import uuid
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentgov.core import (
    USD,
    Direction,
    EntryType,
    LedgerEntry,
    Unit,
    _decode_snapshot,
    _fixed,
    _frontier_root,
    _hash_entry,
    _iso,
    _parse_iso,
    _replay,
    _snapshot_digest,
)
from agentgov.exceptions import LedgerIntegrityError
from agentgov.receipts.canonical import canonical_bytes

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors" / "agov"
FIXED = re.compile(r"\A-?(0|[1-9][0-9]*)\.[0-9]{8}\Z")


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "generate_agov_vectors", ROOT / "scripts" / "generate_agov_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load(name: str) -> Any:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _entry(record: dict[str, str]) -> LedgerEntry:
    return LedgerEntry(
        sequence=int(record["sequence"]),
        entry_id=uuid.UUID(record["entry_id"]),
        transaction_id=uuid.UUID(record["transaction_id"]),
        timestamp=_parse_iso(record["timestamp"]),
        entry_type=EntryType(record["entry_type"]),
        direction=Direction(record["direction"]),
        scope_id=record["scope_id"],
        counterparty_id=record["counterparty_id"] or None,
        amount=Decimal(record["amount"]),
        balance_after=Decimal(record["balance_after"]),
        prev_hash=record["prev_hash"],
        entry_hash=record["entry_hash"],
        memo=record["memo"],
        ref=uuid.UUID(record["ref"]) if record["ref"] else None,
        version=record["version"],
    )


def test_the_committed_vectors_are_exactly_what_the_generator_writes(tmp_path: Path) -> None:
    out = tmp_path / "agov"
    _generator().generate(out)
    written = {p.name: p.read_bytes() for p in out.iterdir()}
    committed = {p.name: p.read_bytes() for p in VECTORS.iterdir()}
    assert written == committed, (
        "vectors/agov/ is stale: run `uv run python scripts/generate_agov_vectors.py` "
        "and commit the result"
    )


@pytest.mark.parametrize("case", _load("entries.json")["cases"], ids=lambda c: c["name"])
def test_each_entry_hashes_exactly_the_text_its_vector_shows(case: dict[str, Any]) -> None:
    entry = _entry(case["entry"])
    assert entry.recompute_hash() == case["sha256"] == entry.entry_hash
    assert _generator()._payload(entry) == case["hashed"]
    if entry.version == "AGOV3":
        # The text is RFC 8785 canonical JSON: an independent encoder agrees.
        assert canonical_bytes(json.loads(case["hashed"])) == case["hashed"].encode("utf-8")
        for key in ("amount", "balance_after"):
            assert FIXED.match(case["entry"][key]), case["entry"][key]


def test_the_chain_replays_to_the_state_it_records() -> None:
    vector = _load("chain.json")
    entries = [_entry(record) for record in vector["entries"]]
    state = _replay(entries)
    expected = vector["state"]
    assert state.length == expected["length"]
    assert state.head == expected["head"]
    assert {s: _fixed(b) for s, b in state.balances.items()} == expected["balances"]
    assert [str(h) for h in state.holds] == expected["open_holds"]
    assert sorted(state.tripped) == expected["halted"]
    assert _frontier_root(state.frontier).hex() == expected["merkle_root"]
    checkpoint = expected["checkpoint"]
    body = checkpoint["snapshot"].encode("utf-8")
    assert _snapshot_digest(body) == checkpoint["sha256"]
    assert _decode_snapshot(body).length == checkpoint["sequence"]
    named = [e for e in entries if e.entry_type is EntryType.CHECKPOINT]
    assert [e.memo for e in named] == [
        f"agentgov-checkpoint v1 seq={checkpoint['sequence']} sha256={checkpoint['sha256']}"
    ]


@pytest.mark.parametrize("case", _load("invalid.json")["cases"], ids=lambda c: c["name"])
def test_every_invalid_chain_is_refused(case: dict[str, Any]) -> None:
    entries = [_entry(record) for record in case["entries"]]
    with pytest.raises(LedgerIntegrityError, match=re.escape(case["error"])):
        _replay(entries)


def test_each_unit_has_the_genesis_its_declaration_hashes_to() -> None:
    vector = _load("units.json")
    for case in vector["genesis"]:
        unit = Unit(case["unit"], case["places"])
        assert unit.genesis == case["genesis"]
        if case["declaration"] is None:
            assert case["genesis"] == "0" * 64 and unit == USD
        else:
            assert hashlib.sha256(case["declaration"].encode("ascii")).hexdigest() == unit.genesis


def test_a_unit_chain_replays_to_its_state_and_its_invalid_chains_are_refused() -> None:
    vector = _load("units.json")
    chain = vector["chain"]
    unit = Unit(chain["unit"], chain["places"])
    entries = [_entry(record) for record in chain["entries"]]
    state = _replay(entries, unit=unit)
    assert state.head == chain["state"]["head"] and state.length == chain["state"]["length"]
    assert {s: _fixed(b) for s, b in state.balances.items()} == chain["state"]["balances"]
    for case in vector["invalid"]:
        broken = [_entry(record) for record in case["entries"]]
        with pytest.raises(LedgerIntegrityError, match=re.escape(case["error"])):
            _replay(broken, unit=Unit(case["unit"], case["places"]))


# -- properties ----------------------------------------------------------------------

_text = st.text(
    alphabet=st.characters(blacklist_categories=["Cs"], blacklist_characters=["\x00"]),
    max_size=40,
)
_amount = st.decimals(
    min_value=Decimal("-1000000000000"), max_value=Decimal("1000000000000"), places=8
)


@given(
    scope=_text,
    counterparty=st.none() | _text,
    memo=_text,
    amount=_amount,
    balance=_amount,
    ref=st.none() | st.uuids(),
    sequence=st.integers(1, 2**53 - 1),
)
def test_the_agov3_payload_is_canonical_json(
    scope: str,
    counterparty: str | None,
    memo: str,
    amount: Decimal,
    balance: Decimal,
    ref: uuid.UUID | None,
    sequence: int,
) -> None:
    fields = dict(
        prev_hash="0" * 64,
        sequence=sequence,
        entry_id=uuid.UUID(int=1),
        transaction_id=uuid.UUID(int=2),
        timestamp=datetime(2026, 10, 11, tzinfo=UTC),
        entry_type=EntryType.ANCHOR,
        direction=Direction.NONE,
        scope_id=scope,
        counterparty_id=counterparty,
        amount=amount,
        balance_after=balance,
        memo=memo,
        ref=ref,
        version="AGOV3",
    )
    entry = LedgerEntry(**fields, entry_hash="")  # type: ignore[arg-type]
    payload = _generator()._payload(entry)
    document = json.loads(payload)
    assert canonical_bytes(document) == payload.encode("utf-8")
    import hashlib

    assert _hash_entry(**fields) == hashlib.sha256(payload.encode("utf-8")).hexdigest()  # type: ignore[arg-type]


@given(st.decimals(min_value=Decimal("-1e12"), max_value=Decimal("1e12"), places=8))
def test_a_fixed_point_amount_reads_back_to_the_same_number(value: Decimal) -> None:
    text = _fixed(value)
    assert FIXED.match(text), text
    assert Decimal(text) == value
    assert text != "-0.00000000"


def test_an_amount_with_more_than_eight_decimals_has_no_agov3_rendering() -> None:
    from decimal import Inexact

    with pytest.raises(Inexact):
        _fixed(Decimal("0.000000001"))


# -- timestamps --------------------------------------------------------------------

_STRFTIME = "%Y-%m-%dT%H:%M:%S.%f"


@given(
    st.datetimes(
        min_value=datetime(1000, 1, 2),
        max_value=datetime(9999, 12, 30),
        timezones=st.sampled_from(
            [UTC, timezone(timedelta(hours=5, minutes=30)), timezone(-timedelta(hours=8))]
        ),
    )
)
def test_a_timestamp_is_written_and_read_as_strftime_and_strptime_would(moment: datetime) -> None:
    """Every hash covers _iso(timestamp): the fast paths may not change a byte."""
    text = moment.astimezone(UTC).strftime(_STRFTIME) + "Z"
    assert _iso(moment) == text
    assert _parse_iso(text) == datetime.strptime(text, _STRFTIME + "Z").replace(tzinfo=UTC)
    assert _parse_iso(text) == moment


@pytest.mark.parametrize(
    "text",
    [
        "2026-1-5T03:04:05.1Z",  # what strptime has always accepted
        "2026-10-11T03:54:12.123456",  # no Z
        "2026-13-01T00:00:00.000000Z",
        "2026-10-11T03:54:12.123456+00:00",
        "\u0662\u0660\u0662\u0666-10-11T03:54:12.123456Z",  # Arabic-Indic digits
        "2026-10-11 03:54:12.123456Z",
    ],
)
def test_a_timestamp_not_in_the_written_form_parses_as_strptime_would(text: str) -> None:
    try:
        expected: object = datetime.strptime(text, _STRFTIME + "Z").replace(tzinfo=UTC)
    except ValueError:
        expected = ValueError
    try:
        found: object = _parse_iso(text)
    except ValueError:
        found = ValueError
    assert found == expected


_TEXT = st.text(alphabet=st.characters(codec="utf-8", exclude_characters="\x00"), max_size=12)


@given(
    scope=_TEXT,
    counterparty=st.none() | _TEXT,
    memo=_TEXT,
    ref=st.none() | st.uuids(),
    sequence=st.integers(min_value=1, max_value=2**53 - 1),
    amount=st.decimals(min_value=Decimal(0), max_value=Decimal("1e9"), places=8),
    balance=st.decimals(min_value=Decimal("-1e9"), max_value=Decimal("1e9"), places=8),
    prev=st.sampled_from(["0" * 64, "ab" * 32, 'not"hex', "A" * 64]),
)
def test_the_agov3_hash_is_its_canonical_documents_digest(
    scope: str,
    counterparty: str | None,
    memo: str,
    ref: uuid.UUID | None,
    sequence: int,
    amount: Decimal,
    balance: Decimal,
    prev: str,
) -> None:
    """However it is computed, an AGOV3 hash is SHA-256 of the RFC 8785
    encoding of the entry's document: the fast path writes the same bytes."""
    import hashlib

    fields: dict[str, Any] = {
        "sequence": sequence,
        "entry_id": uuid.UUID(int=sequence),
        "transaction_id": uuid.UUID(int=sequence + 1),
        "timestamp": datetime(2026, 10, 11, 12, 30, 15, 123456, tzinfo=UTC),
        "entry_type": EntryType.SPEND,
        "direction": Direction.DEBIT,
        "scope_id": scope,
        "counterparty_id": counterparty,
        "amount": amount,
        "balance_after": balance,
        "prev_hash": prev,
        "memo": memo,
        "ref": ref,
        "version": "AGOV3",
    }
    document = {
        "amount": _fixed(amount),
        "balance_after": _fixed(balance),
        "counterparty_id": counterparty,
        "direction": Direction.DEBIT.value,
        "entry_id": str(fields["entry_id"]),
        "entry_type": EntryType.SPEND.value,
        "format": "AGOV3",
        "memo": memo,
        "prev_hash": prev,
        "ref": str(ref) if ref is not None else None,
        "scope_id": scope,
        "sequence": sequence,
        "timestamp": "2026-10-11T12:30:15.123456Z",
        "transaction_id": str(fields["transaction_id"]),
    }
    assert _hash_entry(**fields) == hashlib.sha256(canonical_bytes(document)).hexdigest()
