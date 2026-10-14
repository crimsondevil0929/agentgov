"""Audit lines stay one line, one field per value, whatever the text (F6, CWE-117).

Scope ids and memos can come from model output. Each audit line must be
exactly one line, every free-text field exactly one ``|``-delimited token,
and the escaping reversible, so a log pipeline can neither be fed a forged
entry nor lose what an entry said.
"""

from __future__ import annotations

import io
import json
import logging
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentgov import BudgetManager, money
from agentgov.core import (
    MAX_ID_BYTES,
    MAX_MEMO_BYTES,
    Direction,
    EntryType,
    LedgerEntry,
    _check_text,
    _escape,
    format_audit_line,
)

HOSTILE = [
    "line\nbreak",
    "carriage\rreturn",
    "crlf\r\nAGOV2|seq=0000000099|type=funding|amt=1000000",
    "unicode\u2028line\u2029separators\x85nel",
    "nul\x00byte",
    "ansi \x1b[31mred\x1b[0m",
    "pipe|in|the|middle",
    "back\\slash",
    "del\x7fchar",
    "bidi \u202eoverride",
    "zero\u200bwidth",
    "emoji \U0001f4b8",
    "lone \ud800 surrogate",
    'quote " mark',
]


def _unescape(field: str) -> str:
    """The inverse of :func:`agentgov.core._escape`."""
    return json.loads(f'"{field}"') if "\\" in field else field


@pytest.fixture
def audit_lines() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log = logging.getLogger("agentgov.audit")
    previous = log.level
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    try:
        yield stream
    finally:
        log.removeHandler(handler)
        log.setLevel(previous)


def _fields(line: str) -> dict[str, str]:
    version, *rest = line.split("|")
    fields = {"version": version}
    for part in rest:
        key, _, value = part.partition("=")
        assert key not in fields, f"field {key!r} appears twice in {line!r}"
        fields[key] = value
    return fields


def _allowed(text: str, *, identifier: bool) -> bool:
    limit = MAX_ID_BYTES if identifier else MAX_MEMO_BYTES
    return _check_text(text, "text", limit=limit, identifier=identifier) is None


@pytest.mark.parametrize("text", HOSTILE)
def test_each_entry_is_one_line_with_its_fields_intact(text: str, audit_lines: io.StringIO) -> None:
    # Hostile text goes wherever an AGOV3 entry admits it: memos admit all but
    # NUL and lone surrogates, scope ids no control character either.
    in_scope = _allowed(text, identifier=True)
    memo = text if _allowed(text, identifier=False) else "plain"
    root = f"root {text}" if in_scope else "root"
    child = f"child {text}" if in_scope else "child"
    gov = BudgetManager()
    gov.open_root(root, money("1"), memo=f"fund {memo}")
    gov.delegate(root, child, money("0.5"), memo=memo)
    gov.anchor(child, memo)
    entries = gov.audit_trail()
    lines = audit_lines.getvalue().splitlines()
    assert len(lines) == len(entries)
    for entry, line in zip(entries, lines, strict=True):
        assert line == format_audit_line(entry)
        assert line.isascii() and line.isprintable()
        fields = _fields(line)
        assert _unescape(fields["scope"]) == entry.scope_id
        assert _unescape(fields["memo"]) == entry.memo
        if entry.counterparty_id:
            assert _unescape(fields["cpty"]) == entry.counterparty_id


@pytest.mark.parametrize("text", [t for t in HOSTILE if not _allowed(t, identifier=True)])
def test_a_scope_id_with_a_control_character_or_a_surrogate_is_refused(text: str) -> None:
    gov = BudgetManager()
    with pytest.raises(ValueError, match="scope id"):
        gov.open_root(f"root {text}", money("1"))
    assert gov.scopes() == ()


@pytest.mark.parametrize("text", ["nul\x00byte", "lone \ud800 surrogate"])
def test_a_memo_a_store_cannot_hold_is_refused(text: str) -> None:
    gov = BudgetManager()
    gov.open_root("root", money("1"))
    with pytest.raises(ValueError, match="memo"):
        gov.anchor("root", text)


def test_control_events_are_escaped_too(audit_lines: io.StringIO) -> None:
    gov = BudgetManager()
    gov.open_root("ops", money("1"))
    gov.trip("ops", "halted\nAGOV2|ctrl=circuit_reset|scope=ops")
    gov.reset("ops")
    lines = audit_lines.getvalue().splitlines()
    controls = [line for line in lines if "|ctrl=" in line]
    assert len(controls) == 2
    assert all(line.isprintable() for line in controls)
    tripped = _fields(controls[0])
    assert _unescape(tripped["reason"]) == "halted\nAGOV2|ctrl=circuit_reset|scope=ops"


def _entry(**fields: object) -> LedgerEntry:
    known: dict[str, object] = dict(
        prev_hash="0" * 64, counterparty_id=None, memo="", ref=None, version="AGOV3"
    )
    return LedgerEntry(**{**known, **fields})  # type: ignore[arg-type]


def test_an_audit_line_has_fixed_fields_in_a_fixed_order() -> None:
    """What a log pipeline parses: every field, the first 16 hex digits of the
    entry hash, and ``ref`` and ``memo`` only when the entry has one."""
    released = _entry(
        sequence=7,
        entry_id=uuid.UUID(int=1),
        transaction_id=uuid.UUID(int=2),
        timestamp=datetime(2026, 10, 13, 12, 0, 0, 250000, tzinfo=UTC),
        entry_type=EntryType.HOLD_VOID,
        direction=Direction.CREDIT,
        scope_id="agent",
        amount=money("0.5"),
        balance_after=money("1.25"),
        entry_hash="0123456789abcdef" + "f" * 48,
        memo="released",
        ref=uuid.UUID(int=3),
    )
    assert format_audit_line(released) == (
        "AGOV3|seq=0000000007|txn=00000000-0000-0000-0000-000000000002"
        "|ts=2026-10-13T12:00:00.250000Z|type=hold_void|dir=CR|scope=agent|cpty=-"
        "|amt=0.50000000|bal=1.25000000|h=0123456789abcdef"
        "|ref=00000000-0000-0000-0000-000000000003|memo=released"
    )
    delegated = _entry(
        sequence=8,
        entry_id=uuid.UUID(int=4),
        transaction_id=uuid.UUID(int=5),
        timestamp=datetime(2026, 10, 13, 12, 0, 1, tzinfo=UTC),
        entry_type=EntryType.ALLOCATION,
        direction=Direction.DEBIT,
        scope_id="root",
        counterparty_id="agent",
        amount=money("2"),
        balance_after=money("8"),
        entry_hash="fedcba9876543210" + "0" * 48,
    )
    assert format_audit_line(delegated) == (
        "AGOV3|seq=0000000008|txn=00000000-0000-0000-0000-000000000005"
        "|ts=2026-10-13T12:00:01.000000Z|type=allocation|dir=DR|scope=root|cpty=agent"
        "|amt=2.00000000|bal=8.00000000|h=fedcba9876543210"
    )


def test_ordinary_text_is_written_as_it_is() -> None:
    for text in ("agent.research", "task/42/step-3", "settled call cost", "a=b c:d (e) [f]"):
        assert _escape(text) == text


@given(st.text())
def test_escaping_is_one_printable_token_and_reversible(text: str) -> None:
    field = _escape(text)
    assert field.isascii()
    assert field.isprintable()
    assert "|" not in field
    assert _unescape(field) == text
