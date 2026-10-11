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
from collections.abc import Iterator

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentgov import BudgetManager, money
from agentgov.core import _escape, format_audit_line

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


@pytest.mark.parametrize("text", HOSTILE)
def test_each_entry_is_one_line_with_its_fields_intact(text: str, audit_lines: io.StringIO) -> None:
    gov = BudgetManager()
    gov.open_root(f"root {text}", money("1"), memo=f"fund {text}")
    gov.delegate(f"root {text}", f"child {text}", money("0.5"), memo=text)
    gov.anchor(f"child {text}", text)
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
