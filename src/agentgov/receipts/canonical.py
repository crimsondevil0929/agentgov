"""ARC1 canonical encoding and strict decoding.

Every ARC1 hash and signature covers the *canonical* bytes of a JSON value,
so two parties that hold the same value always hash the same bytes, however
the document was pretty-printed on the way. The encoding is RFC 8785, the JSON
Canonicalization Scheme, restricted to a value domain that makes it exact and
easy to reproduce in any language:

- strings, which must be valid Unicode (no lone surrogates);
- integers in the I-JSON safe range, ``±(2**53 - 1)``;
- ``true``, ``false`` and ``null``;
- arrays, in order;
- objects with string keys, sorted by their UTF-16 code units.

Floats are refused outright. RFC 8785 serializes numbers the way ECMAScript
does, which Python's ``repr`` does not match for every float, and money and
database values are exact decimals anyway: ARC1 carries them as strings.

Within that domain the output is byte-for-byte what any RFC 8785
implementation produces, so a third-party verifier can use an off-the-shelf
JCS library or the thirty lines below.

Decoding is strict in the other direction. A duplicate object key is an
error, not "last one wins": parsers disagree about which duplicate they keep,
and a receipt that displays one value while verifying another is exactly the
ambiguity a signed document must not have.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any, NoReturn

from agentgov.exceptions import MalformedReceiptError

__all__ = [
    "MAX_SAFE_INTEGER",
    "canonical_bytes",
    "loads_strict",
    "sha256_hex",
]

MAX_SAFE_INTEGER = 2**53 - 1
"""The largest integer every JSON implementation represents exactly (I-JSON)."""


def canonical_bytes(value: object) -> bytes:
    """The RFC 8785 canonical UTF-8 encoding of ``value``.

    :raises MalformedReceiptError: If ``value`` contains anything outside the
        ARC1 value domain: a float, an integer beyond the safe range, a
        non-string object key, a lone surrogate, or any other type.
    """
    try:
        ordered = _ordered(value)
    except _OutsideDomainError:
        _encode(value, [], "$")  # raises, naming where
        raise AssertionError("unreachable") from None  # pragma: no cover
    # Within the domain, the C encoder writes exactly what _encode would: the
    # same string escapes, int.__repr__ for integers, keys in the order given.
    text = json.dumps(ordered, ensure_ascii=False, separators=(",", ":"), check_circular=False)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MalformedReceiptError(
            f"a string is not valid Unicode (lone surrogate at offset {exc.start}); "
            f"canonical JSON is defined over Unicode text only"
        ) from exc


class _OutsideDomainError(Exception):
    """A value :func:`_ordered` cannot pass on; :func:`_encode` says why."""


def _ordered(value: object) -> object:
    """``value`` checked against the domain, every object rebuilt with its keys
    in UTF-16 order, ready for ``json.dumps``. Raises :class:`_OutsideDomainError`
    on anything :func:`_encode` would refuse."""
    # The same tests, in the same order, as _encode.
    if value is None or value is True or value is False or isinstance(value, str):
        return value
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise _OutsideDomainError
        return value
    if isinstance(value, Mapping):
        keys = list(value)
        if not all(isinstance(key, str) for key in keys):
            raise _OutsideDomainError
        # Code point order is UTF-16 order for ASCII; otherwise compare units.
        if all(key.isascii() for key in keys):
            keys.sort()
        else:
            keys.sort(key=_utf16_order)
        return {key: _ordered(value[key]) for key in keys}
    if isinstance(value, (list, tuple)):
        return [_ordered(item) for item in value]
    raise _OutsideDomainError


def _encode(value: object, out: list[str], path: str) -> None:
    # bool before int: True and False are ints in Python and JSON literals here.
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise MalformedReceiptError(
                f"{path}: integer {value} is outside the safe range ±(2**53 - 1)"
            )
        out.append(int.__repr__(value))
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, Mapping):
        for key in value:
            if not isinstance(key, str):
                raise MalformedReceiptError(f"{path}: object key {key!r} is not a string")
        out.append("{")
        for index, key in enumerate(sorted(value, key=_utf16_order)):
            if index:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(":")
            _encode(value[key], out, f"{path}.{key}")
        out.append("}")
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _encode(item, out, f"{path}[{index}]")
        out.append("]")
    elif isinstance(value, float):
        raise MalformedReceiptError(
            f"{path}: {value!r} is a float; ARC1 carries decimals as strings so every "
            f"verifier reads the same number"
        )
    else:
        raise MalformedReceiptError(
            f"{path}: a {type(value).__name__} has no canonical JSON encoding"
        )


def _utf16_order(key: str) -> bytes:
    """RFC 8785 sorts object keys by their UTF-16 code units, not code points.

    Encoding to UTF-16BE and comparing bytes compares code units. The two
    orders differ only between supplementary-plane characters and the upper
    BMP, which is exactly where a naive ``sorted()`` would diverge from other
    implementations.
    """
    return key.encode("utf-16-be", "surrogatepass")


def loads_strict(text: str | bytes) -> Any:
    """Decode JSON, refusing what the canonical encoding cannot represent.

    :raises MalformedReceiptError: On invalid JSON, a duplicate object key, a
        float or exponent, or ``NaN``/``Infinity``.
    """
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_keys,
            parse_float=_no_float,
            parse_constant=_no_constant,
        )
    except MalformedReceiptError:
        raise
    except (ValueError, TypeError) as exc:
        raise MalformedReceiptError(f"not valid JSON: {exc}") from exc


def _unique_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MalformedReceiptError(
                f"duplicate object key {key!r}: parsers disagree about which one they "
                f"keep, so a signed document may not contain one"
            )
        result[key] = value
    return result


def _no_float(text: str) -> NoReturn:
    raise MalformedReceiptError(
        f"number {text} has a fraction or exponent; ARC1 carries decimals as strings"
    )


def _no_constant(text: str) -> NoReturn:
    raise MalformedReceiptError(f"{text} is not JSON")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 of ``data``."""
    return hashlib.sha256(data).hexdigest()
