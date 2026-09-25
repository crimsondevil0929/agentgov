"""Ed25519 signature verification in pure Python (RFC 8032, section 5.1.7).

Verification needs no secret and no dependency, so ARC1 receipts can be
checked with nothing but a stock interpreter. This follows the reference
implementation in RFC 8032 section 6. It is not constant-time, which does
not matter here: every input to verification is public.

Signing is deliberately *not* implemented here. A signer handles a secret key,
and ``agentgov.receipts.signing.Ed25519Signer`` uses the ``cryptography``
package for it (the ``agentgov[sign]`` extra).

The acceptance rule matches OpenSSL's, which ``cryptography`` uses, for every
signature: ``S`` must be below the group order, ``R`` must be the canonical
encoding of a curve point, and the check is the cofactorless equation
``[S]B = R + [k]A``. The two implementations therefore accept exactly the
same signatures, which the test suite checks.
"""

from __future__ import annotations

import hashlib

__all__ = ["verify"]

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)

_Point = tuple[int, int, int, int]  # extended coordinates (X, Y, Z, T)
_IDENTITY: _Point = (0, 1, 1, 0)


def _add(p: _Point, q: _Point) -> _Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(scalar: int, point: _Point) -> _Point:
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


def _decompress(encoded: bytes) -> _Point | None:
    y = int.from_bytes(encoded, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _equal(p: _Point, q: _Point) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


_G_Y = 4 * pow(5, _P - 2, _P) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None
_BASE: _Point = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Whether ``signature`` is a valid Ed25519 signature of ``message``.

    Never raises on malformed input: a wrong-length key or signature, a key
    that is not a curve point, a non-canonical ``R`` or an ``S`` at or above
    the group order all verify as ``False``.
    """
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decompress(public_key)
    if a is None:
        return False
    r_bytes, s_bytes = signature[:32], signature[32:]
    r = _decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(s_bytes, "little")
    if s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(r_bytes + public_key + message).digest(), "little") % _L
    return _equal(_multiply(s, _BASE), _add(r, _multiply(k, a)))
