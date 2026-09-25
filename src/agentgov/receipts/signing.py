"""Signers and verifiers for ARC1 documents.

Two algorithms, chosen for who has to check the signature:

- ``hmac-sha256`` (:class:`HmacKey`) uses only the standard library. The
  verifier holds the same secret as the signer, so an HMAC receipt proves
  integrity *inside* one organization, never to an outside auditor.
- ``ed25519`` (:class:`Ed25519Signer` / :class:`Ed25519PublicKey`) is the
  one to hand to third parties: anyone with the public key can verify, and no
  one without the private key can sign.

Verifying Ed25519 needs no dependency: it falls back to a pure-Python RFC 8032
implementation when ``cryptography`` is absent. *Signing* with Ed25519 needs
``cryptography`` (``pip install 'agentgov[sign]'``), because a signer holds a
secret and should run constant-time, audited code.

Every signature ARC1 makes covers a domain-separation prefix naming what is
being signed (``ARC1/receipt/v1``, ``ARC1/checkpoint/v1``,
``ARC1/cosignature/v1``), so a signature over one kind of document can never
be replayed as a signature over another.

A key is written as ``<alg>:<hex>``: ``ed25519:`` and a 32-byte public key, or
``hmac-sha256:`` and the shared secret. :func:`parse_key` reads either.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Protocol, runtime_checkable

from agentgov.exceptions import MalformedReceiptError, SignerUnavailableError
from agentgov.receipts import _ed25519

__all__ = [
    "ALG_ED25519",
    "ALG_HMAC_SHA256",
    "Ed25519PublicKey",
    "Ed25519Signer",
    "HmacKey",
    "Signer",
    "Verifier",
    "parse_key",
]

ALG_HMAC_SHA256 = "hmac-sha256"
ALG_ED25519 = "ed25519"
_ALGORITHMS = frozenset({ALG_HMAC_SHA256, ALG_ED25519})


@runtime_checkable
class Signer(Protocol):
    """Something that signs ARC1 documents."""

    @property
    def alg(self) -> str:
        """``"ed25519"`` or ``"hmac-sha256"``."""
        ...

    @property
    def key_id(self) -> str:
        """16 hex characters naming the key; recorded in every signature."""
        ...

    def sign(self, message: bytes) -> bytes:
        """Sign ``message``, which already carries its domain prefix."""
        ...

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Whether ``signature`` is this key's signature of ``message``.

        A signer can always check its own signatures; a witness uses this to
        re-verify the file it resumes from.
        """
        ...


@runtime_checkable
class Verifier(Protocol):
    """Something that checks ARC1 signatures made by one key."""

    @property
    def alg(self) -> str: ...

    @property
    def key_id(self) -> str: ...

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Whether ``signature`` is this key's signature of ``message``.

        Never raises on a malformed signature; it simply does not verify.
        """
        ...


class HmacKey:
    """A shared HMAC-SHA256 key: it signs, and it verifies what it signed.

    :param secret: At least 32 bytes of key material.
    :param key_id: A name for the key. Derived from the secret by default,
        through HMAC, so it reveals nothing about the secret.
    :raises ValueError: If ``secret`` is shorter than 32 bytes.
    """

    __slots__ = ("_key_id", "_secret")

    def __init__(self, secret: bytes, *, key_id: str | None = None) -> None:
        if len(secret) < 32:
            raise ValueError("an HMAC-SHA256 key must be at least 32 bytes")
        self._secret = bytes(secret)
        derived = hmac.new(self._secret, b"ARC1/key-id/v1", hashlib.sha256).hexdigest()[:16]
        self._key_id = key_id if key_id is not None else derived

    @classmethod
    def generate(cls) -> HmacKey:
        """A fresh random 32-byte key."""
        return cls(secrets.token_bytes(32))

    @property
    def alg(self) -> str:
        return ALG_HMAC_SHA256

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, message: bytes) -> bytes:
        return hmac.new(self._secret, message, hashlib.sha256).digest()

    def verify(self, message: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(message), signature)

    def spec(self) -> str:
        """``hmac-sha256:<hex secret>``. This *is* the secret: store it as one."""
        return f"{ALG_HMAC_SHA256}:{self._secret.hex()}"

    def __repr__(self) -> str:
        return f"HmacKey(key_id={self._key_id!r})"


def _ed25519_key_id(public_key: bytes) -> str:
    return hashlib.sha256(b"ARC1/ed25519/v1\n" + public_key).hexdigest()[:16]


class Ed25519PublicKey:
    """An Ed25519 public key: verifies signatures, with no dependency.

    Uses ``cryptography`` when it is installed, for speed, and the RFC 8032
    reference algorithm otherwise. Both accept exactly the same signatures.

    :param raw: The 32-byte public key.
    :raises ValueError: If ``raw`` is not 32 bytes.
    """

    __slots__ = ("_raw",)

    def __init__(self, raw: bytes) -> None:
        if len(raw) != 32:
            raise ValueError(f"an Ed25519 public key is 32 bytes, got {len(raw)}")
        self._raw = bytes(raw)

    @property
    def alg(self) -> str:
        return ALG_ED25519

    @property
    def key_id(self) -> str:
        return _ed25519_key_id(self._raw)

    @property
    def raw(self) -> bytes:
        return self._raw

    def verify(self, message: bytes, signature: bytes) -> bool:
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey as _CryptoKey,
            )
        except ImportError:
            return _ed25519.verify(self._raw, message, signature)
        if len(signature) != 64:
            return False
        try:
            _CryptoKey.from_public_bytes(self._raw).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True

    def spec(self) -> str:
        """``ed25519:<hex public key>``."""
        return f"{ALG_ED25519}:{self._raw.hex()}"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Ed25519PublicKey) and other._raw == self._raw

    def __hash__(self) -> int:
        return hash(self._raw)

    def __repr__(self) -> str:
        return f"Ed25519PublicKey({self.spec()!r})"


class Ed25519Signer:
    """An Ed25519 private key. Needs ``cryptography`` (``agentgov[sign]``).

    :param seed: The 32-byte private key seed (RFC 8032 "secret key").
    :raises SignerUnavailableError: If ``cryptography`` is not installed.
    :raises ValueError: If ``seed`` is not 32 bytes.
    """

    __slots__ = ("_key", "_public")

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError(f"an Ed25519 seed is 32 bytes, got {len(seed)}")
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError as exc:
            raise SignerUnavailableError(
                "Ed25519 signing needs the 'cryptography' package: "
                "pip install 'agentgov[sign]'. Verifying needs nothing extra."
            ) from exc
        self._key = Ed25519PrivateKey.from_private_bytes(bytes(seed))
        raw = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._public = Ed25519PublicKey(raw)

    @classmethod
    def generate(cls) -> Ed25519Signer:
        """A fresh random key."""
        return cls(secrets.token_bytes(32))

    @property
    def alg(self) -> str:
        return ALG_ED25519

    @property
    def key_id(self) -> str:
        return self._public.key_id

    def public_key(self) -> Ed25519PublicKey:
        return self._public

    def sign(self, message: bytes) -> bytes:
        signature: bytes = self._key.sign(message)
        return signature

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self._public.verify(message, signature)

    def __repr__(self) -> str:
        return f"Ed25519Signer(key_id={self.key_id!r})"


def parse_key(spec: str) -> Verifier:
    """Read a key written as ``<alg>:<hex>``.

    ``ed25519:`` takes a 32-byte public key; ``hmac-sha256:`` takes the
    shared secret.

    :raises MalformedReceiptError: If the text is not a key in either form.
    """
    alg, sep, material = spec.strip().partition(":")
    if not sep or alg not in _ALGORITHMS:
        raise MalformedReceiptError(
            f"a key is written as '{ALG_ED25519}:<hex>' or '{ALG_HMAC_SHA256}:<hex>'"
        )
    try:
        raw = bytes.fromhex(material)
    except ValueError as exc:
        raise MalformedReceiptError(f"the {alg} key material is not hex") from exc
    try:
        if alg == ALG_ED25519:
            return Ed25519PublicKey(raw)
        return HmacKey(raw)
    except ValueError as exc:
        raise MalformedReceiptError(str(exc)) from exc
