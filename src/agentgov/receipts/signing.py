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

Signing and verifying are separate. Every signer has a :meth:`Signer.public_key`,
the :class:`Verifier` that checks its signatures without it, and agentgov
checks signatures with verifiers only, held in a :class:`Keyring` by key id.
So reopening a receipt log or a witness never calls a signer, which matters
when the signer is a key service: :class:`RemoteSigner` holds an Ed25519 key
that lives in a KMS or an HSM, and :class:`HttpRemoteSigner` reaches one over
HTTP. An :class:`AsyncSigner` signs without blocking an event loop; any
signer becomes one with :func:`as_async`.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Iterator
from typing import Any, Final, Protocol, runtime_checkable

from agentgov.exceptions import MalformedReceiptError, SignerUnavailableError
from agentgov.receipts import _ed25519

__all__ = [
    "ALG_ED25519",
    "ALG_HMAC_SHA256",
    "AsyncSigner",
    "Ed25519PublicKey",
    "Ed25519Signer",
    "HmacKey",
    "HttpRemoteSigner",
    "Keyring",
    "RemoteSigner",
    "Signer",
    "Verifier",
    "as_async",
    "parse_key",
    "verifier_of",
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

    def public_key(self) -> Verifier:
        """What checks this signer's signatures without the signer: the public
        key of an Ed25519 signer, the key itself for HMAC. agentgov verifies
        with this, never with :meth:`verify`, so checking a signature never
        calls a key service."""
        ...

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Whether ``signature`` is this key's signature of ``message``.

        Kept for callers that use it; agentgov itself verifies with
        :meth:`public_key`.
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

    def public_key(self) -> HmacKey:
        """The key itself: whoever verifies an HMAC holds the secret."""
        return self

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


def verifier_of(signer: Signer) -> Verifier:
    """The verifier for ``signer``'s signatures: its :meth:`~Signer.public_key`.

    A signer written before ``public_key`` joined the protocol is its own
    verifier, as before.
    """
    public_key = getattr(signer, "public_key", None)
    return public_key() if callable(public_key) else signer


class Keyring:
    """The keys trusted to have signed something, by key id.

    A receipt log, a witness and a verifier check each signature under the key
    its ``key_id`` names, and only if the keyring holds that key. A keyring
    holds verifiers, never signers, so checking never reaches a key service.

    :param keys: Verifiers, or keys written as ``<alg>:<hex>``; any number,
        so a log signed by a key and then by its successor checks out.
    :raises ValueError: On a key that does not parse, or two different keys
        with one key id.
    """

    __slots__ = ("_keys",)

    def __init__(self, keys: Iterable[Verifier | str] = ()) -> None:
        self._keys: dict[str, Verifier] = {}
        for key in keys:
            self.add(key)

    @classmethod
    def of(cls, keys: Keyring | Verifier | str | Iterable[Verifier | str]) -> Keyring:
        """``keys`` as a keyring: a keyring as it is, or one key, or several."""
        if isinstance(keys, Keyring):
            return keys
        if isinstance(keys, str) or hasattr(keys, "verify"):
            return cls([keys])  # type: ignore[list-item]
        return cls(keys)

    def add(self, key: Verifier | str) -> Verifier:
        """Trust ``key`` too. Adding a key already held changes nothing.

        :raises ValueError: If it does not parse, or another key has its id.
        """
        try:
            verifier = parse_key(key) if isinstance(key, str) else key
        except MalformedReceiptError as exc:
            raise ValueError(f"a key that does not parse: {exc}") from exc
        held = self._keys.get(verifier.key_id)
        if held is not None and not _same_key(held, verifier):
            raise ValueError(
                f"two different keys have id {verifier.key_id}; a key id names one key"
            )
        self._keys.setdefault(verifier.key_id, verifier)
        return self._keys[verifier.key_id]

    def get(self, key_id: str) -> Verifier | None:
        """The key with this id, if it is trusted."""
        return self._keys.get(key_id)

    def __contains__(self, key_id: object) -> bool:
        return key_id in self._keys

    def __iter__(self) -> Iterator[Verifier]:
        return iter(tuple(self._keys.values()))

    def __len__(self) -> int:
        return len(self._keys)

    def __repr__(self) -> str:
        return f"Keyring({sorted(self._keys)!r})"


def _same_key(a: Verifier, b: Verifier) -> bool:
    if a is b:
        return True
    if a.alg != b.alg:
        return False
    if isinstance(a, Ed25519PublicKey) and isinstance(b, Ed25519PublicKey):
        return a == b
    if isinstance(a, HmacKey) and isinstance(b, HmacKey):
        return hmac.compare_digest(a._secret, b._secret)
    return False


# --------------------------------------------------------------------------
# Signing without blocking an event loop
# --------------------------------------------------------------------------


@runtime_checkable
class AsyncSigner(Protocol):
    """A signer a coroutine awaits: its event loop never waits on the key."""

    @property
    def alg(self) -> str: ...

    @property
    def key_id(self) -> str: ...

    def public_key(self) -> Verifier: ...

    async def sign_async(self, message: bytes) -> bytes:
        """Sign ``message``, which already carries its domain prefix."""
        ...


class _ThreadedSigner:
    """A :class:`Signer` whose ``sign`` runs on a worker thread."""

    __slots__ = ("_signer",)

    def __init__(self, signer: Signer) -> None:
        self._signer = signer

    @property
    def alg(self) -> str:
        return self._signer.alg

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    def public_key(self) -> Verifier:
        return verifier_of(self._signer)

    def sign(self, message: bytes) -> bytes:
        return self._signer.sign(message)

    async def sign_async(self, message: bytes) -> bytes:
        return await asyncio.to_thread(self._signer.sign, message)

    def __repr__(self) -> str:
        return f"as_async({self._signer!r})"


def as_async(signer: Signer | AsyncSigner) -> AsyncSigner:
    """``signer`` as an :class:`AsyncSigner`: itself if it already has
    ``sign_async`` (a :class:`RemoteSigner` does), otherwise its ``sign`` on a
    worker thread."""
    if callable(getattr(signer, "sign_async", None)):
        return signer  # type: ignore[return-value]
    return _ThreadedSigner(signer)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Keys held elsewhere
# --------------------------------------------------------------------------

_KEY_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SIGNATURE_BYTES: Final = 64
_MAX_ANSWER: Final = 65536
"""The most of a key service's answer that is read: a key or a signature is
far shorter."""


class RemoteSigner:
    """An Ed25519 key a key service holds (a cloud KMS, an HSM, Vault's
    transit engine), signing through the :class:`Signer` protocol. The process
    never holds the private key: it holds the key's name at the service, the
    version it pinned, the public half, and a credential.

    A subclass implements :meth:`_remote_key`, the version and public key to
    pin, which the constructor calls once, and :meth:`_remote_sign`.

    Every signature the service hands back is verified under the pinned public
    key before it is returned. A service that signs with another key, or
    another version, or answers with anything but a signature, fails the call
    with :class:`~agentgov.exceptions.SignerUnavailableError`: what it answered
    never becomes a signature that does not verify.

    A signer pins one version of its key when it is built and signs with that
    version only, because a document names its key before it is signed. A
    rotated key is a new signer.

    :raises SignerUnavailableError: If the service cannot be reached, or
        answers with anything but an Ed25519 public key.
    """

    __slots__ = ("_public", "_version")

    def __init__(self) -> None:
        version, raw = self._remote_key()
        try:
            self._public = Ed25519PublicKey(raw)
        except ValueError as exc:
            raise SignerUnavailableError(
                f"{self.describe()}: its public key is not an Ed25519 key: {exc}"
            ) from exc
        self._version = version

    # -- what a subclass implements ---------------------------------------------

    def _remote_key(self) -> tuple[int, bytes]:
        """The version to pin, and its 32-byte public key."""
        raise NotImplementedError

    def _remote_sign(self, message: bytes) -> bytes:
        """The service's signature of ``message`` with the pinned version."""
        raise NotImplementedError

    def describe(self) -> str:
        """Where the key is, for messages: never a credential."""
        return type(self).__name__

    # -- the Signer protocol ----------------------------------------------------

    @property
    def alg(self) -> str:
        return ALG_ED25519

    @property
    def key_id(self) -> str:
        """Derived from the public key as ARC1 derives it: one key, local or
        remote, has one id."""
        return self._public.key_id

    @property
    def version(self) -> int:
        """The version of the key this signer signs with."""
        return self._version

    def public_key(self) -> Ed25519PublicKey:
        return self._public

    def sign(self, message: bytes) -> bytes:
        """The service's signature of ``message``, verified here first.

        :raises SignerUnavailableError: If the service cannot be reached, or
            answers with a signature the pinned key does not verify.
        """
        message = bytes(message)
        signature = self._remote_sign(message)
        if len(signature) != _SIGNATURE_BYTES or not self._public.verify(message, signature):
            raise SignerUnavailableError(
                f"{self.describe()} answered with a signature its key {self.key_id} "
                f"(version {self._version}) does not verify: nothing is signed"
            )
        return signature

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self._public.verify(message, signature)

    async def sign_async(self, message: bytes) -> bytes:
        """:meth:`sign`, on a worker thread: a coroutine's event loop never
        waits on the service."""
        return await asyncio.to_thread(self.sign, message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(key_id={self.key_id!r}, version={self._version})"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A key service that redirects is answered as one that refused: a
    redirect could carry the credential to another host."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class HttpRemoteSigner(RemoteSigner):
    """A key at a signing service over HTTP, in a minimal protocol shaped like
    Vault's transit engine::

        GET  {url}/v1/keys/{name}[?version=N]  -> {"alg": "ed25519", "version": N,
                                                   "public_key": "<hex>"}
        POST {url}/v1/keys/{name}/sign          <- {"version": N, "message": "<base64>"}
                                                 -> {"version": N, "signature": "<hex>"}

    with ``Authorization: Bearer <token>`` when it has a token. A redirect is
    never followed. An adapter for another service subclasses
    :class:`RemoteSigner` instead.

    :param url: The service: ``https://host[:port][/prefix]``.
    :param key: The key's name at the service.
    :param token: Sent as ``Authorization: Bearer``; read it from the
        environment, never from a file anyone else reads.
    :param timeout: The most one request may take, in seconds.
    :param version: The version to pin; the service's latest by default.
    :raises ValueError: On a url, a key name or a timeout that is not one.
    :raises SignerUnavailableError: If the service cannot be reached, or
        does not answer with an Ed25519 key.
    """

    __slots__ = ("_key", "_opener", "_pin", "_timeout", "_token", "_url")

    def __init__(
        self,
        url: str,
        key: str,
        *,
        token: str | None = None,
        timeout: float = 5.0,
        version: int | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"a signing service's url is http(s)://host[:port], not {url!r}")
        if not _KEY_NAME.fullmatch(key):
            raise ValueError(f"a key's name is letters, digits, '.', '_' and '-', not {key!r}")
        if not timeout > 0:
            raise ValueError("a signing service's timeout is positive")
        if version is not None and version < 1:
            raise ValueError("a key's version is a positive integer")
        self._url = url.rstrip("/")
        self._key = key
        self._token = token
        self._timeout = float(timeout)
        self._pin = version
        self._opener = urllib.request.build_opener(_NoRedirect)
        super().__init__()

    def describe(self) -> str:
        return f"the signing service at {self._url} (key {self._key!r})"

    def _remote_key(self) -> tuple[int, bytes]:
        query = "" if self._pin is None else f"?version={self._pin}"
        answer = self._call("GET", f"/v1/keys/{self._key}{query}", None)
        version = answer.get("version")
        public = answer.get("public_key")
        if answer.get("alg") != ALG_ED25519:
            raise SignerUnavailableError(
                f"{self.describe()} holds a {answer.get('alg')!r} key, not an Ed25519 one"
            )
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise SignerUnavailableError(f"{self.describe()} names no version of its key")
        if self._pin is not None and version != self._pin:
            raise SignerUnavailableError(
                f"{self.describe()} answered for version {version}, not {self._pin}"
            )
        try:
            raw = bytes.fromhex(str(public))
        except ValueError:
            raise SignerUnavailableError(f"{self.describe()}: its public key is not hex") from None
        return version, raw

    def _remote_sign(self, message: bytes) -> bytes:
        answer = self._call(
            "POST",
            f"/v1/keys/{self._key}/sign",
            {"version": self._version, "message": base64.b64encode(message).decode("ascii")},
        )
        if answer.get("version") != self._version:
            raise SignerUnavailableError(
                f"{self.describe()} signed with version {answer.get('version')!r}, not the "
                f"pinned {self._version}: nothing is signed"
            )
        try:
            return bytes.fromhex(str(answer.get("signature")))
        except (ValueError, binascii.Error):
            raise SignerUnavailableError(
                f"{self.describe()} answered with a signature that is not hex"
            ) from None

    def _call(self, method: str, path: str, body: dict[str, Any] | None) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        # http or https only: the constructor refuses any other scheme.
        request = urllib.request.Request(self._url + path, data=data, method=method)  # noqa: S310
        request.add_header("Accept", "application/json")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self._token:
            request.add_header("Authorization", f"Bearer {self._token}")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(_MAX_ANSWER)
        except urllib.error.HTTPError as exc:
            raise SignerUnavailableError(
                f"{self.describe()} answered {exc.code} {exc.reason}"
            ) from None
        except (urllib.error.URLError, OSError) as exc:
            raise SignerUnavailableError(f"{self.describe()} could not be reached: {exc}") from exc
        try:
            answer = json.loads(raw)
        except ValueError:
            raise SignerUnavailableError(f"{self.describe()} answered with no JSON") from None
        if not isinstance(answer, dict):
            raise SignerUnavailableError(f"{self.describe()} answered with no JSON object")
        return answer
