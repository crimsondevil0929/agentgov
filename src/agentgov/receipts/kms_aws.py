"""An Ed25519 key held by AWS KMS, as a :class:`~agentgov.receipts.signing.RemoteSigner`.

Needs ``boto3`` (``pip install 'agentgov[kms-aws]'``). The key is an
asymmetric KMS key of key spec ``ECC_NIST_EDWARDS25519`` and key usage
``SIGN_VERIFY``, and it signs with exactly one combination::

    SigningAlgorithm = "ED25519_SHA_512"    # pure Ed25519 (FIPS 186-5, 7.6)
    MessageType      = "RAW"                # the message itself, not a digest

KMS's other Ed25519 mode, ``ED25519_PH_SHA_512`` with ``MessageType=DIGEST``,
is Ed25519ph (HashEdDSA): its signatures do not verify as Ed25519, and this
signer never asks for it. KMS signs at most 4096 bytes, so the signer signs at
ARC1 signature version 2 by default: every message it is given is a domain
and a SHA-512, at most 84 bytes, whatever the document's size.

The key is pinned when the signer is built: given an alias, the signer signs
with the key the alias named then (by its ARN), so moving the alias later
never changes the key behind a ``key_id``. Every signature is verified under
the pinned public key before it is returned (:class:`RemoteSigner`).
"""

from __future__ import annotations

from typing import Any, Final

from agentgov.exceptions import SignerUnavailableError
from agentgov.receipts.signing import RemoteSigner

__all__ = ["AwsKmsSigner"]

KEY_SPEC: Final = "ECC_NIST_EDWARDS25519"
KEY_USAGE: Final = "SIGN_VERIFY"
SIGNING_ALGORITHM: Final = "ED25519_SHA_512"
MESSAGE_TYPE: Final = "RAW"
MAX_MESSAGE: Final = 4096
"""The most bytes KMS signs as a raw message."""
_SPKI_PREFIX: Final = bytes.fromhex("302a300506032b6570032100")
"""An Ed25519 SubjectPublicKeyInfo (RFC 8410) before its 32-byte key."""


class AwsKmsSigner(RemoteSigner):
    """An Ed25519 key in AWS KMS (module docstring).

    :param key_id: The KMS key: its id, its ARN, an alias name
        (``"alias/..."``) or an alias ARN. It is resolved to the key's ARN
        once, here.
    :param client: A boto3 KMS client, ``boto3.client("kms", ...)``; one from
        the default session (and ``region``) when omitted.
    :param region: The region for that default client.
    :raises SignerUnavailableError: If boto3 is missing, KMS cannot be
        reached, or the key is not an Ed25519 signing key.
    """

    signature_version = 2

    __slots__ = ("_arn", "_client", "_key")

    def __init__(self, key_id: str, *, client: Any = None, region: str | None = None) -> None:
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("a KMS key is named by its id, ARN or alias")
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise SignerUnavailableError(
                    "an AWS KMS signer needs boto3: pip install 'agentgov[kms-aws]'"
                ) from exc
            client = boto3.client("kms", region_name=region)
        self._client = client
        self._key = key_id
        self._arn = key_id
        super().__init__()

    def describe(self) -> str:
        named = self._key if self._arn == self._key else f"{self._key} ({self._arn})"
        return f"the AWS KMS key {named}"

    @property
    def arn(self) -> str:
        """The ARN of the key this signer signs with."""
        return self._arn

    def _remote_key(self) -> tuple[int, bytes]:
        answer = self._call("GetPublicKey", self._client.get_public_key, KeyId=self._key)
        spec, usage = answer.get("KeySpec"), answer.get("KeyUsage")
        if spec != KEY_SPEC:
            raise SignerUnavailableError(
                f"{self.describe()} is a {spec!r} key, not an Ed25519 one ({KEY_SPEC})"
            )
        if usage != KEY_USAGE:
            raise SignerUnavailableError(f"{self.describe()} is for {usage!r}, not {KEY_USAGE}")
        if SIGNING_ALGORITHM not in (answer.get("SigningAlgorithms") or ()):
            raise SignerUnavailableError(f"{self.describe()} does not sign {SIGNING_ALGORITHM}")
        public = answer.get("PublicKey")
        if (
            not isinstance(public, (bytes, bytearray))
            or len(public) != len(_SPKI_PREFIX) + 32
            or not bytes(public).startswith(_SPKI_PREFIX)
        ):
            raise SignerUnavailableError(
                f"{self.describe()}: its public key is not an Ed25519 SubjectPublicKeyInfo"
            )
        arn = answer.get("KeyId")
        if isinstance(arn, str) and arn:
            self._arn = arn  # an alias may move later; this key never does
        # A KMS key's material never changes: its one version is 1.
        return 1, bytes(public)[len(_SPKI_PREFIX) :]

    def _remote_sign(self, message: bytes) -> bytes:
        if not 0 < len(message) <= MAX_MESSAGE:
            raise SignerUnavailableError(
                f"{self.describe()}: KMS signs 1 to {MAX_MESSAGE} bytes, and this message is "
                f"{len(message)}; sign at ARC1 signature version 2, whose messages are at most "
                f"84 bytes"
            )
        answer = self._call(
            "Sign",
            self._client.sign,
            KeyId=self._arn,
            Message=message,
            MessageType=MESSAGE_TYPE,
            SigningAlgorithm=SIGNING_ALGORITHM,
        )
        if answer.get("SigningAlgorithm") != SIGNING_ALGORITHM:
            raise SignerUnavailableError(
                f"{self.describe()} answered with a {answer.get('SigningAlgorithm')!r} "
                f"signature, not {SIGNING_ALGORITHM}: nothing is signed"
            )
        signature = answer.get("Signature")
        if not isinstance(signature, (bytes, bytearray)):
            raise SignerUnavailableError(f"{self.describe()} answered with no signature")
        return bytes(signature)

    def _call(self, operation: str, method: Any, **request: Any) -> dict[str, Any]:
        try:
            answer = method(**request)
        except Exception as exc:  # botocore's errors, and any transport failure
            response = getattr(exc, "response", None)
            error = response.get("Error") if isinstance(response, dict) else None
            code = error.get("Code") if isinstance(error, dict) else None
            reason = code or type(exc).__name__
            raise SignerUnavailableError(
                f"{self.describe()}: {operation} failed: {reason}"
            ) from exc
        if not isinstance(answer, dict):
            raise SignerUnavailableError(f"{self.describe()}: {operation} answered with nothing")
        return answer
