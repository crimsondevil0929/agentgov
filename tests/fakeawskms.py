"""A stand-in for a boto3 KMS client: asymmetric keys as AWS KMS holds them.

It answers ``get_public_key`` and ``sign`` with the request and response
shapes AWS documents (``PublicKey`` a DER SubjectPublicKeyInfo, ``Signature``
raw bytes, ``KeyId`` the key's ARN), and refuses what AWS refuses: a message
over 4096 bytes, ``ED25519_SHA_512`` without ``MessageType=RAW``,
``ED25519_PH_SHA_512`` without ``MessageType=DIGEST``, a disabled key, an
unknown key or alias. Errors are shaped like botocore's ``ClientError``.

Its ``ED25519_PH_SHA_512`` signatures stand in for Ed25519ph: like the real
ones, they do not verify as Ed25519 over the message.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import Any

from agentgov.receipts.signing import Ed25519Signer

_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class ClientError(Exception):
    """Shaped like botocore's: the code is in ``response["Error"]["Code"]``."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"An error occurred ({code}) when calling KMS: {message}")
        self.response = {"Error": {"Code": code, "Message": message}}


class FakeAwsKms:
    """Keys by ARN, aliases, and a record of every call made."""

    def __init__(self, region: str = "us-east-1", account: str = "111122223333") -> None:
        self.region, self.account = region, account
        self.keys: dict[str, dict[str, Any]] = {}
        self.aliases: dict[str, str] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.unreachable = False
        self.answer_algorithm: str | None = None
        """Answer every Sign with this SigningAlgorithm, when set."""

    def create_key(
        self,
        *,
        spec: str = "ECC_NIST_EDWARDS25519",
        usage: str = "SIGN_VERIFY",
        seed: bytes | None = None,
    ) -> str:
        """A key; returns its ARN."""
        key_id = f"{secrets.token_hex(4)}-{secrets.token_hex(2)}-4000-8000-{secrets.token_hex(6)}"
        arn = f"arn:aws:kms:{self.region}:{self.account}:key/{key_id}"
        signer = Ed25519Signer(seed if seed is not None else secrets.token_bytes(32))
        self.keys[arn] = {"spec": spec, "usage": usage, "signer": signer, "enabled": True}
        return arn

    def alias(self, name: str, arn: str) -> None:
        self.aliases[name] = arn

    def signer(self, arn: str) -> Ed25519Signer:
        found: Ed25519Signer = self.keys[arn]["signer"]
        return found

    # -- the client ---------------------------------------------------------------

    def get_public_key(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("GetPublicKey", request))
        arn = self._resolve(request["KeyId"])
        key = self.keys[arn]
        if key["spec"] == "ECC_NIST_EDWARDS25519":
            public = _SPKI_PREFIX + key["signer"].public_key().raw
            algorithms = ["ED25519_SHA_512", "ED25519_PH_SHA_512"]
        else:  # some other key: not an Ed25519 SubjectPublicKeyInfo
            public = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + (
                secrets.token_bytes(64)
            )
            algorithms = ["ECDSA_SHA_256"]
        return {
            "KeyId": arn,
            "KeySpec": key["spec"],
            "KeyUsage": key["usage"],
            "PublicKey": public,
            **({"SigningAlgorithms": algorithms} if key["usage"] == "SIGN_VERIFY" else {}),
        }

    def sign(self, **request: Any) -> dict[str, Any]:
        self.calls.append(("Sign", request))
        arn = self._resolve(request["KeyId"])
        key = self.keys[arn]
        message: bytes = request["Message"]
        algorithm = request["SigningAlgorithm"]
        message_type = request.get("MessageType", "RAW")
        if not 1 <= len(message) <= 4096:
            raise ClientError("ValidationException", "Message must be 1 to 4096 bytes")
        if not key["enabled"]:
            raise ClientError("DisabledException", f"{arn} is disabled")
        if key["spec"] != "ECC_NIST_EDWARDS25519" or key["usage"] != "SIGN_VERIFY":
            raise ClientError("InvalidKeyUsageException", "not an Ed25519 signing key")
        if algorithm == "ED25519_SHA_512":
            if message_type != "RAW":
                raise ClientError("ValidationException", "ED25519_SHA_512 requires RAW")
            signature = key["signer"].sign(message)
        elif algorithm == "ED25519_PH_SHA_512":
            if message_type != "DIGEST" or len(message) != 64:
                raise ClientError("ValidationException", "ED25519_PH_SHA_512 requires DIGEST")
            # HashEdDSA signs a domain-separated prehash: never the message itself.
            signature = key["signer"].sign(b"SigEd25519 ph" + hashlib.sha512(message).digest())
        else:
            raise ClientError("InvalidKeyUsageException", f"{algorithm} is not for this key")
        return {
            "KeyId": arn,
            "Signature": signature,
            "SigningAlgorithm": self.answer_algorithm or algorithm,
        }

    def _resolve(self, key_id: str) -> str:
        if self.unreachable:
            raise ConnectionError("Could not connect to the endpoint URL")
        arn = self.aliases.get(key_id, key_id)
        if arn in self.keys:
            return arn
        for candidate in self.keys:
            if candidate.endswith("/" + key_id):
                return candidate
        raise ClientError("NotFoundException", f"{key_id} does not exist")
