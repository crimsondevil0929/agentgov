"""The AWS KMS adapter (D8), against a fake KMS client shaped like boto3's.

- It signs with the only correct combination for ARC1: an
  ``ECC_NIST_EDWARDS25519`` key, ``ED25519_SHA_512``, ``MessageType=RAW``
  (D3). KMS's Ed25519ph mode does not verify as Ed25519, and is never used.
- It signs at signature version 2, so any receipt fits KMS's 4096 bytes.
- A key is pinned by ARN when the signer is built: an alias moved later
  changes nothing.
- A key that is not an Ed25519 signing key, a disabled key, an unreachable
  service, a wrong answer: each is an error, never a signature.
"""

from __future__ import annotations

import builtins
import secrets
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from agentgov.exceptions import SignerUnavailableError
from agentgov.receipts import (
    CheckpointPolicy,
    Ed25519PublicKey,
    Ed25519Signer,
    ReceiptBundle,
    ReceiptLog,
    verify_bundle,
)
from agentgov.receipts.kms_aws import (
    KEY_SPEC,
    MESSAGE_TYPE,
    SIGNING_ALGORITHM,
    AwsKmsSigner,
)
from tests.fakeawskms import FakeAwsKms

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
TEMPLATE = ReceiptBundle.loads(
    (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
).action_receipt


@pytest.fixture
def kms() -> FakeAwsKms:
    return FakeAwsKms()


def test_a_kms_key_signs_as_the_same_key_would_here(kms: FakeAwsKms) -> None:
    seed = secrets.token_bytes(32)
    arn = kms.create_key(seed=seed)
    local = Ed25519Signer(seed)
    signer = AwsKmsSigner(arn, client=kms)
    assert signer.key_id == local.key_id and signer.public_key() == local.public_key()
    assert signer.arn == arn and signer.version == 1
    message = b"ARC1/receipt/v2\n" + bytes(64)
    assert signer.sign(message) == local.sign(message)
    assert kms.calls == [
        ("GetPublicKey", {"KeyId": arn}),
        (
            "Sign",
            {
                "KeyId": arn,
                "Message": message,
                "MessageType": "RAW",
                "SigningAlgorithm": "ED25519_SHA_512",
            },
        ),
    ]


def test_the_one_correct_combination_is_pinned(kms: FakeAwsKms) -> None:
    """ED25519_SHA_512 with RAW is pure Ed25519; KMS's ED25519_PH_SHA_512 is
    Ed25519ph, whose signatures do not verify as Ed25519."""
    assert (KEY_SPEC, SIGNING_ALGORITHM, MESSAGE_TYPE) == (
        "ECC_NIST_EDWARDS25519",
        "ED25519_SHA_512",
        "RAW",
    )
    arn = kms.create_key()
    public = kms.signer(arn).public_key()
    message = b"a message"
    import hashlib

    prehashed = kms.sign(
        KeyId=arn,
        Message=hashlib.sha512(message).digest(),
        MessageType="DIGEST",
        SigningAlgorithm="ED25519_PH_SHA_512",
    )["Signature"]
    assert not public.verify(message, prehashed)
    pure = kms.sign(
        KeyId=arn, Message=message, MessageType="RAW", SigningAlgorithm="ED25519_SHA_512"
    )["Signature"]
    assert public.verify(message, pure)


def test_it_signs_digests_so_any_receipt_fits(kms: FakeAwsKms, tmp_path: Path) -> None:
    signer = AwsKmsSigner(kms.create_key(), client=kms)
    assert signer.signature_version == 2
    gaps = tuple(sorted(f"gap {i:02d}: " + "unobserved side effect " * 18 for i in range(10)))
    big = replace(
        TEMPLATE,
        receipt_id="00000000-0000-4000-8000-000000000001",
        coverage=replace(TEMPLATE.coverage, known_gaps=gaps),
        anchors=replace(TEMPLATE.anchors, log=None),
        signature=None,
    )
    assert len(big.canonical()) > 4096
    never = CheckpointPolicy(every_receipts=10**6, every_seconds=10**9, background=False)
    with ReceiptLog("kms-log", signer, path=tmp_path / "r.jsonl", policy=never) as log:
        receipt = log.issue(big)
        bundle = log.bundle(0)
    assert receipt.signature is not None and receipt.signature.version == 2
    assert verify_bundle(bundle, issuer_key=signer.public_key()).passed
    assert all(len(call["Message"]) < 100 for name, call in kms.calls if name == "Sign")
    with pytest.raises(SignerUnavailableError, match="KMS signs 1 to 4096 bytes"):
        big.with_log_anchor("kms-log", 1).sign(signer, version=1)
    assert sum(name == "Sign" for name, _ in kms.calls) == 2, "the oversized one never left"


def test_an_alias_is_resolved_once_and_moving_it_changes_nothing(kms: FakeAwsKms) -> None:
    first, second = kms.create_key(), kms.create_key()
    kms.alias("alias/receipts", first)
    signer = AwsKmsSigner("alias/receipts", client=kms)
    assert signer.arn == first and signer.key_id == kms.signer(first).key_id
    assert "alias/receipts" in signer.describe() and first in signer.describe()
    kms.alias("alias/receipts", second)
    message = b"m" * 80
    assert kms.signer(first).public_key().verify(message, signer.sign(message))
    assert kms.calls[-1][1]["KeyId"] == first


@pytest.mark.parametrize(
    ("spec", "usage", "match"),
    [
        ("ECC_NIST_P256", "SIGN_VERIFY", "is a 'ECC_NIST_P256' key, not an Ed25519 one"),
        ("ECC_NIST_EDWARDS25519", "ENCRYPT_DECRYPT", "is for 'ENCRYPT_DECRYPT', not SIGN_VERIFY"),
    ],
)
def test_a_key_that_cannot_sign_ed25519_refuses_the_signer(
    kms: FakeAwsKms, spec: str, usage: str, match: str
) -> None:
    with pytest.raises(SignerUnavailableError, match=match):
        AwsKmsSigner(kms.create_key(spec=spec, usage=usage), client=kms)


def test_a_service_that_fails_is_an_error_never_a_signature(kms: FakeAwsKms) -> None:
    with pytest.raises(SignerUnavailableError, match="GetPublicKey failed: NotFoundException"):
        AwsKmsSigner("alias/nobody", client=kms)
    arn = kms.create_key()
    signer = AwsKmsSigner(arn, client=kms)
    kms.keys[arn]["enabled"] = False
    with pytest.raises(SignerUnavailableError, match="Sign failed: DisabledException"):
        signer.sign(b"m" * 80)
    kms.keys[arn]["enabled"] = True
    kms.answer_algorithm = "ED25519_PH_SHA_512"
    with pytest.raises(SignerUnavailableError, match="not ED25519_SHA_512: nothing is signed"):
        signer.sign(b"m" * 80)
    kms.answer_algorithm = None
    kms.unreachable = True
    with pytest.raises(SignerUnavailableError, match="Sign failed: ConnectionError"):
        signer.sign(b"m" * 80)


def test_a_service_that_signs_with_another_key_is_refused(kms: FakeAwsKms) -> None:
    arn = kms.create_key()
    signer = AwsKmsSigner(arn, client=kms)
    kms.keys[arn]["signer"] = Ed25519Signer.generate()  # the key behind the ARN changed
    with pytest.raises(SignerUnavailableError, match="does not verify: nothing is signed"):
        signer.sign(b"m" * 80)


def test_a_public_key_that_is_not_ed25519_spki_refuses_the_signer(kms: FakeAwsKms) -> None:
    arn = kms.create_key()
    original = kms.get_public_key

    def truncated(**request: Any) -> dict[str, Any]:
        answer = original(**request)
        return {**answer, "PublicKey": answer["PublicKey"][:-1]}

    kms.get_public_key = truncated  # type: ignore[method-assign]
    with pytest.raises(SignerUnavailableError, match="not an Ed25519 SubjectPublicKeyInfo"):
        AwsKmsSigner(arn, client=kms)


def test_without_boto3_the_signer_says_how_to_get_it(monkeypatch: pytest.MonkeyPatch) -> None:
    real = builtins.__import__

    def no_boto3(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "boto3":
            raise ImportError("No module named 'boto3'")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_boto3)
    with pytest.raises(SignerUnavailableError, match=r"agentgov\[kms-aws\]"):
        AwsKmsSigner("alias/receipts")
    with pytest.raises(ValueError, match="named by its id"):
        AwsKmsSigner("", client=object())


def test_its_key_id_is_the_arc1_id_of_its_public_key(kms: FakeAwsKms) -> None:
    arn = kms.create_key()
    signer = AwsKmsSigner(arn, client=kms)
    raw = kms.signer(arn).public_key().raw
    assert signer.key_id == Ed25519PublicKey(raw).key_id
    assert repr(signer) == f"AwsKmsSigner(key_id={signer.key_id!r}, version=1)"
