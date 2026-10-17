"""Signers whose key lives elsewhere, and verifying without a signer.

- A key at the service signs exactly as the same key would here: one key id,
  one signature.
- A signer pins the version it was built with; a rotated key is a new signer.
- Every way a service can fail (unreachable, refusing, slow, signing with
  another key or version, answering with garbage) is an error, never a
  signature that does not verify; and no error carries the credential.
- A coroutine's loop never waits on the service.
- Verifying needs a key, never a signer: a keyring holds keys by id, and every
  signer hands over its public key.

The service is ``tests/fakekms.py``, the fake Interlock's tests use, so the
two projects' remote signers are held to the same protocol.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from agentgov.exceptions import SignerUnavailableError
from agentgov.receipts import (
    ActionReceipt,
    AsyncSigner,
    Ed25519PublicKey,
    Ed25519Signer,
    HmacKey,
    HttpRemoteSigner,
    Keyring,
    ReceiptBundle,
    ReceiptLog,
    RemoteSigner,
    Signer,
    as_async,
    verifier_of,
    verify_bundle,
)
from tests.fakekms import (
    GARBAGE,
    NOT_JSON,
    OTHER_ALG,
    OTHER_KEY,
    WRONG_PIN,
    WRONG_VERSION,
    FakeKms,
)

TOKEN = "kms-token-" + secrets.token_hex(8)
VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"


@pytest.fixture
def kms() -> Iterator[FakeKms]:
    with FakeKms(token=TOKEN) as service:
        yield service


def remote(kms: FakeKms, name: str = "relay", **kwargs: Any) -> HttpRemoteSigner:
    return HttpRemoteSigner(kms.url, name, token=TOKEN, **kwargs)


def test_a_remote_key_signs_as_the_same_key_would_here(kms: FakeKms) -> None:
    seed = secrets.token_bytes(32)
    kms.create("relay", seed)
    local = Ed25519Signer(seed)
    signer = remote(kms)
    assert isinstance(signer, RemoteSigner) and signer.alg == "ed25519"
    assert signer.key_id == local.key_id and signer.version == 1
    assert signer.public_key() == local.public_key()
    message = b"ARC1/attestation/v1\nwhatever is signed"
    # Ed25519 is deterministic: the service's signature is the local one.
    assert signer.sign(message) == local.sign(message)
    assert signer.verify(message, local.sign(message))
    assert not signer.verify(message + b"!", local.sign(message))
    assert kms.signed[("relay", 1)] == 1
    assert repr(signer) == f"HttpRemoteSigner(key_id={local.key_id!r}, version=1)"


def test_a_signer_pins_its_version_and_a_rotated_key_is_a_new_signer(kms: FakeKms) -> None:
    first = kms.create("relay")
    before = remote(kms)
    second = kms.rotate("relay")
    after = remote(kms)
    assert (before.version, after.version) == (1, 2)
    assert before.key_id == first.key_id and after.key_id == second.key_id
    message = b"one message"
    assert before.sign(message) == first.sign(message)
    assert after.sign(message) == second.sign(message)
    assert kms.signed == {("relay", 1): 1, ("relay", 2): 1}
    # A version can be pinned outright, an old one included.
    assert remote(kms, version=1).key_id == first.key_id
    with pytest.raises(SignerUnavailableError, match="404"):
        remote(kms, version=3)


@pytest.mark.parametrize(
    ("misbehave", "status", "match"),
    [
        (GARBAGE, None, "does not verify: nothing is signed"),
        (OTHER_KEY, None, "does not verify: nothing is signed"),
        (WRONG_VERSION, None, "signed with version 2, not the pinned 1"),
        (NOT_JSON, None, "answered with no JSON"),
        (None, 500, "answered 500"),
        (None, 403, "answered 403"),
        (None, 307, "answered 307"),  # a redirect is never followed: the token stays here
    ],
)
def test_a_service_that_fails_to_sign_is_an_error_never_a_signature(
    kms: FakeKms, misbehave: str | None, status: int | None, match: str
) -> None:
    kms.create("relay")
    signer = remote(kms)
    kms.misbehave, kms.status = misbehave, status
    with pytest.raises(SignerUnavailableError, match=match) as raised:
        signer.sign(b"a message")
    assert TOKEN not in str(raised.value)


def test_a_redirect_is_never_followed_and_the_token_never_leaves(kms: FakeKms) -> None:
    """A service that answers 307 to another host is answered as one that
    refused: following it would hand the bearer token to that host."""
    with FakeKms(token=TOKEN) as elsewhere:
        kms.create("relay")
        elsewhere.create("relay")
        kms.redirect = elsewhere.url
        with pytest.raises(SignerUnavailableError, match="answered 307"):
            remote(kms)
        assert not elsewhere.requests


def test_a_service_that_cannot_be_used_refuses_the_signer(kms: FakeKms) -> None:
    kms.create("relay")
    with pytest.raises(SignerUnavailableError, match="401") as raised:
        HttpRemoteSigner(kms.url, "relay", token="not-the-token")  # noqa: S106
    assert "not-the-token" not in str(raised.value)
    with pytest.raises(SignerUnavailableError, match="404"):
        remote(kms, "nobody")
    kms.delay = 0.5
    began = time.monotonic()
    with pytest.raises(SignerUnavailableError, match="could not be reached"):
        remote(kms, timeout=0.1)
    assert time.monotonic() - began < 0.45
    kms.delay = 0.0
    kms.close()
    with pytest.raises(SignerUnavailableError, match="could not be reached"):
        remote(kms)


@pytest.mark.parametrize(
    ("misbehave", "match"),
    [(OTHER_ALG, "holds a 'rsa' key, not an Ed25519 one"), (WRONG_PIN, "for version 2, not 1")],
)
def test_a_service_publishing_another_key_refuses_the_signer(
    kms: FakeKms, misbehave: str, match: str
) -> None:
    kms.create("relay")
    kms.rotate("relay")
    kms.misbehave = misbehave
    with pytest.raises(SignerUnavailableError, match=match):
        remote(kms, version=1)


@pytest.mark.parametrize(
    ("url", "key", "kwargs", "match"),
    [
        ("ftp://kms/", "relay", {}, "http"),
        ("http://", "relay", {}, "http"),
        ("http://kms", "../relay", {}, "name"),
        ("http://kms", "relay", {"timeout": 0}, "timeout"),
        ("http://kms", "relay", {"version": 0}, "version"),
    ],
)
def test_what_is_no_service_is_refused_before_a_request(
    url: str, key: str, kwargs: dict[str, Any], match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        HttpRemoteSigner(url, key, **kwargs)


def test_a_key_that_is_not_ed25519_refuses_the_signer() -> None:
    class Short(RemoteSigner):
        def _remote_key(self) -> tuple[int, bytes]:
            return 1, b"\x01" * 31

    with pytest.raises(SignerUnavailableError, match="Short: its public key is not an Ed25519"):
        Short()


def test_signing_off_the_loop_leaves_it_running(kms: FakeKms) -> None:
    kms.create("relay")
    signer = remote(kms)
    kms.delay = 0.2

    async def main() -> tuple[float, int, list[bytes]]:
        ticks = 0
        done = asyncio.Event()

        async def tick() -> None:
            nonlocal ticks
            while not done.is_set():
                ticks += 1
                await asyncio.sleep(0.01)

        ticker = asyncio.create_task(tick())
        began = time.monotonic()
        signatures = await asyncio.gather(
            *(signer.sign_async(f"message {n}".encode()) for n in range(8))
        )
        took = time.monotonic() - began
        done.set()
        await ticker
        return took, ticks, list(signatures)

    took, ticks, signatures = asyncio.run(main())
    # Eight round trips of 200 ms at once take about one, and the loop ticked
    # all the while.
    assert took < 0.8 and ticks >= 10
    assert all(signer.verify(f"message {n}".encode(), s) for n, s in enumerate(signatures))


# -- through ARC1 ----------------------------------------------------------------


def _draft(n: int) -> ActionReceipt:
    template = ReceiptBundle.loads(
        (VECTORS / "valid" / "committed-refund.bundle.json").read_bytes()
    ).action_receipt
    return replace(template, receipt_id=f"00000000-0000-4000-8000-{n:012d}", signature=None)


def test_a_receipt_log_signs_through_a_remote_key(kms: FakeKms, tmp_path: Path) -> None:
    kms.create("issuer")
    signer = remote(kms, "issuer")
    path = tmp_path / "receipts.jsonl"
    with ReceiptLog("support-eu-1", signer, path=path) as log:
        receipts = [log.issue(_draft(n)) for n in range(3)]
        bundle = log.bundle(2)
    report = verify_bundle(bundle, issuer_key=signer.public_key())
    assert report.passed, report.to_json()
    assert all(r.signature is not None and r.signature.key_id == signer.key_id for r in receipts)
    assert kms.signed[("issuer", 1)] == 4  # three receipts and one checkpoint


# -- verifying without a signer ---------------------------------------------------


def test_every_signer_hands_over_what_verifies_it() -> None:
    ed = Ed25519Signer.generate()
    assert verifier_of(ed) == ed.public_key()
    assert isinstance(verifier_of(ed), Ed25519PublicKey)
    hmac_key = HmacKey.generate()
    assert hmac_key.public_key() is hmac_key and verifier_of(hmac_key) is hmac_key

    class Legacy:
        """A signer written before public_key joined the protocol."""

        alg, key_id = "hmac-sha256", "0123456789abcdef"

        def sign(self, message: bytes) -> bytes:
            return b""

        def verify(self, message: bytes, signature: bytes) -> bool:
            return True

    legacy = Legacy()
    assert verifier_of(legacy) is legacy  # type: ignore[arg-type]
    assert isinstance(ed, Signer) and isinstance(hmac_key, Signer)


def test_a_keyring_holds_keys_by_id_and_one_id_names_one_key() -> None:
    first, second = Ed25519Signer.generate(), Ed25519Signer.generate()
    ring = Keyring([first.public_key(), second.public_key().spec()])
    assert len(ring) == 2 and first.key_id in ring and second.key_id in ring
    assert ring.get(first.key_id) == first.public_key()
    assert ring.get("ffffffffffffffff") is None
    assert {k.key_id for k in ring} == {first.key_id, second.key_id}
    assert ring.add(first.public_key()) == first.public_key()  # again: nothing changes
    assert len(ring) == 2
    secret = HmacKey(b"k" * 32, key_id="feedfacefeedface")
    ring.add(secret)
    ring.add(HmacKey(b"k" * 32, key_id="feedfacefeedface"))  # the same key, rebuilt
    with pytest.raises(ValueError, match="two different keys have id feedfacefeedface"):
        ring.add(HmacKey(b"x" * 32, key_id="feedfacefeedface"))
    with pytest.raises(ValueError, match="does not parse"):
        Keyring(["ed25519:beef"])
    assert repr(Keyring()) == "Keyring([])"


def test_a_keyring_is_made_from_a_key_several_keys_or_a_keyring() -> None:
    key = Ed25519Signer.generate().public_key()
    ring = Keyring.of(key)
    assert list(ring) == [key]
    assert Keyring.of(ring) is ring
    assert list(Keyring.of(key.spec())) == [key]
    assert list(Keyring.of([key])) == [key]


def test_any_signer_signs_off_the_loop(kms: FakeKms) -> None:
    local = Ed25519Signer.generate()
    threaded = as_async(local)
    assert isinstance(threaded, AsyncSigner)
    assert (threaded.alg, threaded.key_id) == (local.alg, local.key_id)
    assert threaded.public_key() == local.public_key()
    assert repr(threaded) == f"as_async({local!r})"
    kms.create("relay")
    signer = remote(kms)
    assert as_async(signer) is signer  # it has sign_async already
    signature = asyncio.run(threaded.sign_async(b"m"))
    assert local.public_key().verify(b"m", signature)
