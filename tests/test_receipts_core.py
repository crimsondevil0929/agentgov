"""ARC1's building blocks, checked against the standards they implement.

- canonical JSON against RFC 8785 (JCS) over the ARC1 value domain;
- the Merkle tree and its proofs against RFC 9162 and the Certificate
  Transparency reference values;
- Ed25519 verification against RFC 8032, and against OpenSSL.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agentgov.exceptions import MalformedReceiptError, SignerUnavailableError
from agentgov.receipts import (
    Ed25519PublicKey,
    Ed25519Signer,
    HmacKey,
    MerkleTree,
    canonical_bytes,
    loads_strict,
    parse_key,
    verify_consistency,
    verify_inclusion,
)
from agentgov.receipts import _ed25519 as pure
from agentgov.receipts.merkle import EMPTY_ROOT, leaf_hash, node_hash

# --------------------------------------------------------------------------
# Canonical JSON (RFC 8785)
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "canonical"),
    [
        ({"b": 1, "a": 2, "c": {"z": True, "y": None}}, '{"a":2,"b":1,"c":{"y":null,"z":true}}'),
        ([], "[]"),
        ({}, "{}"),
        ([1, "x", False, None, [{}]], '[1,"x",false,null,[{}]]'),
        (2**53 - 1, "9007199254740991"),
        (-(2**53 - 1), "-9007199254740991"),
        ("é😀", '"é😀"'),
        ('q" b\\ \n\t\b\f\r', '"q\\" b\\\\ \\n\\t\\b\\f\\r"'),
        ("\u0001\u001f\u007f", '"\\u0001\\u001f\u007f"'),
    ],
)
def test_canonical_encoding_is_rfc8785(value: object, canonical: str) -> None:
    assert canonical_bytes(value) == canonical.encode("utf-8")


def test_object_keys_sort_by_utf16_code_units_not_code_points() -> None:
    """U+1F600 is above U+E000 as a code point but below it in UTF-16
    (0xD83D < 0xE000). RFC 8785 sorts by UTF-16, as JavaScript does."""
    encoded = canonical_bytes({"": 1, "\U0001f600": 2, "a": 3}).decode()
    assert encoded == '{"a":3,"\U0001f600":2,"":1}'
    assert sorted(["", "\U0001f600"]) == ["", "\U0001f600"], "unlike Python's order"


def test_booleans_are_not_integers() -> None:
    assert canonical_bytes([True, 1, False, 0]) == b"[true,1,false,0]"


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (1.5, "float"),
        ({"a": [0.1]}, r"\$\.a\[0\]"),
        (2**53, "safe range"),
        (-(2**53), "safe range"),
        ({1: "x"}, "not a string"),
        ({"s"}, "no canonical"),
        (b"bytes", "no canonical"),
        ("\ud800", "lone surrogate"),
        ({"\udc00": 1}, "lone surrogate"),
    ],
)
def test_values_outside_the_domain_are_refused(value: object, message: str) -> None:
    with pytest.raises(MalformedReceiptError, match=message):
        canonical_bytes(value)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('{"a":1,"a":2}', "duplicate object key 'a'"),
        ('{"a":{"b":1,"b":1}}', "duplicate"),
        ('{"a":1.0}', "fraction or exponent"),
        ('{"a":1e3}', "fraction or exponent"),
        ('{"a":NaN}', "not JSON"),
        ('{"a":-Infinity}', "not JSON"),
        ('{"a":', "not valid JSON"),
        (b"\xff", "not valid JSON"),
    ],
)
def test_strict_decoding_refuses_ambiguity(text: str | bytes, message: str) -> None:
    with pytest.raises(MalformedReceiptError, match=message):
        loads_strict(text)


def test_strict_decoding_keeps_what_it_can_represent() -> None:
    assert loads_strict('{"a":[1,"b",true,null]}') == {"a": [1, "b", True, None]}


# --------------------------------------------------------------------------
# The Merkle tree (RFC 9162)
# --------------------------------------------------------------------------

_CT_LEAVES = [
    bytes.fromhex(h)
    for h in (
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    )
]
# The roots every Certificate Transparency implementation's test suite uses.
_CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]
_CT_INCLUSION = {
    (0, 8): [
        "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
    ],
    (5, 8): [
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    ],
    (2, 3): ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"],
    (1, 5): [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
    ],
}
_CT_CONSISTENCY = {
    (1, 8): _CT_INCLUSION[(0, 8)],
    (6, 8): [
        "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
        "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    ],
    (2, 5): [
        "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
        "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
    ],
}


def _ct_tree() -> MerkleTree:
    return MerkleTree(leaf_hash(leaf) for leaf in _CT_LEAVES)


def test_the_tree_reproduces_the_certificate_transparency_reference_values() -> None:
    tree = _ct_tree()
    assert tree.root(0) == EMPTY_ROOT == hashlib.sha256(b"").digest()
    assert [tree.root(n).hex() for n in range(1, 9)] == _CT_ROOTS
    for (index, size), path in _CT_INCLUSION.items():
        assert [p.hex() for p in tree.inclusion_proof(index, size)] == path
    for (old, new), proof in _CT_CONSISTENCY.items():
        assert [p.hex() for p in tree.consistency_proof(old, new)] == proof


def _flip(node: bytes) -> bytes:
    return bytes([node[0] ^ 0x01]) + node[1:]


def test_every_proof_up_to_33_leaves_verifies_and_every_alteration_fails() -> None:
    tree = MerkleTree(leaf_hash(i.to_bytes(4, "big")) for i in range(33))
    for n in range(1, 34):
        root = tree.root(n)
        for m in range(n):
            path = tree.inclusion_proof(m, n)
            assert verify_inclusion(tree.leaf(m), m, n, path, root)
            assert not verify_inclusion(_flip(tree.leaf(m)), m, n, path, root)
            for j in range(len(path)):
                altered = [*path[:j], _flip(path[j]), *path[j + 1 :]]
                assert not verify_inclusion(tree.leaf(m), m, n, altered, root)
            for other in range(n):
                if other != m:
                    assert not verify_inclusion(tree.leaf(m), other, n, path, root)
            assert not verify_inclusion(tree.leaf(m), m, n, [*path, root], root)
            if path:
                assert not verify_inclusion(tree.leaf(m), m, n, path[:-1], root)
            if len(path) > 1:
                assert not verify_inclusion(tree.leaf(m), m, n, path[::-1], root)
        for m in range(n + 1):
            proof = tree.consistency_proof(m, n)
            assert verify_consistency(m, n, tree.root(m), root, proof)
            for j in range(len(proof)):
                altered = [*proof[:j], _flip(proof[j]), *proof[j + 1 :]]
                assert not verify_consistency(m, n, tree.root(m), root, altered)
            if 0 < m < n:
                assert not verify_consistency(m, n, _flip(tree.root(m)), root, proof)
                assert not verify_consistency(m, n, tree.root(m), _flip(root), proof)
                assert not verify_consistency(m, n, tree.root(m), root, [*proof, root])
                assert not verify_consistency(m, n, tree.root(m), root, proof[:-1])
                if len(proof) > 1:
                    assert not verify_consistency(m, n, tree.root(m), root, proof[::-1])


def test_reordering_two_leaves_changes_the_root_and_breaks_every_old_proof() -> None:
    leaves = [leaf_hash(f"receipt {i}".encode()) for i in range(7)]
    honest = MerkleTree(leaves)
    swapped = MerkleTree([leaves[1], leaves[0], *leaves[2:]])
    assert honest.root() != swapped.root()
    for index in range(7):
        assert not verify_inclusion(
            leaves[index], index, 7, honest.inclusion_proof(index), swapped.root()
        )
    assert not verify_inclusion(leaves[0], 0, 7, swapped.inclusion_proof(0), swapped.root())
    assert not verify_consistency(
        3, 7, honest.root(3), swapped.root(), swapped.consistency_proof(3)
    )


def test_proof_edges() -> None:
    tree = _ct_tree()
    leaf = tree.leaf(0)
    assert not verify_inclusion(leaf, 0, 0, [], EMPTY_ROOT)
    assert not verify_inclusion(leaf, 8, 8, [], tree.root())
    assert not verify_inclusion(leaf, -1, 8, [], tree.root())
    assert verify_consistency(0, 8, EMPTY_ROOT, tree.root(), [])
    assert not verify_consistency(0, 8, tree.root(1), tree.root(), [])
    assert not verify_consistency(0, 8, EMPTY_ROOT, tree.root(), [tree.root()])
    assert verify_consistency(8, 8, tree.root(), tree.root(), [])
    assert not verify_consistency(8, 8, tree.root(), tree.root(7), [])
    assert not verify_consistency(8, 8, tree.root(), tree.root(), [tree.root()])
    assert not verify_consistency(5, 4, tree.root(5), tree.root(4), [])
    assert not verify_consistency(3, 8, tree.root(3), tree.root(), [])
    assert tree.consistency_proof(0, 8) == [] and tree.consistency_proof(8) == []
    left, right = b"a" * 32, b"b" * 32
    assert node_hash(left, right) != node_hash(right, left)
    assert leaf_hash(left + right) != node_hash(left, right), "a node never hashes as a leaf"


def test_the_tree_refuses_what_is_not_a_tree() -> None:
    tree = _ct_tree()
    with pytest.raises(ValueError, match="32 bytes"):
        tree.append(b"short")
    with pytest.raises(ValueError, match="not 9"):
        tree.root(9)
    with pytest.raises(ValueError, match="not in a tree"):
        tree.inclusion_proof(8)
    with pytest.raises(ValueError, match="prefix"):
        tree.consistency_proof(9, 8)
    assert len(tree) == 8


# --------------------------------------------------------------------------
# Ed25519 (RFC 8032) and HMAC
# --------------------------------------------------------------------------

_RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac"
        "c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e"
        "458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290"
        "ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
]
_ORDER = 2**252 + 27742317777372353535851937790883648493


@pytest.mark.parametrize(("seed", "public", "message", "signature"), _RFC8032)
def test_ed25519_matches_rfc8032(seed: str, public: str, message: str, signature: str) -> None:
    signer = Ed25519Signer(bytes.fromhex(seed))
    assert signer.public_key().raw.hex() == public
    assert signer.sign(bytes.fromhex(message)).hex() == signature
    assert pure.verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature))


def _variants(signature: bytes) -> list[bytes]:
    r, s = signature[:32], int.from_bytes(signature[32:], "little")
    y_too_big = (2**255 - 19 + 1).to_bytes(32, "little")  # y >= p: not canonical
    negative_zero = (1 | (1 << 255)).to_bytes(32, "little")  # x = 0 with the sign bit set
    return [
        signature,
        _flip(signature),
        signature[:32] + _flip(signature[32:]),
        r + (s + _ORDER).to_bytes(32, "little"),
        r + (_ORDER).to_bytes(32, "little"),
        y_too_big + signature[32:],
        negative_zero + signature[32:],
        b"\x00" * 64,
        signature[:63],
        signature + b"\x00",
    ]


def test_the_pure_verifier_accepts_exactly_what_openssl_accepts() -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey as OpenSSLKey,
    )

    def openssl(public: bytes, message: bytes, signature: bytes) -> bool:
        try:
            OpenSSLKey.from_public_bytes(public).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True

    for i in range(40):
        signer = Ed25519Signer(hashlib.sha256(f"agreement {i}".encode()).digest())
        message = os.urandom(i * 7)
        public = signer.public_key().raw
        for candidate in _variants(signer.sign(message)):
            assert pure.verify(public, message, candidate) == openssl(public, message, candidate)
    assert not pure.verify(b"\x00" * 31, b"", b"\x00" * 64)
    assert not pure.verify((2**255 - 19 + 2).to_bytes(32, "little"), b"", b"\x00" * 64)


def test_ed25519_keys() -> None:
    signer = Ed25519Signer(b"\x07" * 32)
    public = signer.public_key()
    signature = signer.sign(b"message")
    assert signer.verify(b"message", signature) and public.verify(b"message", signature)
    assert not public.verify(b"message", signature[:63])
    assert signer.key_id == public.key_id and len(public.key_id) == 16
    assert parse_key(public.spec()) == public and hash(parse_key(public.spec())) == hash(public)
    assert public != signer and "ed25519:" in repr(public) and public.key_id in repr(signer)
    assert Ed25519Signer.generate().key_id != signer.key_id
    with pytest.raises(ValueError, match="32 bytes"):
        Ed25519Signer(b"\x00" * 31)
    with pytest.raises(ValueError, match="32 bytes"):
        Ed25519PublicKey(b"\x00" * 33)


def test_hmac_keys() -> None:
    key = HmacKey(b"k" * 32)
    signature = key.sign(b"message")
    assert key.verify(b"message", signature)
    assert not key.verify(b"message!", signature)
    assert key.alg == "hmac-sha256" and len(key.key_id) == 16
    assert b"k".hex() not in key.key_id, "the default key id reveals nothing about the key"
    assert HmacKey(b"k" * 32, key_id="ops-2026").key_id == "ops-2026"
    assert parse_key(key.spec()).verify(b"message", signature)
    assert HmacKey.generate().key_id != key.key_id and key.key_id in repr(key)
    with pytest.raises(ValueError, match="at least 32 bytes"):
        HmacKey(b"short")


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "written as"),
        ("rsa:00", "written as"),
        ("ed25519:not-hex", "not hex"),
        ("ed25519:00", "32 bytes"),
        ("hmac-sha256:00", "at least 32"),
    ],
)
def test_parse_key_refuses_what_is_not_a_key(spec: str, message: str) -> None:
    with pytest.raises(MalformedReceiptError, match=message):
        parse_key(spec)


def test_verification_needs_no_dependency_but_signing_does(monkeypatch: pytest.MonkeyPatch) -> None:
    signer = Ed25519Signer(b"\x09" * 32)
    signature = signer.sign(b"offline")
    for module in ("cryptography", "cryptography.exceptions", "cryptography.hazmat.primitives"):
        monkeypatch.setitem(sys.modules, module, None)
    monkeypatch.setitem(sys.modules, "cryptography.hazmat.primitives.asymmetric.ed25519", None)
    assert signer.public_key().verify(b"offline", signature), "the pure path verifies"
    assert not signer.public_key().verify(b"online", signature)
    with pytest.raises(SignerUnavailableError, match=r"agentgov\[sign\]"):
        Ed25519Signer(b"\x09" * 32)


def test_the_package_imports_and_verifies_without_cryptography(tmp_path: Path) -> None:
    """A stock interpreter, with the optional dependency made unimportable."""
    public, message, signature = _RFC8032[1][1:]
    script = (
        "import sys\n"
        "sys.modules['cryptography'] = None\n"
        "from agentgov.receipts import Ed25519PublicKey\n"
        f"key = Ed25519PublicKey(bytes.fromhex('{public}'))\n"
        f"assert key.verify(bytes.fromhex('{message}'), bytes.fromhex('{signature}'))\n"
        "print('verified without cryptography')\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
    assert "verified without cryptography" in result.stdout
