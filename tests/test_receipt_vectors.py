"""The ARC1 reference vectors in ``vectors/arc1/``, checked three ways.

1. They are exactly what ``scripts/generate_arc1_vectors.py`` writes, so the
   committed files can never drift from the code that defines them.
2. Every case in ``manifest.json`` exits ``agentgov verify-receipt`` with the
   code it promises, in-process and as a real subprocess.
3. Every derived value in them (canonical bytes, Merkle roots and proofs,
   Ed25519 results, the log's checkpoints) is recomputed here from first
   principles, the way an independent implementation would check them.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from agentgov.cli import main
from agentgov.exceptions import MalformedReceiptError
from agentgov.receipts import (
    ActionReceipt,
    Checkpoint,
    Ed25519PublicKey,
    Ed25519Signer,
    FileWitness,
    HmacKey,
    MerkleTree,
    ReceiptBundle,
    ReceiptLog,
    RowDisclosure,
    _ed25519,
    canonical_bytes,
    load_cosignatures,
    loads_strict,
    parse_key,
    verify_consistency,
    verify_disclosure,
    verify_inclusion,
)
from agentgov.receipts.merkle import leaf_hash

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors" / "arc1"
MANIFEST: dict[str, Any] = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))


def _load(relative: str) -> Any:
    return json.loads((VECTORS / relative).read_text(encoding="utf-8"))


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "generate_arc1_vectors", ROOT / "scripts" / "generate_arc1_vectors.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


# -- 1. no drift -------------------------------------------------------------


def test_the_committed_vectors_are_exactly_what_the_generator_writes(tmp_path: Path) -> None:
    out = tmp_path / "arc1"
    assert _generator().main(["--out", str(out)]) == 0
    written, committed = _files(out), _files(VECTORS)
    assert sorted(written) == sorted(committed), "a vector file was added or removed"
    drifted = [name for name in written if written[name] != committed[name]]
    assert not drifted, (
        f"{drifted} differ from the generator's output; run "
        f"`uv run python scripts/generate_arc1_vectors.py` and commit the result"
    )


def test_the_generator_replaces_a_stale_directory(tmp_path: Path) -> None:
    out = tmp_path / "arc1"
    (out / "valid").mkdir(parents=True)
    (out / "valid" / "stale.bundle.json").write_text("{}")
    _generator().generate(out)
    assert not (out / "valid" / "stale.bundle.json").exists()
    assert (out / "manifest.json").is_file()


# -- 2. the manifest ---------------------------------------------------------


def _case_id(case: dict[str, Any]) -> str:
    return str(case["name"])


@pytest.mark.parametrize("case", MANIFEST["cases"], ids=_case_id)
def test_every_manifest_case_exits_with_its_code(
    case: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(VECTORS)
    out = io.StringIO()
    code = main(["verify-receipt", *case["args"], "--json"], out=out)
    report = json.loads(out.getvalue())
    assert code == case["exit"] == report["exit_code"], report
    failed = [check for check in report["checks"] if check["status"] == "fail"]
    if case["exit"] == 0:
        assert report["passed"] and not failed
        assert all(check["status"] in ("pass", "skip") for check in report["checks"])
    else:
        # The first failure is the one the exit code names, and nothing ran
        # that the case did not ask for.
        assert failed and not report["passed"]


def test_the_manifest_covers_every_failure_class_the_vectors_can_show() -> None:
    codes = {case["exit"] for case in MANIFEST["cases"]}
    # 7 needs a SQLite ledger, which is not a portable vector; the ledger
    # check is exercised against a real ledger in test_receipts_verify.
    assert codes == {0, 3, 4, 5, 6, 8}
    names = [case["name"] for case in MANIFEST["cases"]]
    assert len(names) == len(set(names))
    for case in MANIFEST["cases"]:
        for arg in case["args"]:
            if not arg.startswith("--"):
                assert (VECTORS / arg).is_file(), f"{case['name']}: {arg} is missing"


@pytest.mark.parametrize("name", ["committed-refund", "forged-signature", "split-view"])
def test_the_exit_code_reaches_the_shell(name: str) -> None:
    case = next(c for c in MANIFEST["cases"] if c["name"] == name)
    result = subprocess.run(  # noqa: S603 - the interpreter running these tests
        [sys.executable, "-m", "agentgov.cli", "verify-receipt", *case["args"]],
        cwd=VECTORS,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == case["exit"], result.stdout + result.stderr
    assert ("PASS" if case["exit"] == 0 else "FAIL") in result.stdout


# -- 3. independent recomputation --------------------------------------------


def test_canonical_json_vectors() -> None:
    vectors = _load("canonical.json")
    assert len(vectors["accept"]) >= 5 and len(vectors["reject"]) >= 5
    for case in vectors["accept"]:
        assert canonical_bytes(case["input"]) == case["canonical"].encode("utf-8"), case["name"]
        # Canonical output is itself valid strict ARC1 JSON, and a fixed point.
        again = loads_strict(case["canonical"])
        assert canonical_bytes(again) == case["canonical"].encode("utf-8")
    for case in vectors["reject"]:
        with pytest.raises(MalformedReceiptError):
            canonical_bytes(loads_strict(case["text"]))


def test_merkle_vectors_match_rfc9162() -> None:
    vectors = _load("merkle.json")
    leaves = [bytes.fromhex(leaf) for leaf in vectors["leaves"]]
    tree = MerkleTree(leaf_hash(leaf) for leaf in leaves)
    assert [r["size"] for r in vectors["roots"]] == list(range(len(leaves) + 1))
    # RFC 9162's own eight-leaf root, as published with the CT test data.
    assert vectors["roots"][8]["root"] == (
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328"
    )
    roots = {r["size"]: bytes.fromhex(r["root"]) for r in vectors["roots"]}
    for size, root in roots.items():
        assert tree.root(size) == root
    assert roots[0] == hashlib.sha256(b"").digest()
    for case in vectors["inclusion"]:
        index, size = case["index"], case["size"]
        path = [bytes.fromhex(p) for p in case["path"]]
        assert tree.inclusion_proof(index, size) == path
        assert verify_inclusion(leaf_hash(leaves[index]), index, size, path, roots[size])
    for case in vectors["consistency"]:
        old, new = case["old"], case["new"]
        proof = [bytes.fromhex(p) for p in case["proof"]]
        assert tree.consistency_proof(old, new) == proof
        assert verify_consistency(old, new, roots[old], roots[new], proof)
    assert len(vectors["inclusion"]) == 36 and len(vectors["consistency"]) == 44


def test_ed25519_vectors() -> None:
    cases = _load("ed25519.json")["cases"]
    assert {case["valid"] for case in cases} == {True, False}
    for case in cases:
        public = bytes.fromhex(case["public"])
        message = bytes.fromhex(case["message"])
        signature = bytes.fromhex(case["signature"])
        # The standard-library verifier, and the one behind agentgov[sign].
        assert _ed25519.verify(public, message, signature) is case["valid"], case["name"]
        assert Ed25519PublicKey(public).verify(message, signature) is case["valid"], case["name"]


def test_the_keys_are_what_their_seeds_derive() -> None:
    keys = VECTORS / "keys"
    for name in ("issuer", "witness"):
        signer = Ed25519Signer(bytes.fromhex((keys / f"{name}.seed").read_text().strip()))
        assert parse_key((keys / f"{name}.pub").read_text()) == signer.public_key()
    internal = parse_key((keys / "internal.hmac").read_text())
    assert isinstance(internal, HmacKey)


def test_the_log_recomputes_from_its_raw_lines() -> None:
    """An independent verifier needs nothing but SHA-256: each line of the
    log is one leaf, exactly as signed."""
    lines = (VECTORS / "log" / "receipts.jsonl").read_bytes().splitlines()
    checkpoints = [
        Checkpoint.from_json(loads_strict(line))
        for line in (VECTORS / "log" / "receipts.jsonl.checkpoints").read_bytes().splitlines()
    ]
    issuer = parse_key((VECTORS / "keys" / "issuer.pub").read_text())
    assert [c.tree_size for c in checkpoints] == [3, 5, 7]
    for index, line in enumerate(lines):
        receipt = ActionReceipt.loads(line)
        assert receipt.canonical() == line, "a log line is not canonical"
        assert receipt.anchors.log is not None and receipt.anchors.log.leaf_index == index
        receipt.verify(issuer)
    for checkpoint in checkpoints:
        checkpoint.verify(issuer)
        tree = MerkleTree(
            hashlib.sha256(b"\x00" + line).digest() for line in lines[: checkpoint.tree_size]
        )
        assert tree.root().hex() == checkpoint.root_hash


def test_the_logs_consistency_proof() -> None:
    vector = _load("log/consistency.json")
    old, new = Checkpoint.from_json(vector["old"]), Checkpoint.from_json(vector["new"])
    proof = [bytes.fromhex(p) for p in vector["proof"]]
    assert verify_consistency(
        old.tree_size,
        new.tree_size,
        bytes.fromhex(old.root_hash),
        bytes.fromhex(new.root_hash),
        proof,
    )
    assert not verify_consistency(
        old.tree_size,
        new.tree_size,
        bytes.fromhex(old.root_hash),
        bytes.fromhex(new.root_hash),
        list(reversed(proof)),
    )


def test_the_log_and_witness_files_resume(tmp_path: Path) -> None:
    """The committed log and witness record are real files a ReceiptLog and a
    FileWitness reopen, re-checking every position, root and signature."""
    shutil.copytree(VECTORS / "log", tmp_path / "log")
    shutil.copytree(VECTORS / "witness", tmp_path / "witness")
    keys = VECTORS / "keys"
    issuer = Ed25519Signer(bytes.fromhex((keys / "issuer.seed").read_text().strip()))
    witness_signer = Ed25519Signer(bytes.fromhex((keys / "witness.seed").read_text().strip()))
    with ReceiptLog("arc1-vectors", issuer, path=tmp_path / "log" / "receipts.jsonl") as log:
        assert len(log) == 7
        assert log.root() == log.checkpoints()[-1].root_hash
        consistency = _load("log/consistency.json")
        assert [p.hex() for p in log.consistency_proof(3, 7)] == consistency["proof"]
        for path in sorted((VECTORS / "valid").glob("*.bundle.json")):
            bundle = ReceiptBundle.loads(path.read_bytes())
            anchor = bundle.receipt.anchors.log
            assert anchor is not None and bundle.checkpoint is not None
            assert log.receipt(anchor.leaf_index) == bundle.receipt
            assert log.bundle(anchor.leaf_index, bundle.checkpoint) == bundle
    witness = FileWitness(
        tmp_path / "witness" / "cosignatures.jsonl",
        witness_signer,
        witness_id="arc1-vectors-witness",
        logs={"arc1-vectors": issuer.public_key()},
    )
    latest = witness.latest("arc1-vectors")
    assert latest is not None and latest.tree_size == 7
    cosignatures = load_cosignatures(VECTORS / "witness" / "cosignatures.jsonl")
    assert [c.tree_size for c in cosignatures] == [3, 7]


def test_every_valid_document_round_trips_byte_for_byte() -> None:
    for path in sorted((VECTORS / "valid").glob("*.json")):
        raw = json.loads(path.read_text(encoding="utf-8"))
        if path.name.endswith(".rows.json"):
            assert RowDisclosure.loads(path.read_bytes()).to_json() == raw
        elif path.name.endswith(".receipt.json"):
            assert ActionReceipt.loads(path.read_bytes()).to_json() == raw
        else:
            assert ReceiptBundle.loads(path.read_bytes()).to_json() == raw


def test_the_valid_disclosures_verify_directly() -> None:
    for name in ("committed-refund", "refused-tenant-wipe"):
        bundle = ReceiptBundle.loads((VECTORS / "valid" / f"{name}.bundle.json").read_bytes())
        disclosure = RowDisclosure.loads((VECTORS / "valid" / f"{name}.rows.json").read_bytes())
        verify_disclosure(disclosure, bundle.receipt)
