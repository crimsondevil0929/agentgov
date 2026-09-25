"""ARC1 documents: exact round trips, strict decoding, and tamper evidence.

The central property: change any single field of a signed receipt, and the
receipt no longer verifies. Every leaf of a real receipt is altered in turn,
and every list is reordered, truncated and padded, to prove it.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from agentgov.exceptions import (
    MalformedReceiptError,
    ReceiptSignatureError,
    RowDisclosureError,
)
from agentgov.receipts import (
    ActionReceipt,
    Capability,
    Checkpoint,
    Cosignature,
    Ed25519Signer,
    HmacKey,
    ReceiptBundle,
    RowChange,
    RowDisclosure,
    commit_rows,
    parse_key,
    verify_disclosure,
)
from agentgov.receipts.rows import row_leaf_hash, row_salt
from agentgov.receipts.schema import Signature, instant, money_text

VECTORS = Path(__file__).resolve().parent.parent / "vectors" / "arc1"
BUNDLE = ReceiptBundle.loads((VECTORS / "valid" / "committed-refund.bundle.json").read_bytes())
RECEIPT = BUNDLE.receipt
ISSUER = parse_key((VECTORS / "keys" / "issuer.pub").read_text())
RECEIPT_JSON: dict[str, Any] = RECEIPT.to_json()


def test_the_vector_receipt_verifies_as_is() -> None:
    RECEIPT.verify(ISSUER)


def test_every_document_round_trips_exactly() -> None:
    for document in (RECEIPT, BUNDLE.checkpoint):
        assert document is not None
        again = type(document).from_json(json.loads(json.dumps(document.to_json())))
        assert again == document
    assert ReceiptBundle.from_json(BUNDLE.to_json()) == BUNDLE
    assert ActionReceipt.loads(RECEIPT.canonical()) == RECEIPT
    assert (
        RECEIPT.canonical() == ActionReceipt.loads(json.dumps(RECEIPT_JSON, indent=3)).canonical()
    )
    cosignature = Cosignature(
        witness_id="w", log_id="l", tree_size=3, root_hash="a" * 64, witnessed_at=RECEIPT.issued_at
    ).sign(HmacKey(b"w" * 32))
    assert Cosignature.from_json(cosignature.to_json()) == cosignature


# --------------------------------------------------------------------------
# Every field is covered by the signature
# --------------------------------------------------------------------------

_HEXISH = re.compile(r"[0-9a-f-]+")


def _leaves(
    value: Any, path: tuple[str | int, ...] = ()
) -> Iterator[tuple[tuple[str | int, ...], Any]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _leaves(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _leaves(item, (*path, index))
    else:
        yield path, value


def _lists(value: Any, path: tuple[str | int, ...] = ()) -> Iterator[tuple[str | int, ...]]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _lists(item, (*path, key))
    elif isinstance(value, list):
        yield path
        for index, item in enumerate(value):
            yield from _lists(item, (*path, index))


def _altered(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        if _HEXISH.fullmatch(value):
            return value[:-1] + ("0" if value[-1] != "0" else "1")
        if value.endswith("Z") and "T" in value:
            return value[:-2] + ("1" if value[-2] != "1" else "2") + "Z"
        return value + "."
    return {"unexpected": "value"} if value is None else None


def _path_id(path: tuple[str | int, ...]) -> str:
    return "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in path).lstrip(".")


def _set(document: Any, path: tuple[str | int, ...], value: Any) -> Any:
    target = copy.deepcopy(document)
    node = target
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    return target


_FIELDS = [path for path, _ in _leaves(RECEIPT_JSON) if path[0] != "sig"]
_LISTS = [path for path in _lists(RECEIPT_JSON) if path[0] != "sig"]


def _rejected(document: Any) -> str:
    """How an altered receipt is caught: 'malformed' or 'signature'."""
    try:
        receipt = ActionReceipt.from_json(document)
    except MalformedReceiptError:
        return "malformed"
    with pytest.raises(ReceiptSignatureError):
        receipt.verify(ISSUER)
    return "signature"


@pytest.mark.parametrize("path", _FIELDS, ids=[_path_id(p) for p in _FIELDS])
def test_altering_any_single_field_breaks_the_receipt(path: tuple[str | int, ...]) -> None:
    value: Any = RECEIPT_JSON
    for step in path:
        value = value[step]
    _rejected(_set(RECEIPT_JSON, path, _altered(value)))


def test_most_alterations_are_caught_by_the_signature_not_just_the_schema() -> None:
    """A well-formed but different receipt is the real attack; the schema only
    stops sloppy ones. Most single-field edits must reach the signature check."""
    outcomes = [
        _rejected(_set(RECEIPT_JSON, path, _altered(_get(RECEIPT_JSON, path)))) for path in _FIELDS
    ]
    assert outcomes.count("signature") >= 40, outcomes
    assert len(_FIELDS) >= 50


def _get(document: Any, path: tuple[str | int, ...]) -> Any:
    for step in path:
        document = document[step]
    return document


@pytest.mark.parametrize("path", _LISTS, ids=[_path_id(p) for p in _LISTS])
def test_reordering_truncating_or_padding_any_list_breaks_the_receipt(
    path: tuple[str | int, ...],
) -> None:
    items = _get(RECEIPT_JSON, path)
    variants = [[*items, items[0]]] if items else [["an-added-element"]]
    if items:
        variants.append(items[:-1])
    if len(items) > 1:
        variants.append(items[::-1])
    for variant in variants:
        _rejected(_set(RECEIPT_JSON, path, variant))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("alg", "hmac-sha256", "claims an hmac-sha256 signature"),
        ("key_id", "0" * 16, "signed by key 0000000000000000"),
        ("signature", "00" * 64, "does not verify"),
    ],
)
def test_the_signature_block_is_bound_to_its_key(field: str, value: str, message: str) -> None:
    document = _set(RECEIPT_JSON, ("sig", field), value)
    if field == "alg":
        document["sig"]["signature"] = "00" * 32
    with pytest.raises(ReceiptSignatureError, match=message):
        ActionReceipt.from_json(document).verify(ISSUER)


def test_a_signature_for_one_document_type_never_verifies_as_another() -> None:
    """Domain separation: the same key signs receipts and checkpoints, so a
    checkpoint signature over identical bytes must not pass as a receipt's."""
    key = Ed25519Signer(b"\x05" * 32)
    receipt = RECEIPT.sign(key)
    assert receipt.signature is not None
    stolen = key.sign(
        receipt.signing_input(key.alg, key.key_id).replace(
            b"ARC1/receipt/v1\n", b"ARC1/checkpoint/v1\n", 1
        )
    )
    forged = replace(receipt, signature=Signature(key.alg, key.key_id, stolen))
    with pytest.raises(ReceiptSignatureError):
        forged.verify(key.public_key())
    with pytest.raises(ReceiptSignatureError, match="not signed"):
        replace(receipt, signature=None).verify(key.public_key())


# --------------------------------------------------------------------------
# Strict decoding
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("edit", "message"),
    [
        (lambda d: d.pop("issuer"), "missing issuer"),
        (lambda d: d.update(extra=1), "unknown field"),
        (lambda d: d.update(v="ARC2"), "must be 'ARC1'"),
        (lambda d: d["effect"].update(row_count=-1), "between 0"),
        (lambda d: d["effect"].update(row_count=True), "must be an integer"),
        (lambda d: d["effect"].update(truncated="no"), "true or false"),
        (lambda d: d["effect"].update(diff_hash="ABC"), "64 lowercase hex"),
        (lambda d: d.update(receipt_id="not-a-uuid"), "canonical lowercase UUID"),
        (lambda d: d.update(issued_at="2026-09-25 14:00:00"), "not an ARC1 instant"),
        (lambda d: d.update(issued_at="2026-02-30T00:00:00.000000Z"), "not a real instant"),
        (lambda d: d.update(issued_at=5), "must be a string"),
        (lambda d: d.update(issuer=""), "non-empty string"),
        (lambda d: d.update(issuer="line\nbreak"), "control characters"),
        (lambda d: d["cost"].update(settled_usd="0.005"), "exactly 8 places"),
        (lambda d: d["cost"].update(ledger_txn_ids=["b", "a"]), "canonical lowercase UUID"),
        (lambda d: d["authority"].update(scope_path=[]), "at least one scope"),
        (lambda d: d["authority"].update(scope_path=["a", "a"]), "repeats a scope"),
        (lambda d: d["authority"]["capability"].update(tables="orders"), "must be an array"),
        (lambda d: d["authority"]["capability"].update(tenants=["b", "a"]), "is a set"),
        (lambda d: d["decision"].update(checkers=[d["decision"]["checkers"][0]] * 2), "twice"),
        (lambda d: d["outcome"].update(status="done"), "must be one of"),
        (lambda d: d.update(anchors=[]), "must be a JSON object"),
        (lambda d: d["effect"].update(row_count=d["effect"]["row_count"] + 1), "summary counts"),
        (
            lambda d: d["decision"].update(admitted=False),
            "a refused plan cannot have committed",
        ),
        (lambda d: d["sig"].update(alg="rsa"), "must be 'ed25519' or 'hmac-sha256'"),
        (lambda d: d["sig"].update(signature="xyz"), "lowercase hex"),
        (lambda d: d["sig"].update(signature="00" * 10), "is 10 bytes"),
        (lambda d: d["sig"].update(key_id="short"), "16 lowercase hex"),
    ],
)
def test_the_schema_refuses_what_it_does_not_define(edit: Any, message: str) -> None:
    document = copy.deepcopy(RECEIPT_JSON)
    edit(document)
    with pytest.raises(MalformedReceiptError, match=message):
        ActionReceipt.from_json(document)


def test_sets_sort_in_the_one_order_the_format_uses_for_keys() -> None:
    """U+1F600 sorts before U+FF61 in UTF-16 (0xD83D < 0xFF61) and after it
    by code point. Sets use the UTF-16 order canonical JSON sorts keys in, so
    the format has one ordering rule, not two."""
    emoji, halfwidth = chr(0x1F600), chr(0xFF61)
    assert Capability("grant", tables=(halfwidth, emoji)).tables == (emoji, halfwidth)
    document = copy.deepcopy(RECEIPT_JSON)
    document["authority"]["capability"]["tables"] = [emoji, halfwidth]
    assert ActionReceipt.from_json(document).authority.capability.tables == (emoji, halfwidth)
    document["authority"]["capability"]["tables"] = [halfwidth, emoji]
    with pytest.raises(MalformedReceiptError, match="sorted by UTF-16 code units"):
        ActionReceipt.from_json(document)


def test_bundles_carry_a_proof_and_its_checkpoint_together() -> None:
    with pytest.raises(MalformedReceiptError, match="together, or neither"):
        ReceiptBundle(receipt=RECEIPT, inclusion=BUNDLE.inclusion)
    document = BUNDLE.to_json()
    document["inclusion"]["leaf_index"] = document["inclusion"]["tree_size"]
    with pytest.raises(MalformedReceiptError, match="outside a tree"):
        ReceiptBundle.from_json(document)
    bare = ReceiptBundle.loads(RECEIPT.canonical())
    assert bare.receipt == RECEIPT and bare.inclusion is None and bare.checkpoint is None
    checkpoint = BUNDLE.to_json()["checkpoint"]
    with pytest.raises(MalformedReceiptError, match="ARC1-checkpoint"):
        Checkpoint.from_json({**checkpoint, "v": "ARC1"})


def test_field_formats() -> None:
    assert instant(datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=UTC)) == "2026-01-02T03:04:05.000006Z"
    with pytest.raises(ValueError, match="timezone-aware"):
        instant(datetime(2026, 1, 1))
    assert money_text(Decimal("0.5")) == "0.50000000"
    with pytest.raises(ValueError, match="not negative"):
        money_text(Decimal("-1"))
    with pytest.raises(ValueError, match="quanta"):
        money_text(Decimal("0.000000001"))


# --------------------------------------------------------------------------
# Rows: commitments and disclosures
# --------------------------------------------------------------------------

REFUND_ROWS = [
    RowChange.from_values(
        "orders",
        1044,
        tenant="acme",
        before={"id": 1044, "tenant": "acme", "total": "240.00", "status": "paid"},
        after={"id": 1044, "tenant": "acme", "total": "240.00", "status": "refunded"},
    ),
    RowChange.from_values(
        "refunds",
        4044,
        tenant="acme",
        before=None,
        after={"id": 4044, "tenant": "acme", "order_id": 1044, "amount": "240.00"},
    ),
    RowChange.from_values(
        "order_audit",
        88004,
        tenant="acme",
        before={"id": 88004, "tenant": "acme", "note": "payment captured"},
        after=None,
    ),
]
SECRET = b"\x42" * 32


def _receipt_for(commitment: Any) -> ActionReceipt:
    return replace(
        RECEIPT,
        effect=replace(
            RECEIPT.effect,
            row_root=commitment.root,
            row_count=commitment.count,
            summary=commitment.summary(),
        ),
    )


def test_a_commitment_discloses_exactly_the_rows_asked_for() -> None:
    commitment = commit_rows(REFUND_ROWS, secret=SECRET)
    receipt = _receipt_for(commitment)
    summary = commitment.summary()
    assert (summary.inserted, summary.updated, summary.deleted) == (1, 1, 1)
    assert summary.tables == ("order_audit", "orders", "refunds") and summary.tenants == ("acme",)

    disclosure = commitment.disclose([2, 0, 2], receipt_id=receipt.receipt_id)
    assert [row.index for row in disclosure.rows] == [0, 2]
    verify_disclosure(disclosure, receipt)
    assert RowDisclosure.loads(json.dumps(disclosure.to_json())) == disclosure

    text = json.dumps(disclosure.to_json())
    assert "4044" not in text and row_salt(SECRET, 1).hex() not in text, "row 1 stays hidden"
    with pytest.raises(IndexError, match="not one of 3"):
        commitment.disclose([3], receipt_id=receipt.receipt_id)


def test_salts_keep_a_guessable_row_from_being_confirmed() -> None:
    """Without the salt, the leaf of a low-entropy row cannot be recomputed,
    so an auditor holding the root cannot test guesses about hidden rows."""
    commitment = commit_rows(REFUND_ROWS, secret=SECRET)
    other = commit_rows(REFUND_ROWS, secret=b"\x43" * 32)
    assert commitment.root != other.root, "same rows, different secret, different root"
    guess = REFUND_ROWS[0]
    assert row_leaf_hash(b"\x00" * 32, guess) != row_leaf_hash(row_salt(SECRET, 0), guess)
    assert commit_rows(REFUND_ROWS).root != commitment.root, "a fresh secret by default"
    with pytest.raises(ValueError, match="32 bytes"):
        commit_rows(REFUND_ROWS, secret=b"short")


def _tampered_disclosures() -> Iterator[tuple[str, dict[str, Any], str]]:
    commitment = commit_rows(REFUND_ROWS, secret=SECRET)
    good = commitment.disclose([0, 1], receipt_id=RECEIPT.receipt_id).to_json()

    def variant(name: str, edit: Any, message: str) -> tuple[str, dict[str, Any], str]:
        document = copy.deepcopy(good)
        edit(document)
        return name, document, message

    yield variant("value", lambda d: d["rows"][0]["row"]["after"].update(status="paid"), "altered")
    yield variant("salt", lambda d: d["rows"][0].update(salt="00" * 32), "altered")
    yield variant("index", lambda d: d["rows"][1].update(index=2), "altered")
    yield variant(
        "swapped",
        lambda d: d["rows"].__setitem__(
            slice(None),
            [
                {**d["rows"][1], "index": 0},
                {**d["rows"][0], "index": 1},
            ],
        ),
        "altered",
    )
    yield variant("path", lambda d: d["rows"][0]["audit_path"].__setitem__(0, "00" * 32), "altered")
    yield variant("short-path", lambda d: d["rows"][0]["audit_path"].pop(), "altered")
    yield variant("beyond", lambda d: d["rows"][1].update(index=7), "altered")
    yield variant("twice", lambda d: d["rows"].append(d["rows"][0]), "disclosed twice")
    yield variant("empty", lambda d: d["rows"].clear(), "reveals no rows")
    yield variant("count", lambda d: d.update(row_count=4), "commitment of 4 rows")
    yield variant("root", lambda d: d.update(row_root="0" * 64), "commitment of 3 rows")
    yield variant(
        "receipt", lambda d: d.update(receipt_id="00000000-0000-0000-0000-000000000000"), "not"
    )


@pytest.mark.parametrize(("name", "document", "message"), list(_tampered_disclosures()))
def test_any_tampered_disclosure_is_refused(
    name: str, document: dict[str, Any], message: str
) -> None:
    receipt = _receipt_for(commit_rows(REFUND_ROWS, secret=SECRET))
    with pytest.raises(RowDisclosureError, match=message):
        verify_disclosure(RowDisclosure.from_json(document), receipt)


def test_row_changes_have_the_shape_their_operation_implies() -> None:
    with pytest.raises(MalformedReceiptError, match="an insert has no before-image"):
        RowChange("t", "1", "insert", before={"a": 1}, after={"a": 2})
    with pytest.raises(MalformedReceiptError, match="a delete has a before-image and no"):
        RowChange("t", "1", "delete", before={"a": 1}, after={"a": 1})
    with pytest.raises(MalformedReceiptError, match="op must be one of"):
        RowChange("t", "1", "upsert", after={"a": 1})  # type: ignore[arg-type]
    with pytest.raises(MalformedReceiptError, match="before-image, an after-image, or both"):
        RowChange.from_values("t", 1, before=None, after=None)
    change = RowChange.from_values(
        "t",
        7,
        before={},
        after={
            "real": 0.1,
            "decimal": Decimal("1.50"),
            "blob": b"\x01\x02",
            "when": datetime(2026, 1, 1, tzinfo=UTC),
            "huge": 2**60,
            "other": Path("x"),
            "flag": True,
            "none": None,
        },
    )
    assert change.op == "update" and change.pk == "7"
    assert change.after == {
        "real": "0.1",
        "decimal": "1.50",
        "blob": "0102",
        "when": "2026-01-01T00:00:00+00:00",
        "huge": str(2**60),
        "other": "x",
        "flag": True,
        "none": None,
    }


@pytest.mark.parametrize(
    ("row", "message"),
    [
        (
            {"table": "t", "pk": "1", "op": "merge", "tenant": None, "before": None, "after": {}},
            "op",
        ),
        (
            {"table": "t", "pk": "1", "op": "insert", "tenant": None, "before": None, "after": []},
            "object",
        ),
        (
            {
                "table": "t",
                "pk": "1",
                "op": "insert",
                "tenant": None,
                "before": None,
                "after": {"a": 1.5},
            },
            "string, integer",
        ),
        (
            {
                "table": "t",
                "pk": "1",
                "op": "insert",
                "tenant": None,
                "before": None,
                "after": {"a": 2**60},
            },
            "2\\*\\*53",
        ),
        (
            {
                "table": "t",
                "pk": "1",
                "op": "insert",
                "tenant": None,
                "before": None,
                "after": {"": 1},
            },
            "column name",
        ),
    ],
)
def test_disclosed_rows_are_checked_like_every_other_field(
    row: dict[str, Any], message: str
) -> None:
    with pytest.raises(MalformedReceiptError, match=message):
        RowChange.from_json(row, "row")
