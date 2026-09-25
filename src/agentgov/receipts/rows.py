"""Row commitments: a salted Merkle root over the rows a plan changed.

A receipt carries no row data, only ``effect.row_root``: the RFC 9162 root of
one leaf per row change. Later, an auditor can be shown any subset of those
rows, each with the proof that it is one of the committed leaves, while the
rest stay hidden.

Every leaf is salted with 32 bytes of its own::

    leaf_data(i) = "ARC1/row/v1\\n" || salt_i || canonical(row_i)

Without the salt, a row with few possible values (a boolean flag, a status
column) could be recovered from the root by guessing and hashing. With a
per-row salt, revealing one row and its salt says nothing about any other.

The salts are derived from one 32-byte secret the issuer keeps, so disclosing
rows later needs only that secret and the rows themselves::

    salt_i = HMAC-SHA256(secret, "ARC1/row-salt/v1\\n" || uint64_be(i))

HMAC is a pseudorandom function, so a disclosed salt reveals nothing about the
secret or about any other row's salt.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from agentgov.exceptions import RowDisclosureError
from agentgov.receipts.canonical import canonical_bytes
from agentgov.receipts.merkle import MerkleTree, leaf_hash, verify_inclusion
from agentgov.receipts.schema import (
    ActionReceipt,
    DisclosedRow,
    EffectSummary,
    RowChange,
    RowDisclosure,
)

__all__ = [
    "ROW_LEAF_DOMAIN",
    "RowCommitment",
    "commit_rows",
    "row_leaf_hash",
    "row_salt",
    "verify_disclosure",
]

ROW_LEAF_DOMAIN = b"ARC1/row/v1\n"
_SALT_DOMAIN = b"ARC1/row-salt/v1\n"


def row_salt(secret: bytes, index: int) -> bytes:
    """The salt for row ``index``, derived from the issuer's row secret."""
    return hmac.new(secret, _SALT_DOMAIN + index.to_bytes(8, "big"), hashlib.sha256).digest()


def row_leaf_hash(salt: bytes, row: RowChange) -> bytes:
    """The RFC 9162 leaf hash one row contributes to a row commitment."""
    return leaf_hash(ROW_LEAF_DOMAIN + salt + canonical_bytes(row.to_json()))


@dataclass(frozen=True)
class RowCommitment:
    """The committed rows, their salts, and the tree over them.

    Keep the ``secret`` (or this object) wherever the rows are kept: it is
    what lets you disclose rows later. It is never part of a receipt.
    """

    rows: tuple[RowChange, ...]
    secret: bytes = field(repr=False)
    _tree: MerkleTree = field(repr=False, compare=False)

    @property
    def root(self) -> str:
        """``effect.row_root`` for the receipt, in hex."""
        return self._tree.root().hex()

    @property
    def count(self) -> int:
        """``effect.row_count`` for the receipt."""
        return len(self.rows)

    def summary(self) -> EffectSummary:
        """``effect.summary``: the counts and places the rows imply."""
        return EffectSummary(
            inserted=sum(1 for row in self.rows if row.op == "insert"),
            updated=sum(1 for row in self.rows if row.op == "update"),
            deleted=sum(1 for row in self.rows if row.op == "delete"),
            tables=tuple(row.table for row in self.rows),
            tenants=tuple(row.tenant for row in self.rows if row.tenant is not None),
        )

    def disclose(self, indices: Iterable[int], *, receipt_id: str) -> RowDisclosure:
        """Reveal the rows at ``indices``, and nothing about the others.

        :raises IndexError: If an index is not one of the committed rows.
        """
        chosen = sorted(set(indices))
        for index in chosen:
            if not 0 <= index < len(self.rows):
                raise IndexError(f"row {index} is not one of {len(self.rows)} committed rows")
        return RowDisclosure(
            receipt_id=receipt_id,
            row_root=self.root,
            row_count=self.count,
            rows=tuple(
                DisclosedRow(
                    index=index,
                    salt=row_salt(self.secret, index),
                    row=self.rows[index],
                    audit_path=tuple(p.hex() for p in self._tree.inclusion_proof(index)),
                )
                for index in chosen
            ),
        )


def commit_rows(rows: Sequence[RowChange], *, secret: bytes | None = None) -> RowCommitment:
    """Commit to ``rows``, in the order given.

    :param secret: The 32-byte row secret. A fresh random one by default;
        pass your own only to reproduce a commitment, as the test vectors do.
    :raises ValueError: If ``secret`` is not 32 bytes.
    """
    key = secret if secret is not None else secrets.token_bytes(32)
    if len(key) != 32:
        raise ValueError("a row secret is 32 bytes")
    tree = MerkleTree(row_leaf_hash(row_salt(key, i), row) for i, row in enumerate(rows))
    return RowCommitment(rows=tuple(rows), secret=key, _tree=tree)


def verify_disclosure(disclosure: RowDisclosure, receipt: ActionReceipt) -> None:
    """Check that every disclosed row is one ``receipt`` committed to.

    :raises RowDisclosureError: If the disclosure names another receipt or
        another commitment, discloses a row twice or outside the commitment,
        or any row, salt, index or audit path does not reproduce the
        receipt's ``row_root``.
    """
    effect = receipt.effect
    if disclosure.receipt_id != receipt.receipt_id:
        raise RowDisclosureError(
            f"the disclosure is for receipt {disclosure.receipt_id}, not {receipt.receipt_id}"
        )
    if disclosure.row_root != effect.row_root or disclosure.row_count != effect.row_count:
        raise RowDisclosureError(
            f"the disclosure is against a commitment of {disclosure.row_count} rows with root "
            f"{disclosure.row_root[:16]}; the receipt committed to {effect.row_count} rows "
            f"with root {effect.row_root[:16]}"
        )
    if not disclosure.rows:
        raise RowDisclosureError("the disclosure reveals no rows")
    seen: set[int] = set()
    root = bytes.fromhex(effect.row_root)
    for disclosed in disclosure.rows:
        if disclosed.index in seen:
            raise RowDisclosureError(f"row {disclosed.index} is disclosed twice")
        seen.add(disclosed.index)
        leaf = row_leaf_hash(disclosed.salt, disclosed.row)
        path = [bytes.fromhex(node) for node in disclosed.audit_path]
        if not verify_inclusion(leaf, disclosed.index, effect.row_count, path, root):
            raise RowDisclosureError(
                f"row {disclosed.index} ({disclosed.row.table} {disclosed.row.pk}) is not the "
                f"row the receipt committed to at that position: its contents, salt, index or "
                f"audit path were altered"
            )
