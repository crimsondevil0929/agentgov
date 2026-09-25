"""ARC1: signed, logged, witnessed receipts for agent actions.

Every agent action that reaches a system of record can leave an
:class:`ActionReceipt` that an outsider can verify offline: who authorized
it, what the agent said it would do, what it measurably did (and what the
measurement could not see), what was decided, what it cost, and how it ended.

The pieces, each in its own module:

- :mod:`~agentgov.receipts.canonical`: the canonical JSON every hash and
  signature covers (RFC 8785 over a float-free value domain).
- :mod:`~agentgov.receipts.schema`: the documents.
- :mod:`~agentgov.receipts.signing`: HMAC-SHA256 (standard library) and
  Ed25519 (signing needs ``agentgov[sign]``; verifying needs nothing).
- :mod:`~agentgov.receipts.merkle`: the RFC 9162 Merkle tree and proofs.
- :mod:`~agentgov.receipts.log`: the append-only receipt log.
- :mod:`~agentgov.receipts.witness`: witnesses that cosign its checkpoints.
- :mod:`~agentgov.receipts.rows`: salted row commitments and disclosures.
- :mod:`~agentgov.receipts.verify`: the verifier behind
  ``agentgov verify-receipt``.

``docs/RECEIPTS.md`` is the specification, and ``vectors/arc1/`` holds the
reference test vectors an independent implementation can check itself
against.
"""

from __future__ import annotations

from agentgov.receipts.canonical import canonical_bytes, loads_strict
from agentgov.receipts.log import CheckpointPolicy, ReceiptLog
from agentgov.receipts.merkle import MerkleTree, verify_consistency, verify_inclusion
from agentgov.receipts.rows import RowCommitment, commit_rows, verify_disclosure
from agentgov.receipts.schema import (
    ActionReceipt,
    Anchors,
    Authority,
    Capability,
    ChainAnchor,
    CheckerRecord,
    Checkpoint,
    Cosignature,
    Cost,
    Coverage,
    Decision,
    Effect,
    EffectSummary,
    InclusionProof,
    Intent,
    LogAnchor,
    Outcome,
    OutcomeStatus,
    ReceiptBundle,
    RowChange,
    RowDisclosure,
    StatedFootprint,
)
from agentgov.receipts.signing import (
    Ed25519PublicKey,
    Ed25519Signer,
    HmacKey,
    Signer,
    Verifier,
    parse_key,
)
from agentgov.receipts.verify import Check, Failure, VerificationReport, verify_bundle
from agentgov.receipts.witness import FileWitness, Witness, find_cosignature, load_cosignatures

__all__ = [
    "ActionReceipt",
    "Anchors",
    "Authority",
    "Capability",
    "ChainAnchor",
    "Check",
    "CheckerRecord",
    "Checkpoint",
    "CheckpointPolicy",
    "Cosignature",
    "Cost",
    "Coverage",
    "Decision",
    "Ed25519PublicKey",
    "Ed25519Signer",
    "Effect",
    "EffectSummary",
    "Failure",
    "FileWitness",
    "HmacKey",
    "InclusionProof",
    "Intent",
    "LogAnchor",
    "MerkleTree",
    "Outcome",
    "OutcomeStatus",
    "ReceiptBundle",
    "ReceiptLog",
    "RowChange",
    "RowCommitment",
    "RowDisclosure",
    "Signer",
    "StatedFootprint",
    "VerificationReport",
    "Verifier",
    "Witness",
    "canonical_bytes",
    "commit_rows",
    "find_cosignature",
    "load_cosignatures",
    "loads_strict",
    "parse_key",
    "verify_bundle",
    "verify_consistency",
    "verify_disclosure",
    "verify_inclusion",
]
