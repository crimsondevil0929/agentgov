"""Signed ledger checkpoints (D2): rewriting history takes the key too.

A governor opens from its newest checkpoint and trusts the snapshot for
everything before it. With a signer, every checkpoint's snapshot carries a
statement the key signed: the ledger's first entry, the checkpoint's
sequence, the head and Merkle root of every entry up to it, and the
snapshot's digest. A governor that requires signed checkpoints opens only
from one a trusted key signed, and only if the statement describes the
snapshot it holds. The auditor checks every snapshot's statement on the way.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from agentgov import BudgetManager, CheckpointSigning, GovernancePolicy, money
from agentgov.audit import Auditor
from agentgov.core import _CheckpointStatement, _frontier_root
from agentgov.exceptions import LedgerIntegrityError
from agentgov.receipts import Ed25519Signer, Keyring, Verifier

KEY = Ed25519Signer(bytes(range(32)))
NEXT = Ed25519Signer(bytes(range(100, 132)))
ATTACKER = Ed25519Signer(bytes(range(200, 232)))
EVERY_TEN = GovernancePolicy(max_calls_per_window=0, checkpoint_every=10)
TRUSTING = CheckpointSigning(keys=KEY.public_key(), required=True)


def _ledger(path: Path, signing: CheckpointSigning | None, spends: int = 25) -> Path:
    with BudgetManager.open_sqlite(
        str(path), policy=EVERY_TEN, auditor=False, signing=signing
    ) as gov:
        gov.open_root("root", money("100"))
        gov.delegate("root", "agent", money("10"))
        for _ in range(spends):
            gov.spend("agent", money("0.01"))
    return path


def _statements(path: Path) -> list[tuple[int, str | None]]:
    with sqlite3.connect(path) as conn:
        return [
            (int(s), sig)
            for s, sig in conn.execute(
                "SELECT sequence, signature FROM snapshots ORDER BY sequence"
            )
        ]


def _set_statement(path: Path, sequence: int, text: str | None) -> None:
    conn = sqlite3.connect(path)
    with conn:
        conn.execute("UPDATE snapshots SET signature = ? WHERE sequence = ?", (text, sequence))
    conn.close()


def test_every_checkpoint_is_signed_and_a_governor_requiring_it_opens(tmp_path: Path) -> None:
    path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=KEY))
    statements = _statements(path)
    assert len(statements) >= 2 and all(text for _, text in statements)
    with BudgetManager.open_sqlite(str(path), auditor=False, signing=TRUSTING) as gov:
        assert gov.ledger._state.last_checkpoint is not None
        first = gov.entry(1).entry_hash
        sequence, text = statements[-1]
        assert text is not None
        statement = _CheckpointStatement.loads(text)
        statement.verify(KEY.public_key())
        assert (statement.first, statement.sequence) == (first, sequence)
        assert statement.head == gov.entry(sequence).entry_hash
        gov.spend("agent", money("0.01"))  # a governor that requires signatures writes, too


def test_the_statement_holds_the_snapshot_to_the_history_before_it(tmp_path: Path) -> None:
    path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=KEY))
    sequence, text = _statements(path)[-1]
    assert text is not None
    statement = _CheckpointStatement.loads(text)
    with BudgetManager.open_sqlite(str(path), read_only=True, verify="full") as view:
        assert statement.head == view.entry(sequence).entry_hash
        replayed = view.ledger._state
    assert statement.root != _frontier_root(replayed.frontier).hex(), (
        "the root is as of the checkpoint"
    )
    assert statement.snapshot == _statements_digest(path, sequence)


def _statements_digest(path: Path, sequence: int) -> str:
    with sqlite3.connect(path) as conn:
        (digest,) = conn.execute(
            "SELECT digest FROM snapshots WHERE sequence = ?", (sequence,)
        ).fetchone()
    return str(digest)


def test_an_unsigned_checkpoint_opens_only_where_signatures_are_optional(tmp_path: Path) -> None:
    path = _ledger(tmp_path / "g.db", None)
    with pytest.raises(LedgerIntegrityError, match="is not signed, and this governor requires"):
        BudgetManager.open_sqlite(str(path), auditor=False, signing=TRUSTING)
    optional = CheckpointSigning(keys=KEY.public_key())
    BudgetManager.open_sqlite(str(path), auditor=False, signing=optional).close()
    BudgetManager.open_sqlite(str(path), auditor=False).close()


def test_a_statement_by_an_untrusted_key_is_refused_even_where_optional(tmp_path: Path) -> None:
    path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=ATTACKER))
    for signing in (TRUSTING, CheckpointSigning(keys=KEY.public_key())):
        with pytest.raises(LedgerIntegrityError, match=r"does not check out: .*not among the keys"):
            BudgetManager.open_sqlite(str(path), auditor=False, signing=signing)


def test_an_altered_or_borrowed_statement_is_refused(tmp_path: Path) -> None:
    path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=KEY))
    (_, old_text), (newest, text) = _statements(path)[-2:]
    assert text is not None and old_text is not None
    altered = text.replace('"sequence":', '"sequence":1', 1)
    _set_statement(path, newest, altered)
    with pytest.raises(LedgerIntegrityError, match="does not check out"):
        BudgetManager.open_sqlite(str(path), auditor=False, signing=TRUSTING)
    _set_statement(path, newest, old_text)  # a genuine statement, for another checkpoint
    with pytest.raises(LedgerIntegrityError, match="does not describe its snapshot"):
        BudgetManager.open_sqlite(str(path), auditor=False, signing=TRUSTING)
    _set_statement(path, newest, text)
    BudgetManager.open_sqlite(str(path), auditor=False, signing=TRUSTING).close()


def test_a_rewritten_history_does_not_carry_the_keys_word(tmp_path: Path) -> None:
    """A second ledger, written by whoever can write the database, with the
    genuine statement copied onto its newest checkpoint."""
    genuine = _ledger(tmp_path / "genuine.db", CheckpointSigning(signer=KEY))
    forged = _ledger(tmp_path / "forged.db", None, spends=25)
    sequence, text = _statements(genuine)[-1]
    assert sequence in {s for s, _ in _statements(forged)}
    _set_statement(forged, sequence, text)
    with pytest.raises(LedgerIntegrityError, match="does not describe its snapshot"):
        BudgetManager.open_sqlite(str(forged), auditor=False, signing=TRUSTING)


def test_a_replay_from_genesis_checks_the_newest_statement_too(tmp_path: Path) -> None:
    """verify="full" replays every entry, which proves the chain links, not
    who wrote it: a consistent rewrite links as well as the original. So a
    governor that trusts keys checks the newest checkpoint's statement after
    a full replay as an open from that checkpoint does, against the chain it
    replayed."""
    genuine = _ledger(tmp_path / "genuine.db", CheckpointSigning(signer=KEY))
    BudgetManager.open_sqlite(str(genuine), auditor=False, verify="full", signing=TRUSTING).close()
    unsigned = _ledger(tmp_path / "unsigned.db", None)
    with pytest.raises(LedgerIntegrityError, match="is not signed, and this governor requires"):
        BudgetManager.open_sqlite(str(unsigned), auditor=False, verify="full", signing=TRUSTING)
    optional = CheckpointSigning(keys=KEY.public_key())
    BudgetManager.open_sqlite(str(unsigned), auditor=False, verify="full", signing=optional).close()
    by_attacker = _ledger(tmp_path / "attacker.db", CheckpointSigning(signer=ATTACKER))
    with pytest.raises(LedgerIntegrityError, match="not among the keys"):
        BudgetManager.open_sqlite(str(by_attacker), auditor=False, verify="full", signing=optional)
    sequence, text = _statements(genuine)[-1]
    _set_statement(unsigned, sequence, text)  # the genuine statement, on a rewritten history
    with pytest.raises(LedgerIntegrityError, match="does not describe its snapshot"):
        BudgetManager.open_sqlite(str(unsigned), auditor=False, verify="full", signing=TRUSTING)
    with sqlite3.connect(genuine) as conn:  # the snapshot that carries the statement, gone
        conn.execute("DELETE FROM snapshots WHERE sequence = ?", (sequence,))
    conn.close()
    with pytest.raises(LedgerIntegrityError, match=f"checkpoint of sequence {sequence} has no"):
        BudgetManager.open_sqlite(str(genuine), auditor=False, verify="full", signing=TRUSTING)
    BudgetManager.open_sqlite(str(genuine), auditor=False, verify="full", signing=optional).close()


def test_a_key_and_its_successor_both_count(tmp_path: Path) -> None:
    path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=KEY))
    rotated = CheckpointSigning(signer=NEXT, keys=[KEY.public_key()], required=True)
    with BudgetManager.open_sqlite(
        str(path), policy=EVERY_TEN, auditor=False, signing=rotated
    ) as gov:
        for _ in range(12):
            gov.spend("agent", money("0.01"))
    newest = _CheckpointStatement.loads(str(_statements(path)[-1][1]))
    assert newest.signature is not None and newest.signature.key_id == NEXT.key_id
    both = CheckpointSigning(keys=Keyring([KEY.public_key(), NEXT.public_key()]), required=True)
    BudgetManager.open_sqlite(str(path), auditor=False, signing=both).close()
    with pytest.raises(LedgerIntegrityError, match="not among the keys"):
        BudgetManager.open_sqlite(str(path), auditor=False, signing=TRUSTING)


def test_the_auditor_checks_every_snapshots_statement(tmp_path: Path) -> None:
    path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=KEY))
    (first, first_text), *_ = _statements(path)
    with BudgetManager.open_sqlite(str(path), read_only=True) as view:
        store: Any = view.store
        report = Auditor(store.fork(), record=False, signing=TRUSTING).run(from_genesis=True)
    assert report.ok, report
    assert first_text is not None
    forged = _CheckpointStatement.loads(first_text)
    _set_statement(path, first, forged.sign(ATTACKER).text())
    with BudgetManager.open_sqlite(str(path), read_only=True) as view:
        store = view.store
        report = Auditor(store.fork(), record=False, signing=TRUSTING).run(from_genesis=True)
    assert report.failure is not None and "not among the keys" in report.failure


def test_a_version_2_signer_signs_digests(tmp_path: Path) -> None:
    class Digests:
        signature_version = 2
        alg, key_id = KEY.alg, KEY.key_id

        def public_key(self) -> Verifier:
            return KEY.public_key()

        def sign(self, message: bytes) -> bytes:
            assert len(message) < 100
            return KEY.sign(message)

        def verify(self, message: bytes, signature: bytes) -> bool:
            return KEY.verify(message, signature)

    path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=Digests()))
    statement = _CheckpointStatement.loads(str(_statements(path)[-1][1]))
    assert statement.signature is not None and statement.signature.version == 2
    BudgetManager.open_sqlite(str(path), auditor=False, signing=TRUSTING).close()


def test_a_key_service_signs_checkpoints_and_is_never_asked_to_verify(tmp_path: Path) -> None:
    from agentgov.receipts import HttpRemoteSigner
    from tests.fakekms import FakeKms

    with FakeKms() as kms:
        kms.create("ledger", bytes(range(32)))
        signer = HttpRemoteSigner(kms.url, "ledger")
        path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=signer))
        signed = sum(kms.signed.values())
        assert signed == len(_statements(path))
        BudgetManager.open_sqlite(
            str(path), auditor=False, signing=CheckpointSigning(signer=signer, required=True)
        ).close()
        assert sum(kms.signed.values()) == signed, "opening called no signer"


def test_required_signatures_need_a_key_to_check_them() -> None:
    with pytest.raises(ValueError, match="no key is trusted"):
        CheckpointSigning(required=True)


@pytest.mark.usefixtures("pg_dsn")
def test_two_governors_checkpoint_one_sequence_on_postgres(pg_dsn: str) -> None:
    signing = CheckpointSigning(signer=KEY)
    policy = GovernancePolicy(max_calls_per_window=0, checkpoint_every=0)
    with BudgetManager.open_postgres(pg_dsn, policy=policy, auditor=False, signing=signing) as a:
        a.open_root("root", money("10"))
        a.delegate("root", "agent", money("5"))
        with BudgetManager.open_postgres(
            pg_dsn, policy=policy, auditor=False, signing=signing
        ) as b:
            b.refresh()
            assert a.checkpoint() == b.checkpoint()
    with BudgetManager.open_postgres(pg_dsn, auditor=False, signing=TRUSTING) as reopened:
        assert reopened.available("agent") == money("5")


def test_agentgov_verify_checks_every_statement_against_the_keys_given(tmp_path: Path) -> None:
    import io

    from agentgov.cli import main

    path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=KEY))
    key = KEY.public_key().spec()
    out = io.StringIO()
    assert main(["verify", str(path), "--checkpoint-key", key, "--require-signed"], out) == 0
    assert "each signed by a trusted key" in out.getvalue()
    out = io.StringIO()
    other = ATTACKER.public_key().spec()
    assert main(["verify", str(path), "--checkpoint-key", other], out) == 1
    assert "not among the keys" in out.getvalue()
    unsigned = _ledger(tmp_path / "u.db", None)
    assert main(["verify", str(unsigned), "--checkpoint-key", key], io.StringIO()) == 0
    out = io.StringIO()
    assert main(["verify", str(unsigned), "--checkpoint-key", key, "--require-signed"], out) == 1
    assert "is not signed" in out.getvalue()
    assert main(["verify", str(path), "--require-signed"], io.StringIO()) == 2


def test_agentgov_audit_checks_statements_against_the_keys_given(tmp_path: Path) -> None:
    import io

    from agentgov.cli import main

    key, other = KEY.public_key().spec(), ATTACKER.public_key().spec()
    path = _ledger(tmp_path / "g.db", CheckpointSigning(signer=KEY))
    out = io.StringIO()
    assert main(["audit", str(path), "--checkpoint-key", key, "--require-signed"], out) == 0
    assert out.getvalue().startswith("PASS"), out.getvalue()
    out = io.StringIO()
    assert main(["audit", str(path), "--from-genesis", "--checkpoint-key", other], out) == 1
    assert "not among the keys" in out.getvalue()
    unsigned = _ledger(tmp_path / "u.db", None)
    out = io.StringIO()
    assert main(["audit", str(unsigned), "--checkpoint-key", key, "--require-signed"], out) == 1
    assert "is not signed" in out.getvalue()
    assert main(["audit", str(unsigned), "--require-signed"], io.StringIO()) == 2


def test_witnesses_cosign_a_ledgers_checkpoints_and_refuse_a_rewrite(tmp_path: Path) -> None:
    from agentgov.exceptions import WitnessError
    from agentgov.receipts import FileWitness, find_cosignature, load_cosignatures

    signing = CheckpointSigning(signer=KEY)
    path = _ledger(tmp_path / "g.db", signing)
    with BudgetManager.open_sqlite(str(path), read_only=True) as view:
        log_id = f"agentgov-ledger:{view.entry(1).entry_hash}"
    witness = FileWitness(
        tmp_path / "w.jsonl",
        Ed25519Signer(bytes(range(50, 82))),
        witness_id="w",
        logs={log_id: KEY.public_key()},
    )
    with BudgetManager.open_sqlite(
        str(path), policy=EVERY_TEN, auditor=False, signing=signing
    ) as gov:
        first = gov.publish_checkpoint([witness])
        anchored = gov.ledger._state.last_checkpoint
        assert anchored is not None
        assert first.log_id == log_id and first.tree_size == anchored[0]
        for _ in range(12):
            gov.spend("agent", money("0.01"))
        second = gov.publish_checkpoint([witness])  # a consistency proof from the first
        assert second.tree_size > first.tree_size
    cosignatures = load_cosignatures(tmp_path / "w.jsonl")
    assert (
        find_cosignature(second, cosignatures, witness._signer.public_key()).tree_size
        == second.tree_size
    )
    # A ledger written in its place is refused: its first entry differs, so
    # its log id does too, and the witness follows only the first's.
    forged = _ledger(tmp_path / "forged.db", signing, spends=40)
    with BudgetManager.open_sqlite(str(forged), auditor=False, signing=signing) as other:
        with pytest.raises(WitnessError, match="not cosigned by 1 of 1"):
            other.publish_checkpoint([witness])
    with (
        BudgetManager.open_sqlite(str(path), auditor=False) as unsigned,
        pytest.raises(ValueError, match="needs a checkpoint signer"),
    ):
        unsigned.publish_checkpoint([witness])
