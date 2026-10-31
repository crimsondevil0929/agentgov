"""Units (1.1): a ledger conserves one named unit, committed by its genesis.

``docs/LEDGER_FORMAT.md`` §3.8. A ledger that declares no unit conserves US
dollars at eight places, and its genesis is the 64 zeros it always was.
"""

from __future__ import annotations

import hashlib
import io
import sqlite3
import uuid
from contextlib import closing
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import psycopg
import pytest

from agentgov import (
    BudgetExhaustedError,
    BudgetManager,
    DenialOfWalletError,
    GovernancePolicy,
    Unit,
    money,
    quantity,
)
from agentgov.cli import main
from agentgov.core import (
    _AUDIT_V3,
    GENESIS_HASH,
    USD,
    Direction,
    EntryType,
    LedgerEntry,
    _ChainState,
    _decode_snapshot,
    _encode_snapshot,
    _hash_entry,
    _Overlay,
    _replay,
)
from agentgov.exceptions import LedgerIntegrityError

SEATS = Unit("seats", 0)
MME = Unit("mme")


def test_usd_at_eight_places_is_the_default_and_keeps_the_zero_genesis() -> None:
    assert Unit() == USD == Unit("usd", 8)
    assert USD.genesis == GENESIS_HASH
    assert USD.quantum == Decimal("0.00000001")
    assert BudgetManager().unit == USD


def test_any_other_unit_has_a_genesis_of_its_own() -> None:
    declaration = b"agentgov-genesis v1 unit=mme places=8"
    assert MME.genesis == hashlib.sha256(declaration).hexdigest()
    assert Unit("usd", 2).genesis != GENESIS_HASH, "cents are not the default unit"
    assert len({Unit(c, p).genesis for c in ("mme", "vcpu") for p in (0, 8)}) == 4
    assert SEATS.quantum == Decimal(1)
    assert Unit("gib", 2).quantum == Decimal("0.01")


@pytest.mark.parametrize(
    ("code", "places"),
    [("", 8), ("MME", 8), ("9vcpu", 8), ("a" * 33, 8), ("mme", 9), ("mme", -1), ("mme", True)],
)
def test_a_unit_that_is_not_one_is_refused(code: str, places: int) -> None:
    with pytest.raises(ValueError, match="unit"):
        Unit(code, places)


def test_a_unit_round_trips_through_its_text() -> None:
    for unit in (USD, MME, SEATS, Unit("api.calls-v2", 0)):
        assert Unit.parse(unit.text()) == unit
    for text in ("mme", "mme/", "mme/10", "mme/x", "MME/8"):
        with pytest.raises(ValueError):
            Unit.parse(text)
    assert str(SEATS) == "seats (whole)" and str(MME) == "mme"


def test_quantity_is_money_for_any_unit() -> None:
    assert quantity("1.239") == money("1.239")
    assert quantity("1.239", Unit("gib", 2)) == Decimal("1.23")
    assert quantity("7.9", SEATS) == Decimal(7)
    with pytest.raises(TypeError):
        quantity(1.5, SEATS)  # type: ignore[arg-type]


def test_a_whole_number_ledger_rounds_costs_up_and_credits_down() -> None:
    gov = BudgetManager(unit=SEATS)
    gov.open_root("org", Decimal("10.7"))
    assert gov.available("org") == 10
    held = gov.authorize("org", Decimal("2.2"))
    assert held.amount == 3, "a hold is a cost: rounded up"
    gov.capture(held, Decimal("1.5"))
    assert gov.available("org") == 8
    gov.delegate("org", "team", Decimal("3.9"))
    assert gov.available("team") == 3
    assert gov.ledger.entries()[0].prev_hash == SEATS.genesis
    gov.verify_integrity()


def test_the_neutral_name_of_a_denial_of_wallet_is_the_same_error() -> None:
    assert BudgetExhaustedError is DenialOfWalletError
    gov = BudgetManager(unit=SEATS)
    gov.open_root("org", Decimal(2))
    with pytest.raises(BudgetExhaustedError):
        gov.authorize("org", Decimal(3))


def _funding(unit: Unit, amount: Decimal) -> LedgerEntry:
    """Entry 1 of a ledger of ``unit``: a funding of ``amount``, hashed."""
    fields = {
        "sequence": 1,
        "entry_id": uuid.uuid4(),
        "transaction_id": uuid.uuid4(),
        "timestamp": datetime(2026, 10, 30, tzinfo=UTC),
        "entry_type": EntryType.FUNDING,
        "direction": Direction.CREDIT,
        "scope_id": "org",
        "counterparty_id": None,
        "amount": amount,
        "balance_after": amount,
        "memo": "",
        "ref": None,
    }
    digest = _hash_entry(prev_hash=unit.genesis, version=_AUDIT_V3, **fields)  # type: ignore[arg-type]
    return LedgerEntry(
        prev_hash=unit.genesis,
        entry_hash=digest,
        version=_AUDIT_V3,
        **fields,  # type: ignore[arg-type]
    )


def test_the_genesis_binds_the_chain_to_its_unit() -> None:
    entry = _funding(MME, Decimal("900.00000000"))
    assert _replay([entry], unit=MME).balances["org"] == 900
    with pytest.raises(LedgerIntegrityError, match="broken chain link at sequence 1"):
        _replay([entry], unit=USD)
    with pytest.raises(LedgerIntegrityError, match="broken chain link at sequence 1"):
        _replay([entry], unit=Unit("mme", 2))


def test_a_replay_refuses_an_amount_finer_than_the_unit() -> None:
    entry = _funding(SEATS, Decimal("1.50000000"))
    view = _Overlay(_ChainState.empty(SEATS))
    with pytest.raises(LedgerIntegrityError, match="finer than this ledger's unit"):
        view.apply(entry)
    assert _replay([_funding(SEATS, Decimal("2.00000000"))], unit=SEATS).balances["org"] == 2


def test_a_snapshot_carries_a_declared_unit_and_no_other() -> None:
    usd = _ChainState.empty()
    assert b'"unit"' not in _encode_snapshot(usd), "a USD snapshot keeps its bytes"
    state = _replay([_funding(MME, Decimal("5.00000000"))], unit=MME)
    body = _encode_snapshot(state)
    assert b'"unit":["mme",8]' in body
    assert _decode_snapshot(body).unit == MME
    stated = _encode_snapshot(usd).replace(b'"tripped":{}', b'"tripped":{},"unit":["usd",8]')
    with pytest.raises(LedgerIntegrityError, match="not the canonical encoding"):
        _decode_snapshot(stated)
    for bad in (b'"unit":["mme"]', b'"unit":["MME",8]', b'"unit":["mme",true]'):
        with pytest.raises(LedgerIntegrityError, match="unit"):
            _decode_snapshot(body.replace(b'"unit":["mme",8]', bad))


def test_a_new_sqlite_ledger_is_declared_its_unit_and_keeps_it(tmp_path: Path) -> None:
    path = str(tmp_path / "mme.db")
    with BudgetManager.open_sqlite(path, unit=MME) as gov:
        gov.open_root("pharmacy", Decimal(900))
        assert gov.ledger.head_hash != GENESIS_HASH
    with BudgetManager.open_sqlite(path) as gov:
        assert gov.unit == MME
    with BudgetManager.open_sqlite(path, read_only=True, verify="full") as reader:
        assert reader.unit == MME and reader.available("pharmacy") == 900
    with pytest.raises(LedgerIntegrityError, match="conserves mme, not usd"):
        BudgetManager.open_sqlite(path, unit=USD)


def test_an_existing_usd_ledger_cannot_change_its_unit(tmp_path: Path) -> None:
    path = str(tmp_path / "usd.db")
    with BudgetManager.open_sqlite(path) as gov:
        gov.open_root("a", money("1"))
    with BudgetManager.open_sqlite(path, unit=USD) as gov:
        assert gov.unit == USD
    with pytest.raises(LedgerIntegrityError, match="fixed before its first entry"):
        BudgetManager.open_sqlite(path, unit=MME)
    empty = str(tmp_path / "empty.db")
    BudgetManager.open_sqlite(empty).close()
    with pytest.raises(LedgerIntegrityError, match="open it for writing"):
        BudgetManager.open_sqlite(empty, read_only=True, unit=MME)
    with BudgetManager.open_sqlite(empty, unit=MME) as gov:
        assert gov.unit == MME, "an empty ledger nobody declared takes the first unit named"


def test_a_ledger_whose_declared_unit_was_edited_does_not_open(tmp_path: Path) -> None:
    path = str(tmp_path / "mme.db")
    with BudgetManager.open_sqlite(path, unit=MME) as gov:
        gov.open_root("pharmacy", Decimal(900))
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("UPDATE schema_meta SET value = 'mme/2' WHERE key = 'unit'")
        conn.commit()
    with pytest.raises(LedgerIntegrityError, match="broken chain link at sequence 1"):
        BudgetManager.open_sqlite(path)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("DELETE FROM schema_meta WHERE key = 'unit'")
        conn.commit()
    with pytest.raises(LedgerIntegrityError, match="broken chain link at sequence 1"):
        BudgetManager.open_sqlite(path)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("INSERT INTO schema_meta (key, value) VALUES ('unit', 'mme')")
        conn.commit()
    with pytest.raises(LedgerIntegrityError, match="declares no unit it can read"):
        BudgetManager.open_sqlite(path)


def test_a_checkpointed_unit_ledger_opens_from_its_snapshot(tmp_path: Path) -> None:
    path = str(tmp_path / "vcpu.db")
    vcpu = Unit("vcpu", 0)
    never = GovernancePolicy(checkpoint_every=1_000_000)
    with BudgetManager.open_sqlite(path, unit=vcpu, policy=never) as gov:
        gov.open_root("platform", Decimal(64))
        for _ in range(3):
            gov.capture(gov.authorize("platform", Decimal(2)), Decimal(2))
        gov.checkpoint()
        gov.capture(gov.authorize("platform", Decimal(1)), Decimal(1))
    with BudgetManager.open_sqlite(path, policy=never, auditor=False) as gov:
        assert gov.unit == vcpu and gov.available("platform") == 57
    with closing(sqlite3.connect(path)) as conn:
        conn.execute("UPDATE schema_meta SET value = 'vcpu/1' WHERE key = 'unit'")
        conn.commit()
    with pytest.raises(LedgerIntegrityError, match="snapshot is of a ledger of vcpu"):
        BudgetManager.open_sqlite(path, policy=never, auditor=False)


def test_a_governor_over_a_ledger_of_another_unit_is_refused() -> None:
    gov = BudgetManager(unit=MME)
    with pytest.raises(ValueError, match="conserves mme, not seats"):
        BudgetManager(ledger=gov.ledger, unit=SEATS)


def test_inspect_prints_a_declared_unit(tmp_path: Path) -> None:
    path = str(tmp_path / "seats.db")
    with BudgetManager.open_sqlite(path, unit=SEATS) as gov:
        gov.open_root("org", Decimal(40))
    out = io.StringIO()
    assert main(["inspect", path], out=out) == 0
    text = out.getvalue()
    assert "conserves seats, counted to 0 places" in text
    assert "available 40 seats" in text and "$" not in text


@pytest.mark.usefixtures("pg_dsn")
def test_a_postgres_ledger_is_declared_its_unit_and_its_trigger_follows(pg_dsn: str) -> None:
    vcpu = Unit("vcpu", 0)
    with BudgetManager.open_postgres(pg_dsn, schema="agentgov_vcpu", unit=vcpu) as gov:
        assert gov.ledger.head_hash == vcpu.genesis
        gov.open_root("platform", Decimal(64))
        gov.capture(gov.authorize("platform", Decimal("3.5")), Decimal(4))
    with BudgetManager.open_postgres(pg_dsn, schema="agentgov_vcpu", verify="full") as gov:
        assert gov.unit == vcpu and gov.available("platform") == 60
    with pytest.raises(LedgerIntegrityError, match="fixed before its first entry"):
        BudgetManager.open_postgres(pg_dsn, schema="agentgov_vcpu", unit=Unit("vcpu", 1))
    with BudgetManager.open_postgres(pg_dsn, schema="agentgov_usd") as gov:
        assert gov.unit == USD
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        # The trigger admits entry 1 only on the declared unit's genesis.
        source = conn.execute(
            "SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = %s AND p.proname = 'extend_chain'",
            ("agentgov_vcpu",),
        ).fetchone()
        assert source is not None and vcpu.genesis in source[0]
        unit = conn.execute("SELECT value FROM agentgov_vcpu.schema_meta WHERE key = 'unit'")
        assert unit.fetchone() == ("vcpu/0",)
