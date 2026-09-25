"""Tests for the immutable, hash-chained ledger."""

from __future__ import annotations

import dataclasses
from decimal import Decimal

import pytest

from agentgov.core import (
    GENESIS_HASH,
    MAX_AMOUNT,
    Direction,
    EntryType,
    Ledger,
    LedgerLine,
    format_audit_line,
    money,
)
from agentgov.exceptions import LedgerIntegrityError


def fund(scope: str, amount: str) -> LedgerLine:
    return LedgerLine(
        entry_type=EntryType.FUNDING,
        direction=Direction.CREDIT,
        scope_id=scope,
        amount=money(amount),
    )


def spend(scope: str, amount: str) -> LedgerLine:
    return LedgerLine(
        entry_type=EntryType.SPEND,
        direction=Direction.DEBIT,
        scope_id=scope,
        amount=money(amount),
    )


# -- money ----------------------------------------------------------------


def test_money_rejects_float() -> None:
    with pytest.raises(TypeError, match="must not be a float"):
        money(0.1)  # type: ignore[arg-type]


def test_money_quantizes_to_eight_places() -> None:
    assert money("1.000000005") == Decimal("1.00000000")
    assert money(3) == Decimal("3.00000000")


def test_money_rejects_out_of_range_and_nonsense() -> None:
    with pytest.raises(ValueError, match="exceeds the maximum"):
        money(MAX_AMOUNT + 1)
    with pytest.raises(ValueError, match="not a valid decimal"):
        money("not-money")
    with pytest.raises(ValueError, match="must be finite"):
        money(Decimal("Infinity"))


# -- chain ----------------------------------------------------------------


def test_empty_ledger_starts_at_genesis() -> None:
    ledger = Ledger()
    assert len(ledger) == 0
    assert ledger.head_hash == GENESIS_HASH
    assert ledger.balance("nobody") == Decimal(0)


def test_post_chains_entries_and_updates_balance() -> None:
    ledger = Ledger()
    (first,) = ledger.post([fund("root", "1.00")])
    (second,) = ledger.post([spend("root", "0.25")])

    assert first.sequence == 1
    assert first.prev_hash == GENESIS_HASH
    assert second.sequence == 2
    assert second.prev_hash == first.entry_hash
    assert ledger.head_hash == second.entry_hash
    assert ledger.balance("root") == money("0.75")
    ledger.verify_chain()
    ledger.verify_conservation()


def test_one_transaction_shares_a_transaction_id() -> None:
    ledger = Ledger()
    entries = ledger.post(
        [
            LedgerLine(EntryType.ALLOCATION, Direction.DEBIT, "root", money("0.10"), "kid"),
            LedgerLine(EntryType.ALLOCATION, Direction.CREDIT, "kid", money("0.10"), "root"),
        ]
    )
    assert len({e.transaction_id for e in entries}) == 1
    assert len({e.entry_id for e in entries}) == 2


def test_balances_thread_through_a_single_transaction() -> None:
    """A capture credits and debits the same scope in one transaction."""
    ledger = Ledger()
    ledger.post([fund("root", "1.00")])
    (hold,) = ledger.post([LedgerLine(EntryType.HOLD, Direction.DEBIT, "root", money("0.30"))])
    entries = ledger.post(
        [
            LedgerLine(
                EntryType.HOLD_VOID, Direction.CREDIT, "root", money("0.30"), ref=hold.entry_id
            ),
            spend("root", "0.05"),
        ]
    )
    assert entries[0].balance_after == money("1.00")
    assert entries[1].balance_after == money("0.95")
    ledger.verify_chain()
    ledger.verify_conservation()


# -- validation and atomicity ---------------------------------------------


def test_illegal_direction_is_rejected() -> None:
    ledger = Ledger()
    with pytest.raises(ValueError, match="may not be a"):
        ledger.post([LedgerLine(EntryType.SPEND, Direction.CREDIT, "root", money("1"))])


def test_non_positive_amount_is_rejected() -> None:
    ledger = Ledger()
    with pytest.raises(ValueError, match="must be positive"):
        ledger.post([fund("root", "0")])


def test_unquantized_amount_is_rejected() -> None:
    ledger = Ledger()
    line = LedgerLine(EntryType.FUNDING, Direction.CREDIT, "root", Decimal("0.123456789"))
    with pytest.raises(ValueError, match="not quantized"):
        ledger.post([line])


def test_unbalanced_transfer_is_rejected() -> None:
    ledger = Ledger()
    ledger.post([fund("root", "1.00")])
    with pytest.raises(LedgerIntegrityError, match="does not balance"):
        ledger.post(
            [
                LedgerLine(EntryType.ALLOCATION, Direction.DEBIT, "root", money("0.10"), "kid"),
                LedgerLine(EntryType.ALLOCATION, Direction.CREDIT, "kid", money("0.09"), "root"),
            ]
        )


def test_empty_transaction_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one line"):
        Ledger().post([])


def test_a_rejected_transaction_writes_nothing() -> None:
    """Validation completes before any append, so failure leaves no trace."""
    ledger = Ledger()
    ledger.post([fund("root", "1.00")])
    head_before = ledger.head_hash

    with pytest.raises(ValueError):
        ledger.post(
            [
                spend("root", "0.10"),  # valid
                LedgerLine(EntryType.SPEND, Direction.CREDIT, "root", money("0.10")),
            ]
        )

    assert len(ledger) == 1
    assert ledger.head_hash == head_before
    assert ledger.balance("root") == money("1.00")
    ledger.verify_chain()


# -- tamper evidence -------------------------------------------------------


def test_verify_chain_detects_a_forged_amount() -> None:
    ledger = Ledger()
    ledger.post([fund("root", "1.00")])
    ledger.post([spend("root", "0.25")])

    # Simulate an attacker rewriting history in place.
    forged = dataclasses.replace(ledger._entries[1], amount=money("0.01"))
    ledger._entries[1] = forged

    with pytest.raises(LedgerIntegrityError, match="tampered with"):
        ledger.verify_chain()


def test_verify_chain_detects_a_broken_link() -> None:
    ledger = Ledger()
    ledger.post([fund("root", "1.00")])
    ledger.post([spend("root", "0.25")])

    ledger._entries[1] = dataclasses.replace(ledger._entries[1], prev_hash=GENESIS_HASH)

    with pytest.raises(LedgerIntegrityError, match="broken chain link"):
        ledger.verify_chain()


def test_verify_chain_detects_a_desynced_balance_cache() -> None:
    ledger = Ledger()
    ledger.post([fund("root", "1.00")])
    ledger._balances["root"] = money("9999.00")

    with pytest.raises(LedgerIntegrityError, match="cached balance"):
        ledger.verify_chain()


def test_verify_conservation_detects_invented_money() -> None:
    ledger = Ledger()
    ledger.post([fund("root", "1.00")])
    ledger._balances["ghost"] = money("5.00")

    with pytest.raises(LedgerIntegrityError, match="conservation violated"):
        ledger.verify_conservation()


# -- audit output ----------------------------------------------------------


def test_audit_line_is_fixed_field_and_parseable() -> None:
    ledger = Ledger()
    (entry,) = ledger.post(
        [
            LedgerLine(
                EntryType.FUNDING,
                Direction.CREDIT,
                "root",
                money("1.00"),
                memo="opening envelope",
            )
        ]
    )
    line = format_audit_line(entry)
    fields = dict(part.split("=", 1) for part in line.split("|")[1:])

    assert line.startswith("AGOV2|")
    assert fields["seq"] == "0000000001"
    assert fields["type"] == "funding"
    assert fields["dir"] == "CR"
    assert fields["scope"] == "root"
    assert fields["cpty"] == "-"
    assert fields["amt"] == "1.00000000"
    assert fields["bal"] == "1.00000000"
    assert fields["memo"] == "opening envelope"


def test_audit_record_is_all_strings() -> None:
    ledger = Ledger()
    (entry,) = ledger.post([fund("root", "1.00")])
    record = entry.to_audit_record()

    assert all(isinstance(v, str) for v in record.values())
    assert record["entry_hash"] == entry.entry_hash
    assert record["prev_hash"] == GENESIS_HASH


def test_entries_are_frozen() -> None:
    ledger = Ledger()
    (entry,) = ledger.post([fund("root", "1.00")])
    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.amount = money("2.00")  # type: ignore[misc]
