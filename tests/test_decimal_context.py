"""The ledger computes in its own decimal context, never the caller's (F3).

:mod:`decimal` contexts are thread-local and belong to the host application.
Whatever a host does to its own (lower the precision, change the rounding,
trap signals the ledger does not expect), every figure the ledger writes,
and every cost the interceptor prices, is the same as under the default
context, and the ledger it leaves behind replays.
"""

from __future__ import annotations

import decimal
import threading
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from agentgov import BudgetManager, money
from agentgov.exceptions import DenialOfWalletError
from agentgov.interceptor import TokenUsage, pricing_for
from agentgov.reconciliation import MeteredRecord, ProviderUsageRecord, reconcile

HOSTILE: dict[str, dict[str, Any]] = {
    "prec=1": {"prec": 1},
    "prec=6": {"prec": 6},
    "round-down": {"prec": 9, "rounding": decimal.ROUND_DOWN},
    "round-up": {"prec": 9, "rounding": decimal.ROUND_UP},
    "traps-inexact": {"trap": decimal.Inexact},
    "traps-rounded": {"trap": decimal.Rounded},
    "tiny-exponent": {"Emax": 3, "Emin": -3},
}


def _hostile(ctx: decimal.Context, settings: dict[str, Any]) -> None:
    """Make the calling thread's context what a careless host might leave it."""
    for key, value in settings.items():
        if key == "trap":
            ctx.traps[value] = True
        else:
            setattr(ctx, key, value)


def _workload(gov: BudgetManager) -> None:
    """Every kind of write, with amounts that need all of their digits."""
    gov.open_root("root", money("123456.78901234"))
    gov.fund("root", money("0.00000001"))
    gov.delegate("root", "child", money("98765.43210987"))
    gov.spend("child", money("0.00000003"))
    hold = gov.authorize("child", money("12.34567891"))
    gov.capture(hold, money("12.34567890"))
    gov.refund("child", money("0.00000001"))
    gov.release("child", money("1.11111111"))
    other = gov.authorize("root", money("0.00000007"))
    gov.void(other)
    gov.anchor("root", "external record")


@pytest.mark.parametrize("hostile", HOSTILE.values(), ids=HOSTILE.keys())
def test_every_write_is_exact_under_any_host_context(
    hostile: dict[str, Any], tmp_path: Path
) -> None:
    reference = BudgetManager()
    _workload(reference)

    db = str(tmp_path / "ledger.db")
    with BudgetManager.open_sqlite(db) as gov:
        with decimal.localcontext() as ctx:
            _hostile(ctx, hostile)
            _workload(gov)
        gov.verify_integrity()
        for scope in ("root", "child"):
            assert gov.available(scope) == reference.available(scope)
        written = [e.balance_after for e in gov.audit_trail()]
        assert written == [e.balance_after for e in reference.audit_trail()]
    with BudgetManager.open_sqlite(db) as reopened:
        reopened.verify_integrity()
        assert reopened.available("child") == reference.available("child")


def test_money_quantizes_exactly_under_a_low_precision_context() -> None:
    with decimal.localcontext() as ctx:
        ctx.prec = 3
        assert money("123456.78901234") == Decimal("123456.78901234")
        assert str(money("123456.789012349")) == "123456.78901234"


def test_an_overdraft_is_measured_exactly_under_a_low_precision_context() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("100000.00000001"))
    hold = gov.authorize("root", money("100000"))
    with decimal.localcontext() as ctx:
        ctx.prec = 4
        with pytest.raises(DenialOfWalletError) as raised:
            gov.capture(hold, money("100000.00000002"))
    assert gov.available("root") == money("-0.00000001")
    assert raised.value.available == money("100000.00000001")
    gov.verify_integrity()


def test_concurrent_threads_with_different_contexts_agree(tmp_path: Path) -> None:
    gov = BudgetManager.open_sqlite(str(tmp_path / "threads.db"))
    gov.open_root("root", money("1000000"))
    for i in range(4):
        gov.delegate("root", f"t{i}", money("1000.12345678"))
    errors: list[BaseException] = []

    def run(index: int) -> None:
        try:
            with decimal.localcontext() as ctx:
                ctx.prec = 2 + index
                for _ in range(50):
                    gov.spend(f"t{index}", money("0.00000013"))
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    for i in range(4):
        assert gov.available(f"t{i}") == money("1000.12345678") - 50 * money("0.00000013")
    gov.verify_integrity()
    gov.close()


@pytest.mark.parametrize("hostile", HOSTILE.values(), ids=HOSTILE.keys())
def test_pricing_does_not_depend_on_the_host_context(
    hostile: dict[str, Any],
) -> None:
    usage = TokenUsage(
        input_tokens=123_457,
        output_tokens=98_765,
        cache_read_input_tokens=1_111,
        cache_creation_input_tokens=7_777,
    )
    pricing = pricing_for("claude-opus-5")
    expected = pricing.cost_of(usage)
    with decimal.localcontext() as ctx:
        _hostile(ctx, hostile)
        assert pricing.cost_of(usage) == expected


def test_reconciliation_decisions_do_not_depend_on_the_host_context() -> None:
    from datetime import UTC, datetime

    now = datetime(2026, 10, 11, tzinfo=UTC)
    provider = [
        ProviderUsageRecord(
            record_id="line-1",
            timestamp=now,
            model="claude-opus-5",
            input_tokens=1000,
            output_tokens=10,
            total_cost=Decimal("0.123456789"),
        )
    ]
    metered = [
        MeteredRecord(
            transaction_id=uuid.uuid4(),
            sequence=7,
            timestamp=now,
            scope_id="agent",
            model="claude-opus-5",
            input_tokens=1000,
            output_tokens=10,
            settled_cost=Decimal("0.12345678"),
            entry_hash="0" * 64,
        )
    ]
    expected = reconcile(metered, provider)
    with decimal.localcontext() as ctx:
        ctx.prec = 2
        found = reconcile(metered, provider)
        assert found.variance == expected.variance
        assert found.variance_percent == expected.variance_percent
        assert found.passed == expected.passed
