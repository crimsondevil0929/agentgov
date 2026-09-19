"""Tests for the interception layer: pricing, authorize/capture, settlement."""

from __future__ import annotations

import asyncio
from decimal import Decimal
from types import SimpleNamespace

import pytest

from agentgov.core import BudgetManager, EntryType, money
from agentgov.dummy import DummyLLM, DummyResponse
from agentgov.exceptions import CircuitOpenError, DenialOfWalletError
from agentgov.interceptor import (
    PRICING,
    Interceptor,
    ModelPricing,
    TokenUsage,
    default_usage_extractor,
    normalize_model_id,
    pricing_for,
)

ZERO = Decimal("0")


@pytest.fixture
def gov() -> BudgetManager:
    manager = BudgetManager()
    manager.open_root("root", money("1.00"))
    manager.delegate("root", "worker", money("0.50"))
    return manager


# -- pricing ---------------------------------------------------------------


def test_pricing_computes_token_cost_exactly() -> None:
    pricing = pricing_for("claude-opus-5")
    # 1M input @ $5 + 1M output @ $25 = $30 exactly.
    cost = pricing.cost_of(TokenUsage(input_tokens=1_000_000, output_tokens=1_000_000))
    assert cost == money("30.00")


def test_pricing_prices_a_realistic_micro_call() -> None:
    pricing = pricing_for("claude-haiku-4-5")
    # 1200 in @ $1/MTok + 300 out @ $5/MTok = 0.0012 + 0.0015 = $0.0027
    cost = pricing.cost_of(TokenUsage(input_tokens=1200, output_tokens=300))
    assert cost == money("0.00270000")


def test_pricing_includes_cache_tokens() -> None:
    pricing = pricing_for("claude-sonnet-5")
    usage = TokenUsage(
        input_tokens=0,
        output_tokens=0,
        cache_read_input_tokens=1_000_000,
        cache_creation_input_tokens=1_000_000,
    )
    # $2 input rate -> $0.20 read (0.1x) + $2.50 write (1.25x)
    assert pricing.cost_of(usage) == money("2.70")


def test_sub_quantum_cost_rounds_up_not_to_zero() -> None:
    pricing = pricing_for("claude-haiku-4-5")
    # One input token at $1/MTok = $0.000001 -> above the 1e-8 quantum,
    # but a single sub-quantum fragment must still round up, never to zero.
    tiny = ModelPricing(
        model_id="tiny",
        input_usd_per_mtok=Decimal("0.001"),
        output_usd_per_mtok=Decimal("0.001"),
        cache_read_usd_per_mtok=ZERO,
        cache_write_usd_per_mtok=ZERO,
    )
    assert pricing.cost_of(TokenUsage(input_tokens=1)) == money("0.00000100")
    assert tiny.cost_of(TokenUsage(input_tokens=1)) == money("0.00000001")


def test_estimate_assumes_the_full_output_allowance() -> None:
    pricing = pricing_for("claude-opus-5")
    estimate = pricing.estimate(input_tokens=1000, max_output_tokens=4096)
    actual = pricing.cost_of(TokenUsage(input_tokens=1000, output_tokens=4096))
    assert estimate == actual
    assert estimate > pricing.cost_of(TokenUsage(input_tokens=1000, output_tokens=10))


def test_unknown_model_refuses_to_guess() -> None:
    with pytest.raises(KeyError, match="no published pricing"):
        pricing_for("gpt-hypothetical")


def test_pricing_table_covers_the_current_models() -> None:
    assert "claude-opus-5" in PRICING
    assert PRICING["claude-opus-5"].input_usd_per_mtok == Decimal("5.00")
    assert PRICING["claude-sonnet-5"].output_usd_per_mtok == Decimal("10.00")
    # Fable 5.1 publishes an explicit cache-read rate, not the 0.1x default.
    assert PRICING["claude-fable-5-1"].cache_read_usd_per_mtok == Decimal("0.25")


def test_token_usage_rejects_nonsense() -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        TokenUsage(input_tokens=-1)
    with pytest.raises(TypeError, match="must be an int"):
        TokenUsage(input_tokens="many")  # type: ignore[arg-type]


# -- usage extraction ------------------------------------------------------


def test_extractor_reads_an_sdk_shaped_response() -> None:
    response = DummyResponse(
        text="hi", usage=TokenUsage(input_tokens=10, output_tokens=20), model="m"
    )
    assert default_usage_extractor(response).output_tokens == 20


def test_extractor_reads_mappings_and_bare_usage() -> None:
    assert default_usage_extractor(
        {"usage": {"input_tokens": 5, "output_tokens": 7}}
    ) == TokenUsage(input_tokens=5, output_tokens=7)
    assert default_usage_extractor({"input_tokens": 5}) == TokenUsage(input_tokens=5)
    assert default_usage_extractor(TokenUsage(input_tokens=1)) == TokenUsage(input_tokens=1)


def test_extractor_refuses_to_meter_an_unknown_shape() -> None:
    with pytest.raises(TypeError, match="cannot extract token usage"):
        default_usage_extractor("just a string")


# -- interception ----------------------------------------------------------


def test_invoke_settles_the_exact_token_cost(gov: BudgetManager) -> None:
    llm = DummyLLM("claude-opus-5", output_tokens=500)
    metered = Interceptor(gov, "worker", model="claude-opus-5")
    before = gov.available("worker")

    result = metered.invoke(llm.complete, "summarise the quarterly report")

    expected = pricing_for("claude-opus-5").cost_of(result.usage)
    assert result.cost == expected
    assert result.usage.output_tokens == 500
    assert result.scope_id == "worker"
    assert result.entry.entry_type is EntryType.SPEND
    assert gov.available("worker") == before - expected
    assert llm.call_count == 1
    gov.verify_integrity()


def test_the_hold_is_larger_than_the_settled_cost_and_is_returned(
    gov: BudgetManager,
) -> None:
    llm = DummyLLM("claude-opus-5", output_tokens=10)
    metered = Interceptor(gov, "worker", model="claude-opus-5", max_output_tokens=4096)

    result = metered.invoke(llm.complete, "hi")

    assert result.hold > result.cost, "the hold reserves worst-case output"
    assert gov.available("worker") == money("0.50") - result.cost
    gov.verify_integrity()


def test_a_failing_call_is_not_charged(gov: BudgetManager) -> None:
    metered = Interceptor(gov, "worker", model="claude-opus-5")

    def boom(_: str) -> DummyResponse:
        raise RuntimeError("upstream 500")

    with pytest.raises(RuntimeError, match="upstream 500"):
        metered.invoke(boom, "prompt")

    assert gov.available("worker") == money("0.50")
    types = [e.entry_type for e in gov.audit_trail("worker")]
    assert EntryType.SPEND not in types
    assert types[-1] is EntryType.HOLD_VOID, "the hold was released"
    gov.verify_integrity()


def test_a_call_too_expensive_to_authorize_is_blocked_before_it_runs(
    gov: BudgetManager,
) -> None:
    gov.delegate("worker", "pauper", money("0.00001"))
    llm = DummyLLM("claude-opus-5")
    metered = Interceptor(gov, "pauper", model="claude-opus-5")

    with pytest.raises(DenialOfWalletError):
        metered.invoke(llm.complete, "expensive prompt")

    assert llm.call_count == 0, "the model was never called"
    assert gov.is_halted("pauper")
    gov.verify_integrity()


def test_a_halted_scope_cannot_call_at_all(gov: BudgetManager) -> None:
    llm = DummyLLM("claude-opus-5")
    metered = Interceptor(gov, "worker", model="claude-opus-5")
    gov.trip("worker", "manual halt")

    with pytest.raises(CircuitOpenError):
        metered.invoke(llm.complete, "prompt")

    assert llm.call_count == 0


def test_repeated_calls_drain_the_budget_and_halt_at_the_limit() -> None:
    """End to end: a loop burns its envelope and is stopped, not overrun."""
    gov = BudgetManager()
    gov.open_root("root", money("0.05"))
    gov.delegate("root", "looper", money("0.05"))
    llm = DummyLLM("claude-opus-5", output_tokens=200)
    metered = Interceptor(
        gov,
        "looper",
        model="claude-opus-5",
        max_output_tokens=200,
        estimated_input_tokens=100,
    )

    spent = ZERO
    calls = 0
    while True:
        try:
            result = metered.invoke(llm.complete, f"iteration {calls}")
        except (DenialOfWalletError, CircuitOpenError):
            break
        spent += result.cost
        calls += 1

    assert calls > 0
    assert spent <= money("0.05"), "the envelope was never exceeded"
    assert gov.available("looper") >= ZERO
    assert gov.is_halted("looper")
    assert gov.available("looper") == money("0.05") - spent
    gov.verify_integrity()


def test_ainvoke_meters_async_calls(gov: BudgetManager) -> None:
    llm = DummyLLM("claude-opus-5", output_tokens=100)
    metered = Interceptor(gov, "worker", model="claude-opus-5")

    result = asyncio.run(metered.ainvoke(llm.acomplete, "async prompt"))

    assert result.cost > ZERO
    assert gov.available("worker") == money("0.50") - result.cost
    gov.verify_integrity()


def test_concurrent_async_agents_are_metered_independently(gov: BudgetManager) -> None:
    for name in ("a", "b", "c"):
        gov.delegate("worker", name, money("0.10"))
    llm = DummyLLM("claude-opus-5", output_tokens=100, latency_seconds=0.01)

    async def main() -> None:
        base = Interceptor(
            gov,
            "worker",
            model="claude-opus-5",
            estimated_input_tokens=100,
            max_output_tokens=200,
        )
        results = await asyncio.gather(
            *(
                base.for_scope(name).ainvoke(llm.acomplete, f"prompt {name}")
                for name in ("a", "b", "c")
            )
        )
        for name, result in zip(("a", "b", "c"), results, strict=True):
            assert result.scope_id == name
            assert gov.available(name) == money("0.10") - result.cost

    asyncio.run(main())
    gov.verify_integrity()


# -- derivation and manual guards -----------------------------------------


def test_for_scope_and_with_hold_return_configured_copies(gov: BudgetManager) -> None:
    base = Interceptor(gov, "worker", model="claude-opus-5")
    child = base.for_scope("root")
    pinned = base.with_hold(money("0.02"))

    assert base.scope_id == "worker"
    assert child.scope_id == "root"
    assert child.pricing is base.pricing
    assert pinned.hold_amount == money("0.02")
    assert base.hold_amount != money("0.02")


def test_with_limits_resizes_the_default_hold(gov: BudgetManager) -> None:
    base = Interceptor(gov, "worker", model="claude-opus-5", max_output_tokens=4096)
    smaller = base.with_limits(max_output_tokens=128)
    assert smaller.hold_amount < base.hold_amount


def test_spend_guard_settles_a_partial_stream(gov: BudgetManager) -> None:
    metered = Interceptor(gov, "worker", model="claude-opus-5")
    pricing = metered.pricing
    consumed = TokenUsage(input_tokens=100, output_tokens=42)

    with metered.guard(memo="streamed call") as guard:
        guard.settle(pricing.cost_of(consumed))

    assert guard.entry is not None
    assert guard.entry.memo == "streamed call"
    assert gov.available("worker") == money("0.50") - pricing.cost_of(consumed)
    gov.verify_integrity()


def test_an_unsettled_guard_conservatively_captures_the_full_hold(
    gov: BudgetManager, caplog: pytest.LogCaptureFixture
) -> None:
    metered = Interceptor(gov, "worker", model="claude-opus-5")
    hold = metered.hold_amount

    with caplog.at_level("WARNING", logger="agentgov.interceptor"), metered.guard():
        pass

    assert gov.available("worker") == money("0.50") - hold
    assert "did not settle" in caplog.text
    gov.verify_integrity()


def test_interceptor_rejects_negative_token_estimates(gov: BudgetManager) -> None:
    with pytest.raises(ValueError, match="must not be negative"):
        Interceptor(gov, "worker", model="claude-opus-5", max_output_tokens=-1)


def test_dummy_llm_is_deterministic() -> None:
    llm = DummyLLM("claude-opus-5")
    first = llm.complete("same prompt")
    second = llm.complete("same prompt")
    assert first.usage == second.usage
    assert llm.complete("other").usage != first.usage


# --------------------------------------------------------------------------
# Pricing follows what served, not what was configured
# --------------------------------------------------------------------------


def test_normalize_model_id_strips_a_dated_snapshot_suffix() -> None:
    assert normalize_model_id("claude-haiku-4-5-20251001") == "claude-haiku-4-5"
    assert normalize_model_id("claude-opus-4-5-20251101") == "claude-opus-4-5"


def test_normalize_model_id_leaves_an_undated_alias_alone() -> None:
    """The version segment is not eight digits, so it must survive."""
    for alias in ("claude-haiku-4-5", "claude-opus-5", "claude-sonnet-4-6"):
        assert normalize_model_id(alias) == alias


def test_normalize_model_id_folds_case_and_whitespace() -> None:
    assert normalize_model_id("  Claude-Haiku-4-5-20251001 ") == "claude-haiku-4-5"


def test_pricing_for_resolves_a_dated_snapshot() -> None:
    """The API resolves an alias to a dated id and reports that back.

    Without folding the suffix, pricing from response.model raises KeyError
    for every dated model, and an unmetered model is an unmetered budget.
    """
    assert pricing_for("claude-haiku-4-5-20251001") is PRICING["claude-haiku-4-5"]


def test_pricing_for_still_rejects_a_genuinely_unknown_model() -> None:
    with pytest.raises(KeyError, match="no published pricing"):
        pricing_for("some-other-vendor-model-20251001")


def test_a_dated_response_is_priced_at_the_alias_rate(gov: BudgetManager) -> None:
    """End to end: a response naming the dated snapshot settles correctly."""
    metered = Interceptor(gov, "worker", model="claude-haiku-4-5")
    usage = TokenUsage(input_tokens=1000, output_tokens=1000)
    response = DummyResponse(text="x", usage=usage, model="claude-haiku-4-5-20251001")

    call = metered.invoke(lambda: response)

    assert call.model_id == "claude-haiku-4-5"
    assert call.cost == PRICING["claude-haiku-4-5"].cost_of(usage)


def test_a_server_side_fallback_is_priced_at_the_model_that_served(
    gov: BudgetManager,
) -> None:
    """A refusal fallback substitutes a different model mid-request.

    Nothing tells the governor, so pricing the configured model books a cost
    the provider will never invoice. The two tiers here are priced differently
    on purpose: at the configured rates this call costs 5x what it should.
    """
    metered = Interceptor(gov, "worker", model="claude-opus-5")
    usage = TokenUsage(input_tokens=1000, output_tokens=1000)
    response = DummyResponse(text="x", usage=usage, model="claude-haiku-4-5")

    call = metered.invoke(lambda: response)

    assert call.model_id == "claude-haiku-4-5"
    assert call.cost == PRICING["claude-haiku-4-5"].cost_of(usage)
    assert call.cost < PRICING["claude-opus-5"].cost_of(usage)
    assert call.entry.amount == call.cost, "the ledger books what served"


def test_an_explicit_pricing_override_wins_over_the_response(
    gov: BudgetManager,
) -> None:
    """An explicit ModelPricing is for a platform the rate card does not cover.

    Bedrock and Vertex bill differently while reporting a first-party model id,
    so a caller who supplied rates must keep them.
    """
    bedrock = ModelPricing(
        model_id="bedrock/claude-haiku-4-5",
        input_usd_per_mtok=Decimal("2.00"),
        output_usd_per_mtok=Decimal("10.00"),
        cache_read_usd_per_mtok=Decimal("0.20"),
        cache_write_usd_per_mtok=Decimal("2.50"),
    )
    metered = Interceptor(gov, "worker", model="claude-haiku-4-5", pricing=bedrock)
    usage = TokenUsage(input_tokens=1000, output_tokens=1000)
    response = DummyResponse(text="x", usage=usage, model="claude-haiku-4-5-20251001")

    call = metered.invoke(lambda: response)

    assert call.model_id == "bedrock/claude-haiku-4-5"
    assert call.cost == bedrock.cost_of(usage)


def test_an_unpriceable_served_model_falls_back_and_warns(
    gov: BudgetManager, caplog: pytest.LogCaptureFixture
) -> None:
    """A served model with no rate card must not fail a settled call."""
    metered = Interceptor(gov, "worker", model="claude-haiku-4-5")
    usage = TokenUsage(input_tokens=1000, output_tokens=1000)
    response = DummyResponse(text="x", usage=usage, model="something-unlisted")

    with caplog.at_level("WARNING", logger="agentgov.interceptor"):
        call = metered.invoke(lambda: response)

    assert call.model_id == "claude-haiku-4-5"
    assert call.cost == PRICING["claude-haiku-4-5"].cost_of(usage)
    assert "no published rates" in caplog.text


def test_a_response_without_a_model_field_uses_the_configured_rates(
    gov: BudgetManager,
) -> None:
    metered = Interceptor(gov, "worker", model="claude-haiku-4-5")
    usage = TokenUsage(input_tokens=1000, output_tokens=1000)

    call = metered.invoke(lambda: SimpleNamespace(usage=usage))

    assert call.model_id == "claude-haiku-4-5"
    assert call.cost == PRICING["claude-haiku-4-5"].cost_of(usage)


def test_the_hold_is_still_sized_from_the_configured_model(gov: BudgetManager) -> None:
    """The hold is placed before the call, so it cannot know what will serve.

    Only settlement moves to the served model. Pinned so the asymmetry is a
    decision rather than something discovered during an incident.
    """
    metered = Interceptor(gov, "worker", model="claude-opus-5")
    assert metered.pricing.model_id == "claude-opus-5"
    assert metered.hold_amount > 0
