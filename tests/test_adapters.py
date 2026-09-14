"""Tests for the framework drop-in adapters.

Every framework object here is a **fake**. That is the point: the adapters
duck-type rather than import, so they must be provable without LangChain or
CrewAI installed — and they must keep working when those libraries reshuffle
their internals, which they do.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Iterator
from decimal import Decimal
from typing import Any

import pytest

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.adapters.crewai import (
    CrewHalted,
    GovernedCrew,
    extract_crew_usage,
    govern_agent,
    govern_crew,
)
from agentgov.adapters.langchain import (
    GovernedCallbackHandler,
    GovernedChatModel,
    extract_langchain_usage,
    govern_chat_model,
)
from agentgov.cognitive import CognitiveBreaker, CognitivePolicy
from agentgov.core import EntryType
from agentgov.exceptions import AgentThrashingError, CircuitOpenError, DenialOfWalletError
from agentgov.interceptor import TokenUsage
from agentgov.reconciliation import MeteringJournal

ZERO = Decimal("0")
NO_VELOCITY = GovernancePolicy(max_calls_per_window=0)


@pytest.fixture
def gov() -> BudgetManager:
    manager = BudgetManager(policy=NO_VELOCITY)
    manager.open_root("agent", money("5.00"))
    return manager


# --------------------------------------------------------------------------
# LangChain fakes
# --------------------------------------------------------------------------


class HumanMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class AIMessage:
    """A modern LangChain message, carrying normalised usage_metadata."""

    def __init__(self, content: str, usage: dict[str, int] | None = None) -> None:
        self.content = content
        self.usage_metadata = usage


class Generation:
    def __init__(self, message: AIMessage) -> None:
        self.message = message


class LLMResult:
    """LangChain's LLMResult, in whichever shape the test needs."""

    def __init__(
        self,
        message: AIMessage | None = None,
        llm_output: dict[str, Any] | None = None,
    ) -> None:
        self.generations = [[Generation(message)]] if message is not None else []
        self.llm_output = llm_output


class FakeChatModel:
    """A LangChain chat model that reports usage proportional to its input."""

    model = "claude-opus-5"

    def __init__(self, output_tokens: int = 200) -> None:
        self.output_tokens = output_tokens
        self.calls = 0

    def _usage(self, messages: list[Any]) -> dict[str, int]:
        chars = sum(len(getattr(m, "content", str(m))) for m in messages)
        return {"input_tokens": max(1, chars // 4), "output_tokens": self.output_tokens}

    def invoke(self, messages: list[Any], **_: object) -> AIMessage:
        self.calls += 1
        return AIMessage("answer", self._usage(messages))

    async def ainvoke(self, messages: list[Any], **_: object) -> AIMessage:
        self.calls += 1
        return AIMessage("answer", self._usage(messages))

    def stream(self, messages: list[Any], **_: object) -> Iterator[AIMessage]:
        self.calls += 1
        yield AIMessage("part", {"input_tokens": 100, "output_tokens": 0})
        yield AIMessage("done", {"input_tokens": 100, "output_tokens": self.output_tokens})

    def bind_tools(self, tools: list[Any]) -> FakeChatModel:
        bound = FakeChatModel(self.output_tokens)
        bound.calls = self.calls
        return bound

    def get_num_tokens(self, text: str) -> int:
        return len(text) // 4


# --------------------------------------------------------------------------
# LangChain: usage extraction
# --------------------------------------------------------------------------


def test_usage_is_found_in_every_shape_langchain_has_used() -> None:
    modern = LLMResult(AIMessage("x", {"input_tokens": 10, "output_tokens": 20}))
    assert extract_langchain_usage(modern) == TokenUsage(input_tokens=10, output_tokens=20)

    openai_shape = LLMResult(
        llm_output={"token_usage": {"prompt_tokens": 11, "completion_tokens": 22}}
    )
    assert extract_langchain_usage(openai_shape) == TokenUsage(input_tokens=11, output_tokens=22)

    anthropic_shape = LLMResult(llm_output={"usage": {"input_tokens": 13, "output_tokens": 24}})
    assert extract_langchain_usage(anthropic_shape) == TokenUsage(input_tokens=13, output_tokens=24)

    bare_message = AIMessage("x", {"input_tokens": 5, "output_tokens": 6})
    assert extract_langchain_usage(bare_message) == TokenUsage(input_tokens=5, output_tokens=6)

    assert extract_langchain_usage({"usage": {"input_tokens": 1, "output_tokens": 2}}) == (
        TokenUsage(input_tokens=1, output_tokens=2)
    )


def test_an_unrecognised_shape_raises_rather_than_metering_zero() -> None:
    """Silently metering zero would let an unknown shape spend without limit."""
    with pytest.raises(TypeError, match="no token usage found"):
        extract_langchain_usage(object())


def test_cache_tokens_are_carried_through() -> None:
    usage = extract_langchain_usage(
        LLMResult(
            llm_output={
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_read_input_tokens": 900,
                    "cache_creation_input_tokens": 30,
                }
            }
        )
    )
    assert usage.cache_read_input_tokens == 900
    assert usage.cache_creation_input_tokens == 30


# --------------------------------------------------------------------------
# LangChain: GovernedChatModel
# --------------------------------------------------------------------------


def test_two_lines_govern_an_existing_chat_model(gov: BudgetManager) -> None:
    """The headline claim: wrap it, and the call site does not change."""
    raw = FakeChatModel()
    model = GovernedChatModel(raw, gov, "agent")

    answer = model.invoke([HumanMessage("summarise the quarterly report")])

    assert isinstance(answer, AIMessage), "the adapter changed the return type"
    assert answer.content == "answer"
    assert raw.calls == 1
    spend = [e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]
    assert len(spend) == 1
    assert gov.available("agent") == money("5.00") - spend[0].amount
    gov.verify_integrity()


def test_the_hold_is_sized_from_the_messages(gov: BudgetManager) -> None:
    model = GovernedChatModel(FakeChatModel(), gov, "agent")
    small = model.interceptor.size_hold((), {"messages": ["hi"]})
    large = model.interceptor.size_hold((), {"messages": ["word " * 20_000]})
    assert large > small * 2


def test_a_failing_model_is_not_charged(gov: BudgetManager) -> None:
    class Broken(FakeChatModel):
        def invoke(self, messages: list[Any], **_: object) -> AIMessage:
            raise RuntimeError("provider 500")

    model = GovernedChatModel(Broken(), gov, "agent")
    with pytest.raises(RuntimeError, match="provider 500"):
        model.invoke([HumanMessage("hello")])

    assert gov.available("agent") == money("5.00")
    assert gov._open_auths == {}
    gov.verify_integrity()


def test_denial_of_wallet_propagates_into_the_graph() -> None:
    """A halted budget must surface as an exception the caller can see."""
    manager = BudgetManager(policy=NO_VELOCITY)
    manager.open_root("agent", money("0.0000001"))
    raw = FakeChatModel()
    model = GovernedChatModel(raw, manager, "agent")

    with pytest.raises(DenialOfWalletError):
        model.invoke([HumanMessage("this cannot be afforded")])

    assert raw.calls == 0, "the model was called despite an unaffordable hold"


def test_a_thrashing_graph_is_halted_before_the_model_is_called(gov: BudgetManager) -> None:
    breaker = CognitiveBreaker(
        observer=None, manager=gov, policy=CognitivePolicy(max_identical_repeats=2)
    )
    raw = FakeChatModel()
    model = GovernedChatModel(raw, gov, "agent", cognitive=breaker)

    model.invoke([HumanMessage("the same question")])
    with pytest.raises(AgentThrashingError):
        model.invoke([HumanMessage("the same question")])

    assert raw.calls == 1, "the model was reached after the breaker tripped"
    assert gov.is_halted("agent")


def test_the_journal_is_populated_for_reconciliation(gov: BudgetManager) -> None:
    journal = MeteringJournal()
    model = GovernedChatModel(FakeChatModel(), gov, "agent", journal=journal)

    model.invoke([HumanMessage("a question worth eight tokens or so")])

    (entry,) = journal.entries()
    assert entry.model == "claude-opus-5"
    assert entry.usage.output_tokens == 200
    assert entry.scope_id == "agent"


def test_passthrough_and_rewrapping(gov: BudgetManager) -> None:
    model = GovernedChatModel(FakeChatModel(), gov, "agent")

    # An ungoverned helper is forwarded untouched.
    assert model.get_num_tokens("abcdefgh") == 2
    assert model.model == "claude-opus-5"
    assert "governed" in repr(model)

    # bind_tools must not hand back an *un*governed model.
    bound = model.bind_tools([{"name": "search"}])
    assert isinstance(bound, GovernedChatModel)
    bound.invoke([HumanMessage("bound call")])
    assert len([e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]) == 1


def test_async_and_streaming_are_governed(gov: BudgetManager) -> None:
    model = GovernedChatModel(FakeChatModel(), gov, "agent")

    asyncio.run(model.ainvoke([HumanMessage("async question")]))

    stream = model.stream([HumanMessage("streamed question")])
    with stream:
        chunks = list(stream)
    assert len(chunks) == 2
    assert stream.cost is not None and stream.cost > ZERO

    spend = [e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]
    assert len(spend) == 2
    gov.verify_integrity()


def test_govern_chat_model_is_the_one_call_form(gov: BudgetManager) -> None:
    model = govern_chat_model(FakeChatModel(), gov, "agent")
    assert isinstance(model, GovernedChatModel)
    assert isinstance(model.raw, FakeChatModel)


def test_a_model_needs_either_an_interceptor_or_a_scope(gov: BudgetManager) -> None:
    with pytest.raises(ValueError, match="interceptor"):
        GovernedChatModel(FakeChatModel())


# --------------------------------------------------------------------------
# LangChain: GovernedCallbackHandler
# --------------------------------------------------------------------------


def test_the_handler_authorizes_on_start_and_settles_on_end(gov: BudgetManager) -> None:
    handler = GovernedCallbackHandler(gov, "agent")
    run = uuid.uuid4()

    handler.on_chat_model_start({}, [[HumanMessage("a graph node's prompt")]], run_id=run)
    assert handler.outstanding == 1
    assert gov.available("agent") < money("5.00"), "the hold encumbered funds"

    handler.on_llm_end(
        LLMResult(AIMessage("x", {"input_tokens": 500, "output_tokens": 250})), run_id=run
    )

    assert handler.outstanding == 0
    (spend,) = [e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]
    assert spend.amount == handler.interceptor.pricing.cost_of(
        TokenUsage(input_tokens=500, output_tokens=250)
    )
    gov.verify_integrity()


def test_the_handler_raises_errors_rather_than_letting_langchain_swallow_them() -> None:
    """Without raise_error, LangChain logs a callback exception and continues."""
    assert GovernedCallbackHandler.raise_error is True


def test_the_handler_voids_on_model_error(gov: BudgetManager) -> None:
    handler = GovernedCallbackHandler(gov, "agent")
    run = uuid.uuid4()

    handler.on_chat_model_start({}, [[HumanMessage("prompt")]], run_id=run)
    handler.on_llm_error(RuntimeError("provider 503"), run_id=run)

    assert handler.outstanding == 0
    assert gov.available("agent") == money("5.00")
    types = [e.entry_type for e in gov.audit_trail("agent")]
    assert EntryType.SPEND not in types
    gov.verify_integrity()


def test_concurrent_graph_branches_settle_independently(gov: BudgetManager) -> None:
    """LangGraph fans out; each run_id carries its own encumbrance."""
    handler = GovernedCallbackHandler(gov, "agent")
    runs = [uuid.uuid4() for _ in range(4)]

    for run in runs:
        handler.on_chat_model_start({}, [[HumanMessage("branch")]], run_id=run)
    assert handler.outstanding == 4

    for index, run in enumerate(runs):
        handler.on_llm_end(
            LLMResult(AIMessage("x", {"input_tokens": 100 * (index + 1), "output_tokens": 50})),
            run_id=run,
        )

    assert handler.outstanding == 0
    spend = [e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]
    assert len(spend) == 4
    gov.verify_integrity()


def test_an_end_without_a_start_is_ignored(gov: BudgetManager) -> None:
    handler = GovernedCallbackHandler(gov, "agent")
    handler.on_llm_end(
        LLMResult(AIMessage("x", {"input_tokens": 1, "output_tokens": 1})), run_id=uuid.uuid4()
    )
    assert gov.available("agent") == money("5.00")


def test_an_unreadable_response_captures_the_full_hold(
    gov: BudgetManager, caplog: pytest.LogCaptureFixture
) -> None:
    """Conservative: under-charging is the one direction that must not happen."""
    handler = GovernedCallbackHandler(gov, "agent")
    run = uuid.uuid4()
    handler.on_chat_model_start({}, [[HumanMessage("prompt")]], run_id=run)
    held = gov.available("agent")

    with caplog.at_level("WARNING", logger="agentgov.adapters.langchain"):
        handler.on_llm_end(object(), run_id=run)

    assert "usage" in caplog.text
    (spend,) = [e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]
    assert spend.amount == money("5.00") - held, "the full hold should have been captured"
    gov.verify_integrity()


def test_release_all_reclaims_an_abandoned_run(gov: BudgetManager) -> None:
    handler = GovernedCallbackHandler(gov, "agent")
    for _ in range(3):
        handler.on_chat_model_start({}, [[HumanMessage("prompt")]], run_id=uuid.uuid4())

    assert handler.release_all() == 3

    assert handler.outstanding == 0
    assert gov.available("agent") == money("5.00")
    gov.verify_integrity()


def test_the_handler_declares_the_events_it_wants(gov: BudgetManager) -> None:
    handler = GovernedCallbackHandler(gov, "agent")
    assert handler.ignore_llm is False
    assert handler.ignore_chat_model is False
    assert handler.ignore_chain is True


def test_completion_style_starts_are_also_governed(gov: BudgetManager) -> None:
    handler = GovernedCallbackHandler(gov, "agent")
    run = uuid.uuid4()
    handler.on_llm_start({}, ["a legacy completion prompt"], run_id=run)
    assert handler.outstanding == 1
    handler.on_llm_end(
        LLMResult(AIMessage("x", {"input_tokens": 9, "output_tokens": 9})), run_id=run
    )
    assert handler.outstanding == 0


# --------------------------------------------------------------------------
# CrewAI
# --------------------------------------------------------------------------


class UsageMetrics:
    def __init__(self, prompt: int, completion: int, cached: int = 0) -> None:
        self.prompt_tokens = prompt
        self.completion_tokens = completion
        self.cached_prompt_tokens = cached
        self.total_tokens = prompt + completion


class CrewOutput:
    def __init__(self, raw: str, usage: UsageMetrics) -> None:
        self.raw = raw
        self.token_usage = usage


class FakeCrew:
    """A crew whose usage_metrics accumulate across kickoffs, as CrewAI's do."""

    def __init__(self) -> None:
        self.usage_metrics = UsageMetrics(0, 0)
        self.runs = 0

    def kickoff(self, inputs: dict[str, Any] | None = None) -> CrewOutput:
        self.runs += 1
        self.usage_metrics = UsageMetrics(
            self.usage_metrics.prompt_tokens + 1000,
            self.usage_metrics.completion_tokens + 500,
        )
        return CrewOutput(f"run {self.runs}", self.usage_metrics)

    async def kickoff_async(self, inputs: dict[str, Any] | None = None) -> CrewOutput:
        return self.kickoff(inputs)

    def describe(self) -> str:
        return "a crew of two agents"


def test_crew_usage_is_read_from_every_shape() -> None:
    assert extract_crew_usage(CrewOutput("x", UsageMetrics(10, 20))) == TokenUsage(
        input_tokens=10, output_tokens=20
    )
    assert extract_crew_usage(FakeCrew()) == TokenUsage()
    assert extract_crew_usage({"usage_metrics": {"prompt_tokens": 3, "completion_tokens": 4}}) == (
        TokenUsage(input_tokens=3, output_tokens=4)
    )
    assert extract_crew_usage({"prompt_tokens": 5, "completion_tokens": 6}) == TokenUsage(
        input_tokens=5, output_tokens=6
    )


def test_two_lines_govern_a_crew(gov: BudgetManager) -> None:
    raw = FakeCrew()
    crew = GovernedCrew(raw, gov, "agent")

    result = crew.kickoff()

    assert isinstance(result, CrewOutput), "the adapter changed the return type"
    assert raw.runs == 1
    (spend,) = [e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]
    assert spend.amount == crew.interceptor.pricing.cost_of(
        TokenUsage(input_tokens=1000, output_tokens=500)
    )
    gov.verify_integrity()


def test_cumulative_usage_is_billed_only_once(gov: BudgetManager) -> None:
    """The detail that is easy to miss: CrewAI totals accumulate.

    Settling the reported total each run would bill run one again on run two,
    and again on run three.
    """
    crew = GovernedCrew(FakeCrew(), gov, "agent")
    per_run = crew.interceptor.pricing.cost_of(TokenUsage(input_tokens=1000, output_tokens=500))

    for _ in range(3):
        crew.kickoff()

    spend = [e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]
    assert len(spend) == 3
    assert all(entry.amount == per_run for entry in spend), "a run was double-billed"
    assert gov.available("agent") == money("5.00") - per_run * 3
    assert crew.settled_usage == TokenUsage(input_tokens=3000, output_tokens=1500)
    gov.verify_integrity()


def test_a_failing_crew_is_not_charged(gov: BudgetManager) -> None:
    class Exploding(FakeCrew):
        def kickoff(self, inputs: dict[str, Any] | None = None) -> CrewOutput:
            raise RuntimeError("a task failed")

    crew = GovernedCrew(Exploding(), gov, "agent")
    with pytest.raises(RuntimeError, match="a task failed"):
        crew.kickoff()

    assert gov.available("agent") == money("5.00")
    assert gov._open_auths == {}
    gov.verify_integrity()


def test_a_halted_crew_can_exit_gracefully(gov: BudgetManager) -> None:
    """A governance halt is a decision, not a crash: the crew survives it."""
    raw = FakeCrew()
    crew = GovernedCrew(raw, gov, "agent", raise_on_halt=False)
    gov.trip("agent", "operator halt")

    result = crew.kickoff()

    assert isinstance(result, CrewHalted)
    assert not result, "CrewHalted must be falsey so `if not result` reads correctly"
    assert result.scope_id == "agent"
    assert isinstance(result.error, CircuitOpenError)
    assert raw.runs == 0, "the crew ran despite being halted"
    assert gov._open_auths == {}, "a halted crew stranded a hold"
    gov.verify_integrity()


def test_a_halted_crew_raises_by_default(gov: BudgetManager) -> None:
    crew = GovernedCrew(FakeCrew(), gov, "agent")
    gov.trip("agent", "operator halt")
    with pytest.raises(CircuitOpenError):
        crew.kickoff()


def test_a_crew_reporting_no_usage_is_not_charged(gov: BudgetManager) -> None:
    class Silent(FakeCrew):
        def kickoff(self, inputs: dict[str, Any] | None = None) -> CrewOutput:
            return CrewOutput("done", UsageMetrics(0, 0))

    crew = GovernedCrew(Silent(), gov, "agent")
    crew.kickoff()

    assert gov.available("agent") == money("5.00")
    types = [e.entry_type for e in gov.audit_trail("agent")]
    assert EntryType.SPEND not in types
    assert types[-1] is EntryType.HOLD_VOID


def test_crew_passthrough_and_async(gov: BudgetManager) -> None:
    crew = GovernedCrew(FakeCrew(), gov, "agent")
    assert crew.describe() == "a crew of two agents"
    assert "governed" in repr(crew)
    assert isinstance(crew.raw, FakeCrew)

    asyncio.run(crew.kickoff_async())
    assert len([e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]) == 1


def test_govern_crew_is_the_one_call_form(gov: BudgetManager) -> None:
    assert isinstance(govern_crew(FakeCrew(), gov, "agent"), GovernedCrew)


def test_the_crew_journal_records_only_the_delta(gov: BudgetManager) -> None:
    journal = MeteringJournal()
    crew = GovernedCrew(FakeCrew(), gov, "agent", journal=journal)
    crew.kickoff()
    crew.kickoff()

    assert len(journal) == 2
    for entry in journal.entries():
        assert entry.usage == TokenUsage(input_tokens=1000, output_tokens=500)


# --------------------------------------------------------------------------
# The generic decorator
# --------------------------------------------------------------------------


def test_govern_agent_wraps_an_arbitrary_agent_function(gov: BudgetManager) -> None:
    @govern_agent(gov, "agent", usage_of=lambda r: TokenUsage(input_tokens=800, output_tokens=400))
    def run_research(topic: str) -> str:
        """Research a topic."""
        return f"report on {topic}"

    result = run_research("wind turbine siting")

    assert result == "report on wind turbine siting"
    assert run_research.__name__ == "run_research"
    assert run_research.__doc__ == "Research a topic."
    (spend,) = [e for e in gov.audit_trail("agent") if e.entry_type is EntryType.SPEND]
    assert spend.amount > ZERO
    gov.verify_integrity()


def test_govern_agent_voids_when_the_function_raises(gov: BudgetManager) -> None:
    @govern_agent(gov, "agent", usage_of=lambda r: TokenUsage(input_tokens=1, output_tokens=1))
    def flaky() -> str:
        raise ValueError("tool unavailable")

    with pytest.raises(ValueError, match="tool unavailable"):
        flaky()

    assert gov.available("agent") == money("5.00")
    assert gov._open_auths == {}


def test_govern_agent_respects_the_cognitive_breaker(gov: BudgetManager) -> None:
    breaker = CognitiveBreaker(
        observer=None, manager=gov, policy=CognitivePolicy(max_identical_repeats=2)
    )
    ran = 0

    @govern_agent(
        gov,
        "agent",
        cognitive=breaker,
        usage_of=lambda r: TokenUsage(input_tokens=10, output_tokens=10),
    )
    def repeat(query: str) -> str:
        nonlocal ran
        ran += 1
        return "done"

    repeat("identical")
    with pytest.raises(AgentThrashingError):
        repeat("identical")
    assert ran == 1
