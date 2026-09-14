"""Tests for the cognitive circuit breaker.

The headline claim under test: an agent stuck in a *soft loop* — nudging a
search query without making semantic progress — is halted within a handful of
calls, long before the financial envelope notices anything is wrong. The rest
of this file is the other half of that claim: that it does not fire on agents
which are genuinely working, that the semantic lane never blocks the caller,
and that neither lock can deadlock against the other.
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
import uuid
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from decimal import Decimal

import pytest

from agentgov.cognitive import (
    CallCycleDetector,
    CognitiveBreaker,
    CognitivePolicy,
    ExactRepeatDetector,
    NearDuplicateDetector,
    ToolCall,
    TrajectoryEntropyObserver,
    Verdict,
    canonical_arguments,
    jaccard,
    shingles,
)
from agentgov.core import BudgetManager, EntryType, GovernancePolicy, money
from agentgov.dummy import DummyLLM
from agentgov.exceptions import (
    AgentGovError,
    AgentThrashingError,
    AgentThrashingException,
    CircuitBreakerError,
    CircuitOpenError,
)
from agentgov.interceptor import Interceptor

ZERO = Decimal("0")

# An agent stuck retrying one idea with cosmetic edits. A human would call
# these ~90% identical; in character-trigram Jaccard they measure 0.74-0.83.
SOFT_LOOP_QUERIES = [
    "best python web scraping library 2026",
    "best python web scraping libraries 2026",
    "best python web scraping library 2026 guide",
    "the best python web scraping library 2026",
    "best python web scraping library in 2026",
    "best python web-scraping library 2026",
]

# An agent actually working through a research task. Same domain, real
# progress: each call asks something the previous one did not.
PROGRESSING_QUERIES = [
    "python web scraping library comparison",
    "beautifulsoup vs scrapy performance benchmarks",
    "scrapy concurrent request tuning",
    "playwright headless browser scraping cost",
    "rotating proxy providers pricing 2026",
    "robots.txt compliance for commercial crawlers",
]


@pytest.fixture
def breaker() -> CognitiveBreaker:
    """A breaker with only the deterministic tier, for predictable tests."""
    return CognitiveBreaker(observer=None)


def unrelated(seed: object) -> str:
    """Text with no meaningful trigram overlap with any other such text.

    Sequential strings like ``"call 1"``/``"call 2"`` are themselves a soft
    loop by this module's metric, so tests that need "just some distinct
    calls" must not use them, or they measure the wrong thing.
    """
    return f"{seed}-{uuid.uuid4().hex}{uuid.uuid4().hex}"


def drive(breaker: CognitiveBreaker, queries: Sequence[str], *, tool: str = "search") -> int:
    """Feed queries until one is halted. Returns the 1-based call that tripped.

    :returns: The call index that raised, or ``0`` if the run completed.
    """
    for index, query in enumerate(queries, start=1):
        try:
            breaker.observe("agent", tool, canonical_arguments((query,)))
        except AgentThrashingError:
            return index
    return 0


# --------------------------------------------------------------------------
# The headline: soft-loop detection
# --------------------------------------------------------------------------


def test_a_soft_loop_is_halted_within_four_calls(breaker: CognitiveBreaker) -> None:
    """The deliverable: ~90%-overlap query churn trips almost immediately."""
    with pytest.raises(AgentThrashingError) as excinfo:
        for query in SOFT_LOOP_QUERIES:
            breaker.observe("agent", "search", canonical_arguments((query,)))

    error = excinfo.value
    assert error.detector == "near_duplicate"
    assert error.tier == "deterministic"
    assert error.observations == 4, "tripped on the fourth call, not the sixth"
    assert error.scope_id == "agent"
    assert "no semantic progress" in error.reason
    assert float(error.evidence["min_similarity"]) >= 0.70


def test_the_soft_loop_corpus_really_is_a_soft_loop() -> None:
    """Guards the fixture itself: these must be near-duplicates, and the
    progressing corpus must not be. If this fails, the test above proves
    nothing about soft loops."""

    def sim(a: str, b: str) -> float:
        return jaccard(shingles(f"search\x1f{a}"), shingles(f"search\x1f{b}"))

    thrashing = [sim(a, b) for a, b in itertools.pairwise(SOFT_LOOP_QUERIES)]
    progressing = [sim(a, b) for a, b in itertools.pairwise(PROGRESSING_QUERIES)]
    assert min(thrashing) > 0.70, "soft-loop corpus is not actually near-duplicate"
    assert max(progressing) < 0.70, "progressing corpus would be a false positive"
    # A real separation, not a threshold squeaked past.
    assert min(thrashing) > 3 * max(progressing)


def test_an_agent_making_real_progress_is_never_halted(breaker: CognitiveBreaker) -> None:
    assert drive(breaker, PROGRESSING_QUERIES) == 0
    assert not breaker.is_tripped("agent")


def test_identical_calls_trip_on_the_configured_repeat() -> None:
    breaker = CognitiveBreaker(observer=None, policy=CognitivePolicy(max_identical_repeats=3))
    with pytest.raises(AgentThrashingError) as excinfo:
        for _ in range(5):
            breaker.observe("agent", "read_file", canonical_arguments(("/etc/hosts",)))
    assert excinfo.value.detector == "exact_repeat"
    assert excinfo.value.observations == 3
    assert excinfo.value.confidence == 1.0


def test_an_alternating_two_tool_cycle_is_caught(breaker: CognitiveBreaker) -> None:
    """A→B→A→B has low pairwise similarity; only periodicity gives it away."""
    tripped_at = 0
    for index in range(1, 12):
        tool, argument = (
            ("read_file", "/notes.md") if index % 2 else ("search", "where are my notes")
        )
        try:
            breaker.observe("agent", tool, canonical_arguments((argument,)))
        except AgentThrashingError as error:
            assert error.detector == "call_cycle"
            assert error.evidence["period"] == "2"
            tripped_at = index
            break
    assert tripped_at == 6, "a period-2 cycle repeated 3 times trips on the sixth call"


def test_a_non_repeating_sequence_of_mixed_tools_is_left_alone(
    breaker: CognitiveBreaker,
) -> None:
    for index, tool in enumerate(["search", "read_file", "write", "test", "commit", "deploy"]):
        breaker.observe("agent", tool, canonical_arguments((f"target-{index}",)))
    assert not breaker.is_tripped("agent")


# --------------------------------------------------------------------------
# Not firing on legitimate work: the false-positive surface
# --------------------------------------------------------------------------


PAGE_CONTENT = [
    ["Introduction to Rust ownership", "Borrow checker fundamentals"],
    ["Deploying Kubernetes at scale", "Helm chart patterns in practice"],
    ["Postgres index selection", "Analysing slow query plans"],
    ["Designing idempotent webhooks", "Retry storms and jitter"],
    ["Colour theory for dashboards", "Perceptually uniform palettes"],
    ["Fermentation temperature curves", "Sourdough hydration ratios"],
    ["Orbital mechanics primer", "Hohmann transfer windows"],
    ["Medieval manuscript pigments", "Iron gall ink chemistry"],
]


def test_pagination_with_differing_results_is_progress_not_thrashing() -> None:
    """The discriminator: near-identical inputs, genuinely *different* outputs.

    Paginating a cursor is the single most likely false positive for any
    input-similarity heuristic. Feeding results back is what rescues it.
    """
    breaker = CognitiveBreaker(observer=None)
    for page, rows in enumerate(PAGE_CONTENT, start=1):
        breaker.observe("agent", "fetch", canonical_arguments((), {"page": page}))
        breaker.record_result("agent", {"rows": rows})
    assert not breaker.is_tripped("agent"), "pagination must not be mistaken for a loop"


def test_templated_results_defeat_the_discriminator_and_that_is_documented() -> None:
    """A known limitation, pinned by a test rather than left as a surprise.

    When a tool returns a *template* whose only variation is an index —
    ``record-1-0``, ``record-2-0`` — the results are near-identical in
    trigram space even though the agent is genuinely advancing. The
    discriminator cannot see through that, so this pattern trips. The
    documented escape hatch is ``exempt_tools``; this test asserts both the
    limitation and the remedy so neither can regress silently.
    """
    naive = CognitiveBreaker(observer=None)
    with pytest.raises(AgentThrashingError):
        for page in range(1, 9):
            naive.observe("agent", "fetch", canonical_arguments((), {"page": page}))
            naive.record_result("agent", {"rows": [f"record-{page}-{i}" for i in range(20)]})

    exempted = CognitiveBreaker(
        observer=None, policy=CognitivePolicy(exempt_tools=frozenset({"fetch"}))
    )
    for page in range(1, 9):
        exempted.observe("agent", "fetch", canonical_arguments((), {"page": page}))
        exempted.record_result("agent", {"rows": [f"record-{page}-{i}" for i in range(20)]})
    assert not exempted.is_tripped("agent")


def test_pagination_returning_the_same_page_forever_is_thrashing() -> None:
    """The mirror image: same-ish input *and* same output is a real loop —
    an agent paging against a broken cursor that never advances."""
    breaker = CognitiveBreaker(observer=None)
    with pytest.raises(AgentThrashingError) as excinfo:
        for page in range(1, 9):
            breaker.observe("agent", "fetch", canonical_arguments((), {"page": page}))
            breaker.record_result("agent", {"rows": ["always", "the", "same", "page"]})
    assert excinfo.value.detector == "near_duplicate"


def test_exempt_tools_are_never_judged() -> None:
    """The escape hatch for legitimately repetitive calls."""
    breaker = CognitiveBreaker(
        observer=None, policy=CognitivePolicy(exempt_tools=frozenset({"poll_status"}))
    )
    for _ in range(50):
        breaker.observe("agent", "poll_status", canonical_arguments(("job-1",)))
    assert not breaker.is_tripped("agent")
    assert breaker.history("agent") == (), "exempt calls are not even recorded"


def test_raising_the_threshold_tolerates_a_tighter_loop() -> None:
    tolerant = CognitiveBreaker(observer=None, policy=CognitivePolicy(similarity_threshold=0.99))
    assert drive(tolerant, SOFT_LOOP_QUERIES) == 0


# --------------------------------------------------------------------------
# Latching
# --------------------------------------------------------------------------


def test_the_latch_survives_a_retry_storm(breaker: CognitiveBreaker) -> None:
    """An agent that ignores the halt and hammers on cannot wear it down."""
    drive(breaker, SOFT_LOOP_QUERIES)
    assert breaker.is_tripped("agent")

    for _ in range(500):
        with pytest.raises(AgentThrashingError):
            breaker.observe("agent", "search", canonical_arguments(("something else entirely",)))
    assert breaker.is_tripped("agent")


def test_reset_clears_the_latch_and_the_history(breaker: CognitiveBreaker) -> None:
    drive(breaker, SOFT_LOOP_QUERIES)
    assert breaker.is_tripped("agent")

    breaker.reset("agent")

    assert not breaker.is_tripped("agent")
    assert breaker.history("agent") == ()
    breaker.observe("agent", "search", canonical_arguments((SOFT_LOOP_QUERIES[0],)))


def test_the_verdict_is_retrievable_after_a_trip(breaker: CognitiveBreaker) -> None:
    drive(breaker, SOFT_LOOP_QUERIES)
    verdict = breaker.verdict("agent")
    assert verdict is not None
    assert verdict.detector == "near_duplicate"
    assert 0.0 <= verdict.confidence <= 1.0


def test_the_exception_alias_is_the_same_class() -> None:
    assert AgentThrashingException is AgentThrashingError
    assert issubclass(AgentThrashingError, CircuitBreakerError)


# --------------------------------------------------------------------------
# Trajectories
# --------------------------------------------------------------------------


def test_separate_scopes_are_separate_trajectories_by_default(
    breaker: CognitiveBreaker,
) -> None:
    for query in SOFT_LOOP_QUERIES[:3]:
        breaker.observe("agent-a", "search", canonical_arguments((query,)))
        breaker.observe("agent-b", "search", canonical_arguments((query,)))
    assert not breaker.is_tripped("agent-a")
    assert not breaker.is_tripped("agent-b")
    assert len(breaker.history("agent-a")) == 3


def test_a_shared_trajectory_spans_scopes(breaker: CognitiveBreaker) -> None:
    """An orchestrator retrying via fresh sub-agents is *one* trajectory.

    Without this, spawning a replacement worker hands the same degenerate
    task a clean slate, and the loop simply continues under a new name.
    """
    with pytest.raises(AgentThrashingError) as excinfo:
        for index, query in enumerate(SOFT_LOOP_QUERIES):
            breaker.observe(
                f"worker-{index}", "search", canonical_arguments((query,)), trajectory="task-7"
            )

    assert excinfo.value.trajectory == "task-7"
    assert excinfo.value.scope_id == "worker-3", "halts the scope that made the call"
    assert breaker.is_tripped("task-7")


def test_history_is_bounded_per_trajectory() -> None:
    breaker = CognitiveBreaker(observer=None, policy=CognitivePolicy(history_limit=8))
    for index in range(50):
        breaker.observe("agent", "search", canonical_arguments((unrelated(index),)))
    assert len(breaker.history("agent")) == 8


def test_trajectories_are_evicted_least_recently_used() -> None:
    """Bounded memory in a long-lived process."""
    breaker = CognitiveBreaker(observer=None, policy=CognitivePolicy(max_trajectories=4))
    for index in range(10):
        breaker.observe("agent", "search", canonical_arguments(("q",)), trajectory=f"t{index}")
    assert breaker.history("t0") == (), "the oldest trajectory was evicted"
    assert len(breaker.history("t9")) == 1


# --------------------------------------------------------------------------
# Tier 2: the asynchronous semantic lane
# --------------------------------------------------------------------------


def wait_for(predicate: object, timeout: float = 5.0) -> bool:
    """Poll ``predicate`` until true or the timeout expires."""
    assert callable(predicate)
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return False


def test_the_semantic_lane_catches_stagnation_the_inline_tier_misses() -> None:
    """Recombining one vocabulary forever: low pairwise similarity, zero novelty.

    The inline detectors are disabled entirely here, so only the off-thread
    observer can produce this verdict.
    """
    breaker = CognitiveBreaker(
        detectors=[],
        observer=TrajectoryEntropyObserver(window=6, min_novelty_ratio=0.05),
    )
    vocabulary = ["alpha", "beta", "gamma", "delta"]
    tripped: AgentThrashingError | None = None
    try:
        for index in range(1, 60):
            phrase = " ".join(vocabulary[(index + offset) % 4] for offset in range(4))
            try:
                breaker.observe("agent", "think", canonical_arguments((phrase,)))
            except AgentThrashingError as error:
                tripped = error
                break
            time.sleep(0.002)  # let the single worker keep pace
    finally:
        breaker.close()

    assert tripped is not None, "the semantic observer never reached a verdict"
    assert tripped.tier == "semantic"
    assert tripped.detector == "trajectory_entropy"
    assert "stagnation" in tripped.reason


def test_the_semantic_lane_never_blocks_the_caller() -> None:
    """A deliberately glacial observer must not slow the agent down at all."""

    class GlacialObserver:
        @property
        def name(self) -> str:
            return "glacial"

        def evaluate(self, trajectory: str, window: Sequence[ToolCall]) -> Verdict | None:
            time.sleep(0.5)  # 500ms per evaluation, on the worker thread
            return None

        def reset(self, trajectory: str) -> None:
            return None

    breaker = CognitiveBreaker(detectors=[], observer=GlacialObserver())
    try:
        started = time.perf_counter()
        for index in range(20):
            breaker.observe("agent", "tool", canonical_arguments((unrelated(index),)))
        elapsed = time.perf_counter() - started
    finally:
        breaker.close()

    # 20 calls x 500ms = 10s if this were inline. It is not.
    assert elapsed < 0.5, f"observations blocked on the semantic lane ({elapsed:.3f}s)"


def test_a_saturated_semantic_queue_drops_work_instead_of_blocking() -> None:
    """Backpressure must never reach the agent — coverage degrades, not speed."""

    class BlockedObserver:
        def __init__(self) -> None:
            self.release = threading.Event()

        @property
        def name(self) -> str:
            return "blocked"

        def evaluate(self, trajectory: str, window: Sequence[ToolCall]) -> Verdict | None:
            self.release.wait(timeout=10.0)
            return None

        def reset(self, trajectory: str) -> None:
            return None

    observer = BlockedObserver()
    breaker = CognitiveBreaker(
        detectors=[], observer=observer, policy=CognitivePolicy(async_queue_size=4)
    )
    try:
        started = time.perf_counter()
        for index in range(200):
            breaker.observe("agent", "tool", canonical_arguments((unrelated(index),)))
        elapsed = time.perf_counter() - started
        stats = breaker.stats
    finally:
        observer.release.set()
        breaker.close()

    assert elapsed < 1.0, "a saturated queue blocked the agent"
    assert stats.observed == 200
    assert stats.dropped > 0, "the queue should have shed load once full"


def test_a_raising_observer_degrades_detection_without_breaking_the_agent() -> None:
    class BrokenObserver:
        def __init__(self) -> None:
            self.calls = 0

        @property
        def name(self) -> str:
            return "broken"

        def evaluate(self, trajectory: str, window: Sequence[ToolCall]) -> Verdict | None:
            self.calls += 1
            raise RuntimeError("observer is broken")

        def reset(self, trajectory: str) -> None:
            return None

    observer = BrokenObserver()
    breaker = CognitiveBreaker(detectors=[], observer=observer)
    try:
        for index in range(10):
            breaker.observe("agent", "tool", canonical_arguments((unrelated(index),)))
        assert wait_for(lambda: observer.calls > 0)
        # The agent kept running; only semantic coverage was lost.
        breaker.observe("agent", "tool", canonical_arguments(("final",)))
    finally:
        breaker.close()
    assert not breaker.is_tripped("agent")


def test_disabling_the_semantic_lane_starts_no_thread() -> None:
    before = threading.active_count()
    breaker = CognitiveBreaker(observer=None)
    assert not breaker.semantic_enabled
    assert threading.active_count() == before
    breaker.close()  # must be a safe no-op


def test_the_breaker_is_a_context_manager() -> None:
    with CognitiveBreaker() as breaker:
        assert breaker.semantic_enabled
        breaker.observe("agent", "tool", canonical_arguments(("x",)))
    breaker.close()  # idempotent


# --------------------------------------------------------------------------
# Extensibility
# --------------------------------------------------------------------------


def test_a_custom_detector_can_be_plugged_in() -> None:
    """The enterprise extension point: a detector that knows your schema."""

    class ForbidSelfQuery:
        @property
        def name(self) -> str:
            return "forbid_self_query"

        def observe(self, call: ToolCall, history: Sequence[ToolCall]) -> Verdict | None:
            if "self" not in call.arguments:
                return None
            return Verdict(
                detector=self.name,
                reason="the agent is querying itself",
                confidence=1.0,
                observations=len(history) + 1,
            )

    # A detector that reads argument *text* needs retention opted in; the
    # built-in detectors read fingerprints and shingles and do not.
    breaker = CognitiveBreaker(
        observer=None,
        detectors=[ForbidSelfQuery()],
        policy=CognitivePolicy(retain_arguments=True),
    )
    breaker.observe("agent", "search", canonical_arguments(("something normal",)))
    with pytest.raises(AgentThrashingError) as excinfo:
        breaker.observe("agent", "search", canonical_arguments(("ask self",)))
    assert excinfo.value.detector == "forbid_self_query"


def test_a_raising_detector_is_skipped_not_fatal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One bad custom heuristic degrades detection; it does not break calls."""

    class BrokenDetector:
        @property
        def name(self) -> str:
            return "broken"

        def observe(self, call: ToolCall, history: Sequence[ToolCall]) -> Verdict | None:
            raise ValueError("detector is broken")

    breaker = CognitiveBreaker(
        observer=None,
        detectors=[BrokenDetector(), ExactRepeatDetector(max_repeats=3)],
    )
    with caplog.at_level(logging.ERROR, logger="agentgov.cognitive"):
        # The healthy detector behind the broken one still does its job.
        with pytest.raises(AgentThrashingError) as excinfo:
            for _ in range(4):
                breaker.observe("agent", "read", canonical_arguments(("some/path",)))
    assert excinfo.value.detector == "exact_repeat"
    assert "broken" in caplog.text


def test_detectors_are_exposed_and_defaulted_from_policy() -> None:
    breaker = CognitiveBreaker(observer=None, policy=CognitivePolicy(similarity_threshold=0.5))
    names = [detector.name for detector in breaker.detectors]
    assert names == ["exact_repeat", "near_duplicate", "call_cycle"]
    near = breaker.detectors[1]
    assert isinstance(near, NearDuplicateDetector)
    assert near.threshold == 0.5


def test_detectors_are_individually_disengageable() -> None:
    detector = CallCycleDetector(max_period=1)  # below the period-2 minimum
    assert detector.observe(_call("a"), []) is None
    assert ExactRepeatDetector(max_repeats=0).observe(_call("a"), []) is None
    assert NearDuplicateDetector(max_streak=0).observe(_call("a"), []) is None


def _call(text: str) -> ToolCall:
    """Build a bare ToolCall for detector-level unit tests."""
    from datetime import UTC, datetime

    return ToolCall(
        sequence=1,
        scope_id="agent",
        tool="tool",
        arguments=text,
        fingerprint=text,
        shingles=shingles(text),
        timestamp=datetime.now(UTC),
    )


# --------------------------------------------------------------------------
# Integration with the financial governor
# --------------------------------------------------------------------------


def test_a_cognitive_trip_latches_the_financial_breaker() -> None:
    """One actuator, two sensors: the halt lands in the financial audit trail."""
    gov = BudgetManager()
    gov.open_root("root", money("5.00"))
    gov.delegate("root", "worker", money("1.00"))
    breaker = CognitiveBreaker(observer=None, manager=gov)

    with pytest.raises(AgentThrashingError):
        for query in SOFT_LOOP_QUERIES:
            breaker.observe("worker", "search", canonical_arguments((query,)))

    assert gov.is_halted("worker"), "the financial breaker latched too"
    assert not gov.is_halted("root"), "the halt is contained to the offending scope"
    (event,) = gov.control_events
    assert event.event_type == "circuit_tripped"
    assert "cognitive breaker [near_duplicate]" in event.reason
    # Anchored to the ledger, like every other governance event.
    assert event.ledger_head_hash == gov.ledger.head_hash
    gov.verify_integrity()


def test_a_cognitive_trip_halts_the_whole_subtree() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("5.00"))
    gov.delegate("root", "lead", money("2.00"))
    gov.delegate("lead", "worker", money("1.00"))
    breaker = CognitiveBreaker(observer=None, manager=gov)

    with pytest.raises(AgentThrashingError):
        for query in SOFT_LOOP_QUERIES:
            breaker.observe("lead", "search", canonical_arguments((query,)))

    assert gov.is_halted("worker"), "descendants inherit the halt"
    assert gov.halted_by("worker") == "lead"


def test_a_standalone_breaker_tolerates_unregistered_scopes() -> None:
    """Used without a manager — or ahead of funding — the halt still stands."""
    gov = BudgetManager()
    breaker = CognitiveBreaker(observer=None, manager=gov)
    with pytest.raises(AgentThrashingError):
        for query in SOFT_LOOP_QUERIES:
            breaker.observe("never-funded", "search", canonical_arguments((query,)))
    assert breaker.is_tripped("never-funded")


# --------------------------------------------------------------------------
# Integration with the Interceptor: halting before the money moves
# --------------------------------------------------------------------------


def test_the_interceptor_halts_a_thrashing_agent_for_a_fraction_of_the_budget() -> None:
    """The whole point: stop the loop at cents, not at the $5.00 envelope."""
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("5.00"))
    breaker = CognitiveBreaker(observer=None, manager=gov)
    llm = DummyLLM("claude-opus-5", output_tokens=400)
    metered = Interceptor(
        gov,
        "root",
        model="claude-opus-5",
        estimated_input_tokens=64,
        max_output_tokens=576,
        cognitive=breaker,
    )

    executed = 0
    with pytest.raises(AgentThrashingError):
        for query in SOFT_LOOP_QUERIES * 10:
            metered.invoke(llm.complete, query)
            executed += 1

    spent = money("5.00") - gov.available("root")
    assert executed == 3, "halted on the fourth call"
    assert llm.call_count == 3, "the tripping call never reached the model"
    assert spent < money("0.10"), f"halted at {spent}, nowhere near the $5.00 envelope"
    assert spent > ZERO
    gov.verify_integrity()


def test_the_tripping_call_costs_absolutely_nothing() -> None:
    """The check runs ahead of the hold, so a halt is not even a voided hold."""
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("5.00"))
    breaker = CognitiveBreaker(observer=None, manager=gov)
    llm = DummyLLM("claude-opus-5", output_tokens=100)
    metered = Interceptor(gov, "root", model="claude-opus-5", cognitive=breaker)

    for query in SOFT_LOOP_QUERIES[:3]:
        metered.invoke(llm.complete, query)
    entries_before = len(gov.audit_trail())
    balance_before = gov.available("root")

    with pytest.raises(AgentThrashingError):
        metered.invoke(llm.complete, SOFT_LOOP_QUERIES[3])

    assert len(gov.audit_trail()) == entries_before, "no ledger entry for a halted call"
    assert gov.available("root") == balance_before
    types = [e.entry_type for e in gov.audit_trail()]
    assert types.count(EntryType.HOLD) == 3, "no fourth hold was ever placed"


def test_after_a_cognitive_halt_further_calls_fail_on_the_financial_breaker() -> None:
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("5.00"))
    breaker = CognitiveBreaker(observer=None, manager=gov)
    llm = DummyLLM("claude-opus-5", output_tokens=100)
    metered = Interceptor(gov, "root", model="claude-opus-5", cognitive=breaker)

    with pytest.raises(AgentThrashingError):
        for query in SOFT_LOOP_QUERIES:
            metered.invoke(llm.complete, query)

    # A caller that resets only the cognitive latch still hits the financial one.
    breaker.reset("root")
    with pytest.raises(CircuitOpenError):
        metered.invoke(llm.complete, "a completely fresh and unrelated question")


def test_the_interceptor_feeds_results_back_to_the_breaker() -> None:
    """Without results the discriminator is blind; the wiring must be real."""
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("5.00"))
    breaker = CognitiveBreaker(observer=None, manager=gov)
    llm = DummyLLM("claude-opus-5", output_tokens=100)
    metered = Interceptor(gov, "root", model="claude-opus-5", cognitive=breaker)

    metered.invoke(llm.complete, "a question")

    (call,) = breaker.history("root")
    assert call.result_shingles is not None, "the result was never recorded"
    assert call.tool == "complete"


def test_an_interceptor_without_a_breaker_is_unaffected() -> None:
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("5.00"))
    llm = DummyLLM("claude-opus-5", output_tokens=100)
    metered = Interceptor(gov, "root", model="claude-opus-5")
    assert metered.cognitive is None
    for query in SOFT_LOOP_QUERIES:
        metered.invoke(llm.complete, query)
    assert llm.call_count == len(SOFT_LOOP_QUERIES)


def test_for_scope_and_with_trajectory_carry_the_breaker() -> None:
    gov = BudgetManager()
    gov.open_root("root", money("5.00"))
    gov.delegate("root", "worker", money("1.00"))
    breaker = CognitiveBreaker(observer=None, manager=gov)
    base = Interceptor(gov, "root", model="claude-opus-5", cognitive=breaker)

    child = base.for_scope("worker")
    assert child.cognitive is breaker
    assert child.trajectory == "worker"

    shared = child.with_trajectory("task-1")
    assert shared.cognitive is breaker
    assert shared.trajectory == "task-1"
    assert child.trajectory == "worker", "the original was not mutated"


# --------------------------------------------------------------------------
# Concurrency
# --------------------------------------------------------------------------


def test_concurrent_agents_share_one_breaker_without_corruption() -> None:
    breaker = CognitiveBreaker(observer=None)
    workers = 32
    per_worker = 40
    barrier = threading.Barrier(workers)

    def run(index: int) -> None:
        barrier.wait()
        for step in range(per_worker):
            breaker.observe(
                f"agent-{index}", "search", canonical_arguments((unrelated(f"{index}-{step}"),))
            )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(run, range(workers)))

    assert breaker.stats.observed == workers * per_worker
    assert breaker.stats.tripped == 0
    assert all(len(breaker.history(f"agent-{i}")) == per_worker for i in range(workers))


def test_cognitive_and_financial_locks_cannot_deadlock() -> None:
    """The ordering guarantee, exercised under real contention.

    Cognitive trips take the ledger's lock. If anything ever took them in the
    opposite order this would hang, so the test is the watchdog: it must
    finish well inside its timeout.
    """
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("500.00"))
    for index in range(8):
        gov.delegate("root", f"worker-{index}", money("10.00"))
    breaker = CognitiveBreaker(observer=None, manager=gov)
    barrier = threading.Barrier(16)

    def thrash(index: int) -> None:
        barrier.wait()
        for query in SOFT_LOOP_QUERIES * 4:
            try:
                breaker.observe(f"worker-{index}", "search", canonical_arguments((query,)))
            except AgentThrashingError:
                pass

    def spend(index: int) -> None:
        barrier.wait()
        for _ in range(40):
            with suppress(AgentGovError):
                # A halted or exhausted scope is a fine outcome here; a hang is not.
                gov.spend("root", money("0.01"))

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(thrash, i) for i in range(8)]
        futures += [pool.submit(spend, i) for i in range(8)]
        for future in futures:
            future.result(timeout=30)
    elapsed = time.perf_counter() - started

    assert elapsed < 30, "cognitive and financial locks deadlocked"
    assert all(gov.is_halted(f"worker-{i}") for i in range(8))
    gov.verify_integrity()


# --------------------------------------------------------------------------
# The zero-latency claim, measured
# --------------------------------------------------------------------------


def test_inline_observation_is_far_cheaper_than_any_model_call() -> None:
    """Bounds the inline path against pathologically large arguments.

    The threshold is loose on purpose — this is a regression guard against an
    accidentally unbounded similarity computation, not a CI-fragile SLA. A
    real model call is 500-2000ms; anything in the microseconds is noise.
    """
    never_trip = CognitivePolicy(
        max_identical_repeats=10**9, max_similar_streak=10**9, min_cycle_repeats=10**9
    )
    breaker = CognitiveBreaker(observer=None, policy=never_trip)
    oversized = "x" * 8192

    samples: list[float] = []
    for index in range(500):
        arguments = canonical_arguments((f"{oversized}{index}",))
        started = time.perf_counter()
        breaker.observe("agent", "tool", arguments)
        samples.append(time.perf_counter() - started)

    samples.sort()
    p99 = samples[int(len(samples) * 0.99)]
    assert p99 < 0.005, f"inline p99 of {p99 * 1000:.2f}ms is too slow for the hot path"


# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------


def test_canonical_arguments_is_order_insensitive_and_total() -> None:
    assert canonical_arguments((), {"b": 1, "a": 2}) == canonical_arguments((), {"a": 2, "b": 1})
    # An un-serialisable argument must never crash the governor.
    assert canonical_arguments((object(),)) != ""


def test_shingles_are_bounded_by_max_chars() -> None:
    assert len(shingles("x" * 100_000, size=3, max_chars=64)) <= 64
    assert shingles("ab", size=3) == frozenset({"ab"})


def test_jaccard_bounds_and_short_circuit() -> None:
    assert jaccard(frozenset(), frozenset()) == 1.0
    assert jaccard(frozenset({"a"}), frozenset()) == 0.0
    assert jaccard(frozenset({"a", "b"}), frozenset({"a", "b"})) == 1.0
    # The size-ratio bound returns 0.0 rather than computing an intersection
    # it already knows cannot clear the floor.
    assert jaccard(frozenset({"a"}), frozenset({"a", "b", "c", "d"}), floor=0.9) == 0.0


def test_stats_report_the_semantic_lane() -> None:
    breaker = CognitiveBreaker(policy=CognitivePolicy(entropy_window=3))
    try:
        for index in range(10):
            breaker.observe("agent", "tool", canonical_arguments((unrelated(index),)))
        assert wait_for(lambda: breaker.stats.evaluated > 0)
    finally:
        breaker.close()
    stats = breaker.stats
    assert stats.observed == 10
    assert stats.queued > 0
