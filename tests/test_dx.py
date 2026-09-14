"""Tests for Sprint 2: dynamic holds, streaming, the client proxy, and the CLI.

The theme is adoption. Each of these closed a reason an engineer would bounce:
a static hold that mis-sizes real payloads, no way to govern a stream, a
refactor at every call site, and no way to read a ledger without writing
Python.
"""

from __future__ import annotations

import asyncio
import io
import subprocess
import sys
import threading
from collections.abc import AsyncIterator, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from decimal import Decimal
from pathlib import Path

import pytest

from agentgov import BudgetManager, GovernancePolicy, Interceptor, govern, money
from agentgov.cli import main as cli_main
from agentgov.core import EntryType
from agentgov.dummy import DummyLLM
from agentgov.exceptions import DenialOfWalletError
from agentgov.interceptor import (
    TokenUsage,
    estimate_tokens,
    extract_prompt_text,
    pricing_for,
)

ZERO = Decimal("0")
NO_VELOCITY = GovernancePolicy(max_calls_per_window=0)


@pytest.fixture
def gov() -> BudgetManager:
    manager = BudgetManager(policy=NO_VELOCITY)
    manager.open_root("root", money("5.00"))
    return manager


class Event:
    """A stream event, optionally carrying usage like a real SDK's."""

    def __init__(self, usage: TokenUsage | None = None) -> None:
        self.usage = usage


def events(
    count: int = 4, *, final: TokenUsage | None = None, **_ignored: object
) -> Iterator[Event]:
    """A stream that discloses input up front and output at the end.

    Accepts and ignores arbitrary keyword arguments, the way a real SDK
    streaming entry point does.
    """
    yield Event(TokenUsage(input_tokens=1000))
    for _ in range(count - 2):
        yield Event()
    yield Event(final if final is not None else TokenUsage(input_tokens=1000, output_tokens=500))


# --------------------------------------------------------------------------
# Dynamic hold sizing
# --------------------------------------------------------------------------


def test_prompt_text_is_found_in_the_shapes_sdks_actually_use() -> None:
    assert "hello" in extract_prompt_text((), {"messages": [{"role": "u", "content": "hello"}]})
    assert "block" in extract_prompt_text(
        (), {"messages": [{"content": [{"type": "text", "text": "block"}]}]}
    )
    assert "sys" in extract_prompt_text((), {"system": "sys", "messages": []})
    assert "bare" in extract_prompt_text(("bare",), {})
    assert "legacy" in extract_prompt_text((), {"prompt": "legacy"})
    # An unrecognised shape yields nothing rather than a wrong guess.
    assert extract_prompt_text((), {"payload": object()}) == ""


def test_a_large_payload_reserves_a_proportional_hold(gov: BudgetManager) -> None:
    prompt = "word " * 30_000  # 150,000 characters
    dynamic = Interceptor(gov, "root", model="claude-opus-5")
    static = Interceptor(gov, "root", model="claude-opus-5", dynamic_holds=False)

    sized = dynamic.size_hold((prompt,), {})
    expected = pricing_for("claude-opus-5").cost_of(
        TokenUsage(input_tokens=estimate_tokens(prompt), output_tokens=4096)
    ) * Decimal("1.5")

    assert sized > static.size_hold((prompt,), {}) * 3
    assert abs(sized - expected) < money("0.00001"), "hold is not proportional to the payload"


def test_a_long_context_call_settles_without_a_false_overdraft(gov: BudgetManager) -> None:
    """The headline: a 150K-character prompt no longer overruns its own hold."""
    prompt = "word " * 30_000
    metered = Interceptor(gov, "root", model="claude-opus-5")
    llm = DummyLLM("claude-opus-5", output_tokens=4096)

    result = metered.invoke(llm.complete, prompt)

    assert result.hold > result.cost, "the hold must cover the settled cost"
    assert not gov.is_halted("root"), "a legitimate long call must not trip the breaker"
    assert gov.available("root") == money("5.00") - result.cost
    gov.verify_integrity()


def test_under_reserved_holds_would_breach_the_envelope_under_concurrency() -> None:
    """Why sizing matters beyond one call.

    A hold that under-reserves does not merely risk a false trip: it fails to
    encumber, so concurrent callers all pass the pre-flight check and settle
    for more than they reserved. Dynamic sizing is what keeps the envelope a
    bound rather than a suggestion.
    """
    prompt = "word " * 30_000
    advisory = GovernancePolicy(
        max_calls_per_window=0, trip_on_overdraft=False, trip_on_exhaustion=False
    )

    def spend_concurrently(*, dynamic: bool) -> Decimal:
        manager = BudgetManager(policy=advisory)
        manager.open_root("root", money("1.00"))
        metered = Interceptor(manager, "root", model="claude-opus-5", dynamic_holds=dynamic)
        llm = DummyLLM("claude-opus-5", output_tokens=4096, latency_seconds=0.02)
        barrier = threading.Barrier(10)

        def attempt(_: int) -> None:
            barrier.wait()
            with suppress(Exception):
                # A refusal or an overdraft is fine here; the total spend is
                # what this test is measuring.
                metered.invoke(llm.complete, prompt)

        with ThreadPoolExecutor(max_workers=10) as pool:
            list(pool.map(attempt, range(10)))
        return money("1.00") - manager.available("root")

    assert spend_concurrently(dynamic=False) > money("1.00"), "static holds should breach"
    assert spend_concurrently(dynamic=True) <= money("1.00"), "dynamic holds must bound it"


def test_the_call_s_own_max_tokens_is_used_for_the_output_bound(gov: BudgetManager) -> None:
    metered = Interceptor(gov, "root", model="claude-opus-5", max_output_tokens=8192)
    small = metered.size_hold((), {"messages": [{"content": "hi"}], "max_tokens": 64})
    large = metered.size_hold((), {"messages": [{"content": "hi"}], "max_tokens": 8192})
    assert small < large, "the caller's own max_tokens should size the output estimate"


def test_sizing_falls_back_to_the_static_ceiling(gov: BudgetManager) -> None:
    metered = Interceptor(gov, "root", model="claude-opus-5")
    assert metered.size_hold((), {"payload": object()}) == metered.hold_amount
    assert metered.size_hold((), {"messages": [{"content": "x"}]}) >= metered.hold_amount


def test_dynamic_sizing_can_be_switched_off_and_pinned(gov: BudgetManager) -> None:
    prompt = "word " * 30_000
    off = Interceptor(gov, "root", model="claude-opus-5", dynamic_holds=False)
    assert off.size_hold((prompt,), {}) == off.hold_amount
    pinned = Interceptor(gov, "root", model="claude-opus-5", hold=money("0.02"))
    assert pinned.size_hold((prompt,), {}) == money("0.02")


def test_the_safety_buffer_is_configurable_and_validated(gov: BudgetManager) -> None:
    prompt = "word " * 10_000
    lean = Interceptor(gov, "root", model="claude-opus-5", safety_buffer="1.0")
    padded = Interceptor(gov, "root", model="claude-opus-5", safety_buffer="3.0")
    assert padded.size_hold((prompt,), {}) > lean.size_hold((prompt,), {})
    with pytest.raises(ValueError, match=r"at least 1\.0"):
        Interceptor(gov, "root", model="claude-opus-5", safety_buffer="0.5")


# --------------------------------------------------------------------------
# Streaming
# --------------------------------------------------------------------------


def test_a_stream_settles_the_usage_it_observed(gov: BudgetManager) -> None:
    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(events, messages=[{"content": "stream this"}])

    with stream:
        consumed = list(stream)

    assert len(consumed) == 4
    assert stream.usage == TokenUsage(input_tokens=1000, output_tokens=500)
    assert stream.cost == pricing_for("claude-opus-5").cost_of(stream.usage)
    assert stream.resolved
    assert gov.available("root") == money("5.00") - stream.cost
    assert gov._open_auths == {}, "the hold was resolved"
    gov.verify_integrity()


def test_breaking_out_of_a_stream_resolves_the_hold(gov: BudgetManager) -> None:
    """Abandonment must never strand funds."""
    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(events, messages=[{"content": "stream this"}])

    with stream:
        for _ in stream:
            break

    assert stream.resolved
    assert gov._open_auths == {}, "an abandoned stream left its hold open"
    # Settled at what was actually observed, not voided: those tokens were
    # generated and billed, and a spend governor must not under-report.
    assert stream.cost == pricing_for("claude-opus-5").cost_of(TokenUsage(input_tokens=1000))
    gov.verify_integrity()


def test_an_exception_mid_stream_resolves_the_hold(gov: BudgetManager) -> None:
    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(events, messages=[{"content": "stream this"}])

    with pytest.raises(RuntimeError, match="caller blew up"), stream:
        for _ in stream:
            raise RuntimeError("caller blew up")

    assert stream.resolved
    assert gov._open_auths == {}
    gov.verify_integrity()


def test_a_stream_that_never_yields_usage_is_voided(gov: BudgetManager) -> None:
    """Nothing observed means nothing billed: release, do not charge."""

    def silent() -> Iterator[Event]:
        yield from (Event(), Event())

    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(silent)
    with stream:
        list(stream)

    assert stream.cost == ZERO
    assert gov.available("root") == money("5.00"), "a free stream cost nothing"
    types = [e.entry_type for e in gov.audit_trail("root")]
    assert EntryType.SPEND not in types
    assert types[-1] is EntryType.HOLD_VOID
    gov.verify_integrity()


def test_a_provider_that_fails_to_open_releases_the_hold(gov: BudgetManager) -> None:
    def refuses() -> Iterator[Event]:
        raise ConnectionError("provider unreachable")

    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(refuses)
    with pytest.raises(ConnectionError), stream:
        pass  # pragma: no cover - __enter__ raises

    assert gov.available("root") == money("5.00")
    assert gov._open_auths == {}
    gov.verify_integrity()


def test_a_stream_wraps_a_context_manager_style_sdk(gov: BudgetManager) -> None:
    """Anthropic's `.stream()` hands back a context manager, not an iterator."""

    class SdkStream:
        def __init__(self) -> None:
            self.closed = False

        def __enter__(self) -> Iterator[Event]:
            return events()

        def __exit__(self, *exc: object) -> None:
            self.closed = True

        def get_final_message(self) -> Event:
            return Event(TokenUsage(input_tokens=1000, output_tokens=900))

    sdk = SdkStream()
    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(lambda: sdk)
    with stream:
        list(stream)

    assert sdk.closed, "the SDK's own context manager was not exited"
    # get_final_message() is authoritative and outranks the event fragments.
    assert stream.usage.output_tokens == 900
    gov.verify_integrity()


def test_a_stream_is_resolved_only_once(gov: BudgetManager) -> None:
    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(events, messages=[{"content": "x"}])
    with stream:
        list(stream)  # settles on exhaustion
    before = len(gov.audit_trail())
    stream.close()  # and again on exit, and explicitly here
    assert len(gov.audit_trail()) == before, "the hold was settled more than once"


def test_streams_size_their_hold_from_the_payload(gov: BudgetManager) -> None:
    """A stream's hold is payload-derived too, not the static ceiling."""
    metered = Interceptor(gov, "root", model="claude-opus-5")
    tiny = metered.stream(events, messages=[{"content": "hi"}])
    huge = metered.stream(events, messages=[{"content": "word " * 20_000}])

    with tiny:
        tiny_hold = next(iter(gov._open_auths.values())).amount
    with huge:
        huge_hold = next(iter(gov._open_auths.values())).amount

    # Both clear the static floor; the large prompt reserves proportionally
    # more because its input estimate, not just the output ceiling, counts.
    assert tiny_hold >= metered.hold_amount
    assert huge_hold > tiny_hold * 2, "a big streamed prompt must reserve more"


def test_a_stream_must_be_entered_before_iterating(gov: BudgetManager) -> None:
    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(events)
    with pytest.raises(RuntimeError, match="must be entered"):
        next(iter(stream))


def test_async_streams_follow_the_same_lifecycle(gov: BudgetManager) -> None:
    async def aevents() -> AsyncIterator[Event]:
        yield Event(TokenUsage(input_tokens=1000))
        yield Event()
        yield Event(TokenUsage(input_tokens=1000, output_tokens=500))

    async def clean() -> Decimal | None:
        metered = Interceptor(gov, "root", model="claude-opus-5")
        stream = metered.astream(aevents)
        async with stream:
            async for _ in stream:
                pass
        return stream.cost

    async def abandoned() -> tuple[Decimal | None, int]:
        metered = Interceptor(gov, "root", model="claude-opus-5")
        stream = metered.astream(aevents)
        async with stream:
            async for _ in stream:
                break
        return stream.cost, len(gov._open_auths)

    settled = asyncio.run(clean())
    assert settled == pricing_for("claude-opus-5").cost_of(
        TokenUsage(input_tokens=1000, output_tokens=500)
    )
    partial, open_holds = asyncio.run(abandoned())
    assert partial is not None and partial > ZERO
    assert open_holds == 0, "an abandoned async stream left its hold open"
    gov.verify_integrity()


def test_a_stream_is_refused_when_the_budget_cannot_cover_it() -> None:
    manager = BudgetManager(policy=NO_VELOCITY)
    manager.open_root("root", money("0.000001"))
    metered = Interceptor(manager, "root", model="claude-opus-5")
    opened = False

    def tracked() -> Iterator[Event]:
        nonlocal opened
        opened = True
        yield Event()  # pragma: no cover - never reached

    with pytest.raises(DenialOfWalletError), metered.stream(tracked):
        pass  # pragma: no cover
    assert not opened, "the provider was called despite an unaffordable hold"


# --------------------------------------------------------------------------
# The client proxy
# --------------------------------------------------------------------------


class FakeMessages:
    def __init__(self) -> None:
        self.llm = DummyLLM("claude-opus-5", output_tokens=300)
        self.closed = False

    def create(self, **kwargs: object) -> object:
        messages = kwargs["messages"]
        assert isinstance(messages, list)
        return self.llm.complete(str(messages[0]["content"]))

    def stream(self, **kwargs: object) -> Iterator[Event]:
        return events()

    def close(self) -> None:
        self.closed = True


class FakeClient:
    def __init__(self) -> None:
        self.messages = FakeMessages()
        self.api_key = "sk-not-a-real-key"
        self.timeouts = {"read": 30}


def test_the_proxy_returns_what_the_sdk_returns(gov: BudgetManager) -> None:
    """The drop-in property: existing call sites keep compiling and working."""
    client = govern(FakeClient(), gov, "root", model="claude-opus-5")

    response = client.messages.create(
        model="claude-opus-5", messages=[{"role": "user", "content": "hello world"}]
    )

    assert type(response).__name__ == "DummyResponse", "the proxy changed the return type"
    assert response.text
    last = client.agentgov.last_call
    assert last is not None and last.cost > ZERO
    assert gov.available("root") == money("5.00") - last.cost
    gov.verify_integrity()


def test_the_proxy_leaves_everything_that_is_not_a_model_call_alone(
    gov: BudgetManager,
) -> None:
    raw = FakeClient()
    client = govern(raw, gov, "root", model="claude-opus-5")

    assert client.api_key == "sk-not-a-real-key"
    assert client.timeouts == {"read": 30}
    client.messages.close()
    assert raw.messages.closed, "a non-model method was not forwarded"
    assert len(gov.audit_trail()) == 1, "a passthrough attribute charged the ledger"


def test_the_proxy_governs_streams(gov: BudgetManager) -> None:
    client = govern(FakeClient(), gov, "root", model="claude-opus-5")

    with client.messages.stream(
        model="claude-opus-5", messages=[{"role": "user", "content": "stream"}]
    ) as stream:
        chunks = list(stream)

    assert len(chunks) == 4
    assert stream.cost is not None and stream.cost > ZERO
    gov.verify_integrity()


def test_create_with_stream_true_is_treated_as_a_stream(gov: BudgetManager) -> None:
    class StreamingCreate:
        def create(self, **kwargs: object) -> Iterator[Event]:
            return events()

    class Client:
        def __init__(self) -> None:
            self.messages = StreamingCreate()

    client = govern(Client(), gov, "root", model="claude-opus-5")
    with client.messages.create(model="m", messages=[{"content": "x"}], stream=True) as stream:
        list(stream)
    assert stream.cost is not None and stream.cost > ZERO


def test_the_primitive_stays_reachable_and_untouched(gov: BudgetManager) -> None:
    """`invoke()` is the contract; the proxy is sugar over it."""
    client = govern(FakeClient(), gov, "root", model="claude-opus-5")
    interceptor = client.agentgov.interceptor

    assert isinstance(interceptor, Interceptor)
    assert client.agentgov.manager is gov
    assert client.agentgov.scope_id == "root"
    assert isinstance(client.agentgov.raw, FakeClient)

    result = interceptor.invoke(DummyLLM("claude-opus-5", output_tokens=10).complete, "direct")
    assert result.cost > ZERO, "the underlying primitive still works"


def test_the_proxy_can_be_rebound_to_a_sub_agent_scope(gov: BudgetManager) -> None:
    gov.delegate("root", "worker", money("1.00"))
    client = govern(FakeClient(), gov, "root", model="claude-opus-5")

    sub = client.agentgov.for_scope("worker")
    sub.messages.create(model="claude-opus-5", messages=[{"role": "u", "content": "sub"}])

    assert gov.available("worker") < money("1.00")
    assert gov.available("root") == money("4.00"), "the parent was not charged"


def test_the_proxy_is_reprable(gov: BudgetManager) -> None:
    client = govern(FakeClient(), gov, "root", model="claude-opus-5")
    assert "governed" in repr(client) and "root" in repr(client)


# --------------------------------------------------------------------------
# The CLI
# --------------------------------------------------------------------------


@pytest.fixture
def ledger_path(tmp_path: Path) -> str:
    path = str(tmp_path / "governor.db")
    manager = BudgetManager.open_sqlite(path, policy=NO_VELOCITY)
    manager.open_root("orchestrator", money("5.00"))
    manager.delegate("orchestrator", "researcher", money("2.00"))
    manager.delegate("researcher", "scraper", money("0.50"))
    manager.spend("researcher", money("0.25"))
    manager.trip("scraper", "operator halt for review")
    manager.close()
    return path


def run_cli(*argv: str) -> tuple[int, str]:
    out = io.StringIO()
    code = cli_main(list(argv), out=out)
    return code, out.getvalue()


def test_inspect_prints_the_tree_totals_and_entries(ledger_path: str) -> None:
    code, output = run_cli("inspect", ledger_path)

    assert code == 0
    assert "orchestrator" in output
    assert "`- researcher" in output, "the balance tree is not nested"
    assert "HALTED by scraper" in output
    assert "operator halt for review" in output
    assert "settled spend" in output
    assert "$0.25000000" in output


def test_inspect_honours_limit_and_raw(ledger_path: str) -> None:
    _, capped = run_cli("inspect", ledger_path, "--limit", "2")
    assert "last 2 of" in capped

    _, raw = run_cli("inspect", ledger_path, "--raw", "--limit", "1")
    assert "AGOV1|seq=" in raw


def test_inspect_handles_an_empty_ledger(tmp_path: Path) -> None:
    path = str(tmp_path / "empty.db")
    BudgetManager.open_sqlite(path).close()
    code, output = run_cli("inspect", path)
    assert code == 0
    assert "(no scopes)" in output


def test_verify_passes_on_an_intact_ledger(ledger_path: str) -> None:
    code, output = run_cli("verify", ledger_path)
    assert code == 0
    assert "PASS" in output
    assert output.count("ok  ") == 3


def test_verify_fails_with_a_nonzero_exit_on_a_tampered_ledger(ledger_path: str) -> None:
    """The property a pipeline depends on: FAIL is exit code 1."""
    import sqlite3

    connection = sqlite3.connect(ledger_path)
    with connection:
        connection.execute("UPDATE entries SET amount = '999.00000000' WHERE sequence = 2")
    connection.close()

    code, output = run_cli("verify", ledger_path)

    assert code == 1, "a tampered ledger must fail the pipeline"
    assert "FAIL" in output
    assert "tampered with" in output


def test_verify_fails_cleanly_on_a_missing_file(tmp_path: Path) -> None:
    code, output = run_cli("verify", str(tmp_path / "nope.db"))
    assert code == 1
    assert "FAIL" in output


def test_the_cli_reads_a_ledger_a_live_governor_is_holding(ledger_path: str) -> None:
    """Read-only access is what makes the CLI usable in production."""
    live = BudgetManager.open_sqlite(ledger_path, policy=NO_VELOCITY)
    try:
        code, output = run_cli("verify", ledger_path)
        assert code == 0, output
        code, _ = run_cli("inspect", ledger_path)
        assert code == 0
    finally:
        live.close()


def test_the_console_script_is_installed(ledger_path: str) -> None:
    """The entry point in pyproject actually resolves to a runnable command."""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "agentgov.cli", "verify", ledger_path],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


# --------------------------------------------------------------------------
# Streaming: the remaining shapes and integrations
# --------------------------------------------------------------------------


def test_an_async_stream_wraps_an_async_context_manager_sdk(gov: BudgetManager) -> None:
    """The async Anthropic shape: an awaitable returning an async CM."""

    class AsyncSdkStream:
        def __init__(self) -> None:
            self.closed = False

        async def __aenter__(self) -> AsyncIterator[Event]:
            async def gen() -> AsyncIterator[Event]:
                yield Event(TokenUsage(input_tokens=700))
                yield Event(TokenUsage(input_tokens=700, output_tokens=250))

            return gen()

        async def __aexit__(self, *exc: object) -> None:
            self.closed = True

    sdk = AsyncSdkStream()

    async def opener() -> AsyncSdkStream:
        return sdk

    async def run() -> tuple[Decimal | None, int]:
        metered = Interceptor(gov, "root", model="claude-opus-5")
        stream = metered.astream(opener)
        async with stream:
            async for _ in stream:
                pass
        return stream.cost, stream.chunks

    cost, chunks = asyncio.run(run())
    assert sdk.closed, "the SDK's async context manager was not exited"
    assert chunks == 2
    assert cost == pricing_for("claude-opus-5").cost_of(
        TokenUsage(input_tokens=700, output_tokens=250)
    )
    gov.verify_integrity()


def test_an_async_stream_must_be_entered_and_can_be_closed(gov: BudgetManager) -> None:
    async def run() -> None:
        metered = Interceptor(gov, "root", model="claude-opus-5")
        stream = metered.astream(events)
        with pytest.raises(RuntimeError, match="must be entered"):
            await stream.__anext__()
        await stream.aclose()  # a no-op before entry; must not raise

    asyncio.run(run())


def test_usage_can_be_recorded_manually(gov: BudgetManager) -> None:
    """For SDKs that hide usage where the per-event extractor cannot see it."""

    def opaque(**_ignored: object) -> Iterator[Event]:
        yield from (Event(), Event())

    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(opaque)
    with stream:
        for _ in stream:
            pass
        stream.record_usage(TokenUsage(input_tokens=4000, output_tokens=1000))

    assert stream.usage == TokenUsage(input_tokens=4000, output_tokens=1000)
    assert stream.cost == pricing_for("claude-opus-5").cost_of(stream.usage)
    assert stream.entry is not None and stream.entry.entry_type is EntryType.SPEND


def test_a_thrashing_agent_is_halted_before_the_stream_opens(gov: BudgetManager) -> None:
    """The cognitive breaker guards streams too, ahead of the hold."""
    from agentgov.cognitive import CognitiveBreaker, CognitivePolicy
    from agentgov.exceptions import AgentThrashingError

    breaker = CognitiveBreaker(
        observer=None, manager=gov, policy=CognitivePolicy(max_identical_repeats=2)
    )
    metered = Interceptor(gov, "root", model="claude-opus-5", cognitive=breaker)
    opened = 0

    def counted(**_ignored: object) -> Iterator[Event]:
        nonlocal opened
        opened += 1
        yield Event(TokenUsage(input_tokens=10, output_tokens=10))

    with metered.stream(counted, messages=[{"content": "same"}]) as first:
        list(first)
    with (
        pytest.raises(AgentThrashingError),
        metered.stream(counted, messages=[{"content": "same"}]),
    ):
        pass  # pragma: no cover - __enter__ raises

    assert opened == 1, "the provider was reached after the breaker tripped"
    assert gov.is_halted("root")


def test_a_dropped_stream_warns_and_is_reclaimable(
    gov: BudgetManager, caplog: pytest.LogCaptureFixture
) -> None:
    """Entered but never exited: warn, and leave it for void_stale()."""
    import gc
    from datetime import timedelta

    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(events, messages=[{"content": "x"}])
    stream.__enter__()
    assert len(gov._open_auths) == 1

    with caplog.at_level("WARNING", logger="agentgov.streaming"):
        del stream
        gc.collect()

    assert "void_stale" in caplog.text
    # The operator remedy from Sprint 1 reclaims it.
    assert gov.void_stale(timedelta(seconds=-1))
    assert gov.available("root") == money("5.00")
    gov.verify_integrity()


def test_a_final_message_accessor_that_raises_is_tolerated(gov: BudgetManager) -> None:
    class Hostile:
        def __enter__(self) -> Iterator[Event]:
            return events()

        def __exit__(self, *exc: object) -> None:
            return None

        def get_final_message(self) -> Event:
            raise RuntimeError("no final message on this stream")

    metered = Interceptor(gov, "root", model="claude-opus-5")
    stream = metered.stream(Hostile)
    with stream:
        list(stream)
    # Falls back to the usage reconstructed from the events themselves.
    assert stream.usage == TokenUsage(input_tokens=1000, output_tokens=500)
