"""Tests for Sprint 1 hardening: process locking, memory bounds, redaction.

Three properties, each of which was a real defect before this sprint:

- a second process opening a governed database is refused *at open*, with an
  error that names the holder and does not masquerade as ledger corruption;
- nothing the breaker touches grows without bound, and an un-closed breaker
  does not strand a thread;
- prompt text is not retained by default, and a redactor gets first refusal
  on everything before it is fingerprinted or stored.
"""

from __future__ import annotations

import gc
import logging
import os
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentgov.cognitive import (
    CognitiveBreaker,
    CognitivePolicy,
    ToolCall,
    TrajectoryEntropyObserver,
    Verdict,
    canonical_arguments,
    jaccard,
    shingles,
)
from agentgov.core import BudgetManager, EntryType, GovernancePolicy, money
from agentgov.exceptions import (
    ConcurrentGovernorError,
    DoubleSpendError,
    LedgerError,
    ReadOnlyLedgerError,
    StorageError,
)
from agentgov.storage import SqliteStore


@pytest.fixture
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "governor.db")


def unrelated(seed: object) -> str:
    """Text with no meaningful trigram overlap with any other such text."""
    return f"{seed}-{uuid.uuid4().hex}{uuid.uuid4().hex}"


# --------------------------------------------------------------------------
# Gap 1 - the advisory lock
# --------------------------------------------------------------------------


def test_a_second_governor_in_this_process_is_refused(db_path: str) -> None:
    first = BudgetManager.open_sqlite(db_path)
    try:
        with pytest.raises(ConcurrentGovernorError) as excinfo:
            BudgetManager.open_sqlite(db_path)
        assert excinfo.value.holder_pid == os.getpid()
        assert "read_only=True" in str(excinfo.value)
    finally:
        first.close()


def test_a_second_governor_in_another_process_is_refused(db_path: str) -> None:
    """The case that matters: two workers, one database file."""
    holder = BudgetManager.open_sqlite(db_path)
    holder.open_root("root", money("1.00"))
    try:
        result = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-c",
                "import sys;from agentgov import BudgetManager;"
                "from agentgov.exceptions import ConcurrentGovernorError\n"
                "try:\n"
                "    BudgetManager.open_sqlite(sys.argv[1])\n"
                "    print('OPENED')\n"
                "except ConcurrentGovernorError as e:\n"
                "    print(f'REFUSED pid={e.holder_pid}')\n",
                db_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
    finally:
        holder.close()

    assert result.stdout.strip() == f"REFUSED pid={os.getpid()}", result.stdout


def test_contention_never_surfaces_as_ledger_corruption(db_path: str) -> None:
    """The regression this sprint exists for.

    Before the lock, a second writer got as far as its first append and then
    failed a UNIQUE constraint, which was reported as LedgerIntegrityError —
    the one error class documented as "the books cannot be trusted". Routine
    contention must never page someone about tampering.
    """
    first = BudgetManager.open_sqlite(db_path)
    first.open_root("root", money("1.00"))
    try:
        with pytest.raises(ConcurrentGovernorError) as excinfo:
            BudgetManager.open_sqlite(db_path)
        assert not isinstance(excinfo.value, LedgerError)
        assert isinstance(excinfo.value, StorageError)
    finally:
        first.close()


def test_the_claim_is_released_on_close(db_path: str) -> None:
    first = BudgetManager.open_sqlite(db_path)
    first.open_root("root", money("1.00"))
    first.spend("root", money("0.25"))
    first.close()

    second = BudgetManager.open_sqlite(db_path)
    try:
        assert second.available("root") == money("0.75")
    finally:
        second.close()


def test_a_killed_holder_leaves_no_stale_lock(db_path: str) -> None:
    """The kernel drops the claim when the holder dies, including on SIGKILL.

    This is why the lock is an open file descriptor and not a timestamp file:
    there is no staleness heuristic to get wrong.
    """
    child = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-c",
            "import sys, time;from agentgov import BudgetManager, money\n"
            "g = BudgetManager.open_sqlite(sys.argv[1])\n"
            "g.open_root('root', money('1.00'))\n"
            "print('HELD', flush=True)\n"
            "time.sleep(120)\n",
            db_path,
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout is not None
        assert child.stdout.readline().strip() == "HELD"
        with pytest.raises(ConcurrentGovernorError):
            BudgetManager.open_sqlite(db_path)
        child.kill()
        child.wait(timeout=30)
    finally:
        if child.poll() is None:  # pragma: no cover - cleanup path
            child.kill()
            child.wait(timeout=30)

    # No cleanup, no timeout: the next governor simply opens.
    recovered = BudgetManager.open_sqlite(db_path)
    try:
        assert recovered.available("root") == money("1.00")
        recovered.verify_integrity()
    finally:
        recovered.close()


def test_read_only_mode_audits_a_live_governor(db_path: str) -> None:
    """The remedy the error message advertises has to actually work."""
    live = BudgetManager.open_sqlite(db_path)
    live.open_root("root", money("1.00"))
    live.spend("root", money("0.30"))
    try:
        audit = BudgetManager.open_sqlite(db_path, read_only=True)
        try:
            assert audit.available("root") == money("0.70")
            audit.verify_integrity()
            with pytest.raises(ReadOnlyLedgerError, match="read-only"):
                audit.spend("root", money("0.01"))
        finally:
            audit.close()
    finally:
        live.close()


def test_read_only_mode_does_not_claim_the_database(db_path: str) -> None:
    SqliteStore(db_path).close()
    first = BudgetManager.open_sqlite(db_path, read_only=True)
    second = BudgetManager.open_sqlite(db_path, read_only=True)
    writer = BudgetManager.open_sqlite(db_path)  # a writer may still claim it
    first.close()
    second.close()
    writer.close()


def test_a_rejected_database_does_not_keep_the_claim(tmp_path: Path) -> None:
    """If restore-and-verify rejects the file, the claim must not leak.

    Otherwise a corrupt database would report itself as *contended* forever
    after, sending the operator chasing a process that does not exist.
    """
    path = str(tmp_path / "bad.db")
    store = SqliteStore(path)
    store._conn.execute(  # simulating an incompatible writer
        "UPDATE schema_meta SET value = '999' WHERE key = 'schema_version'"
    )
    store._conn.commit()
    store.close()

    with pytest.raises(Exception, match="schema version"):
        BudgetManager.open_sqlite(path)
    # The claim was released, so the failure reads as what it is.
    with pytest.raises(Exception, match="schema version"):
        BudgetManager.open_sqlite(path)


def test_in_memory_databases_are_never_locked() -> None:
    a = BudgetManager.open_sqlite(":memory:")
    b = BudgetManager.open_sqlite(":memory:")  # separate databases, no contention
    a.close()
    b.close()


# --------------------------------------------------------------------------
# Gap 2 - memory and lifecycle bounds
# --------------------------------------------------------------------------


def test_observer_state_is_evicted_with_the_trajectory() -> None:
    """The leak: the breaker capped trajectories, the observer did not."""
    breaker = CognitiveBreaker(policy=CognitivePolicy(max_trajectories=4, async_queue_size=4096))
    try:
        for index in range(200):
            breaker.observe(
                "s", "tool", canonical_arguments((unrelated(index),)), trajectory=f"t{index}"
            )
        deadline = time.perf_counter() + 5
        while time.perf_counter() < deadline and breaker.stats.evaluated < 100:
            time.sleep(0.01)
        observer = breaker._observer  # asserting an internal bound
        assert isinstance(observer, TrajectoryEntropyObserver)
        assert len(breaker._trajectories) == 4
        assert observer.tracked <= 4, f"observer retained {observer.tracked} states"
    finally:
        breaker.close()


def test_the_observer_bounds_itself_independently() -> None:
    """Defence in depth for trajectories the breaker has already forgotten."""
    observer = TrajectoryEntropyObserver(window=3, max_trajectories=8)
    call = ToolCall(
        sequence=1,
        scope_id="s",
        tool="t",
        arguments="",
        fingerprint="f",
        shingles=shingles("abc"),
        timestamp=datetime.now(UTC),
    )
    for index in range(100):
        observer.evaluate(f"t{index}", [call])
    assert observer.tracked == 8


def test_arguments_are_bounded_even_when_retained() -> None:
    breaker = CognitiveBreaker(
        observer=None,
        policy=CognitivePolicy(max_argument_chars=64, retain_arguments=True),
    )
    breaker.observe("s", "tool", canonical_arguments(("P" * 200_000,)))
    (call,) = breaker.history("s")
    assert len(call.arguments) <= 64, "retained text must still be bounded"


def test_truncation_does_not_weaken_exact_repeat_detection() -> None:
    """The digest covers the full string, so two calls differing only past
    the truncation point are still distinguishable."""
    breaker = CognitiveBreaker(observer=None, policy=CognitivePolicy(max_argument_chars=32))
    prefix = "S" * 5_000
    breaker.observe("s", "tool", canonical_arguments((prefix + "alpha",)))
    breaker.observe("s", "tool", canonical_arguments((prefix + "omega",)))
    first, second = breaker.history("s")
    assert first.fingerprint != second.fingerprint


def test_shingles_sample_both_ends_of_a_long_prompt() -> None:
    """A long stable prefix with a varying tail is the common agent shape.

    Head-only truncation made every such call identical; head+tail keeps the
    part that actually differs.
    """
    prefix = "CONTEXT " * 500
    a = shingles(prefix + "find the revenue report", max_chars=256)
    b = shingles(prefix + "book a flight to lisbon", max_chars=256)
    assert jaccard(a, b) < 0.9, "the differing tails must still be visible"


def test_an_unclosed_breaker_does_not_strand_its_thread() -> None:
    """The accidental per-request instantiation, which used to leak a thread."""
    baseline = threading.active_count()
    for index in range(15):
        breaker = CognitiveBreaker()
        breaker.observe("s", "tool", canonical_arguments((unrelated(index),)))
        del breaker
    gc.collect()

    deadline = time.perf_counter() + 10
    while time.perf_counter() < deadline and threading.active_count() > baseline:
        time.sleep(0.05)
        gc.collect()
    leaked = threading.active_count() - baseline
    assert leaked <= 1, f"{leaked} worker threads outlived their breakers"


def test_no_thread_starts_until_there_is_work() -> None:
    baseline = threading.active_count()
    breaker = CognitiveBreaker()
    try:
        assert threading.active_count() == baseline, "constructing one started a thread"
        breaker.observe("s", "tool", canonical_arguments(("first call",)))
        assert threading.active_count() == baseline + 1
    finally:
        breaker.close()


def test_stale_authorizations_are_surfaced_but_not_touched() -> None:
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("1.00"))
    hung = gov.authorize("root", money("0.10"))
    fresh = gov.authorize("root", money("0.10"))
    # Backdate one hold, as a process that died mid-call would leave it.
    gov._open_auths[hung.authorization_id] = type(hung)(
        authorization_id=hung.authorization_id,
        scope_id=hung.scope_id,
        amount=hung.amount,
        opened_at=datetime.now(UTC) - timedelta(minutes=30),
        entry=hung.entry,
    )

    stale = gov.stale_authorizations(timedelta(minutes=5))

    assert [a.authorization_id for a in stale] == [hung.authorization_id]
    assert gov.available("root") == money("0.80"), "surveying releases nothing"
    assert fresh.authorization_id in gov._open_auths
    gov.verify_integrity()


def test_void_stale_releases_the_funds_and_leaves_an_audit_trail() -> None:
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("1.00"))
    hung = gov.authorize("root", money("0.40"))
    gov._open_auths[hung.authorization_id] = type(hung)(
        authorization_id=hung.authorization_id,
        scope_id=hung.scope_id,
        amount=hung.amount,
        opened_at=datetime.now(UTC) - timedelta(hours=2),
        entry=hung.entry,
    )
    assert gov.available("root") == money("0.60")

    voided = gov.void_stale(timedelta(minutes=1))

    assert [a.authorization_id for a in voided] == [hung.authorization_id]
    assert gov.available("root") == money("1.00"), "the encumbrance came back"
    assert gov.audit_trail("root")[-1].entry_type is EntryType.HOLD_VOID
    assert "stale hold" in gov.audit_trail("root")[-1].memo
    gov.verify_integrity()


def test_a_voided_hold_that_later_completes_is_refused() -> None:
    """Voiding asserts the call will never settle. If it does anyway, the
    ledger must refuse to book the same encumbrance twice."""
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("1.00"))
    auth = gov.authorize("root", money("0.20"))
    gov._open_auths[auth.authorization_id] = type(auth)(
        authorization_id=auth.authorization_id,
        scope_id=auth.scope_id,
        amount=auth.amount,
        opened_at=datetime.now(UTC) - timedelta(hours=1),
        entry=auth.entry,
    )
    gov.void_stale(timedelta(minutes=1))

    with pytest.raises(DoubleSpendError):
        gov.capture(auth, money("0.05"))
    gov.verify_integrity()


def test_stale_reaping_can_be_scoped_and_accepts_plain_seconds() -> None:
    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("1.00"))
    gov.delegate("root", "worker", money("0.50"))
    gov.authorize("worker", money("0.10"))
    time.sleep(0.05)

    assert gov.stale_authorizations(0.01, scope_id="root") == ()
    assert len(gov.stale_authorizations(0.01, scope_id="worker")) == 1
    assert len(gov.stale_authorizations(0.01)) == 1
    assert gov.void_stale(0.01, scope_id="worker")
    assert gov.available("worker") == money("0.50")


# --------------------------------------------------------------------------
# Gap 3 - redaction and retention
# --------------------------------------------------------------------------


def test_prompt_text_is_not_retained_by_default() -> None:
    """A governor must not quietly become a copy of every prompt sent."""
    breaker = CognitiveBreaker(observer=None)
    sensitive = "patient SSN 123-45-6789 and card 4111111111111111"
    breaker.observe("s", "lookup", canonical_arguments((sensitive,)))

    (call,) = breaker.history("s")
    assert call.arguments == "", "raw argument text was retained by default"
    assert sensitive not in repr(call)
    assert sensitive not in call.fingerprint


def test_detection_is_unaffected_by_dropping_the_text() -> None:
    """Retention is a privacy knob, not a detection knob."""
    soft_loop = [
        "best python web scraping library 2026",
        "best python web scraping libraries 2026",
        "best python web scraping library 2026 guide",
        "the best python web scraping library 2026",
    ]
    for retain in (False, True):
        breaker = CognitiveBreaker(observer=None, policy=CognitivePolicy(retain_arguments=retain))
        tripped = 0
        for index, query in enumerate(soft_loop, start=1):
            try:
                breaker.observe("s", "search", canonical_arguments((query,)))
            except Exception:
                tripped = index
                break
        assert tripped == 4, f"retain_arguments={retain} changed detection"


def test_fingerprints_are_salted_per_breaker() -> None:
    """An unsalted digest of a prompt is a lookup key for that prompt."""
    text = canonical_arguments(("a known and guessable prompt",))
    first = CognitiveBreaker(observer=None)
    second = CognitiveBreaker(observer=None)
    first.observe("s", "t", text)
    second.observe("s", "t", text)
    assert first.history("s")[0].fingerprint != second.history("s")[0].fingerprint

    # An explicit salt restores reproducibility when a caller needs it.
    a = CognitiveBreaker(observer=None, salt=b"fixed-salt")
    b = CognitiveBreaker(observer=None, salt=b"fixed-salt")
    a.observe("s", "t", text)
    b.observe("s", "t", text)
    assert a.history("s")[0].fingerprint == b.history("s")[0].fingerprint


def test_a_redactor_sees_text_before_anything_else_does() -> None:
    class MaskDigits:
        def __init__(self) -> None:
            self.seen: list[str] = []

        def redact(self, tool: str, text: str) -> str:
            self.seen.append(tool)
            return "".join("#" if ch.isdigit() else ch for ch in text)

    redactor = MaskDigits()
    breaker = CognitiveBreaker(
        observer=None, redactor=redactor, policy=CognitivePolicy(retain_arguments=True)
    )
    breaker.observe("lookup", "lookup", canonical_arguments(("SSN 123-45-6789",)))
    breaker.record_result("lookup", {"account": "4111111111111111"})

    (call,) = breaker.history("lookup")
    assert "123" not in call.arguments
    assert "#" in call.arguments
    assert redactor.seen == ["lookup", "lookup"], "results are redacted too"


def test_a_raising_redactor_drops_the_text_rather_than_leaking_it(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail closed on content: an unvouched-for prompt is not retained."""

    class BrokenRedactor:
        def redact(self, tool: str, text: str) -> str:
            raise RuntimeError("regex blew up")

    breaker = CognitiveBreaker(
        observer=None,
        redactor=BrokenRedactor(),
        policy=CognitivePolicy(retain_arguments=True),
    )
    with caplog.at_level(logging.ERROR, logger="agentgov.cognitive"):
        breaker.observe("s", "lookup", canonical_arguments(("SSN 123-45-6789",)))

    (call,) = breaker.history("s")
    assert call.arguments == ""
    assert "123-45-6789" not in caplog.text
    assert "regex blew up" in caplog.text


def test_a_redactor_can_be_used_with_the_interceptor() -> None:
    """The seam has to be reachable from the surface engineers actually use."""
    from agentgov.dummy import DummyLLM
    from agentgov.interceptor import Interceptor

    class DropEverything:
        def redact(self, tool: str, text: str) -> str:
            return f"<redacted {len(text)} chars>"

    gov = BudgetManager(policy=GovernancePolicy(max_calls_per_window=0))
    gov.open_root("root", money("5.00"))
    breaker = CognitiveBreaker(
        observer=None,
        manager=gov,
        redactor=DropEverything(),
        policy=CognitivePolicy(retain_arguments=True),
    )
    metered = Interceptor(gov, "root", model="claude-opus-5", cognitive=breaker)
    metered.invoke(DummyLLM("claude-opus-5", output_tokens=50).complete, "a secret prompt")

    (call,) = breaker.history("root")
    assert "secret" not in call.arguments
    assert call.arguments.startswith("<redacted")


# --------------------------------------------------------------------------
# Ops baseline
# --------------------------------------------------------------------------


def test_the_velocity_default_does_not_trip_a_fast_fleet() -> None:
    """200/s tripped on this project's own benchmark; 1000/s must not."""
    assert GovernancePolicy().max_calls_per_window == 1000
    gov = BudgetManager()
    gov.open_root("root", money("1000.00"))
    for _ in range(600):  # comfortably inside one 1s window
        gov.spend("root", money("0.0001"))
    assert not gov.is_halted("root")


def test_custom_detectors_still_see_a_stable_call_surface() -> None:
    """Retention changed ToolCall; the detector contract must not have."""

    class Recorder:
        def __init__(self) -> None:
            self.calls: list[ToolCall] = []

        @property
        def name(self) -> str:
            return "recorder"

        def observe(self, call: ToolCall, history: Sequence[ToolCall]) -> Verdict | None:
            self.calls.append(call)
            return None

    recorder = Recorder()
    breaker = CognitiveBreaker(observer=None, detectors=[recorder])
    breaker.observe("s", "tool", canonical_arguments(("x",)))
    (seen,) = recorder.calls
    assert seen.fingerprint and seen.shingles and seen.tool == "tool"
