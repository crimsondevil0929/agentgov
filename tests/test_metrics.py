"""Metrics (Phase 5.6): what a governor reports, and the OpenTelemetry adapter.

A governor given a :class:`agentgov.metrics.Metrics` reports lock waits and
holds, units of work, catch-ups, opens, verifications, open holds, checkpoint
lag, trips and store errors, each under a name in ``INSTRUMENTS`` and as the
kind it is listed as. Without one it measures nothing.
"""

from __future__ import annotations

import functools
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from agentgov import BudgetManager, GovernancePolicy, money
from agentgov.exceptions import DenialOfWalletError, StorageError
from agentgov.metrics import INSTRUMENTS, Metrics
from agentgov.otel import OpenTelemetryMetrics

POLICY = GovernancePolicy(max_calls_per_window=0, checkpoint_every=0)


class Recorder:
    """Every measurement, by name, checked against the names it may use."""

    def __init__(self) -> None:
        self.seen: dict[str, list[float]] = defaultdict(list)

    def _note(self, kind: str, name: str, value: float) -> None:
        assert name in INSTRUMENTS, f"{name} is not a listed instrument"
        assert INSTRUMENTS[name][0] == kind, f"{name} is a {INSTRUMENTS[name][0]}, not a {kind}"
        self.seen[name].append(value)

    def record(self, name: str, value: float) -> None:
        self._note("histogram", name, value)

    def add(self, name: str, value: int = 1) -> None:
        self._note("counter", name, value)

    def set(self, name: str, value: float) -> None:
        self._note("gauge", name, value)


def test_a_recorder_is_metrics() -> None:
    assert isinstance(Recorder(), Metrics)


def test_a_sqlite_governor_reports_its_work(tmp_path: Path) -> None:
    metrics = Recorder()
    gov = BudgetManager.open_sqlite(
        str(tmp_path / "l.db"), policy=POLICY, auditor=False, metrics=metrics
    )
    try:
        assert len(metrics.seen["agentgov.open.duration"]) == 1
        gov.open_root("root", money("10"))
        gov.delegate("root", "a", money("5"))
        hold = gov.authorize("a", money("1"))
        assert metrics.seen["agentgov.holds.open"][-1] == 1
        assert metrics.seen["agentgov.checkpoint.lag"][-1] == len(gov.ledger)
        gov.capture(hold, money("1"))
        assert metrics.seen["agentgov.holds.open"][-1] == 0
        with pytest.raises(DenialOfWalletError):
            gov.authorize("a", money("50"))
        assert metrics.seen["agentgov.trips"] == [1]
        gov.verify_integrity()
        assert len(metrics.seen["agentgov.verify.duration"]) == 1
        # Callers that arrive together share a unit of work, and say how many.
        gov.delegate("root", "b", money("4"))
        with gov.ledger.lock:
            runs = [
                threading.Thread(target=functools.partial(gov.authorize, "b", money("0.1")))
                for _ in range(3)
            ]
            for run in runs:
                run.start()
            deadline = time.monotonic() + 10
            while len(gov._queue) < 3:
                assert time.monotonic() < deadline
                time.sleep(0.001)
        for run in runs:
            run.join(10)
        assert 3 in metrics.seen["agentgov.unit.size"]
    finally:
        gov.close()
    assert "agentgov.lock.wait" not in metrics.seen, "no fleet lock on SQLite"


def test_a_governor_without_metrics_measures_nothing(tmp_path: Path) -> None:
    gov = BudgetManager.open_sqlite(str(tmp_path / "l.db"), policy=POLICY, auditor=False)
    try:
        assert gov._metrics is None
        gov.open_root("root", money("1"))
    finally:
        gov.close()


def test_a_fleet_governor_reports_its_lock_and_catch_ups(
    pg_dsn: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from agentgov.postgres import PostgresStore

    metrics = Recorder()
    gov = BudgetManager.open_postgres(pg_dsn, policy=POLICY, auditor=False, metrics=metrics)
    other = BudgetManager.open_postgres(pg_dsn, policy=POLICY, auditor=False)
    try:
        gov.open_root("root", money("10"))
        gov.delegate("root", "a", money("5"))
        assert len(metrics.seen["agentgov.lock.wait"]) == 2
        assert len(metrics.seen["agentgov.lock.hold"]) == 2
        other.spend("a", money("1"))  # three entries this governor has not seen
        gov.authorize("a", money("1"))
        assert 3 in metrics.seen["agentgov.catch_up.entries"]

        def refuse(self: PostgresStore, session: Any) -> None:
            self._rollback_quietly()
            session.batches.clear()
            raise StorageError("the database refused the commit")

        with monkeypatch.context() as patch:
            patch.setattr(PostgresStore, "_end", refuse)
            with pytest.raises(StorageError):
                gov.authorize("a", money("1"))
        assert metrics.seen["agentgov.store.errors"] == [1]
    finally:
        gov.close()
        other.close()


class _Instrument:
    def __init__(self, kind: str, name: str, unit: str, description: str) -> None:
        self.kind, self.name, self.unit, self.description = kind, name, unit, description
        self.calls: list[tuple[str, float, dict[str, str]]] = []

    def record(self, value: float, attributes: dict[str, str]) -> None:
        self.calls.append(("record", value, attributes))

    def add(self, value: float, attributes: dict[str, str]) -> None:
        self.calls.append(("add", value, attributes))

    def set(self, value: float, attributes: dict[str, str]) -> None:
        self.calls.append(("set", value, attributes))


class _Meter:
    """The part of an OpenTelemetry Meter the adapter uses."""

    def __init__(self) -> None:
        self.made: dict[str, _Instrument] = {}

    def _make(self, kind: str, name: str, unit: str = "", description: str = "") -> _Instrument:
        self.made[name] = _Instrument(kind, name, unit, description)
        return self.made[name]

    def create_histogram(self, name: str, unit: str = "", description: str = "") -> _Instrument:
        return self._make("histogram", name, unit, description)

    def create_counter(self, name: str, unit: str = "", description: str = "") -> _Instrument:
        return self._make("counter", name, unit, description)

    def create_gauge(self, name: str, unit: str = "", description: str = "") -> _Instrument:
        return self._make("gauge", name, unit, description)


def test_the_opentelemetry_adapter_makes_each_instrument_once(tmp_path: Path) -> None:
    meter = _Meter()
    metrics = OpenTelemetryMetrics(meter, attributes={"ledger": "test"})
    gov = BudgetManager.open_sqlite(
        str(tmp_path / "l.db"), policy=POLICY, auditor=False, metrics=metrics
    )
    try:
        gov.open_root("root", money("10"))
        gov.delegate("root", "a", money("5"))
        gov.spend("a", money("1"))
    finally:
        gov.close()
    for name, instrument in meter.made.items():
        kind, unit, description = INSTRUMENTS[name]
        assert (instrument.kind, instrument.unit, instrument.description) == (
            kind,
            unit,
            description,
        )
        assert instrument.calls and all(call[2] == {"ledger": "test"} for call in instrument.calls)
    assert meter.made["agentgov.open.duration"].calls[0][0] == "record"
    assert meter.made["agentgov.holds.open"].calls[-1][:2] == ("set", 0)


def test_the_adapter_never_fails_the_governor() -> None:
    class Broken(_Meter):
        def create_histogram(self, name: str, unit: str = "", description: str = "") -> Any:
            raise RuntimeError("no exporter")

    metrics = OpenTelemetryMetrics(Broken())
    metrics.record("agentgov.lock.wait", 0.1)  # logged, not raised
    metrics.add("agentgov.trips")
    metrics.set("agentgov.holds.open", 3)
