"""Scale gates: open time and memory bounded by state, not by history (§5.2).

Two tiers. The relative gates run on every change and hold on any hardware:
a ledger ten times as long opens in at most twice the time, because a
governor replays only the entries since its last checkpoint; and one with ten
times the scopes in about ten times the time, not a hundred, because no
step of an open is quadratic in the scopes. The absolute gates, the ones 1.0
is held to, run nightly and before a release with ``AGENTGOV_SCALE=1``:

- a 1,000,000-entry ledger whose newest checkpoint is at most 10,000 entries
  behind opens in at most 500 ms, and at most twice a 10,000-entry ledger's
  open;
- the memory an open governor holds is flat from 10,000 to 1,000,000 entries
  at a fixed number of scopes;
- 100,000 scopes and 10,000 open holds checkpoint and reopen.

``AGENTGOV_SCALE_FIXTURES`` names a directory to keep the large ledgers in
between runs (they take minutes to build).
"""

from __future__ import annotations

import gc
import os
import statistics
import time
import tracemalloc
from collections.abc import Callable
from pathlib import Path

import pytest

from agentgov import BudgetManager, GovernancePolicy, money

SCALE = os.environ.get("AGENTGOV_SCALE") == "1"
scale_only = pytest.mark.skipif(not SCALE, reason="set AGENTGOV_SCALE=1 to run the scale gates")


def _build(path: Path, *, entries: int, every: int, scopes: int = 8) -> Path:
    """A ledger of at least ``entries`` entries, checkpointed every ``every``,
    ending with its newest checkpoint as far behind as ``every`` allows."""
    if path.exists():
        return path
    partial = path.with_name(path.name + ".partial")
    for leftover in path.parent.glob(partial.name + "*"):
        leftover.unlink()
    policy = GovernancePolicy(max_calls_per_window=0, checkpoint_every=every)
    with BudgetManager.open_sqlite(
        str(partial), synchronous="OFF", policy=policy, auditor=False
    ) as gov:
        gov.open_root("root", money("1000000000"))
        for i in range(scopes):
            gov.delegate("root", f"agent-{i}", money("1000000"))
        n = 0
        while len(gov.ledger) < entries:
            gov.spend(f"agent-{n % scopes}", money("0.00001"))
            n += 1
    with BudgetManager.open_sqlite(
        str(partial),
        synchronous="OFF",
        policy=GovernancePolicy(max_calls_per_window=0, checkpoint_every=0),
        auditor=False,
    ) as gov:
        last = gov.ledger._state.last_checkpoint
        base = last[0] if last is not None else 0
        while len(gov.ledger) - base < every - 3:  # the worst case: just short of the next
            gov.spend("agent-0", money("0.00001"))
    for suffix in ("-wal", "-shm", ".lock"):
        sidecar = partial.with_name(partial.name + suffix)
        if sidecar.exists():
            sidecar.unlink()
    partial.rename(path)
    return path


def _build_wide(path: Path, *, scopes: int, holds: int) -> Path:
    """A ledger of ``scopes`` children of one root, ``holds`` of them holding,
    checkpointed at its head."""
    policy = GovernancePolicy(max_calls_per_window=0, checkpoint_every=0)
    with BudgetManager.open_sqlite(
        str(path), synchronous="OFF", policy=policy, auditor=False
    ) as gov:
        gov.open_root("root", money("1000000000"))
        for i in range(scopes):
            gov.delegate("root", f"scope-{i}", money("1"))
        for i in range(holds):
            gov.authorize(f"scope-{i}", money("0.5"))
        gov.checkpoint()
    return path


def _open_seconds(path: Path, *, repeat: int = 5) -> float:
    """The median time to open ``path`` for writing (no auditor), over ``repeat``."""
    samples = []
    for _ in range(repeat):
        gc.collect()
        started = time.perf_counter()
        gov = BudgetManager.open_sqlite(str(path), auditor=False)
        samples.append(time.perf_counter() - started)
        gov.close()
    return statistics.median(samples)


def _held_bytes(path: Path) -> int:
    """The Python heap a held, open governor adds."""
    gc.collect()
    tracemalloc.start()
    try:
        before = tracemalloc.take_snapshot()
        gov = BudgetManager.open_sqlite(str(path), read_only=True, auditor=False)
        after = tracemalloc.take_snapshot()
        grown = sum(stat.size_diff for stat in after.compare_to(before, "filename"))
        gov.close()
    finally:
        tracemalloc.stop()
    return grown


def _fixtures(tmp_path: Path) -> Path:
    kept = os.environ.get("AGENTGOV_SCALE_FIXTURES")
    if kept:
        path = Path(kept)
        path.mkdir(parents=True, exist_ok=True)
        return path
    return tmp_path


# -- every change --------------------------------------------------------------------


def test_a_ledger_ten_times_as_long_opens_in_at_most_twice_the_time(tmp_path: Path) -> None:
    short = _build(tmp_path / "short.db", entries=2_000, every=2_000)
    long = _build(tmp_path / "long.db", entries=20_000, every=2_000)
    t_short, t_long = _open_seconds(short), _open_seconds(long)
    assert t_long <= 2 * t_short + 0.02, (
        f"a 20,000-entry ledger took {t_long * 1000:.1f} ms to open; a 2,000-entry one "
        f"{t_short * 1000:.1f} ms: open is not bounded by the entries since the checkpoint"
    )


def test_a_ledger_ten_times_as_wide_opens_in_about_ten_times_the_time(tmp_path: Path) -> None:
    narrow = _build_wide(tmp_path / "narrow.db", scopes=2_000, holds=200)
    wide = _build_wide(tmp_path / "wide.db", scopes=20_000, holds=2_000)
    t_narrow, t_wide = _open_seconds(narrow, repeat=3), _open_seconds(wide, repeat=3)
    assert t_wide <= 20 * t_narrow + 0.05, (
        f"20,000 scopes took {t_wide * 1000:.0f} ms to open; 2,000 took "
        f"{t_narrow * 1000:.0f} ms: some step of an open grows faster than the scopes"
    )


def test_memory_does_not_grow_with_history(tmp_path: Path) -> None:
    short = _build(tmp_path / "short.db", entries=2_000, every=2_000)
    long = _build(tmp_path / "long.db", entries=20_000, every=2_000)
    held_short, held_long = _held_bytes(short), _held_bytes(long)
    assert held_long <= 1.5 * held_short + 64 * 1024, (
        f"an open governor holds {held_long:,} bytes over 20,000 entries and "
        f"{held_short:,} over 2,000: memory is growing with history"
    )


# -- nightly and before a release ------------------------------------------------------


@scale_only
def test_a_million_entries_open_in_at_most_500_ms(tmp_path: Path) -> None:
    root = _fixtures(tmp_path)
    small = _build(root / "scale-10k.db", entries=10_000, every=10_000)
    large = _build(root / "scale-1m.db", entries=1_000_000, every=10_000)
    with BudgetManager.open_sqlite(str(large), read_only=True, auditor=False) as gov:
        last = gov.ledger._state.last_checkpoint
        assert last is not None and len(gov.ledger) >= 1_000_000
        assert len(gov.ledger) - last[0] <= 10_000
    t_small, t_large = _open_seconds(small), _open_seconds(large)
    assert t_large <= 0.5, f"a 1,000,000-entry ledger took {t_large * 1000:.0f} ms to open"
    assert t_large <= 2 * t_small, (
        f"1,000,000 entries: {t_large * 1000:.0f} ms; 10,000: {t_small * 1000:.0f} ms"
    )


@scale_only
def test_memory_is_flat_from_ten_thousand_to_a_million_entries(tmp_path: Path) -> None:
    root = _fixtures(tmp_path)
    small = _build(root / "scale-10k.db", entries=10_000, every=10_000)
    large = _build(root / "scale-1m.db", entries=1_000_000, every=10_000)
    held_small, held_large = _held_bytes(small), _held_bytes(large)
    assert held_large <= 1.5 * held_small + 64 * 1024, (held_small, held_large)


def _time(fn: Callable[[], object]) -> float:
    started = time.perf_counter()
    fn()
    return time.perf_counter() - started


@scale_only
def test_a_hundred_thousand_scopes_and_ten_thousand_open_holds(tmp_path: Path) -> None:
    path = tmp_path / "wide.db"
    policy = GovernancePolicy(max_calls_per_window=0, checkpoint_every=0)
    with BudgetManager.open_sqlite(
        str(path), synchronous="OFF", policy=policy, auditor=False
    ) as gov:
        gov.open_root("root", money("1000000000"))
        started = time.perf_counter()
        for i in range(100_000):
            gov.delegate("root", f"scope-{i}", money("1"))
        delegating = time.perf_counter() - started
        for i in range(10_000):
            gov.authorize(f"scope-{i}", money("0.5"))
        written = _time(gov.checkpoint)
        assert len(gov.stale_authorizations(0)) == 10_000
    reopen = _time(lambda: BudgetManager.open_sqlite(str(path), auditor=False).close())
    # A delegation costs the same under a root with 100,000 children as under
    # one with none: no step copies or scans a parent's children.
    assert delegating < 100_000 * 0.001, f"100,000 delegations took {delegating:.1f}s"
    assert written < 10, f"checkpointing 100,000 scopes took {written:.1f}s"
    assert reopen < 5, f"reopening 100,000 scopes from their checkpoint took {reopen:.1f}s"
    with BudgetManager.open_sqlite(str(path), read_only=True, auditor=False) as view:
        assert len(view.scopes()) == 100_001
        assert len(view.stale_authorizations(0)) == 10_000
