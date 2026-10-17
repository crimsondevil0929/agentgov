#!/usr/bin/env python3
"""Write throughput: governors x callers, authorizing and capturing.

Each caller thread owns a scope and loops ``authorize()`` then ``capture()``
for ``--seconds``; both count as one operation each, and every operation's
latency is recorded. Callers never compete for the same funds, so what this
measures is the write path itself: the lock, the store, and on PostgreSQL the
fleet's single writer lock that every governor takes turns on.

By default the loop is closed: each caller starts its next operation when the
last returns, so the run measures the most it can do, and its latency is what
that load costs (``callers / throughput`` on average). With ``--rate`` it is
open: operations are offered at that many a second in total, each caller on a
fixed schedule, and an operation's latency is counted from when it was due,
so time spent behind schedule is counted rather than hidden. That is latency
*at a given load*.

- ``--backend sqlite``: one governor (SQLite allows one writer process) with
  ``--callers`` threads.
- ``--backend postgres --dsn ...``: ``--governors`` processes, each one
  governor with ``--callers`` threads, all writing one shared ledger.

Usage::

    uv run python benchmarks/bench_throughput.py --backend sqlite --callers 8
    uv run python benchmarks/bench_throughput.py --backend postgres --dsn postgresql://... \\
        --governors 8 --callers 8 [--rate 2000]
"""

from __future__ import annotations

import argparse
import multiprocessing
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import emit, machine, percentiles
from _fixtures import UNLIMITED

from agentgov import BudgetManager, money

HOLD = money("0.01")
COST = money("0.004")


def _callers(
    gov: BudgetManager,
    scopes: list[str],
    seconds: float,
    start_at: float,
    schedule: tuple[float, float] | None = None,
) -> list[float]:
    """Run one caller thread per scope; return every operation's latency.

    :param schedule: For an open loop, ``(interval, offset)``: the caller at
        position ``i`` here is due to start operation ``k`` at ``start_at +
        offset + (k + i / len(scopes)) * interval``.
    """
    latencies: list[list[float]] = [[] for _ in scopes]
    errors: list[BaseException] = []

    def run(index: int, scope: str) -> None:
        mine = latencies[index]
        try:
            while time.monotonic() < start_at:
                time.sleep(0.001)
            stop = start_at + seconds
            if schedule is None:
                while time.monotonic() < stop:
                    t0 = time.perf_counter()
                    hold = gov.authorize(scope, HOLD)
                    t1 = time.perf_counter()
                    gov.capture(hold, COST)
                    t2 = time.perf_counter()
                    mine.append(t1 - t0)
                    mine.append(t2 - t1)
                return
            interval, offset = schedule
            due = start_at + offset + index / len(scopes) * interval
            while due < stop:
                for step in range(2):  # authorize, then capture: one operation each
                    wait = due - time.monotonic()
                    if wait > 0:
                        time.sleep(wait)
                    if step == 0:
                        hold = gov.authorize(scope, HOLD)
                    else:
                        gov.capture(hold, COST)
                    mine.append(time.monotonic() - due)
                    due += interval
        except BaseException as exc:  # reported, never swallowed
            errors.append(exc)

    threads = [threading.Thread(target=run, args=(i, s)) for i, s in enumerate(scopes)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if errors:
        raise errors[0]
    return [lat for per in latencies for lat in per]


def _governor(
    dsn: str,
    schema: str,
    scopes: list[str],
    seconds: float,
    start_at: float,
    schedule: tuple[float, float] | None,
    out: Any,
) -> None:
    gov = BudgetManager.open_postgres(dsn, schema=schema, policy=UNLIMITED)
    try:
        out.put(_callers(gov, scopes, seconds, start_at, schedule))
    finally:
        gov.close()


def _schedule(
    rate: float | None, callers: int, governors: int, g: int
) -> tuple[float, float] | None:
    """Each caller's interval at ``rate`` operations a second in total, and
    governor ``g``'s offset, so the fleet's arrivals are evenly spread."""
    if rate is None:
        return None
    interval = callers * governors / rate
    return interval, g / governors * interval / callers


def _setup(gov: BudgetManager, scopes: list[str]) -> None:
    gov.open_root("root", money("1000000000"))
    for scope in scopes:
        gov.delegate("root", scope, money("1000000"))


def run_sqlite(callers: int, seconds: float, rate: float | None = None) -> dict[str, Any]:
    scopes = [f"caller-{i}" for i in range(callers)]
    with tempfile.TemporaryDirectory() as tmp:
        path = str(Path(tmp) / "throughput.db")
        with BudgetManager.open_sqlite(path, policy=UNLIMITED) as gov:
            _setup(gov, scopes)
            schedule = _schedule(rate, callers, 1, 0)
            latencies = _callers(gov, scopes, seconds, time.monotonic() + 0.2, schedule)
    return {
        "governors": 1,
        "callers": callers,
        **({"offered_ops_per_s": rate} if rate is not None else {}),
        "ops": len(latencies),
        **_summary(latencies, seconds),
    }


def run_postgres(
    dsn: str, governors: int, callers: int, seconds: float, rate: float | None = None
) -> dict[str, Any]:
    schema = f"bench_{uuid.uuid4().hex[:10]}"
    groups = [[f"g{g}-c{c}" for c in range(callers)] for g in range(governors)]
    with BudgetManager.open_postgres(dsn, schema=schema, policy=UNLIMITED) as gov:
        _setup(gov, [s for group in groups for s in group])
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    start_at = time.monotonic() + 3.0 + 0.25 * governors  # every governor open first
    procs = [
        ctx.Process(
            target=_governor,
            args=(
                dsn,
                schema,
                group,
                seconds,
                start_at,
                _schedule(rate, callers, governors, g),
                out,
            ),
        )
        for g, group in enumerate(groups)
    ]
    for proc in procs:
        proc.start()
    latencies: list[float] = []
    for _ in procs:
        latencies.extend(out.get(timeout=seconds + 300))
    for proc in procs:
        proc.join(60)
    return {
        "governors": governors,
        "callers": callers,
        **({"offered_ops_per_s": rate} if rate is not None else {}),
        "ops": len(latencies),
        **_summary(latencies, seconds),
    }


def _summary(latencies: list[float], seconds: float) -> dict[str, Any]:
    return {"ops_per_s": round(len(latencies) / seconds, 1), "latency_ms": percentiles(latencies)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--backend", choices=("sqlite", "postgres"), default="sqlite")
    parser.add_argument("--dsn", default="")
    parser.add_argument("--governors", type=int, default=1)
    parser.add_argument("--callers", type=int, default=8)
    parser.add_argument("--seconds", type=float, default=10.0)
    parser.add_argument(
        "--rate",
        type=float,
        default=None,
        help="offer this many operations a second in total (an open loop); "
        "latency is then counted from when each operation was due",
    )
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    if args.backend == "sqlite":
        result = run_sqlite(args.callers, args.seconds, args.rate)
    else:
        if not args.dsn:
            parser.error("--backend postgres needs --dsn")
        result = run_postgres(args.dsn, args.governors, args.callers, args.seconds, args.rate)
    emit({"bench": "throughput", "backend": args.backend, **machine(), **result}, args.out)


if __name__ == "__main__":
    main()
