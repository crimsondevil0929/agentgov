#!/usr/bin/env python3
"""What opening a governor costs as its ledger grows.

For each size, a SQLite ledger is built (see ``_fixtures.py``) and measured:

- ``open_ms``: :meth:`BudgetManager.open_sqlite`, writable, timed as a whole
  (the best of ``--repeat`` runs, and their median);
- ``open_read_only_ms``: the same, read-only;
- ``verify_ms``: a full :meth:`BudgetManager.verify_integrity` once open;
- ``memory_per_entry``: the Python heap a held, open governor adds, divided
  by its entries (``tracemalloc``).

With ``--postgres DSN`` each ledger is also copied into PostgreSQL and two
more figures are taken there:

- ``pg_open_ms``: :meth:`BudgetManager.open_postgres`, timed as a whole;
- ``pg_stall_ms``: while that open runs, another governor, in another process,
  writes as fast as it can; this is the longest any one of its writes took
  during the open, against ``pg_write_p99_ms`` when nothing is opening. A
  governor that opens under the fleet's writer lock stalls every other writer
  for the whole open.

Usage::

    uv run python benchmarks/bench_open.py --sizes 10000 50000 150000
    uv run python benchmarks/bench_open.py --sizes 10000 --postgres postgresql://...
"""

from __future__ import annotations

import argparse
import gc
import multiprocessing
import statistics
import sys
import time
import tracemalloc
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _common import emit, machine, percentiles, timed
from _fixtures import UNLIMITED, build_sqlite, copy_to_postgres, spends_for

from agentgov import BudgetManager, money


def measure_sqlite(path: Path, repeat: int) -> dict[str, Any]:
    opens: list[float] = []
    for _ in range(repeat):
        gc.collect()
        gov, seconds = timed(lambda: BudgetManager.open_sqlite(str(path)))
        entries = len(gov.ledger)
        gov.close()
        opens.append(seconds)
    gc.collect()
    ro, ro_seconds = timed(lambda: BudgetManager.open_sqlite(str(path), read_only=True))
    _, verify_seconds = timed(ro.verify_integrity)
    ro.close()

    gc.collect()
    tracemalloc.start()
    before = tracemalloc.take_snapshot()
    held = BudgetManager.open_sqlite(str(path), read_only=True)
    after = tracemalloc.take_snapshot()
    tracemalloc.stop()
    grown = sum(stat.size_diff for stat in after.compare_to(before, "filename"))
    held.close()
    return {
        "entries": entries,
        "open_ms": round(min(opens) * 1000, 1),
        "open_median_ms": round(statistics.median(opens) * 1000, 1),
        "open_read_only_ms": round(ro_seconds * 1000, 1),
        "verify_ms": round(verify_seconds * 1000, 1),
        "memory_per_entry": round(grown / max(1, entries)),
        "file_bytes_per_entry": round(path.stat().st_size / max(1, entries)),
    }


def _writer(dsn: str, schema: str, seconds: float, out: Any, ready: Any) -> None:
    """Spend as fast as possible for ``seconds``; report (start, latency) pairs."""
    gov = BudgetManager.open_postgres(dsn, schema=schema, policy=UNLIMITED)
    samples: list[tuple[float, float]] = []
    ready.set()
    stop = time.monotonic() + seconds
    try:
        while time.monotonic() < stop:
            start = time.monotonic()
            gov.spend("agent-0", money("0.00001"))
            samples.append((start, time.monotonic() - start))
    finally:
        gov.close()
    out.put(samples)


def measure_postgres(path: Path, dsn: str, repeat: int) -> dict[str, Any]:
    schema = f"bench_{uuid.uuid4().hex[:10]}"
    copy_to_postgres(path, dsn, schema=schema)
    opens: list[float] = []
    for _ in range(repeat):
        gov, seconds = timed(lambda: BudgetManager.open_postgres(dsn, schema=schema))
        gov.close()
        opens.append(seconds)

    # The stall: a writer in another process, and an open in this one.
    ctx = multiprocessing.get_context("spawn")
    out, ready = ctx.Queue(), ctx.Event()
    window = max(3.0, min(opens) * 3 + 2.0)
    proc = ctx.Process(target=_writer, args=(dsn, schema, window, out, ready))
    proc.start()
    ready.wait(60)
    time.sleep(0.75)  # a baseline of uncontended writes first
    open_start = time.monotonic()
    gov = BudgetManager.open_postgres(dsn, schema=schema)
    open_end = time.monotonic()
    gov.close()
    samples: list[tuple[float, float]] = out.get(timeout=window + 120)
    proc.join(30)

    def overlaps(start: float, latency: float) -> bool:
        return start <= open_end and start + latency >= open_start

    during = [lat for start, lat in samples if overlaps(start, lat)]
    quiet = [lat for start, lat in samples if start + lat < open_start]
    return {
        "pg_open_ms": round(min(opens) * 1000, 1),
        "pg_open_median_ms": round(statistics.median(opens) * 1000, 1),
        "pg_open_during_stall_ms": round((open_end - open_start) * 1000, 1),
        "pg_stall_ms": round(max(during, default=0.0) * 1000, 1),
        "pg_write_p99_ms": percentiles(quiet)["p99"],
        "pg_writes_during_open": len(during),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--sizes", type=int, nargs="+", default=[10_000, 50_000, 150_000])
    parser.add_argument("--scopes", type=int, default=8)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--fixtures", default="benchmarks/.fixtures")
    parser.add_argument("--postgres", default="", help="a DSN; also measure PostgreSQL")
    parser.add_argument("--out", default=None, help="append JSON lines here")
    args = parser.parse_args()

    meta = machine()
    for size in args.sizes:
        spends = spends_for(size, args.scopes)
        path = build_sqlite(
            Path(args.fixtures) / f"ledger-{spends}x{args.scopes}.db",
            spends=spends,
            scopes=args.scopes,
        )
        result: dict[str, Any] = {"bench": "open", **meta, "scopes": args.scopes}
        result.update(measure_sqlite(path, args.repeat))
        if args.postgres:
            result.update(measure_postgres(path, args.postgres, args.repeat))
        emit(result, args.out)


if __name__ == "__main__":
    main()
