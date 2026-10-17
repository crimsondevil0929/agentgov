"""Helpers shared by the benchmarks.

Everything here uses agentgov's public API only, so a benchmark measures any
released version as it is: the baseline in ``benchmarks/baseline/`` was taken
with these same scripts against v0.4.0.
"""

from __future__ import annotations

import json
import os
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TypeVar

T = TypeVar("T")

ROOT = Path(__file__).resolve().parent.parent


def machine() -> dict[str, Any]:
    """What the numbers were measured on."""
    import agentgov

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            cwd=ROOT,
        ).stdout.strip()
    except OSError:
        commit = ""
    return {
        "agentgov": agentgov.__version__,
        "commit": commit,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpus": os.cpu_count(),
    }


def timed(fn: Callable[[], T]) -> tuple[T, float]:
    """``fn()`` and the seconds it took."""
    start = time.perf_counter()
    value = fn()
    return value, time.perf_counter() - start


@contextmanager
def stopwatch() -> Iterator[list[float]]:
    """``with stopwatch() as t: ...``; ``t[0]`` is the elapsed seconds."""
    box: list[float] = []
    start = time.perf_counter()
    try:
        yield box
    finally:
        box.append(time.perf_counter() - start)


def percentiles(
    samples: Sequence[float], points: Sequence[float] = (50, 90, 99)
) -> dict[str, float]:
    """Milliseconds at each percentile of ``samples`` (given in seconds)."""
    if not samples:
        return {f"p{p:g}": 0.0 for p in points}
    ordered = sorted(samples)
    out: dict[str, float] = {}
    for p in points:
        index = min(len(ordered) - 1, max(0, round(p / 100 * len(ordered)) - 1))
        out[f"p{p:g}"] = round(ordered[index] * 1000, 3)
    out["max"] = round(ordered[-1] * 1000, 3)
    out["mean"] = round(statistics.fmean(ordered) * 1000, 3)
    return out


def emit(result: dict[str, Any], out: str | None) -> None:
    """Print a result as one JSON line, and append it to ``out`` if given."""
    line = json.dumps(result, sort_keys=True)
    print(line, flush=True)
    if out:
        with open(out, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def rss_bytes() -> int:
    """This process's resident set size, best effort (0 if unknown)."""
    try:
        import resource

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # ru_maxrss is bytes on macOS, kilobytes on Linux.
        return int(peak if sys.platform == "darwin" else peak * 1024)
    except (ImportError, OSError):  # pragma: no cover - platform dependent
        return 0
