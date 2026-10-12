#!/usr/bin/env python3
"""A soak of governors on one ledger, with chaos, checked against every
invariant the ledger promises.

::

    uv run python scripts/soak.py --ledger postgresql://... --minutes 30 --out soak.json
    uv run python scripts/soak.py --ledger sqlite:///tmp/soak.db --minutes 10

Governor processes, each one governor shared by worker threads, run a mix of
every money operation against one ledger (a fresh schema in the PostgreSQL
database, or a fresh SQLite file, where one process writes): holds captured
and voided, spends, refunds naming their spend, ``try_authorize()``,
check-then-act inside ``transaction()``, and overdraws that trip a scope's
breaker, with the resets that clear it. Every operation that moves money
carries an idempotency key, and every worker journals each one's intent before
the call and its result after, flushed, so a SIGKILL loses nothing a call
returned. A restarted worker first retries the operation it was killed in,
under the same key.

Meanwhile the chaos loop SIGKILLs a governor process and restarts it (on
PostgreSQL never the first, whose memory is sampled), and on PostgreSQL now
and then terminates every governor's database connection mid-flight.
``agentgov audit --follow`` audits the ledger beside them throughout.

At the end it checks:

- the ledger replays from genesis, conserves value, and its caches agree;
- every operation a worker journaled as done is in the ledger exactly once,
  and no money-moving entry exists that no worker began;
- a retry under a used key returned what the first call did;
- the auditor found nothing;
- on PostgreSQL, the first governor's memory stayed flat, and the database's
  connections stayed bounded.

Exits 1 if any check fails.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import random
import signal
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
import uuid
from collections import Counter, deque
from contextlib import closing
from decimal import Decimal
from pathlib import Path
from typing import Any
from urllib.parse import quote

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

import agentgov
from agentgov import (
    BudgetExceededError,
    BudgetManager,
    CircuitOpenError,
    EntryType,
    GovernancePolicy,
    StorageError,
    money,
)
from agentgov.opening import parse_url

# Checkpoints often, so opens from a checkpoint, catch-ups past one and the
# auditor's snapshot checks all happen many times in a run.
POLICY = GovernancePolicy(max_calls_per_window=0, checkpoint_every=2_000)
MONEY_TYPES = {EntryType.SPEND, EntryType.REVERSAL}


# -- one worker ------------------------------------------------------------------------


class Journal:
    """A worker's operations: intent before the call, outcome after.

    It remembers only what a restart needs, so the soak measures the governor
    beside it, not itself: a worker has one operation in flight at a time, so
    the newest line says whether one was left unfinished.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.last: dict[str, Any] | None = None
        if path.exists():
            data = path.read_bytes()
            whole = data[: data.rfind(b"\n") + 1]
            if len(whole) != len(data):
                # A line torn by a SIGKILL mid-write: its call never began.
                path.write_bytes(whole)
            for raw in whole.decode().splitlines():
                self.last = json.loads(raw)
        self._file = path.open("a")

    def write(self, **line: Any) -> None:
        self.last = line
        self._file.write(json.dumps(line, sort_keys=True) + "\n")
        self._file.flush()

    def pending(self) -> dict[str, Any] | None:
        """The operation begun and not finished when the worker last died."""
        return self.last if self.last is not None and self.last["phase"] == "intent" else None

    def next_number(self) -> int:
        return (self.last["n"] if self.last is not None else 0) + 1


class Worker:
    def __init__(self, gov: BudgetManager, name: str, journal: Journal, seed: int) -> None:
        self.gov = gov
        self.name = name
        self.scope = f"w-{name}"
        self.fragile = f"x-{name}"  # a small budget, overdrawn to trip its breaker
        self.journal = journal
        self.rng = random.Random(seed)  # noqa: S311 - a workload, not a secret
        # Recent spends, to refund: (entry id, refundable left).
        self.spends: deque[tuple[str, Decimal]] = deque(maxlen=64)
        self.retries_checked = 0
        self.storage_errors = 0
        self.trips = 0
        self.last_done: dict[str, Any] | None = None

    # Each operation: (kind, args) -> result dict. Keys make each exactly once.

    def run(self, deadline: float, stop: threading.Event) -> None:
        pending = self.journal.pending()
        if pending is not None:
            self._call(pending["n"], pending["op"], pending["args"], resumed=True)
        while time.monotonic() < deadline and not stop.is_set():
            self.step()

    def step(self) -> None:
        roll = self.rng.random()
        n = self.journal.next_number()
        cents = Decimal(self.rng.randint(1, 50)) / 100
        if roll < 0.30:
            self._call(n, "authorize", {"amount": str(cents), "then": "capture"})
        elif roll < 0.45:
            self._call(n, "spend", {"amount": str(cents)})
        elif roll < 0.55 and self.spends:
            entry_id, left = self.spends[self.rng.randrange(len(self.spends))]
            part = min(left, Decimal(self.rng.randint(1, 30)) / 100)
            if part > 0:
                self._call(n, "refund", {"amount": str(part), "reverses": entry_id})
        elif roll < 0.65:
            self._call(n, "authorize", {"amount": str(cents), "then": "void"})
        elif roll < 0.75:
            self._call(n, "try_authorize", {"amount": str(cents)})
        elif roll < 0.85:
            self._call(n, "transaction", {"amount": str(cents)})
        elif roll < 0.90:
            self.overdraw()
        elif self.last_done is not None:
            self.check_retry(self.last_done)

    def _key(self, n: int, part: str = "") -> str:
        return f"soak:{self.name}:{n}{part}"

    def _memo(self, n: int, part: str = "") -> str:
        return f"soak {self.name}#{n}{part}"

    def _call(self, n: int, op: str, args: dict[str, Any], resumed: bool = False) -> None:
        if not resumed:
            self.journal.write(n=n, phase="intent", op=op, args=args)
        for attempt in range(60):
            try:
                result = self._do(n, op, args)
            except StorageError:
                # The database refused or lost the call: the same key again
                # learns whether it committed, and makes it once if not.
                self.storage_errors += 1
                time.sleep(min(2.0, 0.05 * (attempt + 1)))
                continue
            except (BudgetExceededError, CircuitOpenError) as exc:
                self.journal.write(n=n, phase="refused", op=op, error=type(exc).__name__)
                if isinstance(exc, CircuitOpenError):
                    self.gov.reset(self.scope)
                return
            done = {"n": n, "phase": "done", "op": op, "args": args, "result": result}
            self.journal.write(**done)
            self.last_done = done
            return
        raise RuntimeError(f"{self.name}: operation {n} ({op}) kept failing with StorageError")

    def _do(self, n: int, op: str, args: dict[str, Any]) -> dict[str, Any]:
        gov, amount = self.gov, money(args["amount"])
        if op == "spend":
            entry = gov.spend(self.scope, amount, memo=self._memo(n), idempotency_key=self._key(n))
            self.spends.append((str(entry.entry_id), amount))
            return {"entry": str(entry.entry_id), "sequence": entry.sequence}
        if op == "refund":
            entry = gov.refund(
                self.scope,
                amount,
                reverses=uuid.UUID(args["reverses"]),
                memo=self._memo(n),
                idempotency_key=self._key(n),
            )
            self.spends = deque(
                ((e, left - amount if e == args["reverses"] else left) for e, left in self.spends),
                maxlen=64,
            )
            return {"entry": str(entry.entry_id), "sequence": entry.sequence}
        if op == "authorize":
            hold = gov.authorize(
                self.scope, amount, memo=self._memo(n, "h"), idempotency_key=self._key(n, "h")
            )
            settle = gov.authorization(hold.authorization_id)
            if args["then"] == "capture":
                if settle is None:
                    # The hold was settled before a SIGKILL: our own capture,
                    # the only thing that settles it, under its own key.
                    settle = hold
                cost = amount * Decimal("0.6")
                entry = gov.capture(
                    settle, cost, memo=self._memo(n), idempotency_key=self._key(n, "c")
                )
                return {"hold": str(hold.authorization_id), "entry": str(entry.entry_id)}
            entry = gov.void(settle or hold, idempotency_key=self._key(n, "v"))
            return {"hold": str(hold.authorization_id), "void": str(entry.entry_id)}
        if op == "try_authorize":
            placed = gov.try_authorize(
                self.scope, amount, memo=self._memo(n, "h"), idempotency_key=self._key(n, "h")
            )
            if placed is None:
                return {"hold": None}
            entry = gov.capture(
                gov.authorization(placed.authorization_id) or placed,
                amount,
                memo=self._memo(n),
                idempotency_key=self._key(n, "c"),
            )
            return {"hold": str(placed.authorization_id), "entry": str(entry.entry_id)}
        if op == "transaction":
            with gov.transaction() as txn:
                if txn.available(self.scope) < amount:
                    return {"hold": None}
                hold = txn.authorize(
                    self.scope, amount, memo=self._memo(n, "h"), idempotency_key=self._key(n, "h")
                )
                entry = txn.capture(
                    hold, amount, memo=self._memo(n), idempotency_key=self._key(n, "c")
                )
            return {"hold": str(hold.authorization_id), "entry": str(entry.entry_id)}
        raise ValueError(op)

    def overdraw(self) -> None:
        """Ask the fragile scope for more than it has: the breaker trips, and
        the worker resets it."""
        try:
            self.gov.authorize(self.fragile, money("1000"))
        except BudgetExceededError:
            self.trips += 1
        except CircuitOpenError:
            pass
        except StorageError:
            self.storage_errors += 1
            return
        try:
            self.gov.reset(self.fragile)
        except StorageError:
            self.storage_errors += 1

    def check_retry(self, done: dict[str, Any]) -> None:
        """The same call under the same key returns what it returned, and
        writes nothing."""
        op, args, n = done["op"], done["args"], done["n"]
        if op != "spend":
            return
        try:
            again = self._do(n, op, args)
        except StorageError:
            self.storage_errors += 1
            return
        if again != done["result"]:
            raise AssertionError(
                f"{self.name}: retrying {n} returned {again}, not {done['result']}"
            )
        if op == "spend":
            self.spends.pop()  # _do recorded it again
        self.retries_checked += 1


def _governor_process(
    url: str, index: int, threads: int, deadline: float, journals: str, stop: str
) -> None:
    """One governor, shared by ``threads`` workers, until the deadline."""
    gov = agentgov.open(url, policy=POLICY, auditor=False)
    stopping = threading.Event()
    workers = []
    for t in range(threads):
        name = f"g{index}t{t}"
        journal = Journal(Path(journals) / f"{name}.jsonl")
        workers.append(Worker(gov, name, journal, seed=hash((index, t, os.getpid()))))
    errors: list[BaseException] = []

    def run(worker: Worker) -> None:
        try:
            worker.run(deadline, stopping)
        except BaseException as exc:
            errors.append(exc)
            stopping.set()

    runs = [threading.Thread(target=run, args=(w,), name=w.name) for w in workers]
    for r in runs:
        r.start()
    while any(r.is_alive() for r in runs):
        if Path(stop).exists():
            stopping.set()
        time.sleep(0.2)
    stats = {
        w.name: {"retries": w.retries_checked, "storage_errors": w.storage_errors, "trips": w.trips}
        for w in workers
    }
    (Path(journals) / f"g{index}.stats.json").write_text(json.dumps(stats))
    gov.close()
    if errors:
        raise errors[0]


# -- the ledger, the fleet and the chaos -------------------------------------------------


class Target:
    """Where a soak runs: a fresh schema in a PostgreSQL database, or a fresh
    SQLite file."""

    def __init__(self, ledger: str) -> None:
        kind, target, _ = parse_url(ledger)
        self.kind = kind
        if kind == "postgres":
            self.schema = f"soak_{uuid.uuid4().hex[:10]}"
            self.base: dict[str, Any] = conninfo_to_dict(target)
        elif kind == "sqlite":
            self.path = Path(target).resolve()
            if self.path.exists():
                raise SystemExit(f"{self.path} exists: a soak starts from a fresh ledger")
        else:
            raise SystemExit("a soak needs a postgresql:// or sqlite:/// ledger")

    def url(self, app: str) -> str:
        if self.kind == "sqlite":
            return f"sqlite:///{self.path}"
        b = self.base
        return (
            f"postgresql://{quote(str(b.get('user', '')), safe='')}:"
            f"{quote(str(b.get('password', '')), safe='')}@{b.get('host', 'localhost')}:"
            f"{b.get('port', '5432')}/{b.get('dbname', 'postgres')}"
            f"?schema={self.schema}&application_name={app}"
        )

    def connect(self, app: str) -> psycopg.Connection[Any]:
        return psycopg.connect(
            make_conninfo(**{**self.base, "application_name": app}),
            autocommit=True,
            prepare_threshold=None,
        )

    def audit_marks(self) -> list[tuple[str, int, int]]:
        query = "SELECT status, count(*), max(sequence) FROM {} GROUP BY status"
        if self.kind == "sqlite":
            with closing(sqlite3.connect(self.path)) as conn:
                return list(conn.execute(query.format("audit_marks")))
        with self.connect("soak-check") as conn:
            rows = conn.execute(
                sql.SQL(query).format(sql.Identifier(self.schema, "audit_marks"))
            ).fetchall()
            return [(str(s), int(c), int(m)) for s, c, m in rows]


def _rss_kib(pid: int) -> int | None:
    out = subprocess.run(  # noqa: S603
        ["ps", "-o", "rss=", "-p", str(pid)],  # noqa: S607 - ps, wherever the OS keeps it
        capture_output=True,
        text=True,
    )
    text = out.stdout.strip()
    return int(text) if text.isdigit() else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--ledger", required=True, help="postgresql://... or sqlite:///path")
    parser.add_argument("--minutes", type=float, default=30.0)
    parser.add_argument("--governors", type=int, default=4, help="processes; 1 on SQLite")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--kill-every", type=float, default=30.0, help="mean seconds between kills")
    parser.add_argument("--cut-every", type=float, default=120.0, help="seconds between cuts")
    parser.add_argument("--workdir", default=None)
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    target = Target(args.ledger)
    shared = target.kind == "postgres"
    if not shared and args.governors != 1:
        parser.error("a SQLite ledger has one writer: --governors 1")
    work = Path(args.workdir or f"soak-{uuid.uuid4().hex[:8]}")
    journals = work / "journals"
    journals.mkdir(parents=True, exist_ok=True)
    stop = work / "stop"

    # The ledger: a root, and for every worker a scope to spend and a small
    # one to overdraw.
    names = [f"g{g}t{t}" for g in range(args.governors) for t in range(args.threads)]
    with agentgov.open(target.url("soak-setup"), policy=POLICY, auditor=False) as gov:
        gov.open_root("root", money("100000000"))
        for name in names:
            gov.delegate("root", f"w-{name}", money("1000000"))
            gov.delegate("root", f"x-{name}", money("1"))
    where = target.schema if shared else str(target.path)
    print(f"soak: {where}, {len(names)} workers, {args.minutes} minutes", flush=True)

    auditor = subprocess.Popen(  # noqa: S603 - our own interpreter and CLI
        [
            sys.executable,
            "-m",
            "agentgov.cli",
            "audit",
            "--follow",
            target.url("soak-auditor"),
            "--interval",
            "2",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    started = time.monotonic()
    deadline = started + args.minutes * 60
    calm_from = deadline - min(30.0, args.minutes * 60 / 4)  # no chaos at the end
    ctx = multiprocessing.get_context("spawn")

    def launch(index: int) -> multiprocessing.process.BaseProcess:
        proc = ctx.Process(
            target=_governor_process,
            args=(
                target.url(f"soak-g{index}"),
                index,
                args.threads,
                deadline,
                str(journals),
                str(stop),
            ),
        )
        proc.start()
        return proc

    procs = {g: launch(g) for g in range(args.governors)}
    rng = random.Random(7)  # noqa: S311 - a schedule, not a secret
    kills = cuts = 0
    rss: list[tuple[float, int]] = []
    conns: list[int] = []
    next_kill = started + rng.expovariate(1 / args.kill_every)
    next_cut = started + args.cut_every
    next_sample = started
    failures: list[str] = []
    monitor = target.connect("soak-monitor") if shared else None
    # On PostgreSQL the first governor is never killed, so its memory can be
    # followed; on SQLite the one governor is the one killed.
    victims = range(1, args.governors) if shared else range(0, 1)

    while time.monotonic() < deadline:
        now = time.monotonic()
        for g, proc in list(procs.items()):
            if not proc.is_alive() and now < deadline - 5:
                failures.append(f"governor process {g} ended early, with {proc.exitcode}")
                procs[g] = launch(g)
        if monitor is not None and now >= next_sample:
            next_sample = now + 10
            first = procs[0].pid
            sample = _rss_kib(first) if first is not None else None
            if sample is not None:
                rss.append((now - started, sample))
            (count,) = monitor.execute(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()"
            ).fetchone()  # type: ignore[misc]
            conns.append(int(count))
        if len(victims) and now >= next_kill and now < calm_from:
            victim = rng.choice(victims)
            pid = procs[victim].pid
            if pid is not None and procs[victim].is_alive():
                os.kill(pid, signal.SIGKILL)
                procs[victim].join(10)
                kills += 1
                time.sleep(rng.uniform(0.5, 2.0))
                procs[victim] = launch(victim)
            next_kill = now + rng.expovariate(1 / args.kill_every)
        if monitor is not None and now >= next_cut and now < calm_from:
            monitor.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                "WHERE datname = current_database() AND application_name LIKE 'soak-g%'"
            )
            cuts += 1
            next_cut = now + args.cut_every
        if auditor.poll() is not None:
            said = auditor.stdout.read() if auditor.stdout else ""
            failures.append(f"the auditor exited with {auditor.returncode}: {said}")
            break
        time.sleep(0.2)

    stop.touch()
    for proc in procs.values():
        proc.join(120)
        if proc.exitcode != 0:
            failures.append(f"a governor process ended with {proc.exitcode}")
    auditor.terminate()
    auditor.wait(30)

    report = check(target, journals, failures)
    report.update(
        ledger=where,
        minutes=args.minutes,
        governors=args.governors,
        threads=args.threads,
        kills=kills,
        connection_cuts=cuts,
        rss_kib=[s for _, s in rss],
        connections=conns,
    )
    if shared:
        _check_resources(report, rss, conns, args, failures)
    report["failures"] = failures
    print(
        json.dumps(
            {k: v for k, v in report.items() if k not in ("rss_kib", "connections")},
            indent=2,
            default=str,
        )
    )
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=2, default=str))
    if monitor is not None:
        monitor.close()
    return 1 if failures else 0


def _check_resources(
    report: dict[str, Any],
    rss: list[tuple[float, int]],
    conns: list[int],
    args: argparse.Namespace,
    failures: list[str],
) -> None:
    """Memory flat in the never-killed governor; connections bounded."""
    if len(rss) >= 9:
        third = len(rss) // 3
        early = statistics.median(s for _, s in rss[third : 2 * third])
        late = statistics.median(s for _, s in rss[2 * third :])
        report["rss_growth"] = round(late / early - 1, 3)
        if late > early * 1.25:
            failures.append(f"the first governor's memory grew from {early} to {late} KiB")
    # Each governor holds one connection; the auditor, the monitor, and a
    # process starting while one dies may add a few.
    bound = args.governors + 6
    report["max_connections"] = max(conns, default=0)
    if conns and max(conns) > bound:
        failures.append(f"{max(conns)} connections at once, more than {bound}")


def check(target: Target, journals: Path, failures: list[str]) -> dict[str, Any]:
    """Every invariant, against the ledger as the fleet left it."""
    with agentgov.open(
        target.url("soak-check"), read_only=True, verify="full", auditor=False
    ) as view:
        view.verify_integrity()
        view.ledger.verify_chain()
        view.ledger.verify_conservation()
        by_memo: Counter[str] = Counter()
        holds: Counter[str] = Counter()
        for entry in view.iter_audit_trail():  # streamed: the ledger may be millions long
            if entry.entry_type in MONEY_TYPES:
                by_memo[entry.memo] += 1
            elif entry.entry_type is EntryType.HOLD:
                holds[entry.memo] += 1
        length = len(view.ledger)
    done = refused = 0
    expected: Counter[str] = Counter()
    for path in sorted(journals.glob("*.jsonl")):
        name = path.stem
        lines = [json.loads(raw) for raw in path.read_text().splitlines() if raw.strip()]
        finished = {line["n"] for line in lines if line["phase"] != "intent"}
        unfinished = [x for x in lines if x["phase"] == "intent" and x["n"] not in finished]
        if unfinished:
            failures.append(f"{name}: operations begun and never finished: {unfinished[:3]}")
        for line in lines:
            if line["phase"] == "refused":
                refused += 1
            if line["phase"] != "done":
                continue
            done += 1
            n, op, result = line["n"], line["op"], line["result"]
            memo = f"soak {name}#{n}"
            if op in {"spend", "refund"} or result.get("entry"):
                expected[memo] += 1
            if result.get("hold"):
                if holds[memo + "h"] != 1:
                    failures.append(f"{name}#{n}: {holds[memo + 'h']} holds, not one")
    for memo, count in expected.items():
        if by_memo[memo] != count:
            failures.append(f"{memo}: {by_memo[memo]} money entries in the ledger, not {count}")
    strays = [m for m in by_memo if m.startswith("soak ") and m not in expected]
    if strays:
        failures.append(f"money entries no worker finished: {strays[:5]}")
    stats: dict[str, Any] = {}
    for path in journals.glob("g*.stats.json"):
        stats.update(json.loads(path.read_text()))
    audit = {status: {"marks": count, "to": top} for status, count, top in target.audit_marks()}
    if "failed" in audit:
        failures.append(f"the auditor recorded failures: {audit['failed']}")
    if not audit.get("verified"):
        failures.append("the auditor recorded no verified mark")
    return {
        "entries": length,
        "operations_done": done,
        "operations_refused": refused,
        "money_entries_checked": len(expected),
        "retries_checked": sum(s["retries"] for s in stats.values()),
        "storage_errors_retried": sum(s["storage_errors"] for s in stats.values()),
        "trips": sum(s["trips"] for s in stats.values()),
        "audit": audit,
    }


if __name__ == "__main__":
    sys.exit(main())
