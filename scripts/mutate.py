#!/usr/bin/env python3
"""Mutation testing for agentgov: does every mechanism have a test that needs it?

For each target function this generates *mutants* (small, plausible defects)
one at a time, runs the chosen tests against each, and reports which mutants
the tests *killed* (some test failed) and which *survived* (every test still
passed). A surviving mutant is a change to the code that no test notices:
either a missing test, or an equivalent mutant that changes nothing
observable, which must then be justified by name in the spec's
``equivalent`` table.

Two families of mutation:

- **operators**: comparisons (``<`` and ``<=``, ``==`` and ``!=``, ``is``,
  ``in``), boolean ``and``/``or``, ``not`` removed, ``+``/``-``, integer and
  boolean constants;
- **mechanisms**, as Interlock's passes remove them: a ``raise`` removed (a
  guard gone), an ``if`` forced true or false, a call made for its effect
  removed, an assignment to an attribute or item removed (a state update
  gone), a ``return`` value replaced by ``None``.

Each mutant has an id derived from what it changes (the function, the
operator, the source text of the node and its occurrence), not from line
numbers, so a justification survives unrelated edits.

Usage::

    uv run python scripts/mutate.py mutation/phase2.json --jobs 8

The spec is JSON::

    {
      "targets": ["src/agentgov/core.py::_Overlay.apply", ...],
      "tests": ["tests/test_rule_engine.py", ...],
      "env": {"AGENTGOV_MODEL_EXAMPLES": "150"},
      "equivalent": {"<mutant id>": "why no test can tell it apart", ...}
    }

The tests run against a copy of ``src/`` placed first on ``PYTHONPATH``, so
the checkout is never modified, and child processes the tests spawn see the
mutant too.
"""

from __future__ import annotations

import argparse
import ast
import concurrent.futures
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

_COMPARE_SWAPS: dict[type[ast.cmpop], type[ast.cmpop]] = {
    ast.Lt: ast.LtE,
    ast.LtE: ast.Lt,
    ast.Gt: ast.GtE,
    ast.GtE: ast.Gt,
    ast.Eq: ast.NotEq,
    ast.NotEq: ast.Eq,
    ast.Is: ast.IsNot,
    ast.IsNot: ast.Is,
    ast.In: ast.NotIn,
    ast.NotIn: ast.In,
}
_BINOP_SWAPS: dict[type[ast.operator], type[ast.operator]] = {
    ast.Add: ast.Sub,
    ast.Sub: ast.Add,
}
_SYMBOL = {
    ast.Lt: "<",
    ast.LtE: "<=",
    ast.Gt: ">",
    ast.GtE: ">=",
    ast.Eq: "==",
    ast.NotEq: "!=",
    ast.Is: "is",
    ast.IsNot: "is not",
    ast.In: "in",
    ast.NotIn: "not in",
    ast.Add: "+",
    ast.Sub: "-",
    ast.And: "and",
    ast.Or: "or",
}


@dataclass(frozen=True)
class Mutant:
    """One defect, applied to one function."""

    mutant_id: str
    path: str
    function: str
    line: int
    description: str
    source: str  # the whole module, mutated


@dataclass
class Result:
    mutant_id: str
    path: str
    function: str
    line: int
    description: str
    status: str  # killed | survived | timeout | invalid | equivalent
    seconds: float
    detail: str = ""
    justification: str = ""


@dataclass
class Report:
    spec: str
    targets: list[str]
    tests: list[str]
    results: list[Result] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            counts[result.status] = counts.get(result.status, 0) + 1
        return counts

    def kill_rate(self) -> float:
        counts = self.counts()
        killable = sum(counts.get(s, 0) for s in ("killed", "timeout", "survived"))
        if killable == 0:
            return 1.0
        return (counts.get("killed", 0) + counts.get("timeout", 0)) / killable


# --------------------------------------------------------------------------
# Generating mutants
# --------------------------------------------------------------------------


def _find_function(tree: ast.Module, qualname: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    scope: list[ast.stmt] = tree.body
    found: ast.AST | None = None
    for part in qualname.split("."):
        found = next(
            (
                node
                for node in scope
                if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
                and node.name == part
            ),
            None,
        )
        if found is None:
            raise SystemExit(f"no {qualname!r}: {part!r} not found")
        scope = found.body  # type: ignore[union-attr]
    if not isinstance(found, ast.FunctionDef | ast.AsyncFunctionDef):
        raise SystemExit(f"{qualname!r} is not a function")
    return found


def _body_without_docstring(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.stmt]:
    body = fn.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


def _walk(nodes: list[ast.stmt]) -> Iterator[ast.AST]:
    for node in nodes:
        yield from ast.walk(node)


def _short(node: ast.AST) -> str:
    text = ast.unparse(node).replace("\n", " ")
    return text if len(text) <= 70 else text[:67] + "..."


def _points(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, str, list[int]]]:
    """Every mutation point in ``fn``: (operator, detail, path to the node).

    A path is the sequence of child indices from ``fn`` to the node, so the
    same point can be found again in a fresh copy of the tree.
    """
    paths: dict[int, list[int]] = {}

    def index(node: ast.AST, path: list[int]) -> None:
        paths[id(node)] = path
        for i, child in enumerate(ast.iter_child_nodes(node)):
            index(child, [*path, i])

    index(fn, [])
    body = _body_without_docstring(fn)
    points: list[tuple[str, str, list[int]]] = []
    for node in _walk(body):
        path = paths[id(node)]
        if isinstance(node, ast.Compare):
            for i, op in enumerate(node.ops):
                swap = _COMPARE_SWAPS.get(type(op))
                if swap is not None:
                    detail = f"{_SYMBOL[type(op)]} -> {_SYMBOL[swap]} in `{_short(node)}`#{i}"
                    points.append(("compare", detail, [*path, -1 - i]))
        elif isinstance(node, ast.BoolOp):
            other = "or" if isinstance(node.op, ast.And) else "and"
            detail = f"{_SYMBOL[type(node.op)]} -> {other} in `{_short(node)}`"
            points.append(("boolop", detail, path))
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            points.append(("not", f"drop `not` in `{_short(node)}`", path))
        elif isinstance(node, ast.BinOp) and type(node.op) in _BINOP_SWAPS:
            swap = _BINOP_SWAPS[type(node.op)]
            points.append(
                ("binop", f"{_SYMBOL[type(node.op)]} -> {_SYMBOL[swap]} in `{_short(node)}`", path)
            )
        elif isinstance(node, ast.Constant):
            if isinstance(node.value, bool):
                points.append(("constant", f"{node.value} -> {not node.value}", path))
            elif isinstance(node.value, int):
                points.append(("constant", f"{node.value} -> {node.value + 1}", path))
        elif isinstance(node, ast.Raise):
            points.append(("raise", f"remove `{_short(node)}`", path))
        elif isinstance(node, ast.If):
            points.append(("if-true", f"`if {_short(node.test)}` -> always", path))
            points.append(("if-false", f"`if {_short(node.test)}` -> never", path))
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call | ast.Await):
            points.append(("call", f"remove `{_short(node)}`", path))
        elif isinstance(node, ast.Assign | ast.AugAssign) and any(
            isinstance(t, ast.Attribute | ast.Subscript)
            for t in (node.targets if isinstance(node, ast.Assign) else [node.target])
        ):
            points.append(("assign", f"remove `{_short(node)}`", path))
        elif isinstance(node, ast.Return) and node.value is not None:
            if not (isinstance(node.value, ast.Constant) and node.value.value is None):
                points.append(("return", f"`{_short(node)}` -> `return None`", path))
        elif isinstance(node, ast.Continue | ast.Break):
            points.append(("loop", f"remove `{_short(node)}`", path))
    return points


def _resolve(fn: ast.AST, path: list[int]) -> tuple[ast.AST, ast.AST | None, int | None]:
    """The node at ``path`` (a negative last step names a comparison operator)."""
    parent: ast.AST | None = None
    node = fn
    last: int | None = None
    for step in path:
        if step < 0:
            return node, parent, step
        parent = node
        last = step
        node = list(ast.iter_child_nodes(node))[step]
    return node, parent, last


def _replace_statement(parent: ast.AST, target: ast.AST, replacement: list[ast.stmt]) -> None:
    for name, value in ast.iter_fields(parent):
        if isinstance(value, list) and any(item is target for item in value):
            position = next(i for i, item in enumerate(value) if item is target)
            new = [*value[:position], *replacement, *value[position + 1 :]]
            setattr(parent, name, new or [ast.Pass()])
            return
    raise ValueError("statement not found in its parent")


def _mutate(fn: ast.FunctionDef | ast.AsyncFunctionDef, kind: str, path: list[int]) -> None:
    node, parent, step = _resolve(fn, path)
    if kind == "compare":
        assert isinstance(node, ast.Compare) and step is not None
        i = -1 - step
        node.ops[i] = _COMPARE_SWAPS[type(node.ops[i])]()
    elif kind == "boolop":
        assert isinstance(node, ast.BoolOp)
        node.op = ast.Or() if isinstance(node.op, ast.And) else ast.And()
    elif kind == "not":
        assert isinstance(node, ast.UnaryOp) and parent is not None
        _swap_child(parent, node, node.operand)
    elif kind == "binop":
        assert isinstance(node, ast.BinOp)
        node.op = _BINOP_SWAPS[type(node.op)]()
    elif kind == "constant":
        assert isinstance(node, ast.Constant)
        node.value = (not node.value) if isinstance(node.value, bool) else node.value + 1
    elif kind in ("raise", "call", "assign", "loop"):
        assert parent is not None
        _replace_statement(parent, node, [ast.Pass()])
    elif kind == "if-true":
        assert isinstance(node, ast.If)
        node.test = ast.Constant(value=True)
    elif kind == "if-false":
        assert isinstance(node, ast.If)
        node.test = ast.Constant(value=False)
    elif kind == "return":
        assert isinstance(node, ast.Return)
        node.value = ast.Constant(value=None)
    else:  # pragma: no cover - every kind above
        raise ValueError(kind)


def _swap_child(parent: ast.AST, old: ast.AST, new: ast.AST) -> None:
    for name, value in ast.iter_fields(parent):
        if value is old:
            setattr(parent, name, new)
            return
        if isinstance(value, list):
            for i, item in enumerate(value):
                if item is old:
                    value[i] = new
                    return
    raise ValueError("child not found")


def generate(path: str, qualname: str) -> list[Mutant]:
    source = (ROOT / path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    fn = _find_function(tree, qualname)
    start = (fn.decorator_list[0].lineno if fn.decorator_list else fn.lineno) - 1
    end = fn.end_lineno or fn.lineno
    lines = source.splitlines(keepends=True)
    indent = " " * fn.col_offset
    mutants: list[Mutant] = []
    seen: dict[str, int] = {}
    for kind, detail, node_path in _points(fn):
        fresh = copy.deepcopy(fn)
        try:
            _mutate(fresh, kind, node_path)
        except (AssertionError, ValueError, IndexError):
            continue
        body = textwrap.indent(ast.unparse(ast.fix_missing_locations(fresh)), indent)
        mutated = "".join(lines[:start]) + body + "\n" + "".join(lines[end:])
        try:
            compile(mutated, path, "exec")
        except SyntaxError:
            continue
        key = f"{path}::{qualname}::{kind}::{detail}"
        seen[key] = seen.get(key, 0) + 1
        mutant_id = key if seen[key] == 1 else f"{key}::{seen[key]}"
        node, _, _ = _resolve(fn, [s for s in node_path if s >= 0])
        mutants.append(
            Mutant(
                mutant_id=mutant_id,
                path=path,
                function=qualname,
                line=getattr(node, "lineno", fn.lineno),
                description=f"{kind}: {detail}",
                source=mutated,
            )
        )
    return mutants


# --------------------------------------------------------------------------
# Running them
# --------------------------------------------------------------------------

_WORKER: dict[str, Any] = {}


def _init_worker(tests: list[str], env: dict[str, str], timeout: float) -> None:
    workdir = Path(tempfile.mkdtemp(prefix="agentgov-mutant-"))
    shutil.copytree(ROOT / "src", workdir / "src")
    _WORKER.update(workdir=workdir, tests=tests, env=env, timeout=timeout)


def _run(mutant: Mutant) -> Result:
    workdir: Path = _WORKER["workdir"]
    target = workdir / mutant.path
    original = target.read_text(encoding="utf-8")
    target.write_text(mutant.source, encoding="utf-8")
    env = {**os.environ, **_WORKER["env"], "PYTHONPATH": str(workdir / "src")}
    env.pop("PYTHONDONTWRITEBYTECODE", None)
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 - our own interpreter and tests
            [
                sys.executable,
                "-m",
                "pytest",
                "-x",
                "-q",
                "-p",
                "no:cacheprovider",
                "-p",
                "no:randomly",
                "--no-header",
                *_WORKER["tests"],
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=_WORKER["timeout"],
            check=False,
        )
        seconds = time.monotonic() - started
        if completed.returncode == 0:
            status, detail = "survived", ""
        elif completed.returncode in (1,):
            status = "killed"
            failed = [line for line in completed.stdout.splitlines() if line.startswith("FAILED")]
            detail = failed[0][7:] if failed else completed.stdout[-300:]
        else:
            # 2: collection or usage error (an import the mutant broke);
            # anything else: an interpreter crash. Either way, noticed.
            status = "killed"
            detail = f"pytest exited {completed.returncode}"
    except subprocess.TimeoutExpired:
        seconds = time.monotonic() - started
        status, detail = "timeout", f"no result within {_WORKER['timeout']:.0f}s"
    finally:
        target.write_text(original, encoding="utf-8")
    return Result(
        mutant_id=mutant.mutant_id,
        path=mutant.path,
        function=mutant.function,
        line=mutant.line,
        description=mutant.description,
        status=status,
        seconds=round(seconds, 2),
        detail=detail,
    )


def _baseline(tests: list[str], env: dict[str, str]) -> float:
    started = time.monotonic()
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *tests],
        cwd=ROOT,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        print(completed.stdout[-2000:], file=sys.stderr)
        raise SystemExit("the tests fail without any mutant; fix that first")
    return time.monotonic() - started


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("spec", help="the JSON spec: targets, tests, env, equivalent")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    parser.add_argument("--only", default="", help="run only mutants whose id contains this")
    parser.add_argument("--ids", default="", help="run only the mutants listed in this file")
    parser.add_argument(
        "--shard", default="", help="run only every Nth mutant, from the Kth: K/N, 0 <= K < N"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.0,
        help="seconds a mutant's tests may run (default: four times an unmutated run); "
        "raise it on a loaded machine, where a slow survivor would count as a timeout",
    )
    parser.add_argument("--list", action="store_true", help="list the mutants and stop")
    parser.add_argument("--out", default="", help="write the JSON report here")
    args = parser.parse_args()

    spec = json.loads(Path(args.spec).read_text(encoding="utf-8"))
    targets: list[str] = spec["targets"]
    tests: list[str] = spec["tests"]
    env: dict[str, str] = spec.get("env", {})
    equivalent: dict[str, str] = spec.get("equivalent", {})

    mutants: list[Mutant] = []
    for target in targets:
        path, _, qualname = target.partition("::")
        mutants.extend(generate(path, qualname))
    # A justification is stale when no mutant has its id any more, whichever run.
    stale = set(equivalent) - {m.mutant_id for m in mutants}
    if args.only:
        mutants = [m for m in mutants if args.only in m.mutant_id]
    if args.ids:
        wanted = set(Path(args.ids).read_text(encoding="utf-8").split("\n")) - {""}
        mutants = [m for m in mutants if m.mutant_id in wanted]
    if args.shard:
        index, _, count = args.shard.partition("/")
        if not (index.isdigit() and count.isdigit() and int(index) < int(count)):
            raise SystemExit(f"--shard takes K/N with 0 <= K < N, not {args.shard!r}")
        mutants = mutants[int(index) :: int(count)]
    if args.list:
        for mutant in mutants:
            print(f"{mutant.path}:{mutant.line}  {mutant.mutant_id}")
        print(f"{len(mutants)} mutants", file=sys.stderr)
        return

    baseline = _baseline(tests, env)
    timeout = args.timeout or max(60.0, baseline * 4)
    print(
        f"{len(mutants)} mutants over {len(targets)} functions; the tests take "
        f"{baseline:.1f}s unmutated; {args.jobs} jobs, {timeout:.0f}s timeout",
        file=sys.stderr,
    )
    report = Report(spec=args.spec, targets=targets, tests=tests)
    with concurrent.futures.ProcessPoolExecutor(
        max_workers=args.jobs, initializer=_init_worker, initargs=(tests, env, timeout)
    ) as pool:
        for done, result in enumerate(pool.map(_run, mutants), start=1):
            if result.mutant_id in equivalent:
                if result.status == "survived":
                    result.status = "equivalent"
                    result.justification = equivalent[result.mutant_id]
            report.results.append(result)
            marker = {"killed": ".", "timeout": "T", "survived": "S", "equivalent": "e"}
            print(marker.get(result.status, "?"), end="" if done % 80 else "\n", flush=True)
    print(file=sys.stderr)

    # A kill by a test that bounds time (a stall, a lock wait) may be the
    # parallel load's doing, not the mutant's: run those again, alone, and
    # count them only if they fail again.
    timing = tuple(spec.get("recheck", ()))
    suspect = [
        r for r in report.results if r.status == "killed" and any(t in r.detail for t in timing)
    ]
    if suspect:
        print(
            f"rechecking {len(suspect)} kill(s) by timing-bound tests, one at a time",
            file=sys.stderr,
        )
        by_id = {m.mutant_id: m for m in mutants}
        _init_worker(tests, env, timeout)
        for result in suspect:
            again = _run(by_id[result.mutant_id])
            if again.status == "survived":
                result.status = "survived"
                result.detail = f"killed only under load ({result.detail}); survived alone"
                if result.mutant_id in equivalent:
                    result.status = "equivalent"
                    result.justification = equivalent[result.mutant_id]

    counts = report.counts()
    print(json.dumps(counts, sort_keys=True), file=sys.stderr)
    print(f"kill rate (equivalents excluded): {report.kill_rate():.2%}", file=sys.stderr)
    for result in report.results:
        if result.status == "survived":
            print(f"SURVIVED {result.path}:{result.line} {result.mutant_id}", file=sys.stderr)
    if stale:
        print(f"{len(stale)} equivalence justification(s) name no current mutant:", file=sys.stderr)
        for mutant_id in sorted(stale):
            print(f"  STALE {mutant_id}", file=sys.stderr)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(
            json.dumps(
                {
                    "spec": report.spec,
                    "targets": report.targets,
                    "tests": report.tests,
                    "counts": counts,
                    "kill_rate": round(report.kill_rate(), 4),
                    "results": [asdict(r) for r in report.results],
                },
                indent=1,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
    if counts.get("survived"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
