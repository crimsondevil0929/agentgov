"""Execute every Python block in README.md.

A README that cannot be copied and run is a README that has already drifted.
This module extracts each ``python`` fence, runs it in a scratch directory
against a prepared database, and fails the build when one of them stops
working.

Three gates, weakest to strongest:

1. **Parse.** Every block must be syntactically valid Python.
2. **Resolve.** Every ``from agentgov import X`` must name something that
   exists, and every backticked ``symbol()`` in the prose must resolve to a
   real attribute of the package. This is the gate that catches a README
   documenting a function nobody shipped — which is exactly what
   ``normalize_model_id()`` was for one release.
3. **Run.** Every block executes, unless it carries an explicit opt-out.

Most blocks here call a model provider, so they carry ``skip`` with a reason.
Gates 1 and 2 still apply to them, and those are the gates that catch API
drift; only the network call is excluded.

Opting out is deliberate and reviewable. Put an HTML comment directly above
the fence::

    <!-- readme-test: skip reason="needs a live provider client" -->

A ``skip`` without a ``reason`` is itself a failure, so a block can never be
quietly excluded. ``<!-- readme-test: continue -->`` runs a block in the
namespace left by the previous one, for a narrative split across fences.
"""

from __future__ import annotations

import ast
import importlib
import re
from pathlib import Path
from typing import Any

import pytest

import agentgov

README = Path(__file__).resolve().parent.parent / "README.md"
PACKAGE = "agentgov"

_BLOCK = re.compile(
    r"(?:<!--\s*readme-test:(?P<directive>.*?)-->\s*\n)?```python\n(?P<code>.*?)```",
    re.S,
)
_DIRECTIVE_REASON = re.compile(r'reason="(?P<reason>[^"]*)"')
_PROSE_SYMBOL = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\(\)`")

#: Backticked ``name()`` tokens in the prose that are not AgentGov API.
#: Every entry is a deliberate exemption; an unknown symbol fails the build.
PROSE_EXEMPT = frozenset(
    {
        "client.messages.create",
        "evaluate",
        "graph.invoke",
        "crew.kickoff",
        "model.invoke",
        "pip.install",
        "repr",
    }
)


class Block:
    """One fenced block, with its directive."""

    def __init__(self, index: int, code: str, directive: str) -> None:
        self.index = index
        self.code = code
        self.directive = directive.strip()

    @property
    def skipped(self) -> bool:
        return self.directive.startswith("skip")

    @property
    def continues(self) -> bool:
        return "continue" in self.directive

    @property
    def reason(self) -> str:
        found = _DIRECTIVE_REASON.search(self.directive)
        return found.group("reason") if found else ""

    def __repr__(self) -> str:
        return f"block#{self.index}"


def _blocks() -> list[Block]:
    text = README.read_text(encoding="utf-8")
    return [
        Block(i, m.group("code"), m.group("directive") or "")
        for i, m in enumerate(_BLOCK.finditer(text))
    ]


BLOCKS = _blocks()


def _seed(directory: Path) -> Path:
    """A governor database for blocks that open one.

    Left empty deliberately: ``BudgetManager.open_sqlite`` creates and
    verifies its own file, and seeding one here would test this fixture
    rather than the README.
    """
    return directory / "governor.db"


def test_readme_has_python_blocks() -> None:
    """A README with no executable blocks would pass every other test here."""
    assert BLOCKS, "README.md contains no ```python blocks"


@pytest.mark.parametrize("block", BLOCKS, ids=repr)
def test_block_parses(block: Block) -> None:
    """Gate 1: every block is valid Python, including the skipped ones."""
    ast.parse(block.code)


@pytest.mark.parametrize("block", BLOCKS, ids=repr)
def test_block_imports_resolve(block: Block) -> None:
    """Gate 2: every name imported from this package actually exists."""
    tree = ast.parse(block.code)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith(PACKAGE):
            module = _import_module(node.module or PACKAGE)
            for alias in node.names:
                assert hasattr(module, alias.name), (
                    f"{block}: README imports {alias.name!r} from "
                    f"{node.module!r}, which does not export it"
                )


@pytest.mark.parametrize("block", BLOCKS, ids=repr)
def test_skip_carries_a_reason(block: Block) -> None:
    """A block can be excluded, but never silently."""
    if block.skipped:
        assert block.reason, f"{block}: 'skip' needs reason=\"...\" so the exclusion is reviewable"


def test_prose_symbols_resolve() -> None:
    """Gate 2, continued: backticked ``symbol()`` in prose must be real.

    This is the gate that would have caught a README naming a function that
    only ever existed in an unreleased branch.
    """
    text = README.read_text(encoding="utf-8")
    unresolved: list[str] = []
    for symbol in sorted(set(_PROSE_SYMBOL.findall(text))):
        if symbol in PROSE_EXEMPT or not _resolves(symbol):
            if symbol not in PROSE_EXEMPT:
                unresolved.append(symbol)
    assert not unresolved, (
        "README names these symbols in prose but the package does not provide "
        f"them: {', '.join(unresolved)}. Fix the name, ship the symbol, or add "
        "it to PROSE_EXEMPT with a reason."
    )


def test_all_blocks_execute(tmp_path: Path) -> None:
    """Gate 3: run them, in order, sharing a namespace where asked."""
    import os

    seeded = _seed(tmp_path)
    previous = os.getcwd()
    namespace: dict[str, Any] = {}
    os.chdir(tmp_path)
    try:
        for block in BLOCKS:
            if block.skipped:
                continue
            if not block.continues:
                namespace = {"__name__": "__readme__"}
                # Each independent block gets a pristine database, so block
                # order never becomes a hidden dependency.
                seeded.unlink(missing_ok=True)
                for stale in tmp_path.glob("*.db*"):
                    stale.unlink()
            try:
                # S102: executing the README is the entire purpose of this
                # module. The input is a file in this repository, reviewed in
                # the same pull request as the code it documents.
                exec(  # noqa: S102
                    compile(block.code, f"README.md::{block}", "exec"), namespace
                )
            except Exception as exc:
                pytest.fail(
                    f"{block} failed to run verbatim: {type(exc).__name__}: {exc}\n"
                    f"--- block ---\n{block.code}"
                )
    finally:
        os.chdir(previous)


def _import_module(dotted: str) -> Any:
    """Import a dotted submodule. ``getattr`` is not enough: a subpackage that
    ``__init__`` does not itself import is absent as an attribute."""
    return importlib.import_module(dotted)


def _resolves(symbol: str) -> bool:
    """Whether ``a.b()`` names something reachable from the package."""
    head, *rest = symbol.split(".")
    target: Any = getattr(agentgov, head, None)
    if target is None:
        # A subpackage is an attribute only once something has imported it,
        # so ``receipts.verify_bundle()`` must not depend on test order.
        try:
            target = _import_module(f"{PACKAGE}.{head}")
        except ImportError:
            target = None
    if target is None:
        # Bare method names like ``verify()`` resolve against any export.
        return any(
            hasattr(getattr(agentgov, name), head)
            for name in agentgov.__all__
            if isinstance(getattr(agentgov, name, None), type)
        )
    for part in rest:
        target = getattr(target, part, None)
        if target is None:
            return False
    return True


# --------------------------------------------------------------------------
# Badges state only what CI enforces
# --------------------------------------------------------------------------

_CI = README.parent / ".github" / "workflows" / "ci.yml"
_BADGE = re.compile(r"\[!\[(?P<alt>[^\]]*)\]\((?P<url>https://img\.shields\.io/[^)]*)\)\]")


def test_no_badge_claims_a_number_ci_does_not_enforce() -> None:
    """A hard-coded "338/338 passing" was stale within a release. A count is
    only true on the commit it was typed on; the CI badge is the live one."""
    for badge in _BADGE.finditer(README.read_text(encoding="utf-8")):
        url = badge["url"]
        assert "/badge/tests-" not in url, f"static test-count badge: {url}"
        assert not re.search(r"/badge/coverage-\d", url), f"static coverage figure: {url}"


def test_the_coverage_floor_badge_matches_the_floor_ci_enforces() -> None:
    floors = re.findall(r"--fail-under[= ](\d+)", _CI.read_text(encoding="utf-8"))
    assert floors, "ci.yml no longer enforces a coverage floor"
    badges = [
        b["url"]
        for b in _BADGE.finditer(README.read_text(encoding="utf-8"))
        if "coverage%20floor" in b["url"]
    ]
    assert len(badges) == 1, "exactly one coverage-floor badge"
    assert f"floor-{floors[0]}%25" in badges[0], (badges[0], floors)
