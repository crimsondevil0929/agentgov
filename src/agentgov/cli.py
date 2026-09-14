"""``agentgov`` — inspect and verify a ledger from the terminal.

Two commands, aimed at two different readers:

``agentgov inspect <db>``
    For a developer: the double-entry ledger, the balance tree, and breaker
    status, formatted to be read.

``agentgov verify <db>``
    For a pipeline: re-derives the hash chain, the balance cache, the
    conservation identity, and the delegation topology, then exits ``0`` or
    ``1``. Drop it in CI to assert an archived ledger is intact.

Both open the database **read-only**, so they are safe to run against a
governor that is live and holding the write claim.

Standard library only — argparse and nothing else, so the CLI costs the
package no dependencies.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from decimal import Decimal
from typing import TextIO

from agentgov.core import BudgetManager, BudgetNode, EntryType, format_audit_line
from agentgov.exceptions import AgentGovError, LedgerError

__all__ = ["main"]

_DIRECTION_SIGN = {"DR": "-", "CR": "+"}


def _open(path: str) -> BudgetManager:
    """Open a ledger for audit, never claiming it away from a live governor."""
    return BudgetManager.open_sqlite(path, read_only=True)


def _money(amount: Decimal) -> str:
    return f"${amount:,.8f}"


def _render_tree(
    manager: BudgetManager,
    node: BudgetNode,
    out: TextIO,
    prefix: str = "",
    *,
    is_last: bool = True,
    is_root: bool = True,
) -> None:
    """Print one scope and its descendants as an indented tree."""
    halted = manager.halted_by(node.scope_id)
    status = "" if halted is None else f"   [HALTED by {halted}]"
    label = (
        f"{node.scope_id}  available {_money(manager.available(node.scope_id))}"
        f"  of {_money(node.allocated)}{status}"
    )
    if is_root:
        out.write(f"  {label}\n")
        child_prefix = "  "
    else:
        out.write(f"{prefix}{'`- ' if is_last else '|- '}{label}\n")
        child_prefix = prefix + ("   " if is_last else "|  ")

    children = [manager.node(child) for child in node.child_ids]
    for index, child in enumerate(children):
        _render_tree(
            manager,
            child,
            out,
            child_prefix,
            is_last=index == len(children) - 1,
            is_root=False,
        )


def _command_inspect(args: argparse.Namespace, out: TextIO) -> int:
    """Print the ledger, the balance tree, and breaker status."""
    manager = _open(args.path)
    try:
        entries = manager.audit_trail()
        scopes = manager.scopes()

        out.write(f"\nLEDGER  {args.path}\n")
        out.write(
            f"  {len(entries):,} hash-chained entries across {len(scopes)} scopes; "
            f"head {manager.ledger.head_hash[:16]}\n"
        )

        out.write("\nBALANCE TREE\n")
        if not scopes:
            out.write("  (no scopes)\n")
        for scope in scopes:
            node = manager.node(scope)
            if node.parent_id is None:
                _render_tree(manager, node, out)

        out.write("\nTOTALS\n")
        spent = sum((e.amount for e in entries if e.entry_type is EntryType.SPEND), Decimal(0))
        funded = sum((e.amount for e in entries if e.entry_type is EntryType.FUNDING), Decimal(0))
        held = sum(
            (
                e.signed_amount
                for e in entries
                if e.entry_type in (EntryType.HOLD, EntryType.HOLD_VOID)
            ),
            Decimal(0),
        )
        out.write(f"  funded          {_money(funded)}\n")
        out.write(f"  settled spend   {_money(spent)}\n")
        out.write(f"  holds open      {_money(-held)}\n")
        out.write(f"  unspent         {_money(funded - spent + held)}\n")

        events = manager.control_events
        out.write(f"\nCIRCUIT BREAKER  ({len(events)} control events)\n")
        halted = [s for s in scopes if manager.halted_by(s) is not None]
        if not halted:
            out.write("  all scopes running\n")
        else:
            out.write(f"  {len(halted)}/{len(scopes)} scopes halted\n")
        for event in events[-args.events :] if args.events else ():
            out.write(
                f"  {event.timestamp:%Y-%m-%d %H:%M:%S}  {event.event_type:<16} "
                f"{event.scope_id}  {event.reason}\n"
            )

        shown = entries[-args.limit :] if args.limit else entries
        out.write(f"\nENTRIES  (last {len(shown):,} of {len(entries):,})\n")
        for entry in shown:
            if args.raw:
                out.write(f"  {format_audit_line(entry)}\n")
            else:
                sign = _DIRECTION_SIGN[entry.direction.value]
                out.write(
                    f"  {entry.sequence:>8}  {entry.timestamp:%H:%M:%S}  "
                    f"{entry.entry_type.value:<10} {entry.scope_id:<22} "
                    f"{sign}{entry.amount:>14}  bal {entry.balance_after:>14}"
                    f"  {entry.memo}\n"
                )
        out.write("\n")
        return 0
    finally:
        manager.close()


def _command_verify(args: argparse.Namespace, out: TextIO) -> int:
    """Re-derive every invariant and report PASS/FAIL for a pipeline."""
    try:
        manager = _open(args.path)
    except AgentGovError as exc:
        out.write(f"FAIL  {args.path}\n  could not open: {exc}\n")
        return 1

    try:
        checks: list[tuple[str, str | None]] = []
        for label, check in (
            ("hash chain + balance cache", manager.ledger.verify_chain),
            ("conservation identity", manager.ledger.verify_conservation),
            ("delegation topology", manager.verify_integrity),
        ):
            try:
                check()
                checks.append((label, None))
            except LedgerError as exc:
                checks.append((label, str(exc)))

        failures = [(label, detail) for label, detail in checks if detail is not None]
        entries = len(manager.audit_trail())
        for label, detail in checks:
            mark = "ok  " if detail is None else "FAIL"
            out.write(f"  {mark}  {label}\n")
            if detail is not None:
                out.write(f"        {detail}\n")

        if failures:
            out.write(f"\nFAIL  {args.path}  ({len(failures)} of {len(checks)} checks failed)\n")
            return 1
        out.write(
            f"\nPASS  {args.path}  "
            f"({entries:,} entries verified; head {manager.ledger.head_hash[:16]})\n"
        )
        return 0
    finally:
        manager.close()


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="agentgov",
        description="Inspect and verify an AgentGov ledger. Both commands open "
        "the database read-only and are safe to run against a live governor.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    inspect = subcommands.add_parser(
        "inspect", help="print the ledger, balance tree, and breaker status"
    )
    inspect.add_argument("path", help="path to the SQLite ledger")
    inspect.add_argument(
        "--limit", type=int, default=20, help="entries to show, 0 for all (default: 20)"
    )
    inspect.add_argument(
        "--events", type=int, default=5, help="control events to show, 0 for none (default: 5)"
    )
    inspect.add_argument(
        "--raw", action="store_true", help="print the fixed-field audit format instead"
    )
    inspect.set_defaults(handler=_command_inspect)

    verify = subcommands.add_parser(
        "verify", help="re-derive every invariant; exit 0 on PASS, 1 on FAIL"
    )
    verify.add_argument("path", help="path to the SQLite ledger")
    verify.set_defaults(handler=_command_verify)

    return parser


def main(argv: Sequence[str] | None = None, out: TextIO | None = None) -> int:
    """CLI entry point.

    :param argv: Arguments, defaulting to ``sys.argv[1:]``.
    :param out: Stream to write to, defaulting to stdout.
    :returns: Process exit code.
    """
    stream = out if out is not None else sys.stdout
    args = build_parser().parse_args(argv)
    try:
        result: int = args.handler(args, stream)
        return result
    except AgentGovError as exc:
        stream.write(f"error: {exc}\n")
        return 1
    except OSError as exc:
        stream.write(f"error: cannot read {getattr(args, 'path', '?')}: {exc}\n")
        return 1


if __name__ == "__main__":  # pragma: no cover - module entry point
    sys.exit(main())
