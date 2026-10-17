"""``agentgov`` — inspect and verify a ledger from the terminal.

The commands, and the readers each is for:

``agentgov inspect <db>``
    For a developer: the double-entry ledger, the balance tree, and breaker
    status, formatted to be read.

``agentgov verify <db>``
    For a pipeline: re-derives the hash chain, the balance cache, the
    conservation identity, the delegation topology and every checkpoint
    snapshot, then exits ``0`` or ``1``. Drop it in CI to assert an archived
    ledger is intact. ``--checkpoint-key`` checks every checkpoint's signed
    statement against the keys given, and ``--require-signed`` fails on an
    unsigned one.

``agentgov reconcile <db> <provider-export>``
    For finance and security: matches a provider's invoice against the ledger
    and reports matched, discrepant, phantom, and unsettled spend. Exits ``1``
    on any phantom line — billed spend with no local authorization — so it too
    belongs in a pipeline.

``agentgov repair <ledger>``
    For an operator whose governor refused to open because a cache table
    (topology, control events, open authorizations) disagrees with the chain:
    rebuilds those tables from the chain and says what it changed. Moves no
    money and never edits the chain.

``agentgov audit <ledger> [--follow]``
    For an operator or a sidecar: replays the chain from genesis, checks every
    checkpoint snapshot against it, and records how far it verified in the
    ledger itself (see :mod:`agentgov.audit`). A governor opens from its
    newest checkpoint; this is what verifies the history before it. It takes
    ``--checkpoint-key`` and ``--require-signed`` as ``verify`` does.

``agentgov checkpoint <ledger>``
    Writes a checkpoint now, rather than waiting for the next automatic one.

``agentgov export <ledger> --from-seq N``
    Streams entries from sequence ``N`` as JSON lines, for an archive.

``agentgov verify-receipt <bundle> --pubkey <key>``
    For an auditor: verifies an ARC1 receipt offline — its signature, its
    inclusion in the receipt log, a witness's cosignature of that log, its
    agreement with the ledger, and any disclosed rows — and exits with a code
    naming the first thing that failed (see :mod:`agentgov.receipts.verify`).

Every ledger command takes a path to a SQLite ledger or a URL
(``sqlite:///path``, ``postgresql://...?schema=...``; see
:mod:`agentgov.opening`). The ledger commands other than ``repair`` and
``checkpoint`` open the ledger **read-only**, so they are safe to run against
a governor that is live and holding the write claim, and they replay the chain
in full from genesis rather than trusting a checkpoint. ``repair`` needs the
write claim, and is refused while a governor holds it.

Standard library only — argparse and nothing else, so the CLI costs the
package no dependencies.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from decimal import Decimal
from pathlib import Path
from typing import Any, TextIO

from agentgov.audit import Auditor
from agentgov.core import (
    BudgetManager,
    BudgetNode,
    CheckpointSigning,
    EntryType,
    format_audit_line,
)
from agentgov.exceptions import (
    AgentGovError,
    LedgerError,
    LedgerIntegrityError,
    MalformedReceiptError,
)
from agentgov.opening import open_url
from agentgov.receipts import (
    Check,
    Failure,
    Keyring,
    KeyTransition,
    RowDisclosure,
    VerificationReport,
    Verifier,
    load_cosignatures,
    parse_key,
    verify_bundle,
)
from agentgov.reconciliation import (
    MeteringJournal,
    ReconciliationPolicy,
    format_report,
    load_provider_export,
    metered_records,
    reconcile,
)

__all__ = ["main"]

_DIRECTION_SIGN = {"DR": "-", "CR": "+", "--": " "}
_TARGET = "a SQLite ledger's path, or a ledger URL (sqlite:///..., postgresql://...)"


def _open(path: str) -> BudgetManager:
    """Open a ledger for audit, never claiming it away from a live governor,
    and replaying it in full rather than trusting a checkpoint."""
    return open_url(path, read_only=True, verify="full", auditor=False)


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
        width = max((len(entry.entry_type.value) for entry in shown), default=10)
        for entry in shown:
            if args.raw:
                out.write(f"  {format_audit_line(entry)}\n")
            else:
                sign = _DIRECTION_SIGN[entry.direction.value]
                out.write(
                    f"  {entry.sequence:>8}  {entry.timestamp:%H:%M:%S}  "
                    f"{entry.entry_type.value:<{width}} {entry.scope_id:<22} "
                    f"{sign}{entry.amount:>14.8f}  bal {entry.balance_after:>14}"
                    f"  {entry.memo}\n"
                )
        out.write("\n")
        return 0
    finally:
        manager.close()


def _checkpoint_signing(args: argparse.Namespace, out: TextIO) -> CheckpointSigning | int | None:
    """The keys ``--checkpoint-key`` trusts to sign checkpoints, ``None``
    without any, or the exit code for options that cannot be used."""
    if not args.checkpoint_key and not args.require_signed:
        return None
    if not args.checkpoint_key:
        out.write("error: --require-signed needs --checkpoint-key, the key that signs\n")
        return 2
    try:
        return CheckpointSigning(keys=_read_keys(args.checkpoint_key), required=args.require_signed)
    except (OSError, MalformedReceiptError) as exc:
        out.write(f"error: {exc}\n")
        return 2


def _command_verify(args: argparse.Namespace, out: TextIO) -> int:
    """Re-derive every invariant and report PASS/FAIL for a pipeline."""
    signing = _checkpoint_signing(args, out)
    if isinstance(signing, int):
        return signing
    try:
        manager = _open(args.path)
    except AgentGovError as exc:
        out.write(f"FAIL  {args.path}\n  could not open: {exc}\n")
        return 1

    try:
        checks: list[tuple[str, str | None]] = []
        for label, check in (
            ("hash chain, balances + hold pairing", manager.ledger.verify_chain),
            ("conservation identity", manager.ledger.verify_conservation),
            ("topology + breakers, derived from the chain", manager.verify_integrity),
            (
                "checkpoint snapshots, each the state the chain implies"
                + (", each signed by a trusted key" if signing is not None else ""),
                _snapshots(manager, signing),
            ),
        ):
            try:
                check()
                checks.append((label, None))
            except LedgerError as exc:
                checks.append((label, str(exc)))

        failures = [(label, detail) for label, detail in checks if detail is not None]
        entries = len(manager.ledger)
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


def _snapshots(
    manager: BudgetManager, signing: CheckpointSigning | None = None
) -> Callable[[], None]:
    """A check that every checkpoint's snapshot is the state the chain implies
    at its sequence (and, with ``signing``, carries a trusted key's signed
    statement of it), recording nothing."""

    def check() -> None:
        store = manager.store
        if store is None or not hasattr(store, "checkpoints"):
            return
        report = Auditor(store, record=False, signing=signing).run(from_genesis=True)
        if report.failure is not None:
            raise LedgerIntegrityError(report.failure)

    return check


def _command_audit(args: argparse.Namespace, out: TextIO) -> int:
    """Replay the chain from genesis, check every snapshot, record the marks."""
    from agentgov.opening import parse_url

    signing = _checkpoint_signing(args, out)
    if isinstance(signing, int):
        return signing
    kind, target, options = parse_url(args.path)
    store: Any
    if kind == "postgres":
        from agentgov.postgres import PostgresStore

        store = PostgresStore(target, **options)
    elif kind == "sqlite":
        from agentgov.storage import SqliteStore

        store = SqliteStore(target, read_only=True)
    else:
        out.write("error: a memory: ledger has nothing to audit\n")
        return 2
    try:
        auditor = Auditor(store, name=args.name or None, signing=signing)
        if args.follow:
            report = auditor.follow(interval=args.interval)
        else:
            report = auditor.run(from_genesis=args.from_genesis)
        if report.failure is not None:
            out.write(f"FAIL  {args.path}\n  {report.failure}\n")
            return 1
        out.write(
            f"PASS  {args.path}  (verified to {report.verified_to:,} from "
            f"{report.resumed_from:,}: {report.entries:,} entries replayed, "
            f"{report.checkpoints} checkpoint snapshot(s) checked; head {report.head[:16]})\n"
        )
        return 0
    finally:
        store.close()


def _command_checkpoint(args: argparse.Namespace, out: TextIO) -> int:
    """Write a checkpoint of the ledger now."""
    with open_url(args.path, auditor=False) as manager:
        sequence = manager.checkpoint()
    out.write(f"checkpointed {args.path} at sequence {sequence:,}\n")
    return 0


def _command_export(args: argparse.Namespace, out: TextIO) -> int:
    """Stream entries from a sequence on, as JSON lines."""
    manager = open_url(args.path, read_only=True, auditor=False)
    try:
        for entry in manager.ledger.iter_entries(after=max(0, args.from_seq - 1)):
            out.write(json.dumps(entry.to_audit_record(), sort_keys=True) + "\n")
        return 0
    finally:
        manager.close()


def _command_reconcile(args: argparse.Namespace, out: TextIO) -> int:
    """Match a provider invoice against the ledger and report the variance."""
    try:
        provider = load_provider_export(args.export, fmt=args.format)
    except AgentGovError as exc:
        out.write(f"FAIL  could not read {args.export}\n  {exc}\n")
        return 1

    journal: MeteringJournal | None = None
    if args.journal:
        try:
            journal = MeteringJournal.load(args.journal)
        except (AgentGovError, OSError) as exc:
            out.write(f"FAIL  could not read journal {args.journal}\n  {exc}\n")
            return 1

    manager = _open(args.path)
    try:
        report = reconcile(
            metered_records(manager, journal),
            provider,
            ReconciliationPolicy(
                time_tolerance_seconds=args.time_tolerance,
                token_tolerance_percent=args.token_tolerance,
                cost_tolerance_percent=args.cost_tolerance,
            ),
        )
    finally:
        manager.close()

    out.write(format_report(report, path=args.path, export=args.export))
    out.write("\n")
    return 0 if report.passed else 1


def _command_repair(args: argparse.Namespace, out: TextIO) -> int:
    """Rebuild the cache tables from the chain, and report what changed."""
    manager = open_url(args.path, repair=True, auditor=False)
    try:
        if not manager.repairs:
            out.write(
                f"nothing to repair  {args.path}  (every cache table agrees with the chain)\n"
            )
            return 0
        out.write(f"REPAIRED  {args.path}  ({len(manager.repairs)} cache disagreement(s))\n")
        for problem in manager.repairs:
            out.write(f"  - {problem}\n")
        out.write(
            f"\nThe chain was not touched; it verifies "
            f"({len(manager.ledger):,} entries, head {manager.ledger.head_hash[:16]}).\n"
        )
        return 0
    finally:
        manager.close()


_KEY_PREFIXES = ("ed25519:", "hmac-sha256:")
_MARKS = {"pass": "ok  ", "fail": "FAIL", "skip": "--  "}


def _read_key(value: str) -> Verifier:
    """A key given inline (``ed25519:<hex>``) or as a file holding one."""
    text = value if value.startswith(_KEY_PREFIXES) else Path(value).read_text(encoding="utf-8")
    return parse_key(text)


def _read_keys(values: Sequence[str]) -> Verifier | Keyring:
    """One key as itself; several, given by repeating the option, as a keyring
    (a key and its successor, after a rotation)."""
    keys = [_read_key(value) for value in values]
    if len(keys) == 1:
        return keys[0]
    try:
        return Keyring(keys)
    except ValueError as exc:
        raise MalformedReceiptError(str(exc)) from exc


def _command_verify_receipt(args: argparse.Namespace, out: TextIO) -> int:
    """Verify an ARC1 receipt bundle; exit with the first failure's code."""
    try:
        issuer = _read_keys(args.pubkey)
        log_key = _read_keys(args.log_pubkey) if args.log_pubkey else None
        witness_key = _read_keys(args.witness_pubkey) if args.witness_pubkey else None
        relay_keys = [_read_key(key) for key in args.relay_key] if args.relay_key else None
        action = Path(args.action).read_bytes() if args.action else None
        bundle = Path(args.bundle).read_bytes()
    except (OSError, MalformedReceiptError) as exc:
        out.write(f"error: {exc}\n")
        return 2
    if args.witness and witness_key is None:
        out.write("error: --witness needs --witness-pubkey, the key the witness signs with\n")
        return 2
    if args.ledger and not Path(args.ledger).is_file():
        out.write(f"error: no ledger at {args.ledger}\n")
        return 2

    # An input that exists but does not decode fails the check it feeds, in
    # that check's place, so the exit code stays the first failure in order.
    unreadable: dict[str, Check] = {}
    cosignatures = None
    rows = None
    transitions: list[KeyTransition] | None = None
    ledger: BudgetManager | None = None
    try:
        if args.witness:
            try:
                cosignatures = load_cosignatures(args.witness)
            except MalformedReceiptError as exc:
                unreadable["witnessed"] = Check("witnessed", "fail", str(exc), Failure.MALFORMED)
        if args.transitions:
            try:
                lines = Path(args.transitions).read_bytes().splitlines()
                transitions = [KeyTransition.loads(line) for line in lines if line.strip()] or None
            except MalformedReceiptError as exc:
                unreadable["key transitions"] = Check(
                    "key transitions", "fail", f"{args.transitions}: {exc}", Failure.MALFORMED
                )
        if args.rows:
            try:
                rows = RowDisclosure.loads(Path(args.rows).read_bytes())
            except MalformedReceiptError as exc:
                unreadable["disclosed rows"] = Check(
                    "disclosed rows", "fail", str(exc), Failure.MALFORMED
                )
    except OSError as exc:
        out.write(f"error: {exc}\n")
        return 2
    if args.ledger:
        try:
            ledger = open_url(args.ledger, read_only=True, auditor=False)
        except AgentGovError as exc:
            unreadable["agentgov ledger"] = Check(
                "agentgov ledger", "fail", f"the ledger does not verify: {exc}", Failure.LEDGER
            )
    try:
        report = verify_bundle(
            bundle,
            issuer_key=issuer,
            log_key=log_key,
            cosignatures=cosignatures,
            witness_key=witness_key,
            ledger=ledger,
            rows=rows,
            relay_keys=relay_keys,
            action=action,
            transitions=transitions,
        )
    finally:
        if ledger is not None:
            ledger.close()
    if unreadable:
        placed = [unreadable.pop(check.name, check) for check in report.checks]
        report = VerificationReport((*placed, *unreadable.values()), report.receipt)

    if args.json:
        out.write(json.dumps(report.to_json(), indent=2) + "\n")
        return report.exit_code
    width = max(len(check.name) for check in report.checks)
    for check in report.checks:
        out.write(f"  {_MARKS[check.status]}  {check.name:<{width}}  {check.detail}\n")
    failure = report.first_failure
    if failure is not None and failure.failure is not None:
        out.write(
            f"\nFAIL  {args.bundle}  ({failure.name}: exit {int(failure.failure)} "
            f"{failure.failure.name})\n"
        )
    else:
        receipt_id = report.receipt.receipt_id if report.receipt else "?"
        out.write(f"\nPASS  {args.bundle}  (receipt {receipt_id})\n")
    return report.exit_code


def _add_checkpoint_keys(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--checkpoint-key",
        action="append",
        default=[],
        help="a key trusted to sign the ledger's checkpoints ('ed25519:<hex>' or a file); "
        "repeatable. Every signed checkpoint must then check out under one",
    )
    command.add_argument(
        "--require-signed",
        action="store_true",
        help="fail on a checkpoint no --checkpoint-key signed",
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser."""
    parser = argparse.ArgumentParser(
        prog="agentgov",
        description="Inspect, verify, reconcile and repair an AgentGov ledger, and verify "
        "ARC1 action receipts. inspect, verify and reconcile open the database read-only "
        "and are safe to run against a live governor.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    inspect = subcommands.add_parser(
        "inspect", help="print the ledger, balance tree, and breaker status"
    )
    inspect.add_argument("path", help=_TARGET)
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
    verify.add_argument("path", help=_TARGET)
    _add_checkpoint_keys(verify)
    verify.set_defaults(handler=_command_verify)

    reconcile_cmd = subcommands.add_parser(
        "reconcile",
        help="match a provider invoice against the ledger; exit 1 on unmetered spend",
    )
    reconcile_cmd.add_argument("path", help=_TARGET)
    reconcile_cmd.add_argument("export", help="provider usage export (JSON or CSV)")
    reconcile_cmd.add_argument(
        "--journal",
        default="",
        help="metering journal with token counts, for token-level matching",
    )
    reconcile_cmd.add_argument(
        "--format",
        default="auto",
        choices=("auto", "openai-json", "anthropic-csv"),
        help="export format (default: auto-detect by extension)",
    )
    reconcile_cmd.add_argument(
        "--time-tolerance",
        type=float,
        default=5.0,
        help="seconds of timestamp drift allowed when matching (default: 5.0)",
    )
    reconcile_cmd.add_argument(
        "--token-tolerance",
        type=float,
        default=2.0,
        help="percent of token drift allowed when matching (default: 2.0)",
    )
    reconcile_cmd.add_argument(
        "--cost-tolerance",
        type=float,
        default=1.0,
        help="percent of cost drift before a match is a discrepancy (default: 1.0)",
    )
    reconcile_cmd.set_defaults(handler=_command_reconcile)

    repair = subcommands.add_parser(
        "repair",
        help="rebuild cache tables that disagree with the chain; moves no money",
    )
    repair.add_argument("path", help=_TARGET)
    repair.set_defaults(handler=_command_repair)

    audit = subcommands.add_parser(
        "audit",
        help="replay the chain from genesis and check every checkpoint; exit 1 on FAIL",
    )
    audit.add_argument("path", help=_TARGET)
    audit.add_argument("--follow", action="store_true", help="keep auditing what is written")
    audit.add_argument(
        "--interval", type=float, default=5.0, help="seconds between runs with --follow"
    )
    audit.add_argument(
        "--from-genesis", action="store_true", help="ignore earlier audit marks and replay all"
    )
    audit.add_argument("--name", default="", help="who is auditing, recorded in each mark")
    _add_checkpoint_keys(audit)
    audit.set_defaults(handler=_command_audit)

    checkpoint = subcommands.add_parser("checkpoint", help="write a checkpoint of the ledger now")
    checkpoint.add_argument("path", help=_TARGET)
    checkpoint.set_defaults(handler=_command_checkpoint)

    export = subcommands.add_parser("export", help="stream entries as JSON lines")
    export.add_argument("path", help=_TARGET)
    export.add_argument(
        "--from-seq", type=int, default=1, help="the first sequence to export (default: 1)"
    )
    export.set_defaults(handler=_command_export)

    receipt = subcommands.add_parser(
        "verify-receipt",
        help="verify an ARC1 receipt offline; exit 0 on PASS, 3-8 naming what failed",
        description="Verify an ARC1 receipt bundle offline: an action receipt, or a delivery "
        "receipt. Exit codes: 0 pass, 2 usage, 3 malformed, 4 receipt signature, 5 log "
        "inclusion, 6 witness, 7 ledger, 8 rows, 9 relay attestation, 10 action binding.",
    )
    receipt.add_argument("bundle", help="receipt bundle, or bare receipt, as JSON")
    receipt.add_argument(
        "--pubkey",
        required=True,
        action="append",
        help="the issuer's key: 'ed25519:<hex>', 'hmac-sha256:<hex>', or a file holding one; "
        "repeat it for each key the issuer has signed with (after a rotation)",
    )
    receipt.add_argument(
        "--log-pubkey",
        action="append",
        default=[],
        help="the receipt log's checkpoint key (default: --pubkey); repeatable",
    )
    receipt.add_argument(
        "--transitions",
        default="",
        help="the receipt log's key transitions (JSON lines: the log's .transitions file), "
        "followed from --log-pubkey, or --pubkey, to the key that signed",
    )
    receipt.add_argument(
        "--witness", default="", help="a witness's published cosignatures (JSON lines)"
    )
    receipt.add_argument(
        "--witness-pubkey",
        action="append",
        default=[],
        help="the witness's key; required with --witness; repeatable",
    )
    receipt.add_argument(
        "--ledger",
        default="",
        help="an AgentGov ledger the receipt's anchor and settled cost must agree with",
    )
    receipt.add_argument(
        "--rows", default="", help="a row disclosure to check against the row commitment"
    )
    receipt.add_argument(
        "--relay-key",
        action="append",
        default=[],
        help="for a delivery receipt: a relay's key that may have signed its attestation; "
        "repeat for each relay",
    )
    receipt.add_argument(
        "--action",
        default="",
        help="for a delivery receipt: the bundle of the action receipt it must follow from",
    )
    receipt.add_argument("--json", action="store_true", help="print the report as JSON")
    receipt.set_defaults(handler=_command_verify_receipt)

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
