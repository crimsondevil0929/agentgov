"""A standalone Streamlit dashboard for an AgentGov ledger.

Reads a governed ledger (produced by ``examples/live_demo.py`` by default) and
renders it as a web UI: the balance tree as metrics, the circuit-breaker
status, the hash-chained entries as a table, and a button that runs the
invoiced-to-metered reconciliation report against a provider export.

This file is intentionally single-file and dependency-light beyond Streamlit
itself — it opens the ledger **read-only**, so it is safe to point at a
database another process is actively governing.

Install and run::

    uv sync --extra ui
    uv run streamlit run examples/streamlit_dashboard.py

Then, in the sidebar, point it at a ledger — ``demo/governor.db`` after
running ``python examples/live_demo.py`` is the natural starting point.
"""

from __future__ import annotations

import sys
from decimal import Decimal
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Streamlit is an optional extra (`uv sync --extra ui`) and is deliberately
    # absent from the CI type-check environment, so the type checker cannot be
    # allowed to depend on it either way. Declaring it as Any here, rather than
    # silencing the import with `# type: ignore`, keeps this file checking
    # identically whether or not the package is installed: a bare ignore would
    # resolve cleanly in CI and then fail locally under `warn_unused_ignores`.
    st: Any
else:
    import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from agentgov.core import BudgetManager, BudgetNode, EntryType
from agentgov.exceptions import AgentGovError
from agentgov.reconciliation import (
    MeteringJournal,
    ReconciliationPolicy,
    UsageParseError,
    load_provider_export,
    metered_records,
    reconcile,
)

st.set_page_config(page_title="AgentGov Ledger Dashboard", page_icon="\U0001f4d2", layout="wide")


# --------------------------------------------------------------------------
# Data access — every call here is read-only.
# --------------------------------------------------------------------------


def _open_ledger_uncached(path: str) -> BudgetManager:
    """Open a ledger for audit. Cached per path so the advisory lock (which
    read-only mode does not take) isn't reopened on every rerun."""
    return BudgetManager.open_sqlite(path, read_only=True)


# Applied as a call rather than with `@` syntax. `st` is untyped by
# construction (see the import above) and `mypy --strict` rejects an untyped
# decorator, so the wrapping is done here and the result is narrowed back to a
# real type at the one call site below.
_open_ledger = st.cache_resource(show_spinner=False)(_open_ledger_uncached)


def load_manager(path: str) -> BudgetManager | None:
    """Open the ledger, surfacing any failure in the UI instead of crashing."""
    if not Path(path).is_file():
        st.error(
            f"No ledger found at `{path}`. Run `examples/live_demo.py` first, or "
            f"point the sidebar at an existing `.db` file."
        )
        return None
    try:
        manager: BudgetManager = _open_ledger(path)
    except AgentGovError as exc:
        st.error(f"Could not open `{path}` as an AgentGov ledger: {exc}")
        return None
    return manager


def usd(amount: Decimal) -> str:
    """Render a Decimal as a dollar string, keeping sub-cent precision."""
    return f"${amount:,.6f}"


# --------------------------------------------------------------------------
# Balance tree
# --------------------------------------------------------------------------


def render_balance_tree(manager: BudgetManager) -> None:
    st.subheader("Balance tree")

    scopes = manager.scopes()
    if not scopes:
        st.info("This ledger has no scopes yet.")
        return

    roots = [manager.node(scope) for scope in scopes if manager.node(scope).parent_id is None]

    def render_node(node: BudgetNode, depth: int = 0) -> None:
        available = manager.available(node.scope_id)
        halted_by = manager.halted_by(node.scope_id)
        # Em-space, not a regular space: st.markdown renders as Markdown/HTML,
        # which collapses runs of ordinary spaces and would flatten the tree.
        indent = " " * depth  # noqa: RUF001

        columns = st.columns([3, 2, 2, 2])
        with columns[0]:
            label = f"{indent}{'┗ ' if depth else ''}**{node.scope_id}**"
            st.markdown(label)
        with columns[1]:
            st.metric("Available", usd(available), label_visibility="collapsed")
        with columns[2]:
            st.metric("Allocated", usd(node.allocated), label_visibility="collapsed")
        with columns[3]:
            if halted_by is not None:
                st.error(f"HALTED by `{halted_by}`", icon="\U0001f6d1")
            else:
                st.success("running", icon="✅")

        for child_id in node.child_ids:
            render_node(manager.node(child_id), depth + 1)

    for root in roots:
        render_node(root)


def render_summary_metrics(manager: BudgetManager) -> None:
    entries = manager.audit_trail()
    funded = sum((e.amount for e in entries if e.entry_type is EntryType.FUNDING), Decimal(0))
    spent = sum((e.amount for e in entries if e.entry_type is EntryType.SPEND), Decimal(0))
    held = sum(
        (e.signed_amount for e in entries if e.entry_type in (EntryType.HOLD, EntryType.HOLD_VOID)),
        Decimal(0),
    )
    halted_scopes = sum(1 for scope in manager.scopes() if manager.halted_by(scope) is not None)

    cols = st.columns(5)
    cols[0].metric("Funded", usd(funded))
    cols[1].metric("Settled spend", usd(spent))
    cols[2].metric("Holds open", usd(-held))
    cols[3].metric("Unspent", usd(funded - spent + held))
    cols[4].metric(
        "Circuit breakers",
        f"{halted_scopes}/{len(manager.scopes())} halted",
        delta=None if halted_scopes == 0 else "attention",
        delta_color="inverse",
    )


# --------------------------------------------------------------------------
# Hash chain
# --------------------------------------------------------------------------


def render_hash_chain(manager: BudgetManager) -> None:
    st.subheader("Tamper-evident hash chain")

    entries = manager.audit_trail()
    if not entries:
        st.info("No ledger entries yet.")
        return

    try:
        manager.ledger.verify_chain()
        manager.ledger.verify_conservation()
        st.success(
            f"verify_chain() and verify_conservation() both PASS across "
            f"{len(entries):,} entries. Head hash `{manager.ledger.head_hash[:16]}…`",
            icon="\U0001f512",
        )
    except AgentGovError as exc:
        st.error(f"Integrity check FAILED: {exc}", icon="⚠️")

    limit = st.slider(
        "Entries to show (most recent first)", 5, max(len(entries), 5), min(50, len(entries))
    )
    recent = list(reversed(entries[-limit:]))

    rows = [
        {
            "seq": e.sequence,
            "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "type": e.entry_type.value,
            "dir": e.direction.value,
            "scope": e.scope_id,
            "amount": f"{e.amount:.8f}",
            "balance_after": f"{e.balance_after:.8f}",
            "hash": e.entry_hash[:16],
            "prev_hash": e.prev_hash[:16],
            "memo": e.memo,
        }
        for e in recent
    ]
    st.dataframe(rows, width="stretch", hide_index=True)


# --------------------------------------------------------------------------
# Circuit breaker / control events
# --------------------------------------------------------------------------


def render_control_events(manager: BudgetManager) -> None:
    events = manager.control_events
    st.subheader("Circuit breaker events")
    if not events:
        st.info("No breaker trips or resets recorded.")
        return
    rows = [
        {
            "timestamp": e.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "event": e.event_type,
            "scope": e.scope_id,
            "ledger_head": e.ledger_head_hash[:16],
            "reason": e.reason,
        }
        for e in events
    ]
    st.dataframe(rows, width="stretch", hide_index=True)


# --------------------------------------------------------------------------
# Reconciliation
# --------------------------------------------------------------------------


def render_reconciliation(manager: BudgetManager, db_path: str) -> None:
    st.subheader("Invoice reconciliation")
    st.caption(
        "Match a provider usage export against this ledger. A **phantom** line — "
        "billed by the provider but never authorized locally — fails the audit."
    )

    default_export = str(Path(db_path).parent / "provider_invoice.json")
    default_journal = str(Path(db_path).parent / "tokens.jsonl")

    col1, col2 = st.columns(2)
    with col1:
        export_path = st.text_input("Provider usage export", value=default_export)
    with col2:
        journal_path = st.text_input(
            "Metering journal (optional, enables token-level matching)",
            value=default_journal,
        )

    with st.expander("Matching tolerances"):
        t1, t2, t3 = st.columns(3)
        time_tolerance = t1.number_input("Time tolerance (s)", value=5.0, min_value=0.0)
        token_tolerance = t2.number_input("Token tolerance (%)", value=2.0, min_value=0.0)
        cost_tolerance = t3.number_input("Cost tolerance (%)", value=1.0, min_value=0.0)

    if not st.button("Run reconciliation", type="primary"):
        return

    if not Path(export_path).is_file():
        st.error(f"No provider export found at `{export_path}`.")
        return

    try:
        provider_records = load_provider_export(export_path)
    except UsageParseError as exc:
        st.error(f"Could not parse the provider export: {exc}")
        return

    journal = None
    if journal_path and Path(journal_path).is_file():
        try:
            journal = MeteringJournal.load(journal_path)
        except (AgentGovError, OSError) as exc:
            st.warning(f"Could not read the journal ({exc}); matching on cost and time only.")

    policy = ReconciliationPolicy(
        time_tolerance_seconds=time_tolerance,
        token_tolerance_percent=token_tolerance,
        cost_tolerance_percent=cost_tolerance,
    )
    report = reconcile(metered_records(manager, journal), provider_records, policy)

    if report.passed:
        st.success(
            f"AUDIT PASSED — {len(report.matched)} of {report.total_provider_records} "
            f"billed lines reconciled; no unmetered spend.",
            icon="✅",
        )
    else:
        reasons = []
        if report.phantom:
            reasons.append(
                f"{len(report.phantom)} phantom call(s) worth {usd(report.phantom_total)}"
            )
        if report.discrepant:
            reasons.append(f"{len(report.discrepant)} cost discrepancy(ies)")
        st.error(f"AUDIT FAILED — {'; '.join(reasons)}", icon="\U0001f6a8")

    cols = st.columns(4)
    cols[0].metric("Matched", len(report.matched))
    cols[1].metric("Discrepant", len(report.discrepant))
    cols[2].metric(
        "Phantom",
        len(report.phantom),
        delta=None if not report.phantom else "risk",
        delta_color="inverse",
    )
    cols[3].metric("Unsettled", len(report.unsettled))

    v1, v2, v3 = st.columns(3)
    v1.metric("Invoiced total", usd(report.invoiced_total))
    v2.metric("Metered total", usd(report.metered_total))
    v3.metric("Variance", usd(report.variance), delta=f"{report.variance_percent:.2f}%")

    if report.phantom:
        st.markdown("**Phantom calls — billed with no local authorization**")
        st.dataframe(
            [
                {
                    "record_id": r.record_id,
                    "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "model": r.model,
                    "cost": usd(r.total_cost),
                }
                for r in report.phantom
            ],
            width="stretch",
            hide_index=True,
        )

    if report.discrepant:
        st.markdown("**Cost discrepancies**")
        st.dataframe(
            [
                {
                    "scope": d.metered.scope_id,
                    "sequence": d.metered.sequence,
                    "cost_delta": usd(d.cost_delta),
                    "reason": d.reason,
                }
                for d in report.discrepant
            ],
            width="stretch",
            hide_index=True,
        )

    for note in report.notes:
        st.caption(f"note: {note}")


# --------------------------------------------------------------------------
# App shell
# --------------------------------------------------------------------------


def main() -> None:
    st.title("\U0001f4d2 AgentGov Ledger Dashboard")
    st.caption(
        "A hash-chained, double-entry ledger for autonomous agent spend — "
        "read-only inspection and invoice reconciliation."
    )

    st.sidebar.header("Ledger")
    db_path = st.sidebar.text_input("SQLite ledger path", value="demo/governor.db")
    st.sidebar.caption(
        "Opened **read-only** — safe to point at a database a live governor "
        "process is currently writing to."
    )
    if st.sidebar.button("Reload", help="Re-open the ledger and clear cached state"):
        _open_ledger.clear()
        st.rerun()

    manager = load_manager(db_path)
    if manager is None:
        # st.stop() raises internally, so the return never executes. It is here
        # so the None case is closed explicitly rather than relying on the type
        # checker knowing that stop() is NoReturn, which it cannot know when
        # Streamlit is not installed.
        st.stop()
        return

    render_summary_metrics(manager)
    st.divider()
    render_balance_tree(manager)
    st.divider()
    render_control_events(manager)
    st.divider()
    render_hash_chain(manager)
    st.divider()
    render_reconciliation(manager, db_path)


if __name__ == "__main__":
    main()
