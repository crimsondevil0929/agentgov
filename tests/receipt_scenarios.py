"""Realistic execution payloads for the receipt tests.

Nothing in these receipts is made up. A support agent runs plans against a
real SQLite database, and each receipt is built from what actually happened:

- the rows are read back from the database before and after the plan;
- the checks really run, over that measured diff, and a refused plan is
  really rolled back;
- the model calls are priced from token usage at the published rates and
  settled through a real, durable AgentGov ledger, which the receipt then
  anchors to;
- the plan, diff, verdict and checker-configuration hashes are digests of the
  actual documents.
"""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from agentgov import BudgetManager, TokenUsage, money, pricing_for
from agentgov.receipts import (
    ActionReceipt,
    Anchors,
    Authority,
    Capability,
    ChainAnchor,
    CheckerRecord,
    Cost,
    Coverage,
    Decision,
    Effect,
    Intent,
    Outcome,
    OutcomeStatus,
    RowChange,
    RowCommitment,
    StatedFootprint,
    canonical_bytes,
    commit_rows,
)
from agentgov.receipts.canonical import sha256_hex

MODEL = "claude-sonnet-5"
TABLES = ("order_audit", "orders", "refunds")
TENANTS = ("acme", "globex", "initech", "umbrella")

_SCHEMA = """
CREATE TABLE orders(
    id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, customer INTEGER NOT NULL,
    total TEXT NOT NULL, status TEXT NOT NULL
);
CREATE TABLE refunds(
    id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, order_id INTEGER NOT NULL,
    amount TEXT NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE order_audit(
    id INTEGER PRIMARY KEY, tenant TEXT NOT NULL, order_id INTEGER NOT NULL, note TEXT NOT NULL
);
"""

CHECKER_CONFIGS: dict[str, dict[str, Any]] = {
    "blast_radius": {"limit": 8},
    "tenant_isolation": {"limit": 1},
    "no_delete": {"tables": ["order_audit"]},
    "stated_footprint": {"ratio": "2.0"},
}


@dataclass(frozen=True)
class Execution:
    """One plan, run for real, and the unsigned receipt describing it."""

    draft: ActionReceipt
    commitment: RowCommitment
    blocked_by: tuple[str, ...]


class SupportDesk:
    """A tenant-partitioned orders database, and the governor paying for the
    agent that edits it."""

    def __init__(self, workdir: Path) -> None:
        self.db_path = workdir / "support.db"
        self.ledger_path = workdir / "governor.db"
        conn = sqlite3.connect(self.db_path)
        with conn:
            conn.executescript(_SCHEMA)
            for i in range(12):
                tenant = TENANTS[i % 4]
                conn.execute(
                    "INSERT INTO orders VALUES (?, ?, ?, ?, 'paid')",
                    (1040 + i, tenant, 70 + i, f"{120 + i * 30}.00"),
                )
                conn.execute(
                    "INSERT INTO order_audit VALUES (?, ?, ?, 'payment captured')",
                    (88000 + i, tenant, 1040 + i),
                )
        conn.close()
        self.governor = BudgetManager.open_sqlite(str(self.ledger_path))
        self.governor.open_root("orchestrator", money("25.00"))
        self.governor.delegate("orchestrator", "support-agent", money("5.00"))

    def close(self) -> None:
        self.governor.close()

    # -- the parts of a receipt --------------------------------------------

    def settle_model_calls(self, usages: Sequence[TokenUsage]) -> tuple[list[str], Decimal]:
        """Hold, call, settle: the governed metering path for each call."""
        pricing = pricing_for(MODEL)
        txns: list[str] = []
        total = Decimal(0)
        for usage in usages:
            ceiling = TokenUsage(input_tokens=usage.input_tokens, output_tokens=1024)
            authorization = self.governor.authorize("support-agent", pricing.cost_of(ceiling))
            spend = self.governor.capture(authorization, pricing.cost_of(usage))
            txns.append(str(spend.transaction_id))
            total += spend.amount
        return txns, total

    def _snapshot(self, conn: sqlite3.Connection) -> dict[tuple[str, str], dict[str, object]]:
        rows: dict[tuple[str, str], dict[str, object]] = {}
        conn.row_factory = sqlite3.Row
        for table in TABLES:
            for row in conn.execute(f"SELECT * FROM {table}"):  # noqa: S608 - fixed table names
                rows[(table, str(row["id"]))] = dict(row)
        return rows

    def schema_hash(self) -> str:
        conn = sqlite3.connect(self.db_path)
        try:
            ddl = "\n".join(
                sql for (sql,) in conn.execute("SELECT sql FROM sqlite_master ORDER BY name")
            )
        finally:
            conn.close()
        return sha256_hex(ddl.encode())

    def run(
        self,
        intent: str,
        statements: Sequence[tuple[str, Mapping[str, object]]],
        *,
        stated_rows: int,
        usages: Sequence[TokenUsage],
        row_secret: bytes | None = None,
    ) -> Execution:
        """Stage the plan for real, check it, then commit or roll back."""
        plan = {
            "intent": intent,
            "effects": [{"statement": sql, "parameters": dict(p)} for sql, p in statements],
        }
        conn = sqlite3.connect(self.db_path, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            before = self._snapshot(conn)
            for sql, parameters in statements:
                conn.execute(sql, dict(parameters))
            after = self._snapshot(conn)
            changes = _diff(before, after)
            blocked = _adjudicate(changes, stated_rows)
            conn.execute("ROLLBACK" if blocked else "COMMIT")
        finally:
            conn.close()

        commitment = commit_rows(changes, secret=row_secret)
        txns, settled = self.settle_model_calls(usages)
        verdict = {
            "admitted": not blocked,
            "blocking": list(blocked),
            "checkers": list(CHECKER_CONFIGS),
        }
        ledger = self.governor.ledger
        draft = ActionReceipt(
            receipt_id=str(uuid.uuid4()),
            issued_at=datetime.now(UTC),
            issuer="interlock/0.2.0-dev support-desk",
            authority=Authority(
                scope_path=("orchestrator", "support-agent"),
                trajectory_id=f"traj-{uuid.uuid4().hex[:12]}",
                capability=Capability(
                    grant="grant:support-agent/orders-rw@v3",
                    tables=TABLES,
                    tenants=("acme",),
                    row_limit=int(CHECKER_CONFIGS["blast_radius"]["limit"]),
                ),
            ),
            intent=Intent(
                plan_hash=sha256_hex(canonical_bytes(plan)),
                stated=StatedFootprint(
                    rows=stated_rows, tables=tuple(sorted({row.table for row in changes}))
                ),
            ),
            effect=Effect(
                substrate_id="sqlite",
                schema_hash=self.schema_hash(),
                diff_hash=sha256_hex(canonical_bytes([row.to_json() for row in changes])),
                row_root=commitment.root,
                row_count=commitment.count,
                summary=commitment.summary(),
            ),
            coverage=Coverage(
                observed_tables=TABLES,
                cascade_closed=True,
                authorizer_on=True,
                known_gaps=("writes by database triggers into unobserved tables",),
            ),
            decision=Decision(
                verdict_hash=sha256_hex(canonical_bytes(verdict)),
                admitted=not blocked,
                checkers=tuple(
                    CheckerRecord(name, sha256_hex(canonical_bytes(config)))
                    for name, config in CHECKER_CONFIGS.items()
                ),
                policy_epoch=3,
            ),
            cost=Cost(ledger_txn_ids=tuple(txns), settled_usd=settled, served_models=(MODEL,)),
            outcome=Outcome(
                OutcomeStatus.REFUSED if blocked else OutcomeStatus.COMMITTED,
                substrate_txid=f"stage:{uuid.uuid4()}",
            ),
            anchors=Anchors(agentgov=ChainAnchor(seq=len(ledger), head=ledger.head_hash)),
        )
        return Execution(draft=draft, commitment=commitment, blocked_by=blocked)

    # -- the plans ---------------------------------------------------------

    def refund(self, order_id: int, *, reason: str = "damaged in transit") -> Execution:
        """A one-tenant refund: three rows, admitted, committed."""
        return self.run(
            f"refund order {order_id}",
            [
                ("UPDATE orders SET status = 'refunded' WHERE id = :id", {"id": order_id}),
                (
                    "INSERT INTO refunds (id, tenant, order_id, amount, reason) "
                    "SELECT :rid, tenant, id, total, :reason FROM orders WHERE id = :id",
                    {"rid": 3000 + order_id, "id": order_id, "reason": reason},
                ),
                (
                    "INSERT INTO order_audit (id, tenant, order_id, note) "
                    "SELECT :aid, tenant, id, 'refund issued by support-agent' FROM orders "
                    "WHERE id = :id",
                    {"aid": 99000 + order_id, "id": order_id},
                ),
            ],
            stated_rows=3,
            usages=[
                TokenUsage(input_tokens=1840, output_tokens=212),
                TokenUsage(input_tokens=2210, output_tokens=96),
            ],
        )

    def tenant_wipe(self) -> Execution:
        """The prompt-injected plan: every tenant's totals zeroed, the audit
        trail deleted. Refused, and rolled back."""
        return self.run(
            "fix the totals the customer complained about",
            [
                ("UPDATE orders SET total = '0.00'", {}),
                ("DELETE FROM order_audit", {}),
            ],
            stated_rows=4,
            usages=[TokenUsage(input_tokens=3120, output_tokens=388)],
        )

    def orders(self) -> list[tuple[int, str, str]]:
        conn = sqlite3.connect(self.db_path)
        try:
            return [
                (int(r[0]), str(r[1]), str(r[2]))
                for r in conn.execute("SELECT id, total, status FROM orders ORDER BY id")
            ]
        finally:
            conn.close()


def _diff(
    before: Mapping[tuple[str, str], Mapping[str, object]],
    after: Mapping[tuple[str, str], Mapping[str, object]],
) -> list[RowChange]:
    changes: list[RowChange] = []
    for key in sorted(before.keys() | after.keys()):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        table, pk = key
        image = new if new is not None else old
        assert image is not None
        changes.append(
            RowChange.from_values(table, pk, before=old, after=new, tenant=str(image.get("tenant")))
        )
    return changes


def _adjudicate(changes: Sequence[RowChange], stated_rows: int) -> tuple[str, ...]:
    """The checks, run over the measured diff, as interlock runs them."""
    blocked: list[str] = []
    if len(changes) > CHECKER_CONFIGS["blast_radius"]["limit"]:
        blocked.append("blast_radius")
    if len({row.tenant for row in changes}) > CHECKER_CONFIGS["tenant_isolation"]["limit"]:
        blocked.append("tenant_isolation")
    if any(
        row.op == "delete" and row.table in CHECKER_CONFIGS["no_delete"]["tables"]
        for row in changes
    ):
        blocked.append("no_delete")
    return tuple(blocked)
