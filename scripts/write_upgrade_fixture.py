"""Write a ledger with whichever agentgov is importable, for the upgrade tests.

Run by ``scripts/generate_upgrade_fixtures.sh`` once per released version,
with that version's source first on ``PYTHONPATH``, so each fixture is a
database exactly as that release wrote it. Uses only the API every release
has had; what a release lacks it skips.

    python scripts/write_upgrade_fixture.py <sqlite path> [<postgres dsn> <schema>]
"""

from __future__ import annotations

import json
import sys
from decimal import Decimal
from typing import Any

import agentgov
from agentgov import BudgetManager

try:
    from agentgov import money
except ImportError:  # pragma: no cover - every release has it
    money = Decimal  # type: ignore[assignment,misc]


def workload(gov: Any) -> dict[str, Any]:
    """Every kind of state a release can write, and what it should read back as."""
    gov.open_root("orchestrator", money("10.00"))
    gov.delegate("orchestrator", "researcher", money("2.50"))
    gov.delegate("orchestrator", "writer", money("1.00"))
    held = gov.authorize("researcher", money("0.40"))
    gov.capture(held, money("0.31"))
    gov.spend("writer", money("0.25"))
    if hasattr(gov, "refund"):
        gov.refund("writer", money("0.05"))
    gov.authorize("researcher", money("0.10"))  # left open across the upgrade
    voided = gov.authorize("writer", money("0.10"))
    gov.void(voided)
    if hasattr(gov, "release"):
        gov.release("writer", money("0.20"))
    if hasattr(gov, "fund"):
        gov.fund("orchestrator", money("5.00"))
    gov.trip("writer", "operator halt")
    if hasattr(gov, "reset"):
        gov.reset("writer")
        gov.trip("writer", "halted again")
    if hasattr(gov, "anchor"):
        gov.anchor("orchestrator", "escrow head 9f2c")
    return {
        "version": agentgov.__version__,
        "entries": len(gov.ledger),
        "head": gov.ledger.head_hash,
        "balances": {s: str(gov.available(s)) for s in ("orchestrator", "researcher", "writer")},
        "halted": sorted(s for s in ("orchestrator", "researcher", "writer") if gov.is_halted(s)),
        "open_holds": len(gov.stale_authorizations(0)),
    }


def main() -> None:
    path = sys.argv[1]
    with BudgetManager.open_sqlite(path) as gov:
        expected = workload(gov)
    if len(sys.argv) > 2:
        dsn, schema = sys.argv[2], sys.argv[3]
        with BudgetManager.open_postgres(dsn, schema=schema) as gov:
            expected["postgres"] = workload(gov)
    print(json.dumps(expected, sort_keys=True))


if __name__ == "__main__":
    main()
