"""Concurrency tests: concurrent sub-agents must not double-spend.

These are the tests the component exists for. A budget governor that is
merely *usually* correct under concurrency is a governor that will one day
authorize two agents to spend the same dollar.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

from agentgov.core import BudgetManager, GovernancePolicy, money
from agentgov.exceptions import AgentGovError, BudgetExceededError

ZERO = Decimal("0")

# Advisory mode: a refusal must not halt siblings, so every worker gets a fair
# attempt and "exactly N succeed" is a meaningful assertion.
ADVISORY = GovernancePolicy(
    trip_on_overdraft=False,
    trip_on_exhaustion=False,
    max_calls_per_window=0,
)


def test_threads_racing_for_the_last_cent_cannot_double_spend() -> None:
    """40 threads, budget for exactly 10 calls. Exactly 10 may win."""
    unit = money("0.01")
    workers = 40
    affordable = 10

    gov = BudgetManager(policy=ADVISORY)
    gov.open_root("root", unit * affordable)
    barrier = threading.Barrier(workers)

    def attempt(_: int) -> bool:
        barrier.wait()  # maximise contention
        try:
            gov.spend("root", unit)
        except BudgetExceededError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(attempt, range(workers)))

    assert sum(results) == affordable
    assert gov.available("root") == ZERO
    gov.verify_integrity()


def test_concurrent_authorizations_never_overdraw_the_ledger() -> None:
    """Holds are encumbered across the whole call, not just the debit."""
    gov = BudgetManager(policy=ADVISORY)
    gov.open_root("root", money("1.00"))
    gov.delegate("root", "fanout", money("0.50"))

    hold = money("0.05")  # 10 concurrent holds fit; the 11th must not
    workers = 30
    barrier = threading.Barrier(workers)
    granted: list[object] = []
    lock = threading.Lock()

    def attempt(_: int) -> None:
        barrier.wait()
        try:
            auth = gov.authorize("fanout", hold)
        except BudgetExceededError:
            return
        with lock:
            granted.append(auth)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(attempt, range(workers)))

    assert len(granted) == 10
    assert gov.available("fanout") == ZERO, "every dollar is encumbered"
    gov.verify_integrity()


def test_sibling_subagents_cannot_spend_each_others_budget() -> None:
    """Delegation isolates siblings even under concurrent load."""
    gov = BudgetManager(policy=ADVISORY)
    gov.open_root("root", money("1.00"))
    for name in ("alpha", "beta", "gamma"):
        gov.delegate("root", name, money("0.10"))

    unit = money("0.01")
    succeeded: dict[str, int] = {"alpha": 0, "beta": 0, "gamma": 0}
    lock = threading.Lock()

    def hammer(scope: str) -> None:
        for _ in range(40):
            try:
                gov.spend(scope, unit)
            except BudgetExceededError:
                continue
            with lock:
                succeeded[scope] += 1

    threads = [
        threading.Thread(target=hammer, args=(scope,)) for scope in succeeded for _ in range(3)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Each sibling was capped at its own $0.10 = 10 calls, independently.
    assert succeeded == {"alpha": 10, "beta": 10, "gamma": 10}
    assert all(gov.available(scope) == ZERO for scope in succeeded)
    assert gov.available("root") == money("0.70")
    gov.verify_integrity()


def test_the_breaker_stops_a_runaway_thread_pool() -> None:
    """With enforcement on, an overdraw halts the subtree for everyone."""
    gov = BudgetManager()
    gov.open_root("root", money("0.10"))
    gov.delegate("root", "swarm", money("0.10"))

    unit = money("0.01")
    outcomes: list[bool] = []
    lock = threading.Lock()

    def attempt(_: int) -> None:
        try:
            gov.spend("swarm", unit)
            ok = True
        except AgentGovError:
            ok = False
        with lock:
            outcomes.append(ok)

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(attempt, range(200)))

    spent = sum(outcomes) * unit
    assert spent <= money("0.10"), "the envelope was never exceeded"
    assert gov.is_halted("swarm")
    assert gov.available("swarm") >= ZERO
    gov.verify_integrity()


def test_concurrent_asyncio_tasks_cannot_double_spend() -> None:
    """The same guarantee holds for asyncio sub-agents, on one lock.

    Run without pytest-asyncio so the suite has no plugin dependency.
    """
    unit = money("0.01")
    affordable = 10

    async def main() -> int:
        gov = BudgetManager(policy=ADVISORY)
        gov.open_root("root", unit * affordable)

        async def attempt() -> bool:
            await asyncio.sleep(0)  # yield, to interleave tasks
            try:
                gov.spend("root", unit)
            except BudgetExceededError:
                return False
            return True

        results = await asyncio.gather(*(attempt() for _ in range(40)))
        assert gov.available("root") == ZERO
        gov.verify_integrity()
        return sum(results)

    assert asyncio.run(main()) == affordable


def test_mixed_threads_and_asyncio_share_one_governor() -> None:
    """A threading.RLock is correct across both worlds; an asyncio.Lock is not."""
    unit = money("0.01")
    affordable = 20
    gov = BudgetManager(policy=ADVISORY)
    gov.open_root("root", unit * affordable)

    def sync_attempts() -> int:
        wins = 0
        for _ in range(30):
            try:
                gov.spend("root", unit)
            except BudgetExceededError:
                continue
            wins += 1
        return wins

    async def async_attempts() -> int:
        wins = 0
        for _ in range(30):
            await asyncio.sleep(0)
            try:
                gov.spend("root", unit)
            except BudgetExceededError:
                continue
            wins += 1
        return wins

    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(sync_attempts)
        async_wins = asyncio.run(async_attempts())
        sync_wins = future.result()

    assert sync_wins + async_wins == affordable
    assert gov.available("root") == ZERO
    gov.verify_integrity()
