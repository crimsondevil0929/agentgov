"""Concurrency tests: concurrent sub-agents must not double-spend.

These are the tests the component exists for. A budget governor that is
merely *usually* correct under concurrency is a governor that will one day
authorize two agents to spend the same dollar.
"""

from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

from agentgov.core import BudgetManager, EntryType, GovernancePolicy, money
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


# --------------------------------------------------------------------------
# High-concurrency stress: 50+ workers racing a budget to depletion
# --------------------------------------------------------------------------


def audit_spend(gov: BudgetManager, scope: str) -> tuple[int, Decimal, Decimal]:
    """Read settled spend back from the chain: (count, total, lowest balance).

    Deliberately reconstructed from ledger entries rather than from the
    workers' own bookkeeping — the point is to prove the *ledger* is right,
    not that the test counted correctly.
    """
    spends = [e for e in gov.audit_trail(scope) if e.entry_type is EntryType.SPEND]
    total = sum((e.amount for e in spends), ZERO)
    lowest = min((e.balance_after for e in spends), default=ZERO)
    return len(spends), total, lowest


def test_stress_64_threads_racing_a_depleted_budget() -> None:
    """64 worker threads, budget for exactly 25 calls. No double-spend."""
    unit = money("0.02")
    workers = 64
    affordable = 25

    gov = BudgetManager(policy=ADVISORY)
    gov.open_root("root", unit * affordable)
    barrier = threading.Barrier(workers)

    def attempt(_: int) -> bool:
        barrier.wait()  # release all 64 at the same instant
        try:
            gov.spend("root", unit)
        except BudgetExceededError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=workers) as pool:
        wins = sum(pool.map(attempt, range(workers)))

    count, total, lowest = audit_spend(gov, "root")
    assert wins == affordable, "exactly the affordable number of calls executed"
    assert count == wins, "one ledger entry per executed call, no more"
    assert total == unit * affordable, "not one unit of double-spend"
    assert lowest >= ZERO, "the balance never went negative, even transiently"
    assert gov.available("root") == ZERO
    gov.verify_integrity()
    gov.ledger.verify_conservation()


def test_stress_100_async_tasks_racing_a_depleted_budget() -> None:
    """100 concurrent asyncio sub-agents against a budget for 30 calls."""
    unit = money("0.02")
    tasks = 100
    affordable = 30

    async def main() -> tuple[int, BudgetManager]:
        gov = BudgetManager(policy=ADVISORY)
        gov.open_root("root", unit * affordable)
        started = asyncio.Event()

        async def attempt() -> bool:
            await started.wait()  # release every task together
            await asyncio.sleep(0)
            try:
                gov.spend("root", unit)
            except BudgetExceededError:
                return False
            return True

        pending = asyncio.gather(*(attempt() for _ in range(tasks)))
        started.set()
        return sum(await pending), gov

    wins, gov = asyncio.run(main())

    count, total, lowest = audit_spend(gov, "root")
    assert wins == affordable
    assert count == wins
    assert total == unit * affordable
    assert lowest >= ZERO
    assert gov.available("root") == ZERO
    gov.verify_integrity()
    gov.ledger.verify_conservation()


def test_stress_50_threads_and_50_async_tasks_share_one_envelope() -> None:
    """The hardest case: threads and an event loop contending simultaneously.

    This is what rules out ``asyncio.Lock``, which would leave the worker
    threads entirely unguarded.
    """
    unit = money("0.01")
    affordable = 40
    threads = 50
    tasks = 50

    gov = BudgetManager(policy=ADVISORY)
    gov.open_root("root", unit * affordable)
    gate = threading.Barrier(threads + 1)

    def thread_attempt(_: int) -> bool:
        gate.wait()
        try:
            gov.spend("root", unit)
        except BudgetExceededError:
            return False
        return True

    async def async_attempts() -> int:
        async def attempt() -> bool:
            await asyncio.sleep(0)
            try:
                gov.spend("root", unit)
            except BudgetExceededError:
                return False
            return True

        return sum(await asyncio.gather(*(attempt() for _ in range(tasks))))

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [pool.submit(thread_attempt, i) for i in range(threads)]
        gate.wait()  # threads and the loop start racing together
        async_wins = asyncio.run(async_attempts())
        thread_wins = sum(f.result() for f in futures)

    count, total, lowest = audit_spend(gov, "root")
    assert thread_wins + async_wins == affordable
    assert count == affordable
    assert total == unit * affordable
    assert lowest >= ZERO
    assert gov.available("root") == ZERO
    gov.verify_integrity()
    gov.ledger.verify_conservation()


def test_stress_64_workers_with_holds_across_a_simulated_call() -> None:
    """Contention across in-flight calls, not just instantaneous debits.

    Each worker holds funds, "calls the model", then settles for less. A
    governor that only debited at settlement would let all 64 through.

    The property is read from the chain, not from the scheduler. How many
    workers win depends on timing: a straggler that reaches ``authorize``
    after two winners have settled finds their unused headroom returned and
    legitimately wins too. What must never happen, however the threads
    interleave, is more than ten holds open at once — so that is what this
    asserts, by replaying every HOLD and its release in chain order. (It used
    to assert exactly ten winners, which a loaded machine could falsify.)
    """
    hold = money("0.05")
    settle = money("0.01")
    workers = 64
    concurrent_capacity = 10  # 10 holds of $0.05 fit in $0.50

    gov = BudgetManager(policy=ADVISORY)
    gov.open_root("root", hold * concurrent_capacity)
    barrier = threading.Barrier(workers)

    def attempt(_: int) -> bool:
        barrier.wait()
        try:
            auth = gov.authorize("root", hold)
        except BudgetExceededError:
            return False
        time.sleep(0.005)  # the model call is in flight; funds stay encumbered
        gov.capture(auth, settle)
        return True

    with ThreadPoolExecutor(max_workers=workers) as pool:
        wins = sum(pool.map(attempt, range(workers)))

    open_now = peak = 0
    for entry in gov.audit_trail("root"):
        if entry.entry_type is EntryType.HOLD:
            open_now += 1
            peak = max(peak, open_now)
        elif entry.entry_type is EntryType.HOLD_VOID:
            open_now -= 1

    count, total, lowest = audit_spend(gov, "root")
    assert 0 < peak <= concurrent_capacity, "holds bounded concurrency, not settlement"
    assert open_now == 0, "every hold was released"
    assert wins >= concurrent_capacity, "the first ten always fit"
    assert count == wins
    assert total == settle * wins
    assert lowest >= ZERO
    # Unused hold headroom came back once every call settled.
    assert gov.available("root") == hold * concurrent_capacity - total
    gov.verify_integrity()
    gov.ledger.verify_conservation()


def test_stress_enforced_mode_never_exceeds_the_envelope() -> None:
    """With the backstop armed, 80 workers cannot overshoot by one unit."""
    unit = money("0.01")
    envelope = money("0.20")

    gov = BudgetManager()
    gov.open_root("root", envelope)
    gov.delegate("root", "swarm", envelope)

    def attempt(_: int) -> None:
        try:
            gov.spend("swarm", unit)
        except AgentGovError:
            return

    with ThreadPoolExecutor(max_workers=80) as pool:
        list(pool.map(attempt, range(500)))

    count, total, lowest = audit_spend(gov, "swarm")
    assert total <= envelope, "the envelope was never breached"
    assert count * unit == total
    assert lowest >= ZERO
    assert gov.is_halted("swarm"), "the breaker latched closed"
    gov.verify_integrity()
    gov.ledger.verify_conservation()
