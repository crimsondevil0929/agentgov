"""Model-based tests: random operation sequences against a reference model.

A Hypothesis state machine drives a durable governor with random sequences of
every operation, each made under a random host :mod:`decimal` context, with
store failures injected at random write boundaries, and raw ledger writes
mixed in. After every step the governor must agree exactly with a small
reference model of what the operations mean, and must hold every invariant:

- **accepted means replayable**: everything committed verifies, and a fresh
  open from disk serves exactly the same state;
- **conservation**: no money is created or destroyed;
- **delegation**: no scope ever has more available than it was granted, and
  no scope is ever refunded more than it spent;
- **atomicity**: an operation whose write failed changed nothing.
"""

from __future__ import annotations

import decimal
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, settings
from hypothesis import strategies as st
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    consumes,
    invariant,
    precondition,
    rule,
)

from agentgov import BudgetManager, GovernancePolicy
from agentgov.core import QUANTUM, Authorization, Direction, EntryType, LedgerLine, WriteBatch
from agentgov.exceptions import (
    CircuitOpenError,
    DenialOfWalletError,
    DoubleSpendError,
    DuplicateScopeError,
    LedgerIntegrityError,
    StorageError,
    SubBudgetAllocationError,
    UnknownScopeError,
)
from agentgov.storage import SqliteStore

pytestmark = pytest.mark.filterwarnings("error::DeprecationWarning")

EXACT = decimal.Context(prec=60, traps=[decimal.Inexact, decimal.InvalidOperation])
ROUNDED = decimal.Context(prec=60, traps=[decimal.InvalidOperation])
MAX_DEPTH = 3
NAMES = ["a", "b", "c", "d", "e", "agent.research", "task/7", "pipe|name", "line\nbreak", "é"]


def floor(value: Decimal) -> Decimal:
    return value.quantize(QUANTUM, rounding=ROUND_FLOOR, context=ROUNDED)


def ceil(value: Decimal) -> Decimal:
    return value.quantize(QUANTUM, rounding=ROUND_CEILING, context=ROUNDED)


class _FlakyStore(SqliteStore):
    """A store whose next commit can be made to fail before it writes anything."""

    armed = False

    def commit(self, batch: WriteBatch) -> None:
        if self.armed and batch:
            self.armed = False
            raise StorageError("injected: the disk refused the write")
        super().commit(batch)


@dataclass
class _Node:
    parent: str | None
    depth: int
    allocated: Decimal


@dataclass
class _Model:
    """What the operations mean, written independently of the governor."""

    nodes: dict[str, _Node] = field(default_factory=dict)
    balance: dict[str, Decimal] = field(default_factory=dict)
    holds: dict[uuid.UUID, tuple[str, Decimal]] = field(default_factory=dict)
    tripped: set[str] = field(default_factory=set)
    spent: dict[str, Decimal] = field(default_factory=dict)
    refunded: dict[str, Decimal] = field(default_factory=dict)

    def halted(self, scope: str) -> bool:
        cursor: str | None = scope
        while cursor is not None:
            if cursor in self.tripped:
                return True
            cursor = self.nodes[cursor].parent
        return False

    def add(self, scope: str, amount: Decimal) -> None:
        self.balance[scope] = EXACT.add(self.balance.get(scope, Decimal(0)), amount)


HOSTILE_ROUNDING = [
    decimal.ROUND_DOWN,
    decimal.ROUND_UP,
    decimal.ROUND_HALF_UP,
    decimal.ROUND_FLOOR,
    decimal.ROUND_CEILING,
]


class GovernorMachine(RuleBasedStateMachine):
    """A governor under random operations, host contexts and write failures."""

    holds = Bundle("holds")

    def __init__(self) -> None:
        super().__init__()
        self.tmp = Path(tempfile.mkdtemp(prefix="agentgov-model-"))
        self.path = self.tmp / "ledger.db"
        self.policy = GovernancePolicy(max_calls_per_window=0, max_depth=MAX_DEPTH)
        self.store = _FlakyStore(self.path, synchronous="OFF")
        self.gov = BudgetManager(store=self.store, policy=self.policy)
        self.model = _Model()
        self.context: tuple[int, str] = (28, decimal.ROUND_HALF_EVEN)

    def teardown(self) -> None:
        try:
            self.gov.close()
            self.check_a_fresh_open_serves_the_same_state()
        finally:
            shutil.rmtree(self.tmp, ignore_errors=True)

    # -- harness ----------------------------------------------------------

    def call(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        """Run ``fn`` under the host context this step drew."""
        prec, rounding = self.context
        with decimal.localcontext() as ctx:
            ctx.prec = prec
            ctx.rounding = rounding
            ctx.traps[decimal.Inexact] = prec < 12
            return fn(*args, **kwargs)

    @rule(prec=st.integers(1, 28), rounding=st.sampled_from(HOSTILE_ROUNDING))
    def change_the_host_context(self, prec: int, rounding: str) -> None:
        self.context = (prec, rounding)

    @rule()
    def arm_a_write_failure(self) -> None:
        self.store.armed = True

    def failed_write(self) -> bool:
        """Consume an armed failure, if the operation was going to write."""
        armed = self.store.armed
        self.store.armed = False
        return armed

    # -- operations -------------------------------------------------------

    @rule(name=st.sampled_from(NAMES), amount=st.decimals(-1, 5, places=10))
    def open_root(self, name: str, amount: Decimal) -> None:
        m = self.model
        credited = floor(amount)
        if credited <= 0:
            with pytest.raises(ValueError):
                self.call(self.gov.open_root, name, amount)
            return
        if name in m.nodes:
            with pytest.raises(DuplicateScopeError):
                self.call(self.gov.open_root, name, amount)
            return
        if self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.open_root, name, amount)
            return
        self.call(self.gov.open_root, name, amount)
        m.nodes[name] = _Node(None, 0, credited)
        m.add(name, credited)

    @rule(name=st.sampled_from(NAMES), amount=st.decimals(-1, 2, places=10))
    def fund(self, name: str, amount: Decimal) -> None:
        m = self.model
        credited = floor(amount)
        if credited <= 0:
            with pytest.raises(ValueError):
                self.call(self.gov.fund, name, amount)
        elif name not in m.nodes:
            with pytest.raises(UnknownScopeError):
                self.call(self.gov.fund, name, amount)
        elif m.nodes[name].parent is not None:
            with pytest.raises(ValueError, match="not a root"):
                self.call(self.gov.fund, name, amount)
        elif self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.fund, name, amount)
        else:
            self.call(self.gov.fund, name, amount)
            node = m.nodes[name]
            node.allocated = EXACT.add(node.allocated, credited)
            m.add(name, credited)

    @rule(
        parent=st.sampled_from(NAMES),
        child=st.sampled_from(NAMES),
        amount=st.decimals(-1, 2, places=10),
    )
    def delegate(self, parent: str, child: str, amount: Decimal) -> None:
        m = self.model
        granted = floor(amount)
        if granted <= 0:
            with pytest.raises(ValueError):
                self.call(self.gov.delegate, parent, child, amount)
        elif parent not in m.nodes:
            with pytest.raises(UnknownScopeError):
                self.call(self.gov.delegate, parent, child, amount)
        elif child in m.nodes:
            with pytest.raises(DuplicateScopeError):
                self.call(self.gov.delegate, parent, child, amount)
        elif m.halted(parent):
            with pytest.raises(CircuitOpenError):
                self.call(self.gov.delegate, parent, child, amount)
        elif m.nodes[parent].depth + 1 > MAX_DEPTH or granted > m.balance[parent]:
            with pytest.raises(SubBudgetAllocationError):
                self.call(self.gov.delegate, parent, child, amount)
        elif self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.delegate, parent, child, amount)
        else:
            self.call(self.gov.delegate, parent, child, amount)
            m.nodes[child] = _Node(parent, m.nodes[parent].depth + 1, granted)
            m.add(parent, -granted)
            m.add(child, granted)

    @rule(name=st.sampled_from(NAMES), amount=st.none() | st.decimals(-1, 2, places=10))
    def release(self, name: str, amount: Decimal | None) -> None:
        m = self.model
        if name not in m.nodes:
            with pytest.raises(UnknownScopeError):
                self.call(self.gov.release, name, amount)
            return
        node = m.nodes[name]
        if node.parent is None:
            with pytest.raises(ValueError, match="no parent"):
                self.call(self.gov.release, name, amount)
            return
        available = m.balance[name]
        returned = available if amount is None else floor(amount)
        if returned <= 0:
            assert self.call(self.gov.release, name, amount) == 0
        elif returned > available:
            with pytest.raises(ValueError, match="only"):
                self.call(self.gov.release, name, amount)
        elif self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.release, name, amount)
        else:
            assert self.call(self.gov.release, name, amount) == returned
            m.add(name, -returned)
            m.add(node.parent, returned)

    def _would_trip(self, scope: str) -> bool:
        return scope not in self.model.tripped

    @rule(target=holds, name=st.sampled_from(NAMES), amount=st.decimals(-1, 1, places=10))
    def authorize(self, name: str, amount: Decimal) -> Authorization | None:
        m = self.model
        held = ceil(amount)
        if held <= 0:
            with pytest.raises(ValueError):
                self.call(self.gov.authorize, name, amount)
            return None
        if name not in m.nodes:
            with pytest.raises(UnknownScopeError):
                self.call(self.gov.authorize, name, amount)
            return None
        if m.halted(name):
            with pytest.raises(CircuitOpenError):
                self.call(self.gov.authorize, name, amount)
            return None
        if held > m.balance[name]:
            # The refusal trips the breaker, in a write of its own.
            if self.failed_write():
                self.store.armed = True
                with pytest.raises(StorageError):
                    self.call(self.gov.authorize, name, amount)
                return None
            with pytest.raises(DenialOfWalletError):
                self.call(self.gov.authorize, name, amount)
            m.tripped.add(name)
            return None
        if self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.authorize, name, amount)
            return None
        auth: Authorization = self.call(self.gov.authorize, name, amount)
        assert auth.amount == held
        m.holds[auth.authorization_id] = (name, held)
        m.add(name, -held)
        return auth

    def _settle(self, auth: Authorization, settled: Decimal) -> bool:
        """Apply a capture's effect to the model; return whether it overdrew."""
        m = self.model
        scope, held = m.holds.pop(auth.authorization_id)
        m.add(scope, EXACT.subtract(held, settled))
        m.spent[scope] = EXACT.add(m.spent.get(scope, Decimal(0)), settled)
        overdrawn = m.balance[scope] < 0
        others = any(s == scope for s, _ in m.holds.values())
        if overdrawn or (m.balance[scope] <= 0 and not others):
            m.tripped.add(scope)
        return overdrawn

    @rule(auth=consumes(holds), cost=st.decimals(-1, 1, places=10))
    def capture(self, auth: Authorization | None, cost: Decimal) -> None:
        if auth is None:
            return
        m = self.model
        settled = ceil(cost)
        if settled < 0:
            with pytest.raises(ValueError):
                self.call(self.gov.capture, auth, cost)
            return
        if auth.authorization_id not in m.holds:
            with pytest.raises(DoubleSpendError):
                self.call(self.gov.capture, auth, cost)
            return
        if self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.capture, auth, cost)
            return
        if settled == 0:
            self.call(self.gov.capture, auth, cost)
            scope, held = m.holds.pop(auth.authorization_id)
            m.add(scope, held)
            return
        scope, held = m.holds[auth.authorization_id]
        if EXACT.add(m.balance[scope], EXACT.subtract(held, settled)) < 0:
            with pytest.raises(DenialOfWalletError) as raised:
                self.call(self.gov.capture, auth, cost)
            assert raised.value.overspent
        else:
            entry = self.call(self.gov.capture, auth, cost)
            assert entry.amount == settled
        self._settle(auth, settled)

    @rule(auth=consumes(holds))
    def void(self, auth: Authorization | None) -> None:
        if auth is None:
            return
        m = self.model
        if auth.authorization_id not in m.holds:
            with pytest.raises(DoubleSpendError):
                self.call(self.gov.void, auth)
            return
        if self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.void, auth)
            return
        self.call(self.gov.void, auth)
        scope, held = m.holds.pop(auth.authorization_id)
        m.add(scope, held)

    @rule(auth=holds)
    def capture_twice_is_a_double_spend(self, auth: Authorization | None) -> None:
        if auth is None or auth.authorization_id in self.model.holds:
            return
        with pytest.raises(DoubleSpendError):
            self.call(self.gov.capture, auth, Decimal("0.01"))

    @rule(name=st.sampled_from(NAMES), amount=st.decimals(-1, 1, places=10))
    def refund(self, name: str, amount: Decimal) -> None:
        m = self.model
        credited = floor(amount)
        if credited <= 0:
            with pytest.raises(ValueError):
                self.call(self.gov.refund, name, amount)
            return
        if name not in m.nodes:
            with pytest.raises(UnknownScopeError):
                self.call(self.gov.refund, name, amount)
            return
        refundable = EXACT.subtract(m.spent.get(name, Decimal(0)), m.refunded.get(name, Decimal(0)))
        if credited > refundable:
            with pytest.raises(ValueError, match="cannot refund"):
                self.call(self.gov.refund, name, amount)
            return
        if self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.refund, name, amount)
            return
        self.call(self.gov.refund, name, amount)
        m.refunded[name] = EXACT.add(m.refunded.get(name, Decimal(0)), credited)
        m.add(name, credited)

    @rule(name=st.sampled_from(NAMES), memo=st.text(max_size=20))
    def anchor(self, name: str, memo: str) -> None:
        if not memo:
            with pytest.raises(ValueError):
                self.call(self.gov.anchor, name, memo)
        elif name not in self.model.nodes:
            with pytest.raises(UnknownScopeError):
                self.call(self.gov.anchor, name, memo)
        elif self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.anchor, name, memo)
        else:
            entry = self.call(self.gov.anchor, name, memo)
            assert entry.memo == memo

    @rule(name=st.sampled_from(NAMES))
    def trip(self, name: str) -> None:
        m = self.model
        if name not in m.nodes:
            with pytest.raises(UnknownScopeError):
                self.call(self.gov.trip, name, "operator")
        elif name in m.tripped:
            self.call(self.gov.trip, name, "operator")  # already latched: a no-op
        elif self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.trip, name, "operator")
        else:
            self.call(self.gov.trip, name, "operator")
            m.tripped.add(name)

    @rule(name=st.sampled_from(NAMES))
    def reset(self, name: str) -> None:
        m = self.model
        if name not in m.nodes:
            with pytest.raises(UnknownScopeError):
                self.call(self.gov.reset, name)
        elif name not in m.tripped:
            self.call(self.gov.reset, name)  # nothing to reset
        elif self.failed_write():
            self.store.armed = True
            with pytest.raises(StorageError):
                self.call(self.gov.reset, name)
        else:
            self.call(self.gov.reset, name)
            m.tripped.discard(name)

    @rule(
        kind=st.sampled_from(list(EntryType)),
        direction=st.sampled_from(list(Direction)),
        scope=st.sampled_from([*NAMES, ""]),
        counterparty=st.none() | st.sampled_from(NAMES),
        amount=st.decimals(0, 2, places=8),
    )
    def raw_write(
        self,
        kind: EntryType,
        direction: Direction,
        scope: str,
        counterparty: str | None,
        amount: Decimal,
    ) -> None:
        """Whatever a raw write the rules accept does, the model follows; a
        raw write the rules refuse changes nothing."""
        line = LedgerLine(kind, direction, scope, amount, counterparty, memo="raw")
        before = self.snapshot()
        armed = self.store.armed
        try:
            self.call(self.gov.ledger._post, [line])
        except (ValueError, LedgerIntegrityError):
            assert self.snapshot() == before, "a refused write changed the ledger"
            return
        except StorageError:
            assert armed, "only an injected failure fails a write here"
            assert self.snapshot() == before, "a failed write changed the ledger"
            return
        self.follow_an_accepted_raw_write(line)

    def follow_an_accepted_raw_write(self, line: LedgerLine) -> None:
        m = self.model
        kind, scope, amount = line.entry_type, line.scope_id, line.amount
        if kind is EntryType.FUNDING:
            if scope in m.nodes:
                m.nodes[scope].allocated = EXACT.add(m.nodes[scope].allocated, amount)
            else:
                m.nodes[scope] = _Node(None, 0, amount)
            m.add(scope, amount)
        elif kind is EntryType.SPEND:
            m.spent[scope] = EXACT.add(m.spent.get(scope, Decimal(0)), amount)
            m.add(scope, -amount)
        elif kind is EntryType.REVERSAL:
            m.refunded[scope] = EXACT.add(m.refunded.get(scope, Decimal(0)), amount)
            m.add(scope, amount)
        elif kind is EntryType.HOLD:
            (hold,) = self.gov.ledger.entries()[-1:]
            m.holds[hold.entry_id] = (scope, amount)
            m.add(scope, -amount)
        elif kind is EntryType.CIRCUIT_TRIPPED:
            m.tripped.add(scope)
        elif kind is EntryType.CIRCUIT_RESET:
            m.tripped.discard(scope)
        else:
            assert kind is EntryType.ANCHOR, f"the rules accepted a raw {kind.value}"

    # -- invariants -------------------------------------------------------

    def snapshot(self) -> tuple[object, ...]:
        gov = self.gov
        return (
            len(gov.ledger),
            gov.ledger.head_hash,
            gov.ledger.balances(),
            tuple(sorted(gov._open_auths, key=str)),
            tuple(sorted((s, gov.is_halted(s)) for s in gov.scopes())),
        )

    @invariant()
    def the_governor_agrees_with_the_model(self) -> None:
        gov, m = self.gov, self.model
        assert set(gov.scopes()) == set(m.nodes)
        for scope, node in m.nodes.items():
            served = gov.node(scope)
            assert (served.parent_id, served.depth, served.allocated) == (
                node.parent,
                node.depth,
                node.allocated,
            ), scope
            assert gov.available(scope) == m.balance[scope], scope
            assert gov.is_halted(scope) == m.halted(scope), scope
        assert set(gov._open_auths) == set(m.holds)

    @invariant()
    def accepted_means_replayable(self) -> None:
        self.gov.verify_integrity()

    @invariant()
    def no_scope_holds_more_than_it_was_granted(self) -> None:
        m = self.model
        for scope, node in m.nodes.items():
            assert self.gov.available(scope) <= node.allocated, scope
            assert m.refunded.get(scope, Decimal(0)) <= m.spent.get(scope, Decimal(0)), scope

    @precondition(lambda self: len(self.gov.ledger) > 0)
    @rule()
    def reopen_from_disk(self) -> None:
        self.gov.close()
        self.check_a_fresh_open_serves_the_same_state()
        self.store = _FlakyStore(self.path, synchronous="OFF")
        self.gov = BudgetManager(store=self.store, policy=self.policy)

    def check_a_fresh_open_serves_the_same_state(self) -> None:
        with BudgetManager.open_sqlite(str(self.path), read_only=True) as reopened:
            reopened.verify_integrity()
            assert set(reopened.scopes()) == set(self.model.nodes)
            for scope in self.model.nodes:
                assert reopened.available(scope) == self.model.balance[scope]
                assert reopened.is_halted(scope) == self.model.halted(scope)
            assert set(reopened._open_auths) == set(self.model.holds)


# AGENTGOV_MODEL_EXAMPLES raises the budget for a deep run (CI's nightly job
# uses thousands); the default keeps the suite quick.
GovernorMachine.TestCase.settings = settings(
    max_examples=int(os.environ.get("AGENTGOV_MODEL_EXAMPLES", "250")),
    stateful_step_count=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
test_governor_against_the_model = GovernorMachine.TestCase
