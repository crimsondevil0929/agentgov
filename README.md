# AgentGov

**The runtime spend governor and denial-of-wallet circuit breaker for autonomous agent fleets.**

[![tests](https://img.shields.io/badge/tests-113%2F113%20passing-brightgreen)](#code-quality--packaging)
[![coverage](https://img.shields.io/badge/coverage-98%25-brightgreen)](#code-quality--packaging)
[![dependencies](https://img.shields.io/badge/core%20dependencies-zero-blue)](pyproject.toml)
[![mypy](https://img.shields.io/badge/mypy-strict-blue)](pyproject.toml)
[![license](https://img.shields.io/badge/license-Apache%202.0-lightgrey)](LICENSE)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

When an agent spawns sub-agents that spawn tools, nothing in today's stack enforces a
dollar ceiling on the *tree*. Per-account rate limits watch one caller; they cannot see
a fan-out of 50 sub-agents each making a handful of "reasonable" calls that, together,
burn a budget in seconds. AgentGov sits below the payment layer as that missing control
plane: a hierarchical, capability-scoped spend envelope over an immutable, hash-chained
ledger, with a circuit breaker that halts a runaway branch before settlement — not after.

Zero runtime dependencies. Pure standard library (`decimal`, `hashlib`, `threading`,
`asyncio`-compatible). `mypy --strict` clean.

---

## The benchmark

[`examples/denial_of_wallet_benchmark.py`](examples/denial_of_wallet_benchmark.py) runs
the *identical* runaway-agent workload twice — once with no backstop, once behind
AgentGov with a $5.00 envelope — and diffs the outcome. Same orchestrator logic, same
simulated model, same 3 seconds of wall clock; only the harness differs.

```
+=======================+==========================+======================================+
| METRIC                | Scenario A - Ungoverned  |        Scenario B - AgentGov         |
+=======================+==========================+======================================+
| Wall clock            |                    3.00s |                                3.00s |
| Sub-agents spawned    |                      124 |                                   11 |
| Calls attempted       |                1,233,936 |                              771,631 |
| Calls executed        |                1,233,936 |                                  647 |
| Calls refused         |                        0 |                              770,984 |
| Tokens consumed       |              400,254,431 |                              201,683 |
+-----------------------+--------------------------+--------------------------------------+
| Intended budget       |                $5.000000 |                            $5.000000 |
| Actual cost realized  |            $9,883.167155 |                            $4.990315 |
| Cost vs budget        |               197,663.3% |                                99.8% |
| Budget breached after |                   0.002s |                                never |
+-----------------------+--------------------------+--------------------------------------+
| Circuit breaker       | n/a - no backstop exists |   LATCHED OPEN - 11/12 scopes halted |
| verify_integrity()    |   n/a - no ledger exists |          PASS - 1986 entries chained |
| verify_conservation() |   n/a - no ledger exists | PASS - no money created or destroyed |
+=======================+==========================+======================================+
```

**Ungoverned:** 1.2M calls in 3 seconds, $9,883 realized against a $5.00 intended
budget — breached in 2 milliseconds and never stopped. **AgentGov:** capped at 647
executed calls, $4.990315 settled of the $5.00 envelope (99.8% utilization, nothing
stranded), 770,984 further attempts refused, breaker latched open on the exhausted
branch. The governed run's cost is bit-for-bit deterministic across repeated runs —
it is bounded by the budget, not by how many iterations the clock happened to allow.

Reproduce it: `uv run python examples/denial_of_wallet_benchmark.py`. Add `--audit` to
stream every hash-chained ledger line live instead of a tail sample.

Every number above is checked, not narrated. `verify_integrity()` re-derives the
SHA-256 chain and the delegation topology; `verify_conservation()` checks the identity

```
Σ(scope balances) + outstanding_holds + settled_spend − reversals == funded
```

across every scope in the tree. Money is never created, destroyed, or double-counted —
it only ever moves between a parent and a child, or out to a vendor.

---

## Why naive rate limiters fail here, and what replaces each failure

| Naive approach | Where it fails | AgentGov's answer |
|---|---|---|
| Decrement-then-check a counter | Two concurrent sub-agents can both read "funds available" before either writes — a classic TOCTOU race that lets both spend the same dollar | **Authorize → Hold → Settle.** A call reserves its worst-case cost *before* it runs; the hold is encumbered and invisible to concurrent siblings until it settles. Two agents racing for the last cent cannot both win — proven under 64 threads and 100 asyncio tasks contending for one envelope simultaneously. |
| Retry until it works | An agent (or a human debugging one) that ignores a rejection and keeps calling will eventually get through once a competing hold releases | **A latching circuit breaker.** Once a scope overdraws, its breaker trips and *stays* tripped — every subsequent call fails fast with `CircuitOpenError`, independent of balance, until an operator explicitly calls `reset()`. Retry storms cannot wear it down. |
| A dashboard counter or log line | If someone edits the number after the fact, there is no way to tell | **A cryptographic double-entry ledger.** Every economic event is an immutable entry chained to its predecessor by SHA-256 (`prev_hash → entry_hash`); `verify_chain()` re-derives every hash and catches any retroactive edit, including a tampered balance. |
| A single flat quota per API key | Says nothing about *which* sub-agent in a fan-out is responsible, and can't bound a tree that recurses | **A budget DAG.** A root agent's envelope is sub-delegated down a tree of scopes; no descendant can ever spend or re-delegate more than its ancestors granted it, at any depth. |

## Quickstart

Wrap an existing model call and give a sub-agent tree its own budget in a handful
of lines:

```python
from agentgov import BudgetManager, Interceptor, money

gov = BudgetManager()
gov.open_root("orchestrator", money("5.00"))  # the whole fleet's envelope
gov.delegate("orchestrator", "researcher", money("1.00"))  # a sub-agent's slice

metered = Interceptor(gov, "researcher", model="claude-opus-5")
result = metered.invoke(client.messages.create, model="claude-opus-5", messages=[...])

print(result.cost, gov.available("researcher"))  # exact settled cost, remaining budget
```

That's it: `invoke()` authorizes a worst-case hold, runs your call with no lock held,
prices the model's real token usage, and settles atomically. Let it run past budget and
you get `DenialOfWalletError`, not a silent overspend:

```python
from agentgov.exceptions import CircuitOpenError, DenialOfWalletError

try:
    metered.invoke(client.messages.create, model="claude-opus-5", messages=[...])
except DenialOfWalletError:
    ...  # refused pre-flight; the breaker just latched for this scope and its subtree
except CircuitOpenError:
    ...  # already latched from an earlier trip; this call never touched the ledger
```

See [`src/agentgov/core.py`](src/agentgov/core.py) for the ledger and budget DAG,
[`src/agentgov/interceptor.py`](src/agentgov/interceptor.py) for the call-site wrapper,
and [`tests/test_runaway.py`](tests/test_runaway.py) for the recursive-spawn scenario
the design exists to stop.

## Core primitives

- **Authorize → Hold → Settle.** `BudgetManager.authorize()` places an encumbering hold
  before a call is made; `capture()` releases it and posts the true cost as one atomic
  ledger transaction. Funds are unavailable to siblings for the *entire* in-flight
  duration of a call, not just at the instant of debit — the mechanism that makes
  double-spend structurally impossible rather than merely unlikely under load.
- **Latching circuit breaker.** A trip on `overdraft`, `runaway-loop velocity`, or
  `budget exhaustion` halts the scope *and every descendant beneath it*, and stays
  halted until an operator calls `reset()`. A `DenialOfWalletError` on overdraw and a
  `RunawayLoopDetectedError` on call-frequency abuse both trip it; every subsequent
  attempt then fails fast with `CircuitOpenError` without touching the ledger at all.
- **Cryptographic double-entry ledger.** Every line is a DEBIT or CREDIT against exactly
  one scope; internal transfers post balanced pairs in a single transaction. Entries are
  hash-chained with SHA-256 and never mutated — corrections are compensating entries,
  never edits — so `verify_chain()` can prove the entire history is exactly what it
  claims to be, and `verify_conservation()` can prove no money was invented along the way.

## Roadmap — Phase 2

Phase 1 is a correct, single-process governor: one ledger, one mutex, in-memory state.
The evolution beyond that:

- **Distributed multi-node consensus.** Move the ledger off a single process's memory
  onto a replicated store, so a fleet spanning multiple hosts shares one authoritative
  view of every scope's balance without reintroducing the double-spend race this design
  eliminates locally.
- **x402 / AP2 settlement integration.** Use AgentGov's authorize/capture holds as the
  enforcement point those protocols gesture at but don't enforce at runtime — settling
  real sub-cent agent transactions through a payment rail instead of a simulated ledger.
- **Enterprise SecOps control plane.** Centralized policy management, breaker-trip
  alerting, and per-tenant audit export, so the hash-chained trail this library already
  produces plugs into an org's existing compliance and incident-response tooling.

## Code quality & packaging

```bash
uv sync                              # install (zero runtime dependencies)
uv run pytest -v                     # 113 passed
uv run pytest --cov=agentgov         # 98% coverage
uv run ruff check . && uv run ruff format --check .
uv run mypy src/                     # strict, zero errors
uv run python examples/denial_of_wallet_benchmark.py
```

Packaged with [uv](https://docs.astral.sh/uv/); metadata, license, and classifiers live
in [`pyproject.toml`](pyproject.toml). Licensed under [Apache 2.0](LICENSE).
