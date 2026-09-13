# AgentGov

**The runtime spend governor and denial-of-wallet circuit breaker for autonomous agent fleets.**

[![tests](https://img.shields.io/badge/tests-178%2F178%20passing-brightgreen)](#code-quality--packaging)
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
A second, *cognitive* breaker attacks the root cause: it detects the agent looping without
making progress and halts it for a fraction of a cent, long before the envelope is touched.
The ledger, topology, and any in-flight authorization survive a process crash, backed by
SQLite via the standard library.

Zero runtime dependencies. Pure standard library (`decimal`, `hashlib`, `threading`,
`sqlite3`, `asyncio`-compatible). `mypy --strict` clean.

---

## The benchmark

[`examples/denial_of_wallet_benchmark.py`](examples/denial_of_wallet_benchmark.py) runs
the *identical* runaway-agent workload three times — with no backstop, with a $5.00
spend envelope, and with the envelope plus cognitive loop detection — and diffs the
outcome. Same orchestrator logic, same simulated model, same 3 seconds of wall clock.

```
+=======================+==========================+======================================+======================================================+
| METRIC                | Scenario A - Ungoverned  |  Scenario B - AgentGov (Financial)   |    Scenario C - AgentGov (Cognitive + Financial)     |
+=======================+==========================+======================================+======================================================+
| Wall clock            |                    3.00s |                                3.00s |                                                3.00s |
| Sub-agents spawned    |                      116 |                                   11 |                                                    1 |
| Calls attempted       |                1,154,031 |                              656,393 |                                              239,340 |
| Calls executed        |                1,154,031 |                                  636 |                                                    3 |
| Calls refused         |                        0 |                              655,757 |                                              239,337 |
| Tokens consumed       |              376,598,574 |                              207,756 |                                                  770 |
+-----------------------+--------------------------+--------------------------------------+------------------------------------------------------+
| Intended budget       |                $5.000000 |                            $5.000000 |                                            $5.000000 |
| Actual cost realized  |            $9,057.214750 |                            $4.996920 |                                            $0.018330 |
| Cost vs budget        |               181,144.3% |                                99.9% |                                                 0.4% |
| Budget breached after |                   0.002s |                                never |                                                never |
+-----------------------+--------------------------+--------------------------------------+------------------------------------------------------+
| Cognitive breaker     |        n/a - not enabled |                    n/a - not enabled | TRIPPED [deterministic/near_duplicate] after 4 calls |
| Financial breaker     | n/a - no backstop exists |   LATCHED OPEN - 11/12 scopes halted |                     LATCHED OPEN - 1/2 scopes halted |
| verify_integrity()    |   n/a - no ledger exists |          PASS - 1953 entries chained |                            PASS - 12 entries chained |
| verify_conservation() |   n/a - no ledger exists | PASS - no money created or destroyed |                 PASS - no money created or destroyed |
+=======================+==========================+======================================+======================================================+
```

All three run the *identical* workload — an agent that cannot find a report and keeps
re-asking with cosmetic edits. The governed scenarios differ by exactly one constructor
argument, so the third column isolates what loop detection buys and nothing else.

**A — Ungoverned:** 1.2M calls in 3 seconds, $9,057 against a $5.00 intended budget,
breached in 2 milliseconds and never stopped. **B — Financial:** capped at $4.996920 of
the $5.00 envelope, 655,757 further attempts refused. Correct — but the money is gone;
the envelope bounds the damage rather than preventing it. **C — Cognitive + financial:**
halted after **3 executed calls and $0.018330**, 0.4% of the envelope and **273x cheaper
than waiting for the budget to run out**. The remaining 239,337 attempts cost nothing at
all: the check runs ahead of the authorization hold, so a halted call never reaches the
ledger. Both governed costs are bit-for-bit deterministic across runs — bounded by the
policy, not by how many iterations the clock happened to allow.

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
| A dedupe cache on tool calls | Catches byte-identical repeats and nothing else. An agent nudging one word per attempt defeats it on every call while making no progress at all | **A cognitive breaker.** Character-shingle similarity, call-graph cycle detection, and an off-thread novelty tracker catch the *soft* loop — cosmetically different calls that go nowhere — and halt it for cents rather than dollars. |
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

## The cognitive circuit breaker

The financial breaker is reactive by construction: it fires when the money is gone. The
cognitive breaker attacks the cause — the open-loop execution cycle that spends it.
Attach one and every call is checked for thrashing *before* its hold is placed:

```python
from agentgov import BudgetManager, CognitiveBreaker, Interceptor, money

gov = BudgetManager()
gov.open_root("researcher", money("5.00"))
breaker = CognitiveBreaker(manager=gov)  # trips latch the financial breaker too

metered = Interceptor(gov, "researcher", model="claude-opus-5", cognitive=breaker)
metered.invoke(client.messages.create, model="claude-opus-5", messages=[...])
# agentgov.exceptions.AgentThrashingError: Agent thrashing halted for scope 'researcher'
#   after 4 calls [deterministic/near_duplicate, confidence 0.78]: 4 consecutive
#   near-identical calls with no semantic progress
```

**Two tiers, one actuator.**

*Tier 1 runs inline and is deterministic* — three stateless detectors over a bounded
ring buffer: `ExactRepeatDetector` (identical fingerprints), `NearDuplicateDetector`
(character-shingle Jaccard between consecutive calls — the soft loop), and
`CallCycleDetector` (an A→B→A→B oscillation that no pairwise check can see). Measured
overhead is **77µs mean / 122µs p99** even with pathological 8KB arguments — roughly
0.005% of a real model call. Arguments are truncated before shingling and comparisons
are window-capped, so the cost is bounded rather than merely small.

*Tier 2 runs off-thread and is semantic* — a daemon worker drains a bounded queue and
runs a `SemanticObserver`. The shipped `TrajectoryEntropyObserver` tracks novelty decay:
what fraction of each call is vocabulary the trajectory has never produced. An agent
cycling six phrasings of one idea has low pairwise similarity but near-zero novelty.
**The agent thread never waits for it** — a verdict is latched and enforced on the *next*
call, so detection is one call late rather than blocking, and a saturated queue sheds
samples instead of applying backpressure. This is the seam where an LLM-judge observer
plugs in: implement `evaluate()` and change nothing else.

A cognitive trip calls `BudgetManager.trip()`, so it inherits latching, subtree
propagation, hash-anchored control events, and durable persistence from the machinery
that already exists — one halt mechanism, two families of sensor. The verdict is computed
under the cognitive lock and the financial lock is taken only after releasing it, so the
two are never held at once and no lock-ordering hazard exists.

**Extending it.** `LoopDetector` and `SemanticObserver` are Protocols; a detector that
knows your tool schema will beat any generic text heuristic. Pass `detectors=[...]` to
extend or replace the built-ins. A detector that raises is logged and skipped, so one bad
custom heuristic degrades detection rather than breaking production traffic.

**Where it does not reach — stated plainly.** Legitimate iteration (pagination,
map-over-a-list) looks like a soft loop on *input* similarity alone. The discriminator is
the result: near-identical inputs producing near-identical outputs is thrashing;
near-identical inputs producing different outputs is progress. The `Interceptor` feeds
results back automatically, which handles the common case. It still cannot see through a
*templated* result whose only variation is an index (`record-1-0`, `record-2-0`) — those
are near-identical in trigram space even though the agent is advancing. That limitation
is [pinned by a test](tests/test_cognitive_breaker.py), along with its remedy:
`CognitivePolicy(exempt_tools={"fetch"})`, a raised threshold, or a custom detector.

## Durability

An in-memory ledger that calls itself an auditable financial record is a contradiction —
restart the process and the audit trail is gone. Swap `BudgetManager()` for
`BudgetManager.open_sqlite(path)` and every write goes through to disk first, in the same
atomic transaction, before it ever touches memory:

```python
with BudgetManager.open_sqlite("governor.db") as gov:
    gov.open_root("orchestrator", money("5.00"))
    ...  # identical API — every write is durable before it's visible in memory
```

Reopen that file in a brand new process and the ledger, the delegation tree, every
circuit-breaker trip, and any authorization left mid-call are restored exactly —
[`examples/persistence_demo.py`](examples/persistence_demo.py) proves this with two
genuinely separate `python` subprocesses, not just a discarded object:

```bash
uv run python examples/persistence_demo.py
```

```
--- process 1: writes state, then exits completely ---
WRITER  balance(researcher)=0.65000000
WRITER  halted(scraper)=True
WRITER  chain_length=15
WRITER  open_authorization_id=24b1af62-e7ac-4b54-b2fb-2475f6c40006

--- process 2: independent interpreter, same file ---
READER  verify_integrity() = PASS
READER  balance(researcher)=0.65000000
READER  halted(scraper)=True
READER  chain_length=15
READER  open_authorizations=1
READER  scraper still refuses calls: Scope 'scraper' is halted by its own breaker: ...
```

A database that has been tampered with — or merely corrupted by a crash mid-write — is
refused at open time, not served with a wrong balance: `open_sqlite()` re-runs
`verify_chain()` and `verify_integrity()` before handing back a governor at all. This
uses only `sqlite3` from the standard library, so durability adds zero runtime
dependencies. Honest limitation: a hold still open when a process dies (an agent that
crashed between `authorize()` and `capture()`) comes back on restart as an *open*
authorization for an operator — or the caller, if it kept the id — to void or capture by
hand; automatically resolving it would mean guessing whether the call it was reserving
funds for actually happened, which this library will not do silently. See
[`tests/test_persistence.py`](tests/test_persistence.py) for the full restart, corruption,
and durable-write-failure test matrix.

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
- **A cognitive breaker on the same actuator.** Deterministic loop detection inline
  (77µs mean) plus a semantic observer off-thread, halting a thrashing agent for cents
  instead of dollars and recording the verdict in the same hash-anchored audit trail as
  every financial event. See [The cognitive circuit breaker](#the-cognitive-circuit-breaker).
- **Write-through durability.** `BudgetManager.open_sqlite()` writes every ledger entry,
  topology change, breaker trip, and open authorization to disk *before* committing it to
  memory, so a store failure aborts the operation instead of leaving memory ahead of disk.
  A corrupted or tampered file refuses to load rather than being trusted. See
  [Durability](#durability) above.

## Roadmap — Phase 2

Phase 1 is a correct, single-process governor: one ledger, one mutex, durable to a local
SQLite file, with financial and cognitive breakers on the same actuator. Beyond that:

- **Distributed multi-node consensus.** `agentgov.storage.PersistenceStore` is already the
  seam a replicated backend would implement — move the ledger off one host's disk onto a
  store shared across a fleet, so multiple machines share one authoritative view of every
  scope's balance without reintroducing the double-spend race this design eliminates
  locally.
- **x402 / AP2 settlement integration.** Use AgentGov's authorize/capture holds as the
  enforcement point those protocols gesture at but don't enforce at runtime — settling
  real sub-cent agent transactions through a payment rail instead of a simulated ledger.
- **A shipped LLM-judge observer.** Tier 2's `SemanticObserver` seam already accepts one;
  what is missing is a batteries-included implementation with its own cost accounting, so
  the observer that watches for waste cannot itself become a source of it.
- **Enterprise SecOps control plane.** Centralized policy management, breaker-trip
  alerting, and per-tenant audit export, so the hash-chained trail this library already
  produces plugs into an org's existing compliance and incident-response tooling.

## Code quality & packaging

```bash
uv sync                              # install (zero runtime dependencies)
uv run pytest -v                     # 178 passed
uv run pytest --cov=agentgov         # 98% coverage
uv run ruff check . && uv run ruff format --check .
uv run mypy src/                     # strict, zero errors
uv run python examples/denial_of_wallet_benchmark.py
uv run python examples/persistence_demo.py
```

Packaged with [uv](https://docs.astral.sh/uv/); metadata, license, and classifiers live
in [`pyproject.toml`](pyproject.toml). Licensed under [Apache 2.0](LICENSE).
