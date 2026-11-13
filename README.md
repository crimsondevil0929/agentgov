<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
    <img src="docs/logo.svg" width="72" height="72" alt="">
  </picture>
</p>

<h1 align="center">AgentGov</h1>

<p align="center">Spend and rate limits for a whole tree of agents, held before a call and settled after.<br>
Part of the stack with <a href="https://github.com/crimsondevil0929/interlock">Interlock</a> and <a href="https://github.com/crimsondevil0929/fiduciary">Fiduciary</a>.</p>

**The runtime spend governor and denial-of-wallet circuit breaker for autonomous agent fleets.**

> **Start here:** [the live console](https://crimsondevil0929.github.io/fiduciary/) ·
> [how AgentGov, Interlock and Fiduciary fit together](#start-here) ·
> [put it in front of your agent in 30 minutes](https://github.com/crimsondevil0929/fiduciary/blob/main/docs/QUICKSTART.md)

[![CI](https://github.com/crimsondevil0929/agentgov/actions/workflows/ci.yml/badge.svg)](https://github.com/crimsondevil0929/agentgov/actions/workflows/ci.yml)
[![coverage floor](https://img.shields.io/badge/coverage%20floor-95%25%2C%20CI--enforced-brightgreen)](.github/workflows/ci.yml)
[![dependencies](https://img.shields.io/badge/core%20dependencies-zero-blue)](pyproject.toml)
[![mypy](https://img.shields.io/badge/mypy-strict-blue)](pyproject.toml)
[![license](https://img.shields.io/badge/license-Apache%202.0-lightgrey)](LICENSE)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

When an agent spawns sub-agents that spawn tools, nothing in the stack enforces a dollar
ceiling on the *tree*. A per-account rate limit watches one caller. It does not see a
fan-out of 50 sub-agents, each making a handful of reasonable calls that together spend a
budget in seconds. AgentGov sits below the payment layer and provides that control. It
keeps a hierarchical, capability-scoped spend envelope over an append-only, hash-chained
ledger, with a circuit breaker that halts a runaway branch before settlement rather than
after. A second, *cognitive* breaker targets the most common cause of runaway spend. It
detects an agent looping without making progress and halts it for a fraction of a cent,
long before the envelope runs out.
The ledger, topology, and any in-flight authorization survive a process crash, backed by
SQLite via the standard library, or by PostgreSQL for a fleet of governors on many hosts.

Zero runtime dependencies. Pure standard library (`decimal`, `hashlib`, `threading`,
`sqlite3`, `asyncio`-compatible). `mypy --strict` clean.

---

## Start here

**See the whole stack working:** <https://crimsondevil0929.github.io/fiduciary/>. Eight
agent workflows on six kinds of system run on one engine, a real model's recorded turns are
replayed on the current release, and 20 audit bundles can be verified in your browser.

A gateway decides whether an agent may call a tool. This stack decides whether what the call
changed may be kept, and produces evidence for someone who trusts neither the agent nor the
operator. It is three packages:

| Package | On PyPI | What it answers |
|---|---|---|
| [Fiduciary](https://github.com/crimsondevil0929/fiduciary) | [`interlock-fiduciary`](https://pypi.org/project/interlock-fiduciary/) | Who may do what, and who approved each exception. Signed mandates, 2-of-3 quorum warrants, the approvals console, governed MCP tools, and audit bundles anyone can verify offline. **Start here** to put the stack in front of an agent: it installs the other two. |
| [Interlock](https://github.com/crimsondevil0929/interlock) | [`interlock-escrow`](https://pypi.org/project/interlock-escrow/) | Does what this write actually changed satisfy policy? It stages the write, measures it, commits it once or puts it back, and delivers outbound calls exactly once. Each change is measured in one of four ways: **T** inside a transaction, **P** as the system's own plan, **V** predicted then read back, **R** the request only. |
| **AgentGov** (this repository) | [`interlock-agentgov`](https://pypi.org/project/interlock-agentgov/) | May this scope spend this amount? Spend and rate ledgers across a delegation tree, circuit breakers, ARC1 receipts, and reconciliation of a system's own log against them. |

New here? [Put it in front of your agent in 30 minutes](https://github.com/crimsondevil0929/fiduciary/blob/main/docs/QUICKSTART.md),
and read [what it does and does not protect against](https://github.com/crimsondevil0929/fiduciary/blob/main/docs/THREAT_MODEL.md).

## The benchmark

[`examples/denial_of_wallet_benchmark.py`](examples/denial_of_wallet_benchmark.py) runs
the *identical* runaway-agent workload three times and diffs the outcome: with no
backstop, with a $5.00 spend envelope, and with the envelope plus cognitive loop
detection. Same orchestrator logic, same simulated model, same 3 seconds of wall clock.

The model here is a deterministic offline stub, which is what makes a million-call
comparison reproducible. For the same machinery measured against the real Anthropic API,
see [Live API metering](docs/GUIDE.md#live-api-metering) in the guide.

```
+=======================+==========================+==========================================+======================================================+
| METRIC                | Scenario A - Ungoverned  |    Scenario B - AgentGov (Financial)     |    Scenario C - AgentGov (Cognitive + Financial)     |
+=======================+==========================+==========================================+======================================================+
| Wall clock            |                    3.00s |                                    3.00s |                                                3.00s |
| Sub-agents spawned    |                       63 |                                   13,661 |                                                    1 |
| Calls attempted       |                  627,228 |                                   14,295 |                                              140,075 |
| Calls executed        |                  627,228 |                                      635 |                                                    3 |
| Calls refused         |                        0 |                                   13,660 |                                              140,072 |
| Tokens consumed       |              204,685,404 |                                  207,251 |                                                  770 |
+-----------------------+--------------------------+------------------------------------------+------------------------------------------------------+
| Intended budget       |                $5.000000 |                                $5.000000 |                                            $5.000000 |
| Actual cost realized  |            $4,922.694420 |                                $4.984635 |                                            $0.018330 |
| Cost vs budget        |                98,453.9% |                                    99.7% |                                                 0.4% |
| Budget breached after |                   0.003s |                                    never |                                                never |
+-----------------------+--------------------------+------------------------------------------+------------------------------------------------------+
| Cognitive breaker     |        n/a - not enabled |                        n/a - not enabled | TRIPPED [deterministic/near_duplicate] after 4 calls |
| Financial breaker     | n/a - no backstop exists | LATCHED OPEN - 13660/13662 scopes halted |                     LATCHED OPEN - 1/2 scopes halted |
| verify_integrity()    |   n/a - no ledger exists |             PASS - 70208 entries chained |                            PASS - 13 entries chained |
| verify_conservation() |   n/a - no ledger exists |     PASS - no money created or destroyed |                 PASS - no money created or destroyed |
+=======================+==========================+==========================================+======================================================+
```

All three run the same workload: an agent that can't find a report and keeps asking again
with cosmetic edits. The two governed scenarios differ by exactly one constructor argument,
so the third column shows what loop detection adds and nothing else.

**A, ungoverned:** 627K calls in 3 seconds, $4,922.69 against a $5.00 intended budget,
breached in 3 milliseconds and never stopped. **B, financial:** capped at $4.984635 of
the $5.00 envelope, with 13,660 further attempts refused. That's correct, but the money is
gone. The envelope bounds the damage rather than preventing it. **C, cognitive +
financial:** halted after **3 executed calls and $0.018330**, 0.4% of the envelope and
**272x cheaper than waiting for the budget to run out**. The remaining 140,072 attempts
cost nothing, because the check runs before the authorization hold, so a refused call
never reaches the ledger. The halt itself is recorded once, as a zero-value entry in the
chain (the 13th), and nothing is written after it.

Scenario C's cost is bit-for-bit reproducible across runs. It is bounded by the policy,
which does not care how many iterations the clock allowed. A and B are not, and the table
above is one recorded run rather than a fixed expectation: A's total is however many calls
fit in three seconds, and B settles somewhere just under the envelope depending on where
the last holds land. For A and B the *bound* is the guarantee, not the figure.

Reproduce it: `uv run python examples/denial_of_wallet_benchmark.py`. Add `--audit` to
stream every hash-chained ledger line live instead of a tail sample.

Every number above is checked by code. `verify_integrity()` recomputes the SHA-256 chain,
the pairing of every hold with its release, and the delegation tree and breaker state, all
from the chain itself. `verify_conservation()` checks the identity

```
Σ(scope balances) + outstanding_holds + settled_spend − reversals == funded
```

across every scope in the tree. Money is never created, destroyed, or double-counted.
it only ever moves between a parent and a child, or out to a vendor.

---

## Why naive rate limiters fail here, and what replaces each failure

| Naive approach | Where it fails | AgentGov's answer |
|---|---|---|
| Decrement-then-check a counter | Two concurrent sub-agents can both read "funds available" before either writes. A classic TOCTOU race that lets both spend the same dollar | **Authorize → Hold → Settle.** A call reserves its worst-case cost *before* it runs; the hold is encumbered and invisible to concurrent siblings until it settles. Two agents racing for the last cent cannot both win, proven under 64 threads and 100 asyncio tasks contending for one envelope simultaneously. |
| Retry until it works | An agent (or a human debugging one) that ignores a rejection and keeps calling will eventually get through once a competing hold releases | **A latching circuit breaker.** Once a scope overdraws, its breaker trips and *stays* tripped. Every subsequent call fails fast with `CircuitOpenError`, independent of balance, until an operator explicitly calls `reset()`. Retry storms cannot wear it down. |
| A dashboard counter or log line | If someone edits the number after the fact, there is no way to tell | **A cryptographic double-entry ledger.** Every economic event is an immutable entry chained to its predecessor by SHA-256 (`prev_hash → entry_hash`); `verify_chain()` re-derives every hash and catches any retroactive edit, including a tampered balance. |
| A dedupe cache on tool calls | Catches byte-identical repeats and nothing else. An agent nudging one word per attempt defeats it on every call while making no progress at all | **A cognitive breaker.** Character-shingle similarity, call-graph cycle detection, and an off-thread novelty tracker catch the *soft* loop, cosmetically different calls that go nowhere, and halt it for cents rather than dollars. |
| A single flat quota per API key | Says nothing about *which* sub-agent in a fan-out is responsible, and can't bound a tree that recurses | **A budget DAG.** A root agent's envelope is sub-delegated down a tree of scopes; no descendant can ever spend or re-delegate more than its ancestors granted it, at any depth. |

## Quickstart

Wrap an existing model call and give a sub-agent tree its own budget in a handful
of lines:

<!-- readme-test: skip reason="calls a live model provider; the runnable version is directly below" -->
```python
from agentgov import BudgetManager, Interceptor, money

gov = BudgetManager()
gov.open_root("orchestrator", money("5.00"))  # the whole fleet's envelope
gov.delegate("orchestrator", "researcher", money("1.00"))  # a sub-agent's slice

metered = Interceptor(gov, "researcher", model="claude-opus-5")
result = metered.invoke(client.messages.create, model="claude-opus-5", messages=[...])

print(result.cost, gov.available("researcher"))  # exact settled cost, remaining budget
```

Run it now, with no API key, by metering anything that reports token usage:

```python
from agentgov import BudgetManager, Interceptor, money

gov = BudgetManager()
gov.open_root("orchestrator", money("5.00"))
gov.delegate("orchestrator", "researcher", money("1.00"))

metered = Interceptor(gov, "researcher", model="claude-opus-5")
result = metered.invoke(lambda **_: {"input_tokens": 1200, "output_tokens": 350})

print(result.cost, gov.available("researcher"))
# 0.01475000 0.98525000
```

The accounting is the same on either path: `invoke()` authorizes a worst-case
hold, runs your call with no lock held, prices the token usage it reports, and
settles atomically. Let it run past budget and
you get `DenialOfWalletError`, not a silent overspend:

<!-- readme-test: skip reason="calls a live model provider" -->
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

## Documentation

- [docs/GUIDE.md](docs/GUIDE.md): the full guide. It covers live API metering, the cognitive
  breaker, framework adapters, reconciliation, ARC1 receipts, durability and PostgreSQL, the
  core primitives, the [known limitations](docs/GUIDE.md#known-limitations) and the roadmap.
- [docs/API.md](docs/API.md), [docs/RECEIPTS.md](docs/RECEIPTS.md),
  [docs/LEDGER_FORMAT.md](docs/LEDGER_FORMAT.md), [docs/OPERATIONS.md](docs/OPERATIONS.md):
  the reference.
- [CHANGELOG.md](CHANGELOG.md), [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md).
