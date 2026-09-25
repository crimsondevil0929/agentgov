# AgentGov

**The runtime spend governor and denial-of-wallet circuit breaker for autonomous agent fleets.**

[![CI](https://github.com/crimsondevil0929/agentgov/actions/workflows/ci.yml/badge.svg)](https://github.com/crimsondevil0929/agentgov/actions/workflows/ci.yml)
[![coverage floor](https://img.shields.io/badge/coverage%20floor-95%25%2C%20CI--enforced-brightgreen)](.github/workflows/ci.yml)
[![dependencies](https://img.shields.io/badge/core%20dependencies-zero-blue)](pyproject.toml)
[![mypy](https://img.shields.io/badge/mypy-strict-blue)](pyproject.toml)
[![license](https://img.shields.io/badge/license-Apache%202.0-lightgrey)](LICENSE)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)

When an agent spawns sub-agents that spawn tools, nothing in the stack enforces a dollar
ceiling on the *tree*. A per-account rate limit watches one caller. It does not see a
fan-out of 50 sub-agents each making a handful of individually reasonable calls that,
together, burn a budget in seconds. AgentGov sits below the payment layer as that missing control
plane: a hierarchical, capability-scoped spend envelope over an immutable, hash-chained
ledger, with a circuit breaker that halts a runaway branch before settlement, not after.
A second, *cognitive* breaker attacks the root cause: it detects the agent looping without
making progress and halts it for a fraction of a cent, long before the envelope is touched.
The ledger, topology, and any in-flight authorization survive a process crash, backed by
SQLite via the standard library.

Zero runtime dependencies. Pure standard library (`decimal`, `hashlib`, `threading`,
`sqlite3`, `asyncio`-compatible). `mypy --strict` clean.

---

## The benchmark

[`examples/denial_of_wallet_benchmark.py`](examples/denial_of_wallet_benchmark.py) runs
the *identical* runaway-agent workload three times and diffs the outcome: with no
backstop, with a $5.00 spend envelope, and with the envelope plus cognitive loop
detection. Same orchestrator logic, same simulated model, same 3 seconds of wall clock.

The model here is a deterministic offline stub, which is what makes a million-call
comparison reproducible. For the same machinery measured against the real Anthropic API,
see [Live API metering](#live-api-metering) below.

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

All three run the *identical* workload: an agent that cannot find a report and keeps
re-asking with cosmetic edits. The governed scenarios differ by exactly one constructor
argument, so the third column isolates what loop detection buys and nothing else.

**A, ungoverned:** 627K calls in 3 seconds, $4,922.69 against a $5.00 intended budget,
breached in 3 milliseconds and never stopped. **B, financial:** capped at $4.984635 of
the $5.00 envelope, 13,660 further attempts refused. Correct, but the money is gone. The
envelope bounds the damage rather than preventing it. **C, cognitive + financial:**
halted after **3 executed calls and $0.018330**, 0.4% of the envelope and **272x cheaper
than waiting for the budget to run out**. The remaining 140,072 attempts cost nothing at
all: the check runs ahead of the authorization hold, so a refused call never reaches the
ledger. The halt itself is recorded once, as a zero-value entry in the chain (the 13th);
nothing after it is written.

Scenario C's cost is bit-for-bit reproducible across runs. It is bounded by the policy,
which does not care how many iterations the clock allowed. A and B are not, and the table
above is one recorded run rather than a fixed expectation: A's total is however many calls
fit in three seconds, and B settles somewhere just under the envelope depending on where
the last holds land. For A and B the *bound* is the guarantee, not the figure.

Reproduce it: `uv run python examples/denial_of_wallet_benchmark.py`. Add `--audit` to
stream every hash-chained ledger line live instead of a tail sample.

Every number above is checked, not narrated. `verify_integrity()` re-derives the
SHA-256 chain, the pairing of every hold with its release, and the delegation tree and
breaker state, all from the chain itself; `verify_conservation()` checks the identity

```
Σ(scope balances) + outstanding_holds + settled_spend − reversals == funded
```

across every scope in the tree. Money is never created, destroyed, or double-counted.
it only ever moves between a parent and a child, or out to a vendor.

---

## Live API metering

The benchmark above runs against a deterministic stub, which is the right harness for
proving accounting invariants and the wrong one for proving anything about a real
provider. [`scripts/generate_real_usage.py`](scripts/generate_real_usage.py) closes that
gap: four governed workloads across four Anthropic model tiers, through the official
`anthropic` SDK, with every raw response payload written to disk as evidence.

```
+-----------+---------------------------+-------+--------+---------+-------------+-----------+
| TIER      | MODEL SERVED              | CALLS | IN TOK | OUT TOK | COST        | HALTED BY |
+-----------+---------------------------+-------+--------+---------+-------------+-----------+
| runaway   | claude-haiku-4-5-20251001 | 3     | 54     | 384     | $0.00197400 | cognitive |
| workhorse | claude-sonnet-5           | 3     | 112    | 426     | $0.00448400 | -         |
| analyst   | claude-opus-5             | 1     | 124    | 900     | $0.02312000 | -         |
| heavy     | claude-fable-5-1          | 1     | 155    | 407     | $0.02190000 | -         |
+-----------+---------------------------+-------+--------+---------+-------------+-----------+
| TOTAL     |                           | 8     | 445    | 2,117   | $0.05147800 |           |
+-----------+---------------------------+-------+--------+---------+-------------+-----------+

  ledger settled total      $0.05147800
  independent re-price      $0.05147800
  drift                     $0E-8  (MATCH)
  verify_integrity()        PASS - 33 entries chained
```

Recorded with v0.1.1. From v0.1.2 the runaway tier's halt is itself a zero-value entry
in the chain, so the same run chains one entry more.

**Pricing is exact, not approximately right.** Every settled call is re-priced a second
time straight from the published rates and compared against what the ledger captured.
Across 445 input and 2,117 output tokens on four different price tiers the drift is
**$0.00000000**. The metering path reads a real `usage` object and turns it into the
same number twice, independently. `anthropic` 1.6.0; `claude-fable-5-1` served natively.

**The cognitive breaker fires on live traffic.** Tier 1 drives a thrashing loop: four
cosmetically-edited restatements of one request. It halted after **3 executed calls and
$0.001974**, then refused 5 retry attempts with no balance movement at all. Tier 2, a
genuinely progressing three-step workflow, ran to completion untouched: the detector
discriminates, rather than simply halting whatever runs longest.

**This run found two real bugs.** Against the live API the
breaker initially did *not* fire, despite the loop being obvious. Two defects, both
invisible to a stub-backed test suite:

1. **The result comparison was measuring the SDK envelope, not the answer.** Rendering an
   `anthropic.types.Message` through `repr` meant most of the compared characters were
   `Message(id=…`, `TextBlock(citations=None, type='text'…`, `usage=Usage(…)`:
   boilerplate every response from that SDK shares. Two *completely unrelated* answers
   scored 0.42 while two genuinely progressing ones scored 0.48: no usable signal.
   `extract_result_text()` now pulls the prose out first, which roughly doubled the
   separation between thrashing and progress (1.20x → 1.81x).
2. **`result_similarity_threshold` was calibrated on templated stub output.** Real prose
   that means the same thing shares far fewer character trigrams than two renderings of
   one template. The inherited `0.70` detected **0 of 4** thrashing trajectories against
   live traffic.

[`scripts/calibrate_result_threshold.py`](scripts/calibrate_result_threshold.py) is the
reproducible re-calibration: 36 measured pairs across thrashing, pagination, and
genuinely progressing traffic. Its finding is more interesting than a new constant.
**the per-pair distributions genuinely overlap** (thrashing 0.32–0.66, pagination
0.13–0.88), so no single-pair threshold separates them. What separates them is the
*streak* requirement: pagination's similarity is erratic, thrashing's stays persistently
elevated. Sweeping the real rule, `0.25`–`0.30` catches 4/4 thrashing trajectories with
zero false positives on either control family; `0.20` begins false-positiving on
pagination. The shipped default is now **`0.30`**, the conservative end of that band.

Reproduce it. This spends real money, so rehearse first:

```bash
export BENCHMARK_API_KEY=sk-ant-...        # never falls back to ANTHROPIC_API_KEY
uv run python scripts/generate_real_usage.py --dry-run   # free rehearsal, no network
uv run python scripts/generate_real_usage.py             # ~$0.05
uv run python scripts/calibrate_result_threshold.py      # ~$0.03
```

The full write-up is [`ARCHITECTURE.md`, Part A](ARCHITECTURE.md#part-a-the-simulation-gap):
envelope dominance, prose entropy, and why the per-pair distributions cannot be separated
by any constant.

Every call carries an explicit `max_tokens`, the whole run executes inside a $1.50
AgentGov envelope, and the runaway loop is bounded by a hardcoded counter
that breaks at four iterations, so a regression in the breaker still cannot run away.
Raw payloads, the cost summary, the ledger, and the metering journal are written to
timestamped files under `benchmarks/live_data/` (gitignored: they are evidence, not
repository content).

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

## The cognitive circuit breaker

The financial breaker is reactive by construction: it fires when the money is gone. The
cognitive breaker attacks the cause: the open-loop execution cycle that spends it.
Attach one and every call is checked for thrashing *before* its hold is placed:

<!-- readme-test: skip reason="calls a live model provider" -->
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

*Tier 1 runs inline and is deterministic.* Three stateless detectors over a bounded
ring buffer: `ExactRepeatDetector` (identical fingerprints), `NearDuplicateDetector`
(character-shingle Jaccard between consecutive calls, the soft loop), and
`CallCycleDetector` (an A→B→A→B oscillation that no pairwise check can see). Measured
overhead is **77µs mean / 122µs p99** even with pathological 8KB arguments, roughly
0.005% of a real model call. Arguments are truncated before shingling and comparisons
are window-capped, so the cost is bounded rather than merely small.

*Tier 2 runs off-thread and is semantic.* A daemon worker drains a bounded queue and
runs a `SemanticObserver`. The shipped `TrajectoryEntropyObserver` tracks novelty decay:
what fraction of each call is vocabulary the trajectory has never produced. An agent
cycling six phrasings of one idea has low pairwise similarity but near-zero novelty.
**The agent thread never waits for it.** A verdict is latched and enforced on the *next*
call, so detection is one call late rather than blocking, and a saturated queue sheds
samples instead of applying backpressure. This is the seam where an LLM-judge observer
plugs in: implement `evaluate()` and change nothing else.

A cognitive trip calls `BudgetManager.trip()`, so it inherits latching, subtree
propagation, hash-anchored control events, and durable persistence from the machinery
that already exists: one halt mechanism, two families of sensor. The verdict is computed
under the cognitive lock and the financial lock is taken only after releasing it, so the
two are never held at once and no lock-ordering hazard exists.

**Extending it.** `LoopDetector` and `SemanticObserver` are Protocols; a detector that
knows your tool schema will beat any generic text heuristic. Pass `detectors=[...]` to
extend or replace the built-ins. A detector that raises is logged and skipped, so one bad
custom heuristic degrades detection rather than breaking production traffic.

**What it keeps.** Nothing readable, by default. Each observed call is reduced to a
*salted* BLAKE2b digest (the salt is per-instance, so a digest is not a lookup key for a
known prompt) plus a bounded set of character trigrams. Readable text is retained only
under an explicit `CognitivePolicy(retain_arguments=True)`, and is truncated even then.
For regulated data, install a `Redactor`. It runs at the single ingress every argument
and result passes through, before anything is fingerprinted or stored, and a redactor
that raises causes the text to be dropped entirely rather than retained unredacted.
[`SECURITY.md`](SECURITY.md) is the full data map: what lands in SQLite, in memory, and
in logs, and what encryption at rest AgentGov does *not* provide.

**Where it does not reach.** Legitimate iteration (pagination,
map-over-a-list) looks like a soft loop on *input* similarity alone. The discriminator is
the result: near-identical inputs producing near-identical outputs is thrashing;
near-identical inputs producing different outputs is progress. The `Interceptor` feeds
results back automatically, which handles the common case. It still cannot see through a
*templated* result whose only variation is an index (`record-1-0`, `record-2-0`). Those
are near-identical in trigram space even though the agent is advancing. That limitation
is [pinned by a test](tests/test_cognitive_breaker.py), along with its remedy:
`CognitivePolicy(exempt_tools={"fetch"})`, a raised threshold, or a custom detector.

## Dropping it in

`invoke()` is the primitive, and it stays the contract. But adopting it in an
existing codebase means editing every call site, so there is a wrapper that
governs the calls already written:

<!-- readme-test: skip reason="calls a live model provider" -->
```python
import anthropic

from agentgov import govern

client = govern(anthropic.Anthropic(), gov, "researcher", model="claude-opus-5")

response = client.messages.create(model="claude-opus-5", messages=[...])  # unchanged
print(client.agentgov.last_call.cost)
```

The proxy returns exactly what the SDK returns, because anything else would not
be a drop-in, and forwards everything that is not a model call untouched. It is
sugar over `client.agentgov.interceptor`, which hands the primitive back.

**Streaming**, the shape most real agents use, is governed as a context manager:

<!-- readme-test: skip reason="calls a live model provider" -->
```python
with client.messages.stream(model="claude-opus-5", messages=[...]) as events:
    for event in events:
        render(event)
print(events.cost)
```

The hold is resolved on *every* path out of that block: clean exhaustion,
`break`, an exception, or a timeout. An abandoned stream never strands
funds. On abandonment it settles at whatever usage was actually observed
rather than voiding: those tokens were generated and billed, and a spend
governor that forgot them would under-report. Only a stream that produced no
usage at all is voided. `astream()` is the async equivalent.

**Holds are sized from the payload.** A static worst-case hold is wrong in
both directions, and the dangerous direction is *too small*: an
under-reserved hold does not encumber, so concurrent callers all pass the
pre-flight check and settle for more than they reserved. Measured on a
150K-character prompt with ten concurrent callers, static holds **breached a
$1.00 envelope by 2.3x**; payload-derived holds bounded it. Input tokens are
estimated from character length, the output bound is taken from the call's
own `max_tokens`, and a configurable `safety_buffer` (1.5x by default)
absorbs the heuristic's error. Unrecognised payloads fall back to the static
ceiling rather than under-reserving.

### When the cost is only known part-way through

`invoke()` covers a call that returns once. When the cost emerges as you
consume something — a stream you must settle whatever it produced before
re-raising, or a vendor call that reports usage out of band — `SpendGuard` is
the same authorize/settle pair as a context manager:

```python
from decimal import Decimal

from agentgov import BudgetManager, SpendGuard, money

gov = BudgetManager()
gov.open_root("researcher", money("5.00"))

with SpendGuard(gov, "researcher", money("0.25"), memo="batch") as guard:
    consumed = sum(len(chunk) for chunk in ["alpha", "beta", "gamma"])
    guard.settle(Decimal(consumed) / 1000)

print(guard.cost, gov.available("researcher"))
# 0.013 4.987
```

The hold is placed on entry and resolved on every path out, including an
exception: an abandoned block never strands funds. Settling twice raises
rather than double-booking.

### Verifying a ledger

Three checks, all on the manager:

```python
from agentgov import BudgetManager, money

gov = BudgetManager()
gov.open_root("orchestrator", money("5.00"))
gov.delegate("orchestrator", "researcher", money("1.00"))

gov.verify_chain()  # every SHA-256 link, running balance and hold release
gov.verify_conservation()  # no money created, destroyed or double-counted
gov.verify_integrity()  # both, plus the tree and breaker state the chain implies
print("ok")
```

Each hold release names the hold it releases (its `ref`, inside the hash), so
`verify_chain()` proves no hold was released twice, into the wrong scope, or for the
wrong amount. Breaker trips, resets and every delegation are entries in the chain too,
so `verify_integrity()` re-derives the tree and the breakers from the chain instead of
trusting the tables that cache them.

`verify_conservation()` checks

```
Σ(scope balances) + outstanding_holds + settled_spend − reversals == funded
```

across every scope in the tree.

## Framework adapters

Two lines on an agent you have already written. Neither adapter imports its
framework. Every object is duck-typed, so they load without LangChain or
CrewAI installed and keep working when those libraries reshuffle internals.

<!-- readme-test: skip reason="needs langchain installed; agentgov does not depend on it" -->
```python
from agentgov.adapters.langchain import GovernedChatModel

model = GovernedChatModel(ChatAnthropic(model="claude-opus-5"), gov, "researcher")
answer = model.invoke(messages)  # unchanged call site, now metered
```

For **LangGraph**, or any chain deep enough that you never touch the model
object, use the callback handler instead. Callbacks propagate down the whole
run tree, so one handler governs every model call in a graph, keyed by
`run_id` so concurrent branches settle independently:

<!-- readme-test: skip reason="needs langgraph installed; agentgov does not depend on it" -->
```python
from agentgov.adapters.langchain import GovernedCallbackHandler

graph.invoke(state, config={"callbacks": [GovernedCallbackHandler(gov, "researcher")]})
```

**CrewAI** settles per run, because CrewAI reports usage per run:

<!-- readme-test: skip reason="needs crewai installed; agentgov does not depend on it" -->
```python
from agentgov.adapters.crewai import GovernedCrew

crew = GovernedCrew(Crew(agents=[...], tasks=[...]), gov, "research-crew")
result = crew.kickoff()
```

Two details these get right that are easy to get wrong. LangChain **swallows
exceptions raised inside callbacks** unless the handler sets
`raise_error = True`. Without it a denial-of-wallet halt would be logged and
the graph would keep spending. And CrewAI's `usage_metrics` are **cumulative
across kickoffs**, so settling the reported total each run would bill run one
again on run two; `GovernedCrew` charges only the delta.

For a framework with no adapter, `govern_agent` wraps any function that runs a
unit of agent work, given a callable that reads usage off its return value.

## Reconciling the invoice

The question a finance or security team actually asks is not "what did we
budget?" but *"the provider billed us $40,000. Which agent caused it, and is
there anything on there we never authorized?"*

```bash
$ agentgov reconcile governor.db provider_invoice.json --journal tokens.jsonl

  CATEGORY                             COUNT             SPEND
  ------------------------------------------------------------
  Matched (billed and metered)             6         $0.034423
  Discrepant (cost mismatch)               0         $0.000000
  Phantom (billed, NOT metered)            1         $2.470000
  Unsettled (metered, not billed)          0         $0.000000

  PHANTOM CALLS - billed with no local authorization
    2026-09-14 06:42:29  claude-opus-5   $2.470000  req_LEAKED_KEY_7f3a

  AUDIT FAILED  1 phantom call(s) worth $2.470000
```

A **phantom** is the finding that matters: spend the provider billed that
AgentGov never authorized: a leaked key, or a service calling the model
outside the governor. Any phantom line exits `1`, so this belongs in a
pipeline.

Matching is fuzzy on purpose. Timestamps drift by network latency and token
counts drift because pre-flight sizing is a `chars/4` heuristic; exact matching
would report a healthy ledger as entirely broken. Both windows are configurable
(`--time-tolerance`, `--token-tolerance`, `--cost-tolerance`).

Token counts come from a `MeteringJournal`, an additive sidecar. The ledger
records money and structure and deliberately not token metadata. Without a
journal reconciliation still runs on cost and time, and says so.

## Reading a ledger

```
$ agentgov inspect governor.db
BALANCE TREE
  orchestrator  available $3.00000000  of $5.00000000
  `- researcher  available $1.48349000  of $2.00000000
     `- scraper  available $0.49248500  of $0.50000000   [HALTED by scraper]

$ agentgov verify governor.db
  ok    hash chain, balances + hold pairing
  ok    conservation identity
  ok    topology + breakers, derived from the chain

PASS  governor.db  (14 entries verified; head 56d879d72557ec6e)
```

`verify` exits `0` on PASS and `1` on FAIL, so it drops straight into a
pipeline to assert an archived ledger is intact. Both commands open the
database **read-only**, so they are safe to run against a governor that is
live and holding the write claim. `agentgov repair governor.db` is the one
command that writes: see [Durability](#durability).

## Action receipts (ARC1)

*Unreleased, on the v0.2 line: `agentgov.receipts` and `agentgov verify-receipt`.*

A ledger proves what an agent **spent**. A receipt proves what it **did**.
Every governed action against a system of record can leave an ARC1 receipt,
including refused ones. A receipt is a signed record of:
- who authorized the action;
- what the agent said it would do;
- what the action measurably did, and what the measurement could not see;
- what was decided, and by which checks;
- what it cost;
- how it ended.

Receipts go into an append-only [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)
Merkle log, and a witness cosigns the log's checkpoints. A receipt therefore
cannot be edited, moved, dropped from history, or shown differently to
different people without it showing. Row data stays out of the receipt. A
salted Merkle root commits to every changed row, and the issuer can later
disclose any subset to an auditor, with proofs, while the rest stay hidden.

```console
$ cd vectors/arc1
$ agentgov verify-receipt valid/committed-refund.bundle.json --pubkey keys/issuer.pub \
      --witness witness/cosignatures.jsonl --witness-pubkey keys/witness.pub \
      --rows valid/committed-refund.rows.json
  ok    ARC1 schema        receipt f87ad35e-c540-5f93-8c5a-62d3006db353 (committed, ...)
  ok    receipt signature  ed25519, key bcc542d53c8c1a1f
  ok    log inclusion      leaf 0 of 7 in log 'arc1-vectors' (root 5b025750f43bc1be)
  ok    witnessed          by 'arc1-vectors-witness' (key ac51d42df2b0ebbd) at 2026-09-25T15:05:00.000000Z
  --    agentgov ledger    no ledger given
  ok    disclosed rows     2 of 3 committed rows verify under row_root 9ab84da7294fe5de

PASS  valid/committed-refund.bundle.json  (receipt f87ad35e-c540-5f93-8c5a-62d3006db353)
```

`--ledger governor.db` also checks the receipt's cost against the AgentGov
ledger that paid for the action. The ledger must have settled exactly that
amount, in transactions recorded before the receipt was anchored. The exit
code says what failed, so a pipeline can gate on it:

| Exit | Meaning |
|---|---|
| `0` | every check you gave evidence for passed |
| `2` | usage error, or a file that cannot be read |
| `3` | not a well-formed ARC1 document |
| `4` | the receipt's signature does not verify |
| `5` | the log checkpoint's signature, or the audit path to it, fails |
| `6` | the checkpoint was never witnessed, or the witness saw a different history (a split view) |
| `7` | the receipt disagrees with the AgentGov ledger |
| `8` | a disclosed row is not one the receipt committed to |

The same checks are available in code:

<!-- readme-test: skip reason="reads vectors/arc1 from a checkout of this repository" -->
```python
from pathlib import Path

from agentgov.receipts import load_cosignatures, parse_key, verify_bundle

vectors = Path("vectors/arc1")
report = verify_bundle(
    (vectors / "valid" / "committed-refund.bundle.json").read_bytes(),
    issuer_key=parse_key((vectors / "keys" / "issuer.pub").read_text()),
    cosignatures=load_cosignatures(vectors / "witness" / "cosignatures.jsonl"),
    witness_key=parse_key((vectors / "keys" / "witness.pub").read_text()),
)
print(report.exit_code, [check.status for check in report.checks])
# 0 ['pass', 'pass', 'pass', 'pass', 'skip', 'skip']
```

Verifying needs only the standard library, including a built-in RFC 8032
Ed25519 verifier. Issuing receipts with Ed25519 keys needs
`pip install 'agentgov[sign]'`; HMAC-SHA256 keys, for internal use, need
nothing. `receipts.ReceiptLog.issue()` places, signs and logs a receipt in one
step, and `receipts.verify_bundle()` is the verifier behind the command.

[`docs/RECEIPTS.md`](docs/RECEIPTS.md) is the specification. It covers the
canonical encoding, the signed bytes, the log, witnesses, row commitments,
the verification order, and what a receipt does *not* prove.
[`vectors/arc1/`](vectors/arc1/) holds deterministic reference vectors,
regenerated and byte-compared on every CI run. Its `manifest.json` lists each
case with the exit code a conforming verifier must produce.

## Durability

An in-memory ledger is not an audit trail: restart the process and it is gone. Swap `BudgetManager()` for
`BudgetManager.open_sqlite(path)` and every operation goes to disk first, before it ever
touches memory, as **one SQLite transaction**: a capture's release and spend, the hold it
closes, the breaker trip it causes, all or none of it:

```python
from agentgov import BudgetManager, money

with BudgetManager.open_sqlite("governor.db") as gov:
    gov.open_root("orchestrator", money("5.00"))
    ...  # identical API; every write is durable before it's visible in memory
```

Reopen that file in a brand new process and the ledger, the delegation tree, every
circuit-breaker trip, and any authorization left mid-call are restored exactly.
[`examples/persistence_demo.py`](examples/persistence_demo.py) proves this with two
genuinely separate `python` subprocesses, not just a discarded object:

```bash
uv run python examples/persistence_demo.py
```

```
--- process 1: writes state, then exits completely ---
WRITER  balance(researcher)=0.65000000
WRITER  halted(scraper)=True
WRITER  chain_length=16
WRITER  open_authorization_id=24b1af62-e7ac-4b54-b2fb-2475f6c40006

--- process 2: independent interpreter, same file ---
READER  verify_integrity() = PASS
READER  balance(researcher)=0.65000000
READER  halted(scraper)=True
READER  chain_length=16
READER  open_authorizations=1
READER  scraper still refuses calls: Scope 'scraper' is halted by its own breaker: ...
```

A database that has been tampered with, or merely corrupted by a crash mid-write, is
refused at open time, not served with a wrong balance: `open_sqlite()` re-runs
`verify_chain()` and `verify_integrity()` before handing back a governor at all. This
uses only `sqlite3` from the standard library, so durability adds zero runtime
dependencies.

**The chain is the record; the other tables are caches of it.** The delegation tree,
the breaker events and the open authorizations are also kept in their own tables for
fast reads, and at open they must agree exactly with what the chain implies. One that
does not, such as the half-finished capture a v0.1.1 crash could leave behind, is
refused with a message saying which rows disagree. `agentgov repair governor.db` (or
`open_sqlite(path, repair=True)`) rebuilds those tables from the chain. No money moves,
and `BudgetManager.repairs` lists what was rebuilt.

**Upgrading from v0.1.0 or v0.1.1.** A database written by either is upgraded in place
the first time v0.1.2 opens it for writing: its schema gains the columns v0.1.2 needs,
and a migration seal, a zero-value entry carrying a digest of the old breaker events,
commits those events into the chain. Opened read-only, it is served as it is. Entries
keep the audit version they were written with (`AGOV1` or `AGOV2`), and each verifies
under its own rules.

**One writer, enforced.** A governor takes an exclusive advisory lock on its database.
A second process, a second gunicorn worker or a second replica, is refused *at open*
with a `ConcurrentGovernorError` naming the PID that holds it, because two writers would
each cache authoritative balances in memory and diverge. The lock is an open file
descriptor, so the kernel releases it even on `SIGKILL`: a crashed governor leaves a
stale file but never a stale lock, and there is no timeout heuristic to get wrong. To
inspect a ledger another process is governing, open it read-only:

<!-- readme-test: continue -->
```python
audit = BudgetManager.open_sqlite("governor.db", read_only=True)
audit.verify_integrity()  # reads and verifies; every write is refused
audit.refresh()  # catch up with the writer, verifying every new entry
```

A read-only view is a snapshot taken at open until it is refreshed. `refresh()` reads
everything committed since in one consistent read, verifies it against the head the view
already trusts, and applies it all or none of it: balances, tree and breaker state move
forward together. If the ledger was rewritten under the view, `refresh()` raises and the
view refuses to follow it any further.

**Dangling holds are findable.** A hold left open by a process that died between
`authorize()` and `capture()` encumbers funds with nothing left to settle it.
`stale_authorizations(older_than)` surveys them without touching anything, and
`void_stale(older_than)` releases them. Deliberately an operator action rather than a
background timer: voiding asserts the call will never settle, and AgentGov cannot know
that. If such a call *does* complete later, its capture raises `DoubleSpendError`. The
ledger refuses to book the same encumbrance twice, and since v0.1.2 that refusal is a
rule of the chain itself: a release that names a hold already released is rejected
before it is written.

See [`tests/test_persistence.py`](tests/test_persistence.py) and
[`tests/test_hardening.py`](tests/test_hardening.py) for the restart, corruption,
lock-contention, and durable-write-failure matrices.

## Core primitives

- **Authorize → Hold → Settle.** `BudgetManager.authorize()` places an encumbering hold
  before a call is made; `capture()` releases it and posts the true cost as one atomic
  ledger transaction. Funds are unavailable to siblings for the *entire* in-flight
  duration of a call, not just at the instant of debit. That is what makes
  double-spend structurally impossible rather than merely unlikely under load.
- **Latching circuit breaker.** A trip on `overdraft`, `runaway-loop velocity`, or
  `budget exhaustion` halts the scope *and every descendant beneath it*, and stays
  halted until an operator calls `reset()`. A `DenialOfWalletError` on overdraw and a
  `RunawayLoopDetectedError` on call-frequency abuse both trip it; every subsequent
  attempt then fails fast with `CircuitOpenError` without touching the ledger at all.
  The trip and the reset are themselves zero-value entries in the chain, so a halt
  cannot be deleted without breaking verification.
- **Cryptographic double-entry ledger.** Every line is a DEBIT or CREDIT against exactly
  one scope; internal transfers post balanced pairs in a single transaction. Entries are
  hash-chained with SHA-256 and never mutated. Corrections are compensating entries,
  never edits, so `verify_chain()` can prove the entire history is exactly what it
  claims to be, and `verify_conservation()` can prove no money was invented along the way.
- **A cognitive breaker on the same actuator.** Deterministic loop detection inline
  (77µs mean) plus a semantic observer off-thread, halting a thrashing agent for cents
  instead of dollars and recording the verdict in the same hash-anchored audit trail as
  every financial event. See [The cognitive circuit breaker](#the-cognitive-circuit-breaker).
- **Write-through durability.** `BudgetManager.open_sqlite()` writes each operation, its
  ledger entries, topology change, breaker trip and open authorization, to disk as one
  transaction *before* committing it to memory, so a store failure or a crash aborts the
  whole operation instead of leaving memory ahead of disk or half of it on disk. A
  corrupted or tampered file refuses to load rather than being trusted. See
  [Durability](#durability) above.
- **Anchors.** `anchor(scope_id, memo)` commits an external record, typically another
  hash chain's head, into this chain as a zero-value entry. It moves no money, and
  editing the memo afterwards breaks verification. This is how
  [interlock](https://github.com/crimsondevil0929/interlock) binds its record of
  database writes to this ledger.

## Known limitations & v0.1 scope

Every claim on this page is measured, and the boundaries of what was measured matter as
much as the numbers. This section states them plainly rather than leaving them to be
discovered in production.

### Single-writer by design: one process, one host

`BudgetManager.open_sqlite()` takes an exclusive advisory lock on the database. **One
process governs one ledger.** A second process is refused at open with
`ConcurrentGovernorError` naming the holding PID; it is not silently allowed to diverge.

Measured throughput on that single writer, all of it behind one global mutex:

| Configuration | Mean per governed call | p99 | Sustained ceiling |
|---|---|---|---|
| In-memory ledger | 0.062 ms | n/a | ~16,000 calls/sec |
| SQLite, `synchronous=FULL` | 0.613 ms | 3.448 ms | ~1,600 calls/sec |

**This is a deliberate trade, not an oversight.** The alternative, shipping a
coordination service, would mean infrastructure to deploy, a network hop in the hot
path, and a dependency tree, all before anyone could evaluate whether the governor is
worth having. `pip install agentgov` with zero runtime dependencies and a local file is
what makes the thing adoptable in an afternoon. The cost of that choice is that
AgentGov v0.1 governs *a process*, not a fleet.

**The roadmap fix is already seamed for.** `agentgov.storage.PersistenceStore` is a
Protocol, and `SqliteStore` is one implementation of it. A **Postgres or Redis
`PersistenceStore`** puts the ledger in a shared transactional store, making the
database the serialization point so N processes across N hosts share one authoritative
view of every balance. Fleet-wide consensus without a bespoke consensus cluster, and
without touching the ledger, the budget DAG, or the breaker. SQLite stays the default so
the zero-dependency install is unaffected.

### A guardrail inside a process, not a sandbox around it

AgentGov enforces at the call site, in your process. Anything that can `import agentgov`
can also call the provider SDK directly and spend unmetered. The hash chain is
**tamper-evident, not tamper-resistant**. `verify_chain()` will prove a file was edited,
but nothing stops a process with write access from editing it. The chain is keyless and
there is no external witness yet, so someone who can compute SHA-256 can rewrite the
whole chain consistently, or cut entries off its tail, and it will still verify. Only a
copy of the head held somewhere else can show that. The [reconciliation engine](#reconciling-the-invoice) is the backstop for
out-of-band spend, and it is *detection after the fact*, not prevention. Treat AgentGov
as a budget guardrail against runaway and accident, the failure mode that actually burns
money today. It is not a security boundary against a hostile agent.

### Published rates are a snapshot

`agentgov.interceptor.PRICING` is a hardcoded table of published list rates, current as
of the date in its docstring. Vendors change prices, and partner platforms (Bedrock,
Vertex) bill differently. Pass an explicit `ModelPricing` for anything not in the table,
and treat reconciliation against the real invoice as a production requirement rather than
a nicety. That is precisely why the reconciliation engine exists.

**Settlement follows the model that served.** The provider can run a different model than
the one requested — a server-side refusal fallback substitutes one mid-request, and an
undated alias resolves to a dated snapshot (`claude-haiku-4-5` → `claude-haiku-4-5-20251001`).
`invoke()` reads `response.model`, folds any dated suffix with `normalize_model_id()`
(exported from the package, so a caller pricing its own calls folds the same way), and
settles at those rates, so the ledger books what will actually be invoiced.
`MeteredCall.model_id` reports what served. Two gaps remain: the **hold** is sized before
the call and can only use the configured model, and **streamed** calls keep the configured
rates because a stream has no single response object to read the served model from.

### What has been proven deterministically, and what has been proven live

These are different claims and this project keeps them separate.

**Proven deterministically.** The accounting invariants are verified against `DummyLLM`,
a deterministic offline stub, under 64 contending threads and 100 concurrent asyncio
tasks: no double-spend under concurrency, conservation of value, an unbroken SHA-256
chain, the latching breaker. This is the right harness for these properties: a governor
that is only *probably* correct under load is not correct, and a nondeterministic backend
cannot prove a race is absent.

**Proven against the live API.** Correct accounting says nothing about whether the
metering layer reads a *real* provider response. That gap is closed by
[`scripts/generate_real_usage.py`](scripts/generate_real_usage.py), which drives four
governed workloads across four Anthropic model tiers through the official `anthropic`
SDK, re-prices every settled call independently from the published rates, and writes every
raw API payload to disk as evidence. See [Live API metering](#live-api-metering) below.

## Roadmap: Phase 2

Phase 1 is a correct, single-process governor: one ledger, one mutex, durable to a local
SQLite file, with financial and cognitive breakers on the same actuator. Beyond that:

- **State recovery after a trip.** A halt protects the budget and leaves the task
  unfinished, and a human then has to notice, diagnose and restart it. The design brief
  covers cryptographic state checkpointing over a Merkle prefix tree, an append-only
  intervention ladder ordered by prompt-cache invalidation cost, and a budgeted stopping
  rule over the breaker's own novelty signal. See
  [`ARCHITECTURE.md`, Part B](ARCHITECTURE.md#part-b-the-what-then-protocol-v02-state-recovery-roadmap).
- **Distributed multi-node consensus.** `agentgov.storage.PersistenceStore` is already the
  seam a replicated backend would implement. Move the ledger off one host's disk onto a
  store shared across a fleet, so multiple machines share one authoritative view of every
  scope's balance without reintroducing the double-spend race this design eliminates
  locally.
- **x402 / AP2 settlement integration.** Use AgentGov's authorize/capture holds as the
  enforcement point those protocols gesture at but don't enforce at runtime, settling
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
uv run pytest -v
uv run pytest --cov=agentgov         # CI fails the build below 95%
uv run ruff check . && uv run ruff format --check .
uv run mypy src/                     # strict, zero errors
uv run python examples/denial_of_wallet_benchmark.py
uv run python examples/persistence_demo.py
```

Every gate above runs in CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) on
Python 3.11 and 3.12, on Linux and macOS, with a 95% coverage floor and a build that
fails on packaging warnings. Both example scripts are executed end to end so a broken
demo cannot merge.

[`docs/DEMO_RUNBOOK.md`](docs/DEMO_RUNBOOK.md) walks the four commands end to
end (adopt, halt a runaway, read the chain, catch unmetered spend); start with
`uv run python examples/live_demo.py`. [`demo.tape`](demo.tape) renders that
same walkthrough as a terminal recording with [VHS](https://github.com/charmbracelet/vhs)
(`vhs demo.tape`), and [`examples/streamlit_dashboard.py`](examples/streamlit_dashboard.py)
gives the resulting ledger a web UI (balance tree, hash chain, and a
reconciliation button) via `uv sync --extra ui && uv run streamlit run
examples/streamlit_dashboard.py`.

Packaged with [uv](https://docs.astral.sh/uv/); metadata, license, and classifiers live
in [`pyproject.toml`](pyproject.toml). Security policy and data map:
[`SECURITY.md`](SECURITY.md). Contributing guide: [`CONTRIBUTING.md`](CONTRIBUTING.md).
Release notes: [`CHANGELOG.md`](CHANGELOG.md). Licensed under [Apache 2.0](LICENSE).
