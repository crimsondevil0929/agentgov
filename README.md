# AgentGov

**The runtime spend governor and denial-of-wallet circuit breaker for autonomous agent fleets.**

[![CI](https://github.com/crimsondevil0929/agentgov/actions/workflows/ci.yml/badge.svg)](https://github.com/crimsondevil0929/agentgov/actions/workflows/ci.yml)
[![tests](https://img.shields.io/badge/tests-323%2F323%20passing-brightgreen)](#code-quality--packaging)
[![coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)](#code-quality--packaging)
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

The model here is a deterministic offline stub, which is what makes a million-call
comparison reproducible. For the same machinery measured against the real Anthropic API,
see [Live API metering](#live-api-metering) below.

```
+=======================+==========================+==========================================+======================================================+
| METRIC                | Scenario A - Ungoverned  |    Scenario B - AgentGov (Financial)     |    Scenario C - AgentGov (Cognitive + Financial)     |
+=======================+==========================+==========================================+======================================================+
| Wall clock            |                    3.00s |                                    3.00s |                                                3.00s |
| Sub-agents spawned    |                      118 |                                   30,383 |                                                    1 |
| Calls attempted       |                1,175,392 |                                   31,017 |                                              245,666 |
| Calls executed        |                1,175,392 |                                      635 |                                                    3 |
| Calls refused         |                        0 |                                   30,382 |                                              245,663 |
| Tokens consumed       |              383,569,559 |                                  207,251 |                                                  770 |
+-----------------------+--------------------------+------------------------------------------+------------------------------------------------------+
| Intended budget       |                $5.000000 |                                $5.000000 |                                            $5.000000 |
| Actual cost realized  |            $9,224.867435 |                                $4.984635 |                                            $0.018330 |
| Cost vs budget        |               184,497.3% |                                    99.7% |                                                 0.4% |
| Budget breached after |                   0.002s |                                    never |                                                never |
+-----------------------+--------------------------+------------------------------------------+------------------------------------------------------+
| Cognitive breaker     |        n/a - not enabled |                        n/a - not enabled | TRIPPED [deterministic/near_duplicate] after 4 calls |
| Financial breaker     | n/a - no backstop exists | LATCHED OPEN - 30382/30384 scopes halted |                     LATCHED OPEN - 1/2 scopes halted |
| verify_integrity()    |   n/a - no ledger exists |            PASS - 123436 entries chained |                            PASS - 12 entries chained |
| verify_conservation() |   n/a - no ledger exists |     PASS - no money created or destroyed |                 PASS - no money created or destroyed |
+=======================+==========================+==========================================+======================================================+
```

All three run the *identical* workload — an agent that cannot find a report and keeps
re-asking with cosmetic edits. The governed scenarios differ by exactly one constructor
argument, so the third column isolates what loop detection buys and nothing else.

**A — Ungoverned:** 1.18M calls in 3 seconds, $9,224.87 against a $5.00 intended budget,
breached in 2 milliseconds and never stopped. **B — Financial:** capped at $4.984635 of
the $5.00 envelope, 30,382 further attempts refused. Correct — but the money is gone; the
envelope bounds the damage rather than preventing it. **C — Cognitive + financial:**
halted after **3 executed calls and $0.018330**, 0.4% of the envelope and **272x cheaper
than waiting for the budget to run out**. The remaining 245,663 attempts cost nothing at
all: the check runs ahead of the authorization hold, so a halted call never reaches the
ledger.

Scenario C's cost is bit-for-bit reproducible across runs — it is bounded by the policy,
which does not care how many iterations the clock allowed. A and B are not, and the table
above is one recorded run rather than a fixed expectation: A's total is however many calls
fit in three seconds, and B settles somewhere just under the envelope depending on where
the last holds land. For A and B the *bound* is the guarantee, not the figure.

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

**Pricing is exact, not approximately right.** Every settled call is re-priced a second
time straight from the published rates and compared against what the ledger captured.
Across 445 input and 2,117 output tokens on four different price tiers the drift is
**$0.00000000** — the metering path reads a real `usage` object and turns it into the
same number twice, independently. `anthropic` 1.6.0; `claude-fable-5-1` served natively.

**The cognitive breaker fires on live traffic.** Tier 1 drives a thrashing loop — four
cosmetically-edited restatements of one request. It halted after **3 executed calls and
$0.001974**, then refused 5 retry attempts with no balance movement at all. Tier 2, a
genuinely progressing three-step workflow, ran to completion untouched: the detector
discriminates, rather than simply halting whatever runs longest.

**This run found a real bug, which is the point of running it.** Against the live API the
breaker initially did *not* fire, despite the loop being obvious. Two defects, both
invisible to a stub-backed test suite:

1. **The result comparison was measuring the SDK envelope, not the answer.** Rendering an
   `anthropic.types.Message` through `repr` meant most of the compared characters were
   `Message(id=…`, `TextBlock(citations=None, type='text'…`, `usage=Usage(…)` —
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
genuinely progressing traffic. Its finding is more interesting than a new constant —
**the per-pair distributions genuinely overlap** (thrashing 0.32–0.66, pagination
0.13–0.88), so no single-pair threshold separates them. What separates them is the
*streak* requirement: pagination's similarity is erratic, thrashing's stays persistently
elevated. Sweeping the real rule, `0.25`–`0.30` catches 4/4 thrashing trajectories with
zero false positives on either control family; `0.20` begins false-positiving on
pagination. The shipped default is now **`0.30`**, the conservative end of that band.

Reproduce it — this spends real money, so rehearse first:

```bash
export BENCHMARK_API_KEY=sk-ant-...        # never falls back to ANTHROPIC_API_KEY
uv run python scripts/generate_real_usage.py --dry-run   # free rehearsal, no network
uv run python scripts/generate_real_usage.py             # ~$0.05
uv run python scripts/calibrate_result_threshold.py      # ~$0.03
```

The full write-up of what this run exposed — envelope dominance, prose entropy, and why
the per-pair distributions cannot be separated by any constant — is
[`ARCHITECTURE.md`, Part A](ARCHITECTURE.md#part-a--the-simulation-gap).

Every call carries an explicit `max_tokens`, the whole run executes inside a $1.50
AgentGov envelope, and the runaway loop is additionally bounded by a hardcoded counter
that breaks at four iterations — so a regression in the breaker still cannot run away.
Raw payloads, the cost summary, the ledger, and the metering journal are written to
timestamped files under `benchmarks/live_data/` (gitignored: they are evidence, not
repository content).

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

**What it keeps.** Nothing readable, by default. Each observed call is reduced to a
*salted* BLAKE2b digest (the salt is per-instance, so a digest is not a lookup key for a
known prompt) plus a bounded set of character trigrams. Readable text is retained only
under an explicit `CognitivePolicy(retain_arguments=True)`, and is truncated even then.
For regulated data, install a `Redactor` — it runs at the single ingress every argument
and result passes through, before anything is fingerprinted or stored, and a redactor
that raises causes the text to be dropped entirely rather than retained unredacted.
[`SECURITY.md`](SECURITY.md) is the full data map: what lands in SQLite, in memory, and
in logs, and what encryption at rest AgentGov does *not* provide.

**Where it does not reach — stated plainly.** Legitimate iteration (pagination,
map-over-a-list) looks like a soft loop on *input* similarity alone. The discriminator is
the result: near-identical inputs producing near-identical outputs is thrashing;
near-identical inputs producing different outputs is progress. The `Interceptor` feeds
results back automatically, which handles the common case. It still cannot see through a
*templated* result whose only variation is an index (`record-1-0`, `record-2-0`) — those
are near-identical in trigram space even though the agent is advancing. That limitation
is [pinned by a test](tests/test_cognitive_breaker.py), along with its remedy:
`CognitivePolicy(exempt_tools={"fetch"})`, a raised threshold, or a custom detector.

## Dropping it in

`invoke()` is the primitive, and it stays the contract. But adopting it in an
existing codebase means editing every call site, so there is a wrapper that
governs the calls already written:

```python
client = govern(anthropic.Anthropic(), gov, "researcher", model="claude-opus-5")

response = client.messages.create(model="claude-opus-5", messages=[...])  # unchanged
print(client.agentgov.last_call.cost)
```

The proxy returns exactly what the SDK returns — anything else would not be a
drop-in — and forwards everything that is not a model call untouched. It is
sugar over `client.agentgov.interceptor`, which hands the primitive back.

**Streaming**, the shape most real agents use, is governed as a context manager:

```python
with client.messages.stream(model="claude-opus-5", messages=[...]) as events:
    for event in events:
        render(event)
print(events.cost)
```

The hold is resolved on *every* path out of that block — clean exhaustion,
`break`, an exception, or a timeout — so an abandoned stream never strands
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

## Framework adapters

Two lines on an agent you have already written. Neither adapter imports its
framework — every object is duck-typed, so they load without LangChain or
CrewAI installed and keep working when those libraries reshuffle internals.

```python
from agentgov.adapters.langchain import GovernedChatModel

model = GovernedChatModel(ChatAnthropic(model="claude-opus-5"), gov, "researcher")
answer = model.invoke(messages)  # unchanged call site, now metered
```

For **LangGraph** — or any chain deep enough that you never touch the model
object — use the callback handler instead. Callbacks propagate down the whole
run tree, so one handler governs every model call in a graph, keyed by
`run_id` so concurrent branches settle independently:

```python
from agentgov.adapters.langchain import GovernedCallbackHandler

graph.invoke(state, config={"callbacks": [GovernedCallbackHandler(gov, "researcher")]})
```

**CrewAI** settles per run, because CrewAI reports usage per run:

```python
from agentgov.adapters.crewai import GovernedCrew

crew = GovernedCrew(Crew(agents=[...], tasks=[...]), gov, "research-crew")
result = crew.kickoff()
```

Two details these get right that are easy to get wrong. LangChain **swallows
exceptions raised inside callbacks** unless the handler sets
`raise_error = True` — without it a denial-of-wallet halt would be logged and
the graph would keep spending. And CrewAI's `usage_metrics` are **cumulative
across kickoffs**, so settling the reported total each run would bill run one
again on run two; `GovernedCrew` charges only the delta.

For a framework with no adapter, `govern_agent` wraps any function that runs a
unit of agent work, given a callable that reads usage off its return value.

## Reconciling the invoice

The question a finance or security team actually asks is not "what did we
budget?" but *"the provider billed us $40,000 — which agent caused it, and is
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
AgentGov never authorized — a leaked key, or a service calling the model
outside the governor. Any phantom line exits `1`, so this belongs in a
pipeline.

Matching is fuzzy on purpose. Timestamps drift by network latency and token
counts drift because pre-flight sizing is a `chars/4` heuristic; exact matching
would report a healthy ledger as entirely broken. Both windows are configurable
(`--time-tolerance`, `--token-tolerance`, `--cost-tolerance`).

Token counts come from a `MeteringJournal`, an additive sidecar — the ledger
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
  ok    hash chain + balance cache
  ok    conservation identity
  ok    delegation topology

PASS  governor.db  (14 entries verified; head 56d879d72557ec6e)
```

`verify` exits `0` on PASS and `1` on FAIL, so it drops straight into a
pipeline to assert an archived ledger is intact. Both commands open the
database **read-only**, so they are safe to run against a governor that is
live and holding the write claim.

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
dependencies.

**One writer, enforced.** A governor takes an exclusive advisory lock on its database.
A second process — a second gunicorn worker, a second replica — is refused *at open*
with a `ConcurrentGovernorError` naming the PID that holds it, because two writers would
each cache authoritative balances in memory and diverge. The lock is an open file
descriptor, so the kernel releases it even on `SIGKILL`: a crashed governor leaves a
stale file but never a stale lock, and there is no timeout heuristic to get wrong. To
inspect a ledger another process is governing, open it read-only:

```python
audit = BudgetManager.open_sqlite("governor.db", read_only=True)
audit.verify_integrity()  # reads and verifies; every write is refused
```

**Dangling holds are findable.** A hold left open by a process that died between
`authorize()` and `capture()` encumbers funds with nothing left to settle it.
`stale_authorizations(older_than)` surveys them without touching anything, and
`void_stale(older_than)` releases them. Deliberately an operator action rather than a
background timer: voiding asserts the call will never settle, and AgentGov cannot know
that. If such a call *does* complete later, its capture raises `DoubleSpendError` — the
ledger refuses to book the same encumbrance twice.

See [`tests/test_persistence.py`](tests/test_persistence.py) and
[`tests/test_hardening.py`](tests/test_hardening.py) for the restart, corruption,
lock-contention, and durable-write-failure matrices.

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

## Known limitations & v0.1 scope

Every claim on this page is measured, and the boundaries of what was measured matter as
much as the numbers. This section states them plainly rather than leaving them to be
discovered in production.

### Single-writer by design — one process, one host

`BudgetManager.open_sqlite()` takes an exclusive advisory lock on the database. **One
process governs one ledger.** A second process is refused at open with
`ConcurrentGovernorError` naming the holding PID; it is not silently allowed to diverge.

Measured throughput on that single writer, all of it behind one global mutex:

| Configuration | Mean per governed call | p99 | Sustained ceiling |
|---|---|---|---|
| In-memory ledger | 0.062 ms | — | ~16,000 calls/sec |
| SQLite, `synchronous=FULL` | 0.613 ms | 3.448 ms | ~1,600 calls/sec |

**This is a deliberate trade, not an oversight.** The alternative — shipping a
coordination service — would mean infrastructure to deploy, a network hop in the hot
path, and a dependency tree, all before anyone could evaluate whether the governor is
worth having. `pip install agentgov` with zero runtime dependencies and a local file is
what makes the thing adoptable in an afternoon. The cost of that choice is that
AgentGov v0.1 governs *a process*, not a fleet.

**The roadmap fix is already seamed for.** `agentgov.storage.PersistenceStore` is a
Protocol, and `SqliteStore` is one implementation of it. A **Postgres or Redis
`PersistenceStore`** puts the ledger in a shared transactional store, making the
database the serialization point so N processes across N hosts share one authoritative
view of every balance — fleet-wide consensus without a bespoke consensus cluster, and
without touching the ledger, the budget DAG, or the breaker. SQLite stays the default so
the zero-dependency install is unaffected.

### A guardrail inside a process, not a sandbox around it

AgentGov enforces at the call site, in your process. Anything that can `import agentgov`
can also call the provider SDK directly and spend unmetered. The hash chain is
**tamper-evident, not tamper-resistant** — `verify_chain()` will prove a file was edited,
but nothing stops a process with write access from editing it, and there is no external
anchoring. The [reconciliation engine](#reconciling-the-invoice) is the backstop for
out-of-band spend, and it is *detection after the fact*, not prevention. Treat AgentGov
as a budget guardrail against runaway and accident — the failure mode that actually burns
money today — not as a security boundary against a hostile agent.

### Published rates are a snapshot

`agentgov.interceptor.PRICING` is a hardcoded table of published list rates, current as
of the date in its docstring. Vendors change prices, and partner platforms (Bedrock,
Vertex) bill differently. Pass an explicit `ModelPricing` for anything not in the table,
and treat reconciliation against the real invoice as a production requirement rather than
a nicety — that is precisely why the reconciliation engine exists.

### What has been proven deterministically, and what has been proven live

These are different claims and this project keeps them separate.

**Proven deterministically.** The accounting invariants — no double-spend under
concurrency, conservation of value, an unbroken SHA-256 chain, the latching breaker — are
verified against `DummyLLM`, a deterministic offline stub, under 64 contending threads and
100 concurrent asyncio tasks. This is the right harness for these properties: a governor
that is only *probably* correct under load is not correct, and a nondeterministic backend
cannot prove a race is absent.

**Proven against the live API.** Correct accounting says nothing about whether the
metering layer reads a *real* provider response. That gap is closed by
[`scripts/generate_real_usage.py`](scripts/generate_real_usage.py), which drives four
governed workloads across four Anthropic model tiers through the official `anthropic`
SDK, re-prices every settled call independently from the published rates, and writes every
raw API payload to disk as evidence — see [Live API metering](#live-api-metering) below.

## Roadmap — Phase 2

Phase 1 is a correct, single-process governor: one ledger, one mutex, durable to a local
SQLite file, with financial and cognitive breakers on the same actuator. Beyond that:

- **State recovery after a trip — the "what then?" protocol.** A breaker protects the
  wallet, but nobody's goal was to not spend money; it was to finish the task. Halting is
  the cheapest possible failure and it is still a failure. The design brief —
  cryptographic state checkpointing over a Merkle prefix tree, an append-only intervention
  ladder ordered by prompt-cache invalidation cost, and a budgeted stopping rule over the
  breaker's own novelty signal — is
  [`ARCHITECTURE.md`, Part B](ARCHITECTURE.md#part-b--the-what-then-protocol-v02-state-recovery-roadmap).
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
uv run pytest -v                     # 323 passed
uv run pytest --cov=agentgov         # 96% coverage
uv run ruff check . && uv run ruff format --check .
uv run mypy src/                     # strict, zero errors
uv run python examples/denial_of_wallet_benchmark.py
uv run python examples/persistence_demo.py
```

Every gate above runs in CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) on
Python 3.11 and 3.12, on Linux and macOS, with a 95% coverage floor and a build that
fails on packaging warnings. Both example scripts are executed end to end so a broken
demo cannot merge.

For a three-minute live walkthrough — adopt, halt a runaway, verify the chain,
catch unmetered spend — see [`docs/DEMO_RUNBOOK.md`](docs/DEMO_RUNBOOK.md) and
run `uv run python examples/live_demo.py`. [`demo.tape`](demo.tape) renders that
same walkthrough as a terminal recording with [VHS](https://github.com/charmbracelet/vhs)
(`vhs demo.tape`), and [`examples/streamlit_dashboard.py`](examples/streamlit_dashboard.py)
gives the resulting ledger a web UI — balance tree, hash chain, and a
reconciliation button — via `uv sync --extra ui && uv run streamlit run
examples/streamlit_dashboard.py`.

Packaged with [uv](https://docs.astral.sh/uv/); metadata, license, and classifiers live
in [`pyproject.toml`](pyproject.toml). Security policy and data map:
[`SECURITY.md`](SECURITY.md). Contributing guide: [`CONTRIBUTING.md`](CONTRIBUTING.md).
Release notes: [`CHANGELOG.md`](CHANGELOG.md). Licensed under [Apache 2.0](LICENSE).
