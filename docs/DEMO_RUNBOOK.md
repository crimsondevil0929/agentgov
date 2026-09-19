# End-to-end walkthrough

Four commands that exercise the governor from adoption through audit. Nothing
here needs a network or an API key: the model is `DummyLLM`, a deterministic
offline stub, so the figures are reproducible on any machine.

Every number printed is measured at runtime. Where this file disagrees with the
terminal, the terminal is right — latency depends on the host, and cost depends
on which model is priced.

## Setup

```bash
uv sync                      # zero runtime dependencies
uv run pytest -q             # 338 passed
rm -rf demo                  # the demo writes into ./demo; start clean
```

The reconciliation table is 62 columns wide, so run it in a terminal at least
100 columns across or it wraps.

---

## Step 1 and 2 — adoption, then the halt

```bash
uv run python examples/live_demo.py
```

Governs an existing LangChain agent by adding a sub-budget and wrapping the
model object; no call site changes. Then it drives the same agent into a
near-duplicate loop and lets the cognitive breaker stop it.

```
==========================================================================
  AgentGov — runtime spend governor and denial-of-wallet breaker
  Simulated model calls; no network, no API key, no real spend.
==========================================================================

[1/4]  Two lines to govern an existing LangChain agent
       gov.delegate('orchestrator', 'researcher', money('1.00'))
       model = GovernedChatModel(model, gov, 'researcher', journal=journal)

       OK  summarise the consolidated Q3 revenue figures          $0.00955500
       OK  compare gross margin against the Q2 guidance we publ   $0.00957000
       OK  draft the three risks worth flagging to the board      $0.00956000

       3 calls, $0.02868500 of a $1.00000000 sub-budget. The call sites did not change.

[2/4]  An adversarial runaway loop, stopped for a fraction of a cent
       ..  find the Q3 revenue report for the northwest region    executed
       ..  find the Q3 revenue reports for the northwest region   executed
       ..  find the Q3 revenue report for the northwest regions   executed

       HALTED after 3 calls
       detector   near_duplicate (deterministic), confidence 0.88
       reason     4 consecutive near-identical calls to 'invoke' ...
       burned     $0.00573800 of a $1.00000000 sub-budget
       overhead   78us mean, 89us p99 per call, measured just now on this machine
       500 further attempts refused; spend unchanged at $0.00573800 — the breaker latches
```

What the step demonstrates:

- The three loop queries are byte-distinct, so an exact-match dedupe cache or a
  request-rate limiter passes all three. The near-duplicate detector compares
  character-trigram Jaccard and stops the run at three.
- The 500 follow-up attempts move spend by zero. The breaker latches, so a
  retry storm cannot wear it down; those calls fail before the authorization
  hold is placed and never reach the ledger.
- Inline detector overhead is measured on the host during the run, not quoted
  from this file.

---

## Step 3 — read the ledger

```bash
uv run agentgov inspect demo/governor.db
```

```
LEDGER  demo/governor.db
  23 hash-chained entries across 3 scopes; head e6c5c0330217ea83

BALANCE TREE
  orchestrator  available $3.00000000  of $5.00000000
  |- researcher  available $0.97131500  of $1.00000000
  `- runaway  available $0.99426200  of $1.00000000   [HALTED by runaway]

TOTALS
  funded          $5.00000000
  settled spend   $0.03442300
  holds open      $0.00000000
  unspent         $4.96557700

CIRCUIT BREAKER  (1 control events)
  1/3 scopes halted
  ... circuit_tripped  runaway  cognitive breaker [near_duplicate]: ...

ENTRIES  (last 20 of 23)
   18  hold       runaway   -0.03073950  bal 0.96734850  call authorization
   19  hold_void  runaway   +0.03073950  bal 0.99808800  authorization captured
   20  spend      runaway   -0.00191300  bal 0.99617500  settled call cost
```

Entries 18 through 20 are one model call: the hold encumbers the worst-case
cost before the call runs, then the void and the settled spend post together in
one transaction. The funds are unavailable to sibling scopes for the whole
in-flight duration, which is what closes the double-spend window.

The cognitive trip is recorded as a control event in the same hash chain as the
financial entries.

`inspect` opens the database read-only, so it is safe to run against a live
governor holding the write lock.

**Precision on the chain:** tamper-evident, not tamper-resistant. Any process
with write access to the file can rewrite the chain; `verify_chain()` will show
that it was rewritten. There is no external anchoring in v0.1. See
[`SECURITY.md`](../SECURITY.md).

---

## Step 4 — reconcile against the provider invoice

```bash
uv run agentgov reconcile demo/governor.db demo/provider_invoice.json \
    --journal demo/tokens.jsonl
echo $?          # 1 — any phantom line fails the audit
```

```
RECONCILIATION
  tolerance  time +/-5.0s   tokens +/-2.0%   cost +/-1.0%
  matching   token-level (journal supplied)

  CATEGORY                             COUNT             SPEND
  ------------------------------------------------------------
  Matched (billed and metered)             6         $0.034423
  Discrepant (cost mismatch)               0         $0.000000
  Phantom (billed, NOT metered)            1         $2.470000
  Unsettled (metered, not billed)          0         $0.000000

  Invoiced total                                     $2.504423
  Metered total                                      $0.034423
  Variance                          7175.44%         $2.470000

  PHANTOM CALLS - billed with no local authorization
    2026-09-14 06:42:29  claude-opus-5   $2.470000  req_LEAKED_KEY_7f3a

  AUDIT FAILED  1 phantom call(s) worth $2.470000
```

A phantom is spend the provider billed that the governor never authorized: a
leaked key, or a service calling the model outside the process. It is detection
after the fact, not prevention, and it is the only backstop for spend that
bypasses the call site.

The six matched lines were billed ~1.4s after they settled locally. Matching is
on tolerance windows rather than equality because timestamps drift with network
latency and token counts drift because pre-flight sizing is a `chars/4`
heuristic. Exact matching would report a healthy ledger as entirely broken.

---

## Scope of this walkthrough

- The model is a deterministic stub. Swapping in a real client is one line and
  the governor cannot tell the difference — that is the point of the adapter
  layer. For the same machinery against the live Anthropic API, run
  `scripts/generate_real_usage.py` (costs about $0.05).
- Single process. A second governor on the same database is refused at open
  with `ConcurrentGovernorError` naming the holding PID. Multi-host is the
  `PersistenceStore` roadmap item.
- Loop-detection false positives are possible on templated results that differ
  only by an index. That case is pinned by a test in
  `tests/test_cognitive_breaker.py`; the escape hatch is
  `CognitivePolicy(exempt_tools={...})`.

## When a step misbehaves

| Symptom | Cause and fix |
|---|---|
| `ConcurrentGovernorError` on step 3 or 4 | A previous run still holds the database. `rm -rf demo` and re-run step 1. |
| Step 1 reports a different halt count or cost | Expected. The detector is deterministic; the cost depends on the model priced. Read the terminal. |
| Reconciliation table wraps | Widen to 100+ columns, or `agentgov inspect --limit 5`. |
| Anything else | `uv run pytest -q`. A green suite localises the problem to the demo scripts rather than the library. |
