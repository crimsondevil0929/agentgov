# Live demo runbook — three minutes

A four-beat terminal demo. One setup command, then three real CLI invocations.
Every figure is measured at runtime, so you are never reading a slide to
someone — you are showing them a machine doing the thing.

**The arc:** adopt it in two lines → watch it stop a runaway for less than a
cent → prove the books are cryptographically intact → prove nothing spent money
behind its back.

---

## Before you walk in

```bash
cd agentgov
uv sync                      # ~10s, zero runtime dependencies
uv run pytest -q             # 316 passed — run this once, it is your safety net
rm -rf demo                  # start from a clean slate
```

**Rehearse the whole thing once on the machine you will present from.** The
breaker's latency is measured live, so it reflects that hardware.

Terminal setup that matters:

- **Font size up.** 18pt minimum. The reconciliation table is 62 columns wide;
  anything narrower than ~100 columns will wrap and look broken.
- **Dark background, no transparency.** The demo prints red for halts and
  cyan for money.
- **Clear scrollback** (`clear`) between steps so each output starts at the top.

Have this open in a second tab in case someone asks to see the source:
`src/agentgov/cognitive.py` (the detectors) and `src/agentgov/core.py` (the
ledger's `verify_conservation`).

---

## Step 1 + 2 — Adoption, then the halt (~70 seconds)

```bash
uv run python examples/live_demo.py
```

### Expected output

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

### What to say

> "Here's an agent already built on LangChain. To govern it, I changed two
> lines — I gave it a one-dollar sub-budget and wrapped the model. No call site
> changed. It does three pieces of real work, and every one is metered to the
> hundred-millionth of a dollar."

*(pause on the halt)*

> "Now the same agent goes wrong the way agents actually go wrong. It can't
> find the report, so it re-asks with tiny edits. Every one of those strings is
> **different** — an exact-match cache or a dedupe rate-limiter sees five
> distinct requests and lets all five through.
>
> AgentGov stops it after three, for **half a cent**. Against a five-dollar
> envelope, that's a tenth of a percent. And the check costs seventy-eight
> microseconds — that number was measured on this laptop ten seconds ago, not
> written into a slide.
>
> Then it tries five hundred more times with a completely unrelated question.
> Spend doesn't move. The breaker latches — a retry storm can't wear it down."

**The line to land:** *a budget cap stops you after you've spent the money;
this stops you before.*

---

## Step 3 — Prove the ledger (~40 seconds)

```bash
uv run agentgov inspect demo/governor.db
```

### Expected output

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

### What to say

> "This is the ledger. It's double-entry — the same discipline a bank uses.
> Look at those last three lines: that's one model call. A **hold** goes on
> before the call, the hold is **voided** and the true cost **captured** in one
> atomic transaction after. That's why two agents can't spend the same dollar:
> the money is encumbered while the call is in flight.
>
> Every entry is SHA-256 chained to the one before it. And notice the halt is
> recorded here too — a *cognitive* verdict, written into the *financial* audit
> trail, anchored to the chain hash. One halt mechanism, two kinds of sensor."

If someone asks whether it's tamper-proof, be precise:

> "Tamper-**evident**, not tamper-resistant. Anyone who can write the file can
> rewrite the chain — but they can't do it without it being detectable, and
> `SECURITY.md` says exactly that. Anchoring the head hash externally is on
> the roadmap."

---

## Step 4 — Prove there was no unmetered spend (~50 seconds)

```bash
uv run agentgov reconcile demo/governor.db demo/provider_invoice.json \
    --journal demo/tokens.jsonl
```

### Expected output

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

Then, for the people who care about pipelines:

```bash
echo $?          # 1
```

### What to say

> "Last piece. This is the provider's invoice, matched against our ledger.
> Six lines reconcile — and note they were billed **1.4 seconds** after we
> settled them, because clocks and networks drift. It matches on a tolerance
> window, not on equality, or a healthy ledger would look completely broken.
>
> And then there's this one. Two dollars forty-seven, on the invoice, that
> AgentGov never authorized. That's a **phantom call** — a leaked key, or a
> service calling the model outside the governor. This is the question every
> enterprise asks and nobody can currently answer: *is there anything on this
> bill we didn't approve?*
>
> Exit code one. That goes straight in a CI pipeline."

**The line to land:** *this is the difference between a budget tool and a
control plane. One tells you what you meant to spend. This proves what you
actually spent, and attributes every dollar to an agent.*

---

## Closing (~20 seconds)

> "Three hundred and sixteen tests, ninety-six percent coverage, mypy strict,
> and zero runtime dependencies — the whole thing is standard library. It runs
> on a laptop today. The roadmap is distributed leases so it runs across a
> fleet, signed capabilities so a counterparty can verify a spend authorization
> without trusting us, and netting so sub-cent agent transactions can actually
> settle."

---

## Question bank

**"Couldn't Anthropic or OpenAI just ship this?"**
> They can cap spend on their own platform. They can't govern a delegation tree
> that spans providers and organizations — and they have no incentive to help
> you spend less with them.

**"Isn't this a LangChain feature?"**
> They'll add per-framework callbacks, and they should. This is framework-
> neutral, and the ledger and reconciliation layers are a different product.
> The adapters are 200 lines; the ledger is the moat.

**"How do you know the loop detection won't fire on legitimate work?"**
> Measured separation: cosmetically-edited queries score 0.74–0.83 in
> character-trigram Jaccard; queries that genuinely advance a task score below
> 0.14. The 0.70 threshold sits mid-gap with 5× margin. And there's a
> documented false-positive case — templated results that differ only by an
> index — pinned by a test, with `exempt_tools` as the escape hatch.

**"What's the overhead in production?"**
> 78µs mean on the inline path, which you just watched it measure. Roughly
> 0.005% of a real model call. The semantic tier runs off-thread and never
> blocks the agent — there's a test that proves a 500ms-per-call observer
> costs the caller nothing.

**"Does it work across processes?"**
> Not yet, and it says so rather than pretending. A second process gets a
> `ConcurrentGovernorError` naming the PID that holds the database, because two
> writers would each cache balances and diverge. Distributed leases are the
> first roadmap item.

**"Is that a real model?"**
> No — it's a deterministic offline stub, so the demo needs no key and gives
> the same numbers on any machine. Swapping in a real client is one line, and
> the governor can't tell the difference. That's the point of the adapter.

---

## If something goes wrong on stage

| Symptom | Fix |
|---|---|
| `ConcurrentGovernorError` on step 3 or 4 | A previous demo is still holding the DB. `rm -rf demo` and re-run step 1. |
| Step 1 prints a different halt count | Harmless — the detector is deterministic but the *cost* depends on the model priced. Say the number on screen, not the number in this doc. |
| Table wraps | Widen the terminal to 100+ columns, or `agentgov inspect --limit 5`. |
| Anything else | `uv run pytest -q` in the second tab. 316 green tests is a recovery of its own. |

**Never** improvise a number. Every figure here is printed by the tool; if the
screen disagrees with this runbook, the screen is right.
