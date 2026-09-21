# v0.2 Architectural Blueprint: The Token-Native Control Plane

**Scope:** `agentgov` (ledger / governor) and `interlock` (execution proxy).
**Status:** proposal. v0.1.1 Data Plane is locked and CI-green; nothing here
changes it, and every addition is gated on that remaining true.

---

## 0. The thesis, in one paragraph

v0.1 is a **deterministic boundary**: given a state and a measurement, it
returns the same verdict forever. That property is the entire asset, and the
naive way to make the system "smarter" — putting a model on the write path —
destroys it. v0.2 therefore does not make the boundary intelligent. It makes
the boundary **parameterised**, and moves all intelligence into an
asynchronous Control Plane whose only output is a **signed, hash-chained
parameter epoch**. The Data Plane stays a pure function. What changes is that
its parameters are now learned, its cost model is cache-aware, and its refusals
are machine-actionable.

One structure carries most of the weight. A **Merkle prefix tree over the
message array** is simultaneously:

| It answers | Used by |
|---|---|
| "Is this resume a legal continuation?" | §4 state recovery |
| "Will this request hit the provider cache, and for how many tokens?" | §1 token-native pricing |
| "What should I reserve before I know?" | §1 speculative holds |
| "What exactly was the agent looking at when it proposed this?" | §2 reflection provenance |

Four capabilities, one data structure, because *cache residency and resume
legality are the same question*: how long is the shared prefix. Part B of
`ARCHITECTURE.md` identified this coupling. This document makes it concrete.

---

# Part I — Core Concept & Theoretical Foundation

## 1. Token-Native FinOps (`agentgov`)

### 1.1 The cost model v0.1 does not have

`ModelPricing.estimate(input_tokens, max_output_tokens)` is cache-blind.
`TokenUsage` already carries `cache_read_input_tokens` and
`cache_creation_input_tokens`; `PRICING` already carries
`cache_read_usd_per_mtok` and `cache_write_usd_per_mtok`. The rates are
present and the estimator ignores them.

Decompose an input into three segments by cache state:

```
P = L + U          L = cacheable prefix tokens,  U = uncached suffix tokens
```

and let `q = P(the prefix is resident in the provider cache at send time)`.

```
hit :   cost_in = r·L + i·U
miss:   cost_in = w·L + i·U          (you pay to write the cache)

E[cost_in] = ρ(q)·L + i·U        where   ρ(q) = q·r + (1−q)·w
```

`ρ(q)` is the **effective prefix rate**. It is the only new quantity v0.2
needs to price a request.

### 1.2 A model-independent constant falls out

Caching a prefix beats paying the plain input rate exactly when `ρ(q) < i`:

```
q*  =  (w − i) / (w − r)
```

Anthropic's rate card prices cache reads at `0.10·i` and cache writes at
`1.25·i` **uniformly across every model**. Therefore:

```
q*  =  (1.25 − 1.00) / (1.25 − 0.10)  =  0.25 / 1.15  =  21.74%
```

Measured across the shipped `PRICING` table: 21.7391% for every model except
Claude Fable 5.1, whose cheaper cache read (`0.02·i`) gives 20.41%.

> **Set a cache breakpoint only when P(hit) > ~21.7%.** Below that, caching is
> EV-negative and the breakpoint costs money. This is a governor decision, it
> is computable before the call, and nothing in the ecosystem computes it today.

The constant is sensitive to the write multiple, which is TTL-dependent. If a
1-hour-TTL write costs `2.0·i`, the same formula gives `q* = 52.6%` — a
materially different policy for the same prompt. **Required change:**
`ModelPricing` gains per-TTL write rates; `q*` becomes a property of
`(model, ttl)`, not a constant.

### 1.3 Speculative holds, and why the hold is not the forecast

v0.1's hold is worst-case by design, and must stay that way: the README
already establishes that an under-reserved hold does not encumber, so
concurrent callers all pass pre-flight and settle for more than they reserved
(measured: a 2.3× envelope breach on a 150K-character prompt).

So v0.2 separates two things v0.1 conflates:

```
HOLD      = miss-branch cost      (conservative; preserves no-double-spend)
FORECAST  = ρ(q)-weighted cost    (cache-aware; drives every decision)
```

A worst-case hold over a 200K-token cached prefix is enormous and starves
siblings. The fix comes from the correlation structure, not from shrinking the
hold:

**Split the hold, and budget the cache namespace rather than the call.**

```
H  =  H_floor  +  H_contingent
      ├─ H_floor       = r·L + i·U + o·O_max     the hit branch: you will pay at least this
      └─ H_contingent  = (w − r)·L               the delta to the miss branch
```

`H_floor` encumbers the calling scope as today. `H_contingent` encumbers a
**contingency pool held once per cache namespace at the parent scope**, not
once per call — because for N siblings sharing a namespace the miss event is
*common-mode*: if the prefix is resident for one it is resident for all. The
uncertainty is one Bernoulli trial, not N independent ones, so reserving N
times over-reserves by construction.

The **cache namespace key** is `(model_id, tool_set_hash, system_hash)`,
because the provider renders `tools → system → messages` and a change to
either of the first two invalidates everything downstream. This key is
recorded in the checkpoint (§4.2) and is what makes namespace-level budgeting
well-defined.

Conservation is untouched: `H_contingent` is an ordinary hold in an ordinary
scope, so `Σ(balances) + holds + spent − reversals == funded` holds unchanged.
**No new money primitive.**

### 1.4 Burn velocity and acceleration, in token-native units

Dollars per second conflates "expensive model" with "runaway loop." Normalise
every token to **input-token equivalents** at that model's own rates:

```
τ_eff  =  U  +  (r/i)·R  +  (w/i)·W  +  (o/i)·O  +  (o/i)·Θ
```

where `Θ` is thinking tokens. `τ_eff` is comparable across models and across
cache regimes, which dollars are not.

Over the ledger — already a hash-chained time series of settled entries:

```
v = dτ_eff/dt          velocity
a = d²τ_eff/dt²        acceleration
T_exhaust = Δ solving   B + v·Δ + ½·a·Δ² = envelope_remaining
```

v0.1's financial breaker is a **level** trigger: it fires when the money is
gone, which Part B correctly calls reactive by construction. v0.2 adds a
**derivative** trigger:

```
trip  iff   T_exhaust < horizon   AND   drift(novelty) ≤ 0
```

The gating conjunct matters. Acceleration alone would halt a legitimately
expensive task that is making progress. Coupling the financial derivative to
the cognitive drift signal (§4.4) fires only on *fast and going nowhere*.
Both terms are computed from the hash-chained ledger and the existing Tier-2
novelty history, so **the trip stays deterministic**: same chain, same trip.

### 1.5 Preserved thinking as a priced asset

On models enforcing preserved thinking, thinking blocks are bound to the
producing model and are dropped by any other. A thinking token is therefore
not just a cost — it is an **asset with an option value**: reusable on the same
model, worthless on another. That makes model re-route quantifiable rather
than merely "expensive":

```
C_reroute  =  w′·P   +   o′·Θ_replay
              └ rebuild the cache on the new model
                       └ re-derive the thinking the old model produced
```

This is why re-route is the second-to-last rung of the ladder (§4.3), and now
it is last-but-one *for a computed reason* rather than by assertion.

---

## 2. Agent-Native Execution & Reflection (`interlock`)

### 2.1 A refusal must be a constraint, not a complaint

Today a refusal yields `blocked_by: tuple[str, ...]` and human-readable
violation messages. An agent receiving `"blast_radius 12 > 6"` cannot replan
from it. An agent receiving *the feasible region plus a minimal repair* can.

```python
@dataclass(frozen=True)
class RefusalReflection:
    plan_id: PlanId
    stage_id: uuid.UUID
    diff_hash: str                          # what was measured
    chain_head: str                         # tamper-evident provenance
    policy_epoch: str                       # which thresholds decided this (§3.2)
    measured: MeasurementSummary            # what the substrate actually did
    stated: StatedSummary                   # what the agent claimed
    constraints: tuple[Constraint, ...]     # the feasible region, declarative
    counterfactuals: tuple[Counterfactual, ...]   # minimal repairs
    replan_grant: Decimal                   # what you may spend trying again
```

**Constraints are declarative, not prose.** `InvariantChecker` gains an
optional `describe() -> tuple[Constraint, ...]`; checkers that do not implement
it degrade to message-only, so this is backward-compatible.

```python
Constraint(invariant="blast_radius", kind=UPPER_BOUND,
           metric="mutations", limit=6, observed=12, scope="plan")

Constraint(invariant="tenant_isolation", kind=SET_CARDINALITY,
           metric="tenants", limit=1, observed=4,
           members=("acme-pay", "globex", "initech", "northwind"))

Constraint(invariant="tenant_drawdown_guard", kind=RATIO_FLOOR,
           metric="accounts.balance_cents", limit="-0.30",
           observed="-0.998", group="acme-pay")
```

That is a constraint system an agent can solve against, not a log line.

### 2.2 Counterfactuals: the minimal repair, computed for free

Given the measured diff and the violated constraints, compute the
**minimum-cardinality set of effects whose removal makes the plan admissible.**

In general this is a minimal-correction-set problem and NP-hard. Here it is
cheap, for two reasons that are properties of this design rather than luck:

1. **Monotonicity.** Removing an effect never increases blast radius, never
   increases tenant count, never deepens a drawdown. The admissible region is
   downward-closed, so a deletion-based (QuickXplain-style) search finds a
   minimal correction in `O(k · log n)` checker evaluations rather than `2ⁿ`.
2. **Re-evaluation is free.** Checkers are pure functions of `(plan, diff)`
   with no I/O — this is already enforced by the protocol. The diff is already
   in memory. **The search touches the database zero times.**

The one substrate change required: attribute row deltas to the effect that
caused them. No schema change is needed — the engine applies effects one at a
time, so it snapshots the capture-table row count before and after each
`apply()` and attributes the delta. `O(1)` per effect.

```python
Counterfactual(
    drop_effects=("eff-3f2a",),
    residual=MeasurementSummary(mutations=3, tenants=1, drawdown="-0.004"),
    satisfies=True,
    rationale="tenant_isolation, tenant_drawdown_guard, blast_radius all clear",
)
```

An agent that receives this can replan in one turn without re-deriving the
plan from scratch — and without another round-trip through the database.

### 2.3 Shadow branching: speculative execution, verified feasible

**This requires no new substrate.** SQLite `SAVEPOINT` nests inside the open
stage, and — measured against the shipped capture triggers — a
`ROLLBACK TO` unwinds the capture rows along with the data:

```
stage open              rows=300.0  capture=0
branch A applied        rows=201.0  capture=1   <- measurable
branch A discarded      rows=300.0  capture=0   <- capture unwound too
branch B applied        rows=290.0  capture=1
branch B promoted       rows=290.0  capture=1   <- survives into the stage
stage aborted           rows=300.0  capture=0
```

So a branch is **applied for real, measured for real, and discarded for real** —
which is exactly the escrow thesis, one level down.

```
              ┌──── discard ────┐
              │                 ▼
STAGED ──fork──► BRANCHED ──measure──► BRANCH_MEASURED ──promote──► STAGED
                                                                      │
                                                          adjudicate  ▼
                                                        VERIFIED ──► COMMITTED
```

Three invariants preserve the v0.1 guarantee:

1. **A branch can never commit.** Only the stage commits, and only through
   adjudication. The property "no path from `STAGED` to `COMMITTED` skips
   adjudication" is untouched; branches sit strictly *below* the commit gate.
2. **Adjudication is always over the full stage measurement at commit time.**
   A branch's measurement is a *preview*, advisory only. Promoting a branch
   does not pre-authorise anything.
3. **Branches are recorded.** New chain record types `BRANCH_OPENED`,
   `BRANCH_DISCARDED`, `BRANCH_PROMOTED`. A speculative branch touches real
   data; if it were unrecorded, v0.2 would have created an un-audited
   execution channel — the precise thing interlock exists to prevent.

```python
with runtime.stage(plan) as stage:            # opens; does not commit
    for candidate in hypotheses:
        with stage.branch() as b:             # SAVEPOINT
            b.apply(candidate)
            preview = b.measure()             # real diff, advisory verdict
            if preview.admissible:
                b.promote(); break
    result = stage.commit()                   # one adjudication, then commit
```

**Honest cost:** a stage holds write locks for its whole life, and branches
extend that. `max_stage_seconds` still bounds it and `max_branches` is added.
Shadow branching is for sub-second hypothesis tests, **not** for human review —
the same rule the README already states for staged plans.

---

## 3. AI-Native Boundary Intelligence

### 3.1 The rule that makes this safe

Interlock's README already states the correct principle for checkers:

> Where a judgment genuinely needs a model, the model is a **sensor** whose
> output is passed in at configuration time, never consulted from inside
> `check`.

v0.2 generalises that one sentence into the whole architecture. Models never
decide. Models **propose parameters**. Parameters are installed at transaction
boundaries as versioned artifacts.

### 3.2 The membrane: `PolicyEpoch`

```python
@dataclass(frozen=True)
class PolicyEpoch:
    epoch: int
    parent_hash: str                      # hash-chained, like everything else
    thresholds: Mapping[str, str]         # checker name -> serialised parameter
    derived_from: EvidenceRef             # corpus, model, run id, sample size
    proposer: str                         # "drift-detector:v3" | "operator:alice"
    approved_by: str | None               # required for loosening (see below)
    activated_at: datetime
    epoch_hash: str
```

Four rules:

1. **Every `Verdict` records the `epoch_hash` it was decided under.** Replay is
   therefore exact: `(chain, epoch) → identical verdict`, forever. Determinism
   is not weakened by learned parameters; it is *indexed* by them.
2. **Epochs are append-only and hash-chained**, reusing the machinery that
   already exists.
3. **A model may propose an epoch. A model may not activate one.**
4. **The gate is asymmetric — this is the load-bearing safety property:**

   | Direction | Gate |
   |---|---|
   | **Tightening** a blocking threshold | may auto-activate within a bounded delta |
   | **Loosening** a blocking threshold | requires a human signature, always |
   | Changing a **forecast-only** parameter (e.g. `q`) | may auto-activate freely |

   Loosening is the only direction that can cause harm, so it is the only
   direction that requires a human. Forecast parameters affect holds, and holds
   are conservative by construction, so mis-tuning them cannot breach an
   envelope — only mis-size a reservation.

### 3.3 Three concrete sensors

**(a) Trajectory drift detector — tightens admission.**
`ToolCall.shingles` is already a feature vector; upgrade to embeddings.
Maintain a reference distribution over *admitted* plans and run a two-sample
test (MMD / energy distance) against a sliding window. Drift means the traffic
mix moved, which is exactly why Part A found that a tuned constant does not
transfer. Proposes tightened thresholds; may auto-activate.

**(b) Offline SLM judge over refusals — recommends loosening.**
Every `RefusalReflection` is a labelled example, already hash-chained. An SLM
scores each: true positive (genuine overreach) or false positive (legitimate
work blocked). An elevated per-checker FP rate is evidence for relaxation —
surfaced as a **recommendation to a human**, never auto-applied, because it
loosens.

**(c) Cache-survival estimator — tunes forecasts.**
Observed `cache_read_input_tokens` versus the prefix tree's prediction is a
free, continuously generated supervised regression target for `q`. Auto-tunes,
because it touches only forecasting.

### 3.4 Isolating inference from the write lock

Three mechanisms, two of which already exist and are proven:

1. **Off-thread, bounded queue, shed on saturation.** Exactly the shipped
   Tier-2 design: a daemon worker drains a bounded queue, the agent thread
   never waits, verdicts latch and are enforced on the *next* call, and a
   saturated queue drops samples rather than applying backpressure.
2. **Read-only ledger attachment.** `BudgetManager.open_sqlite(read_only=True)`
   takes no advisory lock and can attach while the governor is writing. The
   Control Plane uses this handle exclusively and is structurally incapable of
   blocking the Data Plane.
3. **A CI gate, not a convention.** Checkers are pure functions of frozen
   dataclasses. Run the checker suite under a test-time `socket` monkeypatch
   that raises on any connection attempt. A checker that tries to call a model
   fails the build. This costs nothing at runtime and converts "please do not
   put inference on the write path" from a review comment into a gate — the
   same move as the zero-drift README gate shipped in v0.1.1.

---

## 4. Algorithmic State Recovery: the "What Then?" Protocol

Part B of `ARCHITECTURE.md` is the design brief. This section is the
implementation.

### 4.1 The Merkle prefix tree is a Merkle Mountain Range

Not a balanced Merkle tree. A conversation with a stateless Messages API is
**strictly append-only**, and a classic tree over a fixed-size array must be
rebuilt whenever `n` changes. A **Merkle Mountain Range** gives:

* `O(1)` amortised append,
* `O(log n)` inclusion proofs,
* and the property that actually matters: **its peak list is a commitment to
  every prefix at power-of-two boundaries**, so two conversations sharing a
  prefix share peaks.

This is the standard structure for append-only logs (Certificate Transparency
uses it) and it is the right one here.

```
leaf_i   = H(salt ‖ i ‖ canonical_wire_bytes(message_i))
```

Salted per trajectory, which answers B.7's checkpoint-privacy question: a bare
root plus a guessed message set is a confirmation oracle; a per-trajectory salt
closes it, exactly as it already does for cognitive fingerprints.

```
shared_prefix_len(A, B) = largest k with MMR_root_k(A) == MMR_root_k(B)
```

computed in `O(log n)` by binary search over the peak lists.

**The dual use, made exact:**

```
resume_legal(ckpt, live)   ⟺   shared_prefix_len(ckpt, live) ≥ ckpt.n
cached_tokens(live)         =   token_prefix[ max breakpoint ≤ shared_prefix_len ]
```

The second line is the subtle one. The provider's cache boundary is the
`cache_control` **breakpoint**, not an arbitrary message index, so the MMR
annotates breakpoint positions and carries cumulative token counts at each.
That turns cache prediction from an estimate into an exact lookup.

### 4.2 `EntryType.CHECKPOINT`

A new, **zero-value** ledger entry type.

```python
CheckpointPayload(
    trajectory_id: str,
    scope_id: str,
    mmr_root: str,
    n_messages: int,
    breakpoints: tuple[int, ...],          # cache_control positions
    token_prefix: tuple[int, ...],         # cumulative tokens at each breakpoint
    cache_namespace: tuple[str, str, str], # (model_id, tool_set_hash, system_hash)
    thinking_bound: bool,                  # preserved-thinking model?
    settled_to_date: Decimal,
    ledger_head: str,
)
```

It stores a **root, never the messages** — preserving the existing privacy
posture (`retain_arguments=False` is already the default; the ledger records
money and structure, not transcripts).

**Conservation is untouched.** A checkpoint is zero-value and posts no balanced
pair, so `Σ(balances) + holds + spent − reversals == funded` holds unchanged
and `verify_conservation()` keeps its exact present meaning. B.5's constraint —
*no new money primitive* — is satisfied.

> **Free side effect worth taking.** The README notes that AgentGov has no
> zero-value entry able to carry a memo, which is why interlock's reverse
> anchor must ride on a real `authorize`/`capture` pair and cost money
> (`settle_cost`). A zero-value `CHECKPOINT` entry removes that tax: interlock
> can reverse-anchor for free. One new entry type closes two problems.

### 4.3 The intervention ladder, and a correction to Part B

Part B proposes `r* = argmax_r (p_r · V) / E[C_r]` and calls it
"Gittins-index-flavoured." **The Gittins framing overstates the problem.**
Gittins indices are optimal for independent, *replayable* arms under
discounting. Part B's own rules say the opposite: escalation is **monotone and
latched**, and each rung may be attempted **once**. With a fixed order and
single-attempt arms, this is not a bandit.

It is a **finite-horizon optimal-stopping problem over 7 states**, and it has
an *exact* solution by backward induction:

```
W(7)  = 0                                        # past the last rung: halt
W(r)  = max( 0 ,  p_r·V − E[C_r] + (1 − p_r)·W(r+1) )      subject to E[C_r] ≤ envelope_r
take rung r  ⟺  W(r) > 0  and  r is the current rung
```

Seven states, closed form, microseconds, fully deterministic given
`(p, C, V, envelope)`. No bandit machinery, no regret bounds, no exploration
schedule. **This is a simplification of Part B, not an elaboration of it** —
and it is the version that can live in the Data Plane.

(If the order were *not* fixed — if rungs could be chosen freely — the correct
tool would be Weitzman's Pandora's-Box rule, which is also exactly optimal and
`O(n log n)`. It is worth noting only to record why it is unnecessary here:
the ordering is already pinned by cache-invalidation cost, per B.1.)

`E[C_r]` is now computable rather than notional, because §1 gives the
cache-aware cost of each rung and §4.1 gives the prefix each rung preserves:

| # | Rung | Prefix preserved | `E[C_r]` |
|---|---|---|---|
| 0 | Observe-only | all | 0 |
| 1 | Turn-scoped operator directive | all | `r·L + i·δ` |
| 2 | Effort modulation | all (per-message channel) / none | `r·L + i·δ` or full rebuild |
| 3 | Task-budget injection | all | `r·L + i·δ` |
| 4 | Tool-surface restriction | **none** — tools render first | `w·P` |
| 5 | Model re-route | **none** — caches are model-scoped | `w′·P + o′·Θ_replay` |
| 6 | Graceful degradation | all | `r·L + i·δ` |

### 4.4 The stopping rule, made statistically honest

Part B proposes treating cumulative novelty as a supermartingale. The
implementation detail that matters: **we peek at every call**, so a fixed-`n`
hypothesis test is invalid — repeated looks inflate the false-positive rate.

Use an **anytime-valid confidence sequence** (empirical-Bernstein) on the
running mean of the novelty increment `ΔN_k`:

```
trip  iff   UCB_t( mean ΔN )  ≤  0      at level α
```

Anytime-valid means the guarantee holds under arbitrary optional stopping, so
continuous monitoring is sound by construction. The update is `O(1)`, it is
deterministic, and — as Part B hoped — it does **not** lean on a tuned constant
the way the Part A threshold does. It leans on `α`, which is a stated error
rate rather than a fitted number.

B.7 correctly flags that the supermartingale claim is a modelling assumption
and may not survive live validation. The confidence sequence is the right
instrument *for testing that claim*, not a way of assuming it.

### 4.5 Recovery is governed by the mechanism it is recovering

Per B.5, and requiring no new safety argument: recovery runs in a child scope
`{scope}/recovery`, delegated from the tripped scope's parent with an explicit
grant. The budget-DAG invariant — no descendant may spend or re-delegate more
than its ancestors granted, at any depth — already bounds a recursive recovery
storm exactly as it bounds a recursive agent.

Each rung attempt is an `authorize`/`capture` pair with an outcome observable
one turn later. That makes every recovery attempt a **labelled training example
for `p_r`**, generated as a byproduct of normal operation, hash-chained and
tamper-evident. `p_r` is estimated in the Control Plane and installed as a
`PolicyEpoch`; the Data Plane only ever reads a frozen table.

---

# Part II — Component Placement

The partition is not stylistic. It is the contract that preserves determinism.

### Data Plane — synchronous, deterministic, holds the lock

| Component | Complexity | Budget |
|---|---|---|
| Ledger `authorize` / `capture` / post | O(1) under one mutex | existing: 0.062 ms in-memory, 0.613 ms SQLite mean |
| Checker evaluation | pure, no I/O (CI-enforced) | existing: Tier-1 77 µs mean / 122 µs p99 |
| MMR append + prefix compare | O(1) amortised / O(log n) | ≤ 10 µs / ≤ 5 µs |
| Cache-aware hold (`ρ(q)`, `H_floor`, `H_contingent`) | arithmetic over frozen params | ≤ 5 µs |
| Ladder backward induction | 7-state DP over frozen `(p, C)` | ≤ 20 µs |
| Confidence-sequence update | O(1) | ≤ 5 µs |
| Escrow stage / branch / adjudicate / commit | existing | existing |
| Counterfactual search | O(k log n) checker evals, zero I/O | ≤ 2 ms, **refusal path only** |

Every row is a pure function of frozen inputs. Nothing in this column performs
inference, opens a socket, or reads a clock that affects a verdict.

### Control Plane — asynchronous, probabilistic, never holds the lock

| Component | Attachment | Output |
|---|---|---|
| Trajectory embedding + drift detection | bounded queue, off-thread | proposed epoch (tightening) |
| SLM judge over refusals | batch, offline | recommendation (loosening → human) |
| `p_r` posterior estimation | batch over chain | proposed epoch (ladder table) |
| Cache-survival `q` regression | batch over ledger | proposed epoch (forecast-only) |

Attachment is exclusively via `BudgetManager.open_sqlite(read_only=True)`,
which takes no advisory lock. The Control Plane is *structurally* unable to
block the Data Plane — not by discipline, but because it holds a handle that
cannot write.

### The membrane

```
   Control Plane  ──proposes──►  PolicyEpoch  ──[signed · chained · asymmetric gate]──►  Data Plane
                                      │
                                      └── every Verdict cites epoch_hash ⇒ exact replay
```

**One sentence for the auditor:** *a model has never decided anything in this
system; it has only ever proposed a number, and every number is signed,
versioned, and attributable to the evidence that produced it.*

---

# Part III — Enterprise Diligence Defense

### What is actually defensible

**1. Co-residency of money and trajectory, on one clock, in one process.**
The recovery decision rule is a function of the ledger *and* the cognitive
trajectory. An agent framework has the trajectory and not the budget; a FinOps
platform has the budget and not the trajectory. Neither can evaluate *"is
another $0.40 likely to finish this?"* This cannot be assembled from two
vendors, because the join is per-call and synchronous.

**2. One structure, load-bearing in four places.** The prefix tree answers
resume legality, cache pricing, speculative reservation, and refusal
provenance. A competitor bolting on cache-aware pricing gets one of the four.
The moat is the structure, not any feature built on it — and the coupling was
not designed, it was discovered (cache residency and resume legality are
literally the same question).

**3. Determinism under AI tuning is a compliance artifact.** For a regulated
buyer, "our AI tunes the thresholds" is a liability unless every verdict is
replayable. `PolicyEpoch` lets you answer, for any historical refusal: which
parameters decided it, who proposed them, from what evidence, and who approved
the change. That is precisely what a model-risk-management function asks for.
A competitor who puts a model *on* the write path cannot answer it at all —
and cannot retrofit the answer without rebuilding their core loop.

**4. A flywheel with zero collection cost.** `p_r`, `q`, and per-checker
false-positive rates are byproducts of normal operation, already hash-chained
and tamper-evident. The training corpus **is** the audit log. There is no
separate telemetry pipeline to build, and no customer to persuade about data
collection, because the data is the compliance record they already wanted.

**5. Write-path position.** Interlock requires write credentials inside the
deployment. That integration happens once. The position is earned rather than
asserted: it is the only place the injected-instruction failure can be caught,
because the instruction arrives inside a tool result after every provider-side
filter has run, and the agent executing it is fully authorized.

### What will be attacked in diligence, and the honest answer

A defense that hides these fails the diligence it is written for.

| Challenge | Honest position |
|---|---|
| **"Providers will ship cache-aware billing and erode §1."** | Likely, in part. But the prefix tree is still required for resume legality, and `q*` is a *deployment* decision (where to put breakpoints) that a provider API cannot make for you. |
| **"SQLite single-writer caps you at ~1,600 calls/sec."** | True and measured. `PersistenceStore` is the declared seam and it is **unbuilt**. This is the real scaling limit and should be resourced before it is sold. |
| **"The supermartingale assumption may be false."** | B.7 already says so. §4.4 specifies the instrument for *testing* it. If it fails, the ladder still works — it loses one stopping criterion, not the architecture. |
| **"FK cascades still escape the measurement."** | True, documented, tested as a known gap. The v0.1.1 authorizer closes statement-level escapes; cascades execute internally and are not prepared, so they are neither denied nor measured. This is the last hole in the boundary and it is not closed by anything in this document. |
| **"`V` (value of completion) is your input, not a derived quantity."** | Correct, and B.7 flags it. It is a policy input with a default. The rule is sensitive to it, and we should say so rather than imply the system infers business value. |
| **"Cold start: `p_r` is a guess at launch."** | Yes. A hand-specified prior ordered by the cache-cost table is the v0.2 stand-in. It is a guess that becomes a posterior with volume, and the ordering it starts from is derived from provider semantics rather than invented. |

### Sequencing

Each phase is independently shippable and independently valuable.

| Phase | Contents | Unlocks |
|---|---|---|
| **2.0** | MMR + `EntryType.CHECKPOINT` + cache-aware `ModelPricing` | §1 pricing, free reverse anchors, resume proofs |
| **2.1** | `RefusalReflection` + counterfactuals + `Constraint.describe()` | agent self-healing; generates the SLM corpus |
| **2.2** | `PolicyEpoch` + read-only Control Plane + the socket CI gate | AI tuning with replayable determinism |
| **2.3** | Shadow branching (`SAVEPOINT`) | speculative execution |
| **2.4** | Ladder + backward induction + confidence sequence | the "What Then?" protocol |

2.0 is the foundation and should not be reordered: §1, §2 and §4 all read from
the prefix tree.

### The one thing not in this document

`PersistenceStore` on Postgres. v0.2 makes a single-process governor
dramatically smarter; it does not make it a fleet. Everything here is
compatible with that work and none of it substitutes for it.
