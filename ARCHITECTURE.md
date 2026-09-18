# AgentGov Architecture

A technical note in two parts.

**Part A** documents the *simulation gap*: why a cognitive breaker that passes a
complete offline test suite can be silently inert against a real provider. It
records what we measured when we ran ours against the live Anthropic API for the
first time, and why the calibration harness that came out of it is more durable
than the constant it produced.

**Part B** is the v0.2 design brief: what should happen after a breaker trips,
given that a halted agent has protected the budget and not finished the task.

Part A describes shipped, measured behaviour. Part B is a roadmap and contains
no implementation.

---

# Part A: The Simulation Gap

## A.1 The thesis

A financial breaker is easy to test offline, because money is the same number
whether the model is real or simulated. `$0.023` is `$0.023`. Every accounting
invariant AgentGov claims is fully provable against `DummyLLM`: no
double-spend under 64 contending threads, conservation of value, an unbroken
SHA-256 chain. It should be. A deterministic backend is the only way to prove a
race is absent rather than merely unobserved.

A **cognitive** breaker is not like that. It is a statistical detector whose
input distribution is *model output*. Simulated model output and real model
output are different distributions. That difference is not a detail. It
inverted our detector's behaviour completely.

> A detector calibrated on a simulator does not degrade gracefully in
> production. It goes silently off. There is no error, no exception, no failed
> assertion: the loop simply runs, and the component whose entire job was to
> notice reports nothing.

We shipped v0.1 with 316 passing tests and a cognitive breaker that, against the
live API, detected **0 of 4** thrashing trajectories.

## A.2 Failure mode 1: envelope dominance (structural)

The near-duplicate detector compares character-trigram Jaccard similarity over
a canonical rendering of each call and its result. For arguments this is sound:
tool-call arguments are short, structured, and genuinely near-identical when an
agent is thrashing.

For *results* it was not. Rendering an `anthropic.types.Message` through a
JSON canonicaliser falls back to `repr`, which produces:

```
Message(id='msg_011Cf6W7BbRTCgCKmQZcBj41', container=None,
        content=[TextBlock(citations=None, text="I don't have access to …",
        type='text')], model='claude-haiku-4-5-20251001', role='assistant',
        stop_reason='max_tokens', type='message',
        usage=Usage(input_tokens=18, output_tokens=128, …))
```

Every response from that SDK shares that scaffolding. Under a 1024-character
truncation bound, a substantial fraction of the compared trigrams were
`Message(id=`, `TextBlock(citations=None`, `type='text'`, `role='assistant'`,
`usage=Usage(`. The metric was largely measuring *"are these both Anthropic
Message objects?"*

Measured on live traffic:

| Comparison | Whole `repr` | Text extracted |
|---|---|---|
| Thrashing pair (min) | 0.5796 | 0.3866 |
| Genuinely progressing pair (max) | 0.4832 | 0.2139 |
| **Completely unrelated responses (max)** | **0.4198** | 0.2661 |
| **Separation, thrash vs. progress** | **1.20x** | **1.81x** |

Two responses about entirely different subjects, from different models, scored
**0.42**. Two genuinely progressing steps scored **0.48**. There was no usable
signal. Worse, the threshold was implicitly a function of how verbose the
vendor's `__repr__` happened to be: an SDK release that added a field to `Usage`
would have moved our safety threshold.

The fix (`extract_result_text`, shipped) pulls the prose out before shingling,
duck-typed across the Anthropic Messages shape, the LangChain shape, mappings
and bare strings, with no provider import and a `None` fallback that preserves
prior behaviour for shapes it does not recognise.

**The general lesson:** when a detector consumes a rich object from someone
else's library, decide deliberately what part of it carries signal. A
canonicaliser written for *arguments* is not automatically correct for
*results*, and the failure is silent in both directions.

## A.3 Failure mode 2: prose entropy (statistical)

The second defect was the threshold itself, and it is the more interesting one.

`result_similarity_threshold` existed to separate two cases that look identical
on their inputs:

- **Thrashing.** Near-identical inputs, near-identical outputs. Stop it.
- **Pagination / iteration.** Near-identical inputs, genuinely *different*
  outputs. Leave it alone.

Calibrated at `0.70` against `DummyLLM`. `DummyLLM` emits templated
completions, so two of its outputs share most of their characters and comfortably
clear 0.70 when they should.

Real model prose does not behave that way. These four live Haiku answers are
*semantically the same non-answer*:

```
"I don't have access to specific company documents or databases to retrieve…"
"I don't have access to any specific company documents, databases, or files…"
"I don't have access to specific business documents or databases, so I can't…"
"I don't have access to real-time data or the ability to browse the internet…"
```

Their pairwise trigram similarity is **0.39–0.48**. Natural-language paraphrase
destroys character-level overlap while preserving meaning. A threshold of 0.70
therefore rejected every genuine match, the streak never accumulated, and the
detector never fired.

**Character-trigram Jaccard is a reasonable proxy for "is this the same
request?" and a poor proxy for "is this the same answer?"** Those two facts do
not have to share a constant, and in v0.1 they did.

## A.4 Failure mode 3: the overlap, and why single-pair thresholds cannot work

The obvious fix is to lower the number. Our first estimate, from five samples,
was `0.30`.

That estimate was right by luck and wrong by method. Widening to a
36-pair corpus across three traffic families showed the real picture:

| Family | n | min | median | max | reaches the 0.70 input gate |
|---|---|---|---|---|---|
| Thrashing | 12 | 0.3187 | 0.5281 | 0.6606 | **12/12** (inputs 0.88–0.97) |
| Paginating | 12 | 0.1304 | 0.2693 | **0.8800** | **12/12** (inputs up to 0.96) |
| Progressing | 12 | 0.0758 | 0.2188 | 0.4253 | **0/12** (inputs max 0.5739) |

Two findings fall out, and both changed the design.

**Finding 1: multi-step workflows were never the risk.** Genuinely progressing
work does not clear the *primary* input gate at all. 0/12 pairs reached 0.70,
topping out at 0.57. It never reaches the result veto, so it cannot be
false-positived by it. Our original "progressing" control was measuring
something the mechanism never sees. The only traffic that reaches the result
comparison is traffic with near-duplicate inputs, which means the veto's one
real job is **thrashing vs. pagination**.

**Finding 2: on that job, the per-pair distributions genuinely overlap.**
Pagination's maximum of 0.8800, two Apollo-program facts sharing a framing
sentence, exceeds *every single thrashing pair*. No single-pair threshold
separates these two families. A cleverer constant does not exist.

What separates them is the shape of the sequence, not any individual pair.
Pagination's similarity is **erratic**: one framing-heavy pair, then divergence.
Thrashing's stays **persistently elevated**. The detector already required
`max_similar_streak` consecutive stagnant pairs. The streak requirement, not
the threshold, is doing the discriminating.

Sweeping the actual rule over the corpus:

```
   thr | thrash detected | paginate FP | progress FP
  -----+-----------------+-------------+-------------
  0.20 |             4/4 |         1/4 |         0/4
  0.25 |             4/4 |         0/4 |         0/4   <- full detection, zero FP
  0.30 |             4/4 |         0/4 |         0/4   <- full detection, zero FP
  0.35 |             3/4 |         0/4 |         0/4
  0.40 |             3/4 |         0/4 |         0/4
  0.45 |             2/4 |         0/4 |         0/4
  0.50 |             2/4 |         0/4 |         0/4
  0.55 |             0/4 |         0/4 |         0/4
  0.70 |             0/4 |         0/4 |         0/4   <- shipped in v0.1
```

`0.25`–`0.30` catches everything with zero false positives; `0.20` begins
false-positiving on pagination; `0.55` and above detects nothing. The shipped
default is now **`0.30`**, the top of the clean band. A higher result threshold
makes "these results agree" harder to assert, which is the conservative
direction for a rule that halts somebody's agent.

## A.5 Why the constant does not transfer

`0.30` is one line. Anyone can copy it in ten seconds, and copying it is close
to worthless, because the constant is only valid for the conditions it was
measured under:

- **the model.** Haiku's phrasing entropy is not Opus's.
- **the SDK version.** Response shape determines what gets compared.
- **the shingle size and truncation bound.** Change either and the distribution
  moves.
- **the streak length.** The sweep is a function of `max_similar_streak`.
- **the traffic mix.** A customer whose agents paginate heavily sits at a
  different operating point than one whose agents mostly retry.

What actually transfers is the **Empirical Calibration Harness**:

1. **A three-family corpus design.** Thrashing, pagination, and progressing
   work, generated against the live model rather than hand-written. Getting the
   families right is the hard part. Our first attempt used the wrong control
   and would have produced a confidently wrong threshold.
2. **Gate-aware analysis.** Measure which families reach a given stage of the
   detector before calibrating that stage. Most of the apparent
   false-positive risk evaporated once we checked.
3. **Sweeping the real rule, not the pairwise statistic.** The per-pair
   distributions overlap; the rule's does not. Calibrating the statistic
   instead of the rule is how you arrive at a number that is both
   defensible-sounding and wrong.
4. **Reproducibility as an artifact.** `scripts/calibrate_result_threshold.py`
   is committed, runs for about three cents, and prints the table above. The
   constant in `cognitive.py` cites it.

The harness has to be re-run per model, per SDK bump, per workload mix. Copying
the constant out of this file gets you a number calibrated for Haiku on
`anthropic` 1.6.0 with a 3-shingle window and a streak of 3. Change any of those
and re-run the sweep.

This applies to any detector with a tuned threshold in it. A threshold that has
stopped firing produces no error and no alert, so the only way to find out is to
measure it again against live traffic.

## A.6 Honest limits of Part A

- The corpus is 36 pairs across 12 trajectories on one model. It is enough to
  reject `0.70` decisively and to establish a clean band; it is not enough to
  claim `0.30` is optimal to two decimal places.
- Templated tool output (e.g. `record-1-N` page rows) still scores high enough
  to look stagnant. That limitation is unchanged, pinned by a test, and
  remedied with `exempt_tools`.
- The result veto only applies where results are recorded. Without them,
  input similarity stands alone and pagination must be exempted explicitly.
- Nothing here has been calibrated against non-Anthropic providers.

---

# Part B: The "What Then?" Protocol (v0.2 State Recovery Roadmap)

> **Status: design brief. No implementation. v0.1 is locked.**

## B.0 The reframing

v0.1 minimises spend on failure. That is not the objective anyone has. The
objective is to finish the task under a spend ceiling. Halting beats a runaway
and is still a loss: the agent stops, the budget survives, the work is not done,
and a human has to notice, diagnose and restart it. That human minute usually
costs more than the dollars the halt saved.

Written out, the objective is constrained completion:

```
    maximize   P(task completes successfully)
    subject to E[total spend] ≤ envelope
```

Under that objective, "always halt" is the trivial policy, and it is optimal
only when `P(complete | continue) = 0`. The cognitive breaker's own telemetry is
what tells us that probability is low. Low is not zero. The breaker currently
discards the distinction.

**v0.2's thesis: a breaker trip should be a state transition in a priced
decision process, not a terminal event.**

Recovery needs two inputs that normally live in different components:

- **the money**: what has been spent, what remains, at what rate, priced exactly;
- **the progress signal**: the similarity history, the novelty decay, the
  call-graph shape.

AgentGov holds both, in one process, on one clock. An agent framework has the
trajectory and not the budget; a cost dashboard has the budget and not the
trajectory. Neither can evaluate "is another $0.40 likely to finish this?"

## B.1 Design constraints the live SDK work imposed

The naive recovery tactics are all actively harmful, and each is harmful for a
reason that only shows up once you have read the provider's semantics closely.
These constraints shape everything below.

| Naive tactic | Why it backfires |
|---|---|
| **Retry the call** | Precisely what the breaker exists to stop. |
| **Rewrite the prompt / edit history** | Prompt caching is a **prefix match**: any byte changed anywhere in the prefix invalidates everything after it. A rewrite can cost more than the loop it replaces. On models enforcing *preserved thinking*, editing earlier turns invalidates thinking blocks and can return a hard `400`. |
| **Downshift to a cheaper model** | Caches are **model-scoped**. A downshift forfeits the entire cached prefix, and thinking blocks are bound to the producing model and are silently dropped. A "cheaper" model that needs three more turns on a cold cache is not cheaper. |
| **Just raise `max_tokens`** | Treats a reasoning failure as a truncation failure. Usually buys a longer version of the same loop. |

Three principles follow, and they are strong constraints rather than preferences:

1. **Append-only.** A recovery action may add to the conversation. It may not
   rewrite it. This preserves the cache prefix *and* sidesteps
   preserved-thinking invalidation, which happen to be the same discipline.
2. **Cache-aware pricing.** The unit of account is **cost per completed task**,
   not cost per call. An action that invalidates a 40k-token cached prefix has
   already spent the cache-rebuild cost whether or not it succeeds, and that
   must be in the estimate before the action is chosen.
3. **Bounded by construction.** Recovery spends money, so recovery must itself
   be governed, by the same mechanism rather than a special case.

## B.2 Cryptographic state checkpointing

**A new ledger entry type, `CHECKPOINT`, in the existing hash chain.**

The chain already proves *what was spent*. A checkpoint extends it to prove
*what state that spend produced*. Anchored to the ledger head hash at the moment
of the trip, it makes a claim that is currently unprovable:

> At sequence *n*, with exactly `$X` settled against scope *S*, the conversation
> was in exactly this state. Here is a proof that the run you resumed is a
> legal continuation of it.

The design choice that matters: **a checkpoint stores a Merkle root over the
message array, never the messages.** Two reasons, one of them a genuine
architectural opportunity.

The defensive reason is AgentGov's existing privacy posture: the ledger records
money and structure and deliberately not prompt content
(`retain_arguments=False` is already the default). A checkpoint that inlined the
conversation would turn the audit log into a transcript archive.

The opportunity is sharper. Conversations with a stateless Messages API are
**append-only sequences**, so the natural structure is a **Merkle prefix tree**:
each turn extends the root; any earlier state is a prefix; a resumed
conversation can be proven to share a prefix with the checkpointed one in
`O(log n)`.

And prompt caching *is a prefix match*. The same structure that gives a
tamper-evident resume proof also gives an exact predicate for **"will this
resume hit the provider's cache?"** Both questions reduce to "how long is the
shared prefix?" That coupling is the non-obvious part:

```
   shared-prefix length  ──┬──►  resume legality      (is this a valid continuation?)
                           └──►  cache-hit prediction (what will the resume cost?)
```

A recovery planner can therefore price a candidate action *before executing it*:
compute the prefix the action preserves, derive the cached-vs-uncached token
split, and price it at the known cache-read and cache-write rates. AgentGov
already prices cache reads and writes per model. Those rates sit in `PRICING`
today, unused, because nothing needed them until now.

This is a decisive structural advantage over bolting recovery onto a framework:
a framework can retry, but it cannot *prove* what it resumed from, and it cannot
price the resume before paying for it.

## B.3 The intervention ladder

Not one recovery strategy. An ordered menu, cheapest and least invasive first,
every rung append-only.

| # | Rung | Mechanism | Cache cost | Addresses |
|---|---|---|---|---|
| 0 | **Observe-only** | Record the trip, halt, surface it | none | Loops with no plausible recovery |
| 1 | **Turn-scoped operator directive** | A mid-conversation `system` message, scoped to expire after the next user turn | **none. Appended after the cached prefix** | The agent has not noticed it is looping |
| 2 | **Effort modulation** | Raise effort when the loop looks like under-thinking; lower it when it looks like over-elaboration | none on models with a per-message effort channel; full reset otherwise | Mis-calibrated reasoning depth |
| 3 | **Task-budget injection** | Give the model an explicit remaining-token ceiling so it paces and lands rather than being cut off | none | "Ran out of room" rather than "went in circles" |
| 4 | **Tool-surface restriction** | Withdraw the tool the cycle runs through | **high. The tool list renders before everything else, so this invalidates the whole prefix** | Single-tool oscillation |
| 5 | **Model re-route** | Escalate or downshift | **total. Caches are model-scoped; thinking blocks are dropped** | Genuine capability mismatch |
| 6 | **Graceful degradation** | Request the best partial answer plus an explicit statement of what is missing | none | Nothing above worked |

Rung 1 deserves emphasis, because it is both the cheapest rung and the only one
that is safe by construction. The provider exposes a **mid-conversation system
role** that is appended to the message array rather than editing the top-level
system prompt. It therefore (a) preserves the cached prefix exactly, (b) carries
operator authority rather than user authority, and (c) is the channel the vendor
designates as prompt-injection-safe. A directive that names the observed
behaviour concretely:

> *You have issued four near-identical queries for this resource and received
> four equivalent non-answers. The resource is unlikely to be reachable by this
> route. State that conclusion, or take a materially different approach. Do not
> reissue the query.*

That text is generated from the breaker's own evidence. The detector already
computed the streak length, the similarity, and the offending tool name. The
intervention is not a generic nudge. It is a rendering of the verdict that
halted the agent.

**Escalation is monotone and latched.** A trajectory moves down the ladder, never
back up, and each rung may be attempted once. That makes the recovery process
itself provably finite. It cannot become the loop it is trying to fix.

## B.4 The decision rule

With a ladder of actions, a remaining envelope, and a progress signal, "what
then?" becomes a constrained optimal-stopping problem with restarts.

For each rung `r`, two quantities:

- `C_r`, expected cost. Computed from the prefix-preservation analysis in B.2
  and *reserved as an authorization hold before the attempt*, which is
  machinery v0.1 already has.
- `p_r`, the probability the task completes if this rung is taken.

Choose the rung maximising expected value per dollar,

```
    r* = argmax_r  ( p_r · V ) / E[C_r]      subject to  E[C_r] ≤ envelope_remaining
```

where `V` is the value of completion, and halt when no rung clears the bar. This
is Gittins-index-flavoured: each rung is an arm whose payoff is known only
through experience.

**Two pieces make this rigorous rather than decorative.**

**A stopping rule with actual content.** The Tier-2 observer already tracks
novelty decay: the fraction of each call that is vocabulary the trajectory has
never produced before. Treat cumulative novelty as a stochastic process. A
trajectory making genuine progress has positive drift. A thrashing one is, to a
first approximation, a **supermartingale**, meaning its expected future novelty
does not exceed its present value. Under that condition continuing has
non-positive expected information gain, and continuing to *pay* for it has
strictly negative expected value. That converts "the similarity looked high"
into a stopping criterion with a stated model and a falsifiable assumption. It
also makes the threshold question from Part A secondary, because the drift test
does not lean on a tuned constant the same way.

**`p_r` is learned, and the ledger is already the right substrate.** Every
recovery attempt is a ledger transaction with a cost and, one turn later, an
observable outcome. That is a labelled training example, generated as a
byproduct of normal operation, hash-chained and tamper-evident. Over a fleet,
`p_r` becomes an empirical distribution conditioned on the *signature of the
loop*: which detector fired, streak length, tool, model, elapsed spend.

The threshold in Part A is a constant that gets re-derived; `p_r` is a posterior
that sharpens with every recorded trip. Until there is volume it is a flat
prior, which is the cold-start problem in B.7.

## B.5 Keeping recovery honest

Recovery spends money. If that spend is invisible the cure becomes the disease,
so two structural commitments:

**Recovery gets its own scope in the existing budget DAG.** Not a new
mechanism. A child scope delegated from the tripped scope's parent, with an
explicit grant. The DAG invariant already guarantees no descendant may spend or
re-delegate more than its ancestors granted it, at any depth. A recursive
recovery storm is therefore bounded by the same property that bounds a recursive
agent, and requires no new safety argument. This is the payoff for having built
the hierarchy first.

**The conservation identity extends rather than bends.** v0.1 enforces:

```
Σ(scope balances) + outstanding_holds + settled_spend − reversals == funded
```

Recovery spend is settled spend in a child scope, so the identity holds
unchanged, and `verify_conservation()` keeps meaning exactly what it means
today. Reports can attribute cost to recovery by scope, without a second
accounting concept. **No new money primitive is introduced.** That is the
design constraint every part of B.5 is written to satisfy.

## B.6 Prerequisites

Each of these has to hold before the decision rule in B.4 produces a number
worth acting on.

- **Both inputs in one process.** The rule is a function of the ledger *and* the
  cognitive trajectory. With only one of them the rule degenerates to a guess.
- **A calibrated progress signal.** The stopping rule reads the detector's
  novelty history. On an uncalibrated detector it recovers from loops that are
  not there and misses the ones that are. Part A is the prerequisite, not an
  aside.
- **Provider semantics for the ladder ordering.** The rungs are ordered by cache
  and thinking-block invalidation cost (B.1). Order them wrong and recovery
  costs more than the failure it is recovering from.
- **Volume.** `p_r` is estimated from recorded outcomes. Below some number of
  trips it is a prior, not an estimate.

## B.7 Open questions

Stated because they are unresolved, not because they are minor.

- **Cold start.** `p_r` is unknown at launch. A hand-specified prior ordered by
  the cache-cost table is the obvious v0.2 stand-in, and it is a guess.
- **`V` is not ours to set.** The value of completion is the user's, and the
  rule is sensitive to it. It likely has to be a policy input, with a sane
  default, rather than something AgentGov infers.
- **The supermartingale claim needs testing.** It is a modelling assumption
  about novelty decay, not a proven property. It should be validated on a live
  corpus the way the threshold in Part A was, and it may not survive.
- **Not every loop is recoverable.** Some agents are looping because the task is
  impossible. Rung 6 exists for that, but distinguishing "impossible" from
  "needs a different approach" may be beyond any local signal.
- **Intervention text is a trust boundary.** Directives are generated from
  detector evidence, which is derived from model output. Anything derived from
  model output is attacker-influenceable in principle. The operator channel is
  the right primitive precisely because the provider treats it as
  injection-resistant, but the generation path needs its own review.
- **Checkpoint privacy.** Merkle roots leak nothing directly, but a root plus a
  guessed message set is a confirmation oracle. Salting per trajectory is the
  likely answer, as it already is for cognitive fingerprints.

## B.8 Non-goals for v0.2

- Not a general agent framework. AgentGov does not orchestrate; it governs, and
  now advises on recovery.
- Not automatic recovery by default. The first release should surface a
  recommended action and require opt-in to act on it. A governor that silently
  spends more money to fix a problem is not obviously an improvement.
- Not multi-host. That is the `PersistenceStore` work described in the README's
  roadmap, and it is orthogonal.
