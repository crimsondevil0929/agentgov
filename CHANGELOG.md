# Changelog

All notable changes to AgentGov are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
from 1.0.0 onward. Before 1.0.0, minor versions may include breaking changes.

## [Unreleased]

### Fixed

- **A file that is not a SQLite database crashed `agentgov verify` and
  `agentgov inspect` with a traceback.** SQLite reports it as
  `sqlite3.DatabaseError`, the parent of the `OperationalError` the store
  caught. Opening one now raises `StorageError` naming the file, so the
  commands report it and exit 1. A failed writable open now also closes its
  connection.

## [0.1.2] - 2026-09-25

Makes four of v0.1.1's guarantees true. Each was broken in a way that every
verifier passed, and each fix is tested against a reproduction of the break in
[`tests/test_core_guarantees.py`](tests/test_core_guarantees.py).

### Fixed

- **A crash inside `capture()` could return the same hold twice (R1).**
  `capture()` committed the release and the spend, then deleted the open
  authorization in a second transaction. A process killed between the two
  restarted with a released hold behind an open authorization, and the
  documented recovery, `void_stale()`, released it again: on a $1.00 envelope
  with $0.10 spent, $1.40 became available, and every verifier passed. Three
  independent fixes, any one of which stops it:
  - **One operation is one transaction.** `PersistenceStore.commit(batch)`
    writes an operation's entries, topology, breaker events and authorization
    changes in a single SQLite transaction, and memory changes only once it has
    committed. Tested by failing every statement of every operation in turn,
    and by killing a real process at every statement of `capture()`.
  - **A release names its hold.** `AGOV2` entries carry `ref`, the `entry_id`
    of the hold that a `hold_void` releases and a settling `spend` settles,
    inside the hash. The ledger refuses to release a hold that is not open, one
    from another scope, or a different amount, so no caller can release a hold
    twice, including a buggy recovery path.
  - **The tables must agree with the chain.** At open, every open-authorization
    row must name an open hold of the same scope and amount, and every open hold
    must be named. A database that disagrees, including one a v0.1.1 crash left
    behind, is refused with the rows named. `open_sqlite(path, repair=True)` or
    `agentgov repair` rebuilds the tables from the chain. No money moves.
- **Deleting a trip row un-halted a scope; editing `nodes.parent_id` moved a
  scope out from under its halted parent (R2, R6).** Breaker trips and the
  delegation tree lived in tables outside the chain, and `verify_integrity()`
  never compared the two. Trips and resets are now zero-value
  `circuit_tripped` / `circuit_reset` entries, and the tree is derived from the
  `funding` and `allocation` entries. The `nodes` and `control_events` tables
  are caches, checked against the chain at open and by `verify_integrity()`.
- **The third streamed call on a trajectory tripped as an exact repeat (R3).**
  The streaming path fingerprinted a fixed memo string rather than the request,
  so three different prompts looked identical to the loop detector, at
  confidence 1.0. A stream is now observed by the call it carries, and the text
  it produces (up to 64K characters) is recorded as its result, so the
  result-similarity check can tell pagination from thrashing. An opaque thunk is
  checked against the breaker but not recorded as a call.
- **A read-only manager never saw anything written after it opened (R4, this
  side).** New `BudgetManager.refresh()` reads everything committed since, in
  one consistent read, verifies it against the head the view already trusts,
  and applies it all or nothing: balances, tree and breaker state move together
  or not at all. A rewrite under the view, or anything that fails verification,
  raises, and the view then refuses every later refresh. It follows a writer
  that upgrades the schema under it. interlock calls it before every breaker
  check.
- **The 64-worker stress test is no longer timing-dependent.** It asserted
  exactly ten winners, which failed about one run in five: a straggler that
  reaches `authorize()` after two winners settle legitimately wins too. It now
  replays the chain and asserts what must hold however the threads interleave:
  never more than ten holds open at once.

### Added

- `EntryType.CIRCUIT_TRIPPED`, `CIRCUIT_RESET`, `ANCHOR` and `SEAL`: zero-value
  entries with direction `--`, excluded from the money totals.
- `BudgetManager.anchor(scope_id, memo)` commits an external record, such as
  another chain's head, as a zero-value entry. interlock's reverse anchor uses
  it, so it no longer costs a settled spend.
- `BudgetManager.refresh()`, `BudgetManager.repairs`,
  `open_sqlite(..., repair=True)` and `agentgov repair`.
- `LedgerEntry.ref`, `LedgerEntry.version`, `LedgerLine.ref`,
  `ControlEvent.entry_id`.
- `WriteBatch`, `StoreImage` and `StoreDelta`, and on `PersistenceStore`:
  `commit()`, `load()`, `snapshot()`, `rebuild_caches()` and `read_only`.
- `CognitiveBreaker.check()` and `agentgov.streaming.BoundCall`.

### Changed

- **Audit version `AGOV2`.** New entries also hash `ref` and log as
  `AGOV2|...|ref=<uuid>`. Every entry records the version it was written with,
  and an `AGOV1` entry still verifies under the `AGOV1` rules. `AGOV1` entries
  cannot follow `AGOV2` ones.
- **Schema version 2, upgraded in place.** A v0.1.0 or v0.1.1 database gains
  its new columns the first time v0.1.2 opens it for writing, and a migration
  seal (a zero-value `seal` entry carrying a digest of the old, unchained
  breaker events) commits those events into the chain. Opened read-only, it is
  served as it is.
- **`Authorization.authorization_id` is its hold's `entry_id`**, so the chain
  alone links an authorization to its settlement.
- **A trip is one entry.** The call that trips a breaker now leaves one
  zero-value entry; every refused call after it still writes nothing. Entry
  counts in the benchmark and the demos grow by one per trip, and the README's
  recorded benchmark run is re-recorded.
- **Custom `PersistenceStore` implementations need the new methods.** The
  per-row writers (`append_entries`, `upsert_node` and the rest) stay on
  `SqliteStore` but the core no longer calls them.
- **Consistent reads.** A store is opened with one read transaction over every
  table, so a live writer cannot commit between the entries and the tables
  that describe them.
- **The per-entry audit line is only rendered when something listens at
  `INFO`.** Measured in memory, authorize plus capture went from 116 µs to
  110 µs. `verify_integrity()` on 66,000 entries went from 0.61 s to about
  1.0 s: the new pairing and governance checks run in the same single pass.
- **`agentgov verify` names what each check covers**, and `inspect` aligns
  zero-value rows.
- **README badges state only what CI enforces.** The hard-coded test count and
  coverage figure are gone, and a test ties the coverage-floor badge to the
  floor in `ci.yml`.

### Known limitations

- The chain is keyless. Someone who can write the file and compute SHA-256 can
  rewrite it consistently, or truncate its tail, and it still verifies. Only a
  copy of the head kept elsewhere shows that; signed receipts and an external
  witness are planned.

## [0.1.1] - 2026-09-20

Cut so that the two fixes below are available under a version number. They
were correct on `main` and unreleased, which meant a resolver keyed on
`agentgov==0.1.0` could serve a cached wheel built before them while the
README described them in the present tense. A version that does not move when
behaviour does is a supply-chain defect, not a formality.

### Added

- **`BudgetManager.verify_conservation()` and `BudgetManager.verify_chain()`.**
  Both were reachable only as `manager.ledger.verify_conservation()`, while the
  README named them beside `verify_integrity()` as if all three sat on the
  manager. A reader had no way to know that two of the three were a level down.
  Thin pass-throughs, each taking the manager's lock.

### Fixed

- **Dated snapshot identifiers no longer miss the rate card.** The API resolves
  an undated alias to a dated snapshot and reports it back: a request for
  `claude-haiku-4-5` returns `claude-haiku-4-5-20251001`. `PRICING` is keyed
  only on undated aliases, so `pricing_for(response.model)` raised `KeyError`
  for every dated model, and `agentgov.interceptor` documents that an unmetered
  model is an unmetered budget. New `normalize_model_id()` folds a trailing
  `-YYYYMMDD`; `pricing_for()` tries the identifier as given and then folded.
  The same fold now runs in `reconciliation._normalise_model`, where a provider
  invoice reporting the dated form previously failed to match a ledger entry
  recording the alias, making every line of a healthy invoice read as a model
  mismatch and silently deriving no cost at all for a dated line.

- **Settlement prices the model that served, not the one configured.**
  `Interceptor` fixed its rates at construction from the `model` parameter. A
  server-side refusal fallback substitutes a different model mid-request and
  tells the caller only through `response.model`, so the ledger booked a cost
  the provider will never invoice — silently, and in the dangerous direction
  when the fallback is a cheaper tier. `invoke()` and `ainvoke()` now settle
  through `Interceptor.pricing_for_response()`, and `MeteredCall.model_id`
  reports what served. Three carve-outs, each deliberate and tested: an
  explicit `ModelPricing` still wins, because it is an operator override for a
  platform the rate card does not cover; a served model with no published rates
  logs a warning and falls back rather than failing a settled call; and the
  hold is still sized from the configured model, because it is placed before
  the call and cannot know what will serve. Streamed calls keep the configured
  rates — a stream has no single response object to read the served model from,
  and `Interceptor.stream()` says so.

### Fixed

- **`NearDuplicateDetector.result_threshold` default, 0.70 → 0.30.** The
  recalibration below changed `CognitivePolicy.result_similarity_threshold` and
  left the detector's own default at the stub-tuned `0.70`. `CognitiveBreaker`
  passes the policy value in, so the shipped path was correct, but
  `NearDuplicateDetector` is a documented extension point: a caller following
  the README's `detectors=[...]` guidance constructed it directly and got the
  threshold that detected 0 of 4 live thrashing trajectories. No test covered
  the detector's own default; one now pins the two values equal.

### Changed

- **`CONCEPT.md` removed** and pitch/positioning filenames added to
  `.gitignore`. This repository is public; its documentation is engineering
  mechanics.
- **`docs/DEMO_RUNBOOK.md` rewritten** as a command-by-command walkthrough. It
  was a presentation script ("what to say", "the line to land", a question
  bank); the commands, expected output and failure modes are what belongs in
  the repo.
- **`docs/EFFECT_ESCROW_SPEC.md` moved** to the `interlock` repository as
  `docs/ESCROW_SPEC.md`, retargeted from the placeholder name `agentescrow` to
  the shipped package, and given a conformance section stating what `interlock`
  v0.1.0 implements, partially implements and does not implement. It described
  a sibling package and claimed no implementation existed.
- **`ARCHITECTURE.md` A.5 and B.6 retitled** and rewritten to drop competitive
  framing. The technical content (why a threshold does not transfer across
  models, SDK versions and traffic mixes; what the calibration harness has to
  re-run) is unchanged.

### Empirical Optimizations

Everything in 0.1.0 was verified against `DummyLLM`, a deterministic offline
stub. That proves the accounting invariants and proves nothing about the
integration surface. Running the same machinery against the live Anthropic API
for the first time surfaced two defects that no stub-backed test could have
caught, both in the cognitive breaker's result comparison.

- **Compare the answer, not the SDK envelope.** `CognitiveBreaker.record_result()`
  rendered whole response objects through `canonical_arguments()`, which falls
  back to `repr`. For an `anthropic.types.Message` that meant most of the
  compared characters were wrapper boilerplate (`Message(id=…`,
  `TextBlock(citations=None, type='text'…`, `usage=Usage(…)`) shared by every
  response from that SDK. Measured on live traffic, two *completely unrelated*
  answers scored 0.42 similarity while two genuinely progressing ones scored
  0.48: the metric was reading the envelope, and would have drifted with the
  SDK's `__repr__` rather than with meaning. New `agentgov.cognitive.extract_result_text()`
  pulls the prose out first. It is duck-typed across the Anthropic Messages
  shape, the LangChain shape, mappings and bare strings, with no provider
  import. Unfamiliar shapes return `None`, which preserves the previous
  behaviour. Thrashing/progress separation roughly doubled, 1.20x to 1.81x.

- **`CognitivePolicy.result_similarity_threshold` recalibrated, 0.70 → 0.30.**
  The 0.70 default was tuned against the stub's templated completions. Real
  model prose that *means* the same thing shares far fewer character trigrams
  than two renderings of one template, so the veto that distinguishes
  thrashing from pagination was rejecting every genuine match: the inherited
  threshold detected **0 of 4** live thrashing trajectories. The breaker's
  headline feature was inert in production.

  The re-calibration is reproducible (`scripts/calibrate_result_threshold.py`,
  36 measured pairs across thrashing, pagination and genuinely progressing
  traffic) and its finding matters more than the constant: the per-pair
  distributions genuinely **overlap** (thrashing 0.32–0.66, pagination
  0.13–0.88), so no single-pair threshold separates them. The discriminator is
  the *streak* requirement. Pagination's similarity is erratic; thrashing's
  stays persistently elevated. Sweeping the real detector rule, 0.25-0.30
  catches 4/4 thrashing trajectories with zero false positives on either
  control family, while 0.20 begins false-positiving on pagination. 0.30 is
  the conservative end of that band.

- **No change was needed to `PRICING` or to usage extraction.** Both were
  verified rather than assumed: the published rates for `claude-fable-5-1`,
  `claude-opus-5`, `claude-sonnet-5` and `claude-haiku-4-5` already matched,
  and `default_usage_extractor` read live `usage` objects with no
  special-casing, including `stop_reason: max_tokens` truncation and null
  cache fields. Across 445 input and 2,117 output tokens on four price
  tiers, independently re-pricing every settled call from the published rates
  agreed with the ledger to **$0.00000000**.

### Added

- `scripts/generate_real_usage.py`: meters four governed workloads across four
  Anthropic model tiers (`claude-haiku-4-5`, `claude-sonnet-5`,
  `claude-opus-5`, `claude-fable-5-1`) through the official SDK, re-prices every
  call independently, and persists raw response payloads, a cost summary, the
  ledger and the metering journal to timestamped files under
  `benchmarks/live_data/`. It authenticates only from `BENCHMARK_API_KEY` and
  never falls back to `ANTHROPIC_API_KEY` or an `ant auth login` profile, so it
  cannot bill an unintended account. Budget guardrails: an explicit `max_tokens`
  on every call, a $1.50 AgentGov envelope around the whole run, a hardcoded
  four-iteration bound on the runaway loop that holds even if the breaker
  regresses, and a `--dry-run` mode that exercises every path with no network
  and no spend.
- `scripts/calibrate_result_threshold.py`: the reproducible justification for
  `result_similarity_threshold`, sweeping the real detector rule over a live
  three-family corpus.
- `agentgov.cognitive.extract_result_text()`, exported for callers implementing
  a custom `LoopDetector` or `Redactor`.
- `ARCHITECTURE.md`: a technical note in two parts. Part A documents the
  simulation gap: envelope dominance, prose entropy, the measured overlap
  between thrashing and pagination, and why the calibration harness rather than
  the constant is the durable asset. Part B is the v0.2 **State Recovery
  Roadmap**. It covers cryptographic state checkpointing over a Merkle prefix
  tree, whose shared-prefix length answers both "is this resume legal?" and
  "will it hit the provider's cache?". It covers an append-only intervention
  ladder ordered by cache- and thinking-block-invalidation cost. And it covers a
  budgeted stopping rule over the breaker's existing novelty signal. Design
  only. No implementation.
- README: **Known limitations & v0.1 scope**, stating the single-writer boundary
  and its measured ~1,600 calls/sec ceiling, the guardrail-not-sandbox
  enforcement model, the pricing snapshot, and the line between what is proven
  deterministically and what is proven live. README: **Live API metering**, with
  the measured results.

### Changed

- `anthropic` added to the `dev` dependency *group*. Groups are local to this
  repository and absent from the published wheel, so the installed package
  keeps its zero-runtime-dependency guarantee.

## [0.1.0] - 2026-09-14

Initial public release: a runtime spend governor and denial-of-wallet circuit
breaker for autonomous agent fleets, with dual financial and cognitive
enforcement, framework drop-ins, and a FinOps reconciliation engine.

### Added

**Financial ledger and budget governance**

- Append-only, SHA-256 hash-chained, double-entry ledger (`agentgov.core.Ledger`).
  Every economic event is an immutable entry linked to its predecessor;
  `verify_chain()` re-derives the chain and detects any retroactive edit,
  including a tampered balance.
- `BudgetManager`: a hierarchical budget DAG. A root agent's envelope is
  sub-delegated down a tree of scopes, and no descendant can ever spend or
  re-delegate more than its ancestors granted it, at any depth.
- Authorize → hold → capture lifecycle. A call reserves its worst-case cost
  before it runs; the hold is encumbered and invisible to concurrent siblings
  until it settles. That is what makes double-spend structurally impossible
  under concurrency rather than merely unlikely.
- Latching circuit breaker on overdraft, runaway-loop velocity, and budget
  exhaustion. A trip halts the scope and every descendant beneath it until an
  operator explicitly resets it.
- `verify_conservation()`: proves
  `Σ(scope balances) + outstanding_holds + settled_spend − reversals == funded`
  across the whole tree. Money is never created, destroyed, or double-counted.
- Write-through SQLite persistence (`BudgetManager.open_sqlite()`). The ledger,
  topology, control events, and any open authorization survive a process
  restart. Uses only `sqlite3` from the standard library.
- Exclusive advisory locking on the database file. A second process opening
  the same file is refused at open with `ConcurrentGovernorError` naming the
  holding PID, rather than corrupting shared in-memory state. `read_only=True`
  allows safe inspection of a database another process is actively governing.
- `stale_authorizations()` / `void_stale()`: surface and reclaim holds left
  open by a process that died mid-call, as an explicit operator action.
- Redaction hooks and salted digests throughout: raw prompt text is never
  retained by default, only bounded shingle sets and cryptographic digests.

**Cognitive circuit breaker**

- Two-tier loop detection (`agentgov.cognitive`). Tier 1 runs inline and
  deterministic: exact-repeat fingerprinting, Jaccard-shingled near-duplicate
  detection for the "soft loop" (cosmetically different calls that go
  nowhere), and call-graph cycle detection for A→B→A→B oscillation. Tier 2
  runs off-thread: a semantic novelty tracker that never blocks the calling
  agent.
- Measured inline overhead: ~78µs mean, ~89µs p99 per call, roughly 0.005%
  of a real model call.
- Trips share the same actuator as the financial breaker: a cognitive halt
  latches the budget scope and is recorded as a hash-anchored control event
  in the same ledger.

**Interception and dynamic sizing**

- `Interceptor.invoke()` / `ainvoke()`: authorize, execute with no lock held,
  price the response's real token usage, and settle atomically.
- `MeteredStream` / `AsyncMeteredStream`: governs streaming calls. The hold
  is resolved on every exit path: clean exhaustion, `break`, exception, or
  timeout. An abandoned stream never strands funds.
- Payload-derived hold sizing: input tokens estimated from prompt length, the
  output bound taken from the call's own `max_tokens`, with a configurable
  safety buffer. Replaces a static worst-case ceiling that could both
  false-trip on long-context calls and, worse, under-reserve enough to let
  concurrent callers breach the envelope.
- `govern()`: a client proxy that meters an existing SDK client's calls
  without changing call sites.

**Framework adapters**

- `agentgov.adapters.langchain`: `GovernedChatModel` for direct model wrapping,
  and `GovernedCallbackHandler` for LangGraph and deep chains where the model
  object is never in reach. Sets `raise_error = True` so a denial-of-wallet
  halt is not silently swallowed by LangChain's callback system.
- `agentgov.adapters.crewai`: `GovernedCrew`, settling per run against
  CrewAI's cumulative `usage_metrics` (billing only the delta between runs),
  plus `govern_agent` as a generic decorator for frameworks with no dedicated
  adapter.
- Neither adapter imports its framework. Every object is duck-typed, so both
  load and are tested without LangChain or CrewAI installed.

**Reconciliation engine**

- `agentgov.reconciliation`: matches a provider's usage export against the
  local ledger and sorts every line into matched, discrepant, phantom
  (billed but never authorized locally, which is the finding that matters), or
  unsettled.
- Fuzzy matching with configurable timestamp and token tolerance, to absorb
  network latency and pre-flight sizing drift without erasing real
  discrepancies.
- Parsers for OpenAI-style JSON and Anthropic-style CSV usage exports.
- `agentgov reconcile <ledger-db> <provider-export>` CLI command, exiting
  non-zero when any phantom (unmetered) spend is found. Suitable for CI.

**CLI**

- `agentgov inspect <db>`: renders the ledger, balance tree, and circuit
  breaker status.
- `agentgov verify <db>`: re-runs `verify_chain()` and `verify_conservation()`,
  exiting 0/1 for pipeline use.
- `agentgov reconcile <db> <export>`: the reconciliation report above.

**Documentation and demos**

- `examples/denial_of_wallet_benchmark.py`: reproduces the denial-of-wallet
  failure mode this project exists to stop.
- `examples/persistence_demo.py`, `examples/live_demo.py`: end-to-end
  demonstrations of durability and the full governed-agent lifecycle.
- `docs/DEMO_RUNBOOK.md`: a scripted three-minute live walkthrough.
- `SECURITY.md`: threat model, redaction guarantees, and disclosure process.

### Notes

- Zero runtime dependencies; pure standard library. `mypy --strict` clean
  across `src/`, `tests/`, and `examples/`.
- Single-process governance model: cross-process coordination is enforced via
  the advisory file lock, not distributed consensus. Multi-node coordination
  is on the roadmap, not yet implemented.
