# Changelog

All notable changes to AgentGov are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project intends to follow [Semantic Versioning](https://semver.org/)
from 1.0.0 onward. Before 1.0.0, minor versions may include breaking changes.

## [0.1.0] — 2026-09-14

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
  until it settles — the mechanism that makes double-spend structurally
  impossible under concurrency, not merely unlikely.
- Latching circuit breaker on overdraft, runaway-loop velocity, and budget
  exhaustion. A trip halts the scope and every descendant beneath it until an
  operator explicitly resets it.
- `verify_conservation()`: proves
  `Σ(scope balances) + outstanding_holds + settled_spend − reversals == funded`
  across the whole tree — money is never created, destroyed, or double-counted.
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
- Measured inline overhead: ~78µs mean, ~89µs p99 per call — roughly 0.005%
  of a real model call.
- Trips share the same actuator as the financial breaker: a cognitive halt
  latches the budget scope and is recorded as a hash-anchored control event
  in the same ledger.

**Interception and dynamic sizing**

- `Interceptor.invoke()` / `ainvoke()`: authorize, execute with no lock held,
  price the response's real token usage, and settle atomically.
- `MeteredStream` / `AsyncMeteredStream`: governs streaming calls. The hold
  is resolved on every exit path — clean exhaustion, `break`, exception, or
  timeout — so an abandoned stream never strands funds.
- Payload-derived hold sizing: input tokens estimated from prompt length, the
  output bound taken from the call's own `max_tokens`, with a configurable
  safety buffer. Replaces a static worst-case ceiling that could both
  false-trip on long-context calls and, more importantly, under-reserve
  enough to let concurrent callers breach the envelope.
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
- Neither adapter imports its framework — every object is duck-typed, so both
  load and are tested without LangChain or CrewAI installed.

**Reconciliation engine**

- `agentgov.reconciliation`: matches a provider's usage export against the
  local ledger and sorts every line into matched, discrepant, phantom
  (billed but never authorized locally — the finding that matters), or
  unsettled.
- Fuzzy matching with configurable timestamp and token tolerance, to absorb
  network latency and pre-flight sizing drift without erasing real
  discrepancies.
- Parsers for OpenAI-style JSON and Anthropic-style CSV usage exports.
- `agentgov reconcile <ledger-db> <provider-export>` CLI command, exiting
  non-zero when any phantom (unmetered) spend is found — suitable for CI.

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
