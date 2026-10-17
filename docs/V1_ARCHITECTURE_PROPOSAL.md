# AgentGov v1.0.0: Architecture Proposal

**Status: proposal for review. No implementation.** Written against v0.4.0 (`7bb97a8`) on
2026-10-10. Interlock v1.0.1 (`8df350b`) was read for cross-repository context. Nothing in this
document has been built. Every number in it was either measured, with the method in Appendix A, or
is labelled as an extrapolation.

## Contents

- [0. Summary](#0-summary)
- [1. How this was produced](#1-how-this-was-produced)
- [2. What 1.0.0 has to mean](#2-what-100-has-to-mean)
- [3. Findings](#3-findings)
- [4. Principles every 1.0 change keeps](#4-principles-every-10-change-keeps)
- [5. Proposed architecture](#5-proposed-architecture)
- [6. Release plan](#6-release-plan)
- [7. Decisions needed before Phase 1](#7-decisions-needed-before-phase-1)
- [8. Non-goals for 1.0](#8-non-goals-for-10)
- [9. Risks](#9-risks)
- [10. What changes in Interlock](#10-what-changes-in-interlock)
- [Appendix A: Measurements](#appendix-a-measurements)
- [Appendix B: Reproductions](#appendix-b-reproductions)
- [Appendix C: Sources](#appendix-c-sources)

---

## 0. Summary

Within the envelope its tests cover, v0.4.0 is correct, and those tests are good. They inject a
fault at every write boundary, kill a process inside `capture()`, lose commit outcomes, and race
eight processes against one envelope. Four things stand between it and an enterprise 1.0:

1. **Cost grows with history.** Opening a governor replays the whole chain twice while holding the
   fleet-wide writer lock. Every governor also keeps the whole chain in memory and copies it on
   every fleet catch-up. This is the cause of Interlock's 2.5-second stall, and it gets worse for
   every hour the ledger runs.
2. **Defects outside the tested envelope.** Four were confirmed:
   - two make a database permanently unopenable;
   - one creates spending power;
   - one forges audit-log lines.
3. **Keys in files.** agentgov ships no remote signer. Its receipt log assumes a key that is fast,
   local and never rotates. ARC1's signing input also outgrows what AWS KMS can sign as Ed25519.
4. **Nothing is frozen.** The ledger format has no specification. The top level exports 81 names,
   internals among them. A downstream consumer takes agentgov's private mutex.

### Findings

| # | Finding | Severity | Evidence |
|---|---|---|---|
| F1 | Opening a writable governor replays every entry twice, under the fleet-wide writer lock. Cost is about 30 µs per entry, linear in history | Critical | §3.1, measured |
| F2 | Past about 1M entries, one governor opening makes every other governor's writes time out (`lock_timeout`, 30 s). Past about 2M, the opener is ended by `idle_timeout` (60 s) and can never open | Critical | §3.1, extrapolated from F1 |
| F3 | Ledger arithmetic uses the calling thread's `decimal` context. A `prec=6` thread wrote a rounded balance, and the database no longer opens, even with `repair=True` | Critical | §3.4, reproduced |
| F4 | The public `Ledger.post()` checks ledger rules but not governance rules. A FUNDING to a child scope was committed and served, and the database no longer opens, even with `repair=True` | Critical | §3.4, reproduced |
| F5 | `refund()` has no bound. A scope granted 0.10 shows 1000.10 available after a refund, and `verify_integrity()` passes | High | §3.4, reproduced |
| F6 | The audit line interpolates memo and scope unescaped. One memo forged a complete `AGOV2` line in the log (CWE-117) | High | §3.4, reproduced |
| F7 | Every governor holds the whole chain (about 1.1 KB per entry) and copies it on each fleet catch-up. Fleet throughput falls as the ledger ages | High | §3.2, measured |
| F8 | `ainvoke()` and async streams make durable ledger writes on the event loop. On PostgreSQL, one lock wait can block every coroutine for up to 30 s | High | §3.4 |
| F9 | agentgov has no remote signer. The receipt log signs and calls witnesses under its lock, verifies through the signer on reopen, and cannot reopen after a key rotation. AWS KMS cannot sign ARC1 inputs over 4096 bytes as Ed25519 | High | §3.5 |
| F10 | The ledger has no key. Its hash format is defined by CPython behaviour, with no specification and no vectors | Medium | §3.5, §3.8 |
| F11 | There is one global chain. A write takes about 5 round trips uncontended and about 11 contended, all under the lock. Adding governors lowers total throughput | Medium | §3.3, §3.6 |
| F12 | Interlock takes agentgov's private `RLock` in five places to make check-then-authorize atomic, which is not atomic across a fleet. There are no idempotency keys, and internals are in the public API | Medium | §3.7 |
| F13 | There are no soak, scale, model-based or linearizability tests. Python 3.13/3.14, PostgreSQL 17/18, PgBouncer and Windows are outside CI | Medium | §3.9 |

### The plan

| Release | Theme | Fixes |
|---|---|---|
| 0.4.1 | Unblock Interlock: lock-free open, the ledger's own decimal context, an escaped audit line | F1 (the stall), F3, F6 |
| 0.5.0 | One rule engine for writes and replay; async work off the event loop; model-based tests | F4, F5, F8 |
| 0.6.0 | The `AGOV3` format and its specification, checkpoints, store-backed history. Open time becomes constant in history length | F1, F2, F7, F10 (format) |
| 0.7.0 | `RemoteSigner` in agentgov, pipelined issuance, rotation inside a log, ARC1 1.2, signed ledger checkpoints | F9, F10 (key) |
| 0.8.0 | Fewer round trips, group commit, `transaction()`, idempotency keys, PgBouncer, failover semantics | F11, F12 |
| 0.9.0 | Public API and SPI split, the CLI on PostgreSQL, docs, release engineering | F12, F13 |
| 1.0.0 | rc1; a 72-hour soak and a chaos matrix; Interlock's suite and soak on the rc; performance gates | F13 |

Ten decisions are needed before Phase 1 starts. They are listed with recommendations in §7.

---

## 1. How this was produced

- Every module in `src/agentgov` was read (16,859 lines), along with the docs, the CI workflow and
  the test inventory (582 test functions in 13,053 lines).
- Interlock's local checkout was read, and not modified, wherever it touches agentgov. That covers
  its `RemoteSigner` (`src/interlock/signers.py`), its Epic 8 and Epic 9 design notes, and its call
  sites into agentgov.
- Open cost was measured against ledger size on SQLite, using Python 3.11.14 on an Apple Silicon
  laptop. PostgreSQL was not measured here. Replay and verification are the same Python work on
  either store. See Appendix A.
- Each suspected defect was reproduced against an unmodified 0.4.0 with a short script. See
  Appendix B.
- KMS behaviour was checked against vendor documentation. See Appendix C.

The only change to the repository is this file.

---

## 2. What 1.0.0 has to mean

The changelog commits to Semantic Versioning from 1.0.0. For a ledger, the contract covers more
than the Python API:

1. **Formats.** This means ledger entries, ARC1 documents, and the SQLite and PostgreSQL layouts.
   Anything a 1.x release writes must verify under every later release, and a 1.x database must
   upgrade in place.
2. **Public API.** Breaking changes happen only in 2.0, and only after a deprecation in a 1.x.
3. **Resource bounds.** Open time, memory and the cost of one write are each stated as a function of
   what they depend on, and CI gates hold them there.
4. **Failure semantics.** The behaviour on a lost commit, a failover, a lock timeout, a signer
   outage, and a crash at any point is written down and tested.
5. **Supply chain.** Each release can be traced to the commit and the workflow that built it.

v0.4.0 meets (2) informally and much of (4). It does not meet (1), because the ledger format has no
specification, and it does not meet (3) or (5).

---

## 3. Findings

### 3.1 Opening a governor replays all of history under the fleet-wide lock (F1, F2)

On a shared store, `BudgetManager.__init__` enters `shared.writer()` (`core.py:1942`). That means
`BEGIN`, then `pg_advisory_xact_lock` on the ledger's schema. Inside the lock it does four things:

1. `store.load()` reads and parses every entry and cache row (`core.py:1949`).
2. `Ledger._from_entries()` replays every hash, balance and hold pairing (`core.py:1180`, `896`).
3. `_restore_from_store()` derives the tree and the breakers from every entry (`core.py:2132`).
4. `verify_integrity()` (`core.py:2175`) replays the chain a second time (`core.py:3530` → `1408`).
   It then derives the governance a second time (`core.py:3565`).

`PostgresStore._open()` also takes the same lock beforehand, just to read the schema version, even
when the schema is already installed (`postgres.py:310`). So every open takes the fleet's lock
twice. `_reload()` runs after a lost commit outcome or a schema change, and it constructs a whole
new manager. That is the same work, under the lock again (`core.py:2693`).

Measured (Appendix A):

| Entries | Open | Load | Replay | Governance | `verify_integrity()` |
|---:|---:|---:|---:|---:|---:|
| 9,017 | 271 ms | 81 ms | 72 ms | 3 ms | 76 ms |
| 45,017 | 1,300 ms | 578 ms | 360 ms | 15 ms | 370 ms |
| 150,017 | 4,823 ms | 2,099 ms | 1,304 ms | 55 ms | 1,227 ms |

That is about 30 µs per entry, linear in history. Interlock's Epic 8 soak recorded the
consequence (`docs/EPIC8_DESIGN.md` §9). A reload reopened two governors, "each opening a new
AgentGov governor, which opens under the ledger's writer lock: two and a half seconds without a
ledger write, every engine waiting." At the cost measured here, that is consistent with a ledger of
a few tens of thousands of entries. Interlock's workaround is to stop reopening governors. Every
cold start and every failover still pays the cost, and the cost keeps growing.

**Extrapolation (not measured).** During this work the session holds the lock and sits idle in
transaction while Python verifies.

- **At about 1M entries,** open takes about 30 s, which is the default `lock_timeout`. While one
  governor opens, every other governor's mutation fails with `StorageError`.
- **At about 2M entries,** open takes about 60 s, which is the default `idle_timeout`. The server
  ends the opener's session, so it can never open. A supervisor that retries just repeats the
  stall.
- **Interlock clusters are lower.** They bound sessions by `session_timeout_seconds`
  (`docs/EPIC9_DESIGN.md` §3.3), which lowers this ceiling in proportion.

A fleet settling ten calls a second, at three entries each, writes 1M entries in about nine hours.

### 3.2 Memory and the cost of a write grow with history (F7)

- **Every entry stays in memory.** `Ledger._entries` holds every entry for the life of the process
  (`core.py:1171`). Each costs about 1.12 KB (Appendix A), and Interlock opens one governor per part
  on every node.
- **Every catch-up copies history.** Each fleet catch-up republishes `[*verified, *delta.entries]`,
  a copy of all of history, under both locks (`core.py:2671`). That takes 0.89 ms at 150k entries
  and grows linearly.
- **Catch-ups redo other work too.** A catch-up that finds new entries does four more things:
  - copies every `BudgetNode` (`core.py:2652`);
  - rebuilds the list of chained control events (`core.py:2619`);
  - re-reads the entire `open_authorizations` table (`postgres.py:728`, `storage.py:854`);
  - makes two schema-version queries (`postgres.py:722`).
- **Several reads scan everything.**
  - `_exhausted()` scans every open authorization on every capture (`core.py:3703`).
  - `audit_trail(scope)` scans all of history (`core.py:1265`).
  - `descendants()` is quadratic, because of `list.pop(0)` (`core.py:2785`).
- **Interlock scans too.** It scans the full audit trail to find a single `ANCHOR` by its memo
  (`vacuum.py:998`), and again to match settlement claims (`settlement.py:591`).

So even before contention is counted, a fleet write gets more expensive as the ledger ages.

### 3.3 Hash-chain bottlenecks

- **The hash is not the bottleneck.** SHA-256 over an entry's payload costs 0.38 µs. Building that
  payload with `json.dumps` and `str()` costs about 5 µs. The rest of the roughly 31 µs per entry is
  parsing rows into objects and running the rules, both done twice. A faster hash would change
  nothing measurable. The fix is to stop replaying (§5.2).
- **Serialization is the bottleneck.** One chain has one head, so the fleet takes turns.
  - Each turn holds the lock across network round trips: about 5 when nothing changed, about 11
    after another governor wrote.
  - It also holds the lock while Python verifies whatever the other governors wrote.
  - So throughput is bounded by one over the lock's hold time. The README measures about 500 writes
    a second from one governor, and about 180 in total from eight.
- **Proofs need the whole chain.** Nothing commits to an entry except the entry after it. So proving
  that a transaction is in the ledger means reading the ledger. `verify-receipt --ledger` opens and
  replays the entire database, then scans `audit_trail()` (`receipts/verify.py:383`).
- **Linearity is cheap.** The `extend_chain` trigger is a primary-key lookup. It stays as it is.

### 3.4 Correctness defects (F3–F6, F8)

Each of these was reproduced against an unmodified 0.4.0 (Appendix B).

**F3: ledger arithmetic follows the caller's `decimal` context.**
- **The bug.** `balance + signed_amount` (`core.py:713`, `1087`) is computed in the calling thread's
  context. Under `decimal.localcontext(prec=6)`, `spend()` wrote `balance_after = 123457`. The
  chain implies `123456.78901233`.
- **Why it was committed.** The write-time check ran under the same context, so it passed.
- **The result.** `verify_integrity()` fails in an ordinary context, and reopening is refused, with
  or without `repair=True`. Any code in the host process that lowers precision on a thread that
  reaches the governor can make a ledger permanently unopenable.

**F4: what may be written and what may be replayed differ.**
- **The gap.** `_Overlay` is documented as "one set of rules" for writes, refreshes and replays
  (`core.py:620`). But the governance rules live in `_Governance` (`core.py:1594`), which runs only
  on replay and catch-up. Those rules are: FUNDING only to a root, ALLOCATION only to a new scope,
  and control events only on known scopes.
- **What happened.** The public `Ledger.post()` (`core.py:1297`) accepted a FUNDING to a child
  scope and committed it. The live manager then served 1000.50 as available. The database now
  refuses to open, with or without `repair=True`.
- **Root cause.** F3 and F4 share one: the ledger can accept something it cannot replay.

**F5: refunds create spending power.**
- **The bug.** `refund()` (`core.py:3271`) credits any amount to any scope without naming a spend,
  and a `REVERSAL` cannot carry a `ref` (`core.py:316`).
- **The result.** A child granted 0.10 and then refunded 1000 shows 1000.10 available. That breaks
  the delegation invariant.
- **Why verification misses it.** `verify_conservation()` passes, because the identity counts
  reversals.

**F6: audit-line injection (CWE-117).**
- **The bug.** `format_audit_line()` (`core.py:520`) interpolates `scope_id` and `memo` unescaped
  into its pipe-delimited line.
- **What happened.** An anchor memo containing a newline produced three log lines for two entries.
  The third was a well-formed forgery: `AGOV2|seq=0000000099|type=funding|...`.
- **Why it matters.** Scope ids and memos can come from agent and tool names, which means from
  model output. The structured `extra` record is safe, but the message string is what log pipelines
  parse.

**F8: the async paths block the event loop.**
- **The bug.** `Interceptor.ainvoke()` (`interceptor.py:902`) and `AsyncMeteredStream` call
  `authorize()` and `capture()` synchronously on the loop.
- **The cost.** On SQLite with `synchronous=FULL`, that is an fsync per call. On PostgreSQL, it is
  five or more round trips plus a lock wait of up to `lock_timeout`.
- **Why tests miss it.** The docstring says "concurrent tasks contend only for the microseconds each
  ledger write takes." That holds only for an in-memory manager, which is what the async stress
  tests use.

### 3.5 Signing and the `RemoteSigner` gap (F9, F10)

**What Interlock built.** `interlock.signers.RemoteSigner` implements agentgov's `Signer` protocol
for an Ed25519 key held by a service.
- It pins a key version and its public half when it is built.
- It verifies every signature the service returns before passing it on.
- It verifies locally, and offers `sign_async` on a worker thread.

`HttpRemoteSigner` speaks a Vault-transit-shaped protocol over `urllib`. It refuses redirects and
takes its token from the environment.

It satisfies agentgov's protocol by duck typing, so `ReceiptLog` accepts it today. Here is what
agentgov is missing:

1. **The abstraction lives downstream.** Without Interlock, an agentgov user signs with a seed
   (`Ed25519Signer(seed)`) or an HMAC secret held in process memory. In practice that is read from a
   file.
2. **Verification goes through the signer.**
   - The protocol requires `Signer.verify()` (`signing.py:70`).
   - `ReceiptLog._resume()` verifies every checkpoint, and every receipt after the last one, with
     `self._signer` (`log.py:404`, `421`). `FileWitness.__init__` does the same (`witness.py:111`).
   - Interlock's signer happens to verify locally, but the protocol does not require that. With a
     signer whose verification is remote, a reopen costs one network call per receipt.
3. **Signing happens under the log's lock.**
   - `issue()` signs inside `self._lock` (`log.py:202`).
   - `_append()` publishes checkpoints to every witness inside the same lock (`log.py:366`).
   - With a 50 ms signer, a log issues at most 20 receipts a second, and readers such as `bundle()`
     and the proof methods wait on the key service.
   - Interlock found and fixed the same pattern in its inbox (`docs/EPIC8_DESIGN.md` §9).
4. **A key cannot rotate inside a log.**
   - `_check_signature()` requires a signature's `key_id` to equal the verifier's (`schema.py:324`).
   - A log resumes by checking its old checkpoints against the current signer, and a `FileWitness`
     takes one key per log.
   - So a log whose key rotates cannot reopen. Interlock's Epic 8 records it (§8): "rotating it
     starts a new receipt log: ARC1's log is signed by one key."
5. **ARC1 does not yet fit KMS limits.**
   - **AWS KMS** signs Ed25519 (key spec `ECC_NIST_EDWARDS25519`, available since November 2025),
     but only as `ED25519_SHA_512` over a raw message of at most 4096 bytes. Its digest mode,
     `ED25519_PH_SHA_512`, is Ed25519ph. That is a different algorithm, and its signatures do not
     verify as Ed25519.
   - **ARC1 signs the domain prefix plus the canonical body.** The reference vectors are already
     1,316 to 2,348 bytes. A receipt with a few more effects or checkers cannot be signed by AWS KMS
     at all.
   - **Google Cloud KMS** signs pure Ed25519 over data (`EC_SIGN_ED25519`).
   - **Azure Key Vault:** Ed25519 support could not be confirmed. If it is absent, Azure deployments
     need an algorithm ARC1 does not define.
6. **The ledger has no key.** The README states the limit: anyone who can write the database and
   compute SHA-256 can rewrite it consistently. Signing ledger checkpoints with the same `Signer`
   fixes this, and it is the same mechanism a constant-time open needs (§5.2).

### 3.6 Fleet coordination, pooling and failover (F11)

- **One advisory lock per schema** (`postgres.py:126`) serializes the fleet. §3.3 gives the cost of
  each turn.
- **Transaction pooling is unsupported.**
  - The store sets `idle_in_transaction_session_timeout` once per session (`postgres.py:235`). For
    readers it also sets `default_transaction_read_only` per session. It lets psycopg prepare
    statements.
  - Behind PgBouncer in transaction mode, a session setting lands on whichever server connection
    happened to serve it. Two things then break:
    - the idle bound that cuts off a frozen lock holder silently stops applying to later
      transactions;
    - a reader's read-only default can land on a connection that another client then writes
      through.
  - `begin_locked` already sends `BEGIN` and `SET LOCAL lock_timeout` as one message. The idle bound
    needs to travel the same way. Interlock's stage does exactly this (`1a63718`), and Interlock
    tests it through PgBouncer in transaction mode.
- **A failover can roll the chain back.**
  - A replica promoted under asynchronous replication may be missing the last commits.
  - Governors read the shorter chain as history rewritten under them, and stop writing for good
    (`core.py:2631`).
  - Anchors that name a lost head, such as Interlock's records and ARC1 receipts, no longer verify.
  - Nothing distinguishes this from tampering, and no recovery procedure is documented.
- **Timestamps come from each host's clock** (`core.py:1046`). So entry timestamps can run
  backwards across governors, and `stale_authorizations()` compares them with the local clock.
- **The velocity window is per governor** (`core.py:3627`). As the README says, N governors admit N
  times the configured rate.

### 3.7 API surface and ergonomics (F12)

- **`agentgov.__all__` has 81 names.** Among them are types that only a store implementer needs
  (`WriteBatch`, `StoreImage`, `StoreDelta`, `WriterSession`, `PersistedNode`,
  `PersistedAuthorization`) and two alias exceptions. Freezing that list at 1.0 would freeze
  internals.
- **Interlock takes agentgov's private mutex.**
  - Where: `governor.ledger.lock` in `anchor.py:318`, `recovery.py:1059` and `1220`, and
    `extension.py:363` and `475`.
  - Why: mostly to make "check `available()`, then `authorize()`" atomic, because `authorize()` on
    insufficient funds trips the breaker.
  - The problem: on a shared ledger the check is not atomic. `available()` reads the last refresh,
    and the writer lock is taken only inside `authorize()`.
  - What is missing: a public, fleet-atomic unit of work, and an authorize that refuses without
    tripping.
- **No idempotency keys.** When a commit's outcome is lost, the governor re-reads the ledger. But
  the caller gets a `StorageError` and cannot tell whether `authorize()` happened. If it retries,
  the funds can be encumbered twice until `void_stale()`.
- **Reads on a shared ledger are stale by default.** `available()` and `is_halted()` serve the last
  refresh, and nothing at the call site says so.
- **Construction is awkward.** `BudgetManager(ledger=..., store=...)` asks for the same store twice.
  There is no URL-based open, so Interlock sniffs connection strings itself (`wiring.py`,
  `open_ledger`).
- **No lookup of an authorization by id.** Capturing on another host needs one.
- **The CLI reads SQLite only.**
- **Packaging.**
  - The classifier is `3 - Alpha`.
  - The `[tool.uv_build]` and `[tool.setuptools...]` tables remain beside hatchling.
  - The distribution is named `interlock-agentgov` while the import is `agentgov`.

### 3.8 A format a non-Python auditor cannot reimplement (F10)

- **How the hash is built.** An `AGOV2` entry hash is SHA-256 over
  `json.dumps([...], separators=(",", ":"), ensure_ascii=True)`. Its inputs are `str(Decimal)`,
  `str(UUID)` and a custom timestamp format (`core.py:470`).
- **Why that is hard to reproduce.** `str(Decimal("0.00000001"))` is `"1E-8"`. An auditor in Go or
  Rust has to reproduce CPython's decimal-to-string rules and its `json.dumps` escaping by reading
  source code, because there is no specification and there are no vectors.
- **ARC1 already has both** (RFC 8785, `docs/RECEIPTS.md`, `vectors/arc1/`).
- **Storage layouts.** Neither is documented as a contract.

### 3.9 Testing and release engineering (F13)

What exists is already strong:
- a failure injected at every write boundary of every operation;
- a process killed inside `capture()`;
- lost commit outcomes;
- stale views refused;
- the lock removed, with the chain still linear;
- races of 64 threads, 100 tasks and 8 processes;
- vectors regenerated and byte-compared;
- README blocks executed;
- a 95% coverage floor.

What is missing:

- **Soak.** There is no long-running mixed workload under faults. Interlock has one, run as a
  cluster with nodes killed and frozen.
- **Scale.** Nothing exercises a ledger beyond the tens of thousands of entries the benchmark
  produces. Nothing runs at a million entries, 100,000 scopes or 10,000 open holds.
- **Model-based testing.** F3, F4 and F5 are exactly what a stateful property test finds. Such a
  test runs random operation sequences, random host decimal contexts and raw posts, then asserts
  that whatever was accepted replays.
- **Linearizability.** The fleet tests assert invariants such as no overcommit. They do not check
  that the history the governors observed is linearizable.
- **Performance gates.** Nothing asserts open time, memory or throughput. v0.1.2 recorded
  `verify_integrity()` slowing from 0.61 s to 1.0 s on 66,000 entries; nothing would have failed at
  10 s.
- **Mutation testing.** Interlock runs a mutation pass for each epic. agentgov does not.
- **Fuzzing.** `loads_strict`, the provider-export parsers and CLI input are not fuzzed.
- **Matrix.**
  - Python 3.13 is a declared classifier but untested.
  - Python 3.14 and free-threaded 3.14t are untested.
  - PostgreSQL 17 and 18 are untested.
  - There is no PgBouncer job.
  - Windows has a code path (`storage.py:408`) but no CI.
- **Release.** There is no trusted publishing with attestations, and no SBOM.

---

## 4. Principles every 1.0 change keeps

1. **Accepted means replayable.** One rule engine decides both, and a property test holds it to
   that.
2. **Fail closed, off the hot path.**
   - Verification that can run in the background does.
   - A failure still latches the governor, as it does today.
   - Nothing proportional to history runs under a lock.
3. **No lock across foreign I/O.** A lock covers the ledger write and nothing else. It never covers
   a signer, a witness, or a full verification.
4. **Bounded by state, not history.** Each cost is proportional to:
   - memory: scopes and open holds;
   - open: the entries since the last checkpoint;
   - a write: its own batch.
5. **Specified formats, verified forever.** Every format has a specification and vectors. Data
   written as `AGOV1`, `AGOV2`, ARC1 1.0 or ARC1 1.1 verifies under every 1.x release.
6. **Zero runtime dependencies for the core.** The in-memory store, SQLite and verification need
   nothing extra. PostgreSQL, Ed25519 signing, KMS adapters and OpenTelemetry stay extras.
7. **Every claim measured.** The important ones become CI gates.

---

## 5. Proposed architecture

### 5.1 One rule engine (F3, F4)

- **Governance becomes chain state.**
  - `_ChainState` gains the tree, the roots, breaker state and the control-event high-water mark.
  - `_Overlay.apply()` enforces the ledger and governance rules together, so `_Governance` stops
    being a separate pass.
  - Writes, catch-up, refresh and replay all call the same function.
- **Ledger arithmetic runs in the ledger's own context.**
  - Every balance and total is computed under a module-level context, through
    `decimal.localcontext()`. That context has `prec=50`, with `Inexact`, `InvalidOperation` and
    `Overflow` trapped.
  - Quantization keeps its deliberate rounding (ceiling for costs, floor for credits) in a context
    that does not trap `Inexact`.
  - The same inputs then produce the same bytes, whatever the host has done to its own context. Any
    rounding in balance arithmetic raises instead of being written.
- **`Ledger.post()` becomes private.** `Ledger` becomes a read-only view, and every write goes
  through the manager. 0.5.0 deprecates the public method and 1.0 removes it (D6).
- **A property test holds this in place.** It runs:
  - random operation sequences;
  - raw posts through the private path;
  - random host decimal contexts;
  - injected store failures.

  Whatever was accepted must replay. Conservation and the delegation invariant must also hold: a
  scope's lifetime inflow never exceeds its grants plus bounded reversals.

### 5.2 Checkpoints: open constant in history, memory bounded by state (F1, F2, F7)

**First, lock-free open (0.4.1).** The committed prefix of the chain never changes. On PostgreSQL
the append-only triggers guarantee that; on SQLite the single writer does. So open does not need the
writer lock:

1. Read entries and caches in one `REPEATABLE READ READ ONLY` snapshot, verify them, and serve.
2. The first mutation catches up with the suffix under the lock, exactly as it does today.
3. Only a repair takes the writer lock, and it re-reads under the lock before writing.
4. `PostgresStore._open()` reads the installed version without the lock. It takes the lock only to
   install.
5. Open reuses the replay and governance it has just computed, instead of running
   `verify_integrity()` over both again.

On its own, this removes the fleet-wide stall and cuts about a quarter of open time (Appendix A).
Open is still linear in history, but only for the governor that is opening.

**State checkpoints (0.6.0).**

- **Content.** A checkpoint is the derived state as of a sequence `s`:
  - head, length and totals;
  - balances and open holds;
  - the tree, the breakers, and the control-event high-water mark;
  - an RFC 9162 frontier over entry hashes. This is a logarithmic number of hashes, and it later
    allows inclusion proofs for ledger entries without changing the format.
- **Storage.** The checkpoint is stored as a canonical (RFC 8785) snapshot row, keyed by `s`. It is
  written outside the writer lock, because the state at `s` never changes.
- **Commitment.** A zero-value `CHECKPOINT` entry (`AGOV3`) then commits the snapshot into the
  chain. Its memo names `s` and the snapshot's SHA-256, so editing the snapshot breaks its link to
  the chain. Only this small entry is appended under the lock.
- **Signing.** With a `Signer` configured, local or remote, the checkpoint is signed. That gives the
  ledger its first key. The existing `Witness` protocol can cosign it.
- **Cadence.** The governor that crosses the threshold writes a checkpoint every N entries (default
  10,000). It does so in a short session of its own, never inside the operation that crossed the
  threshold. A snapshot is proportional to scopes plus open holds. Deployments with very large state
  can raise N.

```
open:    one snapshot read, no writer lock
         ├─ newest CHECKPOINT entry; it names s and the digest of snapshot S(s)
         ├─ digest(S(s)) matches; the signature verifies (signed mode)
         ├─ replay s+1..head from S(s); the caches agree with the result
         └─ serve                                    cost: O(head − s) + O(state)
mutate:  writer lock → catch up from head → check → write → commit       (unchanged)
audit:   no lock: replay 1..head in chunks; each S(s) must equal the state replayed to s
```

**The auditor.**
- **Where it runs.** Out of process by default, as `agentgov audit --follow` in a sidecar or a
  scheduled job. For a single-process SQLite deployment it can run as a thread instead.
- **What it does.** It replays from genesis in chunks while holding no lock, and records signed
  progress marks in the database.
- **On a mismatch.** It records a failure that latches every governor at its next catch-up. That is
  the same fail-closed behaviour an unverifiable catch-up has today.
- **`agentgov verify`** remains a full replay and gains `--jobs N`. Entry hashes are independent of
  each other, and the segments between checkpoints can be replayed in parallel, each starting from
  its own snapshot.

**The trust model, stated plainly.**
- **Today.** Open replays from genesis. That catches naive edits to old rows, and bit rot, before
  anything is served. It does not stop a consistent rewrite by anyone who can write the database
  (README, *Known limitations*).
- **With checkpoint open.** Detection of edits to old rows moves from open to the auditor.
- **With signed checkpoints.** Consistent rewrites become detectable for the first time.
- **Policies (D1, D2).** `verify="checkpoint"` is the proposed default for writers. `verify="full"`
  runs a genesis replay at open and still takes no writer lock.

**Full verification without the lock.** `verify_integrity()` keeps its meaning, which is a full
verification.
- **What changes.** It no longer holds the manager's lock while it replays. It copies the head and
  derived state under the lock, which costs time proportional to state, then releases the lock,
  replays from the store and compares. Writers keep writing meanwhile.
- **A cheaper variant.** `verify_integrity(since="checkpoint")` checks only the suffix. It is for
  callers that verify often, such as Interlock's anchor.

**Memory bounded by state.** A stored ledger stops holding `_entries`. History is read from the
store on demand, through indexed queries:

```python
gov.entry(sequence)  # one entry
gov.entries(after=0, limit=1000)  # paged, oldest first
gov.find_entries(scope_id=None, entry_type=None, memo=None, transaction_id=None, ref=None)
```

- **Compatibility.** `audit_trail()` keeps its signature. It materializes its result at a
  documented cost, and gains an iterator twin.
- **The in-memory backend** keeps its list.
- **Catch-up gets cheaper.** It no longer copies history or re-reads the authorization table,
  because the new entries already say which holds opened and closed.
- **Captures get cheaper.** A per-scope count of open holds replaces the scan in `_exhausted()`.

**Targets, enforced as CI gates:**
- **Open time.** Opening a 1M-entry ledger whose newest checkpoint is at most 10,000 entries behind
  head takes at most 500 ms. That is also at most twice the time to open a 10,000-entry ledger.
- **Memory.** Resident memory is flat from 10,000 to 1,000,000 entries at a fixed number of scopes.
- **Results.** Full verification gives the same results as today.

### 5.3 Signing: `RemoteSigner` parity, and what it enables (F9, F10)

1. **The abstraction moves upstream.** `agentgov.receipts.signing` gains `RemoteSigner` and
   `HttpRemoteSigner`, API-identical to Interlock's. That includes:
   - the `_remote_key()` and `_remote_sign()` hooks;
   - a pinned version and public key;
   - verification before return, and `sign_async`;
   - no redirects, a token from the environment, and bounded answers.

   `interlock.signers` becomes a re-export. `SignerUnavailableError` already belongs to agentgov.
2. **Signing and verifying separate.**
   - `Signer` gains `public_key() -> Verifier`.
   - `Signer.verify()` stays for compatibility, but agentgov stops calling it.
   - `ReceiptLog`, `FileWitness` and checkpoint verification take a `Keyring` (verifiers by
     `key_id`), never the signer. So a reopen makes no network calls.
3. **`AsyncSigner`.** A protocol with `async def sign_async()`, plus an adapter that runs any
   `Signer` on a worker thread.
4. **Pipelined issuance.**
   - `ReceiptLog.issue()` reserves the next index under a short lock and signs outside it. A
     sequencer then appends in index order. Readers never wait on the key service.
   - If the signature for index `i` fails, every reservation after `i` is released and taken again.
     So each receipt still signs its own position, and the log has no gaps.
   - Witness publication moves to a background publisher. `issue()` returns once the receipt is
     durable, which is already what happens when a publication fails.

```
caller A: reserve #7 ─┐ sign #7 (KMS, 50 ms) ───────────► append #7
caller B: reserve #8 ─┤ sign #8 (KMS, 50 ms) ──────────► wait for #7, append #8
caller C: reserve #9 ─┘ sign #9 fails ✗  → #9 onward released, re-reserved, re-signed
                       (the lock is held only to reserve and to append)
```

5. **Rotation inside a log (ARC1 1.2).**
   - A key transition is a document signed by the outgoing key. It names the incoming key and the
     tree size from which that key signs.
   - `_resume()`, `verify_bundle()` and witnesses check each checkpoint under the key in force at
     its size.
   - A witness's `logs` mapping becomes a keyring per log.
   - Interlock can then stop starting a new log at each rotation.
6. **Digest-then-sign (ARC1 1.2, signature version 2).**
   - The signed message becomes `domain_v2 || SHA-512(canonical(body + sig header))`. That is under
     100 bytes, which fits every KMS limit.
   - It is signed with pure Ed25519, never Ed25519ph.
   - Version 1 signatures (ARC1 1.0 and 1.1) verify unchanged.
   - The AWS adapter, and a test, pin the only correct combination: `ECC_NIST_EDWARDS25519`,
     `ED25519_SHA_512`, `MessageType=RAW` (D3).
7. **Adapters.**
   - 1.0 ships `HttpRemoteSigner` (standard library only) and an AWS KMS adapter behind
     `agentgov[kms-aws]`. The adapter is tested against a fake key service, like Interlock's
     `tests/fakekms.py`.
   - Google Cloud KMS and PKCS#11 follow in 1.x (D8).
   - HMAC stays local, because a remote HMAC would need the service to verify as well.
   - ECDSA P-256, for HSMs without Ed25519, is D4.
8. **Signed ledger checkpoints** (§5.2) use the same `Signer`. One key-service configuration then
   serves both receipts and the ledger.
9. **The receipt log also opens in constant time.**
   - Each checkpoint persists the Merkle frontier and an offset index.
   - A resume verifies the newest checkpoint under the keyring, and re-verifies only the receipts
     after it.
   - Receipts stay on disk instead of in memory.

**Targets:**
- **Throughput.** With a 50 ms signer and 16 issues in flight, at least ten times today's serial
  issuance rate.
- **Rotation.** A log reopens after a key rotation.
- **Reopen.** A reopen makes no signer calls.
- **Compatibility.** Every ARC1 1.0 and 1.1 vector stays byte-identical.

### 5.4 The fleet write path (F11)

These are ordered by payoff per unit of risk:

1. **Fewer round trips, with no format change.**
   - Fold the head check into the simple query that begins the transaction and takes the lock.
   - Send entries and every cache write as one statement: either a server-side `apply_batch()`, or
     a multi-statement simple query. Not pipeline mode, for the idle-timeout reason
     `postgres.py:509` gives.
   - Check the schema version at open and after a failed catch-up, not on every catch-up.
   - Derive open-hold changes from the new entries.
   - Target: 3 round trips when uncontended.
2. **Group commit.**
   - One writer per manager drains a queue of operations into one unit of work and one store
     transaction. One lock acquisition and one commit then serve many concurrent callers.
   - Operations are validated in order against the overlay. One that fails gets its own exception
     and is left out, and the rest commit together (D9).
   - The synchronous API submits and waits. The asynchronous API awaits (§5.6).
3. **Partitioned chains, in 1.1, and only if measured necessary.**
   - Money never moves between roots. FUNDING enters a root, ALLOCATION and RELEASE stay within its
     tree, and SPEND and REVERSAL leave it.
   - So each root's tree can be its own chain, with its own sequence, head and advisory lock. Writes
     to different roots then stop contending.
   - A ledger checkpoint commits to every partition's head, and ARC1's `ChainAnchor` gains an
     optional partition. Both changes are additive (D5).

**Targets** on the CI reference PostgreSQL. These are to be confirmed against the Phase 0 baseline:
- **Fleet.** Eight governors with eight concurrent callers each reach at least 2,000 operations a
  second in total. Today's figure is about 180.
- **Single governor.** At least 1,500 operations a second.
- **Latency.** p99 per operation is at most 25 ms at that load.

### 5.5 HA and failure semantics

- **Transaction pooling.**
  - Add a `prepare_threshold=None` option.
  - Send `SET LOCAL idle_in_transaction_session_timeout` in the same message that begins each
    transaction, as `lock_timeout` already is.
  - Use `READ ONLY` transactions for readers, instead of a session default.
  - Add a CI job behind PgBouncer, modelled on Interlock's.
- **Failover.**
  - Document synchronous replication as the supported configuration for the ledger's database.
  - Add `LedgerRollbackError` for a chain shorter than one a governor has verified, distinct from
    tampering. Signed and witnessed checkpoints make a rollback provable.
  - Write a runbook for anchors that name lost heads.
  - The soak includes a primary failover.
- **Monotonic timestamps.** An entry's timestamp is the later of the clock and the previous entry's
  timestamp.
- **A fleet-wide velocity window (opt-in).** It counts a scope's `HOLD` entries in the caught-up
  chain rather than local calls, so it covers every governor.
- **Signer outages.**
  - Issuance fails with `SignerUnavailableError` and never falls back to a local key. That is
    Interlock's rule.
  - Ledger writes do not depend on the signer. Checkpoint signing retries in the background, and
    any unsigned interval is visible.

### 5.6 The 1.0 API

```python
import agentgov
from agentgov import money

gov = agentgov.open("postgresql://governor@db/fleet?schema=agentgov")  # or sqlite:///, memory:

with gov.transaction() as txn:  # fleet-atomic; reads inside are current
    if txn.available("researcher") >= money("0.02"):
        hold = txn.authorize("researcher", money("0.02"), idempotency_key="req-81f3")

hold = gov.try_authorize("researcher", money("0.02"))  # None, and no trip, if it cannot pay
spend = gov.capture(hold, money("0.013"), idempotency_key="req-81f3:capture")
gov.refund("researcher", money("0.013"), reverses=spend.entry_id)  # bounded by that spend

agov = agentgov.AsyncBudgetManager(gov)  # never blocks the event loop
hold = await agov.authorize("researcher", money("0.02"))
```

- **`agentgov.open(url, **options)`** takes `sqlite:///path`, `postgresql://...` or `memory:`.
  `open_sqlite()` and `open_postgres()` stay.
- **`BudgetManager.transaction()`** is a public, fleet-atomic unit of work. Reads inside it are
  current, and every mutation inside it joins one commit. It replaces `ledger.lock` for callers;
  `ledger.lock` keeps working through 1.x, and warns.
- **`try_authorize()`** refuses without tripping the breaker, atomically under the writer lock.
- **`idempotency_key=`** on `fund`, `delegate`, `authorize`, `capture`, `void`, `spend` and
  `refund`.
  - A retried call returns the first call's result.
  - A different call with the same key raises `IdempotencyConflictError`.
- **Lookups:** `authorization(authorization_id)`, `entry()`, `entries()` and `find_entries()`
  (§5.2).
- **Current reads on a shared ledger:** `available(scope_id, fresh=True)`, or anything inside
  `transaction()`.
- **`AsyncBudgetManager`** exposes the same operations as coroutines, over the group-commit writer.
  `ainvoke()` and async streams use it.
- **`refund(..., reverses=)`** is bounded by the unreversed amount of the spend it names. This works
  through an `AGOV3` `REVERSAL` with a `ref`.
  - 0.5.0 enforces a per-scope bound first, before the format change: lifetime reversals never
    exceed lifetime spend.
  - Refunds that name no spend are deprecated.
- **Public API and SPI.**
  - `agentgov` exports the user API.
  - `agentgov.spi` exports what a store implementer needs: `WriteBatch`, `StoreImage`,
    `StoreDelta`, `WriterSession`, `PersistedNode`, `PersistedAuthorization`, `SharedStore` and
    `JoinableStore`.
  - The old import paths warn from 0.9 and are removed in 2.0.
- **Observability.** A `Metrics` protocol with a no-op default, plus an `agentgov[otel]` adapter. It
  reports:
  - lock wait time and lock hold time;
  - catch-up length;
  - open time and verify time;
  - open holds and trips;
  - store errors;
  - checkpoint lag.
- **CLI.** Every command takes a PostgreSQL URL. New commands: `checkpoint`, `audit [--follow]` and
  `export --from-seq`.
- **Exceptions.** New `LedgerRollbackError` and `IdempotencyConflictError`. The two aliases are D6.

### 5.7 Format freeze

- **`AGOV3` entries.**
  - Encoding: RFC 8785 canonical JSON, reusing `receipts/canonical.py`.
  - Amounts: fixed-point strings (`"0.00000001"`, never `"1E-8"`).
  - New: a `REVERSAL` may carry `ref`, and there is a new `CHECKPOINT` type.
  - Compatibility: `AGOV1` and `AGOV2` entries keep verifying under their own rules, through the
    versioning that already exists.
  - Specification: `docs/LEDGER_FORMAT.md` covers entry hashing, replay rules and checkpoints.
  - Vectors: `vectors/agov/` holds conformance vectors, regenerated and byte-compared in CI as
    `vectors/arc1/` are.
- **ARC1 1.2.**
  - Signature version 2 (digest-then-sign).
  - Key transitions.
  - An optional partition, reserved in `ChainAnchor`.
  - Every 1.0 and 1.1 document, signature, leaf and root stays unchanged.
- **Storage.**
  - SQLite schema 3 and PostgreSQL layout `pg2` add a snapshot table, an idempotency table and a
    balance cache.
  - They add indexes on `(scope_id, sequence)`, `(entry_type, memo digest)`, `transaction_id` and
    `ref`.
  - Upgrades are in place, forward-only, and run under the writer lock. They are tested from fixture
    databases written by every released version, from 0.1.0 to 0.4.x.
  - A read-only open never upgrades.

### 5.8 Verification program

| Kind | What | When |
|---|---|---|
| Model-based | A Hypothesis state machine against a reference model. It asserts that accepted means replayable, under random host decimal contexts and injected store failures | Every PR |
| Linearizability | Fleet histories are recorded and checked against the sequential specification, with chain order as the witness | Every PR (small), nightly (large) |
| Scale | 1M- and 10M-entry fixtures, 100,000 scopes, 10,000 open holds; open-time and memory gates | Nightly, and every release |
| Soak | N processes × M threads of mixed operations, under SIGKILL and SIGSTOP, PostgreSQL restart and failover, added network latency, and PgBouncer. Invariants are checked continuously; memory, file descriptors, connections and p99 are tracked | 30 min on merges to `main`, 4 h nightly, 72 h before 1.0 |
| Mutation | A pass each phase, kept as an inventory of mechanisms, as Interlock does | Each phase |
| Fuzzing | `loads_strict`, the export parsers, CLI input | Nightly |
| Matrix | Python 3.11 to 3.14 and 3.14t; PostgreSQL 14 to 18; Linux, macOS and Windows | Every PR (a subset) |
| Downstream | Interlock's agentgov-facing tests, run against this branch | Every PR |

---

## 6. Release plan

Each step is one PR with its tests, and each phase is a release.

### Phase 0: baselines and guards (no behaviour change)

- **0.1** Add `benchmarks/`. It measures:
  - open time against ledger size;
  - memory per entry;
  - SQLite and PostgreSQL throughput at one and at eight governors;
  - receipt issuance against a slow signer.

  Commit a baseline as JSON, and have CI run a short version.
- **0.2** Add strict `xfail` tests for F3, F4, F5, F6 and F8. Add one more, on PostgreSQL, for "a
  governor opening does not stall other governors' writes." Each flips to passing when its fix
  lands.
- **0.3** Add a downstream job that runs Interlock's agentgov-facing tests against the branch.

### Phase 1: 0.4.1, unblock Interlock

- **1.1** Lock-free open, the version check without the lock, and no second replay at open.
  - *Done when* another governor's write latency stays within normal contention while one governor
    opens a 150,000-entry ledger. The test bound is 250 ms.
  - Open must also be at least 20% faster.
- **1.2** The ledger's own decimal context (F3).
- **1.3** Scope and memo escaped in the audit line (F6).

### Phase 2: 0.5.0, one rule engine

- **2.1** Fold governance into chain state, so one `apply()` serves writes, catch-up, refresh and
  replay (F4).
- **2.2** Deprecate `Ledger.post()`; all writes go through the manager.
- **2.3** Add the per-scope refund bound (F5). This holds until 3.1 brings `REVERSAL.ref`.
- **2.4** Move the ledger calls in `ainvoke()` and async streams off the loop, onto a worker thread
  (F8). This holds until 5.2.
- **2.5** Add model-based tests, and run a mutation pass over `core.py`.

### Phase 3: 0.6.0, open constant in history, memory bounded by state

- **3.1** `docs/LEDGER_FORMAT.md`, `AGOV3`, and `vectors/agov/`.
- **3.2** SQLite schema 3 and PostgreSQL `pg2`, upgraded from every released version.
- **3.3** The checkpoint writer, checkpoint open, the auditor, and the verification policies.
- **3.4** Store-backed history and indexed queries; catch-up without copies; migration notes for
  Interlock.
- **3.5** Scale tests, and the open-time and memory gates (§5.2).

### Phase 4: 0.7.0, signing parity

- **4.1** `RemoteSigner` and `HttpRemoteSigner` in agentgov, with `Signer.public_key()` and
  `AsyncSigner`. Interlock switches its imports.
- **4.2** Keyring verification everywhere, so a reopen makes no signer calls.
- **4.3** Pipelined issuance and the background witness publisher.
- **4.4** ARC1 1.2: signature version 2 and key transitions, with vectors. Verifiers accept 1.0
  through 1.2.
- **4.5** Signed, and optionally witnessed, ledger checkpoints.
- **4.6** The AWS KMS adapter and a fake key service.
- **4.7** A receipt log that opens in constant time.

### Phase 5: 0.8.0, the fleet write path and HA

- **5.1** Fewer round trips.
- **5.2** The group-commit writer and `AsyncBudgetManager`.
- **5.3** `transaction()`, `try_authorize()`, idempotency keys, `authorization()`, and current
  reads.
- **5.4** PgBouncer support and its CI job; PostgreSQL 17 and 18 in the matrix.
- **5.5** `LedgerRollbackError`, monotonic timestamps, the fleet-wide velocity option, and the
  failover runbook.
- **5.6** The `Metrics` protocol and the OpenTelemetry extra.

*Done when* the §5.4 targets hold and the full suite passes behind PgBouncer.

### Phase 6: 0.9.0, the freeze

- **6.1** Split the public API from the SPI, cut down `__all__`, add deprecations for what 2.0
  removes, and publish an API reference.
- **6.2** The CLI on PostgreSQL, and `agentgov.open(url)`.
- **6.3** Docs:
  - the README's limitations section rewritten;
  - `docs/MIGRATING_TO_1.0.md`;
  - `SECURITY.md` with the keyed-ledger threat model;
  - an operations runbook covering backup and restore, failover, rotation, and checkpoint tuning.
- **6.4** Release engineering:
  - trusted publishing with attestations, and an SBOM;
  - corrected classifiers, and the stale build tables removed;
  - Windows and 3.14t in CI.

### Phase 7: 1.0.0rc1, then 1.0.0

- **7.1** Publish rc1 to PyPI, and run Interlock's full suite and soak against it.
- **7.2** Get a clean 72-hour soak and chaos matrix:
  - no invariant violated;
  - memory flat;
  - no connection leaked;
  - every performance gate met.
- **7.3** Run a final mutation pass, then tag 1.0.0.

**After 1.0:**
- partitioned chains, if D5 calls for them;
- inclusion proofs for ledger entries;
- interoperability with public transparency-log witnesses (C2SP `tlog-witness`);
- Google Cloud KMS and PKCS#11 adapters.

---

## 7. Decisions needed before Phase 1

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Default verification at open | checkpoint plus auditor / full replay | Checkpoint plus auditor for writers. Full replay in the CLI and on request |
| D2 | Signed ledger checkpoints | required / optional | Optional in the API, but documented as required in production |
| D3 | ARC1 1.2 digest-then-sign | adopt / cap documents at 4 KB | Adopt. A size cap would fail at run time, on the receipts that matter most |
| D4 | ECDSA P-256 in ARC1 | 1.0 / later / never | Later, unless a deployment needs an HSM without Ed25519. The `alg` field already allows it |
| D5 | Partitioned chains | 1.0 / 1.1 if measured necessary | 1.1, and only if Phase 5 misses its targets |
| D6 | `Ledger.post()` and the `*Exception` aliases | remove in 1.0 / deprecate until 2.0 | Remove `Ledger.post()` in 1.0, because it can make a ledger unopenable. Keep the aliases, deprecated, until 2.0 |
| D7 | The distribution name `interlock-agentgov` | keep / rename | Your call. A rename is cheapest before 1.0 |
| D8 | KMS adapters in 1.0 | HTTP only / plus AWS / plus GCP and PKCS#11 | HTTP plus AWS |
| D9 | When one operation in a group commit fails | isolate it / fail the batch | Isolate it. Failing the batch couples unrelated callers |
| D10 | A 0.4.1 patch release | ship it / fold into 0.5.0 | Ship it. Interlock pins `>=0.4.0`, so it gets the fix with no code change |

---

## 8. Non-goals for 1.0

- **A server.** agentgov stays a library, and the database is the point of coordination.
- **Holds that expire on their own.** Voiding a hold asserts that its call will never settle, which
  agentgov cannot know. This is unchanged from the README.
- **The recovery protocol** (ARCHITECTURE.md, Part B) **and an LLM-judge observer.**
- **Units other than USD.** A unit per root can be added later, additively.
- **Deleting history.** Signed segments can be exported, but nothing is pruned, and the triggers
  still refuse deletion.
- **Public witness networks** (C2SP `tlog-witness`). These come in 1.x.

---

## 9. Risks

| Risk | Mitigation |
|---|---|
| The checkpoint trust model is misunderstood | Put §5.2's statement in SECURITY.md, turn the auditor on by default, and document signed checkpoints as the production setting |
| A format upgrade makes old ledgers unopenable | Old versions verify under their own rules. Upgrades are tested in CI from fixtures written by every release, and read-only opens never upgrade |
| Group commit couples callers or adds races | Failures are isolated per operation; model-based and linearizability tests; an opt-out for one release |
| A lock-free open misses a concurrent repair | A repair always re-reads under the lock before it writes |
| Pipelined issuance reorders the log or leaves a gap | The sequencer appends strictly in index order, and a failure re-reserves the tail. Tests kill the signer mid-pipeline |
| Scope delays 1.0 | Phase gates. Partitions, and every adapter beyond AWS, are deferred |
| Interlock breaks | The downstream job from Phase 0. Until 2.0, changes are deprecations rather than removals, except `Ledger.post()` |

---

## 10. What changes in Interlock

Once the agentgov side lands:

- **Imports.** Import `RemoteSigner` and `HttpRemoteSigner` from agentgov (Phase 4.1).
- **No more private mutex.** Replace `governor.ledger.lock` with `transaction()` and
  `try_authorize()` (Phase 5.3).
- **No more full scans.** Replace full `audit_trail()` scans with `find_entries()` (Phase 3.4), at:
  - `vacuum.py:998`
  - `settlement.py:591`
  - `operators.py:267`
  - `extension.py:385`
- **Keep one receipt log across a rotation** (Phase 4.4).
- **Reopen freely.** Reopening a governor becomes cheap (Phase 1.1). Keeping governors open still
  saves the warm-up.
- **One signer configuration.** Sign ledger checkpoints with the same `[signers]` entries as
  everything else.

---

## Appendix A: Measurements

**Environment.**
- An Apple Silicon laptop (aarch64), CPython 3.11.14, agentgov 0.4.0 from this checkout, the SQLite
  store.
- One run per size.
- The absolute numbers will differ on CI hardware. Phase 0 re-baselines them there.

**Method.**
- **Building the ledgers.** Each ledger was built with `open_sqlite(..., synchronous="OFF")`: one
  root, eight delegated scopes, then N calls to `spend()` of 0.00001, at three entries each.
- **Open.** This is `BudgetManager.open_sqlite(path)`, timed as a whole.
- **Phases.** These are timed separately, in the order the constructor runs them:
  - `store.load()`;
  - `_replay()` over the loaded entries;
  - `_Governance.from_chain()`;
  - `verify_integrity()` on a read-only manager.
- **Copy.** This is the `[*entries, *new]` list that `_catch_up()` republishes.
- **Memory.** This is the `tracemalloc` growth while a manager is opened and held.
- **Hashing.** This is `LedgerEntry.recompute_hash()` over the 150,017 entries, compared against
  `hashlib.sha256` over 300 bytes.

| Entries | Open | Per entry | Load | Replay | Governance | `verify_integrity()` | Copy | Memory per entry | File per entry |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 9,017 | 270.6 ms | 30.0 µs | 81.0 ms | 71.6 ms | 3.0 ms | 75.8 ms | 0.02 ms | 1,156 B | 428 B |
| 45,017 | 1,299.6 ms | 28.9 µs | 577.5 ms | 360.0 ms | 15.0 ms | 369.6 ms | 0.17 ms | 1,126 B | 424 B |
| 150,017 | 4,822.8 ms | 32.1 µs | 2,099.4 ms | 1,303.5 ms | 54.9 ms | 1,227.1 ms | 0.89 ms | 1,121 B | 424 B |

**Hashing.** `recompute_hash()` costs 5.48 µs per entry, of which SHA-256 is 0.38 µs.

**Extrapolations (§3.1).** These divide the default timeouts by the measured cost per entry:
- 30 s / 31 µs ≈ 1.0M entries;
- 60 s / 31 µs ≈ 1.9M entries.

On PostgreSQL, the load phase adds network transfer and parses rows differently. Replay and
verification, which are about 60% of open, are identical.

## Appendix B: Reproductions

Each of these runs against an unmodified 0.4.0 checkout with `uv run python`.

```python
# F3: the caller's decimal context reaches the ledger
import decimal
import tempfile
from pathlib import Path

from agentgov import BudgetManager, money

db = str(Path(tempfile.mkdtemp()) / "f3.db")
with BudgetManager.open_sqlite(db) as gov:
    gov.open_root("r", money("123456.78901234"))
    with decimal.localcontext() as ctx:
        ctx.prec = 6
        gov.spend("r", "0.00000001")  # accepted; available() is now 123457
BudgetManager.open_sqlite(db)
# LedgerIntegrityError: entry 2 records a balance of 123457, but the chain implies
# 123456.78901233. The same with repair=True.
```

```python
# F4: a raw post that the governance rules refuse on replay
import tempfile
from pathlib import Path

from agentgov import BudgetManager, money
from agentgov.core import Direction, EntryType, LedgerLine

db = str(Path(tempfile.mkdtemp()) / "f4.db")
with BudgetManager.open_sqlite(db) as gov:
    gov.open_root("root", money("1"))
    gov.delegate("root", "child", money("0.5"))
    gov.ledger.post([LedgerLine(EntryType.FUNDING, Direction.CREDIT, "child", money("1000"))])
    print(gov.available("child"))  # 1000.50000000
BudgetManager.open_sqlite(db)
# LedgerIntegrityError: entry 4 funds a scope that is not a root. The same with repair=True.
```

```python
# F5: a refund larger than anything spent
from agentgov import BudgetManager, money

gov = BudgetManager()
gov.open_root("root", money("1.00"))
gov.delegate("root", "child", money("0.10"))
gov.refund("child", money("1000"))
print(gov.available("child"))  # 1000.10000000
gov.verify_integrity()  # passes
```

```python
# F6: a memo that forges an audit line
import logging

from agentgov import BudgetManager, money

logging.basicConfig(level=logging.INFO, format="%(message)s")
gov = BudgetManager()
gov.open_root("ops", money("5"))
gov.anchor("ops", "x\nAGOV2|seq=0000000099|type=funding|dir=CR|scope=ops|amt=1000000")
# Three lines for two entries; the third is the forgery.
```

## Appendix C: Sources

- **AWS, *Sign*, AWS KMS API Reference.** Raw messages are limited to 4096 bytes.
  `ED25519_SHA_512` is used with `RAW`, and `ED25519_PH_SHA_512` with `DIGEST`.
  <https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html>
- **AWS, *AWS KMS now supports Edwards-curve Digital Signature Algorithm (EdDSA)*,** November 2025.
  <https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/>
- **Google Cloud, *Key purposes and algorithms*.** `EC_SIGN_ED25519` is PureEdDSA over data.
  <https://docs.cloud.google.com/kms/docs/algorithms>
- **Azure Key Vault.** Ed25519 support could not be confirmed from Microsoft documentation in this
  review.
- **Interlock v1.0.1.**
  - `src/interlock/signers.py`
  - `docs/EPIC8_DESIGN.md`, §8 and §9
  - `docs/EPIC9_DESIGN.md`, §3.3
  - commit `1a63718`
  - the call sites cited in §3.7 and §10
