# Security

AgentGov sits between an agent and its model provider, so it necessarily
*sees* every prompt an agent sends, and its ledger decides what an agent may
spend. This document states exactly what it keeps, where that lands, who can
change the ledger and what detects the change, and what it deliberately does
not do — so a platform or security team can make a decision without reading
the source.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public
issue: open a [GitHub security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Expect an acknowledgement within a week.

Please include a reproduction and the AgentGov version. If the issue involves
prompt content, redact it — the report should not be the leak.

Fixes land on `main` and ship in the next 1.x release; there is no backport
branch for earlier releases.

---

## Data map: what is stored, and where

### 1. The ledger (durable: SQLite or PostgreSQL)

Written only when a governor has a store: `BudgetManager.open_sqlite()`,
`BudgetManager.open_postgres()`, or `agentgov.open()` with a `sqlite:` or
`postgresql:` URL. An in-memory `BudgetManager()` writes nothing to disk.

| Stored | Contains prompt content? |
|---|---|
| Scope ids (`"orchestrator"`, `"worker.3"`) | Only if **you** put it there — these are your names |
| Amounts, balances, timestamps, hash chain | No |
| Entry memos | **Only if you pass it.** AgentGov's own memos are fixed strings (`"settled call cost"`, `"authorization hold"`). The `memo=` parameter is caller-controlled — do not pass prompt text |
| Control-event reasons | Detector name and statistics. The cognitive breaker's reasons quote *similarity scores and counts*, never the text |
| Token counts and costs | No |
| Checkpoint snapshots | Nothing new: a copy of the state the chain implies (balances, the tree, open holds with their memos, breaker reasons) and its signed statement |
| Idempotency records | Your **key**, and the call it was used for: operation, scope, amount and memo. Do not derive keys from prompt text |
| Audit marks | How far an auditor verified, and its name: host and PID unless you name it |
| Settlement claims (PostgreSQL) | A claim's scope, amount, memo and hold, until it is booked |

**The ledger never stores prompts, completions, or arguments.** It stores money
and structure. The only text in it is what you pass as scope ids, memos and
idempotency keys.

A PostgreSQL ledger also holds `join_key`, a random secret from which the tokens
of joined transactions are derived. The ledger's owner and the governors that
join callers' transactions can read it; a joined role never can.

### 2. The cognitive breaker (in memory, never persisted)

`CognitiveBreaker` holds nothing on disk. In memory, per observed call:

| Field | Default | Notes |
|---|---|---|
| `fingerprint` | always | Salted BLAKE2b digest. The salt is random per breaker instance, so a digest is not a lookup key for a known prompt and is not comparable across processes |
| `shingles` | always | A set of character trigrams over redacted text, capped by `max_argument_chars`. **Treat as derived prompt data, not as a hash** — a trigram set of short text is substantially reconstructible |
| `result_shingles` | when results are recorded | Same caveat, over model output |
| `arguments` | **empty** | Readable text is retained *only* when you set `CognitivePolicy(retain_arguments=True)`, and is truncated to `max_argument_chars` even then |

Everything is bounded: `history_limit` calls per trajectory,
`max_trajectories` trajectories, both LRU-evicted.

### 3. Logs

| Logger | Level | Contains prompt content? |
|---|---|---|
| `agentgov.audit` | INFO | Ledger lines: amounts, scopes, hashes, memos. No prompt text unless you passed it as a memo |
| `agentgov.audit` | WARNING | Circuit-breaker trips: reason, scope, ledger head hash |
| `agentgov.audit` | ERROR | An auditor's finding that the chain does not verify: the sequence, and why |
| `agentgov` | WARNING | A checkpoint, a re-read or a trip record that failed, or an auditor's failure: what failed, naming a scope at most |
| `agentgov.cognitive` | WARNING | Thrashing halts: detector name and similarity scores, **not** the text |
| `agentgov.interceptor` | INFO | Scope, model, token counts, cost, latency |
| `agentgov.receipts` | WARNING, ERROR | A torn line repaired at open, a failed issuance or checkpoint: the log's id or path, and the error |

No logger emits prompt or completion text. Set these to `CRITICAL+1` to
silence them entirely.

### 4. Metrics

A governor given a `Metrics` (or `agentgov[otel]`'s `OpenTelemetryMetrics`)
reports durations, counts and gauges under the names in
`agentgov.metrics.INSTRUMENTS`. Each carries a number and the attributes you
configure, nothing else: no scope id, memo or amount.

---

## Redaction

If your prompts carry regulated data, install a `Redactor`. It runs at the
single ingress through which every argument and result passes, **before**
anything is fingerprinted, shingled, or stored:

```python
class MaskPII:
    def redact(self, tool: str, text: str) -> str:
        return SSN_PATTERN.sub("<ssn>", text)


breaker = CognitiveBreaker(redactor=MaskPII())
```

A redactor that raises is treated as a failure to vouch for the text: the call
is observed with **no** text at all rather than with unredacted text. Detection
degrades; content does not leak because of a bug in your regex.

---

## Encryption at rest, and in transit

**AgentGov encrypts nothing itself.** Python's bundled `sqlite3` has no
encryption support, and shipping a homegrown scheme would be worse than being
clear that there isn't one.

If the ledger holds anything you consider sensitive — including scope ids that
name customers, or memos you populated — keep it where storage is encrypted:

- **SQLite.** Put the database on an encrypted volume (LUKS, FileVault, a
  KMS-encrypted EBS volume) and set filesystem permissions so only the
  governor's user can read it. The lock sidecar (`<db>.lock`) contains a PID,
  hostname, and timestamp, nothing else.
- **PostgreSQL.** Use the server's encrypted storage, connect over TLS
  (`sslmode=verify-full` in the connection string), and grant the ledger's
  tables to no role that does not need them
  ([docs/OPERATIONS.md](docs/OPERATIONS.md#the-database)). Backups and
  replicas hold everything the ledger does.

## Integrity: who can change the ledger, and what detects it

The ledger decides what may be spent, so its integrity is the property that
matters most. This section states who can change it, what each layer of
protection detects, and what none of them prevents.

### What the chain proves

The ledger is a SHA-256 hash chain of canonical entries
([docs/LEDGER_FORMAT.md](docs/LEDGER_FORMAT.md)). Each entry's hash covers its
content and the hash of the entry before it, so an edit to any entry breaks
every link after it. The chain also carries the state that decides what may
run, and every replay re-checks it by the same rules every write obeys:

- **Hold pairing.** Every hold release names the hold it releases inside its
  hash, and the ledger refuses a release of a hold that is not open. A hold
  cannot be returned twice, even by a crash-recovery path.
- **Breakers and topology.** Trips, resets and delegations are entries in the
  chain. Deleting a trip row, or re-parenting a scope out from under a halted
  parent, does not un-halt anything: the `nodes`, `control_events` and
  `open_authorizations` tables are caches, checked against the chain at open
  and by `verify_integrity()`. A disagreement is refused, and `agentgov repair`
  rebuilds the caches from the chain without moving money.
- **Bounds.** A scope's refunds never exceed what it spent, nor a spend's
  refunds the spend. Time never runs backwards in the chain.
- **One operation, one transaction.** An operation's entries and cache writes
  commit together or not at all, so a crash cannot leave a half-applied
  operation for a recovery path to act on twice.

**Verification refuses rather than serves.** A governor that meets an entry that
does not verify — at open, while catching up with the rest of a fleet, or
through its auditor — raises `LedgerIntegrityError` and stops writing.

### Who can change the ledger

| Who | Can | Is stopped by |
|---|---|---|
| Code in a governor's process | Anything a governor can: fund a root, `reset()` a breaker, `void_stale()` | Nothing. AgentGov is not a boundary inside a process ([Concurrency boundary](#concurrency-boundary)) |
| The fleet's database role (PostgreSQL) | Append an entry that obeys the rules, as a governor would; edit the cache tables | The triggers, which refuse an edit, a deletion, or an entry that does not link to the head; and every governor, which refuses an entry that breaks a rule, or a cache that disagrees with the chain |
| A joined role (`grant_join`) | Claim settlement inside its own transaction, with a token derived from a secret it cannot read | It has no privilege on any table |
| Whoever can write the SQLite file or owns the PostgreSQL schema: a DBA, an attacker with the disk, whoever restores a backup | Anything: rewrite the chain from any point and re-link it, or cut entries off its tail | What the rest of this section describes |

**The fleet's database role carries a governor's authority.** Entries are not
signed one by one: an entry that links to the head and obeys the rules is valid,
whoever wrote it. Grant the role only to governors, and guard its credentials as
you would the budget.

### What an open verifies, and what the auditor adds

- **`verify="full"`**, which `agentgov verify` always uses, replays the whole
  chain from genesis before anything is served. That catches a naive edit to
  any row, and bit rot. On its own it does not catch a *consistent* rewrite,
  every entry after the edit re-hashed and re-linked, by anyone who can write
  the database: the rewritten chain links as well as the original did.
- **`verify="checkpoint"`, the default for writers,** checks the newest
  checkpoint's snapshot against the digest a chain entry commits to, and
  replays every entry after it. An edit to a row *before* that checkpoint is no
  longer caught at open. It is caught by the **auditor**, which replays the
  chain from genesis off the hot path and checks that each checkpoint's
  snapshot is the state the chain implies there. A governor that opened from a
  checkpoint runs one in a thread unless told not to (`auditor=False`, where a
  sidecar runs `agentgov audit --follow`). An auditor that finds a mismatch
  records it in the ledger's database: every governor then refuses to open for
  writing, and the one whose auditor found it stops writing.
- **Audit marks are rows in the same database, and are not signed.** Anyone who
  can insert into it, the fleet's role included, can forge one. A forged
  "verified" mark lets an auditor that resumes from it skip what came before;
  a forged failure stops the fleet's writers until an audit verifies past it.
  `agentgov audit --from-genesis` and `agentgov verify` trust no mark.

### What a key adds: signed checkpoints

Without a key, a checkpoint is trusted for everything before it: a consistent
rewrite of that history, with the snapshot and checkpoint entries recomputed to
match, opens as well as the original. With `CheckpointSigning(signer=...,
keys=..., required=True)`, every checkpoint carries a statement signed by the
ledger's key. It names the ledger (by its first entry), the checkpoint's
sequence and head, the Merkle root of every entry up to it, and the snapshot's
digest. A governor so configured checks the newest checkpoint's statement at
every open, whether it opens from that checkpoint or replays from genesis. It
refuses a statement that is missing, signed by a key it does not trust, or made
for another state. `agentgov verify` and `agentgov audit` check every statement
they reach, given `--checkpoint-key` (and `--require-signed`).

**Rewriting any history a signed checkpoint covers then takes the key as well as
the database.** That is the production setting. `required=False` accepts an
unsigned checkpoint, so stripping the signature defeats it. It is there to move
a ledger with unsigned checkpoints onto signed ones.

The signature does not cover:

- **The entries after the newest checkpoint.** They are hash-chained, not
  signed: up to `checkpoint_every` entries (10,000 by default), and more while
  the signer is unavailable (`checkpoint_lag()` says how many).
- **A cut back to an earlier checkpoint.** Deleting the newest entries,
  checkpoints included, leaves a shorter chain whose newest checkpoint is still
  genuinely signed. History rewritten from there is a fork the signature cannot
  tell from the original.
- **A ledger replaced whole by one with no checkpoints.** Nothing in it is
  signed, so there is nothing to refuse.
- **Whoever can use the key.** A key held by a key service (`AwsKmsSigner`, or
  any `RemoteSigner`) cannot be copied, but a host allowed to call it can sign
  anything, a rewritten history included. Governors sign checkpoints, so a
  signature protects the ledger from those who can write its database, not from
  a compromised governor.

### What only a record kept elsewhere shows

Each of those is caught by a record of the ledger kept where its writers cannot
reach:

- **Witnesses.** `publish_checkpoint(witnesses)` asks witnesses (`FileWitness`,
  or any ARC1 witness) to cosign the newest checkpoint, as an ARC1 checkpoint
  of the Merkle tree of the ledger's entries. A witness cosigns a tree only if
  it extends the last one that witness cosigned, so a rewritten, forked or
  cut-back history cannot be witnessed: the next publish fails with
  `WitnessError`. Publish from a periodic job and alert on that failure
  ([docs/OPERATIONS.md](docs/OPERATIONS.md#witnesses)). A witness run by
  another team, on other infrastructure, catches a compromised governor too.
- **Running governors.** A governor remembers the chain it verified. One that
  finds the ledger rewritten under it raises `LedgerIntegrityError`; one that
  finds it cut back to exactly what it verified raises `LedgerRollbackError`.
  Either stops writing.
- **Anchors.** `anchor()` commits another system's head into this chain. In
  the other direction, `ledger.head_hash`, or an ARC1 receipt's chain anchor,
  recorded in another system pins this chain from outside.

### In one table

| Change to the ledger | Detected by |
|---|---|
| A row edited, or bit rot | An open (`verify="full"`, or the entries after the newest checkpoint); the auditor; `agentgov verify` |
| An appended entry that breaks a rule | Every governor, at its next catch-up or open |
| A cache table edited | An open, and `verify_integrity()`; `agentgov repair` rebuilds it |
| History behind the newest signed checkpoint rewritten | Every open with `CheckpointSigning(required=True)`; `agentgov verify --checkpoint-key ... --require-signed` |
| The entries after the newest checkpoint rewritten, or the chain cut back | Running governors; witnesses; heads recorded elsewhere |
| The whole ledger replaced | Witnesses; heads recorded elsewhere |
| A rewrite signed by a compromised governor | Witnesses that governor does not control |

This is **tamper-evidence, not tamper-resistance.** Nothing here stops a
writer; it decides what detects their change, and when. Treat write access to
the ledger's database as write access to the audit log, and restrict it
accordingly.

ARC1 action receipts have their own security considerations:
[docs/RECEIPTS.md](docs/RECEIPTS.md), sections 12, 13.6 and 14.3.

## Concurrency boundary

**SQLite: one writer.** A governor takes an exclusive advisory lock on its
database. A second process opening the same file is refused with
`ConcurrentGovernorError`, because two writers would each cache authoritative
balances in memory and diverge. This is a correctness boundary, not a security
one — it is advisory, so a process that does not use AgentGov can still write
to the file.

**PostgreSQL: many writers, one lock.** Governors in any number of processes
serialize on a transaction-scoped advisory lock, and each verifies what the
others wrote before it acts. The triggers refuse a write from a governor that
skipped the lock or went stale: the lock is for liveness, the chain and its
triggers for safety.

**Neither is a boundary inside a process.** AgentGov is a library: any code that
can import it can call `reset()`, `trip()`, or `void_stale()`, and can call the
provider's SDK directly and spend unmetered. It bounds *accidental* spend, not
an adversary already running inside your process.

## Dependencies

The core package, the SQLite store included, has zero runtime dependencies:
standard library only. Each optional feature brings its own, installed only
with its extra and imported only when the feature is used:

| Extra | Brings | For |
|---|---|---|
| `sign` | `cryptography` | Signing with a local Ed25519 key (`Ed25519Signer`). Verifying needs nothing: there is a pure-Python RFC 8032 fallback |
| `postgres` | `psycopg[binary]` | The shared ledger (`agentgov.postgres`) |
| `kms-aws` | `boto3` | `AwsKmsSigner` |
| `otel` | `opentelemetry-api` | `OpenTelemetryMetrics` |
| `ui` | `streamlit` | The example dashboard |

The development toolchain (pytest, ruff, mypy, hypothesis) is pinned in
`uv.lock`.
