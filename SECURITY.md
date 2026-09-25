# Security

AgentGov sits between an agent and its model provider, so it necessarily
*sees* every prompt an agent sends. This document states exactly what it keeps,
where that lands, and what it deliberately does not do — so a platform or
security team can make a decision without reading the source.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public
issue: open a [GitHub security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Expect an acknowledgement within a week.

Please include a reproduction and the AgentGov version. If the issue involves
prompt content, redact it — the report should not be the leak.

AgentGov is pre-1.0. Fixes land on `main`; there is no backport branch yet.

---

## Data map: what is stored, and where

### 1. The SQLite ledger (durable, on disk)

Written only when you opt into persistence with `BudgetManager.open_sqlite()`.
An in-memory `BudgetManager()` writes nothing to disk.

| Stored | Contains prompt content? |
|---|---|
| Scope ids (`"orchestrator"`, `"worker.3"`) | Only if **you** put it there — these are your names |
| Amounts, balances, timestamps, hash chain | No |
| Entry memos | **Only if you pass it.** AgentGov's own memos are fixed strings (`"settled call cost"`, `"authorization hold"`). The `memo=` parameter is caller-controlled — do not pass prompt text |
| Control-event reasons | Detector name and statistics. The cognitive breaker's reasons quote *similarity scores and counts*, never the text |
| Token counts and costs | No |

**The ledger never stores prompts, completions, or arguments.** It stores money
and structure.

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
| `agentgov.cognitive` | WARNING | Thrashing halts: detector name and similarity scores, **not** the text |
| `agentgov.interceptor` | INFO | Scope, model, token counts, cost, latency |

No logger emits prompt or completion text. Set these to `CRITICAL+1` to
silence them entirely.

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

## Encryption at rest

**AgentGov does not encrypt the SQLite file.** Python's bundled `sqlite3` has
no encryption support, and shipping a homegrown scheme would be worse than
being clear that there isn't one.

If the ledger holds anything you consider sensitive — including scope ids that
name customers, or memos you populated — put the database on an encrypted
volume (LUKS, FileVault, a KMS-encrypted EBS volume) and set filesystem
permissions so only the governor's user can read it. The lock sidecar
(`<db>.lock`) contains a PID, hostname, and timestamp, nothing else.

## Integrity, and what it does and does not protect

The ledger is a SHA-256 hash chain: `verify_integrity()` re-derives every entry
and detects any retroactive edit, including a doctored balance. A corrupted or
tampered database is refused at open rather than served.

Since v0.1.2 the chain also carries the state that decides what may run:

- **Hold pairing.** Every hold release names the hold it releases inside its
  hash, and the ledger refuses a release of a hold that is not open. A hold
  cannot be returned twice, even by a crash-recovery path.
- **Breakers and topology.** Trips, resets and delegations are entries in the
  chain. Deleting a trip row, or re-parenting a scope out from under a halted
  parent, no longer un-halts anything: the `nodes`, `control_events` and
  `open_authorizations` tables are caches, checked against the chain at open
  and by `verify_integrity()`. A disagreement is refused, and `agentgov repair`
  rebuilds the caches from the chain without moving money.
- **One operation, one transaction.** An operation's entries and cache writes
  commit together or not at all, so a crash cannot leave a half-applied
  operation for a recovery path to act on twice.

This is **tamper-evidence, not tamper-resistance.** Anyone who can write to the
file can rewrite the whole chain from any point and re-link it, or cut entries
off its tail, because the chain is keyless and not anchored to anything outside
the file. Detecting that requires periodically copying `ledger.head_hash`
somewhere the writer cannot reach, or committing it into another system's chain
with `BudgetManager.anchor()`.
Treat write access to the database as equivalent to write access to the audit
log, and restrict it accordingly.

## Concurrency boundary

A governor takes an exclusive advisory lock on its database. A second process
opening the same file is refused with `ConcurrentGovernorError`, because two
writers would each cache authoritative balances in memory and diverge. This is
a correctness boundary, not a security one — it is advisory, so a process that
does not use AgentGov can still write to the file.

**AgentGov is a single-process governor.** It is not a trust boundary between
mutually distrusting agents in one process: any code that can import the module
can call `reset()`, `trip()`, or `void_stale()`. It bounds *accidental* spend,
not an adversary already running inside your process.

## Dependencies

Zero runtime dependencies — standard library only. The development toolchain
(pytest, ruff, mypy) is pinned in `uv.lock`.
