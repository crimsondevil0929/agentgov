# Migrating to agentgov 1.0

This guide is for code and ledgers written against agentgov 0.4. Ledgers
written by any release since 0.1.0 upgrade to 1.0 the same way, so it serves
earlier releases too. The distribution is still `interlock-agentgov` and the
package still `agentgov`; Python 3.11 or later, as before.

Most code runs unchanged. What needs attention, roughly in order of how likely
it is to affect you:

1. [Back up the ledger, and upgrade a fleet all at once](#before-you-upgrade):
   1.0 upgrades a ledger in place, and 0.4 cannot open the result.
2. [Opening no longer takes the fleet's writer lock](#opening-no-longer-takes-the-writer-lock),
   so an open is no longer a way to probe it.
3. [Refunds are bounded by what was spent](#refunds-are-bounded).
4. [`Ledger.post()` is gone](#ledgerpost-is-removed).
5. [History is read from the store, and holds `CHECKPOINT` entries](#history-lives-in-the-store).
6. [`ledger.lock` is deprecated in favour of `transaction()`](#transaction-replaces-ledgerlock).
7. [Concurrent callers share units of work](#concurrent-callers-share-units-of-work).

Every name 1.0 moved or retired, other than `Ledger.post()`, is still served
until 2.0 with a `DeprecationWarning` that says what to use instead. Run your
tests with `-W error::DeprecationWarning` to find them.

## Before you upgrade

**Back up the ledger.** The first time 1.0 opens a ledger for writing, it
upgrades it in place: SQLite to schema 3, PostgreSQL to layout `pg2`. The upgrade
adds tables (checkpoint snapshots, audit marks, idempotency records) and indexes
on history. It does not rewrite a single entry. 0.4 refuses the upgraded ledger,
rather than misreading it:

```
LedgerIntegrityError: database schema version '3' does not match this version
of agentgov ('2'); refusing to open a file this version cannot interpret
```

A backup taken before the upgrade is the way back. See
[docs/OPERATIONS.md](OPERATIONS.md#backup-and-restore) for taking one while a
governor runs.

**Upgrade a fleet all at once.** Stop every 0.x governor of a shared ledger
before the first 1.0 governor opens it for writing. A 0.4 governor still running
when the layout is upgraded refuses its next write with `LedgerIntegrityError`
("layout version 'pg2'; this version of agentgov reads ['pg1']"): nothing is
corrupted, but it stops. The upgrade needs the ledger's owner role, as the
install did.

**Read-only opens never upgrade.** A 1.0 view (`read_only=True`, or any
`agentgov` CLI command other than `repair` and `checkpoint`) reads a 0.x ledger
as it is.

## Your ledger

- **Old entries keep their format.** Entries written before 1.0 keep the audit
  version they were written with (`AGOV1` or `AGOV2`) and verify under their own
  rules. New entries are `AGOV3`: canonical JSON (RFC 8785), fixed-point amounts,
  specified in [docs/LEDGER_FORMAT.md](LEDGER_FORMAT.md) for anyone writing an
  independent verifier.
- **Text has limits.** An `AGOV3` scope id or counterparty is at most 1,024
  bytes of UTF-8 and holds no control character; a memo is at most 65,536 bytes
  and holds no NUL; no text holds a lone surrogate. A call that breaks a limit
  raises `ValueError` and writes nothing. An idempotency key is at most 255
  bytes, with no control character.
- **Time never runs backwards in the chain.** An entry's timestamp is the later
  of the clock and the newest entry's, so a host whose clock steps back does not
  write entries dated before ones already in the chain.
- **Balances use the ledger's own decimal context.** Every balance and total is
  computed in a fixed context, never the calling thread's. A host that lowered
  `decimal.getcontext().prec` can no longer write a balance a replay does not
  reproduce. No code change is needed.

## Changes that can break code

### Opening no longer takes the writer lock

A governor opens from one consistent snapshot, without the fleet's writer lock,
so an open never stalls the fleet (0.4 stalled every writer for the whole open).
The first mutation catches up under the lock, as every mutation does.

Code that tested whether a writer was mid-transaction by trying to open a
governor with a short `lock_timeout` now always succeeds. Probe the lock
instead; this writes nothing:

```python
from agentgov.postgres import PostgresStore

store = PostgresStore(dsn, read_only=True)
try:
    busy = store.writer_lock_held(0.3)  # True if another transaction holds it
finally:
    store.close()
```

### Refunds are bounded

A scope's refunds can no longer exceed what it has spent, so `available()` never
exceeds what the scope was granted. A refund past the bound raises
`ValueError` ("cannot refund 0.25 to 'agent': it has spent 0.05 and been
refunded 0, so at most 0.05 remains refundable") and writes nothing. History
written before the bound existed still opens.

Name the spend a refund reverses. Its refunds are then bounded by that spend as
well, and the warning 1.0 gives for an unnamed refund goes away:

```python
spend = gov.spend("agent", cost)  # the SPEND entry
gov.refund("agent", cost, reverses=spend)  # or its entry_id
```

### `Ledger.post()` is removed

`Ledger.post()` wrote entries past the governor, and could commit what a later
open refused, making the ledger unopenable. Use the governor's operations
(`fund`, `delegate`, `authorize`, `capture`, `spend`, `refund`, `anchor`), and
`transaction()` to make several of them one atomic step. `LedgerLine`, its
argument type, is deprecated.

### History lives in the store

A governor over a store keeps the chain's *state* in memory (balances, the tree,
open holds), not its entries, so its memory is flat however long the ledger
grows. History is read from the store when asked for:

| Instead of | Use |
|---|---|
| `audit_trail()` over a long ledger | `iter_audit_trail()`: the same entries, read a chunk at a time |
| Scanning entries for a scope, a type or an anchor's memo | `find_entries(scope_id=..., entry_type=..., memo=...)`, which reads only what matches, by index. `transaction_id=` and `ref=` filter what those find |
| `gov.ledger.entries()[n - 1]` | `gov.entry(n)` |
| Paging through history | `gov.entries(after=..., limit=...)` |

`audit_trail()` and `ledger.entries()` still work. Each reads all of history
from the store, a cost that grows with the ledger.

**The chain holds `CHECKPOINT` entries.** Every
`GovernancePolicy.checkpoint_every` entries (10,000 by default) a governor
writes a checkpoint: a snapshot of the state, committed into the chain by a
zero-value `EntryType.CHECKPOINT` entry with an empty scope id. Code that walks
history and expects every entry to name a scope should skip them, by
`entry.entry_type`. `checkpoint_every=0` turns automatic checkpoints off, and
opens then replay from the last one.

### `transaction()` replaces `ledger.lock`

Holding `gov.ledger.lock` around a check and the act it decides is atomic within
one process only: on a shared ledger another governor can act between the two.
`ledger.lock` is deprecated. `transaction()` makes the check and the act one
step across the fleet:

```python
# 0.4
with gov.ledger.lock:
    if gov.available("agent") >= cost:
        hold = gov.authorize("agent", cost)

# 1.0
with gov.transaction() as txn:
    if txn.available("agent") >= cost:
        hold = txn.authorize("agent", cost)
```

Inside a transaction, reads are current: on a shared ledger the writer lock is
held and the view caught up under it. Every mutation joins one commit. A block
that raises writes nothing, unlike `ledger.lock`, where each mutation inside
committed on its own. A breaker trip recorded inside still commits: it belongs
to the breaker, not to the block. Transactions do not nest and belong to the
thread that opened them.

When the check is only "can this scope pay?", `try_authorize()` is shorter. It
places the hold, or returns `None` and writes nothing, without tripping the
breaker:

```python
hold = gov.try_authorize("agent", cost)
if hold is None:
    ...  # cannot pay; nothing was written and nothing tripped
```

### Concurrent callers share units of work

Callers of one governor that arrive together share a unit of work: one writer
lock, one catch-up and one commit for all of them, on PostgreSQL and on SQLite
(one sync of the file instead of one each). With a unit of work down to two
round trips, this took one governor with eight callers from 425 operations a second
on PostgreSQL to about 2,100, measured side by side
([benchmarks](../benchmarks/README.md#throughput)). What a caller sees:

- **Its own failure is its own.** A refused authorization raises its error and
  writes nothing, and the others commit as if alone.
- **A failed commit fails every mutation it carried.** Each caller gets the
  `StorageError`, and the governor re-reads the ledger at once, before it serves
  another read. (0.4 re-read lazily, on the next mutation.)
- **A commit whose answer was lost** is reported as `StorageError` and never
  retried blind. Retry with an [idempotency key](#idempotency-keys) to learn
  whether it committed.

### Deprecated names

Each still works until 2.0, and warns:

| Deprecated | Use |
|---|---|
| `from agentgov import WriteBatch` (and the other store types) | `from agentgov.spi import WriteBatch`: the store-implementer's interface moved to `agentgov.spi` |
| `AgentThrashingException`, `DenialOfWalletException` | `AgentThrashingError`, `DenialOfWalletError` (the same classes) |
| `gov.ledger.lock` | `gov.transaction()`, or `try_authorize()` |
| `LedgerLine` | The governor's operations |
| `refund()` without `reverses=` | `refund(..., reverses=spend)`, the SPEND entry or its id |

[docs/API.md](API.md) lists the 1.0 API, frozen for 1.x: names are added or
deprecated, never removed.

### Smaller changes

- **Audit lines escape free text.** In `format_audit_line()` and the
  `agentgov.audit` logger, a scope id, counterparty or memo that is not
  printable ASCII, or holds `|` or `\`, is written as the body of a JSON string,
  so it stays one field of one line (CWE-117). `json.loads('"' + field + '"')`
  recovers it. Ordinary ids and memos are unchanged.
- **Async calls write off the event loop.** `ainvoke()` and async streams place
  and settle holds on a worker thread. A task cancelled mid-write lets the write
  finish, releases a hold placed for a call that will never be made, and then
  raises the cancellation.
- **Two background threads.** A writer that opened from a checkpoint runs an
  auditor thread, a quarter of one core, replaying the history before the
  checkpoint (`auditor=False` turns it off). A `ReceiptLog` publishes
  checkpoints from a thread of its own (below).
- **`verify_integrity()` runs outside the governor's lock.** Writes continue
  while it replays.
- **The CLI takes URLs.** Every ledger command takes a SQLite path or a URL
  (`sqlite:///path`, `postgresql://...?schema=...`). `verify` also checks every
  checkpoint snapshot, and `audit`, `checkpoint` and `export --from-seq` are new.

## Receipts (ARC1)

ARC1 1.0 and 1.1 documents, logs and vectors are byte-for-byte unchanged, and
1.0 verifies all of them.

- **`RemoteSigner` and `HttpRemoteSigner` live in
  `agentgov.receipts.signing`,** API-identical to Interlock's `interlock.signers`.
  `AwsKmsSigner` (`agentgov.receipts.kms_aws`, the `kms-aws` extra) signs with
  an Ed25519 key held by AWS KMS.
- **A log publishes checkpoints in the background.** `issue()` returns once the
  receipt is durable; `flush()` publishes what is due now, and `close()`
  publishes before it releases the log.
  `ReceiptLog(..., policy=CheckpointPolicy(background=False))` keeps publishing
  inline.
- **Keys, not signers, verify.** A `ReceiptLog` reopens under a keyring (its
  signer's key, plus any passed as `keyring=`), and a `FileWitness` under its
  own public key: neither calls a signer to reopen. `FileWitness(logs=...)`
  takes a key or a keyring per log; `verify_bundle()` and `find_cosignature()`
  take keyrings; `agentgov verify-receipt` takes repeated `--pubkey` options.
- **A log's key can rotate in place.** `ReceiptLog.rotate(new_signer)` writes
  an ARC1 1.2 key transition to `<path>.transitions`, so rotating no longer
  means starting a new log. A log with transitions opens only with the signer
  of the key in force. Verifiers follow transitions with
  `verify_bundle(transitions=...)` or `verify-receipt --transitions`.
- **Signature version 2 is opt-in.** `signature_version=2` on `ReceiptLog`,
  `FileWitness` and a document's `sign()` signs a digest, so a key service with
  a message limit signs any receipt. A signer can make it its default with a
  `signature_version` attribute. 1.0 verifies both versions.
- **A log keeps an index beside it,** `<path>.index` (SQLite), so it reopens
  without reading the receipts its checkpoints cover. It still checks every
  checkpoint's signature, so a log whose key changed without a transition
  reopens only with the old public key in `keyring=`. The index is derived
  from the log and rebuilt when missing; back up the log file, not the index.

## New in 1.0, worth adopting

### Idempotency keys

`authorize`, `try_authorize`, `capture`, `void`, `spend`, `refund`, `fund` and
`delegate` take `idempotency_key=`. The call is recorded in the same transaction
as its entries. A retry with the same key and arguments returns the recorded
result and writes nothing: on any governor of the fleet, after a restart, or
after a commit whose answer was lost.

```python
hold = gov.authorize("agent", cost, idempotency_key=f"request-{request_id}")
```

The same key with different arguments raises `IdempotencyConflictError`. A
refused call records nothing, so it can be retried once the scope can pay.

### More

- **`agentgov.open(url)`** opens any ledger: `memory:`, `sqlite:///path`,
  `postgresql://...?schema=...`.
- **`AsyncBudgetManager`**: the governor's operations as coroutines that never
  block the event loop and share its group commit.
- **`authorization(id)`** finds a hold placed by another governor, to capture
  it here; `available()`, `subtree_available()` and `is_halted()` take
  `fresh=True` to catch up first.
- **Signed checkpoints, witnesses and the auditor:** `CheckpointSigning`,
  `publish_checkpoint()`, `agentgov audit`. [SECURITY.md](../SECURITY.md) says
  what each protects against; [docs/OPERATIONS.md](OPERATIONS.md) how to run
  them.
- **`LedgerRollbackError`** tells a ledger cut back by a failover from one
  rewritten ([docs/OPERATIONS.md](OPERATIONS.md#failover-a-ledger-that-lost-commits)).
- **`metrics=`** reports lock waits, units of work, checkpoint lag and more;
  `agentgov.otel.OpenTelemetryMetrics` with the `otel` extra.
- **`GovernancePolicy(fleet_velocity=True)`**: one runaway-loop limit for the
  whole fleet, instead of one per governor.
- **PgBouncer in transaction mode** and PostgreSQL 14 to 18 are tested.

## For Interlock

Interlock's suite passes against 1.0 with two test changes, and its own code
needs none to keep working. What to change, and what it can now drop:

- `tests/test_crash_consistency.py` probes the writer lock by opening a
  governor with `lock_timeout=0.3`. Use
  `PostgresStore(dsn, read_only=True).writer_lock_held(0.3)` (4 tests).
- `tests/test_settlement.py::test_verify_settlements_names_a_credit_no_settlement_made`
  posts a credit beyond what was spent, which 1.0 refuses. Spend first, or
  assert the refusal (2 tests).
- `refund(scope, cost, memo=...)` warns: pass `reverses=` with the spend.
- `with governor.ledger.lock:` around a check and an act (the anchor, recovery
  and extension code) can become `with governor.transaction() as txn:`.
- `interlock.signers` can re-export `agentgov.receipts.signing`.
- Rotating a receipt key no longer needs a new receipt log: `ReceiptLog.rotate()`.
