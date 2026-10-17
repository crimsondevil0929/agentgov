# Operating agentgov

This guide is for whoever runs agentgov in production, usually a fleet of
governors over one ledger in PostgreSQL. It covers configuring the database and
the governors, backing the ledger up and restoring it, rotating keys, tuning
checkpoints, and what to do when the database, its replication, or a key service
fails. A single SQLite governor needs little of it. Where it does (checkpoints,
backups, keys), the section says so; the [README](../README.md) covers the rest.

## Production settings

A governor's defaults suit a laptop. In production:

| Setting | Why | Section |
|---|---|---|
| Synchronous replication for the ledger's database | A failover to an asynchronous standby loses commits that callers were told succeeded | [The database](#the-database) |
| Governors run as a role with DML grants only | It cannot alter the schema, lift the triggers or edit history | [The database](#the-database) |
| `CheckpointSigning(signer=..., keys=..., required=True)`, the key in a key service | Rewriting checkpointed history then takes the key as well as the database | [Keys](#key-services-and-rotation); [SECURITY.md](../SECURITY.md#what-a-key-adds-signed-checkpoints) |
| One auditor per ledger, `agentgov audit --follow`, and governors opened with `auditor=False` | The history before each checkpoint is replayed once, not by every governor | [Checkpoints and the auditor](#checkpoints-and-the-auditor) |
| `publish_checkpoint()` to witnesses run elsewhere, on a schedule | Catches a cut-back, a fork, a replaced ledger, or a compromised governor | [Witnesses](#witnesses) |
| Metrics, with alerts on them | Failing checkpoints, store errors and lock waits show here first | [Metrics and alerts](#metrics-and-alerts) |
| Backups, each checked with `agentgov verify` | A backup that does not verify is not a backup | [Backup and restore](#backup-and-restore) |

## The database

**Replication: synchronous.** Every governor verifies the whole chain it writes
on, and every receipt and anchor names a ledger head. A failover to a replica
that had not received the last commits leaves the ledger *shorter* than what the
fleet verified and what callers were told committed (see
[Failover](#failover-a-ledger-that-lost-commits)). Run the ledger's primary with
synchronous replication to at least one standby (`synchronous_commit = on`, a
non-empty `synchronous_standby_names`) and fail over only to a synchronous
standby. Asynchronous replication works, and agentgov detects what it loses;
it does not prevent the loss.

**Roles.** Install the ledger once as its owner: the first governor to open a
database creates the tables (schema layout `pg2`), and an upgrade from an older
layout needs the owner too. Run the fleet as a role granted no more than this,
which cannot alter the schema, lift the append-only triggers or edit history
(`tests/test_postgres_store.py`,
`test_a_role_with_only_dml_grants_can_run_a_governor`, pins it):

```sql
GRANT USAGE ON SCHEMA agentgov TO governor;
GRANT SELECT ON agentgov.schema_meta TO governor;
GRANT SELECT, INSERT ON agentgov.entries TO governor;
GRANT SELECT, INSERT, UPDATE, DELETE ON agentgov.nodes TO governor;
GRANT SELECT, INSERT ON agentgov.control_events TO governor;
GRANT SELECT, INSERT, DELETE ON agentgov.open_authorizations TO governor;
GRANT SELECT, INSERT ON agentgov.snapshots TO governor;
GRANT SELECT, INSERT ON agentgov.audit_marks TO governor;
GRANT SELECT, INSERT ON agentgov.idempotency TO governor;
```

A fleet that joins callers' transactions (`joined()`, `redeem()`) also reads
the join key and books claims: `GRANT SELECT ON agentgov.join_key` and
`GRANT SELECT, DELETE ON agentgov.claims`. The callers themselves, roles that
only settle with the ledger inside their own transactions, get
`PostgresStore.grant_join(role)`: no table access at all.

**Timeouts.** `lock_timeout` (30 s) bounds how long a governor waits for the
fleet's writer lock before it raises `StorageError` and changes nothing.
`idle_timeout` (60 s) is how long the server lets a governor sit idle inside a
transaction, holding the lock, before ending its session: a paused or hung
governor cannot stall the fleet for longer. Both are set in each transaction,
never on the session.

## Connection poolers

agentgov runs behind PgBouncer in **transaction mode**, and CI runs its whole
suite through one (`tests/pgbouncer/pgbouncer.ini`). The store keeps no state
on its session: each transaction sets its own lock wait and idle bound
(`SET LOCAL`), reads declare themselves `READ ONLY`, the writer lock is a
transaction's advisory lock, and no statement is prepared:
`prepare_threshold` defaults to `None`. Raise it (`open_postgres(...,
prepare_threshold=5)`, or `?prepare_threshold=5` in a ledger URL) only on a
direct connection, or behind a pooler that tracks prepared statements
(PgBouncer 1.21+ with `max_prepared_statements` set). Session mode works as a
direct connection does.

Size the pool for the fleet: every governor holds a server connection for the
whole of each unit of work, including its wait for the writer lock.

## Checkpoints and the auditor

These apply to SQLite and PostgreSQL alike.

A governor opens from its ledger's newest checkpoint. It decodes the snapshot,
in time proportional to the state (scopes and open holds), and replays the
entries after it, in time proportional to their number.
`GovernancePolicy.checkpoint_every` (10,000) bounds the second. Measured on the
laptop the [benchmarks](../benchmarks/README.md) ran on, SQLite:

| State | Snapshot | Writing a checkpoint | Opening from one at head |
|---:|---:|---:|---:|
| 100 scopes, 10 open holds | 16 KiB | 0.6 ms | 2.3 ms |
| 1,000 scopes, 100 open holds | 155 KiB | 5 ms | 11 ms |
| 10,000 scopes, 1,000 open holds | 1.6 MiB | 53 ms | 118 ms |

A 1,000,000-entry ledger with 8 scopes, 9,997 entries past its newest
checkpoint, opens in 172 ms on SQLite and 258 ms on PostgreSQL (medians of
seven; `tests/test_scale.py` holds it under 500 ms, nightly).

- **Who writes them.** The governor whose write takes the chain
  `checkpoint_every` entries past the last checkpoint writes the next, once that
  write has committed. The snapshot is stored outside the fleet's writer lock,
  and only a small `CHECKPOINT` entry that commits to it is appended under the
  lock. The call that made it due returns once the checkpoint is written, so
  encoding and signing the snapshot add to that one call's latency, once every
  `checkpoint_every` entries. The other governors of a fleet leave it to that
  one, so the fleet stores one snapshot per checkpoint. A governor that opens a
  ledger already `checkpoint_every` entries past its newest checkpoint writes
  one after its first write.
- **Tuning `checkpoint_every`.** Lower it to bound open time more tightly.
  Raise it when the state is large, so the snapshot is encoded and signed less
  often. Set it to `0` only where something else checkpoints, such as
  `agentgov checkpoint <ledger>` from a scheduled job.
- **When checkpoints fail.** A failed automatic checkpoint never fails the write
  that made it due; the next attempts back off ([Key services](#key-services-and-rotation)).
  `checkpoint_lag()`, and the `agentgov.checkpoint.lag` gauge, count the
  entries past the newest checkpoint.
- **`verify="full"`** replays the chain from genesis at open, at about 25 µs an
  entry on that laptop, or 25 s per million entries. It is for an open that must
  not trust a checkpoint, such as an audit or a restore drill, not for writers.

**The auditor** replays the history an open from a checkpoint did not: it
verifies the chain from genesis and checks each checkpoint's snapshot against
the state the chain implies there, recording each verified checkpoint as a mark
in the ledger's database. Every run resumes from the newest mark any auditor
verified, so the replay from genesis is paid once per ledger.

- A governor that opened from a checkpoint runs an auditor in a thread (a
  quarter of one core, every 5 s) unless opened with `auditor=False`. On a
  single SQLite governor, leave it on.
- In a fleet, every governor's thread replays everything the fleet writes. Run
  one auditor beside the fleet instead, and open the governors with
  `auditor=False`:

  ```sh
  agentgov audit --follow 'postgresql://auditor@db/fleet?schema=agentgov' \
      --name audit-1 --checkpoint-key checkpoint.pub --require-signed
  ```

  It needs the governors' grants (it records marks). Its first run replays from
  genesis; later runs resume.
- **A failure stops the fleet's writers.** An auditor that finds the chain does
  not verify records the failure and exits 1. From then on every governor
  refuses to open for writing, and the one whose thread found it stops writing.
  Investigate with `agentgov verify`. A later audit that verifies the chain past
  the failure clears it.

## Witnesses

Signed checkpoints make rewriting checkpointed history take the key. A witness
catches what a key cannot: a ledger cut back to an earlier checkpoint, a history
forked from one, a ledger replaced whole, and a compromised governor signing any
of these ([SECURITY.md](../SECURITY.md#what-only-a-record-kept-elsewhere-shows)).

```python
from agentgov.receipts import FileWitness

log_id = f"agentgov-ledger:{view.entry(1).entry_hash}"
witness = FileWitness(
    "witness.jsonl", witness_signer, witness_id="audit-team", logs={log_id: checkpoint_key}
)
view.publish_checkpoint([witness])  # raises WitnessError if any witness refuses
```

- **Publish on a schedule, off the write path.** `publish_checkpoint()` computes
  consistency proofs from every entry hash up to the checkpoint, so its cost
  grows with the ledger. Run it from a job every few minutes, on a read-only
  governor opened with the checkpoint signer (`open_postgres(...,
  read_only=True, signing=...)`), never from request handlers.
- **Alert on `WitnessError`.** It names each witness that refused and why. A
  checkpoint that does not extend what a witness cosigned before means the
  ledger was cut back or forked: the [failover runbook](#failover-a-ledger-that-lost-commits)
  applies. A witness that cannot be reached is an outage of the witness.
- **Run witnesses where the fleet cannot reach.** A witness on the governors'
  hosts, with its key in their key service, catches a database writer, not a
  compromised governor. One run by another team, on other infrastructure, with
  its own key, catches both.
- **Witnesses check the checkpoint key**, as `logs={log_id: key}`. After a key
  rotation, give them a keyring of the old and new keys.
- **A witness never follows a rollback.** Once it has cosigned a checkpoint, it
  refuses every later checkpoint of a ledger cut back before it, because the
  ledger has forked from what it witnessed. Resuming after a deliberate
  rollback, such as a restore from backup or a failover that lost commits, is
  the witness operator's decision. For a `FileWitness`, that means a new
  cosignature file, keeping the old one as the record of the history that was
  lost.

## Backup and restore

A backup is a copy of the ledger as of some head. Restoring it puts the ledger
back to that head: everything committed after it is lost, exactly as in a
failover that lost commits, and the same [runbook](#failover-a-ledger-that-lost-commits)
applies once the restore is done.

**SQLite.** Copy the database with SQLite's online backup, never with `cp` while
a governor runs. It copies a consistent snapshot while the governor keeps
writing, and the copy verifies:

```python
import sqlite3
from contextlib import closing

with closing(sqlite3.connect("governor.db")) as live, closing(sqlite3.connect("backup.db")) as copy:
    live.backup(copy)
```

or `sqlite3 governor.db ".backup backup.db"`. To restore, stop the governor and
move `governor.db` aside together with any `governor.db-wal` and
`governor.db-shm` beside it (a write-ahead log left next to a different database
corrupts it), then put the backup in its place.

**PostgreSQL.** Back up the ledger's schema whole, with its triggers and
functions, using `pg_dump` or the cluster's own physical backups and
point-in-time recovery:

```sh
pg_dump --schema=agentgov --format=custom --file=ledger.dump "$LEDGER_DATABASE"
pg_restore --dbname="$RESTORED_DATABASE" ledger.dump
```

Restore as the ledger's owner, into a database that does not have the schema
yet, with the fleet's roles already created so that their grants restore too.
A full restore recreates the triggers, enabled `ALWAYS`, and with them the
chain's protection. The idempotency records, snapshots and audit marks come back
with the entries they describe, so a key recorded before the backup still
returns its recorded outcome. The dump holds `join_key`, the secret that admits
settlement claims, so keep dumps as secret as the database.

**Check every backup** before you need it. `agentgov verify` on the restored copy
(`sqlite:///...` or `postgresql://...`) replays it from genesis and checks every
snapshot, and, given `--checkpoint-key`, every signature.

**After a restore,** before the fleet writes:

1. `agentgov verify` the restored ledger.
2. Compare its head with the newest record of the ledger kept elsewhere: the
   witnesses' newest cosigned checkpoint, anchors, receipts. Everything after
   the restored head is lost. Follow steps 2 and 3 of the failover runbook for
   it.
3. Witnesses that cosigned past the restored head refuse the restored ledger
   from now on ([Witnesses](#witnesses)).

## Failover: a ledger that lost commits

When a governor finds the ledger shorter than the chain it verified, and what is
left is exactly the chain it verified, cut back, it raises
`LedgerRollbackError` (a `LedgerIntegrityError`) and stops writing: every later
write raises, and reads keep serving what it last verified. The error carries
`verified_length` (what it had verified), `ledger_length` (what the ledger holds
now) and `confirmed` (whether the surviving head was compared with the one it
verified there: a governor remembers the hashes of its newest 4,096 entries). A
ledger whose surviving entries differ from what was verified is not a rollback:
that raises a plain `LedgerIntegrityError`, and is treated as tampering.

1. **Confirm it.** Compare the new primary's head with the error's
   `verified_length`: a failover to a lagging standby explains the gap. Run
   `agentgov verify` (or `open_postgres(..., read_only=True, verify="full")` and
   `verify_integrity()`) on the new primary: the chain that is left must verify.
   A witness's cosigned checkpoints (`publish_checkpoint`) prove the longer
   chain existed: a cosigned checkpoint past the new head is a rollback, not an
   operator error.
2. **Decide what the lost commits were.** Every entry after `ledger_length` is
   gone: holds, spends, refunds, trips. Callers were told they committed. A
   caller that used an **idempotency key** can retry its call: the key's record
   was rolled back with the entries, so the retry is made again, once. Callers
   that did not need reconciling from their own records.
3. **Re-anchor.** Anything that recorded a ledger head past `ledger_length` (an
   ARC1 receipt's chain anchor, an anchor entry's subject, a downstream system's
   records) names an entry that no longer exists. Re-issue or re-anchor those
   against the new chain; a verifier will refuse the old ones.
4. **Restart the governors.** A governor that raised `LedgerRollbackError`
   never resumes; open a new one. It verifies the chain as it now stands and
   carries on from there.
5. **Tell the witnesses' operators.** A witness that cosigned past
   `ledger_length` refuses this ledger from now on ([Witnesses](#witnesses)).

## Key services and rotation

**Receipts fail closed.** A `ReceiptLog` whose signer cannot be reached raises
`SignerUnavailableError` from `issue()`: it never falls back to another key, and
nothing is logged unsigned.

**Ledger writes never wait on a checkpoint's signer.** With
`CheckpointSigning(signer=...)`, an automatic checkpoint is signed before it is
written. If the key service is down the checkpoint fails, the write that made
it due has already committed, and the next tries back off (one second, doubling
to a minute). Until one succeeds the chain grows past its last checkpoint:
`BudgetManager.checkpoint_lag()` stays near `GovernancePolicy.checkpoint_every`
while checkpoints succeed, and growing past it means they are failing. An open
then replays the entries since the last checkpoint, which takes longer, but
nothing is lost or unsigned.

**Rotating the checkpoint key.** A governor trusts its own signer's key and the
keys in `CheckpointSigning.keys`, and it checks every checkpoint its auditor
reaches. A governor or auditor that meets a checkpoint signed by a key it does
not trust records the ledger as failing verification, and the fleet stops
writing. So rotate in two rolls, never one:

1. Add the new public key to `keys` on every governor and auditor, and roll the
   fleet. Every governor now accepts either key.
2. Switch the signer, `CheckpointSigning(signer=new, keys=[old_public],
   required=True)`, and roll the fleet again. Checkpoints written from then on
   are signed by the new key.
3. Keep the old public key in `keys` for good: the auditor checks the old
   checkpoints too. Public keys are not secret, and `agentgov verify` and
   `agentgov audit` take one `--checkpoint-key` per key.
4. Give the witnesses a keyring of both keys for the ledger's log id.

**A compromised checkpoint key.** Rotate at once, write a checkpoint with the new
key (`agentgov checkpoint`), and publish it to the witnesses. A successful
publish shows the ledger still extends what the witnesses cosigned before the
compromise. In 1.0 a governor that trusts a key accepts any checkpoint it
signed, at any sequence: ledger checkpoints do not have the key eras that ARC1
receipt logs do. Until they do, the witnesses' cosignatures are what pin the
history the old key signed. A rewrite signed with the stolen key cannot be
witnessed.

**Rotating a receipt log's key.** `ReceiptLog.rotate(new_signer)` has the
outgoing key sign a checkpoint at the current size and a key transition (ARC1
1.2) naming the incoming key, kept in `<log>.transitions`. From then on the new
key signs every leaf and every larger checkpoint. Verifiers follow transitions
(`agentgov verify-receipt --transitions`), and witnesses need the incoming key
in their keyring for the log ([docs/RECEIPTS.md](RECEIPTS.md), section 14).
Rotate while the outgoing key can still sign: a lost key cannot hand the log
over.

## Metrics and alerts

Pass `metrics=` to `open_postgres()`, `open_sqlite()` or `agentgov.open()`:
`agentgov.otel.OpenTelemetryMetrics()` with `agentgov[otel]`, or any object with
`record`, `add` and `set` (`agentgov.metrics.Metrics`). A governor reports:

| Instrument | Kind | Watch for |
|---|---|---|
| `agentgov.checkpoint.lag` | gauge, entries | Growing past `checkpoint_every`: automatic checkpoints are failing, usually at the signer |
| `agentgov.store.errors` | counter | Any sustained rate: the database is refusing or losing commits. Each failed unit of work is re-read at once |
| `agentgov.lock.wait` | histogram, s | A p99 approaching `lock_timeout` (30 s): writers are about to fail with `StorageError` |
| `agentgov.lock.hold` | histogram, s | Growth: units of work are slowing, and every other governor waits on them |
| `agentgov.unit.size` | histogram, calls | Context for the two above: the mutations one unit of work carried |
| `agentgov.catch_up.entries` | histogram, entries | How much of the others' work each unit of work verifies first |
| `agentgov.holds.open` | gauge, holds | Growth without matching spend: holds left by callers that died. Survey them with `stale_authorizations()` |
| `agentgov.trips` | counter | Breaker trips this governor wrote. Each halts a subtree until `reset()` |
| `agentgov.open.duration` | histogram, s | Growth: the distance to the newest checkpoint, or the state, is growing |
| `agentgov.verify.duration` | histogram, s | `verify_integrity()` time, linear in history |

The `agentgov.audit` logger's ERROR lines, and `agentgov audit --follow`
exiting 1, mean the chain failed verification: page someone
([Checkpoints and the auditor](#checkpoints-and-the-auditor)).

## The velocity window across a fleet

The runaway-loop detector (`max_calls_per_window` within `window_seconds`)
counts each governor's own calls by default, so N governors admit N times the
rate. `GovernancePolicy(fleet_velocity=True)` counts a scope's holds in the
chain instead, by every governor, by their timestamps: one limit for the fleet.
It relies on the hosts' clocks agreeing to well within the window.
