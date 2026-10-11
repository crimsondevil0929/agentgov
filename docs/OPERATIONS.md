# Operating agentgov on PostgreSQL

This guide is for whoever runs a fleet of governors over one ledger in
PostgreSQL: how to configure the database, and what to do when the database,
its replication, or a key service fails. A single SQLite governor needs none of
it; the [README](../README.md) covers it.

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

## Key services

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

## The velocity window across a fleet

The runaway-loop detector (`max_calls_per_window` within `window_seconds`)
counts each governor's own calls by default, so N governors admit N times the
rate. `GovernancePolicy(fleet_velocity=True)` counts a scope's holds in the
chain instead, by every governor, by their timestamps: one limit for the fleet.
It relies on the hosts' clocks agreeing to well within the window.
