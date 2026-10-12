# The AgentGov ledger format

**Status: frozen for 1.x.** This document specifies what an AgentGov ledger
holds, how each entry is hashed, the rules a valid chain obeys, and how a
checkpoint commits to the state at a point in the chain. It is written so
that an auditor can verify a ledger in any language without reading the
Python. `vectors/agov/` holds conformance vectors generated from the reference
implementation; an implementation that reproduces every vector and refuses
every invalid one follows this specification.

Anything a 1.x release writes verifies under every later 1.x release.
Entries written as `AGOV1` (v0.1.0, v0.1.1), `AGOV2` (v0.1.2 to v0.4) and
`AGOV3` (from v1.0) each verify under their own version's rules, below.

## Contents

1. [Entries](#1-entries)
2. [Hashing an entry](#2-hashing-an-entry)
3. [The chain](#3-the-chain)
4. [Checkpoints and snapshots](#4-checkpoints-and-snapshots)
5. [Storage layouts](#5-storage-layouts)
6. [Verifying a ledger](#6-verifying-a-ledger)

---

## 1. Entries

A ledger is a sequence of entries. Each entry records one event against one
scope (an agent's budget) and is linked to the entry before it by hash.

| Field | Type | Meaning |
|---|---|---|
| `sequence` | integer ≥ 1 | Position in the chain; the first entry is 1, and each entry is one more than the last. |
| `entry_id` | UUID | The entry's own identifier, unique in the ledger. |
| `transaction_id` | UUID | Shared by every entry written together as one transaction. |
| `timestamp` | instant | When the entry was written, in UTC. |
| `entry_type` | enum | What happened (below). |
| `direction` | `DR`, `CR` or `--` | Whether the entry debits, credits, or moves nothing. |
| `scope_id` | text | The scope whose balance the entry moves. Empty for `seal` and `checkpoint`. |
| `counterparty_id` | text or null | The other scope of a transfer; null at the boundary. |
| `amount` | amount | Strictly positive, except zero for the zero-value types. |
| `balance_after` | amount | `scope_id`'s balance once the entry is applied (may be negative). |
| `memo` | text | Free text; for some types, a structured record (below). |
| `ref` | UUID or null | The entry this one settles or reverses (below). |
| `prev_hash` | 64 lowercase hex | The previous entry's `entry_hash`; 64 zeros for entry 1. |
| `entry_hash` | 64 lowercase hex | SHA-256 over the entry's hash input (§2). |
| `version` | `AGOV1`, `AGOV2`, `AGOV3` | Which rules the entry was written under. |

**Entry types**, with the directions each allows:

| Type | Direction | Moves money | Meaning |
|---|---|---|---|
| `funding` | `CR` | yes | The treasury funds a root scope. |
| `allocation` | `DR` (parent), `CR` (child) | yes | A parent delegates to a new child, as a balanced pair. |
| `release` | `DR` (child), `CR` (parent) | yes | A child returns budget to its parent, as a balanced pair. |
| `hold` | `DR` | yes | An authorization hold: funds encumbered before a call. |
| `hold_void` | `CR` | yes | A hold released, on capture or cancellation; names the hold (`ref`). |
| `spend` | `DR` | yes | Money paid out to a vendor; may name the hold it settles (`ref`). |
| `reversal` | `CR` | yes | A vendor refund; from `AGOV3`, may name the spend it reverses (`ref`). |
| `circuit_tripped` | `--` | no | A scope's breaker latched; `memo` is the reason. |
| `circuit_reset` | `--` | no | A scope's breaker re-armed. |
| `anchor` | `--` | no | An external record committed by digest (`memo`). |
| `seal` | `--` | no | Written once, when a pre-0.1.2 ledger is upgraded (§3.7). |
| `checkpoint` | `--` | no | `AGOV3` only: commits a snapshot of the state (§4). |

**Amounts** are decimal numbers of US dollars, at most 10¹² in magnitude,
with exactly eight decimal places (the quantum is 0.00000001). **Instants**
are rendered `YYYY-MM-DDTHH:MM:SS.ffffffZ`, always with six fractional digits.
**UUIDs** are rendered as 36 lowercase hexadecimal characters with hyphens.

## 2. Hashing an entry

`entry_hash` is the lowercase hex SHA-256 of the entry's *hash input*, a
UTF-8 string whose construction depends on the entry's version.

### 2.1 AGOV3

The hash input is the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
canonical JSON encoding (JCS) of this object:

```json
{
  "amount": "<amount>",
  "balance_after": "<amount>",
  "counterparty_id": "<text>" | null,
  "direction": "DR" | "CR" | "--",
  "entry_id": "<uuid>",
  "entry_type": "<type>",
  "format": "AGOV3",
  "memo": "<text>",
  "prev_hash": "<64 hex>",
  "ref": "<uuid>" | null,
  "scope_id": "<text>",
  "sequence": <integer>,
  "timestamp": "<instant>",
  "transaction_id": "<uuid>"
}
```

- **Amounts** are fixed-point strings matching `-?(0|[1-9][0-9]*)\.[0-9]{8}`:
  `"0.00000001"`, `"1000.00000000"`, `"-0.25000000"`. Zero is
  `"0.00000000"`, never with a sign. No exponent is ever written.
- **Canonical JSON** sorts the keys (they are listed above in that order),
  writes no insignificant whitespace, writes `sequence` as a plain integer,
  and escapes strings minimally: `"` and `\` with a backslash, the control
  characters U+0000 to U+001F as `\b`, `\t`, `\n`, `\f`, `\r` or `\u00XX`
  (lowercase hex), and every other character literally, encoded as UTF-8.
- `format` is a constant that separates this hash's domain from any other.

Every string must be Unicode text: an entry holding a lone surrogate has no
encoding, and is refused. `vectors/agov/entries.json` gives the exact hash
input and hash of entries of every type, including text that needs escaping.

### 2.2 AGOV2 and AGOV1

The hash input is the JSON array, with no whitespace and every non-ASCII
character escaped as `\uXXXX` (Python's `json.dumps(..., separators=(",",
":"), ensure_ascii=True)`):

```
["AGOV2", prev_hash, sequence, entry_id, transaction_id, timestamp,
 entry_type, direction, scope_id, counterparty_id, amount, balance_after,
 memo, ref]
```

`AGOV1` omits `ref` (the last element) and has `"AGOV1"` first. Amounts in
these versions are rendered as CPython's `str(Decimal)` renders them, which
uses an exponent for small values (`"1E-8"` for 0.00000001, `"0"` for zero):
this is why `AGOV3` replaced them. An implementation that verifies older
ledgers renders a quantized amount as `str(Decimal)` does: the coefficient
digits with the decimal point eight places from the right, except that when
the adjusted exponent is below −6 it is written in scientific notation.

## 3. The chain

A replay applies the entries in order to an initially empty state, and a
ledger is valid if every entry satisfies every rule below. Writers enforce
the same rules before they write, so nothing a writer accepts is refused by
a replay. The state a replay keeps:

- each scope's **balance** (zero until an entry moves it);
- the boundary **totals**: funded, spent, reversed, and held;
- the **open holds**: every `hold` not yet released, by `entry_id`;
- the **delegation tree**: every scope, its parent, depth and lifetime
  allocation (the sum of what was granted to it), and the list of roots;
- the **halted** scopes and why;
- each scope's lifetime **spend** and **refunds**, and, from `AGOV3`, how
  much of each spend named refunds have returned (counted from the chain
  when a rule needs it, not kept: see §4.1);
- the **head** (the last `entry_hash`), the length, the last timestamp, and
  an RFC 9162 **Merkle frontier** over every entry hash (§4.3).

### 3.1 Position and versions

1. `sequence` is one more than the previous entry's (1 for the first).
2. `prev_hash` equals the previous entry's `entry_hash` (64 zeros for the first).
3. `entry_hash` is the hash of the entry's hash input (§2).
4. Versions never go back: no `AGOV1` entry after an `AGOV2` or `AGOV3` one,
   and no `AGOV2` entry after an `AGOV3` one.
5. In a ledger with `AGOV1` history, the first entry of a later version is the
   `seal` (§3.7).

### 3.2 Shape

1. The direction is one the type allows (§1).
2. A type that moves money has a strictly positive amount; a zero-value type
   has amount zero.
3. `seal` and `checkpoint` have an empty `scope_id`; every other type has a
   non-empty one.
4. `ref` is null except on `hold_void` and `spend` (which name a hold) and,
   from `AGOV3`, `reversal` (which names a spend).
5. **AGOV3 text:** no string holds a lone surrogate or a NUL; `scope_id` and
   `counterparty_id` hold no control character (Unicode category Cc) and are
   at most 1024 bytes of UTF-8; `memo` is at most 65536 bytes.
6. **AGOV3 time:** `timestamp` is not earlier than the previous entry's.

### 3.3 Money

1. `balance_after` equals the scope's balance before the entry plus the
   entry's signed amount (`+amount` for `CR`, `−amount` for `DR`, zero for
   `--`), computed exactly.
2. Within one transaction (consecutive entries sharing a `transaction_id`),
   the signed amounts of the `allocation` and `release` entries sum to zero.
3. The totals move: `funding` adds to funded, `spend` to spent, `reversal`
   to reversed, `hold` to held, and `hold_void` subtracts from held.

At every point, the conservation identity holds:
**Σ balances + held + spent − reversed = funded**.

### 3.4 Holds

1. A `hold` opens a hold, identified by its `entry_id`.
2. A `hold_void` (from `AGOV2`) names an open hold in `ref`, in the same
   scope and for exactly its amount, and closes it. Naming a hold that is
   not open (never placed, or already released) is refused.
3. A `spend` that names a hold (`ref`) may only follow, in the same
   transaction, the `hold_void` that released that hold.
4. An `AGOV1` `hold_void` names no hold: it closes any open hold of the same
   scope and amount, and one must exist.

### 3.5 Governance

1. A `funding` to an unknown scope creates a **root** (depth 0); a `funding`
   to an existing scope is allowed only if it is a root, and adds to its
   lifetime allocation.
2. An `allocation` `CR` entry creates a new scope, the child of
   `counterparty_id`, which must exist; its depth is its parent's plus one,
   and its allocation is the amount. The scope must not already exist.
3. An `allocation` `DR` entry, and a `hold`, `hold_void`, `spend`,
   `reversal`, `anchor`, `circuit_tripped` or `circuit_reset`, names a scope
   that exists.
4. A `release` moves money between a child and its parent, in either leg.
5. `circuit_tripped` halts its scope (and, for the purposes of a governor,
   its subtree); `circuit_reset` re-arms it.

### 3.6 Refunds

1. A scope's lifetime refunds never exceed its lifetime spend. Writers have
   enforced this since v1.0; replays enforce it on `AGOV3` entries (older
   history is not held to a rule it predates).
2. An `AGOV3` `reversal` that names a spend (`ref`) names a `spend` entry
   earlier in the ledger, in the same scope, and the refunds naming that
   spend never sum to more than its amount.

### 3.7 The migration seal

A ledger written by v0.1.0 or v0.1.1 kept circuit-breaker events outside the
chain. The first time a later version writes such a ledger, it writes a
`seal`: a zero-value entry, with no scope, whose `memo` is

```
pre-0.1.2 control events: n=<count> sha256=<digest>
```

where the digest is SHA-256 over the JSON array (Python `json.dumps`, no
whitespace, ASCII-escaped) of those events in the order they were written,
each as `[event_id, timestamp, event_type, scope_id, reason,
ledger_head_hash]`. A ledger has at most one seal, and only if it has
`AGOV1` history.

## 4. Checkpoints and snapshots

A checkpoint lets a governor open without replaying history: it is a
*snapshot* of the state at a sequence, stored once, and a `checkpoint` entry
that commits to the snapshot's digest.

### 4.1 The snapshot

A snapshot is the RFC 8785 canonical JSON encoding of an object holding the
whole state of §3 as of a sequence `s`. Its fields (the reference encoder is
`agentgov.core._snapshot_document`):

| Field | Content |
|---|---|
| `format` | `"agentgov-snapshot/1"` |
| `sequence` | `s` |
| `head` | the `entry_hash` of entry `s` |
| `last_timestamp` | entry `s`'s timestamp, or null |
| `balances` | scope → amount |
| `totals` | `funded`, `spent`, `reversed`, `holds_open` → amount |
| `nodes` | every scope in creation order: `[scope_id, parent_id, depth, allocation, created_at, [children...]]` |
| `roots` | root scopes in creation order |
| `tripped` | scope → `[instant, reason]` |
| `holds` | every open hold, in placement order, as the full entry (each field a string, its amounts in its own version's rendering) |
| `spent`, `refunded` | scope → amount |
| `ambiguous` | the `[scope, amount]` keys `AGOV1` releases touched (§3.4.4) |
| `flags` | `saw_v1`, `saw_v2`, `saw_v3`, `legacy_applied` |
| `seal` | the seal entry, or null |
| `legacy` | the pre-0.1.2 control events (§3.7) |
| `last_checkpoint` | `[s', digest']` of the previous checkpoint, or null |
| `frontier` | the Merkle frontier (§4.3), as hex |

Amounts are fixed-point strings (§2.1). The encoding is canonical, so one
state has exactly one snapshot, and a reader refuses a snapshot whose bytes
are not the canonical encoding of the state they hold.

A snapshot holds no per-spend refund totals. The bound of §3.6 (2) counts
the refunds naming a spend among the entries before the one being checked;
a reader that keeps history in a store asks it, by the index of refunds by
the spend they name (§5), so neither a snapshot nor a governor's memory
grows with every spend ever refunded.

The snapshot's **digest** is SHA-256 over the bytes
`agentgov/snapshot/v1\n` followed by the snapshot, in lowercase hex.

### 4.2 The checkpoint entry

A `checkpoint` entry is an `AGOV3` zero-value entry with an empty scope whose
`memo` is exactly

```
agentgov-checkpoint v1 seq=<s> sha256=<digest>
```

1. `s` is less than the checkpoint entry's own sequence (a snapshot is
   written before the entry that commits to it, outside any lock, because the
   state as of `s` never changes).
2. `s` is greater than the `s` of every earlier checkpoint entry.
3. The snapshot stored for `s` has the digest the memo names, and is the
   state a replay reaches at `s` (§6).

A governor writes a checkpoint every 10,000 entries by default, between
units of work, so `s` always ends a transaction.

### 4.3 The Merkle frontier

Each entry hash is a leaf of an RFC 9162 Merkle tree: the leaf hash is
SHA-256(0x00 ‖ the 32 bytes of `entry_hash`), and an interior node is
SHA-256(0x01 ‖ left ‖ right). The frontier after `n` entries is the list of
roots of the perfect subtrees given by the binary digits of `n`, largest
first (`popcount(n)` hashes). Appending an entry hashes its leaf and merges
it with the frontier's last node once for each trailing one bit of `n`. The
tree's root folds the frontier from the right; the root of no entries is
SHA-256 of the empty string. `chain.json` gives the root of its chain.

### 4.4 The signed statement

A snapshot is trusted for every entry before it. To make rewriting that
history take a key as well as write access to the database, a governor with a
checkpoint signer stores with each snapshot, in its `signature` column, a
**checkpoint statement** the key signed:

| Field | Content |
|---|---|
| `v` | `"agentgov-checkpoint"` |
| `first` | the `entry_hash` of entry 1: which ledger |
| `sequence` | `s` |
| `head` | the `entry_hash` of entry `s` |
| `root` | the Merkle root (§4.3) of entries 1 to `s` |
| `snapshot` | the snapshot's digest (§4.1) |
| `issued_at` | when it was signed, as `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| `sig` | the signature, as an ARC1 `sig` object |

It is signed exactly as an ARC1 document is (`docs/RECEIPTS.md` §4): over
`agentgov/checkpoint/v1\n` followed by the canonical encoding of the statement
with `sig` reduced to `{"alg", "key_id"}`, or, at signature version 2, over
`agentgov/checkpoint/v2\n` followed by the SHA-512 of the encoding with
`"sv": 2` in the header. The column holds the statement's canonical encoding.

A reader that trusts some keys accepts a snapshot only if its statement
verifies under one of them and its `first`, `sequence`, `head`, `root` and
`snapshot` are the ledger's and the snapshot's own. A statement signed by any
other key is tampering, whether or not signatures are required. Entries after
the newest checkpoint are held by the hash chain alone.

## 5. Storage layouts

The SQLite layout is schema `3`; the PostgreSQL layout is `pg2`. Both hold
the same logical tables. The chain lives in `entries`; every other table is
either a cache derived from the chain (checked against it, and rebuilt from
it by `repair`), or evidence that is never edited.

| Table | Role | Contents |
|---|---|---|
| `entries` | the chain | One row per entry, every field of §1, amounts as text in the entry's own version's rendering (§2). Append-only (PostgreSQL triggers refuse UPDATE, DELETE and TRUNCATE), and an entry is admitted only if it links to the one before it. |
| `nodes` | cache | One row per scope: parent, depth, allocation, created. |
| `control_events` | cache | One row per trip or reset; pre-0.1.2 rows have no `entry_id`. |
| `open_authorizations` | cache | One row per open hold. |
| `snapshots` | evidence | One row per checkpoint snapshot: `sequence`, `digest`, `body`, `signature`. Never edited. |
| `audit_marks` | evidence | One row per auditor result: the sequence verified, its head, the state digest there, `verified` or `failed`. Never edited. |
| `idempotency` | records | One row per idempotency key an operation was given: the request it named and what it returned, committed with its entries. |
| `claims` | PostgreSQL only | Settlement claims committed inside callers' transactions. |
| `schema_meta` | metadata | `schema_version`. |

Indexes on `entries`: `(scope_id, sequence)`, `(entry_type, memo)`
(PostgreSQL: `(entry_type, md5(memo))`), the `reversal` entries by `ref`
(the spend they name, for §3.6), and on PostgreSQL the checkpoint entries by
sequence. `transaction_id` and the `ref` of other entries are not indexed:
their values are random, so an index on either would cost every commit a
page write, and no write or replay looks an entry up by them.

**Upgrades** are in place and forward-only: a writer opening an older layout
upgrades it, under the writer lock, in one transaction, before it writes
anything. A read-only open never upgrades, and reads every older layout as
it is. SQLite schemas `1` (v0.1.0, v0.1.1) and `2` (v0.1.2 to v0.4) and
PostgreSQL `pg1` (v0.3, v0.4) upgrade to the current layouts.

## 6. Verifying a ledger

A **full verification** replays every entry from genesis under §3 and checks,
at every checkpoint's `s`, that the snapshot stored for `s` is the canonical
encoding of the replayed state and has the digest the checkpoint entry names,
and, given the keys trusted to sign checkpoints, that its statement (§4.4)
checks out. It then compares the caches with the state. `agentgov verify`
does this (`--checkpoint-key`, `--require-signed`).

An **open from a checkpoint** (what a governor does by default) finds the
newest checkpoint entry, reads the snapshot it names, checks the digest,
decodes the snapshot (refusing anything not canonical), and replays only the
entries after `s` under §3. It trusts the snapshot for everything up to `s`.
A missing or altered snapshot is refused, never skipped for an older one.

The **auditor** (`agentgov audit`) is the full verification run continuously:
it records each checkpoint it verifies as a mark, resumes from the newest
verified mark, and records a failure that every writer then refuses to open
past until a later audit verifies the chain.

What each mode proves, stated plainly: a full verification detects any edit
to any row that its author did not also rewrite consistently through the end
of the chain; an open from a checkpoint detects edits after the checkpoint,
and leaves edits before it to the auditor. Neither detects a consistent
rewrite by someone who can write the database and compute SHA-256: signed
checkpoints (see `SECURITY.md`) close that gap, by binding each snapshot to
a key the database's writers do not hold.
