# ARC1: verifiable action receipts

**Status:** draft 1, shipping unreleased on the v0.2 line (`agentgov.receipts`).
Every ARC1 document names its version in its `v` field, and every signature
names its document type in a domain string. A breaking change will get a new
version. ARC1 documents will never be reinterpreted.

An ARC1 receipt is a signed record of one agent action against a system of
record. It says:
- who authorized the action;
- what the agent said it would do;
- what the action measurably did, and what the measurement could not see;
- what was decided, and by which checks;
- what it cost;
- how it ended.

Refused actions get receipts too. A verifier needs only the receipt and the
keys it trusts to check a receipt offline. With more evidence it can check
more:
- the receipt log's checkpoint, and the path from the receipt to its root;
- a witness's record of that checkpoint;
- the AgentGov ledger that paid for the action;
- rows the issuer chooses to disclose.

This document is normative. Section 11 describes the reference test vectors
in [`vectors/arc1/`](../vectors/arc1/). Check an independent implementation
against them.

- [1. What a receipt proves](#1-what-a-receipt-proves)
- [2. Conventions](#2-conventions)
- [3. Canonical encoding](#3-canonical-encoding)
- [4. Signatures](#4-signatures)
- [5. The receipt](#5-the-receipt)
- [6. Row commitments and disclosures](#6-row-commitments-and-disclosures)
- [7. The receipt log](#7-the-receipt-log)
- [8. Witnesses](#8-witnesses)
- [9. Bundles](#9-bundles)
- [10. Verification](#10-verification)
- [11. Test vectors](#11-test-vectors)
- [12. Security considerations](#12-security-considerations)

## 1. What a receipt proves

| Claim | Evidence | Fails with |
|---|---|---|
| The issuer said exactly this, and nothing was changed afterwards | the receipt's signature over its canonical bytes | 4 `SIGNATURE` |
| The receipt holds the position it claims in a log whose operator signed that log's size and root | the checkpoint signature, the audit path, and the position signed inside the receipt | 5 `INCLUSION` |
| That log is the one everyone else sees: it was not forked, rolled back or rewritten | a witness cosignature of the same checkpoint | 6 `WITNESS` |
| The money the receipt reports is what the ledger settled, and was settled before the receipt was anchored | the AgentGov ledger's hash chain | 7 `LEDGER` |
| A disclosed row is one of the rows the action changed, at the position it is shown at | the salted row commitment in the receipt | 8 `ROWS` |

A receipt does **not** prove that the issuer measured honestly. The effect
section is the issuer's measurement, and the coverage section is the issuer's
own statement of what that measurement could not see. What ARC1 guarantees:
once issued, logged and witnessed, a measurement can no longer be changed,
reordered, dropped from the log's history, or shown differently to different
verifiers without the change being detectable. A log proves what it contains.
It cannot prove what it omits.

## 2. Conventions

Every object has **exactly** the fields its table lists. A missing field or
an unknown field makes the document malformed, and a verifier refuses what it
does not understand. `null` is written out. It is never expressed by omitting
the field.

| Format | Definition |
|---|---|
| *hex* | lowercase hexadecimal |
| *hash* | SHA-256, 64 *hex* characters |
| *text* | a string of 1 to 512 characters, none of them U+0000 to U+001F or U+007F |
| *instant* | UTC, exactly `YYYY-MM-DDTHH:MM:SS.ffffffZ` (six fractional digits), a real calendar instant |
| *uuid* | a canonical lowercase UUID, `8-4-4-4-12` *hex*, any version |
| *int* | an integer from 0 to 2^53 − 1, never a boolean |
| *money* | a string matching `(0\|[1-9][0-9]*)\.[0-9]{8}`: US dollars, exactly eight places, the ledger's quantum |
| *set* | an array of *text*, sorted by UTF-16 code units (the order of section 3), with no duplicates |
| *key id* | 16 *hex* characters (section 4.3) |

## 3. Canonical encoding

Every hash and signature in ARC1 covers the canonical bytes of a JSON value.
The encoding is [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JCS),
restricted to this value domain:

- strings of Unicode scalar values (a lone surrogate is refused);
- integers from −(2^53 − 1) to 2^53 − 1;
- `true`, `false`, `null`;
- arrays, in their order;
- objects with string keys.

Floats are refused. RFC 8785 formats numbers as ECMAScript does, and exact
decimals (money, database values) belong in strings anyway. Within this
domain the rules come down to:

1. No whitespace anywhere.
2. Object members are sorted by their keys' **UTF-16 code units**. This order
   differs from code-point order for supplementary-plane characters: U+1F600
   (`D83D DE00`) sorts before U+FF61. Set-valued arrays (section 2) use the
   same order.
3. Strings are escaped as JCS does:
   - `"` and `\` are escaped;
   - U+0008, U+0009, U+000A, U+000C and U+000D become `\b \t \n \f \r`;
   - every other character below U+0020 becomes `\u00xx` (lowercase *hex*);
   - everything else is literal UTF-8, including U+007F, U+2028 and U+2029.
4. Integers are written in decimal with no leading zeros, `-` for negatives.

**Decoding is strict.** The following are refused, not "repaired":
- an object with a duplicate key;
- any number with a fraction or exponent;
- `NaN` or `Infinity`;
- an integer outside the safe range;
- text that is not valid JSON.

Different parsers keep different duplicates, and a signed document must never
display one value while verifying another.

## 4. Signatures

### 4.1 The signed bytes

Every signed document has a `sig` field:

```json
"sig": {"alg": "ed25519", "key_id": "bcc542d53c8c1a1f", "signature": "<hex>"}
```

The signature is computed over:

```
signing_input = DOMAIN || canonical(document with sig = {"alg": alg, "key_id": key_id})
```

The `signature` member is removed and `alg` and `key_id` stay, so the
signature covers which algorithm and which key it claims. `DOMAIN` is fixed
per document type. A signature over one kind of document never verifies as
another:

| Document | `v` | `DOMAIN` (ASCII, with the trailing newline) |
|---|---|---|
| receipt | `ARC1` | `ARC1/receipt/v1\n` |
| checkpoint | `ARC1-checkpoint` | `ARC1/checkpoint/v1\n` |
| cosignature | `ARC1-cosignature` | `ARC1/cosignature/v1\n` |

A document with `"sig": null` is unsigned. It may be well formed, but it
never verifies.

### 4.2 Algorithms

| `alg` | Signature | Verifying needs |
|---|---|---|
| `ed25519` | 64 bytes, RFC 8032 Ed25519 (pure, not Ed25519ph). Verification is cofactorless: `S < L` and the encoding of `R` are enforced as RFC 8032 section 5.1.7 requires. | the 32-byte public key |
| `hmac-sha256` | 32 bytes, HMAC-SHA256 keyed with the shared secret | the secret (so anyone who can verify can also sign: section 12) |

The reference implementation verifies Ed25519 with the standard library alone.
[`src/agentgov/receipts/_ed25519.py`](../src/agentgov/receipts/_ed25519.py)
implements RFC 8032. It uses `cryptography`, if installed, only for speed, and
both paths accept exactly the same signatures. Signing with Ed25519 needs the
optional extra, `pip install 'agentgov[sign]'`. HMAC-SHA256 needs nothing.

### 4.3 Key ids and key specs

A `key_id` names a key. It is not a trust anchor.

- Ed25519: the first 16 *hex* characters of `SHA-256("ARC1/ed25519/v1\n" || public_key)`.
  The vector issuer key
  `84d68357a03e617192556ebb3243e3d735512f882c97d4521f00155580443d7f` has id
  `bcc542d53c8c1a1f`.
- HMAC-SHA256: the first 16 *hex* characters of `HMAC-SHA256(secret, "ARC1/key-id/v1")`,
  unless the issuer names the key explicitly.

A key is written on the command line or in a file as `<alg>:<hex>`. For
example, `ed25519:<64 hex chars>` is a public key and `hmac-sha256:<hex>` is a
shared secret.

### 4.4 Verification rule

The verifier supplies the key it trusts, and the key decides the algorithm.
The document never does. A signature verifies only if:
- `sig.alg` equals the key's algorithm;
- `sig.key_id` equals the key's id;
- the signature is valid over the signing input.

A document signed with an HMAC "keyed" with the issuer's *public* Ed25519 key
therefore fails on the first rule. That is the vector case `alg-confusion`.

## 5. The receipt

### 5.1 Top level

| Field | Type | Meaning |
|---|---|---|
| `v` | `"ARC1"` | |
| `receipt_id` | *uuid* | unique within a log (section 7.1) |
| `issued_at` | *instant* | when the issuer signed it, by the issuer's clock |
| `issuer` | *text* | who measured and signed, e.g. `interlock/0.2.0 support-eu-1` |
| `authority` | object, 5.2 | who authorized the action |
| `intent` | object, 5.3 | what the agent said it would do |
| `effect` | object, 5.4 | what it measurably did |
| `coverage` | object, 5.5 | what the measurement could not see |
| `decision` | object, 5.6 | what was decided |
| `cost` | object, 5.7 | what it cost |
| `outcome` | object, 5.8 | how it ended |
| `anchors` | object, 5.9 | where it sits in other chains |
| `sig` | object (4.1) or `null` | |

### 5.2 `authority`

| Field | Type | Meaning |
|---|---|---|
| `scope_path` | array of *text*, at least one, no repeats | the AgentGov scope path from the root to the acting scope, in order |
| `trajectory_id` | *text* | the agent run this action belongs to |
| `capability.grant` | *text* | the grant the agent acted under |
| `capability.tables` | *set* | tables it may write |
| `capability.tenants` | *set* | tenants it may write |
| `capability.row_limit` | *int* or `null` | the most rows one action may change |

### 5.3 `intent`

| Field | Type | Meaning |
|---|---|---|
| `plan_hash` | *hash* | SHA-256 of the canonical plan the agent submitted |
| `stated.rows` | *int* or `null` | the number of rows the agent said the plan would change |
| `stated.tables` | *set* | the tables it said the plan would touch |

### 5.4 `effect`

| Field | Type | Meaning |
|---|---|---|
| `substrate_id` | *text* | the system of record, e.g. `sqlite` |
| `schema_hash` | *hash* | its schema when the plan ran |
| `diff_hash` | *hash* | the measured diff, as the escrow chain's `DIFF_COMPUTED` record carries it |
| `row_root` | *hash* | the salted Merkle root over the row changes (section 6) |
| `row_count` | *int* | how many row changes `row_root` commits to |
| `summary.ins`, `summary.upd`, `summary.del` | *int* | row changes by operation |
| `summary.tables`, `summary.tenants` | *set* | where they were |
| `truncated` | boolean | `true` if the measurement stopped at its row cap. The diff, and everything committed to here, is then a prefix of the plan's full effect, not all of it. |

**Rule:** `row_count = ins + upd + del`.

### 5.5 `coverage`

| Field | Type | Meaning |
|---|---|---|
| `observed_tables` | *set* | the tables the measurement read before and after |
| `cascade_closed` | boolean | writes by foreign-key cascades were followed into the diff |
| `authorizer_on` | boolean | writes to tables outside `observed_tables` were refused at the substrate |
| `known_gaps` | *set* | what the issuer knows the measurement cannot see, in words |

A receipt must never promise more than was measured, so its blind spots are
part of what is signed.

### 5.6 `decision`

| Field | Type | Meaning |
|---|---|---|
| `verdict_hash` | *hash* | SHA-256 of the canonical verdict document |
| `admitted` | boolean | every check admitted the plan |
| `checkers` | array of `{name: text, config_hash: hash}`, names unique | each check that ran, with a digest of its configuration |
| `policy_epoch` | *int* | the version of the policy the checks belonged to |
| `repair_of` | *uuid* or `null` | the `receipt_id` of a refused action this one repairs |

### 5.7 `cost`

| Field | Type | Meaning |
|---|---|---|
| `ledger_txn_ids` | array of *uuid*, sorted (section 2), no duplicates | the AgentGov ledger transactions that paid for the action |
| `settled_usd` | *money* | the SPEND those transactions settled, in total |
| `served_models` | *set* | the models that served the calls |

### 5.8 `outcome`

| Field | Type | Meaning |
|---|---|---|
| `status` | `committed`, `refused`, `recovered_committed` or `recovered_aborted` | whether the effects are durable. The `recovered_*` values are settled after a crash, from the escrow chain's commit marker. |
| `substrate_txid` | *text* or `null` | the substrate's own id for the transaction |

**Rule:** a `committed` or `recovered_committed` status requires `decision.admitted = true`.
A refused plan cannot have committed.

### 5.9 `anchors`

Each member is an object or `null`, and a verifier checks the ones it can.

| Field | Type | Meaning |
|---|---|---|
| `agentgov` | `{seq: int, head: hash}` or `null` | the AgentGov ledger had `seq` entries, and its head hash was `head`, when the receipt was issued (section 10, check 5) |
| `escrow` | `{seq: int, head: hash}` or `null` | the same, for the issuer's escrow chain |
| `log` | `{log_id: text, leaf_index: int}` or `null` | the receipt log and index the receipt claims (section 7.1). It is inside the signature. |

## 6. Row commitments and disclosures

A receipt carries no row data. It commits to the rows in `effect.row_root`.
The issuer keeps a 32-byte **row secret** per receipt. It can later disclose
any subset of the rows, each with a proof, while the rest stay hidden.

**A row change** is an object:

| Field | Type |
|---|---|
| `table` | *text* |
| `pk` | *text* |
| `op` | `insert`, `update` or `delete` |
| `tenant` | *text* or `null` |
| `before` | object of column → value, or `null` |
| `after` | object of column → value, or `null` |

An insert has only `after`, a delete only `before`, and an update both. Column
names are *text*. Values are strings, integers in the safe range, booleans or
`null`. Anything else is converted to a string before committing:
- integers outside the safe range, in decimal;
- floats, in their shortest round-trip form;
- decimals, exactly;
- bytes, as *hex*;
- instants, in ISO 8601.

**The commitment** over rows `row_0 … row_{n−1}`, in the order the issuer
measured them:

```
salt_i     = HMAC-SHA256(row_secret, "ARC1/row-salt/v1\n" || uint64_be(i))
leaf_i     = SHA-256(0x00 || "ARC1/row/v1\n" || salt_i || canonical(row_i))
row_root   = the RFC 9162 root over leaf_0 … leaf_{n−1}   (section 7.2)
```

The per-row salt prevents guessing. Without it, a row with few possible values
could be recovered from the root by hashing candidates. Revealing one row's
salt reveals nothing about any other, because HMAC is a pseudorandom function.

**A disclosure** (`v: "ARC1-rows"`):

| Field | Type |
|---|---|
| `v` | `"ARC1-rows"` |
| `receipt_id` | *uuid* |
| `row_root` | *hash* |
| `row_count` | *int* |
| `rows` | array of `{index: int, salt: hash, row: row change, audit_path: [hash]}` |

A disclosure verifies against a receipt only if all of these hold:
- `receipt_id`, `row_root` and `row_count` equal the receipt's `receipt_id`,
  `effect.row_root` and `effect.row_count`;
- at least one row is disclosed;
- no index appears twice;
- every row's leaf, computed from its `salt` and `row`, is included at `index`
  in a tree of `row_count` leaves with root `row_root`, by its `audit_path`
  (RFC 9162 section 2.1.3.2).

## 7. The receipt log

### 7.1 Leaves and positions

A receipt log is an append-only RFC 9162 Merkle tree. Leaf *i* is the
canonical bytes of the *i*-th signed receipt, signature included. Its leaf
hash is `SHA-256(0x00 || canonical(receipt))`.

A receipt names its own place, `anchors.log = {log_id, leaf_index}`, inside
its signature. A log operator therefore cannot move a receipt to another index
or another log without breaking the signature, even while handing out a valid
audit path to the new position (the vector case `leaf-moved`). A log accepts a
receipt only at the index it names, and accepts each `receipt_id` once.

The reference log stores one canonical receipt per line in a JSON-lines file,
and its checkpoints in `<file>.checkpoints`, forcing each line to disk before
acknowledging it. The byte-exact lines are the leaves, so recomputing the log
needs nothing but SHA-256. `vectors/arc1/log/` is such a log.

### 7.2 The tree

As [RFC 9162 section 2.1](https://www.rfc-editor.org/rfc/rfc9162#section-2.1):

```
MTH({})       = SHA-256()
MTH({d0})     = SHA-256(0x00 || d0)
MTH(D[n])     = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                where k is the largest power of two smaller than n
```

Inclusion proofs (audit paths) and consistency proofs are RFC 9162's `PATH`
and `PROOF`. They are verified exactly as sections 2.1.3.2 and 2.1.4.2
specify, including their early rejections.

### 7.3 Checkpoints

A checkpoint (`v: "ARC1-checkpoint"`) is the log's signed statement of its
size and root:

| Field | Type |
|---|---|
| `v` | `"ARC1-checkpoint"` |
| `log_id` | *text* |
| `tree_size` | *int* |
| `root_hash` | *hash* |
| `issued_at` | *instant* |
| `sig` | object (4.1) or `null` |

The signed tree size matters. An RFC 9162 audit path can also verify against
the root of a tree of a *different* size. A verifier must therefore check that
a proof's tree size equals the checkpoint's signed `tree_size`, and never
trust a size carried only in the proof.

## 8. Witnesses

A log operator can rebuild its tree at will, so a checkpoint signed by the
log proves nothing about what the log said yesterday. A **witness** is an
independent party that cosigns checkpoints. Before cosigning a checkpoint of
log *L* at size *n*, a witness must check all of the following:

1. The checkpoint verifies under *L*'s key (section 4.4).
2. For the last checkpoint of *L* it cosigned, at size *m* with root *r*:
   - *n* ≥ *m*: a smaller *n* is a **rollback**, refused;
   - if *n* = *m*, the root equals *r*: a different root is a **fork**,
     refused. An equal root is cosigned once, idempotently;
   - if *n* > *m*, an RFC 9162 consistency proof from *m* to *n* verifies
     against *r* and the new root. Otherwise **history was rewritten**, and
     the checkpoint is refused.

A cosignature (`v: "ARC1-cosignature"`):

| Field | Type |
|---|---|
| `v` | `"ARC1-cosignature"` |
| `witness_id` | *text* |
| `log_id` | *text* |
| `tree_size` | *int* |
| `root_hash` | *hash* |
| `witnessed_at` | *instant* |
| `sig` | object (4.1) or `null` |

A witness publishes its cosignatures as a JSON-lines file, one canonical
cosignature per line, in the order it made them. To check that a checkpoint
was witnessed, a verifier holds the witness's key and considers only lines of
that file that verify under it. A forged line is ignored, never trusted. The
checkpoint was witnessed if a verifying line has the same `log_id`,
`tree_size` and `root_hash`. The verifier reports a **split view** if any
verifying line has the same `log_id` and `tree_size` but a different root,
even when another line matches. Two witnessed roots for one size are
themselves proof that the log showed two histories.

`FileWitness` is the development witness. In production a witness runs
somewhere the log operator cannot write. RFC 3161 timestamp authorities and
public transparency-log witnesses fit behind the same `Witness` interface.

## 9. Bundles

A bundle (`v: "ARC1-bundle"`) is what a verifier is handed:

| Field | Type |
|---|---|
| `v` | `"ARC1-bundle"` |
| `receipt` | a receipt (section 5) |
| `inclusion` | `{leaf_index: int, tree_size: int ≥ 1, audit_path: [hash]}` with `leaf_index < tree_size`, or `null` |
| `checkpoint` | a checkpoint (section 7.3), or `null` |

`inclusion` and `checkpoint` are both present or both `null`. A verifier also
accepts a bare receipt as a bundle without a proof.

## 10. Verification

A verifier runs the checks it was given evidence for, **in this order**. It
reports every check, and the first failure decides the result. The reference
verifier is `verify_bundle()` in
[`src/agentgov/receipts/verify.py`](../src/agentgov/receipts/verify.py), and
its command line is `agentgov verify-receipt`.

| # | Check | Passes when | Needs | Fails with |
|---|---|---|---|---|
| 1 | ARC1 schema | the bundle, and everything in it, decodes strictly (sections 2, 3, 5, 9) | the bundle | 3 `MALFORMED` (the only check that stops the others) |
| 2 | receipt signature | section 4.4, over the receipt | the issuer's key | 4 `SIGNATURE` |
| 3 | log inclusion | the checkpoint verifies under the log's key; the receipt's `anchors.log` names the checkpoint's `log_id` and the proof's `leaf_index`; the proof's `tree_size` is the checkpoint's; the audit path leads from the receipt's leaf hash to `root_hash` | a bundle with a checkpoint; the log's key (the issuer's by default) | 5 `INCLUSION` |
| 4 | witnessed | section 8, for the bundle's checkpoint | the witness's cosignature file and key | 6 `WITNESS` |
| 5 | agentgov ledger | the ledger has at least `anchors.agentgov.seq` entries; entry `seq` hashes to `head` (seq 0 is the genesis hash); every `cost.ledger_txn_ids` transaction is among the first `seq` entries; their SPEND amounts sum to exactly `cost.settled_usd` | the AgentGov ledger, which itself verifies at open | 7 `LEDGER` |
| 6 | disclosed rows | section 6 | a disclosure | 8 `ROWS` |

A check with no evidence is reported as skipped, not passed. An input that
exists but does not decode fails the check it feeds, in that check's place in
the order. For example, a malformed witness file fails check 4 with
`MALFORMED`. A forged receipt signature is therefore never hidden behind a
bad input further down the list.

```console
$ agentgov verify-receipt BUNDLE --pubkey KEY
      [--log-pubkey KEY]                     # when the log signs with its own key
      [--witness FILE --witness-pubkey KEY]  # the witness's cosignatures, and its key
      [--ledger DB]                          # an AgentGov SQLite ledger, opened read-only
      [--rows FILE]                          # an ARC1-rows disclosure
      [--json]                               # the report as JSON
```

A `KEY` is a key spec (section 4.3) or a file holding one. The exit code is 0
when every requested check passes. Otherwise it is the first failure's code
(3 to 8), or 2 for a usage error or a file that cannot be read.

## 11. Test vectors

[`vectors/arc1/`](../vectors/arc1/) is generated deterministically by
[`scripts/generate_arc1_vectors.py`](../scripts/generate_arc1_vectors.py).
The test suite regenerates it on every run and fails if a byte differs. See
its [README](../vectors/arc1/README.md) for the layout. `manifest.json` lists
every command-line case with its expected exit code, which makes it a
conformance suite for any other verifier.

## 12. Security considerations

- **HMAC keys are internal.** Anyone who can verify an `hmac-sha256` signature
  can forge one. Use HMAC between components that already share a trust
  domain, and Ed25519 for anything shown to an outside party.
- **Pass an HMAC secret as a file.** A key written inline on the command line
  is visible to other users of the machine, and lands in shell history. Every
  key option also accepts the path of a file that holds the key.
- **Trust comes from the key the verifier supplies.** A `key_id` is a label.
  The verifier never takes the algorithm or the key from the document
  (section 4.4).
- **Clocks.** `issued_at` is the issuer's claim. A witness cosignature bounds
  it from above: the receipt existed no later than the `witnessed_at` of the
  first cosigned checkpoint that covers it.
- **Witness independence.** A witness the log operator can write to protects
  against accidents, not against the operator. Keep the witness's key and file
  out of the operator's reach, and verify against more than one witness where
  it matters.
- **The row secret is a key.** Anyone holding it can recompute every salt,
  which lets them test guesses at hidden rows against the leaf hashes that
  disclosures reveal. Store it like a signing key, and destroy it when the
  retention period for disclosures ends. Once it is gone, no row can be
  disclosed.
- **Metadata.** A receipt reveals the tables, tenants, row counts, models and
  cost of the action, even when no row is disclosed. Consider that before
  publishing receipts outside the organization.
- **Omissions.** A log proves what it contains, in order. An issuer that never
  logs an action is detectable only by comparing the log with an independent
  record of what happened, such as the AgentGov ledger's transactions or the
  escrow chain. Refusals are logged exactly like commits, so the log also
  records what was *not* allowed.
