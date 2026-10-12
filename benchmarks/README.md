# Benchmarks

What agentgov costs as a ledger grows, and how that compares with 0.4.0. The
scripts use the public API only, so the same script measures any release.

| Script | Measures |
|---|---|
| `bench_open.py` | Opening a governor at each ledger size: SQLite open (writable and read-only), `verify_integrity()`, held memory per entry and file size. With `--postgres DSN`, also the PostgreSQL open and the *stall*: the longest write another governor makes while the open runs. |
| `bench_throughput.py` | Writes per second and latency percentiles, with several callers, on SQLite or PostgreSQL. |
| `bench_receipts.py` | Receipt issuance with a signer that takes a fixed time per signature, as a key service does. |

```sh
uv run python benchmarks/bench_open.py --sizes 10000 50000 150000 --postgres postgresql://...
uv run python benchmarks/bench_throughput.py --backend sqlite --callers 4 --seconds 10
uv run python benchmarks/bench_receipts.py --count 256 --latency-ms 50
```

Ledgers are built once under `benchmarks/.fixtures/` (git-ignored) and reused.
Each script prints one JSON object per measurement, and `--out FILE` appends
them to a JSON-lines file.

The pass/fail gates on these numbers are tests, not this directory:
`tests/test_scale.py` holds the relative gates that run on every change, and
the absolute gates that run nightly with `AGENTGOV_SCALE=1`.

## Baseline

`baseline/` holds the numbers 1.0 is compared against. Both sets were taken
with these scripts on one machine (Apple Silicon, 10 cores, CPython 3.11.14,
PostgreSQL 16 in Docker), one after the other: 0.4.0 from its released wheel
in a separate virtualenv, building and opening ledgers in its own format, and
the 1.0 development tree at `7d881d4`. Every ledger has one root, eight
delegated scopes and three entries per `spend()`.

| Entries | SQLite open, 0.4.0 → 1.0 | PostgreSQL open | Stall of another writer | `verify_integrity()` | Held memory per entry | File per entry |
|---:|---:|---:|---:|---:|---:|---:|
| 10,000 | 258 → 1.6 ms | 328 → 27 ms | 312 → 3.3 ms | 83 → 193 ms | 1,152 → 3 B | 397 → 545 B |
| 50,000 | 1,284 → 1.5 ms | 1,719 → 34 ms | 1,701 → 10 ms | 404 → 1,005 ms | 1,125 → 1 B | 393 → 540 B |
| 150,000 | 4,409 → 1.9 ms | 4,576 → 37 ms | 5,193 → 2.9 ms | 1,328 → 3,768 ms | 1,121 → 0 B | 393 → 541 B |

How to read it:

- **Open.** 1.0 opens from the newest checkpoint and replays only the entries
  after it, so open time follows the distance to the last checkpoint, not
  the ledger's length. These ledgers end just after a checkpoint. The worst
  case, 9,997 entries past the last checkpoint, is the scale gate below.
- **Stall.** 0.4.0 opened under the fleet's writer lock, so every other
  governor waited for the whole open. 1.0 opens without it: the stall is
  one ordinary write.
- **`verify_integrity()`.** This now reads history from the store; 0.4.0
  already held it in memory, having loaded all of it at open. Open and
  verify together are faster in 1.0 (3.8 s against 5.7 s at 150,000), and
  the replay runs outside the governor's lock, so writes continue during it.
- **Memory.** 1.0 serves history from the store, so an open governor holds
  its state, not its history.
- **File size.** 38% more per entry: the indexes that serve `find_entries()`
  and history by sequence without a scan, and AGOV3's fixed-point amounts.

## Throughput

`bench_throughput.py` in a closed loop: each caller loops `authorize()` and `capture()` on
a scope of its own for 10 seconds. The median of three runs, 0.4.0 and 1.0 interleaved run
by run on the same machine, with a load average of 3 to 7 from other work
(`baseline/throughput-*.jsonl`):

| | SQLite, 1 caller | SQLite, 8 callers | PostgreSQL, 1 governor, 8 callers | PostgreSQL, 8 governors of 8 callers |
|---|---:|---:|---:|---:|
| 0.4.0 | 5,907 /s, p99 0.7 ms | 5,850 /s, p99 9.7 ms | 425 /s, p99 66 ms | 188 /s, p99 1,944 ms |
| 1.0 | 4,208 /s, p99 1.7 ms | 5,428 /s, p99 11.9 ms | 2,126 /s, p99 9.4 ms | 1,684 /s, p99 105 ms |

How to read it:

- **PostgreSQL.** 0.4.0 made each mutation alone, in six or more round trips under the
  fleet's writer lock. In 1.0 a unit of work is two round trips, and it carries every
  caller that arrived while the last one committed.
- **SQLite, one caller.** 1.0 does more for each operation: AGOV3's canonical hashing,
  the rule engine's checks, and two history indexes, about 70 µs in all. With eight
  callers, units of work share one commit and one sync, and the gap nearly closes. Two
  more indexes, on `transaction_id` and `ref`, cost a further 20% with one caller and
  are not kept (`docs/LEDGER_FORMAT.md`, section 5).
- **The 1.0 targets.** One governor: 1,500 a second, met. Eight governors: 2,000 a
  second, met at `6d2dc06` on a quieter machine (2,026 to 2,187). On this machine
  `6d2dc06` measured 1,455 against this tree's 1,837, interleaved. A p99 under 25 ms for
  eight governors was not met: in a closed loop, mean latency is at least
  callers / throughput, 38 ms for 64 callers at 1,700 a second. A chain per root scope,
  in 1.1 if measurements call for it, is how that would come down.
- **Latency at a load** is `--rate`'s: an open loop offers operations at a fixed rate and
  counts each operation's latency from when it was due.

## Receipt issuance

`bench_receipts.py` with a signer that takes 50 ms per signature, as a round
trip to a KMS does, 128 receipts (`baseline/receipts-*.jsonl`):

| | One caller | 16 callers |
|---|---:|---:|
| 0.4.0 | 18.6 /s | 18.4 /s |
| 1.0 | 18.1 /s | 246.5 /s |

0.4.0 signed while holding the log's lock, so callers queued behind one
another. 1.0 takes a position under the lock, signs outside it, and appends
in position order, so 16 callers overlap their signatures: 13.4 times
0.4.0's rate, against the target of 10.

A durable receipt log of 100,000 receipts (a 238 MB file, a checkpoint
every 1,000), reopened:

| | Reopen | Memory held open |
|---|---:|---:|
| 0.4.0 | 24,326 ms | 672 MB |
| 1.0 | 1.3 ms | 27 KB |

0.4.0 parsed every receipt into memory and checked every checkpoint. 1.0
keeps an index of the file beside it, checks the newest checkpoint against
the index's tree and re-verifies only what was signed since it; receipts are
read from the file when asked for, each checked against the leaf hash
recorded for it.

## Scale gates

Measured the same way (`tests/test_scale.py` and the scripts above):

| Gate | Result | Bound |
|---|---:|---:|
| 1,009,998 entries, newest checkpoint 9,997 behind: SQLite open | 245 ms | 500 ms |
| The same ledger copied into PostgreSQL: open | 275 ms | 500 ms |
| Stall of another writer during that open | 4 ms | 250 ms |
| 1M entries against 10,000: open time ratio | 1.0× | 2× |
| Held memory, 10,000 → 1M entries | flat | 1.5× |
| 100,000 scopes and 10,000 open holds: checkpoint, reopen | 1.2 s, 2.2 s | 10 s, 5 s |
