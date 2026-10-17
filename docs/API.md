# API reference (1.0)

`agentgov` exports what a user of the governor needs, and `agentgov.spi` what a store
implementer needs. Both lists are frozen for 1.x by `tests/test_public_api.py`: within
1.x a name is added, or deprecated (warning, and still served), never removed. Every
module, class and function below carries its full documentation in its docstring; this
page is the map.

Names 1.0 moved or retired are still served from `agentgov` with a `DeprecationWarning`,
and are removed in 2.0: the store types (now `agentgov.spi`), `AgentThrashingException`
and `DenialOfWalletException` (the same classes as their `*Error` names), and
`LedgerLine`. `Ledger.lock` warns too: use `BudgetManager.transaction()` or
`try_authorize()`. `Ledger.post()` is removed (D6).

## Opening a governor

| Name | |
|---|---|
| `open(url, **options)` | A governor for `memory:`, `sqlite:///path` or `postgresql://...` (with `?schema=`, `lock_timeout`, `idle_timeout`, `prepare_threshold`). |
| `BudgetManager` | The governor. `BudgetManager()` in memory, `BudgetManager.open_sqlite(path)`, `BudgetManager.open_postgres(dsn)`. |
| `AsyncBudgetManager` | The same operations as coroutines, off the event loop, sharing the governor's group commit. |
| `GovernancePolicy` | Limits: the runaway-loop window (`fleet_velocity`), delegation depth, overdraft and exhaustion trips, `checkpoint_every`. |
| `CheckpointSigning` | Who signs ledger checkpoints, whose signatures count, and whether an unsigned one may be opened from. |
| `SqliteStore` | The SQLite store, for constructing a governor over one by hand. |

## The governor's operations

`BudgetManager` (and `AsyncBudgetManager`, awaited):

- **Topology:** `open_root`, `fund`, `delegate`, `release`, `scopes`, `descendants`,
  `ancestry`.
- **Spending:** `authorize`, `try_authorize`, `capture`, `void`, `spend`,
  `refund(..., reverses=)`, `anchor`. Each money operation takes `idempotency_key=`.
- **Atomic units:** `transaction()` yields a `Transaction`: current reads, one commit,
  atomic across a fleet; a block that raises writes nothing.
- **Reads:** `available`, `subtree_available` and `is_halted` (each with `fresh=True` to
  catch up first), `halted_by`, `authorization(id)`, `stale_authorizations`.
- **History:** `entry`, `entries`, `find_entries`, `audit_trail`, `iter_audit_trail`.
- **The breaker:** `trip`, `reset`, `void_stale`, `control_events`.
- **The ledger's health:** `refresh`, `verify_integrity`, `checkpoint`,
  `checkpoint_lag`, `publish_checkpoint`, `pending_claims`, `redeem`, `joined`.

| Value type | |
|---|---|
| `Authorization` | A hold placed before a call: what `capture()` and `void()` settle. |
| `LedgerEntry` | One immutable, hash-chained record. `EntryType` and `Direction` describe it. |
| `BudgetNode` | One scope in the delegation tree. |
| `ControlEvent` | A breaker trip or reset, as recorded in the chain. |
| `Transaction` | The unit of work `transaction()` holds open. |
| `JoinedTransaction`, `SettlementClaim` | A governor's part in a transaction someone else owns, and what it owes. |
| `Ledger` | The governor's read-only view of the chain (`gov.ledger`). |
| `money(value)` | A quantized monetary `Decimal`. |
| `format_audit_line(entry)` | An entry as one fixed-field audit log line. |

## Errors

`AgentGovError` is the root. Four branches never overlap:

- **Refused** (`BudgetError`): `BudgetExceededError`, `DenialOfWalletError` (also a breaker
  trip), `SubBudgetAllocationError`.
- **Halted** (`CircuitBreakerError`): `CircuitOpenError`, `AgentThrashingError`,
  `RunawayLoopDetectedError`.
- **Compromised** (`LedgerError`): `LedgerIntegrityError`, `LedgerRollbackError` (the chain
  was cut back, as by a failover), `DoubleSpendError`.
- **Unavailable or contended** (`StorageError`): `ConcurrentGovernorError`,
  `ReadOnlyLedgerError`, `LedgerConflictError`.

Also `ScopeError` (`UnknownScopeError`, `DuplicateScopeError`) and
`IdempotencyConflictError` (a key reused for another call). Receipt errors live in
`agentgov.exceptions` and `agentgov.receipts`.

## Metering calls

| Name | |
|---|---|
| `Interceptor` | Wraps model calls so each is authorized, metered and captured. |
| `SpendGuard` | Authorize and capture around one call site, as a context manager. |
| `MeteredCall`, `MeteredStream`, `AsyncMeteredStream` | What a governed call returned, and streaming calls. |
| `govern(client)`, `GovernedClient`, `GovernorHandle` | An SDK client whose calls are governed where they are made. |
| `TokenUsage`, `ModelPricing`, `PRICING`, `pricing_for`, `normalize_model_id` | Usage and rates. |
| `default_usage_extractor`, `estimate_tokens`, `extract_prompt_text`, `CHARS_PER_TOKEN` | Helpers for usage extraction. |

## The cognitive breaker

`CognitiveBreaker` and `CognitivePolicy`; the detectors `LoopDetector`,
`ExactRepeatDetector`, `NearDuplicateDetector`, `CallCycleDetector`; `SemanticObserver` and
`TrajectoryEntropyObserver`; `ToolCall`, `Verdict`, `Redactor`, `canonical_arguments`,
`extract_result_text`.

## Reconciliation

`reconcile`, `load_provider_export`, `ProviderUsageRecord`, `ReconciliationPolicy`,
`ReconciliationReport`, `MeteringJournal`.

## Other modules

| Module | |
|---|---|
| `agentgov.receipts` | ARC1 action receipts: documents, signing (`Ed25519Signer`, `RemoteSigner`, `HttpRemoteSigner`, `Keyring`), `ReceiptLog`, witnesses, bundles and verification. |
| `agentgov.receipts.kms_aws` | `AwsKmsSigner` (`agentgov[kms-aws]`). |
| `agentgov.postgres` | `PostgresStore`, the shared ledger (`agentgov[postgres]`). |
| `agentgov.metrics`, `agentgov.otel` | The `Metrics` protocol and its instrument names; `OpenTelemetryMetrics` (`agentgov[otel]`). |
| `agentgov.audit` | `Auditor` and `AuditorThread`: history an open from a checkpoint did not replay. |
| `agentgov.adapters` | LangChain and CrewAI drop-ins. |
| `agentgov.cli` | The `agentgov` command. |

## The SPI: `agentgov.spi`

For implementing a store: `PersistenceStore` (and the optional `idempotency(keys)` and
`unit()` it may offer), `SharedStore` with its `WriterSession`, `JoinableStore`; what
crosses the seam: `WriteBatch`, `StoreImage`, `StoreDelta`, `PersistedNode`,
`PersistedAuthorization`, `Snapshot`, `AuditMark`, `IdempotencyRecord`. A store's
transactions on one connection must each be kept whole against other threads; the
shipped stores hold a guard around each.
