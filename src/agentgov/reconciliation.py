"""Invoiced-to-metered reconciliation: proving there was no unmetered spend.

A governor that only knows what it *thinks* it spent is an estimate. The
question a finance or security team actually asks is narrower and harder:

    The provider billed us $40,000 last month. Which agent caused it, and is
    there anything on that invoice we never authorized?

This module answers it by matching a provider's usage export against the
hash-chained ledger and sorting every line into one of four buckets:

- **Matched** — billed and metered, within tolerance. The healthy case.
- **Discrepant** — the same call, but the billed cost differs from what was
  settled. Usually a stale price table; occasionally a billing error.
- **Phantom** — billed by the provider, absent from the ledger. **This is the
  finding that matters.** Either something called the model outside the
  governor, or a credential leaked. Any phantom line fails the audit.
- **Unsettled** — metered locally, never billed. Usually a timing boundary,
  sometimes a provider under-count.

Two deliberate design points.

**Tolerances, not equality.** Timestamps drift by network latency, and token
counts drift because the pre-flight estimate is a ``chars/4`` heuristic. Exact
matching would report a healthy ledger as entirely broken, so matching is
fuzzy along both axes, with the windows configurable.

**Tokens come from a journal, not the ledger.** :class:`~agentgov.core.LedgerEntry`
records money and structure, deliberately — it does not carry token counts.
:class:`MeteringJournal` is the additive sidecar that does. Without one,
reconciliation still works on cost and time; with one, it can also match on
tokens and tell a price-table drift apart from a genuine billing discrepancy.
"""

from __future__ import annotations

import csv
import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from io import StringIO
from pathlib import Path
from typing import TypeVar

from agentgov.core import BudgetManager, EntryType
from agentgov.exceptions import AgentGovError
from agentgov.interceptor import PRICING, MeteredCall, TokenUsage

__all__ = [
    "Discrepancy",
    "MatchedCall",
    "MeteredRecord",
    "MeteringJournal",
    "ProviderUsageRecord",
    "ReconciliationPolicy",
    "ReconciliationReport",
    "UsageParseError",
    "format_report",
    "load_provider_export",
    "metered_records",
    "parse_anthropic_csv",
    "parse_openai_json",
    "reconcile",
]

_CENT = Decimal("0.000001")

R = TypeVar("R")


class UsageParseError(AgentGovError):
    """Raised when a provider export cannot be interpreted.

    :param detail: What could not be read, and what was expected instead.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(f"cannot parse provider usage export: {detail}")


# --------------------------------------------------------------------------
# Records
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProviderUsageRecord:
    """One billed line item from a provider's usage export.

    :ivar record_id: Stable identifier from the export, or a synthesised one.
    :ivar timestamp: When the provider says the call happened (UTC).
    :ivar model: The provider's model identifier.
    :ivar input_tokens: Billed input tokens.
    :ivar output_tokens: Billed output tokens.
    :ivar total_cost: What the provider charged, in USD.
    :ivar source: Which export the line came from, for the audit trail.
    :ivar cost_was_derived: ``True`` when the export omitted a cost and it was
        computed from the published rate card. Such a line cannot, by
        construction, reveal a pricing discrepancy — the report says so rather
        than implying a match it did not verify.
    """

    record_id: str
    timestamp: datetime
    model: str
    input_tokens: int
    output_tokens: int
    total_cost: Decimal
    source: str = ""
    cost_was_derived: bool = False

    @property
    def total_tokens(self) -> int:
        """Billed tokens across both directions."""
        return self.input_tokens + self.output_tokens


@dataclass(frozen=True, slots=True)
class MeteredRecord:
    """One settled call as AgentGov recorded it.

    Assembled from a ledger ``SPEND`` entry, enriched with token counts from a
    :class:`MeteringJournal` when one is available.

    :ivar transaction_id: The ledger transaction that settled the call.
    :ivar sequence: The spend entry's position in the hash chain.
    :ivar timestamp: When the settlement was committed (UTC).
    :ivar scope_id: The agent charged — the attribution answer.
    :ivar model: The model billed against, when known.
    :ivar input_tokens: Metered input tokens, or ``None`` without a journal.
    :ivar output_tokens: Metered output tokens, or ``None`` without a journal.
    :ivar settled_cost: What AgentGov settled, in USD.
    :ivar entry_hash: The chain hash, so a matched line can be proven.
    """

    transaction_id: uuid.UUID
    sequence: int
    timestamp: datetime
    scope_id: str
    model: str
    input_tokens: int | None
    output_tokens: int | None
    settled_cost: Decimal
    entry_hash: str

    @property
    def total_tokens(self) -> int | None:
        """Metered tokens, or ``None`` when no journal recorded them."""
        if self.input_tokens is None or self.output_tokens is None:
            return None
        return self.input_tokens + self.output_tokens


# --------------------------------------------------------------------------
# The metering journal
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """Token counts for one settled transaction.

    :ivar transaction_id: The ledger transaction this describes.
    :ivar model: The model the call was priced against.
    :ivar usage: The token counts the provider reported.
    :ivar scope_id: The scope that made the call.
    :ivar settled_at: When the call settled (UTC).
    """

    transaction_id: uuid.UUID
    model: str
    usage: TokenUsage
    scope_id: str
    settled_at: datetime


class MeteringJournal:
    """Token counts alongside the ledger, keyed by transaction.

    The ledger records money and structure and deliberately nothing else — a
    financial record should not become a second copy of every prompt's
    metadata. But reconciliation wants token counts, so this is the additive
    sidecar that carries them.

    Populate it from the :class:`~agentgov.interceptor.MeteredCall` every
    governed call already returns; the framework adapters do it for you::

        journal = MeteringJournal()
        result = interceptor.invoke(client.messages.create, ...)
        journal.record(result)
        journal.save("governor.db.tokens.jsonl")

    Reconciliation works without one — on cost and time alone — but cannot
    then distinguish a price-table drift from a genuine billing discrepancy.
    """

    __slots__ = ("_entries",)

    def __init__(self, entries: Iterable[JournalEntry] = ()) -> None:
        self._entries: dict[uuid.UUID, JournalEntry] = {
            entry.transaction_id: entry for entry in entries
        }

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, transaction_id: object) -> bool:
        return transaction_id in self._entries

    def entries(self) -> tuple[JournalEntry, ...]:
        """Every recorded entry, in insertion order."""
        return tuple(self._entries.values())

    def get(self, transaction_id: uuid.UUID) -> JournalEntry | None:
        """Look up one transaction's token counts."""
        return self._entries.get(transaction_id)

    def record(self, call: MeteredCall[R]) -> JournalEntry:
        """Record the token counts of a completed metered call.

        :param call: The result of a governed call.
        :returns: The journal entry written.
        """
        entry = JournalEntry(
            transaction_id=call.transaction_id,
            model=call.model_id,
            usage=call.usage,
            scope_id=call.scope_id,
            settled_at=call.entry.timestamp,
        )
        self._entries[entry.transaction_id] = entry
        return entry

    def record_usage(
        self,
        transaction_id: uuid.UUID,
        model: str,
        usage: TokenUsage,
        scope_id: str,
        settled_at: datetime,
    ) -> JournalEntry:
        """Record token counts directly, for callers not holding a MeteredCall.

        :param transaction_id: The ledger transaction that settled the call.
        :param model: The model the call was priced against.
        :param usage: The token counts.
        :param scope_id: The scope charged.
        :param settled_at: When the call settled.
        :returns: The journal entry written.
        """
        entry = JournalEntry(
            transaction_id=transaction_id,
            model=model,
            usage=usage,
            scope_id=scope_id,
            settled_at=settled_at,
        )
        self._entries[transaction_id] = entry
        return entry

    # -- persistence ------------------------------------------------------

    def save(self, path: str | Path) -> None:
        """Write the journal as JSON Lines.

        One object per line, so the file can be appended to by a long-running
        process and read back by ``agentgov reconcile --journal``.

        :param path: Destination file.
        """
        with Path(path).open("w", encoding="utf-8") as handle:
            for entry in self._entries.values():
                handle.write(
                    json.dumps(
                        {
                            "transaction_id": str(entry.transaction_id),
                            "model": entry.model,
                            "scope_id": entry.scope_id,
                            "settled_at": entry.settled_at.astimezone(UTC).isoformat(),
                            "input_tokens": entry.usage.input_tokens,
                            "output_tokens": entry.usage.output_tokens,
                            "cache_read_input_tokens": entry.usage.cache_read_input_tokens,
                            "cache_creation_input_tokens": (
                                entry.usage.cache_creation_input_tokens
                            ),
                        },
                        separators=(",", ":"),
                    )
                    + "\n"
                )

    @classmethod
    def load(cls, path: str | Path) -> MeteringJournal:
        """Read a journal previously written by :meth:`save`.

        :param path: The JSON Lines file to read.
        :returns: The restored journal.
        :raises UsageParseError: If a line cannot be interpreted.
        """
        entries: list[JournalEntry] = []
        for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                entries.append(
                    JournalEntry(
                        transaction_id=uuid.UUID(record["transaction_id"]),
                        model=record.get("model", ""),
                        scope_id=record.get("scope_id", ""),
                        settled_at=_parse_timestamp(record["settled_at"]),
                        usage=TokenUsage(
                            input_tokens=int(record.get("input_tokens", 0)),
                            output_tokens=int(record.get("output_tokens", 0)),
                            cache_read_input_tokens=int(record.get("cache_read_input_tokens", 0)),
                            cache_creation_input_tokens=int(
                                record.get("cache_creation_input_tokens", 0)
                            ),
                        ),
                    )
                )
            except (KeyError, ValueError, TypeError) as exc:
                raise UsageParseError(f"{path}:{number}: {exc}") from exc
        return cls(entries)


# --------------------------------------------------------------------------
# Reading the ledger side
# --------------------------------------------------------------------------


def metered_records(
    manager: BudgetManager, journal: MeteringJournal | None = None
) -> tuple[MeteredRecord, ...]:
    """Extract every settled call from a ledger, oldest first.

    :param manager: The governor whose ledger to read. A read-only manager is
        fine, and is what the CLI uses.
    :param journal: Token counts to enrich the records with, if available.
    :returns: One record per ``SPEND`` entry.
    """
    records: list[MeteredRecord] = []
    for entry in manager.audit_trail():
        if entry.entry_type is not EntryType.SPEND:
            continue
        journalled = journal.get(entry.transaction_id) if journal is not None else None
        records.append(
            MeteredRecord(
                transaction_id=entry.transaction_id,
                sequence=entry.sequence,
                timestamp=entry.timestamp,
                scope_id=entry.scope_id,
                model=journalled.model if journalled is not None else "",
                input_tokens=journalled.usage.input_tokens if journalled is not None else None,
                output_tokens=journalled.usage.output_tokens if journalled is not None else None,
                settled_cost=entry.amount,
                entry_hash=entry.entry_hash,
            )
        )
    return tuple(records)


# --------------------------------------------------------------------------
# Parsing provider exports
# --------------------------------------------------------------------------

_TIMESTAMP_KEYS = (
    "timestamp",
    "aggregation_timestamp",
    "created_at",
    "start_time",
    "usage_date_utc",
    "date",
    "usage_date",
)
_MODEL_KEYS = ("model", "snapshot_id", "model_id", "model_version")
_INPUT_KEYS = ("input_tokens", "n_context_tokens_total", "prompt_tokens", "context_tokens")
_OUTPUT_KEYS = ("output_tokens", "n_generated_tokens_total", "completion_tokens")
_COST_KEYS = ("total_cost", "cost", "cost_usd", "amount", "amount_usd")
_ID_KEYS = ("id", "request_id", "record_id", "line_id")


def _pick(row: Mapping[str, object], keys: Sequence[str]) -> object | None:
    """Return the first present, non-empty value among ``keys``."""
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def _parse_timestamp(value: object) -> datetime:
    """Interpret an ISO-8601 string, a date, or a Unix epoch as UTC."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, int | float) and not isinstance(value, bool):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            try:  # a bare epoch rendered as a string
                return datetime.fromtimestamp(float(text), tz=UTC)
            except ValueError as exc:
                raise UsageParseError(f"unrecognised timestamp {value!r}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    raise UsageParseError(f"unrecognised timestamp {value!r}")


def _parse_int(value: object, label: str) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError) as exc:
        raise UsageParseError(f"{label} is not a number: {value!r}") from exc


def _parse_cost(value: object, label: str) -> Decimal:
    try:
        return Decimal(str(value).replace("$", "").replace(",", "").strip())
    except (InvalidOperation, AttributeError) as exc:
        raise UsageParseError(f"{label} is not an amount: {value!r}") from exc


def _derive_cost(model: str, input_tokens: int, output_tokens: int) -> tuple[Decimal, bool]:
    """Price a line the export did not cost, using the published rate card.

    :returns: ``(cost, was_derived)``. A line with no cost and no known rate
        prices at zero and is flagged, rather than being silently dropped.
    """
    pricing = PRICING.get(_normalise_model(model))
    if pricing is None:
        return Decimal(0), True
    return (
        pricing.cost_of(TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens)),
        True,
    )


def _normalise_model(model: str) -> str:
    """Fold a provider's model string toward a rate-card identifier."""
    return model.strip().lower()


def _record_from_row(row: Mapping[str, object], index: int, source: str) -> ProviderUsageRecord:
    """Build one record from a parsed export row."""
    timestamp = _pick(row, _TIMESTAMP_KEYS)
    if timestamp is None:
        raise UsageParseError(
            f"{source} row {index}: no timestamp column (looked for {', '.join(_TIMESTAMP_KEYS)})"
        )
    model = str(_pick(row, _MODEL_KEYS) or "")
    input_tokens = _parse_int(_pick(row, _INPUT_KEYS) or 0, f"{source} row {index} input tokens")
    output_tokens = _parse_int(_pick(row, _OUTPUT_KEYS) or 0, f"{source} row {index} output tokens")

    raw_cost = _pick(row, _COST_KEYS)
    if raw_cost is None:
        cost, derived = _derive_cost(model, input_tokens, output_tokens)
    else:
        cost, derived = _parse_cost(raw_cost, f"{source} row {index} cost"), False

    identifier = _pick(row, _ID_KEYS)
    return ProviderUsageRecord(
        record_id=str(identifier) if identifier is not None else f"{source}#{index}",
        timestamp=_parse_timestamp(timestamp),
        model=model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_cost=cost,
        source=source,
        cost_was_derived=derived,
    )


def parse_openai_json(text: str, *, source: str = "openai-json") -> tuple[ProviderUsageRecord, ...]:
    """Parse an OpenAI-style JSON usage export.

    Accepts either ``{"data": [...]}`` or a bare list of objects, and resolves
    field names by alias — ``n_context_tokens_total`` and ``input_tokens`` are
    both understood — because the shape has changed more than once and an
    exporter that only handles today's is a liability.

    :param text: The JSON document.
    :param source: Label recorded on each record.
    :returns: The parsed records.
    :raises UsageParseError: If the document is not readable as usage lines.
    """
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise UsageParseError(f"{source}: invalid JSON: {exc}") from exc

    if isinstance(document, Mapping):
        rows = document.get("data", document.get("results", document.get("usage")))
    else:
        rows = document
    if not isinstance(rows, list):
        raise UsageParseError(
            f"{source}: expected a list of usage rows, or an object with a 'data' list"
        )

    parsed: list[ProviderUsageRecord] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise UsageParseError(f"{source} row {index}: expected an object, got {type(row)}")
        parsed.append(_record_from_row(row, index, source))
    return tuple(parsed)


def parse_anthropic_csv(
    text: str, *, source: str = "anthropic-csv"
) -> tuple[ProviderUsageRecord, ...]:
    """Parse an Anthropic-style CSV billing export.

    Column names are resolved by alias, so ``usage_date_utc``/``timestamp``
    and ``cost_usd``/``cost`` are equally acceptable.

    Note that a console export aggregated **per day** cannot be matched to
    individual calls — the timestamps are not per-call. Totals-level variance
    from such a file is still exact and still worth checking; the per-call
    buckets are only meaningful with a per-call export.

    :param text: The CSV document, including its header row.
    :param source: Label recorded on each record.
    :returns: The parsed records.
    :raises UsageParseError: If the document has no header or no rows.
    """
    reader = csv.DictReader(StringIO(text))
    if reader.fieldnames is None:
        raise UsageParseError(f"{source}: the file has no header row")
    normalised = [name.strip().lower().replace(" ", "_") for name in reader.fieldnames]
    reader.fieldnames = normalised

    parsed: list[ProviderUsageRecord] = []
    for index, row in enumerate(reader):
        if not any(value for value in row.values()):
            continue
        parsed.append(_record_from_row(dict(row), index, source))
    return tuple(parsed)


def load_provider_export(path: str | Path, *, fmt: str = "auto") -> tuple[ProviderUsageRecord, ...]:
    """Read a provider export, choosing a parser by extension or by ``fmt``.

    :param path: The export file.
    :param fmt: ``"auto"``, ``"openai-json"``, or ``"anthropic-csv"``.
    :returns: The parsed records.
    :raises UsageParseError: If the format cannot be determined or parsed.
    """
    location = Path(path)
    try:
        text = location.read_text(encoding="utf-8")
    except OSError as exc:
        raise UsageParseError(f"cannot read {location}: {exc}") from exc

    chosen = fmt
    if chosen == "auto":
        suffix = location.suffix.lower()
        if suffix == ".json":
            chosen = "openai-json"
        elif suffix in (".csv", ".tsv"):
            chosen = "anthropic-csv"
        else:
            chosen = "openai-json" if text.lstrip()[:1] in "[{" else "anthropic-csv"

    if chosen == "openai-json":
        return parse_openai_json(text, source=location.name)
    if chosen == "anthropic-csv":
        return parse_anthropic_csv(text, source=location.name)
    raise UsageParseError(f"unknown format {fmt!r}; expected auto, openai-json, or anthropic-csv")


# --------------------------------------------------------------------------
# The reconciliation itself
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReconciliationPolicy:
    """Tolerances for matching billed lines to settled ones.

    :ivar time_tolerance_seconds: How far a provider's timestamp may sit from
        the local settlement and still be the same call. Covers network
        latency, clock skew, and the gap between a call starting and settling.
    :ivar token_tolerance_percent: Permitted drift between billed and metered
        tokens. Pre-flight sizing is a ``chars/4`` heuristic, so some drift is
        expected; a large gap means the two are not the same call.
    :ivar cost_tolerance_percent: Permitted drift between billed and settled
        cost before a matched pair is reported as a discrepancy. This is what
        catches a stale rate card.
    :ivar require_model_match: Whether two lines must name the same model to
        be considered the same call. Comparison is prefix-based, so
        ``claude-opus-5`` matches a dated variant of itself.
    """

    time_tolerance_seconds: float = 5.0
    token_tolerance_percent: float = 2.0
    cost_tolerance_percent: float = 1.0
    require_model_match: bool = True


@dataclass(frozen=True, slots=True)
class MatchedCall:
    """A provider line matched to a settled call.

    :ivar provider: The billed line.
    :ivar metered: The settled call it matched.
    :ivar cost_delta: Billed minus settled, in USD.
    :ivar time_delta_seconds: Absolute timestamp distance.
    :ivar token_delta_percent: Token drift, or ``None`` without a journal.
    :ivar exact: Whether cost and tokens agreed to the last unit.
    """

    provider: ProviderUsageRecord
    metered: MeteredRecord
    cost_delta: Decimal
    time_delta_seconds: float
    token_delta_percent: float | None
    exact: bool


@dataclass(frozen=True, slots=True)
class Discrepancy:
    """A matched pair whose costs disagree beyond tolerance.

    :ivar provider: The billed line.
    :ivar metered: The settled call.
    :ivar cost_delta: Billed minus settled, in USD. Positive means underbilled
        locally — the provider charged more than AgentGov recorded.
    :ivar cost_delta_percent: The same, relative to the settled cost.
    :ivar reason: A human-readable diagnosis.
    """

    provider: ProviderUsageRecord
    metered: MeteredRecord
    cost_delta: Decimal
    cost_delta_percent: float
    reason: str


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    """The outcome of matching an invoice against the ledger.

    :ivar policy: The tolerances used.
    :ivar matched: Lines billed and metered, in agreement.
    :ivar discrepant: Lines billed and metered, disagreeing on cost.
    :ivar phantom: Lines billed with no corresponding settlement. Any entry
        here fails the audit: something spent money outside the governor.
    :ivar unsettled: Settlements the provider never billed.
    :ivar token_matching: Whether a journal supplied token counts.
    """

    policy: ReconciliationPolicy
    matched: tuple[MatchedCall, ...] = ()
    discrepant: tuple[Discrepancy, ...] = ()
    phantom: tuple[ProviderUsageRecord, ...] = ()
    unsettled: tuple[MeteredRecord, ...] = ()
    token_matching: bool = False
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def invoiced_total(self) -> Decimal:
        """Everything the provider billed."""
        billed = [m.provider for m in self.matched]
        billed += [d.provider for d in self.discrepant]
        billed += list(self.phantom)
        return sum((record.total_cost for record in billed), Decimal(0))

    @property
    def metered_total(self) -> Decimal:
        """Everything AgentGov settled."""
        settled = [m.metered for m in self.matched]
        settled += [d.metered for d in self.discrepant]
        settled += list(self.unsettled)
        return sum((record.settled_cost for record in settled), Decimal(0))

    @property
    def phantom_total(self) -> Decimal:
        """Billed spend with no local authorization behind it."""
        return sum((record.total_cost for record in self.phantom), Decimal(0))

    @property
    def variance(self) -> Decimal:
        """Invoiced minus metered. Positive means the provider billed more."""
        return self.invoiced_total - self.metered_total

    @property
    def variance_percent(self) -> float:
        """Variance relative to metered spend."""
        if self.metered_total == 0:
            return 0.0 if self.invoiced_total == 0 else 100.0
        return float(self.variance / self.metered_total * 100)

    @property
    def passed(self) -> bool:
        """Whether the audit passes.

        Fails on any phantom line — billed spend with no local authorization
        is the finding this whole exercise exists to surface — or on any cost
        discrepancy outside tolerance. Unsettled lines alone do not fail: a
        call settled locally near the end of a billing window legitimately
        lands on the next invoice.
        """
        return not self.phantom and not self.discrepant

    @property
    def total_provider_records(self) -> int:
        """How many billed lines were considered."""
        return len(self.matched) + len(self.discrepant) + len(self.phantom)


def _models_agree(left: str, right: str, *, required: bool) -> bool:
    """Whether two model strings can denote the same model."""
    a, b = _normalise_model(left), _normalise_model(right)
    if not a or not b:
        # One side is unknown — a ledger without a journal has no model. Fall
        # back to time and cost rather than refusing to match at all.
        return True
    if a == b:
        return True
    if not required:
        return True
    # Dated snapshots: `claude-opus-5` vs `claude-opus-5-20260401`.
    return a.startswith(b) or b.startswith(a)


def _token_delta_percent(provider: ProviderUsageRecord, metered: MeteredRecord) -> float | None:
    """Relative token drift between a billed and a settled line."""
    metered_total = metered.total_tokens
    if metered_total is None:
        return None
    if metered_total == 0:
        return 0.0 if provider.total_tokens == 0 else 100.0
    return abs(provider.total_tokens - metered_total) / metered_total * 100


def _cost_delta_percent(provider: ProviderUsageRecord, metered: MeteredRecord) -> float:
    """Relative cost drift between a billed and a settled line."""
    if metered.settled_cost == 0:
        return 0.0 if provider.total_cost == 0 else 100.0
    return float(abs(provider.total_cost - metered.settled_cost) / metered.settled_cost * 100)


def reconcile(
    metered: Sequence[MeteredRecord],
    provider: Sequence[ProviderUsageRecord],
    policy: ReconciliationPolicy | None = None,
) -> ReconciliationReport:
    """Match a provider's billed lines against locally settled calls.

    Candidate pairs are those within the time window that could name the same
    model. Every candidate is scored on token drift (when known), cost drift,
    and time distance, then assigned greedily best-first and one-to-one — a
    deterministic approximation of optimal bipartite matching that is stable
    across runs and cheap enough for a month of traffic.

    :param metered: Settled calls, from :func:`metered_records`.
    :param provider: Billed lines, from a parser or :func:`load_provider_export`.
    :param policy: Matching tolerances; defaults to :class:`ReconciliationPolicy`.
    :returns: The categorised report.
    """
    rules = policy if policy is not None else ReconciliationPolicy()
    has_tokens = any(record.total_tokens is not None for record in metered)

    # Score every plausible pairing, then take them best-first.
    candidates: list[tuple[float, int, int]] = []
    for provider_index, billed in enumerate(provider):
        for metered_index, settled in enumerate(metered):
            gap = abs((billed.timestamp - settled.timestamp).total_seconds())
            if gap > rules.time_tolerance_seconds:
                continue
            if not _models_agree(billed.model, settled.model, required=rules.require_model_match):
                continue

            token_drift = _token_delta_percent(billed, settled)
            if token_drift is not None and token_drift > rules.token_tolerance_percent:
                # Same instant, same model, wildly different size: two calls,
                # not one. Leaving them unmatched is the honest outcome.
                continue

            cost_drift = _cost_delta_percent(billed, settled)
            score = (token_drift or 0.0) + cost_drift + gap
            candidates.append((score, provider_index, metered_index))

    candidates.sort(key=lambda item: (item[0], item[1], item[2]))

    claimed_provider: set[int] = set()
    claimed_metered: set[int] = set()
    matched: list[MatchedCall] = []
    discrepant: list[Discrepancy] = []

    for _score, provider_index, metered_index in candidates:
        if provider_index in claimed_provider or metered_index in claimed_metered:
            continue
        claimed_provider.add(provider_index)
        claimed_metered.add(metered_index)

        billed, settled = provider[provider_index], metered[metered_index]
        cost_delta = billed.total_cost - settled.settled_cost
        cost_drift = _cost_delta_percent(billed, settled)
        token_drift = _token_delta_percent(billed, settled)
        gap = abs((billed.timestamp - settled.timestamp).total_seconds())

        if cost_drift > rules.cost_tolerance_percent:
            discrepant.append(
                Discrepancy(
                    provider=billed,
                    metered=settled,
                    cost_delta=cost_delta,
                    cost_delta_percent=cost_drift,
                    reason=(
                        f"provider billed {billed.total_cost} against a settled "
                        f"{settled.settled_cost} ({cost_drift:.2f}% drift, tolerance "
                        f"{rules.cost_tolerance_percent:.2f}%)"
                        + (
                            "; the export carried no cost, so this compares a "
                            "rate-card estimate against the ledger"
                            if billed.cost_was_derived
                            else "; likely a stale rate card in agentgov.interceptor.PRICING"
                        )
                    ),
                )
            )
            continue

        matched.append(
            MatchedCall(
                provider=billed,
                metered=settled,
                cost_delta=cost_delta,
                time_delta_seconds=gap,
                token_delta_percent=token_drift,
                exact=cost_delta == 0 and (token_drift == 0.0 if token_drift is not None else True),
            )
        )

    notes: list[str] = []
    if not has_tokens:
        notes.append(
            "No metering journal supplied: matched on cost and time only. Token "
            "tolerance was not applied. Pass --journal for token-level matching."
        )
    if any(record.cost_was_derived for record in provider):
        notes.append(
            "Some billed lines carried no cost and were priced from the local rate "
            "card; those cannot independently confirm the provider's pricing."
        )

    return ReconciliationReport(
        policy=rules,
        matched=tuple(matched),
        discrepant=tuple(discrepant),
        phantom=tuple(
            record for index, record in enumerate(provider) if index not in claimed_provider
        ),
        unsettled=tuple(
            record for index, record in enumerate(metered) if index not in claimed_metered
        ),
        token_matching=has_tokens,
        notes=tuple(notes),
    )


def format_report(report: ReconciliationReport, *, path: str = "", export: str = "") -> str:
    """Render a report as a terminal summary.

    :param report: The report to render.
    :param path: Ledger path, for the header.
    :param export: Provider export path, for the header.
    :returns: The formatted text, without a trailing newline.
    """
    lines: list[str] = []

    def money(amount: Decimal) -> str:
        return f"${amount.quantize(_CENT, rounding=ROUND_HALF_EVEN):,}"

    lines.append("")
    lines.append("RECONCILIATION")
    if path or export:
        lines.append(f"  ledger    {path}")
        lines.append(f"  invoice   {export}")
    lines.append(
        f"  tolerance  time +/-{report.policy.time_tolerance_seconds}s   "
        f"tokens +/-{report.policy.token_tolerance_percent}%   "
        f"cost +/-{report.policy.cost_tolerance_percent}%"
    )
    basis = "token-level (journal supplied)" if report.token_matching else "cost and time only"
    lines.append(f"  matching   {basis}")

    lines.append("")
    lines.append(f"  {'CATEGORY':<34}{'COUNT':>8}{'SPEND':>18}")
    lines.append(f"  {'-' * 60}")
    matched_spend = sum((m.provider.total_cost for m in report.matched), Decimal(0))
    discrepant_spend = sum((d.provider.total_cost for d in report.discrepant), Decimal(0))
    unsettled_spend = sum((u.settled_cost for u in report.unsettled), Decimal(0))
    for label, count, amount in (
        ("Matched (billed and metered)", len(report.matched), matched_spend),
        ("Discrepant (cost mismatch)", len(report.discrepant), discrepant_spend),
        ("Phantom (billed, NOT metered)", len(report.phantom), report.phantom_total),
        ("Unsettled (metered, not billed)", len(report.unsettled), unsettled_spend),
    ):
        lines.append(f"  {label:<34}{count:>8}{money(amount):>18}")

    lines.append("")
    lines.append(f"  {'Invoiced total':<34}{'':>8}{money(report.invoiced_total):>18}")
    lines.append(f"  {'Metered total':<34}{'':>8}{money(report.metered_total):>18}")
    lines.append(f"  {'Variance':<34}{report.variance_percent:>7.2f}%{money(report.variance):>18}")

    if report.discrepant:
        lines.append("")
        lines.append("  COST DISCREPANCIES")
        for item in report.discrepant[:10]:
            lines.append(
                f"    seq {item.metered.sequence:<6} {item.metered.scope_id:<20} "
                f"{money(item.cost_delta):>14}  {item.reason}"
            )

    if report.phantom:
        lines.append("")
        lines.append("  PHANTOM CALLS - billed with no local authorization")
        for record in report.phantom[:10]:
            lines.append(
                f"    {record.timestamp:%Y-%m-%d %H:%M:%S}  {record.model:<24} "
                f"{money(record.total_cost):>14}  {record.record_id}"
            )
        if len(report.phantom) > 10:
            lines.append(f"    ... and {len(report.phantom) - 10} more")

    for note in report.notes:
        lines.append("")
        lines.append(f"  note: {note}")

    lines.append("")
    if report.passed:
        lines.append(
            f"  AUDIT PASSED  {len(report.matched)} of {report.total_provider_records} "
            f"billed lines reconciled; no unmetered spend"
        )
    else:
        reasons = []
        if report.phantom:
            reasons.append(
                f"{len(report.phantom)} phantom call(s) worth {money(report.phantom_total)}"
            )
        if report.discrepant:
            reasons.append(f"{len(report.discrepant)} cost discrepancy(ies)")
        lines.append(f"  AUDIT FAILED  {'; '.join(reasons)}")
    return "\n".join(lines)
