"""Cognitive circuit breaker: halting agents that thrash instead of progress.

Design brief
------------
The financial breaker in :mod:`agentgov.core` bounds the *blast radius* of a
runaway agent. It is, by construction, reactive: it fires when the money is
gone. This module attacks the root cause one layer up — the open-loop
execution cycle that burns the money in the first place. An agent calling the
same tool with the same arguments, or making cosmetic edits to a query while
making zero semantic progress, is *thrashing*, and it is detectable long
before the envelope is exhausted.

**Two tiers, one actuator.**

*Tier 1 — deterministic, inline, sub-100µs.* Three stateless detectors run on
the calling thread against a bounded per-trajectory ring buffer:
:class:`ExactRepeatDetector` (identical call fingerprints),
:class:`NearDuplicateDetector` (character-shingle Jaccard similarity between
consecutive calls — the "soft loop"), and :class:`CallCycleDetector` (an
A→B→A→B call-graph cycle that no pairwise check would catch). Every cost here
is bounded: arguments are truncated before shingling, comparisons are capped
at a small window, and a set-size ratio bound prunes most of them outright.

*Tier 2 — semantic, off-thread, eventually consistent.* A single daemon worker
drains a bounded queue and runs a :class:`SemanticObserver`. The shipped
default, :class:`TrajectoryEntropyObserver`, tracks novelty decay: what
fraction of each call is vocabulary the trajectory has never produced before.
A trajectory whose novelty collapses toward zero is recombining the same
ground. **The agent thread never waits for this.** A verdict reached
asynchronously is latched and enforced on the *next* inline observation, so
detection is one call late rather than blocking — the correct trade, and the
seam where an LLM-judge observer plugs in without changing anything else.

**Reusing the financial actuator.** A cognitive trip calls
:meth:`~agentgov.core.BudgetManager.trip`, so it inherits latching, subtree
propagation, hash-anchored control events, and durable persistence from the
machinery that already exists. One halt mechanism, two families of sensor.

**Locking.** This module owns a mutex *separate* from the ledger's, so
similarity math never contends with the financial hot path. The verdict is
computed under the cognitive lock, which is then **released before** the
financial breaker is tripped — the two locks are never held simultaneously, so
there is no lock-ordering hazard to reason about.

**Known limitation.** Legitimate iteration — pagination,
map-over-a-list, retry-with-backoff — looks like a soft loop on input
similarity alone. The discriminator is the *result*: near-identical inputs
producing near-identical outputs is thrashing; near-identical inputs producing
*different* outputs is progress. Pass results to :meth:`CognitiveBreaker.record_result`
(:class:`~agentgov.interceptor.Interceptor` does it automatically) and the
detectors use them. Without results, raise
:attr:`CognitivePolicy.similarity_threshold`, list the tool in
:attr:`CognitivePolicy.exempt_tools`, or supply a custom
:class:`LoopDetector`.
"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import secrets
import threading
import weakref
from collections import OrderedDict, deque
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import TracebackType
from typing import TYPE_CHECKING, Final, Protocol

from agentgov.exceptions import AgentThrashingError, UnknownScopeError

if TYPE_CHECKING:
    from agentgov.core import BudgetManager

__all__ = [
    "CallCycleDetector",
    "CognitiveBreaker",
    "CognitivePolicy",
    "ExactRepeatDetector",
    "LoopDetector",
    "NearDuplicateDetector",
    "Redactor",
    "SemanticObserver",
    "ToolCall",
    "TrajectoryEntropyObserver",
    "Verdict",
    "canonical_arguments",
    "extract_result_text",
    "jaccard",
    "shingles",
]

logger: Final = logging.getLogger("agentgov.cognitive")

_UNIT_SEPARATOR: Final = "\x1f"


# --------------------------------------------------------------------------
# Observation vocabulary
# --------------------------------------------------------------------------


def canonical_arguments(args: Sequence[object] = (), kwargs: Mapping[str, object] = {}) -> str:
    """Render a call's arguments as a stable, comparable string.

    Ordering is normalised (keyword arguments are sorted) so that two calls
    differing only in keyword order fingerprint identically. Values that are
    not JSON-serialisable fall back to :func:`repr`, which keeps the function
    total: an un-serialisable argument must never crash the governor.

    :param args: Positional arguments.
    :param kwargs: Keyword arguments.
    :returns: A deterministic string representation.
    """
    try:
        return json.dumps(
            [list(args), dict(sorted(kwargs.items()))],
            sort_keys=True,
            ensure_ascii=True,
            default=repr,
        )
    except (TypeError, ValueError):  # pragma: no cover - default=repr covers most
        return repr((tuple(args), tuple(sorted(kwargs.items()))))


_RESULT_TEXT_ATTRS: Final = ("content", "text", "thinking", "completion")
_MAX_RESULT_DEPTH: Final = 6


def extract_result_text(result: object) -> str | None:
    """Reduce a model response to the prose worth comparing, if recognisable.

    Comparing whole SDK response objects measures the wrong thing. Rendering
    an ``anthropic.types.Message`` through :func:`canonical_arguments` falls
    back to ``repr``, so the shingled string is mostly *envelope* —
    ``Message(id=…, content=[TextBlock(citations=None, type='text'…``,
    ``role='assistant'``, ``usage=Usage(…)`` — which every response from that
    SDK shares. Measured against live traffic, that boilerplate inflated two
    *completely unrelated* responses to 0.42 similarity while two genuinely
    progressing steps scored 0.48: no usable separation, and a threshold that
    would drift with the SDK's ``__repr__`` rather than with meaning.

    Extracting the text first restores the signal. On the same live corpus,
    thrashing/progress separation roughly doubled (1.20x to 1.81x) and
    unrelated responses fell to where they belong.

    Duck-typed on purpose — AgentGov imports no provider SDK. Understands the
    Anthropic Messages shape (``.content`` of blocks carrying ``.text`` or
    ``.thinking``), the LangChain shape (``.content`` as a plain string),
    mappings with those keys, and bare strings.

    :param result: A call's return value.
    :returns: The concatenated text, or ``None`` when the shape is unfamiliar
        or carries no prose — the caller then falls back to canonicalising
        the whole object, which is strictly better than comparing nothing.
    """
    found: list[str] = []
    _walk_result_text(result, found, _MAX_RESULT_DEPTH)
    joined = "".join(found).strip()
    return joined or None


def _walk_result_text(value: object, found: list[str], depth: int) -> None:
    """Accumulate prose from a nested response structure."""
    if depth <= 0:
        return
    if isinstance(value, str):
        found.append(value)
        return
    if isinstance(value, bytes | bytearray):
        return
    if isinstance(value, Mapping):
        for key in _RESULT_TEXT_ATTRS:
            if key in value:
                _walk_result_text(value[key], found, depth - 1)
        return
    if isinstance(value, Sequence):
        for item in value:
            _walk_result_text(item, found, depth - 1)
        return
    # An object: take the first text-bearing attribute it actually has, so a
    # content-block list is preferred over a sibling summary field.
    for name in _RESULT_TEXT_ATTRS:
        attr = getattr(value, name, None)
        if attr is not None:
            _walk_result_text(attr, found, depth - 1)
            return


def shingles(text: str, *, size: int = 3, max_chars: int = 1024) -> frozenset[str]:
    """Decompose ``text`` into a set of overlapping character n-grams.

    Character shingles rather than word tokens because agent arguments are
    often JSON, URLs, or code, where whitespace tokenisation is meaningless.
    ``max_chars`` bounds the cost: this is on the inline path, so an agent
    passing a megabyte of context must not turn a similarity check into a
    latency spike.

    Oversized text is sampled from **both ends** rather than truncated to the
    head. Agent prompts routinely carry a long stable prefix — a system
    prompt, a tool schema, retrieved context — with the part that actually
    varies at the very end. Head-only truncation would make every such call
    look identical and turn the near-duplicate detector into a constant.

    :param text: The text to shingle.
    :param size: n-gram width.
    :param max_chars: Sample budget. Text longer than this contributes its
        first and last ``max_chars // 2`` characters.
    :returns: The set of n-grams.
    """
    if len(text) > max_chars:
        half = max_chars // 2
        # The separator keeps the junction deterministic: without it the
        # splice would mint n-grams that appear in neither end of the text.
        text = text[:half] + _UNIT_SEPARATOR + text[-half:]
    if len(text) <= size:
        return frozenset({text})
    return frozenset(text[i : i + size] for i in range(len(text) - size + 1))


class Redactor(Protocol):
    """Removes sensitive material before AgentGov ever sees it.

    Applied at canonicalisation — the single ingress through which every
    observed argument and result passes — so redacted text is what gets
    fingerprinted, shingled, and (only if explicitly retained) stored. Raw
    prompt content never reaches the breaker's memory or the audit log.

    Implementations must be pure and fast: this runs inline, on the agent's
    own thread, before the tool call is allowed to proceed.
    """

    def redact(self, tool: str, text: str) -> str:
        """Return ``text`` with sensitive material removed or masked.

        :param tool: The tool being called, so a redactor can apply
            per-tool rules.
        :param text: Canonicalised arguments, or a canonicalised result.
        :returns: The text safe to fingerprint and retain.
        """
        ...


def jaccard(left: frozenset[str], right: frozenset[str], *, floor: float = 0.0) -> float:
    """Jaccard similarity of two shingle sets, in ``[0, 1]``.

    ``floor`` enables a cheap early exit: because Jaccard can never exceed
    ``min(|a|, |b|) / max(|a|, |b|)``, a size ratio below the floor rules out
    a match without computing the intersection at all. That prunes most
    comparisons on the inline path.

    :param left: First shingle set.
    :param right: Second shingle set.
    :param floor: Similarity below which the caller does not care.
    :returns: The similarity, or ``0.0`` when the size bound rules it out.
    """
    if not left or not right:
        return 1.0 if left == right else 0.0
    if floor > 0.0:
        smaller, larger = sorted((len(left), len(right)))
        if smaller / larger < floor:
            return 0.0
    union = len(left | right)
    return len(left & right) / union if union else 0.0


@dataclass(slots=True)
class ToolCall:
    """One observed tool invocation.

    Deliberately *not* frozen: :attr:`result_shingles` is attached after the
    call returns, via :meth:`CognitiveBreaker.record_result`. This is
    telemetry, not a financial record — the immutability guarantees that
    matter live in the ledger.

    :ivar sequence: Position within the trajectory, starting at 1.
    :ivar scope_id: The budget scope that made the call.
    :ivar tool: The tool or function name.
    :ivar arguments: Canonicalised arguments, redacted and truncated to
        :attr:`CognitivePolicy.max_argument_chars` — and empty unless
        :attr:`CognitivePolicy.retain_arguments` was explicitly enabled.
        Never the raw prompt, and never unbounded.
    :ivar fingerprint: Salted digest over the *full* redacted text, so
        exact-repeat identity survives truncation while the digest itself
        reveals nothing and cannot be matched against a precomputed table.
    :ivar shingles: Shingle set over tool *and* arguments, so calls to
        different tools are never mistaken for near-duplicates.
    :ivar timestamp: UTC instant the call was observed.
    :ivar result_shingles: Shingles over the call's result, once known.
    """

    sequence: int
    scope_id: str
    tool: str
    arguments: str
    fingerprint: str
    shingles: frozenset[str]
    timestamp: datetime
    result_shingles: frozenset[str] | None = None


@dataclass(frozen=True, slots=True)
class Verdict:
    """A detector's judgment that a trajectory is thrashing.

    :ivar detector: Name of the detector that fired.
    :ivar reason: Human-readable explanation, surfaced in the exception and
        the control-event audit trail.
    :ivar confidence: ``0..1``. Deterministic detectors report high
        confidence; semantic ones report what their heuristic supports.
    :ivar observations: How many calls the trajectory had made when it fired.
    :ivar tier: ``"deterministic"`` (inline) or ``"semantic"`` (off-thread).
    :ivar evidence: Detector-specific detail for debugging and audit.
    """

    detector: str
    reason: str
    confidence: float
    observations: int
    tier: str = "deterministic"
    evidence: Mapping[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CognitivePolicy:
    """Tunable limits for the cognitive breaker.

    :ivar max_identical_repeats: Identical consecutive calls tolerated before
        tripping. ``3`` means the third byte-identical call trips.
    :ivar similarity_threshold: Jaccard similarity at or above which two
        consecutive calls count as "no progress".

        Character-trigram Jaccard is not on the same scale as "percent
        overlap": two queries a reader would call 90% identical measure
        0.74-0.83, because a one-word edit disturbs several trigrams. On this
        project's corpus, cosmetically edited queries score 0.74-0.83 and
        queries that advance a task, even within one topic, score below 0.14.
        The ``0.70`` default sits in that gap.

        Measured against ``DummyLLM``, unlike
        :attr:`result_similarity_threshold`, which was recalibrated against
        live traffic. Input similarity is the more stable of the two because
        tool arguments are short and structured, but this number has not had
        the same treatment.

    :ivar max_similar_streak: Consecutive near-duplicate *pairs* tolerated.
        ``3`` trips on the fourth call of a soft loop.
    :ivar result_similarity_threshold: When results are known for both calls,
        they must *also* be this similar for a near-duplicate to count. This
        is what separates thrashing from legitimate iteration: pagination has
        similar inputs but dissimilar outputs.

        Calibrated against live traffic, not the offline stub — see
        ``scripts/calibrate_result_threshold.py``, which is the reproducible
        justification for this number. Model *prose* behaves nothing like
        ``DummyLLM``'s templated completions: two answers meaning the same
        thing share far fewer trigrams than two renderings of one template.
        Over 36 measured pairs the per-pair distributions genuinely overlap
        (thrashing 0.32-0.66, pagination 0.13-0.88), so no single-pair value
        separates them. What separates them is
        :attr:`max_similar_streak`: pagination's similarity is erratic — one
        framing-heavy pair, then divergence — while thrashing stays
        persistently elevated, so consecutive agreement is the real signal.
        Sweeping the actual rule, ``0.25``-``0.30`` catches 4/4 thrashing
        trajectories with zero false positives on pagination or on genuinely
        progressing work; ``0.20`` starts false-positiving on pagination.
        ``0.30`` is the top of that band, the conservative end for a rule that
        halts an agent. The previous ``0.70`` — inherited from stub-based
        tuning — detected **0/4** against live prose.
    :ivar comparison_window: How many recent calls the near-duplicate detector
        may compare against. Bounds inline cost.
    :ivar max_cycle_period: Longest call-graph cycle to look for (an
        A→B→C→A→B→C loop has period 3).
    :ivar min_cycle_repeats: How many times a cycle must repeat to trip.
    :ivar history_limit: Calls retained per trajectory.
    :ivar max_trajectories: Trajectories tracked before the least recently
        used is evicted. Bounds memory in a long-lived process.
    :ivar shingle_size: Character n-gram width.
    :ivar max_argument_chars: Arguments are truncated to this before shingling.
    :ivar exempt_tools: Tools never judged — the escape hatch for legitimately
        repetitive calls (polling a status endpoint, paginating a cursor).
    :ivar retain_arguments: Whether to keep readable (redacted, truncated)
        argument text on each :class:`ToolCall`. **Off by default**: a
        governor should not become an unlogged copy of every prompt an agent
        sends. Enable it for local debugging, or when a redactor guarantees
        the text is safe. Detection is unaffected either way — the detectors
        read fingerprints and shingles, never this field.
    :ivar entropy_window: Calls the semantic observer averages novelty over.
    :ivar min_novelty_ratio: Mean novel-shingle fraction below which the
        semantic observer calls a trajectory stagnant.
    :ivar async_queue_size: Bounded queue depth for the semantic lane.
        Samples are *dropped* when full — backpressure must never reach the
        agent's thread.
    """

    max_identical_repeats: int = 3
    similarity_threshold: float = 0.70
    max_similar_streak: int = 3
    result_similarity_threshold: float = 0.30
    comparison_window: int = 6
    max_cycle_period: int = 4
    min_cycle_repeats: int = 3
    history_limit: int = 64
    max_trajectories: int = 256
    shingle_size: int = 3
    max_argument_chars: int = 1024
    exempt_tools: frozenset[str] = frozenset()
    retain_arguments: bool = False
    entropy_window: int = 12
    min_novelty_ratio: float = 0.02
    async_queue_size: int = 256


# --------------------------------------------------------------------------
# Tier 1 - deterministic detectors (inline)
# --------------------------------------------------------------------------


class LoopDetector(Protocol):
    """A pluggable, stateless thrashing heuristic.

    Implement this to add a domain-specific check — a detector that knows
    your tool schema can be far sharper than a generic text heuristic.
    Detectors are called on the agent's own thread, under the breaker's lock,
    so an implementation must be fast and must not block on I/O. Anything
    expensive belongs in a :class:`SemanticObserver` instead.

    Detectors are stateless by contract: everything needed is derived from
    ``call`` and ``history``. That keeps them safe to share across
    trajectories and threads.
    """

    @property
    def name(self) -> str:
        """Short identifier, recorded on the verdict and in the audit trail."""
        ...

    def observe(self, call: ToolCall, history: Sequence[ToolCall]) -> Verdict | None:
        """Judge ``call`` against ``history`` (oldest first, excluding ``call``).

        :returns: A :class:`Verdict` to halt the trajectory, or ``None``.
        """
        ...


@dataclass(frozen=True, slots=True)
class ExactRepeatDetector:
    """Trips when a call is repeated byte-identically N times in a row.

    The crudest and most certain signal: an agent re-issuing a fingerprint it
    has just issued cannot be making progress, because the tool is
    deterministic with respect to its arguments or it is not a tool.
    """

    max_repeats: int = 3

    @property
    def name(self) -> str:
        return "exact_repeat"

    def observe(self, call: ToolCall, history: Sequence[ToolCall]) -> Verdict | None:
        if self.max_repeats < 1:
            return None
        run = 1
        for previous in reversed(history):
            if previous.fingerprint != call.fingerprint:
                break
            run += 1
            if run >= self.max_repeats:
                break
        if run < self.max_repeats:
            return None
        return Verdict(
            detector=self.name,
            reason=(
                f"{run} byte-identical calls to {call.tool!r} in a row "
                f"(fingerprint {call.fingerprint[:12]})"
            ),
            confidence=1.0,
            observations=len(history) + 1,
            evidence={"repeats": str(run), "fingerprint": call.fingerprint},
        )


@dataclass(frozen=True, slots=True)
class NearDuplicateDetector:
    """Trips on a run of consecutive calls that barely differ — the soft loop.

    Catches what exact matching misses: an agent nudging a search query,
    incrementing a guess, or reformatting a prompt while making no semantic
    progress. Similarity is Jaccard over character shingles of
    tool-plus-arguments.

    When results are known for both calls in a pair, they must also be similar
    for the pair to count as stagnant. That is the discriminator between
    thrashing and legitimate iteration: paginating a cursor produces
    near-identical inputs and different outputs, and is left alone.
    """

    threshold: float = 0.70
    max_streak: int = 3
    result_threshold: float = 0.30
    """Matches :attr:`CognitivePolicy.result_similarity_threshold`. Calibrated
    against live traffic by ``scripts/calibrate_result_threshold.py``; the
    ``0.70`` this used to default to detected 0/4 thrashing trajectories
    against real prose. Keep the two in step: constructing this detector
    directly is a documented extension point, so a stale default here is a
    detector that silently does not fire."""

    @property
    def name(self) -> str:
        return "near_duplicate"

    def observe(self, call: ToolCall, history: Sequence[ToolCall]) -> Verdict | None:
        if self.max_streak < 1 or not history:
            return None

        sequence = [*history, call]
        streak = 0
        weakest = 1.0
        for index in range(len(sequence) - 1, 0, -1):
            similarity = jaccard(
                sequence[index].shingles, sequence[index - 1].shingles, floor=self.threshold
            )
            if similarity < self.threshold:
                break
            if not self._results_agree(sequence[index], sequence[index - 1]):
                break
            streak += 1
            weakest = min(weakest, similarity)
            if streak >= self.max_streak:
                break

        if streak < self.max_streak:
            return None
        return Verdict(
            detector=self.name,
            reason=(
                f"{streak + 1} consecutive near-identical calls to {call.tool!r} "
                f"(pairwise similarity >= {weakest:.2f}, threshold {self.threshold:.2f}) "
                f"with no semantic progress"
            ),
            confidence=min(1.0, weakest),
            observations=len(history) + 1,
            evidence={
                "streak": str(streak),
                "min_similarity": f"{weakest:.4f}",
                "threshold": f"{self.threshold:.2f}",
            },
        )

    def _results_agree(self, newer: ToolCall, older: ToolCall) -> bool:
        """Whether two calls' results are similar enough to call it stagnation.

        Unknown results are treated as agreement: absent evidence of progress,
        the input similarity stands on its own.
        """
        if newer.result_shingles is None or older.result_shingles is None:
            return True
        return (
            jaccard(newer.result_shingles, older.result_shingles, floor=self.result_threshold)
            >= self.result_threshold
        )


@dataclass(frozen=True, slots=True)
class CallCycleDetector:
    """Trips on a repeating cycle in the call graph — A→B→A→B→A→B.

    Pairwise similarity cannot see this: consecutive calls are genuinely
    different, so nothing looks wrong locally. Only the periodicity of the
    fingerprint sequence gives it away. This is the classic two-tool
    oscillation, where an agent alternates between reading a file and
    searching for the thing it just read.
    """

    max_period: int = 4
    min_repeats: int = 3

    @property
    def name(self) -> str:
        return "call_cycle"

    def observe(self, call: ToolCall, history: Sequence[ToolCall]) -> Verdict | None:
        if self.max_period < 2 or self.min_repeats < 2:
            return None
        fingerprints = [c.fingerprint for c in history]
        fingerprints.append(call.fingerprint)

        # Period 1 is an exact repeat, already ExactRepeatDetector's job.
        for period in range(2, self.max_period + 1):
            span = period * self.min_repeats
            if len(fingerprints) < span:
                continue
            tail = fingerprints[-span:]
            if all(tail[i] == tail[i % period] for i in range(span)):
                distinct = len(set(tail))
                if distinct < 2:  # degenerate: all identical, not a cycle
                    continue
                return Verdict(
                    detector=self.name,
                    reason=(
                        f"call-graph cycle of period {period} repeated "
                        f"{self.min_repeats} times ({distinct} distinct calls "
                        f"looping with no progress)"
                    ),
                    confidence=0.95,
                    observations=len(history) + 1,
                    evidence={"period": str(period), "repeats": str(self.min_repeats)},
                )
        return None


# --------------------------------------------------------------------------
# Tier 2 - semantic observer (off-thread)
# --------------------------------------------------------------------------


class SemanticObserver(Protocol):
    """A heavier judgment that runs off the agent's thread.

    Implementations may do anything expensive — embedding similarity, an
    LLM-judge call, a trajectory-summarisation pass — because they never run
    inline. The breaker feeds a snapshot of the recent window to a background
    worker and picks up any verdict on the *next* observation.

    An implementation must be safe to call from that single worker thread and
    must not raise; the breaker logs and swallows exceptions so a faulty
    observer degrades detection rather than breaking the agent.
    """

    @property
    def name(self) -> str:
        """Short identifier, recorded on the verdict."""
        ...

    def evaluate(self, trajectory: str, window: Sequence[ToolCall]) -> Verdict | None:
        """Judge a trajectory's recent window. ``None`` means "keep going"."""
        ...

    def reset(self, trajectory: str) -> None:
        """Discard accumulated state for one trajectory."""
        ...


@dataclass(slots=True)
class _EntropyState:
    """Per-trajectory novelty bookkeeping for the entropy observer."""

    seen: set[str] = field(default_factory=set)
    ratios: deque[float] = field(default_factory=lambda: deque[float](maxlen=12))


class TrajectoryEntropyObserver:
    """Semantic stagnation via novelty decay — the shipped Tier 2 default.

    Tracks the vocabulary a trajectory has ever produced and measures what
    fraction of each new call is genuinely new ground. A productive agent
    keeps introducing unseen material as it explores; a thrashing one
    recombines what it has already said, and its novelty ratio collapses
    toward zero.

    This catches stagnation that no pairwise comparison sees — an agent
    cycling through six different-looking phrasings of one idea has low
    pairwise similarity but near-zero trajectory novelty.

    Runs on the breaker's worker thread. State is guarded because
    :meth:`reset` may be called from the agent's thread.

    :param window: Calls to average novelty over before judging.
    :param min_novelty_ratio: Mean novelty below which the trajectory is
        called stagnant.
    :param include_results: Fold result shingles into the novelty measure
        when they are available, which sharply distinguishes real iteration
        (new outputs) from thrashing (same outputs).
    :param max_trajectories: Independent LRU bound on retained state. The
        breaker also evicts this observer's state when it evicts a
        trajectory of its own; this bound is the backstop for trajectories
        the observer sees that the breaker has already forgotten, so a
        long-lived process cannot accumulate novelty sets without limit.
    """

    __slots__ = (
        "_include_results",
        "_lock",
        "_max_trajectories",
        "_min_ratio",
        "_states",
        "_window",
    )

    def __init__(
        self,
        *,
        window: int = 12,
        min_novelty_ratio: float = 0.02,
        include_results: bool = True,
        max_trajectories: int = 256,
    ) -> None:
        self._window = max(2, window)
        self._min_ratio = min_novelty_ratio
        self._include_results = include_results
        self._max_trajectories = max(1, max_trajectories)
        self._states: OrderedDict[str, _EntropyState] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def tracked(self) -> int:
        """How many trajectories currently hold novelty state."""
        with self._lock:
            return len(self._states)

    @property
    def name(self) -> str:
        return "trajectory_entropy"

    def evaluate(self, trajectory: str, window: Sequence[ToolCall]) -> Verdict | None:
        if not window:
            return None
        newest = window[-1]
        material = newest.shingles
        if self._include_results and newest.result_shingles is not None:
            material = material | newest.result_shingles

        with self._lock:
            state = self._states.get(trajectory)
            if state is None:
                state = _EntropyState(ratios=deque(maxlen=self._window))
                self._states[trajectory] = state
                while len(self._states) > self._max_trajectories:
                    self._states.popitem(last=False)
            else:
                self._states.move_to_end(trajectory)

            novel = len(material - state.seen)
            total = len(material) or 1
            state.seen |= material
            state.ratios.append(novel / total)

            if len(state.ratios) < self._window:
                return None
            mean_novelty = sum(state.ratios) / len(state.ratios)

        if mean_novelty >= self._min_ratio:
            return None
        return Verdict(
            detector=self.name,
            reason=(
                f"semantic stagnation: only {mean_novelty:.1%} of the last "
                f"{self._window} calls was material this trajectory had not "
                f"already produced (floor {self._min_ratio:.1%})"
            ),
            confidence=0.75,
            observations=len(window),
            tier="semantic",
            evidence={
                "mean_novelty": f"{mean_novelty:.4f}",
                "window": str(self._window),
                "floor": f"{self._min_ratio:.4f}",
            },
        )

    def reset(self, trajectory: str) -> None:
        with self._lock:
            self._states.pop(trajectory, None)


# --------------------------------------------------------------------------
# The breaker
# --------------------------------------------------------------------------


@dataclass(slots=True)
class _Trajectory:
    """Everything the breaker tracks for one logical unit of agent work."""

    calls: deque[ToolCall]
    observed: int = 0
    verdict: Verdict | None = None
    pending: Verdict | None = None


@dataclass(frozen=True, slots=True)
class CognitiveStats:
    """Counters for observability.

    :ivar observed: Calls fed to the breaker.
    :ivar tripped: Trajectories currently latched.
    :ivar queued: Snapshots handed to the semantic lane.
    :ivar dropped: Snapshots discarded because the lane was saturated. A
        nonzero value means semantic coverage is partial — never that an
        agent was slowed down.
    :ivar evaluated: Snapshots the semantic lane actually judged.
    """

    observed: int = 0
    tripped: int = 0
    queued: int = 0
    dropped: int = 0
    evaluated: int = 0


class _DefaultObserver:
    """Sentinel type meaning "construct the default semantic observer".

    A plain ``None`` default could not distinguish "give me the default" from
    "disable Tier 2 entirely", and both need to be expressible.
    """


_DEFAULT_OBSERVER: Final = _DefaultObserver()

_QueueItem = tuple[str, tuple["ToolCall", ...]]
if TYPE_CHECKING:
    _LaneFinalizer = weakref.finalize[[queue.Queue[_QueueItem | None]], "CognitiveBreaker"]
"""A trajectory id and the window handed to the semantic lane.

``None`` on the queue is the shutdown sentinel, which keeps the queue
precisely typed instead of needing a cast on every drain."""


class CognitiveBreaker:
    """Detects thrashing agents and halts them before the money is gone.

    Feed it every tool call an agent makes. Inline detectors judge it in
    microseconds; a background worker adds semantic judgment without ever
    blocking the caller. When a trajectory is found to be looping,
    :class:`~agentgov.exceptions.AgentThrashingError` is raised and — if a
    :class:`~agentgov.core.BudgetManager` was supplied — the financial
    breaker is latched too, so the halt lands in the same audit trail as
    every other governance event.

    Used directly::

        breaker = CognitiveBreaker(manager=gov)
        breaker.observe("researcher", "search", canonical_arguments((query,)))

    or wired into an :class:`~agentgov.interceptor.Interceptor`, which
    observes every call and records every result automatically.

    **Trajectories.** History is keyed by *trajectory*, which defaults to the
    budget scope but can be shared across scopes. That matters: an
    orchestrator that responds to a halt by spawning a fresh sub-agent to
    retry the same degenerate task is one trajectory, not two, and passing a
    shared trajectory id makes the breaker see it that way.

    :param policy: Thresholds and bounds; defaults to :class:`CognitivePolicy`.
    :param detectors: Inline detectors. Defaults to the three built-ins
        configured from ``policy``. Pass your own to extend or replace them.
    :param observer: The off-thread semantic judge. Defaults to
        :class:`TrajectoryEntropyObserver`; pass ``None`` to disable Tier 2
        entirely (no worker thread is started).
    :param manager: When given, a cognitive trip also latches this governor's
        financial breaker for the offending scope and its subtree.
    """

    __slots__ = (
        # Weak references are what let an un-closed breaker's worker thread
        # be reaped instead of leaking; a slotted class needs this explicitly.
        "__weakref__",
        "_closed",
        "_detectors",
        "_finalizer",
        "_lock",
        "_manager",
        "_observer",
        "_policy",
        "_queue",
        "_redactor",
        "_salt",
        "_stats_dropped",
        "_stats_evaluated",
        "_stats_observed",
        "_stats_queued",
        "_trajectories",
        "_worker",
    )

    def __init__(
        self,
        *,
        policy: CognitivePolicy | None = None,
        detectors: Sequence[LoopDetector] | None = None,
        observer: SemanticObserver | _DefaultObserver | None = _DEFAULT_OBSERVER,
        manager: BudgetManager | None = None,
        redactor: Redactor | None = None,
        salt: bytes | None = None,
    ) -> None:
        self._policy = policy if policy is not None else CognitivePolicy()
        self._detectors: tuple[LoopDetector, ...] = (
            tuple(detectors) if detectors is not None else self._default_detectors(self._policy)
        )
        resolved: SemanticObserver | None
        if isinstance(observer, _DefaultObserver):
            resolved = TrajectoryEntropyObserver(
                window=self._policy.entropy_window,
                min_novelty_ratio=self._policy.min_novelty_ratio,
                max_trajectories=self._policy.max_trajectories,
            )
        else:
            resolved = observer
        self._observer: SemanticObserver | None = resolved
        self._manager = manager
        self._redactor = redactor
        # Per-instance random salt: fingerprints stay comparable for the life
        # of this breaker, which is all detection needs, while the digests
        # themselves cannot be matched against a table of known prompts.
        self._salt = salt if salt is not None else secrets.token_bytes(16)

        self._lock = threading.RLock()
        self._trajectories: OrderedDict[str, _Trajectory] = OrderedDict()
        self._closed = False
        self._stats_observed = 0
        self._stats_queued = 0
        self._stats_dropped = 0
        self._stats_evaluated = 0

        # The worker starts on first use and is reaped by a finalizer, so a
        # breaker that is constructed and dropped — the shape of an accidental
        # per-request instantiation — never leaves a thread behind.
        self._queue: queue.Queue[_QueueItem | None] | None = (
            queue.Queue(maxsize=self._policy.async_queue_size) if resolved is not None else None
        )
        self._worker: threading.Thread | None = None
        self._finalizer: _LaneFinalizer | None = None

    @staticmethod
    def _default_detectors(policy: CognitivePolicy) -> tuple[LoopDetector, ...]:
        return (
            ExactRepeatDetector(max_repeats=policy.max_identical_repeats),
            NearDuplicateDetector(
                threshold=policy.similarity_threshold,
                max_streak=policy.max_similar_streak,
                result_threshold=policy.result_similarity_threshold,
            ),
            CallCycleDetector(
                max_period=policy.max_cycle_period, min_repeats=policy.min_cycle_repeats
            ),
        )

    # -- accessors --------------------------------------------------------

    @property
    def policy(self) -> CognitivePolicy:
        """The thresholds in force."""
        return self._policy

    @property
    def detectors(self) -> tuple[LoopDetector, ...]:
        """The inline detectors, in evaluation order."""
        return self._detectors

    @property
    def semantic_enabled(self) -> bool:
        """Whether the off-thread semantic lane is running."""
        return self._observer is not None

    @property
    def stats(self) -> CognitiveStats:
        """A snapshot of the breaker's counters."""
        with self._lock:
            return CognitiveStats(
                observed=self._stats_observed,
                tripped=sum(1 for t in self._trajectories.values() if t.verdict is not None),
                queued=self._stats_queued,
                dropped=self._stats_dropped,
                evaluated=self._stats_evaluated,
            )

    def verdict(self, trajectory: str) -> Verdict | None:
        """The latched verdict for ``trajectory``, if it has been tripped."""
        with self._lock:
            state = self._trajectories.get(trajectory)
            return state.verdict if state is not None else None

    def is_tripped(self, trajectory: str) -> bool:
        """Whether ``trajectory`` is latched as thrashing."""
        return self.verdict(trajectory) is not None

    def history(self, trajectory: str) -> tuple[ToolCall, ...]:
        """The retained call history for ``trajectory``, oldest first."""
        with self._lock:
            state = self._trajectories.get(trajectory)
            return tuple(state.calls) if state is not None else ()

    # -- the enforcement point --------------------------------------------

    def observe(
        self,
        scope_id: str,
        tool: str,
        arguments: str,
        *,
        trajectory: str | None = None,
    ) -> None:
        """Record a tool call and halt the agent if it is thrashing.

        Call this *before* the tool runs, so a tripping call costs nothing.
        The inline detectors run on this thread; the semantic lane is fed
        without waiting for it.

        :param scope_id: The budget scope making the call.
        :param tool: Tool or function name.
        :param arguments: Canonicalised arguments — see
            :func:`canonical_arguments`.
        :param trajectory: Logical unit of work this call belongs to.
            Defaults to ``scope_id``.
        :raises ~agentgov.exceptions.AgentThrashingError: If this trajectory
            is thrashing, or was already latched as thrashing.
        """
        key = trajectory if trajectory is not None else scope_id
        if tool in self._policy.exempt_tools:
            return

        # Redaction, hashing and shingling are pure; keep them outside the
        # lock so concurrent sub-agents contend only for the bookkeeping.
        arguments = self._redact(tool, arguments)
        text = f"{tool}{_UNIT_SEPARATOR}{arguments}"
        call = ToolCall(
            sequence=0,
            scope_id=scope_id,
            tool=tool,
            # Bounded, and empty unless retention was explicitly enabled: the
            # fingerprint below already covers the *full* text, so dropping
            # this costs nothing in detection and everything in exposure.
            arguments=(
                arguments[: self._policy.max_argument_chars]
                if self._policy.retain_arguments
                else ""
            ),
            fingerprint=self._digest(text),
            shingles=shingles(
                text,
                size=self._policy.shingle_size,
                max_chars=self._policy.max_argument_chars,
            ),
            timestamp=datetime.now(UTC),
        )

        snapshot: tuple[ToolCall, ...] | None = None
        evicted: list[str] = []
        with self._lock:
            self._stats_observed += 1
            state = self._touch(key, evicted)
            verdict: Verdict | None

            # A latched trajectory stays latched: the loop that caused it has
            # not stopped just because the caller tried again.
            if state.verdict is not None:
                verdict = state.verdict
            else:
                # A verdict the semantic lane reached since the last call is
                # enforced here, on the next inline observation.
                verdict = state.pending
                state.pending = None

                history = tuple(state.calls)
                state.observed += 1
                call.sequence = state.observed
                state.calls.append(call)

                if verdict is None:
                    verdict = self._judge(call, history)

                if verdict is not None:
                    state.verdict = verdict
                elif self._queue is not None:
                    snapshot = tuple(state.calls)

        # Outside the lock, for the same reason the halt below is: the
        # observer takes its own mutex, and the worker thread acquires them
        # in the opposite order. Never hold both.
        if evicted and self._observer is not None:
            for stale in evicted:
                self._observer.reset(stale)

        if snapshot is not None:
            self._enqueue(key, snapshot)

        if verdict is not None:
            # Deliberately outside the lock: tripping the financial breaker
            # takes the ledger's mutex, and holding both at once would create
            # a lock-ordering hazard that this ordering makes impossible.
            self._halt(scope_id, key, verdict)

    def observe_call(
        self,
        scope_id: str,
        tool: str,
        args: Sequence[object] = (),
        kwargs: Mapping[str, object] | None = None,
        *,
        trajectory: str | None = None,
    ) -> None:
        """Convenience wrapper: canonicalise arguments, then :meth:`observe`.

        :param scope_id: The budget scope making the call.
        :param tool: Tool or function name.
        :param args: Positional arguments.
        :param kwargs: Keyword arguments.
        :param trajectory: Logical unit of work; defaults to ``scope_id``.
        """
        self.observe(
            scope_id,
            tool,
            canonical_arguments(args, kwargs if kwargs is not None else {}),
            trajectory=trajectory,
        )

    def check(self, scope_id: str, *, trajectory: str | None = None) -> None:
        """Refuse a call on a latched trajectory, without recording one.

        For a call whose arguments cannot be observed. Feeding it to
        :meth:`observe` with a placeholder would fingerprint every such call
        identically and read as a loop; skipping the breaker would let a
        halted trajectory keep calling. This does neither: a trajectory that
        is already latched — or that the semantic lane has since judged —
        is halted, and nothing is added to its history.

        :param scope_id: The budget scope making the call.
        :param trajectory: Logical unit of work; defaults to ``scope_id``.
        :raises ~agentgov.exceptions.AgentThrashingError: If the trajectory
            is latched as thrashing.
        """
        key = trajectory if trajectory is not None else scope_id
        with self._lock:
            state = self._trajectories.get(key)
            if state is None:
                return
            verdict = state.verdict
            if verdict is None and state.pending is not None:
                verdict = state.verdict = state.pending
                state.pending = None
        if verdict is not None:
            self._halt(scope_id, key, verdict)

    def record_result(
        self,
        scope_id: str,
        result: object,
        *,
        trajectory: str | None = None,
    ) -> None:
        """Attach a call's result to the most recent observation.

        Optional but valuable: with results attached, the near-duplicate
        detector can tell thrashing (same input, same output) from
        legitimate iteration (same input, *different* output), which is the
        single largest source of false positives without them.

        :param scope_id: The budget scope that made the call.
        :param result: The call's return value. Rendered with
            :func:`canonical_arguments` and shingled; never retained whole.
        :param trajectory: Logical unit of work; defaults to ``scope_id``.
        """
        key = trajectory if trajectory is not None else scope_id
        with self._lock:
            state_calls = self._trajectories.get(key)
            tool = state_calls.calls[-1].tool if state_calls and state_calls.calls else ""
        payload = extract_result_text(result)
        rendered = self._redact(
            tool, payload if payload is not None else canonical_arguments((result,))
        )
        digest = shingles(
            rendered, size=self._policy.shingle_size, max_chars=self._policy.max_argument_chars
        )
        with self._lock:
            state = self._trajectories.get(key)
            if state is not None and state.calls:
                state.calls[-1].result_shingles = digest

    def reset(self, trajectory: str) -> None:
        """Clear a trajectory's history and unlatch it.

        The cognitive latch, like the financial one, is deliberately manual:
        an agent found to be looping should not be handed back the keys by a
        timer that knows nothing about whether the cause was fixed.

        :param trajectory: The trajectory to clear.
        """
        with self._lock:
            self._trajectories.pop(trajectory, None)
        if self._observer is not None:
            self._observer.reset(trajectory)

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        """Stop the semantic worker. Idempotent; safe to call from any thread."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
        if self._finalizer is not None:
            self._finalizer.detach()
            self._finalizer = None
        if self._queue is not None:
            _stop_lane(self._queue)
        if self._worker is not None:
            self._worker.join(timeout=2.0)
            self._worker = None

    def __enter__(self) -> CognitiveBreaker:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    # -- internals --------------------------------------------------------

    def _touch(self, key: str, evicted: list[str]) -> _Trajectory:
        """Fetch or create a trajectory, evicting the least recent. Lock held.

        Evicted keys are reported rather than cleaned up here: the observer's
        state has to be dropped alongside them, and that call must happen
        outside this lock to keep the two mutexes from ever being nested.
        """
        state = self._trajectories.get(key)
        if state is None:
            state = _Trajectory(calls=deque(maxlen=self._policy.history_limit))
            self._trajectories[key] = state
            while len(self._trajectories) > self._policy.max_trajectories:
                stale, _ = self._trajectories.popitem(last=False)
                evicted.append(stale)
        else:
            self._trajectories.move_to_end(key)
        return state

    def _redact(self, tool: str, text: str) -> str:
        """Apply the configured redactor. A failure must not break the call."""
        if self._redactor is None:
            return text
        try:
            return self._redactor.redact(tool, text)
        except Exception:
            # Fail closed on *content*: if the redactor cannot vouch for this
            # text, none of it is retained or shingled. Detection degrades;
            # unredacted material never leaks as a consequence of a bug here.
            logger.exception("redactor %r raised; dropping this call's text", self._redactor)
            return ""

    def _digest(self, text: str) -> str:
        """Salted digest of the full text — the exact-repeat identity."""
        return hashlib.blake2b(text.encode("utf-8"), key=self._salt, digest_size=16).hexdigest()

    def _judge(self, call: ToolCall, history: Sequence[ToolCall]) -> Verdict | None:
        """Run every inline detector, first verdict wins. Lock held.

        A detector that raises is a bug in *that* detector, not grounds for
        failing the agent's call — it is logged and skipped so one bad
        custom heuristic degrades detection instead of breaking production.
        """
        window = history[-self._policy.comparison_window :]
        for detector in self._detectors:
            try:
                verdict = detector.observe(call, window)
            except Exception:  # a detector must never break the agent
                logger.exception("loop detector %r raised; skipping it", detector)
                continue
            if verdict is not None:
                return verdict
        return None

    def _enqueue(self, key: str, snapshot: tuple[ToolCall, ...]) -> None:
        """Hand a window to the semantic lane, dropping it if saturated."""
        if self._queue is None:
            return
        with self._lock:
            self._ensure_worker()
        try:
            self._queue.put_nowait((key, snapshot))
        except queue.Full:
            with self._lock:
                self._stats_dropped += 1
            return
        with self._lock:
            self._stats_queued += 1

    def _evaluate_window(self, key: str, snapshot: tuple[ToolCall, ...]) -> None:
        """Run the semantic observer over one window. Called on the worker."""
        observer = self._observer
        if observer is None:  # pragma: no cover - defensive
            return
        try:
            verdict = observer.evaluate(key, snapshot)
        except Exception:  # a bad observer must not kill the lane
            logger.exception("semantic observer %r raised; skipping this window", observer)
            return
        with self._lock:
            self._stats_evaluated += 1
            if verdict is None:
                return
            state = self._trajectories.get(key)
            if state is not None and state.verdict is None and state.pending is None:
                state.pending = verdict

    def _ensure_worker(self) -> None:
        """Start the semantic lane on first use. Caller holds the lock."""
        if self._worker is not None or self._queue is None or self._closed:
            return
        self._worker = threading.Thread(
            target=_drain_lane,
            args=(weakref.ref(self), self._queue),
            name="agentgov-cognitive",
            daemon=True,
        )
        self._worker.start()
        # Reap the thread if the breaker is dropped without close(). The
        # callback closes over the queue only — capturing `self` here would
        # keep the breaker alive forever and the finalizer would never run.
        self._finalizer = weakref.finalize(self, _stop_lane, self._queue)

    def _halt(self, scope_id: str, trajectory: str, verdict: Verdict) -> None:
        """Latch the financial breaker and raise. Called with no lock held."""
        reason = f"cognitive breaker [{verdict.detector}]: {verdict.reason}"
        if self._manager is not None:
            try:
                self._manager.trip(scope_id, reason)
            except UnknownScopeError:
                # Legitimate when the breaker is used standalone, or ahead of
                # the scope being funded. The cognitive halt still stands.
                logger.debug("scope %r is not financially registered; halting anyway", scope_id)
        logger.warning("thrashing halt: scope=%s trajectory=%s %s", scope_id, trajectory, reason)
        raise AgentThrashingError(
            scope_id=scope_id,
            trajectory=trajectory,
            detector=verdict.detector,
            reason=verdict.reason,
            observations=verdict.observations,
            confidence=verdict.confidence,
            tier=verdict.tier,
            evidence=dict(verdict.evidence),
        )


def _stop_lane(work: queue.Queue[_QueueItem | None]) -> None:
    """Signal the semantic worker to exit. Safe from a finalizer or close()."""
    try:
        work.put_nowait(None)
    except queue.Full:  # pragma: no cover - free a slot, then retry
        with suppress(queue.Empty, queue.Full):
            work.get_nowait()
            work.put_nowait(None)


def _drain_lane(
    breaker_ref: weakref.ReferenceType[CognitiveBreaker],
    work: queue.Queue[_QueueItem | None],
) -> None:
    """Semantic-lane worker loop.

    Deliberately a module-level function over a :mod:`weakref` rather than a
    bound method: a thread running a bound method holds a strong reference to
    its breaker, which would keep every dropped breaker — and its thread —
    alive for the life of the process. Holding only a weak reference means a
    breaker that goes out of scope is collected, its finalizer wakes this
    loop, and the thread exits.
    """
    while True:
        item = work.get()
        if item is None:
            return
        breaker = breaker_ref()
        if breaker is None:
            # The breaker was collected while this item was queued.
            return
        try:
            breaker._evaluate_window(*item)
        finally:
            # Do not hold the breaker alive across the next blocking get().
            del breaker
