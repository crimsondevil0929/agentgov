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

**Known limitation, stated plainly.** Legitimate iteration — pagination,
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
import threading
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
    "SemanticObserver",
    "ToolCall",
    "TrajectoryEntropyObserver",
    "Verdict",
    "canonical_arguments",
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


def shingles(text: str, *, size: int = 3, max_chars: int = 1024) -> frozenset[str]:
    """Decompose ``text`` into a set of overlapping character n-grams.

    Character shingles rather than word tokens because agent arguments are
    often JSON, URLs, or code, where whitespace tokenisation is meaningless.
    ``max_chars`` bounds the cost: this is on the inline path, so an agent
    passing a megabyte of context must not turn a similarity check into a
    latency spike.

    :param text: The text to shingle.
    :param size: n-gram width.
    :param max_chars: Truncate the input to this many characters first.
    :returns: The set of n-grams.
    """
    clipped = text[:max_chars]
    if len(clipped) <= size:
        return frozenset({clipped})
    return frozenset(clipped[i : i + size] for i in range(len(clipped) - size + 1))


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
    :ivar arguments: Canonicalised arguments.
    :ivar fingerprint: Digest of ``tool`` and ``arguments`` — the exact-repeat
        identity.
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

        Note that character-trigram Jaccard is *not* the same scale as
        intuitive "percent overlap": two search queries a human would call
        90% identical measure 0.74-0.83, because a one-word edit disturbs
        several trigrams. Measured on this project's corpus, cosmetically
        edited queries score 0.74-0.83 while queries that genuinely advance
        a task — even within one topic — score below 0.14. The ``0.70``
        default sits in that gap with roughly 5x margin on either side.

    :ivar max_similar_streak: Consecutive near-duplicate *pairs* tolerated.
        ``3`` trips on the fourth call of a soft loop.
    :ivar result_similarity_threshold: When results are known for both calls,
        they must *also* be this similar for a near-duplicate to count. This
        is what separates thrashing from legitimate iteration: pagination has
        similar inputs but dissimilar outputs.
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
    result_similarity_threshold: float = 0.70
    comparison_window: int = 6
    max_cycle_period: int = 4
    min_cycle_repeats: int = 3
    history_limit: int = 64
    max_trajectories: int = 256
    shingle_size: int = 3
    max_argument_chars: int = 1024
    exempt_tools: frozenset[str] = frozenset()
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

    This is the detector that catches the failure mode exact matching misses:
    an agent nudging a search query, incrementing a guess, or reformatting a
    prompt while making no semantic progress. Similarity is Jaccard over
    character shingles of tool-plus-arguments.

    When results are known for both calls in a pair, they must *also* be
    similar for the pair to count as stagnant. That is the discriminator
    between thrashing and legitimate iteration: paginating a cursor produces
    near-identical inputs but genuinely different outputs, and is left alone.
    """

    threshold: float = 0.70
    max_streak: int = 3
    result_threshold: float = 0.70

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
    """

    __slots__ = ("_include_results", "_lock", "_min_ratio", "_states", "_window")

    def __init__(
        self,
        *,
        window: int = 12,
        min_novelty_ratio: float = 0.02,
        include_results: bool = True,
    ) -> None:
        self._window = max(2, window)
        self._min_ratio = min_novelty_ratio
        self._include_results = include_results
        self._states: dict[str, _EntropyState] = {}
        self._lock = threading.Lock()

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
        "_closed",
        "_detectors",
        "_lock",
        "_manager",
        "_observer",
        "_policy",
        "_queue",
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
            )
        else:
            resolved = observer
        self._observer: SemanticObserver | None = resolved
        self._manager = manager

        self._lock = threading.RLock()
        self._trajectories: OrderedDict[str, _Trajectory] = OrderedDict()
        self._closed = False
        self._stats_observed = 0
        self._stats_queued = 0
        self._stats_dropped = 0
        self._stats_evaluated = 0

        self._queue: queue.Queue[_QueueItem | None] | None = None
        self._worker: threading.Thread | None = None
        if resolved is not None:
            self._queue = queue.Queue(maxsize=self._policy.async_queue_size)
            self._worker = threading.Thread(
                target=self._drain, name="agentgov-cognitive", daemon=True
            )
            self._worker.start()

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

        # Hashing and shingling are pure; keep them outside the lock so
        # concurrent sub-agents contend only for the bookkeeping itself.
        text = f"{tool}{_UNIT_SEPARATOR}{arguments}"
        call = ToolCall(
            sequence=0,
            scope_id=scope_id,
            tool=tool,
            arguments=arguments,
            fingerprint=hashlib.blake2b(text.encode("utf-8"), digest_size=16).hexdigest(),
            shingles=shingles(
                text,
                size=self._policy.shingle_size,
                max_chars=self._policy.max_argument_chars,
            ),
            timestamp=datetime.now(UTC),
        )

        snapshot: tuple[ToolCall, ...] | None = None
        with self._lock:
            self._stats_observed += 1
            state = self._touch(key)
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
        rendered = canonical_arguments((result,))
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
        if self._queue is not None:
            try:
                self._queue.put_nowait(None)
            except queue.Full:  # pragma: no cover - free a slot, then retry
                with suppress(queue.Empty, queue.Full):
                    self._queue.get_nowait()
                    self._queue.put_nowait(None)
        if self._worker is not None:
            self._worker.join(timeout=2.0)

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

    def _touch(self, key: str) -> _Trajectory:
        """Fetch or create a trajectory, evicting the least recent. Lock held."""
        state = self._trajectories.get(key)
        if state is None:
            state = _Trajectory(calls=deque(maxlen=self._policy.history_limit))
            self._trajectories[key] = state
            while len(self._trajectories) > self._policy.max_trajectories:
                self._trajectories.popitem(last=False)
        else:
            self._trajectories.move_to_end(key)
        return state

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
        try:
            self._queue.put_nowait((key, snapshot))
        except queue.Full:
            with self._lock:
                self._stats_dropped += 1
            return
        with self._lock:
            self._stats_queued += 1

    def _drain(self) -> None:
        """Worker loop for the semantic lane."""
        assert self._queue is not None
        while True:
            item = self._queue.get()
            if item is None:
                return
            key, snapshot = item
            observer = self._observer
            if observer is None:  # pragma: no cover - defensive
                continue
            try:
                verdict = observer.evaluate(key, snapshot)
            except Exception:  # a bad observer must not kill the lane
                logger.exception("semantic observer %r raised; skipping this window", observer)
                continue
            with self._lock:
                self._stats_evaluated += 1
                if verdict is None:
                    continue
                state = self._trajectories.get(key)
                if state is not None and state.verdict is None and state.pending is None:
                    state.pending = verdict

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
