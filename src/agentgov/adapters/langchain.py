"""LangChain and LangGraph adapter.

Two entry points, for the two ways people actually build on LangChain.

:class:`GovernedChatModel` wraps a chat model directly. It is the two-line
drop-in: construct it around the model you already have, and every ``invoke``
authorizes, meters, and settles.

:class:`GovernedCallbackHandler` plugs into LangChain's callback system
instead. This is the one to reach for with **LangGraph**, agent executors, or
any chain deep enough that you never touch the model object — callbacks
propagate down the whole run tree, so one handler governs every model call in
a graph regardless of how many nodes it passes through.

**Nothing here imports LangChain.** Every object is duck-typed, so this module
loads on a machine that has never heard of it and is tested against fakes.

One implementation detail worth knowing, because it is the difference between
a governor that works and one that silently does not: LangChain **swallows
exceptions raised inside callbacks** unless the handler sets
``raise_error = True``. :class:`GovernedCallbackHandler` sets it, so a
:class:`~agentgov.exceptions.DenialOfWalletError` or
:class:`~agentgov.exceptions.AgentThrashingError` actually halts the graph
rather than being logged and ignored.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

from agentgov.core import Authorization, BudgetManager
from agentgov.exceptions import AgentGovError
from agentgov.interceptor import Interceptor, TokenUsage
from agentgov.reconciliation import MeteringJournal

__all__ = [
    "GovernedCallbackHandler",
    "GovernedChatModel",
    "extract_langchain_usage",
    "govern_chat_model",
]

logger = logging.getLogger("agentgov.adapters.langchain")

# Usage has lived in three different places across LangChain versions and
# provider integrations. Try all of them rather than pinning to one.
_USAGE_CONTAINERS = ("usage_metadata", "token_usage", "usage")
_INPUT_ALIASES = ("input_tokens", "prompt_tokens", "promptTokens")
_OUTPUT_ALIASES = ("output_tokens", "completion_tokens", "completionTokens")
_CACHE_READ_ALIASES = ("cache_read_input_tokens", "cache_read")
_CACHE_WRITE_ALIASES = ("cache_creation_input_tokens", "cache_creation")


def _read_int(source: object, aliases: Sequence[str]) -> int:
    """Pull the first present integer among ``aliases`` off a dict or object."""
    for alias in aliases:
        value: object = None
        if isinstance(source, Mapping):
            value = source.get(alias)
        else:
            value = getattr(source, alias, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
        if isinstance(value, float):
            return int(value)
    return 0


def _usage_from(source: object) -> TokenUsage | None:
    """Build usage from a dict or object that carries token counts."""
    if source is None:
        return None
    usage = TokenUsage(
        input_tokens=_read_int(source, _INPUT_ALIASES),
        output_tokens=_read_int(source, _OUTPUT_ALIASES),
        cache_read_input_tokens=_read_int(source, _CACHE_READ_ALIASES),
        cache_creation_input_tokens=_read_int(source, _CACHE_WRITE_ALIASES),
    )
    return usage if usage.total_tokens else None


def extract_langchain_usage(result: object) -> TokenUsage:
    """Read token counts out of a LangChain ``LLMResult`` or message.

    Looks in every place LangChain has put usage across its versions and
    provider integrations: ``llm_output["token_usage"]`` (the OpenAI shape),
    ``llm_output["usage"]`` (the Anthropic shape), and
    ``generations[0][0].message.usage_metadata`` (the modern, normalised one).

    :param result: An ``LLMResult``, an ``AIMessage``, or anything carrying
        one of the recognised usage containers.
    :returns: The token counts found.
    :raises TypeError: If no usage is present anywhere. Deliberately loud:
        silently metering zero would let an unrecognised response shape spend
        without limit.
    """
    # 1. The modern normalised location, on the generated message itself.
    generations = getattr(result, "generations", None)
    if isinstance(generations, Sequence):
        for batch in generations:
            if not isinstance(batch, Sequence):
                continue
            for generation in batch:
                message = getattr(generation, "message", generation)
                for container in _USAGE_CONTAINERS:
                    found = _usage_from(getattr(message, container, None))
                    if found is not None:
                        return found

    # 2. The provider-specific `llm_output` bag.
    llm_output = getattr(result, "llm_output", None)
    if isinstance(llm_output, Mapping):
        for container in _USAGE_CONTAINERS:
            found = _usage_from(llm_output.get(container))
            if found is not None:
                return found
        found = _usage_from(llm_output)
        if found is not None:
            return found

    # 3. The object itself, for a bare message or a plain dict.
    for container in _USAGE_CONTAINERS:
        found = _usage_from(getattr(result, container, None))
        if found is not None:
            return found
    if isinstance(result, Mapping):
        for container in _USAGE_CONTAINERS:
            found = _usage_from(result.get(container))
            if found is not None:
                return found
    direct = _usage_from(result)
    if direct is not None:
        return direct

    raise TypeError(
        f"no token usage found on {type(result).__name__}; pass an explicit "
        f"extract_usage to the Interceptor, or record usage manually"
    )


class GovernedCallbackHandler:
    """A LangChain callback handler that governs every model call in a run.

    Attach it once and every model call beneath it — through chains, agents,
    tools, or a LangGraph state machine — is authorized before it starts and
    settled when it ends::

        handler = GovernedCallbackHandler(manager, "researcher")
        graph.invoke(state, config={"callbacks": [handler]})

    The hold is keyed by LangChain's ``run_id``, so concurrent branches of a
    graph each carry their own encumbrance and settle independently.

    A run that errors has its hold voided. A run that never reports an end —
    a process killed mid-graph — leaves a hold that
    :meth:`~agentgov.core.BudgetManager.void_stale` reclaims.

    :param manager: The governor to enforce against.
    :param scope_id: The scope these calls are charged to.
    :param model: Model id used to look up pricing.
    :param interceptor: An existing interceptor to use instead of building one.
    :param journal: Optional metering journal, for later reconciliation.
    :param interceptor_options: Forwarded to :class:`~agentgov.interceptor.Interceptor`
        when one is constructed — ``cognitive``, ``safety_buffer``, and the rest.
    """

    # LangChain swallows callback exceptions unless this is set. Without it a
    # denial-of-wallet halt would be logged and the graph would keep spending.
    raise_error = True
    run_inline = True

    def __init__(
        self,
        manager: BudgetManager | None = None,
        scope_id: str = "",
        *,
        model: str = "claude-opus-5",
        interceptor: Interceptor | None = None,
        journal: MeteringJournal | None = None,
        **interceptor_options: Any,
    ) -> None:
        if interceptor is None:
            if manager is None or not scope_id:
                raise ValueError(
                    "provide either an interceptor, or a manager and scope_id to build one"
                )
            interceptor = Interceptor(manager, scope_id, model=model, **interceptor_options)
        self._interceptor = interceptor
        self._journal = journal
        self._lock = threading.Lock()
        self._holds: dict[uuid.UUID, Authorization] = {}

    # -- LangChain's handler protocol -------------------------------------

    @property
    def ignore_llm(self) -> bool:
        """LangChain asks this before dispatching model events."""
        return False

    @property
    def ignore_chain(self) -> bool:
        return True

    @property
    def ignore_agent(self) -> bool:
        return True

    @property
    def ignore_retriever(self) -> bool:
        return True

    @property
    def ignore_chat_model(self) -> bool:
        return False

    @property
    def interceptor(self) -> Interceptor:
        """The underlying primitive, unchanged and reachable."""
        return self._interceptor

    @property
    def outstanding(self) -> int:
        """How many runs currently hold an unsettled authorization."""
        with self._lock:
            return len(self._holds)

    # -- lifecycle --------------------------------------------------------

    def on_chat_model_start(
        self,
        serialized: Mapping[str, Any],
        messages: Sequence[Sequence[Any]],
        *,
        run_id: uuid.UUID,
        **kwargs: Any,
    ) -> None:
        """Authorize before a chat model call begins.

        :raises ~agentgov.exceptions.DenialOfWalletError: If the scope cannot
            afford the call.
        :raises ~agentgov.exceptions.AgentThrashingError: If the cognitive
            breaker finds the graph looping.
        """
        self._begin(run_id, _flatten_messages(messages), kwargs)

    def on_llm_start(
        self,
        serialized: Mapping[str, Any],
        prompts: Sequence[str],
        *,
        run_id: uuid.UUID,
        **kwargs: Any,
    ) -> None:
        """Authorize before a completion-style model call begins."""
        self._begin(run_id, list(prompts), kwargs)

    def on_llm_end(self, response: object, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        """Settle the call at its true cost."""
        authorization = self._claim(run_id)
        if authorization is None:
            return
        try:
            usage = extract_langchain_usage(response)
        except TypeError:
            # An unrecognised response shape. Charging the full hold is the
            # conservative choice: under-charging is the one direction a spend
            # governor must never fail in.
            logger.warning(
                "no usage on %s for run %s; capturing the full authorization of %s",
                type(response).__name__,
                run_id,
                authorization.amount,
            )
            self._interceptor.manager.capture(
                authorization, authorization.amount, memo="langchain call, usage unavailable"
            )
            return

        cost = self._interceptor.pricing.cost_of(usage)
        entry = self._interceptor.manager.capture(authorization, cost, memo="langchain model call")
        if self._journal is not None:
            self._journal.record_usage(
                entry.transaction_id,
                self._interceptor.pricing.model_id,
                usage,
                self._interceptor.scope_id,
                entry.timestamp,
            )

    def on_llm_error(self, error: BaseException, *, run_id: uuid.UUID, **kwargs: Any) -> None:
        """Release the hold: a failed call generated nothing to bill."""
        authorization = self._claim(run_id)
        if authorization is not None:
            self._interceptor.manager.void(authorization, memo="langchain call failed")

    # -- internals --------------------------------------------------------

    def _begin(self, run_id: uuid.UUID, texts: Sequence[str], kwargs: Mapping[str, Any]) -> None:
        """Size, observe, and authorize one model call."""
        payload: dict[str, Any] = {"messages": list(texts)}
        invocation = kwargs.get("invocation_params")
        if isinstance(invocation, Mapping) and "max_tokens" in invocation:
            payload["max_tokens"] = invocation["max_tokens"]

        breaker = self._interceptor.cognitive
        if breaker is not None:
            # Ahead of the hold, so a thrashing graph costs nothing to stop.
            breaker.observe_call(
                self._interceptor.scope_id,
                "langchain.model",
                (),
                payload,
                trajectory=self._interceptor.trajectory,
            )

        hold = self._interceptor.size_hold((), payload)
        authorization = self._interceptor.manager.authorize(
            self._interceptor.scope_id, hold, memo="langchain call authorization"
        )
        with self._lock:
            self._holds[run_id] = authorization

    def _claim(self, run_id: uuid.UUID) -> Authorization | None:
        """Take ownership of a run's hold, exactly once."""
        with self._lock:
            return self._holds.pop(run_id, None)

    def release_all(self, *, memo: str = "langchain run abandoned") -> int:
        """Void every outstanding hold. For teardown after a failed run.

        :param memo: Audit context recorded on the releases.
        :returns: How many holds were released.
        """
        with self._lock:
            outstanding = list(self._holds.values())
            self._holds.clear()
        for authorization in outstanding:
            try:
                self._interceptor.manager.void(authorization, memo=memo)
            except AgentGovError:  # pragma: no cover - already settled elsewhere
                logger.debug("hold %s was already resolved", authorization.authorization_id)
        return len(outstanding)


def _flatten_messages(messages: Sequence[Sequence[Any]]) -> list[str]:
    """Reduce LangChain's nested message batches to plain text for sizing."""
    texts: list[str] = []
    for batch in messages:
        if isinstance(batch, str):
            texts.append(batch)
            continue
        for message in batch:
            content = getattr(message, "content", message)
            if isinstance(content, str):
                texts.append(content)
            elif isinstance(content, Sequence):
                for block in content:
                    if isinstance(block, Mapping) and isinstance(block.get("text"), str):
                        texts.append(block["text"])
                    elif isinstance(block, str):
                        texts.append(block)
    return texts


class GovernedChatModel:
    """A LangChain chat model whose calls are metered and enforced.

    The two-line drop-in::

        model = GovernedChatModel(ChatAnthropic(model="claude-opus-5"), gov, "researcher")
        response = model.invoke(messages)     # unchanged call site, now governed

    Attribute access falls through to the wrapped model, so anything this
    adapter does not govern keeps working. ``invoke``, ``ainvoke``, and
    ``stream`` are routed through the interceptor; ``bind``, ``bind_tools``,
    and ``with_config`` return a governed wrapper around the model they
    produce, so a bound model does not silently escape governance.

    :param model: The LangChain chat model to wrap. Never mutated.
    :param manager: The governor to enforce against.
    :param scope_id: The scope these calls are charged to.
    :param pricing_model: Model id used to look up pricing, when it cannot be
        read off the wrapped model. When omitted, the wrapped model's own
        ``model``/``model_name`` attribute is used.
    :param journal: Optional metering journal, for later reconciliation.
    :param interceptor: An existing interceptor to use instead of building one.
    :param interceptor_options: Forwarded to :class:`~agentgov.interceptor.Interceptor`.
    """

    __slots__ = ("_interceptor", "_journal", "_model")

    def __init__(
        self,
        model: object,
        manager: BudgetManager | None = None,
        scope_id: str = "",
        *,
        pricing_model: str | None = None,
        journal: MeteringJournal | None = None,
        interceptor: Interceptor | None = None,
        **interceptor_options: Any,
    ) -> None:
        if interceptor is None:
            if manager is None or not scope_id:
                raise ValueError(
                    "provide either an interceptor, or a manager and scope_id to build one"
                )
            resolved = pricing_model or _infer_model_name(model) or "claude-opus-5"
            # Default to the LangChain-aware extractor: the generic one does
            # not know where LangChain hides usage, and silently metering zero
            # is the one failure a spend governor must not have.
            interceptor_options.setdefault("extract_usage", extract_langchain_usage)
            interceptor = Interceptor(manager, scope_id, model=resolved, **interceptor_options)
        self._model = model
        self._interceptor = interceptor
        self._journal = journal

    @property
    def interceptor(self) -> Interceptor:
        """The underlying primitive, unchanged and reachable."""
        return self._interceptor

    @property
    def raw(self) -> object:
        """The unwrapped LangChain model."""
        return self._model

    def __repr__(self) -> str:
        return f"<governed {self._model!r} scope={self._interceptor.scope_id!r}>"

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            # Without this, an attribute miss during construction or copying
            # recurses forever through this same __getattr__.
            raise AttributeError(name)
        attribute = getattr(self._model, name)
        if name in ("bind", "bind_tools", "with_config", "with_retry", "with_structured_output"):
            return self._rewrap(attribute)
        return attribute

    def _rewrap(self, factory: Any) -> Any:
        """Keep governance attached across LangChain's builder methods."""

        def bound(*args: object, **kwargs: object) -> Any:
            produced = factory(*args, **kwargs)
            return GovernedChatModel(produced, interceptor=self._interceptor, journal=self._journal)

        return bound

    def invoke(self, input: object, *args: object, **kwargs: object) -> Any:
        """Call the model under budget enforcement, returning its own result."""
        return self._run(self._model.invoke, input, args, kwargs)  # type: ignore[attr-defined]

    async def ainvoke(self, input: object, *args: object, **kwargs: object) -> Any:
        """Await the model under budget enforcement."""
        payload = _sizing_payload(input, kwargs)
        result = await self._interceptor.ainvoke(
            _sizing_shim_async(self._model.ainvoke, input, args),  # type: ignore[attr-defined]
            **payload,
        )
        return self._settle(result)

    def stream(self, input: object, *args: object, **kwargs: object) -> Any:
        """Stream from the model under budget enforcement.

        Returns an unentered :class:`~agentgov.streaming.MeteredStream`, so the
        hold is resolved however the caller leaves the loop.
        """
        payload = _sizing_payload(input, kwargs)
        return self._interceptor.stream(
            _sizing_shim(self._model.stream, input, args),  # type: ignore[attr-defined]
            **payload,
        )

    def _run(
        self, call: Any, input: object, args: Sequence[object], kwargs: Mapping[str, object]
    ) -> Any:
        payload = _sizing_payload(input, kwargs)
        result = self._interceptor.invoke(_sizing_shim(call, input, args), **payload)
        return self._settle(result)

    def _settle(self, result: Any) -> Any:
        if self._journal is not None:
            self._journal.record(result)
        return result.response


def _sizing_payload(input: object, kwargs: Mapping[str, object]) -> dict[str, Any]:
    """Build the kwargs the interceptor sizes a hold from.

    The wrapped call's real arguments are captured in a closure; what is
    passed through the interceptor is a payload shaped for
    :func:`~agentgov.interceptor.extract_prompt_text` to read.
    """
    payload: dict[str, Any] = {"messages": _flatten_messages([input])}  # type: ignore[list-item]
    if "max_tokens" in kwargs:
        payload["max_tokens"] = kwargs["max_tokens"]
    return payload


def _sizing_shim(call: Any, input: object, args: Sequence[object]) -> Any:
    """Adapt a model call so the interceptor can size it and still invoke it."""

    def invoke(**_sizing: object) -> Any:
        return call(input, *args)

    invoke.__name__ = getattr(call, "__name__", "invoke")
    return invoke


def _sizing_shim_async(call: Any, input: object, args: Sequence[object]) -> Any:
    """Async counterpart of :func:`_sizing_shim`."""

    async def ainvoke(**_sizing: object) -> Any:
        return await call(input, *args)

    ainvoke.__name__ = getattr(call, "__name__", "ainvoke")
    return ainvoke


def _infer_model_name(model: object) -> str | None:
    """Best-effort read of a LangChain model's identifier."""
    for attribute in ("model", "model_name", "model_id", "deployment_name"):
        value = getattr(model, attribute, None)
        if isinstance(value, str) and value:
            return value
    return None


def govern_chat_model(
    model: object,
    manager: BudgetManager,
    scope_id: str,
    **options: Any,
) -> GovernedChatModel:
    """Wrap a LangChain chat model in one call.

    :param model: The chat model to govern.
    :param manager: The governor to enforce against.
    :param scope_id: The scope these calls are charged to.
    :param options: Forwarded to :class:`GovernedChatModel`.
    :returns: The governed model.
    """
    return GovernedChatModel(model, manager, scope_id, **options)
