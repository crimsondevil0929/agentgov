"""``govern()`` — put a budget in front of an SDK client without a refactor.

:meth:`~agentgov.interceptor.Interceptor.invoke` is the honest primitive: it
makes the enforcement point visible at the call site. But adopting it means
rewriting every call in an existing codebase, which is the difference between
a library someone tries on a Friday and one they schedule a migration for.

``govern()`` wraps a client object so the calls already written are governed
where they stand::

    client = govern(anthropic.Anthropic(), manager, "researcher")
    response = client.messages.create(model=…, messages=…)   # unchanged, now metered

The proxy returns exactly what the SDK returns, because anything else is not a
drop-in — the cost lands in the ledger, not in the caller's variable. Reach it
through :attr:`GovernedClient.agentgov` when you want it.

**This is sugar, not the contract.** It matches SDK shapes by method name, so
a client with an unusual layout may need ``metered_methods`` /
``stream_methods`` set explicitly, and a future SDK reshuffle could require an
update here. ``invoke()`` is the stable API and stays untouched underneath;
``client.agentgov.interceptor`` hands it back at any time.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agentgov.core import BudgetManager
from agentgov.interceptor import Interceptor, MeteredCall

if TYPE_CHECKING:
    from agentgov.streaming import MeteredStream

__all__ = ["GovernedClient", "GovernorHandle", "govern"]

DEFAULT_METERED_METHODS: frozenset[str] = frozenset({"create", "parse", "generate"})
"""Methods treated as one metered call.

Covers ``client.messages.create`` (Anthropic), ``client.chat.completions.create``
and ``client.responses.create`` (OpenAI), and ``messages.parse`` for structured
outputs.
"""

DEFAULT_STREAM_METHODS: frozenset[str] = frozenset({"stream"})
"""Methods that return a stream rather than a response.

A ``create(stream=True)`` call is also routed here — the keyword is what
decides, not only the method name.
"""

_PASSTHROUGH = (str, bytes, bytearray, int, float, bool, complex, type(None))


@dataclass(slots=True)
class _Recorder:
    """Shared mutable state across a proxy and its nested namespaces."""

    interceptor: Interceptor
    last_call: MeteredCall[Any] | None = None


class GovernorHandle:
    """AgentGov's own surface on a governed client, under one reserved name.

    Everything AgentGov exposes lives here rather than on the proxy itself, so
    exactly one attribute name (``agentgov``) is reserved and the rest of the
    namespace stays the SDK's.
    """

    __slots__ = ("_recorder", "_target")

    def __init__(self, recorder: _Recorder, target: object) -> None:
        self._recorder = recorder
        self._target = target

    @property
    def interceptor(self) -> Interceptor:
        """The underlying primitive. Unchanged, and always reachable."""
        return self._recorder.interceptor

    @property
    def manager(self) -> BudgetManager:
        """The governor enforcing this client's budget."""
        return self._recorder.interceptor.manager

    @property
    def scope_id(self) -> str:
        """The scope this client's calls are charged to."""
        return self._recorder.interceptor.scope_id

    @property
    def last_call(self) -> MeteredCall[Any] | None:
        """The most recent metered call, with its usage, cost, and entry.

        Convenience for a single-threaded caller. Concurrent callers should
        read cost from the ledger, which is the authoritative record.
        """
        return self._recorder.last_call

    @property
    def raw(self) -> object:
        """The unwrapped client, for anything the proxy should not touch."""
        return self._target

    def for_scope(self, scope_id: str) -> GovernedClient:
        """Return a governed client bound to a different budget scope.

        The natural way to hand a freshly delegated sub-agent its own metered
        client without rebuilding it.

        :param scope_id: The scope the copy charges.
        """
        return GovernedClient(
            self._target,
            _Recorder(interceptor=self._recorder.interceptor.for_scope(scope_id)),
        )


class GovernedClient:
    """An SDK client whose model calls are metered where they already are.

    Attribute access is forwarded to the wrapped object: namespaces
    (``client.messages``, ``client.chat.completions``) come back as further
    proxies, metered methods come back wrapped, and everything else — helpers,
    config, ``close()`` — is returned untouched.

    Build one with :func:`govern` rather than constructing it directly.
    """

    __slots__ = ("_metered", "_recorder", "_stream", "_target")

    def __init__(
        self,
        target: object,
        recorder: _Recorder,
        *,
        metered_methods: frozenset[str] = DEFAULT_METERED_METHODS,
        stream_methods: frozenset[str] = DEFAULT_STREAM_METHODS,
    ) -> None:
        self._target = target
        self._recorder = recorder
        self._metered = metered_methods
        self._stream = stream_methods

    @property
    def agentgov(self) -> GovernorHandle:
        """AgentGov's surface: the interceptor, the manager, the last call."""
        return GovernorHandle(self._recorder, self._target)

    def __repr__(self) -> str:
        return f"<governed {self._target!r} scope={self._recorder.interceptor.scope_id!r}>"

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(self._target, name)

        if callable(attribute):
            if name in self._stream:
                return self._wrap_stream(attribute)
            if name in self._metered:
                return self._wrap_metered(attribute)
            # Not a model call: hand back the SDK's own callable untouched.
            return attribute

        if isinstance(attribute, _PASSTHROUGH) or isinstance(
            attribute, Mapping | list | tuple | set
        ):
            return attribute

        # A namespace such as `.messages` or `.chat`: keep proxying downward.
        return GovernedClient(
            attribute,
            self._recorder,
            metered_methods=self._metered,
            stream_methods=self._stream,
        )

    def _wrap_metered(self, call: Callable[..., Any]) -> Callable[..., Any]:
        """Meter one call, returning what the SDK would have returned."""

        def metered(*args: object, **kwargs: object) -> Any:
            if kwargs.get("stream") is True:
                # `create(stream=True)` is a stream despite the method name.
                return self._recorder.interceptor.stream(call, *args, **kwargs)
            result = self._recorder.interceptor.invoke(call, *args, **kwargs)
            self._recorder.last_call = result
            # The SDK's own return value, so existing call sites keep working.
            return result.response

        return metered

    def _wrap_stream(self, call: Callable[..., Any]) -> Callable[..., MeteredStream[Any]]:
        """Return an unentered metered stream in place of the SDK's."""

        def streamed(*args: object, **kwargs: object) -> MeteredStream[Any]:
            return self._recorder.interceptor.stream(call, *args, **kwargs)

        return streamed


def govern(
    client: object,
    manager: BudgetManager,
    scope_id: str,
    *,
    metered_methods: frozenset[str] = DEFAULT_METERED_METHODS,
    stream_methods: frozenset[str] = DEFAULT_STREAM_METHODS,
    **interceptor_options: Any,
) -> GovernedClient:
    """Wrap an SDK client so its model calls are governed.

    Two lines to adopt on an existing codebase::

        manager.open_root("researcher", money("5.00"))
        client = govern(anthropic.Anthropic(), manager, "researcher")

        # every existing call site now authorizes, meters, and settles
        response = client.messages.create(model="claude-opus-5", messages=[...])

    Streaming works the same way, and returns a context manager::

        with client.messages.stream(model=…, messages=…) as events:
            for event in events:
                render(event)

    :param client: The SDK client to wrap. Never mutated.
    :param manager: The governor to enforce against.
    :param scope_id: The scope these calls are charged to.
    :param metered_methods: Method names treated as one metered call.
    :param stream_methods: Method names that return a stream.
    :param interceptor_options: Forwarded to :class:`~agentgov.interceptor.Interceptor`
        — ``model``, ``cognitive``, ``safety_buffer``, ``max_output_tokens``,
        and the rest.
    :returns: A proxy that behaves like ``client``.
    """
    interceptor = Interceptor(manager, scope_id, **interceptor_options)
    return GovernedClient(
        client,
        _Recorder(interceptor=interceptor),
        metered_methods=metered_methods,
        stream_methods=stream_methods,
    )
