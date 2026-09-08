"""A deterministic fake model client, for tests and demos.

Not a production component. It exists so the governor can be exercised —
and a denial-of-wallet run can be reproduced — without spending real money
or depending on network access.

Token counts are derived from a SHA-256 of the prompt rather than drawn at
random, so a given prompt always bills the same amount. That reproducibility
is what lets a test assert an exact ledger balance to the last hundred-
millionth of a dollar.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass

from agentgov.interceptor import TokenUsage

__all__ = ["DummyLLM", "DummyResponse"]


@dataclass(frozen=True, slots=True)
class DummyResponse:
    """A stand-in for a model response.

    Shaped like the Anthropic Messages API response in the ways the governor
    cares about: it exposes ``usage``, so
    :func:`~agentgov.interceptor.default_usage_extractor` reads it with no
    special-casing.

    :ivar text: The generated text.
    :ivar usage: Token counts for the call.
    :ivar model: The model that produced it.
    """

    text: str
    usage: TokenUsage
    model: str


class DummyLLM:
    """A deterministic, offline stand-in for a model client.

    :param model: Model id reported on responses.
    :param output_tokens: Fixed output token count, or ``None`` to derive one
        from the prompt (in ``[64, 576)``).
    :param latency_seconds: Artificial delay per call, for exercising
        concurrency.
    """

    __slots__ = ("_calls", "_latency", "_model", "_output_tokens")

    def __init__(
        self,
        model: str = "claude-opus-5",
        *,
        output_tokens: int | None = None,
        latency_seconds: float = 0.0,
    ) -> None:
        self._model = model
        self._output_tokens = output_tokens
        self._latency = latency_seconds
        self._calls = 0

    @property
    def call_count(self) -> int:
        """How many calls this client has served."""
        return self._calls

    def complete(self, prompt: str) -> DummyResponse:
        """Return a deterministic response for ``prompt``.

        :param prompt: The prompt text; drives both token counts.
        :returns: The fake response.
        """
        self._calls += 1
        if self._latency:
            import time

            time.sleep(self._latency)
        return self._response(prompt)

    async def acomplete(self, prompt: str) -> DummyResponse:
        """Async counterpart of :meth:`complete`.

        :param prompt: The prompt text.
        :returns: The fake response.
        """
        self._calls += 1
        if self._latency:
            await asyncio.sleep(self._latency)
        return self._response(prompt)

    def _response(self, prompt: str) -> DummyResponse:
        """Build the deterministic response for ``prompt``."""
        digest = hashlib.sha256(prompt.encode("utf-8")).digest()
        input_tokens = max(1, len(prompt) // 4)
        output_tokens = (
            self._output_tokens
            if self._output_tokens is not None
            else 64 + (int.from_bytes(digest[:2], "big") % 512)
        )
        return DummyResponse(
            text=f"[{self._model}] response to: {prompt[:40]}",
            usage=TokenUsage(input_tokens=input_tokens, output_tokens=output_tokens),
            model=self._model,
        )
