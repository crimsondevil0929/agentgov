"""Drop-in adapters for the major agent frameworks.

Each adapter is a thin translation layer between a framework's execution model
and AgentGov's ``authorize -> execute -> capture`` lifecycle. None of them adds
a dependency: every framework object is **duck-typed**, so
``import agentgov.adapters.langchain`` works on a machine with no LangChain
installed, and the adapters are testable against fakes rather than against a
pinned framework version.

That choice is deliberate. A governor that only works with LangChain 0.3.x is
a liability the first time LangChain ships 0.4; matching on the shapes these
frameworks expose — and degrading clearly when a shape is unrecognised — keeps
AgentGov useful across versions it has never seen.

- :mod:`agentgov.adapters.langchain` — ``GovernedChatModel`` and
  ``GovernedCallbackHandler`` for LangChain and LangGraph.
- :mod:`agentgov.adapters.crewai` — ``GovernedCrew`` and ``govern_agent`` for
  CrewAI and any framework reporting cumulative ``usage_metrics``.
"""

from __future__ import annotations

__all__ = ["crewai", "langchain"]
