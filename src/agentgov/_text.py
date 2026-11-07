"""Counted nouns for the messages AgentGov writes: ``1 phantom action``, ``3 phantom actions``.

Every count a message reports takes the form its number takes (1.3.2), never ``action(s)``.
"""

from __future__ import annotations

__all__ = ["noun", "tally"]


def noun(count: int, word: str) -> str:
    """``word`` in the form ``count`` takes: ``claim`` for one, ``claims`` otherwise."""
    if count == 1:
        return word
    if word.endswith("y") and len(word) > 1 and word[-2] not in "aeiou":
        return word[:-1] + "ies"
    if word.endswith(("s", "x", "z", "ch", "sh")):
        return word + "es"
    return word + "s"


def tally(count: int, word: str) -> str:
    """``count`` and ``word`` in the form it takes: ``1 claim``, ``3 claims``."""
    return f"{count} {noun(count, word)}"
