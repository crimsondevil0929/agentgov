"""Torn-line tolerance for append-only JSON-lines files.

Every writer in :mod:`agentgov.receipts` (:class:`~agentgov.receipts.log.ReceiptLog`
and :class:`~agentgov.receipts.witness.FileWitness` alike) appends one whole
line and a trailing newline per record. A process killed mid-write can leave,
at most, one incomplete final line: bytes after the last newline that were
never acknowledged as a completed append. That tail is unwritten data, not
corruption, and a reader that treats it as a parse failure makes the file
unopenable forever after an ordinary crash. :func:`read_complete_lines` is
the one place that distinction is made, so every reader in this package
treats a torn line the same way.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = ["read_complete_lines"]


def read_complete_lines(path: Path, *, repair: bool = False) -> list[bytes]:
    """The file's complete, non-blank lines, ignoring a torn final one.

    :param path: The file to read. A missing file reads as empty.
    :param repair: When true, truncate the file in place to drop the torn
        tail once it has been identified, so the next append starts clean
        instead of concatenating onto an incomplete line. Appropriate for a
        writer resuming a file only it owns (a :class:`ReceiptLog` or
        :class:`FileWitness` reopening its own file). Leave this false for a
        read-only caller inspecting a file it does not own -- verifying
        someone else's published evidence must never mutate it, even to fix
        a crash artifact that isn't harming the read.
    """
    if not path.exists():
        return []
    data = path.read_bytes()
    cut = data.rfind(b"\n") + 1
    if cut < len(data):
        logger.warning(
            "%s ends in a torn line (%d bytes) left by a crash mid-append; %s",
            path,
            len(data) - cut,
            "cutting it off" if repair else "ignoring it for this read",
        )
        if repair:
            with path.open("r+b") as handle:
                handle.truncate(cut)
                handle.flush()
                os.fsync(handle.fileno())
    return [line for line in data[:cut].split(b"\n") if line.strip()]
