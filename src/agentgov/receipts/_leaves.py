"""Where a receipt log keeps its leaves: in memory, or in its file and an index.

A durable log's file of JSON lines *is* the log: one canonical receipt per
line, each line one Merkle leaf, readable and checkable with nothing but
SHA-256. Beside it, ``<file>.index`` is an index of that file in SQLite: each
receipt's place in the file, its id and its leaf hash, and the roots of the
tree's perfect subtrees of 256 leaves and more, stored as each completes. The
index is derived from the file and rebuilt from it when it is missing, stale
or does not match; a log reopens from it in time that does not grow with the
log, and holds none of its receipts in memory.

Every receipt read through the index is checked against the leaf hash the
index recorded for its line, and the index's tree is checked against the
newest signed checkpoint when the log opens.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import BinaryIO, Final

from agentgov.exceptions import MalformedReceiptError, ReceiptLogError
from agentgov.receipts.canonical import loads_strict
from agentgov.receipts.merkle import MerkleTree, _split, leaf_hash, node_hash
from agentgov.receipts.schema import LogDocument, document_from_json

logger = logging.getLogger("agentgov.receipts")

INDEX_VERSION: Final = "1"
BLOCK: Final = 8
"""Perfect subtrees of ``2**BLOCK`` leaves and more are stored in the index;
smaller ones are hashed from their leaves, at most 255 of them, when needed."""

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS leaves (
    idx INTEGER PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE,
    offset INTEGER NOT NULL,
    length INTEGER NOT NULL,
    leaf BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    level INTEGER NOT NULL,
    start INTEGER NOT NULL,
    hash BLOB NOT NULL,
    PRIMARY KEY (level, start)
) WITHOUT ROWID;
"""


class IndexWriteError(Exception):
    """Receipts are durable in the log's file, but its index could not record
    them: the log must be reopened, which indexes them from the file."""


# --------------------------------------------------------------------------
# The file
# --------------------------------------------------------------------------


def complete_length(path: Path, *, repair: bool) -> int:
    """The file's length up to and including its last newline, read from its
    tail. A torn final line (a crash mid-append) is cut off with ``repair``,
    and ignored without it."""
    if not path.exists():
        return 0
    size = path.stat().st_size
    cut = 0
    with path.open("rb") as handle:
        position = size
        while position > 0:
            start = max(0, position - 65536)
            handle.seek(start)
            found = handle.read(position - start).rfind(b"\n")
            if found >= 0:
                cut = start + found + 1
                break
            position = start
    if cut < size:
        logger.warning(
            "%s ends in a torn line (%d bytes) left by a crash mid-append; %s",
            path,
            size - cut,
            "cutting it off" if repair else "ignoring it for this read",
        )
        if repair:
            with path.open("r+b") as handle:
                handle.truncate(cut)
                handle.flush()
                os.fsync(handle.fileno())
    return cut


def lines_from(path: Path, start: int, end: int) -> Iterator[tuple[int, bytes]]:
    """The non-blank lines between byte ``start`` and ``end``, each with the
    offset it begins at."""
    if start >= end:
        return
    with path.open("rb") as handle:
        handle.seek(start)
        offset = start
        while offset < end:
            line = handle.readline()
            if not line:
                return
            here, offset = offset, offset + len(line)
            body = line.rstrip(b"\n")
            if body.strip():
                yield here, body


def write_lines(path: Path, lines: Sequence[bytes], *, fsync: bool) -> int:
    """Append ``lines`` with one write, forced to disk with ``fsync``.

    :returns: The offset the first line begins at.
    """
    with path.open("ab") as handle:
        start = handle.tell()
        try:
            handle.write(b"".join(line + b"\n" for line in lines))
            handle.flush()
            if fsync:
                os.fsync(handle.fileno())
        except BaseException:
            # Never leave a torn line for the next append to follow.
            handle.truncate(start)
            raise
    return start


def _parse(path: Path, number: int, line: bytes) -> LogDocument:
    try:
        return document_from_json(loads_strict(line), f"{path}:{number}")
    except MalformedReceiptError as exc:
        raise ReceiptLogError(f"{path} line {number} is not a receipt: {exc}") from exc


def _perfect_root(leaves: Sequence[bytes]) -> bytes:
    """The root of a perfect tree over ``leaves`` (a power of two of them)."""
    level = list(leaves)
    while len(level) > 1:
        level = [node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


# --------------------------------------------------------------------------
# A log in memory
# --------------------------------------------------------------------------


class MemoryLeaves:
    """The receipts of a log without a file."""

    __slots__ = ("_ids", "_receipts", "tree")

    def __init__(self) -> None:
        self._receipts: list[LogDocument] = []
        self._ids: dict[str, int] = {}
        self.tree = MerkleTree()

    def __len__(self) -> int:
        return len(self._receipts)

    def get(self, index: int) -> LogDocument:
        return self._receipts[index]

    def all(self) -> tuple[LogDocument, ...]:
        return tuple(self._receipts)

    def index_of(self, receipt_id: str) -> int | None:
        return self._ids.get(receipt_id)

    def extend(self, receipts: Sequence[LogDocument]) -> None:
        for receipt in receipts:
            self.tree.append(receipt.leaf_hash())
            self._ids[receipt.receipt_id] = len(self._receipts)
            self._receipts.append(receipt)

    def close(self) -> None:
        return None


# --------------------------------------------------------------------------
# A log in a file, and its index
# --------------------------------------------------------------------------


class _Index:
    """The SQLite index of a log's file. Its owner serializes every call."""

    __slots__ = ("_conn", "_count", "_end", "_path")

    def __init__(self, path: Path) -> None:
        self._path = path
        try:
            self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
            row = self._conn.execute("SELECT value FROM meta WHERE key = 'version'").fetchone()
            if row is None or row[0] != INDEX_VERSION:
                self.reset()
        except sqlite3.Error as exc:
            raise ReceiptLogError(f"cannot open the receipt log's index {path}: {exc}") from exc
        self._count, self._end = 0, 0
        self._refresh()

    @property
    def count(self) -> int:
        """How many receipts the index holds: the first ``count`` lines."""
        return self._count

    @property
    def end(self) -> int:
        """The byte just past the last indexed line."""
        return self._end

    def _refresh(self) -> None:
        row = self._conn.execute(
            "SELECT idx, offset, length FROM leaves ORDER BY idx DESC LIMIT 1"
        ).fetchone()
        self._count, self._end = (0, 0) if row is None else (row[0] + 1, row[1] + row[2] + 1)

    def reset(self) -> None:
        """Forget everything: the index is rebuilt from the file."""
        with self._transaction():
            self._conn.execute("DELETE FROM leaves")
            self._conn.execute("DELETE FROM nodes")
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('version', ?)", (INDEX_VERSION,)
            )
        self._count, self._end = 0, 0

    def file_state(self) -> tuple[int, int] | None:
        """The size and modification time the file had when the index last
        recorded it, if it ever did."""
        rows = dict(
            self._conn.execute(
                "SELECT key, value FROM meta WHERE key IN ('file_size', 'file_mtime_ns')"
            ).fetchall()
        )
        if "file_size" not in rows or "file_mtime_ns" not in rows:
            return None
        return int(rows["file_size"]), int(rows["file_mtime_ns"])

    def _record_file(self, state: tuple[int, int]) -> None:
        self._conn.executemany(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (("file_size", str(state[0])), ("file_mtime_ns", str(state[1]))),
        )

    def add(
        self,
        rows: Sequence[tuple[int, str, int, int, bytes]],
        file_state: tuple[int, int] | None = None,
    ) -> None:
        """Record receipts ``(index, receipt_id, offset, length, leaf)``, in
        order after the last, every perfect subtree they complete, and the
        file's size and modification time after they were appended."""
        if not rows:
            if file_state is not None:
                with self._transaction():
                    self._record_file(file_state)
            return
        with self._transaction():
            if file_state is not None:
                self._record_file(file_state)
            self._conn.executemany(
                "INSERT INTO leaves (idx, receipt_id, offset, length, leaf) VALUES (?, ?, ?, ?, ?)",
                rows,
            )
            for index, *_ in rows:
                completed = index + 1
                level = BLOCK
                while completed % (1 << level) == 0:
                    size = 1 << level
                    start = completed - size
                    if level == BLOCK:
                        root = _perfect_root(self.leaves(start, completed))
                    else:
                        half = size // 2
                        left = self.node(level - 1, start)
                        right = self.node(level - 1, start + half)
                        assert left is not None and right is not None
                        root = node_hash(left, right)
                    self._conn.execute(
                        "INSERT OR REPLACE INTO nodes (level, start, hash) VALUES (?, ?, ?)",
                        (level, start, root),
                    )
                    level += 1
        last = rows[-1]
        self._count, self._end = last[0] + 1, last[2] + last[3] + 1

    def leaf(self, index: int) -> bytes:
        row = self._conn.execute("SELECT leaf FROM leaves WHERE idx = ?", (index,)).fetchone()
        if row is None:
            raise IndexError(f"the log has no receipt {index}")
        return bytes(row[0])

    def leaves(self, start: int, end: int) -> list[bytes]:
        rows = self._conn.execute(
            "SELECT leaf FROM leaves WHERE idx >= ? AND idx < ? ORDER BY idx", (start, end)
        ).fetchall()
        return [bytes(row[0]) for row in rows]

    def locate(self, index: int) -> tuple[int, int, bytes]:
        """``(offset, length, leaf)`` of receipt ``index``."""
        row = self._conn.execute(
            "SELECT offset, length, leaf FROM leaves WHERE idx = ?", (index,)
        ).fetchone()
        if row is None:
            raise IndexError(f"the log has no receipt {index}")
        return int(row[0]), int(row[1]), bytes(row[2])

    def index_of(self, receipt_id: str) -> int | None:
        row = self._conn.execute(
            "SELECT idx FROM leaves WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()
        return None if row is None else int(row[0])

    def node(self, level: int, start: int) -> bytes | None:
        row = self._conn.execute(
            "SELECT hash FROM nodes WHERE level = ? AND start = ?", (level, start)
        ).fetchone()
        return None if row is None else bytes(row[0])

    def close(self) -> None:
        self._conn.close()

    def _transaction(self) -> _Transaction:
        return _Transaction(self._conn)


class _Transaction:
    __slots__ = ("_conn",)

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> None:
        self._conn.execute("BEGIN")

    def __exit__(self, kind: object, *rest: object) -> None:
        self._conn.execute("COMMIT" if kind is None else "ROLLBACK")


class _IndexedTree(MerkleTree):
    """The RFC 9162 tree over an index's leaves: the same recursions as
    :class:`MerkleTree`, reading leaves and stored subtrees, never holding
    them all."""

    __slots__ = ("_index",)

    def __init__(self, index: _Index) -> None:
        super().__init__()
        self._index = index

    def __len__(self) -> int:
        return self._index.count

    def append(self, leaf: bytes) -> int:  # pragma: no cover - guarded by design
        raise TypeError("a stored tree grows through its index")

    def leaf(self, index: int) -> bytes:
        return self._index.leaf(index)

    def forget(self) -> None:
        """Drop the subtrees remembered in memory (the index was rebuilt)."""
        self._cache.clear()

    def _size(self, size: int | None) -> int:
        n = len(self)
        if size is None:
            return n
        if not 0 <= size <= n:
            raise ValueError(f"the tree has {n} leaves, not {size}")
        return size

    def _hash(self, start: int, n: int) -> bytes:
        if n == 1:
            return self._index.leaf(start)
        if n & (n - 1) == 0:
            level = n.bit_length() - 1
            if level < BLOCK:
                return _perfect_root(self._index.leaves(start, start + n))
            cached = self._cache.get((start, n))
            if cached is None:
                cached = self._index.node(level, start)
                if cached is None:  # pragma: no cover - the index stores every one it completes
                    half = n // 2
                    cached = node_hash(self._hash(start, half), self._hash(start + half, half))
                self._cache[(start, n)] = cached
            return cached
        k = _split(n)
        return node_hash(self._hash(start, k), self._hash(start + k, n - k))


class FileLeaves:
    """The receipts of a durable log: its file, and the index of it."""

    __slots__ = ("_fsync", "_index", "_path", "_reader", "tree")

    def __init__(self, path: Path, *, fsync: bool) -> None:
        self._path = path
        self._fsync = fsync
        self._index = _Index(path.with_name(path.name + ".index"))
        self._reader: BinaryIO | None = None
        self.tree = _IndexedTree(self._index)

    def __len__(self) -> int:
        return self._index.count

    @property
    def end(self) -> int:
        """The byte just past the last indexed line."""
        return self._index.end

    def trustworthy(self, size: int) -> bool:
        """Whether the index describes the first lines of a file of ``size``
        bytes: it ends within the file; the file was not rewritten in place
        since the index recorded it (the same size, but modified); and its
        last indexed line is the receipt recorded there. A file that grew was
        appended to (a crash before the index caught up): the lines after the
        index are checked and indexed."""
        if self._index.end > size:
            return False
        recorded = self._index.file_state()
        if recorded is not None:
            current = self._state()
            if current[0] == recorded[0] and current != recorded:
                return False
        if self._index.count == 0:
            return True
        try:
            offset, length, leaf = self._index.locate(self._index.count - 1)
        except IndexError:  # pragma: no cover - count says it is there
            return False
        return leaf_hash(self._read(offset, length)) == leaf

    def reset(self) -> None:
        self._index.reset()
        self.tree.forget()

    def get(self, index: int) -> LogDocument:
        """The receipt at ``index``, read from the file and checked against the
        leaf hash the index recorded for it.

        :raises IndexError: If there is no receipt at ``index``.
        :raises ReceiptLogError: If its line is not what was appended there.
        """
        if index < 0:
            raise IndexError(f"the log has no receipt {index}")
        offset, length, leaf = self._index.locate(index)
        line = self._read(offset, length)
        if leaf_hash(line) != leaf:
            raise ReceiptLogError(
                f"{self._path} line {index + 1} is not the receipt the log appended there: "
                f"the log was edited"
            )
        return _parse(self._path, index + 1, line)

    def all(self) -> tuple[LogDocument, ...]:
        recorded = self._index.leaves(0, self._index.count)
        found: list[LogDocument] = []
        for number, (_, line) in enumerate(lines_from(self._path, 0, self._index.end), start=1):
            if number > len(recorded) or leaf_hash(line) != recorded[number - 1]:
                raise ReceiptLogError(
                    f"{self._path} line {number} is not the receipt the log appended there: "
                    f"the log was edited"
                )
            found.append(_parse(self._path, number, line))
        if len(found) != len(recorded):
            raise ReceiptLogError(f"{self._path} is shorter than its index: the log was edited")
        return tuple(found)

    def index_of(self, receipt_id: str) -> int | None:
        return self._index.index_of(receipt_id)

    def extend(self, receipts: Sequence[LogDocument]) -> None:
        """Append ``receipts`` to the file (durable once this returns or raises
        :class:`IndexWriteError`), then record them in the index."""
        lines = [receipt.canonical() for receipt in receipts]
        offset = write_lines(self._path, lines, fsync=self._fsync)
        state = self._state()
        rows = []
        index = self._index.count
        for receipt, line in zip(receipts, lines, strict=True):
            rows.append((index, receipt.receipt_id, offset, len(line), leaf_hash(line)))
            offset += len(line) + 1
            index += 1
        try:
            self._index.add(rows, state)
        except sqlite3.Error as exc:
            raise IndexWriteError(str(exc)) from exc

    def adopt(self, found: Sequence[tuple[int, bytes, LogDocument]], *, last: bool) -> None:
        """Record receipts already in the file, ``(offset, line, receipt)``;
        with ``last``, the file as it now stands, too."""
        index = self._index.count
        rows = [
            (index + i, receipt.receipt_id, offset, len(line), leaf_hash(line))
            for i, (offset, line, receipt) in enumerate(found)
        ]
        self._index.add(rows, self._state() if last else None)

    def _state(self) -> tuple[int, int]:
        """The file's size and modification time: ``(0, 0)`` before it exists."""
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            return 0, 0
        return stat.st_size, stat.st_mtime_ns

    def close(self) -> None:
        reader, self._reader = self._reader, None
        if reader is not None:
            reader.close()
        self._index.close()

    def _read(self, offset: int, length: int) -> bytes:
        if self._reader is None:
            self._reader = self._path.open("rb")
        self._reader.seek(offset)
        return self._reader.read(length)
