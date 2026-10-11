"""What a store implementer needs: the durability seam, and what crosses it.

A governor writes through a :class:`PersistenceStore` (or, shared by a fleet, a
:class:`SharedStore`, whose :class:`WriterSession` holds the fleet's writer
lock); each operation is one :class:`WriteBatch`, applied all or nothing. A
store answers opens with a :class:`StoreImage`, catch-ups with a
:class:`StoreDelta`, and keeps checkpoint :class:`Snapshot` rows, auditors'
:class:`AuditMark` rows and the :class:`IdempotencyRecord` of each call made
under a key. ``agentgov.storage.SqliteStore`` and
``agentgov.postgres.PostgresStore`` are the two this package ships.

Users of the governor need none of this: :mod:`agentgov` is their API.
"""

from __future__ import annotations

from agentgov.core import IdempotencyRecord, WriteBatch
from agentgov.storage import (
    AuditMark,
    JoinableStore,
    PersistedAuthorization,
    PersistedNode,
    PersistenceStore,
    SharedStore,
    Snapshot,
    StoreDelta,
    StoreImage,
    WriterSession,
)

__all__ = [
    "AuditMark",
    "IdempotencyRecord",
    "JoinableStore",
    "PersistedAuthorization",
    "PersistedNode",
    "PersistenceStore",
    "SharedStore",
    "Snapshot",
    "StoreDelta",
    "StoreImage",
    "WriteBatch",
    "WriterSession",
]
