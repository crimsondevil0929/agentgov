"""How a governor is doing, reported as it works.

Give a governor a :class:`Metrics` at open (``metrics=`` on
:class:`~agentgov.core.BudgetManager`, :meth:`~agentgov.core.BudgetManager.open_sqlite`
and :meth:`~agentgov.core.BudgetManager.open_postgres`); without one it reports
nowhere, and measures nothing. :class:`agentgov.otel.OpenTelemetryMetrics`
reports to OpenTelemetry (``pip install 'agentgov[otel]'``).

Every measurement has one of these names (kind, unit):

- ``agentgov.lock.wait`` (histogram, s): waiting for the fleet's writer lock,
  with the read that comes with it, on a shared ledger.
- ``agentgov.lock.hold`` (histogram, s): holding it, through the commit.
- ``agentgov.unit.size`` (histogram, calls): mutations one unit of work
  carried (group commit).
- ``agentgov.catch_up.entries`` (histogram, entries): what other governors
  wrote, verified in one catch-up.
- ``agentgov.open.duration`` (histogram, s): opening a governor over a store.
- ``agentgov.verify.duration`` (histogram, s): one ``verify_integrity()``.
- ``agentgov.holds.open`` (gauge, holds): authorizations open, after each
  unit of work.
- ``agentgov.checkpoint.lag`` (gauge, entries): entries past the newest
  checkpoint, after each unit of work; growing past ``checkpoint_every``,
  checkpoints are failing.
- ``agentgov.trips`` (counter, trips): breaker trips this governor wrote.
- ``agentgov.store.errors`` (counter, errors): writes that failed with
  ``StorageError``.
"""

from __future__ import annotations

from typing import Final, Protocol, runtime_checkable

__all__ = ["INSTRUMENTS", "Metrics"]

INSTRUMENTS: Final[dict[str, tuple[str, str, str]]] = {
    "agentgov.lock.wait": (
        "histogram",
        "s",
        "Time waiting for the fleet's writer lock, with the read that comes with it.",
    ),
    "agentgov.lock.hold": ("histogram", "s", "Time holding the fleet's writer lock."),
    "agentgov.unit.size": ("histogram", "{call}", "Mutations one unit of work carried."),
    "agentgov.catch_up.entries": (
        "histogram",
        "{entry}",
        "Entries other governors wrote, verified in one catch-up.",
    ),
    "agentgov.open.duration": ("histogram", "s", "Time opening a governor over a store."),
    "agentgov.verify.duration": ("histogram", "s", "Time spent in one verify_integrity()."),
    "agentgov.holds.open": ("gauge", "{hold}", "Authorizations open."),
    "agentgov.checkpoint.lag": ("gauge", "{entry}", "Entries past the newest checkpoint."),
    "agentgov.trips": ("counter", "{trip}", "Circuit-breaker trips this governor wrote."),
    "agentgov.store.errors": ("counter", "{error}", "Writes that failed with StorageError."),
}
"""Every name a governor reports under: its kind, unit and description."""


@runtime_checkable
class Metrics(Protocol):
    """Where a governor reports. Called from the governor's own threads,
    often with its lock held: each call must be quick, and must not raise
    (a failure to report is not the governor's to handle)."""

    def record(self, name: str, value: float) -> None:
        """One measurement of a histogram."""
        ...

    def add(self, name: str, value: int = 1) -> None:
        """An increment of a counter."""
        ...

    def set(self, name: str, value: float) -> None:
        """The current value of a gauge."""
        ...
