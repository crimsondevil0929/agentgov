"""A governor's metrics as OpenTelemetry instruments: ``agentgov[otel]``.

::

    from agentgov.otel import OpenTelemetryMetrics

    gov = BudgetManager.open_postgres(dsn, metrics=OpenTelemetryMetrics())

Each name in :data:`agentgov.metrics.INSTRUMENTS` becomes a histogram, counter
or gauge of the meter, with that unit and description, created when first
reported. ``opentelemetry-api`` is imported only when no meter is given; the
SDK, readers and exporters are the application's to configure.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from agentgov.metrics import INSTRUMENTS

__all__ = ["OpenTelemetryMetrics"]

logger = logging.getLogger("agentgov")


class OpenTelemetryMetrics:
    """:class:`agentgov.metrics.Metrics` reported through an OpenTelemetry meter.

    :param meter: The meter to create instruments on; by default
        ``opentelemetry.metrics.get_meter("agentgov")``.
    :param attributes: Attributes every measurement carries, to tell one
        ledger or one governor from another (``{"ledger": "fleet-eu"}``).
    """

    def __init__(self, meter: Any = None, *, attributes: Mapping[str, str] | None = None) -> None:
        if meter is None:
            from opentelemetry import metrics

            meter = metrics.get_meter("agentgov")
        self._meter = meter
        self._attributes = dict(attributes or {})
        self._instruments: dict[str, Any] = {}

    def _instrument(self, name: str, kind: str) -> Any:
        instrument = self._instruments.get(name)
        if instrument is None:
            known_kind, unit, description = INSTRUMENTS.get(name, (kind, "1", name))
            create = {
                "histogram": self._meter.create_histogram,
                "counter": self._meter.create_counter,
                "gauge": self._meter.create_gauge,
            }[known_kind]
            instrument = create(name, unit=unit, description=description)
            self._instruments[name] = instrument
        return instrument

    def record(self, name: str, value: float) -> None:
        """Record a histogram's measurement."""
        try:
            self._instrument(name, "histogram").record(value, attributes=self._attributes)
        except Exception:  # reporting never fails the governor
            logger.debug("could not record %s", name, exc_info=True)

    def add(self, name: str, value: int = 1) -> None:
        """Add to a counter."""
        try:
            self._instrument(name, "counter").add(value, attributes=self._attributes)
        except Exception:
            logger.debug("could not add to %s", name, exc_info=True)

    def set(self, name: str, value: float) -> None:
        """Set a gauge."""
        try:
            self._instrument(name, "gauge").set(value, attributes=self._attributes)
        except Exception:
            logger.debug("could not set %s", name, exc_info=True)
