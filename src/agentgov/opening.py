"""Opening a governor from a URL: ``agentgov.open("postgresql://...")``.

One string names any ledger, so configuration needs no code to tell a SQLite
path from a PostgreSQL DSN:

- ``memory:``: a governor with no store (tests and examples);
- ``sqlite:///path/to/ledger.db`` (absolute; ``sqlite:////path`` too),
  ``sqlite:ledger.db`` (relative), or a bare filesystem path;
- ``postgresql://user:password@host:port/database?schema=agentgov`` (or
  ``postgres://``). ``schema``, ``lock_timeout`` and ``idle_timeout`` are read
  from the query and given to :meth:`~agentgov.core.BudgetManager.open_postgres`;
  every other query parameter (``sslmode``, ...) is passed to libpq;
- a libpq ``key=value`` connection string (``host=db dbname=fleet``), passed to
  libpq as it is; give ``schema`` and the timeouts as keyword options. Such a
  string is never taken for a file name.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from agentgov.core import BudgetManager, GovernancePolicy

__all__ = ["open_url", "parse_url"]

_POSTGRES_SCHEMES = ("postgresql", "postgres")
_POSTGRES_OPTIONS: dict[str, type] = {"schema": str, "lock_timeout": float, "idle_timeout": float}
_CONNINFO = re.compile(r"\A\s*[a-z_]+\s*=")
"""A libpq ``key=value`` connection string, as opposed to a URL or a path."""


def parse_url(url: str) -> tuple[str, str, dict[str, Any]]:
    """Split a ledger URL into its kind, its target, and the options it carries.

    :returns: ``("memory", "", {})``, ``("sqlite", path, {})``, or
        ``("postgres", dsn, options)`` with ``schema``, ``lock_timeout`` and
        ``idle_timeout`` taken out of the DSN's query.
    :raises ValueError: On a URL that names no kind of ledger this knows, or
        an option that is not a number where one is needed.
    """
    if url == "memory:":
        return "memory", "", {}
    if _CONNINFO.match(url):
        return "postgres", url, {}
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme in _POSTGRES_SCHEMES:
        options: dict[str, Any] = {}
        passed: list[tuple[str, str]] = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            kind = _POSTGRES_OPTIONS.get(key)
            if kind is None:
                passed.append((key, value))
                continue
            try:
                options[key] = kind(value)
            except ValueError as exc:
                raise ValueError(
                    f"{key}={value!r} in the ledger URL is not a {kind.__name__}"
                ) from exc
        dsn = urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(passed), parts.fragment)
        )
        return "postgres", dsn, options
    if scheme == "sqlite":
        path = url[len("sqlite:") :]
        if path.startswith("//"):
            rest = path[2:]
            if not rest.startswith("/"):
                raise ValueError(
                    f"a SQLite URL is sqlite:///absolute/path or sqlite:relative/path, with "
                    f"no host: {url!r}"
                )
            path = "/" + rest.lstrip("/")
        if not path:
            raise ValueError("a SQLite URL needs a path")
        return "sqlite", path, {}
    if len(scheme) > 1 and parts.netloc:
        raise ValueError(f"{url!r} names no kind of ledger agentgov knows (sqlite:, postgresql:)")
    return "sqlite", url, {}


def open_url(
    url: str,
    *,
    policy: GovernancePolicy | None = None,
    read_only: bool = False,
    repair: bool = False,
    verify: str = "checkpoint",
    auditor: bool | None = None,
    **options: Any,
) -> BudgetManager:
    """Open the governor a URL names. See the module docstring for the forms.

    Keyword options are those of the opener the URL selects
    (:meth:`~agentgov.core.BudgetManager.open_sqlite`,
    :meth:`~agentgov.core.BudgetManager.open_postgres`); one given here wins
    over the same one in the URL.

    :raises ValueError: If the URL names no kind of ledger this knows.
    """
    kind, target, found = parse_url(url)
    if kind == "memory":
        if read_only or options:
            raise ValueError("a memory: governor takes no store options")
        return BudgetManager(policy=policy)
    if kind == "sqlite":
        return BudgetManager.open_sqlite(
            target,
            policy=policy,
            read_only=read_only,
            repair=repair,
            verify=verify,
            auditor=auditor,
            **options,
        )
    return BudgetManager.open_postgres(
        target,
        policy=policy,
        read_only=read_only,
        repair=repair,
        verify=verify,
        auditor=auditor,
        **{**found, **options},
    )
