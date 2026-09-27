"""Shared fixtures: a real PostgreSQL for the shared-ledger tests.

PostgreSQL tests run against a live server named by
``AGENTGOV_TEST_POSTGRES_DSN`` (a role that may create databases and roles).
Each test gets a database of its own, created from ``template0`` and dropped
afterwards. Without the variable those tests are skipped, unless
``AGENTGOV_REQUIRE_POSTGRES=1``, which turns the skip into a failure: CI sets
it, so a misconfigured service cannot pass the suite by skipping it.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

POSTGRES_DSN_VAR = "AGENTGOV_TEST_POSTGRES_DSN"
REQUIRE_POSTGRES_VAR = "AGENTGOV_REQUIRE_POSTGRES"


@pytest.fixture(scope="session")
def pg_admin_dsn() -> str:
    """The server's administrative DSN."""
    dsn = os.environ.get(POSTGRES_DSN_VAR, "")
    if not dsn:
        if os.environ.get(REQUIRE_POSTGRES_VAR) == "1":
            pytest.fail(f"{REQUIRE_POSTGRES_VAR}=1 but {POSTGRES_DSN_VAR} is not set")
        pytest.skip(f"set {POSTGRES_DSN_VAR} to run the PostgreSQL integration tests")
    return dsn


@pytest.fixture
def pg_dsn(pg_admin_dsn: str) -> Iterator[str]:
    """A fresh, empty PostgreSQL database; yields its DSN."""
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    name = f"agentgov_t_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(pg_admin_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(name)))
    try:
        yield make_conninfo(pg_admin_dsn, dbname=name)
    finally:
        with psycopg.connect(pg_admin_dsn, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )
