"""PostgreSQL verified against a real server (DB-001..DB-007 on the Postgres dialect).

The rest of the database suite uses SQLite, which exercises the whole execution path for real
but cannot prove the PostgreSQL dialect: `information_schema` queries, `%s` placeholders and
`EXPLAIN (FORMAT TEXT)` are only correct if a real server accepts them.

This module fills that gap and is **skipped unless a server is configured**, so the suite still
runs on a machine with no database:

    docker run -d --name aica-pg -e POSTGRES_PASSWORD=... -e POSTGRES_DB=aica_test \\
        -p 55433:5432 postgres:17-alpine
    set AICA_TEST_POSTGRES_DSN=postgresql://postgres@127.0.0.1:55433/aica_test
    set AICA_TEST_POSTGRES_PASSWORD=...

The DSN carries no password, exactly as a configured connection may not (SAFE-006); the
password comes from its own environment variable.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.approvals import AllowAllApprover, DenyAllApprover
from aica.audit import AuditLog, EventCategory, InMemoryAuditSink
from aica.database.connections import Connection, ConnectionConfig, ReadOnlyViolation
from aica.policy import Policy
from aica.policy.models import ActionCategory
from aica.tools import ToolContext, default_registry
from aica.workspace import WorkspaceGuard

pytestmark = pytest.mark.integration

DSN = os.environ.get("AICA_TEST_POSTGRES_DSN")
PASSWORD_ENV = "AICA_TEST_POSTGRES_PASSWORD"

pytest.importorskip("psycopg", reason="PostgreSQL verification needs the postgres extra")
if not DSN:  # pragma: no cover - the skip is the point on a machine with no server
    pytest.skip(
        "set AICA_TEST_POSTGRES_DSN (and AICA_TEST_POSTGRES_PASSWORD) to verify PostgreSQL",
        allow_module_level=True,
    )

SCHEMA = """
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS customers;
CREATE TABLE customers (
    id integer PRIMARY KEY,
    email text NOT NULL UNIQUE,
    name text
);
CREATE TABLE orders (
    id integer PRIMARY KEY,
    customer_id integer NOT NULL REFERENCES customers(id),
    total_cents integer NOT NULL,
    status text NOT NULL
);
CREATE INDEX orders_customer ON orders(customer_id);
INSERT INTO customers (id, email, name) VALUES
    (1, 'ada@example.com', 'Ada'), (2, 'grace@example.com', 'Grace');
INSERT INTO orders (id, customer_id, total_cents, status) VALUES
    (1, 1, 2500, 'shipped'), (2, 1, 900, 'pending'), (3, 2, 15000, 'shipped');
"""


@pytest.fixture(scope="module", autouse=True)
def schema() -> Iterator[None]:
    """Create the schema with the driver directly, so the tools are tested against it."""
    import psycopg

    with psycopg.connect(DSN, password=os.environ.get(PASSWORD_ENV), autocommit=True) as conn:
        conn.execute(SCHEMA)
    yield


def config(*, read_only: bool = True, environment: str = "development") -> ConnectionConfig:
    return ConnectionConfig(
        name="pg",
        dialect="postgresql",
        target=DSN or "",
        password_env=PASSWORD_ENV,
        read_only=read_only,
        environment=environment,
        max_rows=100,
    )


@pytest.fixture
def ctx(tmp_path: Path) -> ToolContext:
    policy = Policy()
    (tmp_path / "databases.toml").write_text(
        'default = "pg"\n\n'
        "[[connections]]\n"
        'name = "pg"\n'
        'dialect = "postgresql"\n'
        f'target = "{DSN}"\n'
        f'password_env = "{PASSWORD_ENV}"\n'
        "read_only = true\n"
        "max_rows = 100\n\n"
        "[[connections]]\n"
        'name = "pg-write"\n'
        'dialect = "postgresql"\n'
        f'target = "{DSN}"\n'
        f'password_env = "{PASSWORD_ENV}"\n'
        "read_only = false\n",
        encoding="utf-8",
    )
    context = ToolContext(
        workspace=WorkspaceGuard(tmp_path, policy.autonomy.allowed_directories),
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="pg-integration", session_id="pg-1"),
        approver=AllowAllApprover(),
    )
    context.databases_file = str(tmp_path / "databases.toml")
    return context


# ---------------------------------------------------------------- DB-001/002


def test_information_schema_queries_work_on_a_real_server(ctx: ToolContext) -> None:
    """DB-001/002: the PostgreSQL dialect's own statements, accepted by PostgreSQL."""
    tables = default_registry().call("db.schema", {}, ctx)
    names = {t["table_name"] for t in tables.data["tables"]}
    assert {"customers", "orders"} <= names
    assert all(t["table_schema"] == "public" for t in tables.data["tables"])


def test_table_description_and_indexes(ctx: ToolContext) -> None:
    result = default_registry().call("db.schema", {"table": "orders"}, ctx)
    columns = {c["column_name"]: c for c in result.data["columns"]}
    assert set(columns) == {"id", "customer_id", "total_cents", "status"}
    assert columns["customer_id"]["is_nullable"] == "NO"
    assert columns["id"]["primary_key"] == 1  # the correlated subquery really resolves
    assert any("orders_customer" in str(i) for i in result.data["indexes"])


def test_placeholder_style_is_the_postgres_one(ctx: ToolContext) -> None:
    """DB-002: `%s` binding, which would be a syntax error in the SQLite dialect."""
    result = default_registry().call(
        "db.query",
        {
            "sql": "SELECT count(*) FROM orders WHERE customer_id = %s AND status = %s",
            "parameters": [1, "shipped"],
        },
        ctx,
    )
    assert result.data["rows"][0][0] == 1


def test_a_real_join_and_aggregate(ctx: ToolContext) -> None:
    result = default_registry().call(
        "db.query",
        {
            "sql": (
                "SELECT c.name, count(o.id) AS orders, sum(o.total_cents) AS cents "
                "FROM customers c JOIN orders o ON o.customer_id = c.id "
                "GROUP BY c.name ORDER BY cents DESC"
            )
        },
        ctx,
    )
    assert [row[0] for row in result.data["rows"]] == ["Grace", "Ada"]


# ---------------------------------------------------------------- DB-003


def test_explain_returns_a_postgres_plan(ctx: ToolContext) -> None:
    result = default_registry().call(
        "db.explain", {"sql": "SELECT * FROM orders WHERE customer_id = 1"}, ctx
    )
    plan = " ".join(result.data["plan"]).lower()
    assert "scan" in plan  # a real PostgreSQL plan node
    assert result.data["dialect"] == "postgresql"


def test_explain_analyze_runs_for_a_read(ctx: ToolContext) -> None:
    result = default_registry().call(
        "db.explain", {"sql": "SELECT count(*) FROM orders", "analyze": True}, ctx
    )
    assert any("actual time" in line.lower() for line in result.data["plan"])


# ---------------------------------------------------------------- DB-005


def test_read_only_is_enforced_by_the_server_not_just_the_classifier(tmp_path: Path) -> None:
    """The session is set read-only server-side, so a write fails even past the classifier."""
    import psycopg

    with Connection(config(read_only=True)) as connection:
        with pytest.raises(ReadOnlyViolation):
            connection.execute("DELETE FROM orders WHERE id = 1")
        # Bypassing the classifier entirely still fails: PostgreSQL itself refuses.
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            connection._raw.execute("DELETE FROM orders WHERE id = 1")  # noqa: SLF001


def test_write_requires_approval_and_leaves_data_intact(tmp_path: Path, ctx: ToolContext) -> None:
    denying = ToolContext(
        workspace=ctx.workspace,
        policy=ctx.policy,
        audit=AuditLog(InMemoryAuditSink(), actor="pg-integration"),
        approver=DenyAllApprover(),
    )
    denying.databases_file = ctx.databases_file
    with pytest.raises(Exception, match="approval|Approval") as exc:
        default_registry().call(
            "db.execute", {"connection": "pg-write", "sql": "DELETE FROM orders"}, denying
        )
    assert exc.value is not None

    remaining = default_registry().call("db.query", {"sql": "SELECT count(*) FROM orders"}, ctx)
    assert remaining.data["rows"][0][0] == 3


def test_destructive_statement_needs_destructive_approval(ctx: ToolContext) -> None:
    denying = ToolContext(
        workspace=ctx.workspace,
        policy=ctx.policy,
        audit=AuditLog(InMemoryAuditSink(), actor="pg-integration"),
        approver=DenyAllApprover(),
    )
    denying.databases_file = ctx.databases_file
    from aica.approvals import ApprovalRequired

    with pytest.raises(ApprovalRequired) as exc:
        default_registry().call(
            "db.execute", {"connection": "pg-write", "sql": "DROP TABLE orders"}, denying
        )
    assert ActionCategory.DESTRUCTIVE in exc.value.request.categories
    assert ActionCategory.DATABASE_WRITE in exc.value.request.categories


def test_approved_write_really_changes_postgres(ctx: ToolContext) -> None:
    import psycopg

    result = default_registry().call(
        "db.execute",
        {
            "connection": "pg-write",
            "sql": "UPDATE orders SET status = %s WHERE id = %s",
            "parameters": ["cancelled", 2],
        },
        ctx,
    )
    assert result.data["row_count"] == 1
    # Confirmed with the driver, independently of the tool that made the change.
    with psycopg.connect(DSN, password=os.environ.get(PASSWORD_ENV)) as conn:
        status = conn.execute("SELECT status FROM orders WHERE id = 2").fetchone()
        assert status is not None and status[0] == "cancelled"


def test_statement_timeout_is_applied(tmp_path: Path) -> None:
    """The configured timeout reaches the server, so a runaway query cannot hang the agent."""
    import psycopg

    quick = ConnectionConfig(
        name="pg-quick",
        dialect="postgresql",
        target=DSN or "",
        password_env=PASSWORD_ENV,
        read_only=True,
        statement_timeout_seconds=1.0,
    )
    with Connection(quick) as connection:
        with pytest.raises((psycopg.errors.QueryCanceled, Exception), match="(?i)timeout|cancel"):
            connection.execute("SELECT pg_sleep(5)")


# ---------------------------------------------------------------- DB-007 / SAFE-006


def test_rows_are_not_written_to_the_audit_trail(ctx: ToolContext) -> None:
    default_registry().call("db.query", {"sql": "SELECT email FROM customers"}, ctx)
    events = [e for e in ctx.audit.sink.events if e.category is EventCategory.DATABASE]  # type: ignore[attr-defined]
    assert events
    trail = " ".join(str(e.details) for e in events)
    assert "SELECT email FROM customers" in trail
    assert "ada@example.com" not in trail


def test_the_password_never_appears_in_the_configuration(ctx: ToolContext) -> None:
    """SAFE-006: the DSN holds no password; it is read from the named environment variable."""
    text = Path(str(ctx.databases_file)).read_text(encoding="utf-8")
    password = os.environ.get(PASSWORD_ENV, "")
    assert password, "the test password must come from the environment"
    assert password not in text
    assert PASSWORD_ENV in text


def test_a_missing_password_variable_fails_clearly(monkeypatch: pytest.MonkeyPatch) -> None:
    from aica.database.connections import DatabaseError

    monkeypatch.delenv(PASSWORD_ENV, raising=False)
    monkeypatch.setenv("PGPASSWORD", "")  # do not let libpq fall back to another source
    with pytest.raises(DatabaseError, match="is not set"):
        Connection(config()).open()
