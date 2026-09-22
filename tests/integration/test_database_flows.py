"""Database tools end to end over a real database (TEST-003, DB-001..DB-007).

A real SQLite file with a real schema and real rows. The agent loop drives it through the
ordinary tool registry, so the same guards apply as anywhere else: a read-only connection
cannot be written to, a destructive statement needs approval, and a migration is proposed
rather than applied.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.agent.loop import AgentLoop
from aica.approvals import AllowAllApprover, DenyAllApprover
from aica.audit import AuditLog, EventCategory, InMemoryAuditSink
from aica.database.migrations import generate_migration
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.tools import ToolContext, default_registry
from aica.workspace import WorkspaceGuard

pytestmark = pytest.mark.integration

SCHEMA = """
CREATE TABLE customers (
    id INTEGER PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    name TEXT
);
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    total_cents INTEGER NOT NULL,
    status TEXT NOT NULL
);
CREATE INDEX orders_customer ON orders(customer_id);
INSERT INTO customers (id, email, name) VALUES
    (1, 'ada@example.com', 'Ada'), (2, 'grace@example.com', 'Grace');
INSERT INTO orders (id, customer_id, total_cents, status) VALUES
    (1, 1, 2500, 'shipped'), (2, 1, 900, 'pending'), (3, 2, 15000, 'shipped');
"""


@pytest.fixture
def project(tmp_path: Path) -> Iterator[Path]:
    connection = sqlite3.connect(tmp_path / "app.sqlite")
    connection.executescript(SCHEMA)
    connection.commit()
    connection.close()
    (tmp_path / "databases.toml").write_text(
        'default = "app"\n\n'
        "[[connections]]\n"
        'name = "app"\n'
        'dialect = "sqlite"\n'
        'target = "app.sqlite"\n'
        "read_only = true\n"
        "max_rows = 100\n"
        'environment = "development"\n\n'
        "[[connections]]\n"
        'name = "app-write"\n'
        'dialect = "sqlite"\n'
        'target = "app.sqlite"\n'
        "read_only = false\n"
        'environment = "development"\n',
        encoding="utf-8",
    )
    yield tmp_path


def _ctx(root: Path, approve: bool = True) -> ToolContext:
    policy = Policy()
    ctx = ToolContext(
        workspace=WorkspaceGuard(root, policy.autonomy.allowed_directories),
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="db-integration", session_id="db-1"),
        approver=AllowAllApprover() if approve else DenyAllApprover(),
    )
    ctx.databases_file = str(root / "databases.toml")
    return ctx


def test_inspect_then_query_a_real_database(project: Path) -> None:
    """DB-001 + DB-002 + DB-004: discover the schema, then query it correctly."""
    ctx = _ctx(project)
    registry = default_registry()

    tables = registry.call("db.schema", {}, ctx)
    assert {t["table_name"] for t in tables.data["tables"]} == {"customers", "orders"}

    orders = registry.call("db.schema", {"table": "orders"}, ctx)
    columns = [c["column_name"] for c in orders.data["columns"]]
    assert columns == ["id", "customer_id", "total_cents", "status"]

    # A real join across the two tables the schema just described.
    result = registry.call(
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
    assert result.data["rows"] == [["Grace", 1, 15000], ["Ada", 2, 3400]]


def test_plan_shows_the_index_being_used(project: Path) -> None:
    """DB-003: a real query plan from the real database."""
    result = default_registry().call(
        "db.explain",
        {"sql": "SELECT * FROM orders WHERE customer_id = 1"},
        _ctx(project),
    )
    assert any("orders_customer" in line for line in result.data["plan"])


def test_read_only_connection_cannot_change_data(project: Path) -> None:
    """DB-005: the read-only connection refuses, and the data is provably untouched."""
    ctx = _ctx(project)
    registry = default_registry()
    with pytest.raises(PermissionError, match="read-only"):
        registry.call("db.execute", {"sql": "DELETE FROM orders WHERE id = 1"}, ctx)

    remaining = registry.call("db.query", {"sql": "SELECT count(*) FROM orders"}, ctx)
    assert remaining.data["rows"][0][0] == 3


def test_destructive_statement_needs_approval_and_leaves_data_intact(project: Path) -> None:
    ctx = _ctx(project, approve=False)
    registry = default_registry()
    with pytest.raises(Exception, match="approval|Approval"):
        registry.call("db.execute", {"connection": "app-write", "sql": "DROP TABLE orders"}, ctx)
    # Verified straight from sqlite, not through the tool that just refused.
    connection = sqlite3.connect(project / "app.sqlite")
    try:
        assert connection.execute("SELECT count(*) FROM orders").fetchone()[0] == 3
    finally:
        connection.close()


def test_approved_write_changes_the_database_for_real(project: Path) -> None:
    ctx = _ctx(project)
    result = default_registry().call(
        "db.execute",
        {
            "connection": "app-write",
            "sql": "UPDATE orders SET status = ? WHERE id = ?",
            "parameters": ["cancelled", 2],
        },
        ctx,
    )
    assert result.data["row_count"] == 1
    connection = sqlite3.connect(project / "app.sqlite")
    try:
        assert (
            connection.execute("SELECT status FROM orders WHERE id=2").fetchone()[0] == "cancelled"
        )
    finally:
        connection.close()


def test_migration_is_proposed_reviewed_and_applied_only_on_purpose(project: Path) -> None:
    """DB-006: generation never applies; applying is a separate approved statement."""
    ctx = _ctx(project)
    registry = default_registry()
    schema_text = registry.call("db.schema", {"table": "orders"}, ctx).output

    migration = generate_migration(
        ScriptedAdapter(
            [
                "-- up\nALTER TABLE orders ADD COLUMN note TEXT;\n"
                "-- down\nALTER TABLE orders DROP COLUMN note;\n"
            ]
        ),
        "add a free-text note to orders",
        "sqlite",
        schema=schema_text,
    )
    assert "No destructive statements" in migration.review()

    # Nothing has changed yet.
    before = registry.call("db.schema", {"table": "orders"}, ctx)
    assert "note" not in [c["column_name"] for c in before.data["columns"]]

    for statement in migration.up:
        registry.call("db.execute", {"connection": "app-write", "sql": statement}, ctx)

    after = registry.call("db.schema", {"table": "orders"}, ctx)
    assert "note" in [c["column_name"] for c in after.data["columns"]]


def test_agent_can_answer_a_question_from_the_database(project: Path) -> None:
    """The database tools are ordinary tools, so the agent can plan with them."""
    ctx = _ctx(project)
    plan = json.dumps(
        {
            "summary": "find the highest-value customer",
            "steps": [
                {"intent": "look at the schema", "tool": "db.schema", "arguments": {}},
                {
                    "intent": "total per customer",
                    "tool": "db.query",
                    "arguments": {
                        "sql": (
                            "SELECT c.name, sum(o.total_cents) AS cents FROM customers c "
                            "JOIN orders o ON o.customer_id = c.id GROUP BY c.name "
                            "ORDER BY cents DESC"
                        )
                    },
                },
            ],
            "verification": [],
        }
    )
    loop = AgentLoop(ScriptedAdapter([plan]), default_registry())
    report = loop.run("who is our highest-value customer?", ctx)

    assert report.steps_used == 2
    assert loop.state is not None
    assert "Grace" in loop.state.plan.steps[1].result


def test_database_activity_is_audited_without_leaking_rows(project: Path) -> None:
    """DB-007: the trail records the statement, never the customer data it returned."""
    ctx = _ctx(project)
    default_registry().call("db.query", {"sql": "SELECT email FROM customers ORDER BY id"}, ctx)
    events = [e for e in ctx.audit.sink.events if e.category is EventCategory.DATABASE]  # type: ignore[attr-defined]
    assert events
    trail = json.dumps([e.model_dump(mode="json") for e in ctx.audit.sink.events])  # type: ignore[attr-defined]
    assert "SELECT email FROM customers" in trail
    assert "ada@example.com" not in trail
    assert "grace@example.com" not in trail
