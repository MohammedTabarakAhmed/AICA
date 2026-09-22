"""Database tools (DB-001..DB-007).

The tools expose exactly the shape the BRD asks for: inspect an authorized schema, generate
and run dialect-correct SQL, explain a plan, automate read-only queries, protect writes and
destructive statements behind approval, propose migrations, and audit all of it.

Three layered controls, so no single mistake is enough to damage a database:

1. **Configuration** decides which databases exist. A tool call names a connection; it can
   never supply a DSN (DB-001).
2. **The connection** refuses non-read statements when it is read-only - at the driver level
   as well as by classification (DB-004, DB-005).
3. **Approval** gates writes (``database_write``), destructive statements (``destructive``)
   and anything against a production-classified connection (``production``) (DB-005, SAFE-001).

Every call is audited with the statement and its classification, never with row values
(DB-007, SAFE-006).
"""

from __future__ import annotations

from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aica.audit import EventCategory, Outcome
from aica.database.connections import (
    Connection,
    ConnectionConfig,
    DatabaseError,
    QueryResult,
    ensure_read,
    load_databases,
)
from aica.database.sql import SqlError, StatementClass, classify
from aica.policy.models import ActionCategory
from aica.safety.redaction import redact
from aica.tools.base import Tool, ToolContext, ToolError, ToolResult

MAX_SQL_CHARS = 20_000


def _config(ctx: ToolContext, name: str | None) -> ConnectionConfig:
    try:
        return load_databases(getattr(ctx, "databases_file", None)).get(name)
    except DatabaseError as exc:
        raise ToolError(str(exc)) from exc


def _connect(ctx: ToolContext, config: ConnectionConfig) -> Connection:
    return Connection(config, workspace_root=ctx.workspace.root)


def _record(
    ctx: ToolContext,
    action: str,
    config: ConnectionConfig,
    *,
    ok: bool = True,
    **details: object,
) -> None:
    """DB-007: the statement and its classification are audited; row values never are."""
    ctx.audit.record(
        category=EventCategory.DATABASE,
        action=action,
        outcome=Outcome.SUCCESS if ok else Outcome.FAILURE,
        tool="database",
        details={
            "connection": config.name,
            "dialect": config.dialect,
            "database": config.name,
            "read_only": config.read_only,
            **details,
        },
        session_id=ctx.session_id,
    )


def _gate(ctx: ToolContext, tool: str, config: ConnectionConfig, sql: str) -> StatementClass:
    """Apply the approval gates a statement needs before it runs (DB-005)."""
    classification = classify(sql)
    categories: list[ActionCategory] = []
    if classification.statement_class is StatementClass.DESTRUCTIVE:
        categories += [ActionCategory.DESTRUCTIVE, ActionCategory.DATABASE_WRITE]
    elif classification.statement_class in {
        StatementClass.WRITE,
        StatementClass.DDL,
        StatementClass.ADMIN,
    }:
        categories.append(ActionCategory.DATABASE_WRITE)
    elif classification.statement_class is StatementClass.UNKNOWN:
        # Never run something we could not classify without a human looking at it.
        categories.append(ActionCategory.DATABASE_WRITE)
    if config.environment == "production":
        categories.append(ActionCategory.PRODUCTION)
    if categories:
        ctx.require_approval(
            tool,
            f"{classification.statement_class.value} statement on {config.name}: "
            f"{classification.statement}"[:500],
            categories,
            connection=config.name,
            statement=redact(classification.statement).text[:2000],
            reason=classification.reason,
        )
    return classification.statement_class


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connection: str | None = Field(
        default=None, description="configured connection name; omitted uses the default"
    )


# ------------------------------------------------------------------ DB-001


class DatabaseList(Tool):
    name: ClassVar[str] = "db.connections"
    description: ClassVar[str] = "List the configured, approved database connections."

    class Args(BaseModel):
        model_config = ConfigDict(extra="forbid")

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        config = load_databases(getattr(ctx, "databases_file", None))
        if not config.connections:
            return ToolResult(
                output="(no databases configured; add them to config/databases.toml)",
                data={"connections": []},
            )
        lines = [
            f"{'*' if c.name == config.default else ' '} {c.name}  [{c.dialect}] "
            f"{'read-only' if c.read_only else 'WRITABLE'}  env={c.environment}"
            f"{'' if c.enabled else '  (disabled)'}"
            + (f"  - {c.description}" if c.description else "")
            for c in config.connections
        ]
        return ToolResult(
            output="\n".join(lines),
            data={
                "connections": [
                    {
                        "name": c.name,
                        "dialect": c.dialect,
                        "read_only": c.read_only,
                        "environment": c.environment,
                        "enabled": c.enabled,
                    }
                    for c in config.connections
                ],
                "default": config.default,
            },
        )


class DatabaseSchema(Tool):
    name: ClassVar[str] = "db.schema"
    description: ClassVar[str] = (
        "Inspect an authorized database schema: list tables, or describe one table's "
        "columns, types, nullability, defaults, primary keys and indexes."
    )

    class Args(_Args):
        table: str | None = Field(default=None, max_length=128)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _config(ctx, args.connection)
        if config.environment == "production":
            ctx.require_approval(
                self.name,
                f"inspect the schema of production database {config.name}",
                [ActionCategory.PRODUCTION],
                connection=config.name,
            )
        with _connect(ctx, config) as connection:
            dialect = connection.dialect
            if args.table is None:
                result = connection.execute(dialect.list_tables())
                _record(ctx, "schema: list tables", config, tables=result.row_count)
                return ToolResult(
                    output=result.render(),
                    data={
                        "connection": config.name,
                        "dialect": config.dialect,
                        "tables": [dict(zip(result.columns, r, strict=True)) for r in result.rows],
                    },
                )
            columns_sql, _ = dialect.describe_table()
            columns = connection.execute(columns_sql, [args.table])
            if not columns.rows:
                raise ToolError(f"table {args.table!r} not found in {config.name}")
            indexes_sql, _ = dialect.list_indexes()
            try:
                indexes = connection.execute(indexes_sql, [args.table])
            except DatabaseError:
                indexes = QueryResult([], [], 0, False, 0, StatementClass.READ)
            _record(ctx, f"schema: describe {args.table}", config, columns=columns.row_count)
            output = f"{config.name}.{args.table}\n{columns.render()}"
            if indexes.rows:
                output += f"\n\nindexes:\n{indexes.render()}"
            return ToolResult(
                output=output,
                data={
                    "connection": config.name,
                    "table": args.table,
                    "columns": [dict(zip(columns.columns, r, strict=True)) for r in columns.rows],
                    "indexes": [dict(zip(indexes.columns, r, strict=True)) for r in indexes.rows],
                },
            )


# ------------------------------------------------------------------ DB-004


class DatabaseQuery(Tool):
    name: ClassVar[str] = "db.query"
    description: ClassVar[str] = (
        "Run a read-only SQL query and return the rows. Refuses anything that is not a read; "
        "use db.execute for changes. Parameters are bound, never interpolated."
    )

    class Args(_Args):
        sql: str = Field(min_length=1, max_length=MAX_SQL_CHARS)
        parameters: list[Any] = Field(default_factory=list)
        max_rows: int | None = Field(default=None, ge=1, le=100_000)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _config(ctx, args.connection)
        try:
            ensure_read(args.sql)
        except SqlError as exc:
            raise ToolError(str(exc)) from exc
        if config.environment == "production":
            ctx.require_approval(
                self.name,
                f"query production database {config.name}",
                [ActionCategory.PRODUCTION],
                connection=config.name,
                statement=redact(args.sql).text[:2000],
            )
        with _connect(ctx, config) as connection:
            try:
                result = connection.execute(args.sql, args.parameters, max_rows=args.max_rows)
            except DatabaseError as exc:
                _record(ctx, "query failed", config, ok=False, error=str(exc)[:500])
                raise ToolError(str(exc)) from exc
        _record(
            ctx,
            "query",
            config,
            statement=redact(args.sql).text[:2000],
            rows=result.row_count,
            duration_ms=result.duration_ms,
        )
        return ToolResult(
            output=result.render(),
            data={
                "connection": config.name,
                "columns": result.columns,
                "rows": [list(r) for r in result.rows],
                "row_count": result.row_count,
                "truncated": result.truncated,
                "duration_ms": result.duration_ms,
                "notes": result.notes,
            },
        )


# ------------------------------------------------------------------ DB-003


class DatabaseExplain(Tool):
    name: ClassVar[str] = "db.explain"
    description: ClassVar[str] = (
        "Show the query plan for a statement, in the connection's own dialect. "
        "ANALYZE actually executes the statement and is only allowed for reads."
    )

    class Args(_Args):
        sql: str = Field(min_length=1, max_length=MAX_SQL_CHARS)
        parameters: list[Any] = Field(default_factory=list)
        analyze: bool = False

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _config(ctx, args.connection)
        try:
            classification = classify(args.sql)
        except SqlError as exc:
            raise ToolError(str(exc)) from exc
        if args.analyze and not classification.is_read:
            raise ToolError(
                "EXPLAIN ANALYZE executes the statement; it is refused for a "
                f"{classification.statement_class.value} statement. Explain it without ANALYZE."
            )
        with _connect(ctx, config) as connection:
            plan_sql = connection.dialect.explain(args.sql, analyze=args.analyze)
            try:
                result = connection.execute(plan_sql, args.parameters)
            except DatabaseError as exc:
                raise ToolError(str(exc)) from exc
        _record(
            ctx,
            "explain",
            config,
            statement=redact(args.sql).text[:2000],
            analyze=args.analyze,
        )
        return ToolResult(
            output=result.render(max_width=120),
            data={
                "connection": config.name,
                "plan": ["  ".join(str(v) for v in row) for row in result.rows],
                "statement_class": classification.statement_class.value,
                "dialect": config.dialect,
            },
        )


# ------------------------------------------------------------------ DB-005


class DatabaseExecute(Tool):
    name: ClassVar[str] = "db.execute"
    description: ClassVar[str] = (
        "Run a statement that changes data or schema. Requires a writable connection and "
        "approval; destructive statements (DROP, TRUNCATE, unqualified DELETE/UPDATE) "
        "additionally require destructive approval."
    )

    class Args(_Args):
        sql: str = Field(min_length=1, max_length=MAX_SQL_CHARS)
        parameters: list[Any] = Field(default_factory=list)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _config(ctx, args.connection)
        if config.read_only:
            raise PermissionError(
                f"connection {config.name!r} is configured read-only; change "
                "config/databases.toml if writes are intended (DB-005)"
            )
        try:
            statement_class = _gate(ctx, self.name, config, args.sql)
        except SqlError as exc:
            raise ToolError(str(exc)) from exc
        with _connect(ctx, config) as connection:
            try:
                result = connection.execute(args.sql, args.parameters)
            except DatabaseError as exc:
                _record(ctx, "execute failed", config, ok=False, error=str(exc)[:500])
                raise ToolError(str(exc)) from exc
        _record(
            ctx,
            f"execute ({statement_class.value})",
            config,
            statement=redact(args.sql).text[:2000],
            rows_affected=result.row_count,
        )
        return ToolResult(
            output=result.render(),
            data={
                "connection": config.name,
                "statement_class": statement_class.value,
                "row_count": result.row_count,
                "columns": result.columns,
                "rows": [list(r) for r in result.rows],
                "duration_ms": result.duration_ms,
            },
        )


DATABASE_TOOLS: list[Tool] = [
    DatabaseList(),
    DatabaseSchema(),
    DatabaseQuery(),
    DatabaseExplain(),
    DatabaseExecute(),
]
