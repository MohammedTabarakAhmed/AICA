"""SQL statement classification and dialect handling (DB-002, DB-005).

Two separable jobs live here:

* **Classification** decides what a statement *does* before it is allowed to run. It is the
  database counterpart of ``aica.safety.commands``: conservative, pattern-based, and biased
  towards the severe class when a statement matches several. A read-only connection can then
  refuse anything that is not a read, and writes can be routed through the
  ``database_write`` approval gate (DB-004, DB-005).
* **Dialects** supply the statements that differ between engines - listing tables, describing
  a table, reading indexes, explaining a plan - plus the placeholder style for bound
  parameters. This is what makes DB-002 ("queries match the selected dialect") a property of
  the code rather than a hope about the model's output.

Classification is defence in depth, not a SQL parser. The authoritative controls are the
read-only connection flag, the approval gate and the credentials the database itself grants.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class StatementClass(StrEnum):
    READ = "read"  # SELECT, WITH ... SELECT, SHOW, VALUES
    EXPLAIN = "explain"  # a plan request: reads nothing itself
    WRITE = "write"  # INSERT, UPDATE, DELETE, MERGE, UPSERT
    DDL = "ddl"  # CREATE, ALTER, COMMENT, INDEX changes
    DESTRUCTIVE = "destructive"  # DROP, TRUNCATE, DELETE without WHERE
    ADMIN = "admin"  # GRANT, REVOKE, SET ROLE, VACUUM, COPY, ATTACH
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Classification:
    statement_class: StatementClass
    reason: str
    statement: str

    @property
    def is_read(self) -> bool:
        return self.statement_class in {StatementClass.READ, StatementClass.EXPLAIN}

    @property
    def is_destructive(self) -> bool:
        return self.statement_class is StatementClass.DESTRUCTIVE


class SqlError(ValueError):
    """The statement is malformed, empty, or more than one statement."""


_LINE_COMMENT = re.compile(r"--[^\n]*")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_LITERAL = re.compile(r"'(?:''|[^'])*'")

# Ordered most-severe first; the first match wins.
_RULES: list[tuple[StatementClass, str, re.Pattern[str]]] = [
    (
        StatementClass.DESTRUCTIVE,
        "drops a table, database, schema or column",
        re.compile(r"^\s*DROP\s+", re.I),
    ),
    (StatementClass.DESTRUCTIVE, "truncates a table", re.compile(r"^\s*TRUNCATE\b", re.I)),
    (
        StatementClass.DESTRUCTIVE,
        "deletes every row (no WHERE clause)",
        re.compile(r"^\s*DELETE\s+FROM\s+\S+\s*(RETURNING\b.*)?;?\s*$", re.I),
    ),
    (
        StatementClass.DESTRUCTIVE,
        "updates every row (no WHERE clause)",
        re.compile(r"^\s*UPDATE\s+\S+\s+SET\b(?![\s\S]*\bWHERE\b)", re.I),
    ),
    (
        StatementClass.ADMIN,
        "changes privileges or roles",
        re.compile(
            r"^\s*(GRANT|REVOKE|SET\s+ROLE|ALTER\s+(ROLE|USER)|CREATE\s+(ROLE|USER))\b", re.I
        ),
    ),
    (
        StatementClass.ADMIN,
        "administrative or bulk-transfer statement",
        re.compile(
            r"^\s*(VACUUM|ANALYZE|REINDEX|COPY|ATTACH|DETACH|PRAGMA|CLUSTER|CHECKPOINT)\b", re.I
        ),
    ),
    (StatementClass.EXPLAIN, "query plan request", re.compile(r"^\s*EXPLAIN\b", re.I)),
    (
        StatementClass.WRITE,
        "modifies rows",
        re.compile(r"^\s*(INSERT|UPDATE|DELETE|MERGE|REPLACE|UPSERT)\b", re.I),
    ),
    (
        StatementClass.DDL,
        "changes schema",
        re.compile(r"^\s*(CREATE|ALTER|COMMENT\s+ON|RENAME)\b", re.I),
    ),
    (
        StatementClass.READ,
        "reads data",
        re.compile(r"^\s*(SELECT|WITH|SHOW|VALUES|TABLE|DESCRIBE|DESC)\b", re.I),
    ),
]

# A CTE may end in a write: WITH x AS (...) INSERT/UPDATE/DELETE ... must not count as a read.
_CTE_WRITE = re.compile(r"\)\s*(INSERT|UPDATE|DELETE|MERGE)\b", re.I)


def strip_comments(sql: str) -> str:
    """Remove comments so they cannot hide a statement from classification."""
    return _BLOCK_COMMENT.sub(" ", _LINE_COMMENT.sub(" ", sql))


def split_statements(sql: str) -> list[str]:
    """Split on semicolons that are not inside a string literal."""
    cleaned = strip_comments(sql)
    parts: list[str] = []
    buffer: list[str] = []
    in_string = False
    index = 0
    while index < len(cleaned):
        char = cleaned[index]
        if char == "'":
            # '' inside a string is an escaped quote, not a terminator.
            if in_string and index + 1 < len(cleaned) and cleaned[index + 1] == "'":
                buffer.append("''")
                index += 2
                continue
            in_string = not in_string
            buffer.append(char)
        elif char == ";" and not in_string:
            parts.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)
        index += 1
    parts.append("".join(buffer))
    return [p.strip() for p in parts if p.strip()]


def classify(sql: str) -> Classification:
    """Classify a single statement. Raises :class:`SqlError` for empty or multiple statements."""
    statements = split_statements(sql)
    if not statements:
        raise SqlError("empty statement")
    if len(statements) > 1:
        raise SqlError(
            f"{len(statements)} statements in one call; submit them separately so each is "
            "classified and approved on its own"
        )
    statement = statements[0]
    # Blank out string literals so their contents cannot trip a pattern.
    probe = _STRING_LITERAL.sub("''", statement)
    for statement_class, reason, pattern in _RULES:
        if pattern.search(probe):
            if statement_class is StatementClass.READ and _CTE_WRITE.search(probe):
                return Classification(
                    StatementClass.WRITE, "CTE ending in a data change", statement
                )
            return Classification(statement_class, reason, statement)
    return Classification(StatementClass.UNKNOWN, "unrecognised statement", statement)


class Dialect(Protocol):
    """DB-002: the statements and parameter style that differ between engines."""

    name: str
    placeholder: str  # "?" or "%s"

    def quote(self, identifier: str) -> str: ...
    def list_tables(self) -> str: ...
    def describe_table(self) -> tuple[str, int]: ...
    def list_indexes(self) -> tuple[str, int]: ...
    def explain(self, sql: str, analyze: bool = False) -> str: ...
    def limit(self, sql: str, max_rows: int) -> str: ...


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")


def _quote_double(identifier: str) -> str:
    """Quote an identifier for any engine that uses double quotes (both of ours do)."""
    if not identifier or len(identifier) > 128:
        raise SqlError(f"unusable identifier {identifier!r}")
    if _IDENTIFIER.match(identifier):
        return f'"{identifier}"'
    if '"' in identifier or "\x00" in identifier:
        raise SqlError(f"unusable identifier {identifier!r}")
    return '"' + identifier + '"'


class SQLiteDialect:
    name = "sqlite"
    placeholder = "?"

    def quote(self, identifier: str) -> str:
        return _quote_double(identifier)

    def list_tables(self) -> str:
        return (
            "SELECT name AS table_name, type AS object_type, 'main' AS table_schema "
            "FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' "
            "ORDER BY name"
        )

    def describe_table(self) -> tuple[str, int]:
        """Returns (sql, parameter count). SQLite exposes columns through a table function."""
        return (
            "SELECT name AS column_name, type AS data_type, "
            "CASE \"notnull\" WHEN 1 THEN 'NO' ELSE 'YES' END AS is_nullable, "
            "dflt_value AS column_default, pk AS primary_key "
            "FROM pragma_table_info(?) ORDER BY cid",
            1,
        )

    def list_indexes(self) -> tuple[str, int]:
        return (
            'SELECT name AS index_name, "unique" AS is_unique, origin '
            "FROM pragma_index_list(?) ORDER BY seq",
            1,
        )

    def explain(self, sql: str, analyze: bool = False) -> str:
        # SQLite has no EXPLAIN ANALYZE; the query plan is the useful form either way.
        return f"EXPLAIN QUERY PLAN {sql}"

    def limit(self, sql: str, max_rows: int) -> str:
        return sql  # rows are capped while fetching instead, which never rewrites the SQL


class PostgresDialect:
    name = "postgresql"
    placeholder = "%s"

    def quote(self, identifier: str) -> str:
        return _quote_double(identifier)

    def list_tables(self) -> str:
        return (
            "SELECT table_name, "
            "CASE table_type WHEN 'BASE TABLE' THEN 'table' ELSE lower(table_type) END "
            "AS object_type, table_schema "
            "FROM information_schema.tables "
            "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
            "ORDER BY table_schema, table_name"
        )

    def describe_table(self) -> tuple[str, int]:
        return (
            "SELECT column_name, data_type, is_nullable, column_default, "
            "(SELECT count(*) FROM information_schema.key_column_usage k "
            " JOIN information_schema.table_constraints t "
            "   ON t.constraint_name = k.constraint_name "
            " WHERE t.constraint_type = 'PRIMARY KEY' AND k.table_name = c.table_name "
            "   AND k.column_name = c.column_name) AS primary_key "
            "FROM information_schema.columns c WHERE table_name = %s ORDER BY ordinal_position",
            1,
        )

    def list_indexes(self) -> tuple[str, int]:
        return (
            "SELECT indexname AS index_name, indexdef AS definition "
            "FROM pg_indexes WHERE tablename = %s ORDER BY indexname",
            1,
        )

    def explain(self, sql: str, analyze: bool = False) -> str:
        # ANALYZE actually executes the statement, so it is only offered for reads and is
        # gated by the caller (db.explain refuses ANALYZE on a write).
        return f"EXPLAIN (FORMAT TEXT{', ANALYZE true' if analyze else ''}) {sql}"

    def limit(self, sql: str, max_rows: int) -> str:
        return sql


DIALECTS: dict[str, Dialect] = {"sqlite": SQLiteDialect(), "postgresql": PostgresDialect()}


def dialect_for(name: str) -> Dialect:
    try:
        return DIALECTS[name]
    except KeyError:
        raise SqlError(
            f"unsupported dialect {name!r}; supported: {', '.join(sorted(DIALECTS))}"
        ) from None
