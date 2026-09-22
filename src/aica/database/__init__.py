"""Controlled database access (DB-001..DB-007).

Connections are named in configuration and never supplied by a model; read-only is enforced
at the driver as well as by statement classification; writes and destructive statements pass
through approval; migrations are generated and reviewed but never applied automatically.
"""

from aica.database.connections import (
    DEFAULT_DATABASES_PATH,
    Connection,
    ConnectionConfig,
    DatabaseError,
    DatabasesConfig,
    DriverUnavailable,
    QueryResult,
    ReadOnlyViolation,
    ensure_read,
    load_databases,
)
from aica.database.migrations import (
    Migration,
    MigrationError,
    generate_migration,
    parse_migration,
)
from aica.database.sql import (
    DIALECTS,
    Classification,
    Dialect,
    PostgresDialect,
    SqlError,
    SQLiteDialect,
    StatementClass,
    classify,
    dialect_for,
    split_statements,
)

__all__ = [
    "DEFAULT_DATABASES_PATH",
    "DIALECTS",
    "Classification",
    "Connection",
    "ConnectionConfig",
    "DatabaseError",
    "DatabasesConfig",
    "Dialect",
    "DriverUnavailable",
    "Migration",
    "MigrationError",
    "PostgresDialect",
    "QueryResult",
    "ReadOnlyViolation",
    "SQLiteDialect",
    "SqlError",
    "StatementClass",
    "classify",
    "dialect_for",
    "ensure_read",
    "generate_migration",
    "load_databases",
    "parse_migration",
    "split_statements",
]
