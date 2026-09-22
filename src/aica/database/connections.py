"""Database connection configuration and execution (DB-001, DB-004, DB-005, DB-007).

Connections are **named in configuration, never supplied by the model**. A tool call selects
a connection by name; it cannot pass a DSN. That is the difference between an agent that can
query the databases you approved and one that can reach any database it can guess a
connection string for.

Credentials follow the same rule as models: configuration names an environment variable, and
the value is read at connect time. A DSN with a password embedded in the config file is
rejected outright.

Every connection carries ``read_only``, which is enforced here rather than left to the caller:
a read-only connection refuses a non-read statement before the database sees it. That is the
first of DB-005's two gates; the approval category is the second.
"""

from __future__ import annotations

import os
import re
import sqlite3
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aica.database.sql import (
    Classification,
    Dialect,
    SqlError,
    StatementClass,
    classify,
    dialect_for,
)
from aica.safety.redaction import redact

DEFAULT_DATABASES_PATH = Path("config/databases.toml")
MAX_VALUE_CHARS = 500

_PASSWORD_IN_DSN = re.compile(r"://[^/\s:]+:[^/\s@]+@")

PSYCOPG_HINT = (
    "psycopg is not installed. PostgreSQL connections need it:\n"
    "  pip install 'psycopg[binary]>=3.1,<4'"
)


class DatabaseError(RuntimeError):
    """A connection or statement could not be completed."""


class DriverUnavailable(DatabaseError):
    """The driver for this dialect is not installed."""


class ReadOnlyViolation(PermissionError):
    """A non-read statement was attempted on a read-only connection (DB-005)."""


class ConnectionConfig(BaseModel):
    """One approved database. ``extra="forbid"`` so a typo fails loudly."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    dialect: str = Field(pattern="^(sqlite|postgresql)$")
    # sqlite: a path relative to the workspace. postgresql: a DSN without a password.
    target: str = Field(min_length=1, max_length=1000)
    password_env: str | None = None
    read_only: bool = True
    max_rows: int = Field(default=1000, ge=1, le=100_000)
    statement_timeout_seconds: float = Field(default=30.0, gt=0, le=3600)
    environment: str = Field(default="development", pattern="^(development|test|production)$")
    enabled: bool = True
    description: str = ""

    @field_validator("target")
    @classmethod
    def _no_embedded_password(cls, value: str) -> str:
        if _PASSWORD_IN_DSN.search(value):
            raise ValueError(
                "the connection target contains an inline password; remove it and name an "
                "environment variable in password_env instead (SAFE-006)"
            )
        return value

    @property
    def host(self) -> str:
        if self.dialect == "sqlite":
            return "localhost"
        return urlparse(self.target).hostname or ""

    def dialect_impl(self) -> Dialect:
        return dialect_for(self.dialect)


class DatabasesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default: str | None = None
    connections: list[ConnectionConfig] = Field(default_factory=list)

    def get(self, name: str | None) -> ConnectionConfig:
        wanted = name or self.default
        if wanted is None:
            if len(self.connections) == 1:
                return self.connections[0]
            raise DatabaseError(
                "no connection named and no default set; configured: "
                + (", ".join(c.name for c in self.connections) or "none")
            )
        for connection in self.connections:
            if connection.name == wanted:
                if not connection.enabled:
                    raise DatabaseError(f"connection {wanted!r} is disabled in configuration")
                return connection
        raise DatabaseError(
            f"unknown connection {wanted!r}; configured: "
            + (", ".join(c.name for c in self.connections) or "none")
        )

    def names(self) -> list[str]:
        return [c.name for c in self.connections]


def load_databases(path: str | Path | None = None) -> DatabasesConfig:
    """Load ``config/databases.toml``. A missing file means no databases, not an error."""
    target = Path(path or os.environ.get("AICA_DATABASES_FILE") or DEFAULT_DATABASES_PATH)
    if not target.exists():
        return DatabasesConfig()
    try:
        raw = tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise DatabaseError(f"{target}: could not read database configuration: {exc}") from exc
    try:
        return DatabasesConfig.model_validate(raw)
    except ValidationError as exc:
        raise DatabaseError(
            f"{target}: invalid database configuration: {exc.errors(include_url=False)}"
        ) from exc


@dataclass
class QueryResult:
    columns: list[str]
    rows: list[tuple[Any, ...]]
    row_count: int  # rows returned, or rows affected for a write
    truncated: bool
    duration_ms: int
    statement_class: StatementClass
    notes: list[str] = field(default_factory=list)

    def render(self, max_width: int = 40) -> str:
        if not self.columns:
            return f"{self.row_count} row(s) affected in {self.duration_ms} ms"
        widths = [
            min(
                max(len(c), *(len(_cell(r[i])) for r in self.rows)) if self.rows else len(c),
                max_width,
            )
            for i, c in enumerate(self.columns)
        ]
        header = " | ".join(c[:w].ljust(w) for c, w in zip(self.columns, widths, strict=True))
        divider = "-+-".join("-" * w for w in widths)
        body = [
            " | ".join(_cell(v)[:w].ljust(w) for v, w in zip(row, widths, strict=True))
            for row in self.rows
        ]
        footer = f"({self.row_count} row(s)"
        if self.truncated:
            footer += ", truncated"
        footer += f", {self.duration_ms} ms)"
        return "\n".join([header, divider, *body, footer])


def _cell(value: Any) -> str:
    if value is None:
        return "NULL"
    return redact(str(value)).text[:MAX_VALUE_CHARS].replace("\n", " ")


class Connection:
    """An open connection to one configured database. Use as a context manager."""

    def __init__(self, config: ConnectionConfig, workspace_root: Path | None = None) -> None:
        self.config = config
        self.dialect = config.dialect_impl()
        self._raw: Any = None
        self._workspace_root = workspace_root
        self.database_label = self._label()

    def _label(self) -> str:
        if self.config.dialect == "sqlite":
            return self.config.target
        parsed = urlparse(self.config.target)
        return f"{parsed.hostname or '?'}/{(parsed.path or '').lstrip('/') or '?'}"

    # ------------------------------------------------------------------ lifecycle
    def __enter__(self) -> Connection:
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def open(self) -> None:
        if self._raw is not None:
            return
        if self.config.dialect == "sqlite":
            self._raw = self._open_sqlite()
        else:
            self._raw = self._open_postgres()

    def _open_sqlite(self) -> Any:
        path = Path(self.config.target)
        if not path.is_absolute() and self._workspace_root is not None:
            path = self._workspace_root / path
        if not path.exists():
            raise DatabaseError(f"sqlite database {path} does not exist")
        # A read-only connection is opened read-only at the driver level too, so the
        # guarantee does not rest on statement classification alone.
        if self.config.read_only:
            uri = f"file:{path.as_posix()}?mode=ro"
            connection = sqlite3.connect(
                uri, uri=True, timeout=self.config.statement_timeout_seconds
            )
        else:
            connection = sqlite3.connect(str(path), timeout=self.config.statement_timeout_seconds)
        connection.row_factory = None
        return connection

    def _open_postgres(self) -> Any:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - only without the extra
            raise DriverUnavailable(PSYCOPG_HINT) from exc
        password = None
        if self.config.password_env:
            password = os.environ.get(self.config.password_env)
            if not password:
                raise DatabaseError(
                    f"environment variable {self.config.password_env} is not set; it holds the "
                    f"password for connection {self.config.name!r}"
                )
        try:
            connection = psycopg.connect(
                self.config.target,
                password=password,
                connect_timeout=int(self.config.statement_timeout_seconds),
                autocommit=False,
            )
            with connection.cursor() as cursor:
                # PostgreSQL's SET takes no bound parameters, so these go through
                # set_config(), which does. The alternative - interpolating the value into
                # the statement - is exactly the habit this project refuses everywhere else.
                cursor.execute(
                    "SELECT set_config('statement_timeout', %s, false)",
                    (str(int(self.config.statement_timeout_seconds * 1000)),),
                )
                if self.config.read_only:
                    cursor.execute(
                        "SELECT set_config('default_transaction_read_only', 'on', false)"
                    )
            connection.commit()
        except Exception as exc:
            raise DatabaseError(f"could not connect to {self.database_label}: {exc}") from exc
        return connection

    def close(self) -> None:
        if self._raw is not None:
            try:
                self._raw.close()
            finally:
                self._raw = None

    # ------------------------------------------------------------------ execution
    def check_allowed(self, sql: str) -> Classification:
        """DB-005 first gate: classify, and refuse a write on a read-only connection."""
        classification = classify(sql)
        if self.config.read_only and not classification.is_read:
            raise ReadOnlyViolation(
                f"connection {self.config.name!r} is read-only; this statement "
                f"{classification.reason} ({classification.statement_class.value})"
            )
        return classification

    def execute(
        self, sql: str, parameters: list[Any] | None = None, *, max_rows: int | None = None
    ) -> QueryResult:
        """Run one already-authorized statement. Callers apply approval gates first."""
        if self._raw is None:
            self.open()
        classification = self.check_allowed(sql)
        limit = max_rows or self.config.max_rows
        started = time.monotonic()
        cursor = self._raw.cursor()
        try:
            cursor.execute(sql, tuple(parameters or ()))
            columns = [d[0] for d in cursor.description] if cursor.description else []
            rows: list[tuple[Any, ...]] = []
            truncated = False
            if columns:
                fetched = cursor.fetchmany(limit + 1)
                truncated = len(fetched) > limit
                rows = [tuple(r) for r in fetched[:limit]]
                row_count = len(rows)
            else:
                row_count = max(cursor.rowcount, 0)
            if not self.config.read_only and not classification.is_read:
                self._raw.commit()
        except ReadOnlyViolation:
            raise
        except Exception as exc:
            detail = ""
            if not self.config.read_only:
                try:
                    self._raw.rollback()
                except Exception as rollback_error:  # noqa: BLE001 - reported, never masking
                    # A failed rollback matters: the transaction state is now unknown, and
                    # the caller must be told rather than seeing only the original error.
                    detail = f" (rollback also failed: {_first_line(rollback_error)})"
            raise DatabaseError(f"{_first_line(exc)}{detail}") from exc
        finally:
            cursor.close()
        notes = []
        if truncated:
            notes.append(f"result truncated at {limit} rows (connection max_rows)")
        return QueryResult(
            columns=columns,
            rows=rows,
            row_count=row_count,
            truncated=truncated,
            duration_ms=int((time.monotonic() - started) * 1000),
            statement_class=classification.statement_class,
            notes=notes,
        )


def _first_line(exc: Exception) -> str:
    text = str(exc).strip() or type(exc).__name__
    return redact(text.splitlines()[0]).text[:600]


def ensure_read(sql: str) -> Classification:
    """Classify and require a read. Used by tools that must never write (DB-004)."""
    classification = classify(sql)
    if not classification.is_read:
        raise SqlError(
            f"this tool only runs read queries; the statement {classification.reason} "
            f"({classification.statement_class.value}). Use db.execute for changes."
        )
    return classification
