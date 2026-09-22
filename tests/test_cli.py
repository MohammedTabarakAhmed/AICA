from pathlib import Path

import pytest

from aica.cli import main

PY = "def compute_total(items):\n    return sum(items)\n"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "invoice.py").write_text(PY, encoding="utf-8")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n", encoding="utf-8"
    )
    return tmp_path


def run(repo: Path, *args: str) -> int:
    return main(["-w", str(repo), "--policy", str(repo / "config" / "policy.toml"), *args])


def test_index_then_search(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(repo, "index") == 0
    out = capsys.readouterr().out
    assert "indexed 2 file(s)" in out  # invoice.py + policy.toml
    assert "code_files: 1" in out
    assert run(repo, "search", "compute total") == 0
    out = capsys.readouterr().out
    assert "src/invoice.py:" in out and "compute_total" in out


def test_search_before_index_is_an_error(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(repo, "search", "anything") == 2
    assert "run `aica index`" in capsys.readouterr().err


def test_policy_command_shows_effective_policy(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "policy") == 0
    out = capsys.readouterr().out
    assert "max_steps: 10" in out
    assert "network: deny" in out
    assert "fs.read" in out  # available tools listed


def test_run_command_executes_and_returns_exit_code(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "run", "echo", "hello") == 0
    assert "hello" in capsys.readouterr().out


def test_run_destructive_command_is_denied_without_approval(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # No --yes: ConsoleApprover reads EOF from the captured stdin and denies.
    assert run(repo, "run", "rm", "-rf", "src") == 4
    assert (repo / "src").exists()


def test_deps_command(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "src" / "caller.py").write_text(
        "from src.invoice import compute_total\n", encoding="utf-8"
    )
    run(repo, "index")
    capsys.readouterr()
    assert run(repo, "deps", "--symbol", "compute_total") == 0
    assert "definitions of compute_total" in capsys.readouterr().out


def test_test_discovery_command(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    (repo / "tests").mkdir()
    assert run(repo, "test", "--discover-only") == 0
    assert "pytest" in capsys.readouterr().out


def test_models_command_lists_configured_models(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "config" / "models.toml").write_text(
        'default = "m1"\n[[models]]\nname = "m1"\nfamily = "deepseek"\n'
        'version = "deepseek-chat"\nbase_url = "https://api.deepseek.com"\n',
        encoding="utf-8",
    )
    assert (
        main(
            [
                "-w",
                str(repo),
                "--policy",
                str(repo / "config" / "policy.toml"),
                "--models-file",
                str(repo / "config" / "models.toml"),
                "models",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "m1" in out and "deepseek" in out and "*" in out


def test_ask_without_models_reports_cleanly(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(repo, "ask", "what", "is", "this") == 3
    assert "model unavailable" in capsys.readouterr().err


def test_audit_records_cli_activity(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    run(repo, "run", "echo", "audited")
    capsys.readouterr()
    assert run(repo, "audit") == 0
    out = capsys.readouterr().out
    assert "command" in out and "echo audited" in out


def test_sessions_empty(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(repo, "sessions") == 1
    assert "(no sessions)" in capsys.readouterr().out


def test_git_command_outside_repo(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(Exception, match="not a Git repository"):
        run(repo, "git", "status")


# ---------------------------------------------------------------- new Phase 1 commands


def test_conventions_command_reports_evidence(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """CC-004: detected conventions are shown with the file that stated them."""
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n\n[tool.ruff]\nline-length = 88\n', encoding="utf-8"
    )
    assert run(repo, "conventions") == 0
    out = capsys.readouterr().out
    assert "Maximum line length: 88" in out
    assert "pyproject.toml" in out
    assert "(none recorded)" in out


def test_conventions_command_records_project_context(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """MEM-004: recorded conventions/preferences persist for the project."""
    assert run(repo, "conventions", "--record", "Prefer dataclasses", "--set", "style=terse") == 0
    capsys.readouterr()
    assert run(repo, "conventions") == 0
    out = capsys.readouterr().out
    assert "Prefer dataclasses" in out
    assert "style: terse" in out
    assert (repo / ".aica" / "project.json").exists()


def test_conventions_rejects_malformed_preference(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "conventions", "--set", "nope") == 2
    assert "KEY=VALUE" in capsys.readouterr().err


def test_debug_command_requires_a_non_empty_log(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "err.log").write_text("   \n", encoding="utf-8")
    assert run(repo, "debug", "--log", "err.log") == 2
    assert "empty log" in capsys.readouterr().err


def test_debug_command_without_a_model_reports_cleanly(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "err.log").write_text(
        'Traceback (most recent call last):\n  File "src/invoice.py", line 2, in compute_total\n'
        "TypeError: unsupported operand\n",
        encoding="utf-8",
    )
    assert run(repo, "debug", "--log", "err.log") == 3
    assert "model unavailable" in capsys.readouterr().err


def test_commit_message_command_outside_repo_reports_no_changes(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(Exception, match="not a Git repository"):
        run(repo, "commit-message")


def test_gen_tests_command_without_a_model_reports_cleanly(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "gen-tests", "--file", "src/invoice.py") == 3
    assert "model unavailable" in capsys.readouterr().err


def test_gen_tests_and_commit_message_happy_path(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """TEST-007/GIT-006 through the CLI, with the model scripted (no network; SAFE-005)."""
    import subprocess

    from aica import cli
    from aica.models.fake import ScriptedAdapter

    scripted = ScriptedAdapter(
        [
            "def test_compute_total() -> None:\n    assert compute_total([1, 2]) == 3\n",
            "Add a totals helper for invoices\n\nSum the item amounts.\n",
        ]
    )
    monkeypatch.setattr(cli, "_adapter", lambda args, ctx: (scripted, None))

    assert run(repo, "gen-tests", "--file", "src/invoice.py", "--focus", "empty lists") == 0
    captured = capsys.readouterr()
    assert "test_compute_total" in captured.out
    assert "proposed tests/test_invoice.py" in captured.err
    # TEST-007 is advisory: the CLI must not write the file.
    assert not (repo / "tests" / "test_invoice.py").exists()

    for args in (
        ["git", "init", "-q", "-b", "work"],
        ["git", "config", "user.email", "t@example.com"],
        ["git", "config", "user.name", "T"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "initial"],
    ):
        subprocess.run(args, cwd=repo, check=True)
    (repo / "src" / "invoice.py").write_text(PY + "\n\ndef tax(x):\n    return x * 0.2\n", "utf-8")

    assert run(repo, "commit-message") == 0
    captured = capsys.readouterr()
    assert captured.out.splitlines()[0] == "Add a totals helper for invoices"
    assert "model scripted-model-v0" in captured.err


def test_task_command_plans_executes_and_reports(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AG-001..AG-010 through the CLI, with the model scripted (no network)."""
    import json
    import sys as _sys

    from aica import cli
    from aica.models.fake import ScriptedAdapter

    (repo / "tests").mkdir()
    (repo / "tests" / "test_ok.py").write_text(
        "def test_ok():\n    assert True\n", encoding="utf-8"
    )
    command = f'"{_sys.executable}" -m pytest tests -q -p no:cacheprovider'
    plan = json.dumps(
        {
            "summary": "check the invoice module and verify",
            "steps": [
                {"intent": "read it", "tool": "fs.read", "arguments": {"path": "src/invoice.py"}},
                {
                    "intent": "run the tests",
                    "tool": "test.run",
                    "arguments": {"command": command, "kind": "unit"},
                },
            ],
            "verification": ["unit"],
        }
    )
    monkeypatch.setattr(cli, "_adapter", lambda args, ctx: (ScriptedAdapter([plan]), None))

    assert run(repo, "task", "check", "the", "invoice", "module") == 0
    captured = capsys.readouterr()
    assert "**Outcome:** SUCCESS" in captured.out
    assert "All required verification passed" in captured.out
    # UX-001/002: progress and the plan were streamed while it ran.
    assert "plan_created" in captured.err
    assert "[1/2] step_started (fs.read)" in captured.err
    assert "resume with" in captured.err


def test_task_plan_only_does_not_execute(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import json

    from aica import cli
    from aica.models.fake import ScriptedAdapter

    plan = json.dumps(
        {
            "summary": "delete everything",
            "steps": [
                {
                    "intent": "remove src",
                    "tool": "fs.delete",
                    "arguments": {"path": "src/invoice.py"},
                }
            ],
            "verification": [],
        }
    )
    monkeypatch.setattr(cli, "_adapter", lambda args, ctx: (ScriptedAdapter([plan]), None))

    assert run(repo, "task", "--plan-only", "clean", "up") == 0
    assert "Plan for: clean up" in capsys.readouterr().out
    assert (repo / "src" / "invoice.py").exists(), "--plan-only must not execute anything"


def test_task_resume_without_a_saved_task_is_an_error(
    repo: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from aica import cli
    from aica.chat.session import Session, SessionStore
    from aica.models.fake import ScriptedAdapter

    monkeypatch.setattr(cli, "_adapter", lambda args, ctx: (ScriptedAdapter([]), None))
    session = Session(workspace=str(repo))
    SessionStore(repo).save(session)
    assert run(repo, "task", "--session", session.session_id, "--resume") == 2
    assert "no task to resume" in capsys.readouterr().err


def test_task_without_a_model_reports_cleanly(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "task", "do", "something") == 3
    assert "model unavailable" in capsys.readouterr().err


def test_browse_command_refuses_a_forbidden_host(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """WEB-001 through the CLI: a non-allowlisted host is refused before a browser starts."""
    assert run(repo, "browse", "--url", "https://example.com") == 4
    assert "not permitted" in capsys.readouterr().err


def test_browse_command_rejects_malformed_fill(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "browse", "--url", "ftp://nope/") == 3
    assert "scheme" in capsys.readouterr().err


def test_db_command_reports_no_configured_databases(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """DB-001: with nothing configured there is nothing to reach."""
    assert run(repo, "db", "connections", "--databases-file", str(repo / "absent.toml")) == 0
    assert "no databases configured" in capsys.readouterr().out


def test_db_query_refuses_a_write_through_the_cli(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import sqlite3

    (repo / "app.sqlite").touch()
    connection = sqlite3.connect(repo / "app.sqlite")
    connection.execute("CREATE TABLE t (id INTEGER)")
    connection.commit()
    connection.close()
    config = repo / "databases.toml"
    config.write_text(
        'default = "app"\n\n[[connections]]\nname = "app"\ndialect = "sqlite"\n'
        'target = "app.sqlite"\nread_only = true\n',
        encoding="utf-8",
    )
    assert run(repo, "db", "query", "--databases-file", str(config), "--sql", "DROP TABLE t") == 3
    assert "only runs read queries" in capsys.readouterr().err
    # The table is still there.
    connection = sqlite3.connect(repo / "app.sqlite")
    try:
        assert (
            connection.execute("SELECT count(*) FROM sqlite_master WHERE name='t'").fetchone()[0]
            == 1
        )
    finally:
        connection.close()


def test_db_query_needs_sql(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(repo, "db", "query") == 2
    assert "needs --sql" in capsys.readouterr().err


def test_mcp_list_with_no_servers(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(repo, "mcp", "list", "--mcp-file", str(repo / "absent.toml")) == 1
    assert "no MCP servers configured" in capsys.readouterr().out


def test_mcp_call_rejects_non_json_arguments(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = repo / "mcp.toml"
    config.write_text('[[servers]]\nname = "x"\ncommand = "python"\n', encoding="utf-8")
    assert (
        run(
            repo,
            "mcp",
            "call",
            "--tool",
            "echo",
            "--arguments",
            "not json",
            "--mcp-file",
            str(config),
        )
        == 2
    )
    assert "must be a JSON object" in capsys.readouterr().err


def test_mcp_invalid_config_is_reported(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = repo / "mcp.toml"
    config.write_text('[[servers]]\nname = "bad name"\ncommand = "x"\n', encoding="utf-8")
    assert run(repo, "mcp", "list", "--mcp-file", str(config)) == 2
    assert "invalid MCP configuration" in capsys.readouterr().err


def test_serve_command_is_registered(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """API surface: `aica serve` exists and documents its loopback default."""
    from aica.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["serve"])
    assert args.host == "127.0.0.1"  # never exposed beyond this machine by default
    assert args.port == 8000
