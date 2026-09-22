"""Integration tests (TEST-003): multi-module flows over real files, Git and processes.

These are integration rather than unit tests because each one crosses module boundaries and
uses the real dependency instead of a double: a real SQLite index, a real Git repository, a
real child process. Only the model is scripted - a live model call would make the suite
non-deterministic and would need network access, which policy denies by default (SAFE-005).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from aica.approvals import AllowAllApprover, DenyAllApprover
from aica.audit import AuditLog, EventCategory, InMemoryAuditSink, Outcome
from aica.chat.assistant import CodingAssistant
from aica.chat.commit_message import suggest_commit_message
from aica.chat.report import FileChange, TaskReport
from aica.chat.session import Session, SessionStore
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.rag.index import RepositoryIndex
from aica.testing.results import VerificationLedger, parse_output
from aica.tools import ToolContext, default_registry
from aica.workspace import GitGuard, WorkspaceGuard
from aica.workspace.project_context import ProjectContextStore

# Every test in this module is an integration test (TEST-003).
pytestmark = pytest.mark.integration

CALC = '''"""Arithmetic helpers."""


def divide(a: float, b: float) -> float:
    """Divide a by b. Raises ZeroDivisionError when b is zero."""
    if b == 0:
        raise ZeroDivisionError("b must not be zero")
    return a / b


def ratio(values: list[float]) -> float:
    """Ratio of the first two values."""
    return divide(values[0], values[1])
'''


def _context(root: Path, policy: Policy | None = None, approve: bool = True) -> ToolContext:
    policy = policy or Policy()
    ws = WorkspaceGuard(root, policy.autonomy.allowed_directories)
    git = GitGuard(ws.root, policy.git)
    return ToolContext(
        workspace=ws,
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="integration", session_id="int-1"),
        git=git if git.is_repository() else None,
        approver=AllowAllApprover() if approve else DenyAllApprover(),
    )


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A small but real Python project in a real Git repository."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "calc.py").write_text(CALC, encoding="utf-8")
    (tmp_path / "tests" / "test_calc.py").write_text(
        "from src.calc import divide\n\n\ndef test_divide() -> None:\n    assert divide(6, 3) == 2\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\n\n'
        "[tool.ruff]\nline-length = 100\n\n"
        "[tool.mypy]\nstrict = true\n",
        encoding="utf-8",
    )
    for args in (
        ["git", "init", "-q", "-b", "work"],
        ["git", "config", "user.email", "integration@example.com"],
        ["git", "config", "user.name", "Integration"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "initial"],
    ):
        subprocess.run(args, cwd=tmp_path, check=True)
    return tmp_path


# ------------------------------------------------------------------ retrieval + chat


def test_index_search_and_answer_with_citations(project: Path) -> None:
    """RAG-001/004/008 + CHAT-001/002 + CC-004 over a real index."""
    ctx = _context(project)
    registry = default_registry()
    with RepositoryIndex(ctx.workspace) as index:
        ctx.index = index
        indexed = registry.call("repo.index", {}, ctx)
        assert indexed.data["files_indexed"] >= 3

        hits = registry.call("repo.search", {"query": "divide by zero", "limit": 5}, ctx)
        assert any("src/calc.py" in line for line in hits.output.splitlines())

        adapter = ScriptedAdapter(
            ["`divide` raises ZeroDivisionError for a zero divisor (src/calc.py:5-8)."]
        )
        store = ProjectContextStore(project)
        context = store.load()
        context.record_convention("Raise, never return None, on invalid input")
        store.save(context)

        assistant = CodingAssistant(
            adapter, index, workspace_root=project, project_context=store.load()
        )
        session = Session(workspace=str(project))
        answer = assistant.ask(session, "what happens when the divisor is zero?")

        assert "src/calc.py:5-8" in answer.citations
        assert any(r.path == "src/calc.py" for r in answer.retrieved)
        system = adapter.calls[0][0].content
        assert "Maximum line length: 100" in system  # CC-004 from pyproject.toml
        assert "Raise, never return None" in system  # MEM-004 from .aica/project.json

        saved = SessionStore(project).save(session)
        assert saved.exists()
        reloaded = SessionStore(project).load(session.session_id)
        assert reloaded.turns[-1].model == "scripted-model-v0"  # MM-012


# ------------------------------------------------------------------ edit + verify + commit


def test_edit_run_tests_and_commit_a_generated_message(project: Path) -> None:
    """FS-003 + TEST-002 + GIT-006/007 + TEST-009 in one flow."""
    ctx = _context(project)
    registry = default_registry()

    edit = registry.call(
        "fs.edit",
        {
            "path": "src/calc.py",
            "old_text": "    return divide(values[0], values[1])",
            "new_text": '    if len(values) < 2:\n        raise ValueError("two values are required")\n    return divide(values[0], values[1])',
        },
        ctx,
    )
    assert "ValueError" in edit.data["diff"]

    (project / "tests" / "test_ratio.py").write_text(
        "import pytest\n\nfrom src.calc import ratio\n\n\n"
        "def test_ratio_needs_two_values() -> None:\n"
        "    with pytest.raises(ValueError):\n        ratio([1])\n",
        encoding="utf-8",
    )

    ledger = VerificationLedger()
    ledger.require("unit")
    run = registry.call(
        "test.run",
        {"command": f'"{sys.executable}" -m pytest tests -q -p no:cacheprovider'},
        ctx,
    )
    assert run.ok, run.output
    assert run.data["passed"] == 2
    ledger.record(
        parse_output("unit", str(run.data["command"]), run.output, "", int(run.data["exit_code"]))
    )
    assert ledger.can_report_success

    diff = registry.call("git.diff", {}, ctx).output
    message = suggest_commit_message(
        ScriptedAdapter(
            ["Require two values in ratio\n\nRaise ValueError instead of IndexError.\n"]
        ),
        diff,
    )
    assert message.generated is True

    commit = registry.call("git.commit", {"message": message.text}, ctx)
    assert commit.ok
    subject = subprocess.run(
        ["git", "log", "-1", "--pretty=%s"],
        cwd=project,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    assert subject == "Require two values in ratio"

    report = TaskReport(
        task="require two values in ratio",
        model="scripted-model-v0",
        changes=[FileChange(path="src/calc.py", action="modified", diff=edit.data["diff"])],
        ledger=ledger,
        steps_used=4,
    )
    assert report.succeeded and report.outcome() == "SUCCESS"


def test_failing_tests_prevent_a_success_report(project: Path) -> None:
    """TEST-009: a real failing test run must make the report INCOMPLETE."""
    ctx = _context(project)
    (project / "tests" / "test_broken.py").write_text(
        "from src.calc import divide\n\n\ndef test_wrong() -> None:\n    assert divide(1, 2) == 99\n",
        encoding="utf-8",
    )
    run = default_registry().call(
        "test.run",
        {"command": f'"{sys.executable}" -m pytest tests -q -p no:cacheprovider'},
        ctx,
    )
    assert not run.ok and run.data["failed"] == 1
    assert "tests/test_broken.py" in run.data["analysis"].replace("\\", "/")

    ledger = VerificationLedger()
    ledger.require("unit")
    ledger.record(parse_output("unit", "pytest", run.output, "", int(run.data["exit_code"])))
    report = TaskReport(task="break something", model="scripted-model-v0", ledger=ledger)
    assert report.succeeded is False
    assert "unit" in report.render()


# ------------------------------------------------------------------ debugging a real failure


def test_debug_a_real_traceback_end_to_end(project: Path) -> None:
    """CHAT-004: run code that really fails, then diagnose it from the captured output."""
    ctx = _context(project)
    registry = default_registry()
    (project / "boom.py").write_text("from src.calc import ratio\n\nratio([1])\n", encoding="utf-8")

    run = registry.call("shell.run", {"command": f'"{sys.executable}" boom.py'}, ctx)
    assert run.data["exit_code"] != 0
    log = str(run.data["stderr"])
    assert "IndexError" in log

    with RepositoryIndex(ctx.workspace) as index:
        index.index_repository()
        adapter = ScriptedAdapter(
            ["`ratio` indexes values[1] without checking the length (src/calc.py:12-14)."]
        )
        assistant = CodingAssistant(adapter, index, workspace_root=project)
        answer, diagnosis = assistant.debug(Session(workspace=str(project)), log)

    assert diagnosis.error_type == "IndexError"
    assert diagnosis.culprit is not None
    assert diagnosis.culprit.file in {"boom.py", "src/calc.py"}
    assert any(f.file == "src/calc.py" for f in diagnosis.project_frames)
    assert any(r.path == "src/calc.py" for r in answer.retrieved)


# ------------------------------------------------------------------ discovery of this suite


def test_discovery_finds_unit_and_integration_commands(project: Path) -> None:
    """TEST-001/003: an integration suite in tests/integration is discovered as integration."""
    (project / "tests" / "integration").mkdir()
    (project / "tests" / "integration" / "test_smoke.py").write_text(
        "def test_smoke() -> None:\n    assert True\n", encoding="utf-8"
    )
    ctx = _context(project)
    discovered = default_registry().call("test.discover", {}, ctx)
    kinds = {c["kind"]: c["command"] for c in discovered.data["commands"]}
    assert "unit" in kinds
    assert kinds["integration"].endswith("pytest tests/integration")

    # Execute that suite for real. The discovered command names the project interpreter,
    # which the fixture project does not have, so the same command is run with this one.
    run = default_registry().call(
        "test.run",
        {
            "kind": "integration",
            "command": f'"{sys.executable}" -m pytest tests/integration -q -p no:cacheprovider',
        },
        ctx,
    )
    assert run.ok, run.output
    assert run.data["passed"] == 1
    assert run.data["kind"] == "integration"


# ------------------------------------------------------------------ guardrails hold end to end


def test_guardrails_hold_across_the_stack(project: Path) -> None:
    """RAG-007 + FS-001 + EXEC-006 + GIT-010 under one restricted policy."""
    policy = Policy()
    policy.autonomy.allowed_directories = ["src"]
    ctx = _context(project, policy, approve=False)
    registry = default_registry()

    with pytest.raises(PermissionError):
        registry.call("fs.read", {"path": "pyproject.toml"}, ctx)

    with RepositoryIndex(
        WorkspaceGuard(project),
    ) as full_index:
        full_index.index_repository()
    with RepositoryIndex(ctx.workspace) as restricted:
        # RAG-007: the restricted guard cannot retrieve outside src/, even from a full index.
        assert all(r.path.startswith("src/") for r in restricted.search("pyproject", 10))

    with pytest.raises(Exception) as destructive:
        registry.call("shell.run", {"command": "rm -rf src"}, ctx)
    assert (project / "src").exists()
    assert destructive.value is not None

    blocked = [
        e
        for e in ctx.audit.sink.events  # type: ignore[attr-defined]
        if e.outcome in {Outcome.BLOCKED, Outcome.PENDING_APPROVAL}
        or e.category is EventCategory.APPROVAL
    ]
    assert blocked, "policy denials must be audited"
