"""Agent loop end to end over a real project (TEST-003 + AG-001..AG-010).

Real files, a real Git repository, real pytest child processes. Only the model is scripted,
so the run is deterministic and needs no network (SAFE-005) - but every effect it causes is
real: the edit lands on disk, the tests genuinely execute, and the success claim is decided
by their actual exit code rather than by anything the model said.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aica.agent.events import EventType, ListSink, StepStatus
from aica.agent.loop import AgentLoop, AgentState
from aica.approvals import AllowAllApprover, DenyAllApprover
from aica.audit import AuditLog, InMemoryAuditSink
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.policy.budget import RunBudget
from aica.tools import ToolContext, default_registry
from aica.workspace import GitGuard, WorkspaceGuard

pytestmark = pytest.mark.integration

CALC = '''"""Arithmetic helpers."""


def ratio(values: list[float]) -> float:
    """Ratio of the first two values."""
    return values[0] / values[1]
'''

TEST_FILE = """import pytest

from src.calc import ratio


def test_ratio() -> None:
    assert ratio([6, 3]) == 2


def test_ratio_rejects_short_input() -> None:
    with pytest.raises(ValueError):
        ratio([1])
"""

FIXED = '''def ratio(values: list[float]) -> float:
    """Ratio of the first two values."""
    if len(values) < 2:
        raise ValueError("two values are required")
    return values[0] / values[1]
'''


def _context(root: Path, approve: bool = True) -> ToolContext:
    policy = Policy()
    ws = WorkspaceGuard(root, policy.autonomy.allowed_directories)
    git = GitGuard(ws.root, policy.git)
    return ToolContext(
        workspace=ws,
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="agent-integration", session_id="agent-1"),
        git=git if git.is_repository() else None,
        approver=AllowAllApprover() if approve else DenyAllApprover(),
    )


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A real project whose test suite fails until the agent fixes the code."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "calc.py").write_text(CALC, encoding="utf-8")
    (tmp_path / "tests" / "test_calc.py").write_text(TEST_FILE, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\n\n[tool.ruff]\nline-length = 100\n',
        encoding="utf-8",
    )
    for args in (
        ["git", "init", "-q", "-b", "work"],
        ["git", "config", "user.email", "agent@example.com"],
        ["git", "config", "user.name", "Agent"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "initial"],
    ):
        subprocess.run(args, cwd=tmp_path, check=True)
    return tmp_path


def _pytest_command() -> str:
    return f'"{sys.executable}" -m pytest tests -q -p no:cacheprovider'


def _plan(*steps: dict[str, object], verification: list[str] | None = None) -> str:
    return json.dumps(
        {"summary": "fix and verify", "steps": list(steps), "verification": verification or []}
    )


def test_agent_fixes_real_code_and_proves_it_with_real_tests(project: Path) -> None:
    """The full loop: the first test run really fails, the agent adapts, the rerun passes."""
    ctx = _context(project)
    sink = ListSink()
    command = _pytest_command()

    # 1st reply: a plan that runs the (failing) suite. 2nd: the repair after it fails.
    adapter = ScriptedAdapter(
        [
            _plan(
                {
                    "intent": "run the suite to see the failure",
                    "tool": "test.run",
                    "arguments": {"command": command, "kind": "unit"},
                },
                verification=["unit"],
            ),
            json.dumps(
                {
                    "action": "replace",
                    "reason": "ratio indexes values[1] without checking the length",
                    "steps": [
                        {
                            "intent": "add the length guard",
                            "tool": "fs.edit",
                            "arguments": {
                                "path": "src/calc.py",
                                "old_text": "    return values[0] / values[1]",
                                "new_text": '    if len(values) < 2:\n        raise ValueError("two values are required")\n    return values[0] / values[1]',
                            },
                        },
                        {
                            "intent": "rerun the suite",
                            "tool": "test.run",
                            "arguments": {"command": command, "kind": "unit"},
                        },
                    ],
                }
            ),
        ]
    )

    report = AgentLoop(adapter, default_registry(), sink=sink).run("make the tests pass", ctx)

    # The file on disk really changed.
    source = (project / "src" / "calc.py").read_text(encoding="utf-8")
    assert "two values are required" in source

    # The suite really passes now - checked independently of the agent.
    rerun = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"],
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
    )
    assert rerun.returncode == 0, rerun.stdout

    # AG-009/TEST-009: SUCCESS is only reachable because the rerun actually passed.
    assert report.succeeded is True
    assert report.outcome() == "SUCCESS"
    assert "All required verification passed: unit" in report.ledger.disclosure()
    assert [c.path for c in report.changes] == ["src/calc.py"]
    assert report.changes[0].diff, "UX-004: the change must carry its diff"

    # AG-004: the failure was observed and the plan revised.
    revised = sink.of_type(EventType.PLAN_REVISED)
    assert revised and revised[0].data["action"] == "replace"
    verifications = sink.of_type(EventType.VERIFICATION)
    assert [v.status for v in verifications] == [StepStatus.FAILED, StepStatus.SUCCEEDED]


def test_agent_cannot_report_success_when_the_fix_does_not_work(project: Path) -> None:
    """The safety property: a wrong fix must end INCOMPLETE, never SUCCESS."""
    ctx = _context(project)
    command = _pytest_command()
    adapter = ScriptedAdapter(
        [
            _plan(
                {
                    "intent": "apply a fix",
                    "tool": "fs.edit",
                    "arguments": {
                        "path": "src/calc.py",
                        "old_text": '    """Ratio of the first two values."""',
                        "new_text": '    """Ratio of the first two values. (annotated)"""',
                    },
                },
                {
                    "intent": "run the suite",
                    "tool": "test.run",
                    "arguments": {"command": command, "kind": "unit"},
                },
                verification=["unit"],
            )
        ]
    )
    report = AgentLoop(adapter, default_registry()).run("make the tests pass", ctx)

    assert report.succeeded is False
    assert report.outcome() == "INCOMPLETE"
    assert "VERIFICATION INCOMPLETE" in report.ledger.disclosure()
    assert "unit: failed" in report.ledger.disclosure()
    # The comment edit really happened - the agent is not pretending otherwise.
    assert "(annotated)" in (project / "src" / "calc.py").read_text(encoding="utf-8")


def test_agent_run_is_resumable_across_processes(project: Path) -> None:
    """AG-005/NFR-002: stop on the budget, persist, resume, finish."""
    ctx = _context(project)
    command = _pytest_command()
    plan = _plan(
        {"intent": "read the module", "tool": "fs.read", "arguments": {"path": "src/calc.py"}},
        {
            "intent": "apply the guard",
            "tool": "fs.edit",
            "arguments": {
                "path": "src/calc.py",
                "old_text": "    return values[0] / values[1]",
                "new_text": '    if len(values) < 2:\n        raise ValueError("two values are required")\n    return values[0] / values[1]',
            },
        },
        {
            "intent": "verify",
            "tool": "test.run",
            "arguments": {"command": command, "kind": "unit"},
        },
        verification=["unit"],
    )

    first = AgentLoop(ScriptedAdapter([plan]), default_registry())
    stopped = first.run("guard ratio", ctx, budget=RunBudget(max_steps=1, max_seconds=120))
    assert stopped.succeeded is False
    assert first.state is not None
    saved = first.state.to_json()  # what a session would persist

    # A fresh loop, a fresh state object: nothing is carried over in memory.
    second = AgentLoop(ScriptedAdapter([]), default_registry())
    finished = second.run("guard ratio", _context(project), state=AgentState.from_json(saved))

    assert finished.succeeded is True
    assert "two values are required" in (project / "src" / "calc.py").read_text(encoding="utf-8")


def test_agent_respects_the_approval_gate_on_a_real_repository(project: Path) -> None:
    """SAFE-001/003: the agent cannot self-approve a destructive step."""
    ctx = _context(project, approve=False)
    adapter = ScriptedAdapter(
        [
            _plan(
                {
                    "intent": "clean the tree",
                    "tool": "shell.run",
                    "arguments": {"command": "rm -rf src"},
                }
            )
        ]
    )
    report = AgentLoop(adapter, default_registry()).run("clean up", ctx)

    assert (project / "src" / "calc.py").exists(), "nothing may be deleted without approval"
    assert report.succeeded is False
    assert any("approval" in u for u in report.unresolved)


def test_agent_changes_are_reviewable_and_revertible(project: Path) -> None:
    """GIT-004/GIT-009: what the agent did shows up in Git and can be undone."""
    ctx = _context(project)
    adapter = ScriptedAdapter(
        [
            _plan(
                {
                    "intent": "add the guard",
                    "tool": "fs.edit",
                    "arguments": {
                        "path": "src/calc.py",
                        "old_text": "    return values[0] / values[1]",
                        "new_text": '    if len(values) < 2:\n        raise ValueError("two")\n    return values[0] / values[1]',
                    },
                }
            )
        ]
    )
    AgentLoop(adapter, default_registry()).run("guard ratio", ctx)

    diff = default_registry().call("git.diff", {}, ctx).output
    assert "two values" in diff or "raise ValueError" in diff

    subprocess.run(["git", "checkout", "--", "src/calc.py"], cwd=project, check=True)
    assert (project / "src" / "calc.py").read_text(encoding="utf-8") == CALC
