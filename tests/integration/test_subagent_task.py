"""Delegation over a real project (AG-008 end to end).

Real files, a real Git repository, real pytest child processes; only the model is scripted,
so the run is deterministic and needs no network. Everything the subagent causes is real: the
edit lands on disk, the suite genuinely executes, and the parent's success claim is decided by
its actual exit code.

The two questions these tests answer are the ones a unit test cannot: does a delegated agent
actually change the working tree it was given, and does the parent's report still tell the
truth about it?
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from aica.agent.loop import AgentLoop
from aica.agent.subagents import DELEGATE_TOOL, Delegation
from aica.approvals import AllowAllApprover
from aica.audit import AuditLog, InMemoryAuditSink
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.policy.budget import RunBudget
from aica.testing.results import CheckStatus
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

GUARD_OLD = "    return values[0] / values[1]"
GUARD_NEW = (
    '    if len(values) < 2:\n        raise ValueError("two values are required")\n'
    "    return values[0] / values[1]"
)


def _context(root: Path) -> ToolContext:
    policy = Policy()
    ws = WorkspaceGuard(root, policy.autonomy.allowed_directories)
    git = GitGuard(ws.root, policy.git)
    return ToolContext(
        workspace=ws,
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="subagent-integration", session_id="sub-1"),
        git=git if git.is_repository() else None,
        approver=AllowAllApprover(),
    )


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A real project whose suite fails until someone guards ``ratio``."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "src" / "calc.py").write_text(CALC, encoding="utf-8")
    (tmp_path / "tests" / "test_calc.py").write_text(TEST_FILE, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.1.0"\n', encoding="utf-8"
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
        {"summary": "delegate and verify", "steps": list(steps), "verification": verification or []}
    )


def _delegate(role: str, objective: str, **extra: object) -> dict[str, object]:
    return {
        "intent": f"hand this to the {role} subagent",
        "tool": DELEGATE_TOOL,
        "arguments": {"role": role, "objective": objective, **extra},
    }


def _suite_passes(project: Path) -> bool:
    """Run the project's tests ourselves, independently of anything the agent reported."""
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "tests", "-q", "-p", "no:cacheprovider"],
        cwd=project,
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode == 0


def test_an_implementation_subagent_really_fixes_the_code(project: Path) -> None:
    """AG-008 + AG-009: the child edits real files and proves it with a real test run."""
    assert not _suite_passes(project), "the fixture must start red"
    ctx = _context(project)
    command = _pytest_command()
    adapter = ScriptedAdapter(
        [
            _plan(_delegate("implementation", "guard ratio against a short list and verify")),
            # The subagent's own plan, produced with only the tools its role allows.
            _plan(
                {
                    "intent": "add the length guard",
                    "tool": "fs.edit",
                    "arguments": {
                        "path": "src/calc.py",
                        "old_text": GUARD_OLD,
                        "new_text": GUARD_NEW,
                    },
                },
                {
                    "intent": "run the suite",
                    "tool": "test.run",
                    "arguments": {"command": command, "kind": "unit"},
                },
                verification=["unit"],
            ),
        ]
    )
    delegation = Delegation(adapter)
    report = AgentLoop(adapter, default_registry(), delegation=delegation).run("guard ratio", ctx)

    # The child really changed the file, and the suite really passes now.
    assert "two values are required" in (project / "src" / "calc.py").read_text(encoding="utf-8")
    assert _suite_passes(project)

    # The parent inherited both the change and the passing check (AG-010, AG-009).
    assert [c.path for c in report.changes] == ["src/calc.py"]
    assert report.ledger.required["unit"] is CheckStatus.PASSED
    assert report.succeeded is True
    assert delegation.history[0].report.steps_used == 2


def test_a_read_only_subagent_cannot_touch_the_working_tree(project: Path) -> None:
    """The narrowing is real, not advisory: a review role has no tool that writes."""
    ctx = _context(project)
    before = (project / "src" / "calc.py").read_text(encoding="utf-8")
    adapter = ScriptedAdapter(
        [
            _plan(_delegate("review", "review ratio and fix it if it is wrong")),
            # The child tries to edit anyway - twice, because its planner retries once.
            _plan({"intent": "fix it", "tool": "fs.edit", "arguments": {"path": "src/calc.py"}}),
            _plan({"intent": "fix it", "tool": "fs.edit", "arguments": {"path": "src/calc.py"}}),
            json.dumps({"action": "abort", "reason": "the review subagent could not proceed"}),
        ]
    )
    delegation = Delegation(adapter)
    report = AgentLoop(adapter, default_registry(), delegation=delegation).run("review it", ctx)

    assert (project / "src" / "calc.py").read_text(encoding="utf-8") == before
    assert report.changes == []
    assert report.succeeded is False
    child = delegation.history[0]
    assert any("not available" in item for item in child.report.unresolved)

    # GIT-004: and Git agrees that nothing changed.
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=project, capture_output=True, text=True, check=True
    )
    assert status.stdout.strip() == ""


def test_a_subagents_red_suite_keeps_the_parent_incomplete(project: Path) -> None:
    """TEST-009: delegation cannot launder a failure into a parent SUCCESS."""
    ctx = _context(project)
    command = _pytest_command()
    adapter = ScriptedAdapter(
        [
            _plan(_delegate("testing", "run the suite and report")),
            _plan(
                {
                    "intent": "run the suite",
                    "tool": "test.run",
                    "arguments": {"command": command, "kind": "unit"},
                },
                verification=["unit"],
            ),
            json.dumps({"action": "abort", "reason": "the suite is red and I cannot fix it"}),
            json.dumps({"action": "abort", "reason": "the subagent could not finish"}),
        ]
    )
    delegation = Delegation(adapter)
    report = AgentLoop(adapter, default_registry(), delegation=delegation).run("prove it", ctx)

    assert not _suite_passes(project), "the code was never fixed"
    assert report.succeeded is False
    assert report.ledger.required["unit"] is CheckStatus.FAILED
    assert "VERIFICATION INCOMPLETE" in report.ledger.disclosure()
    assert any("[testing]" in w for w in report.warnings)


def test_a_subagent_cannot_spend_more_than_the_parent_has_left(project: Path) -> None:
    """AG-007: the child's allowance is carved out of the parent's, not added to it."""
    ctx = _context(project)
    read = {"intent": "read", "tool": "fs.read", "arguments": {"path": "src/calc.py"}}
    adapter = ScriptedAdapter(
        [
            _plan(_delegate("research", "read the module a few times", max_steps=50)),
            _plan(read, read, read, read, read),
            json.dumps({"action": "abort", "reason": "out of budget"}),
        ]
    )
    delegation = Delegation(adapter)
    loop = AgentLoop(adapter, default_registry(), delegation=delegation)
    report = loop.run("look around", ctx, budget=RunBudget(max_steps=3, max_seconds=120))

    child = delegation.history[0]
    # One parent step went on the delegation itself, leaving two for the child.
    assert child.report.steps_used == 2
    assert report.steps_used == 3
    assert child.completed is False  # it ran out mid-plan, and says so
