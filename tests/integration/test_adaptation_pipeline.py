"""BRD 13 end to end, from a genuine agent run to a promoted and rolled-back adapter.

The agent really edits a real project and real pytest decides the outcome; the persisted
session is then collected, approved, built into a dataset, planned for training, and the
adapter a trainer would produce is registered, gated, promoted and rolled back - all through
the CLI. Two things are necessarily stand-ins, and are named as such: the adapter files
(nothing here trains) and the golden-suite report (producing a real one needs a live model
serving the adapter).
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from aica.adaptation import AdapterRegistry, CandidateStore
from aica.agent.loop import STATE_KEY, AgentLoop
from aica.approvals import AllowAllApprover
from aica.audit import AuditLog, InMemoryAuditSink
from aica.chat.session import Session, SessionStore
from aica.cli import main
from aica.evaluation.metrics import Provenance, SuiteReport, TaskResult
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.tools import ToolContext, default_registry
from aica.workspace import GitGuard, WorkspaceGuard

pytestmark = pytest.mark.integration

MODELS = """default = "coder"

[[models]]
name = "coder"
provider = "openai_compatible"
family = "coder"
version = "coder-2026-06-01"
base_url = "https://models.example/v1"
api_key_env = "CODER_KEY"
context_window = 32000
capabilities = ["chat", "tools"]
status = "approved"
"""


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "config").mkdir()
    (root / "src" / "__init__.py").write_text("", encoding="utf-8")
    (root / "src" / "calc.py").write_text(
        "def ratio(values):\n    return values[0] / values[1]\n", encoding="utf-8"
    )
    (root / "tests" / "test_calc.py").write_text(
        "import pytest\n\nfrom src.calc import ratio\n\n\n"
        "def test_ratio():\n    assert ratio([6, 3]) == 2\n\n\n"
        "def test_short():\n    with pytest.raises(ValueError):\n        ratio([1])\n",
        encoding="utf-8",
    )
    (root / "config" / "policy.toml").write_text(
        "version = 1\n[adaptation]\ncollection_enabled = true\nmin_training_examples = 1\n",
        encoding="utf-8",
    )
    (root / "config" / "models.toml").write_text(MODELS, encoding="utf-8")
    for args in (
        ["git", "init", "-q", "-b", "work"],
        ["git", "config", "user.email", "agent@example.com"],
        ["git", "config", "user.name", "Agent"],
        ["git", "add", "-A"],
        ["git", "commit", "-qm", "initial"],
    ):
        subprocess.run(args, cwd=root, check=True)
    return root


def _genuine_run(root: Path) -> str:
    """A real agent run: real edit, real pytest. Persisted exactly as `aica task` would."""
    policy = Policy()
    ws = WorkspaceGuard(root, policy.autonomy.allowed_directories)
    git = GitGuard(ws.root, policy.git)
    ctx = ToolContext(
        workspace=ws,
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="dana"),
        git=git if git.is_repository() else None,
        approver=AllowAllApprover(),
    )
    # The runner is left to test discovery, as an agent normally does. A command spelling
    # out an interpreter path under a home directory would - correctly - be excluded.
    plan = {
        "summary": "guard short input, then verify",
        "steps": [
            {
                "intent": "add the length guard",
                "tool": "fs.edit",
                "arguments": {
                    "path": "src/calc.py",
                    "old_text": "    return values[0] / values[1]",
                    "new_text": "    if len(values) < 2:\n        raise ValueError('two values')\n    return values[0] / values[1]",
                },
            },
            {
                "intent": "run the suite",
                "tool": "test.run",
                "arguments": {"kind": "unit"},
            },
        ],
        "verification": ["unit"],
    }
    loop = AgentLoop(ScriptedAdapter([json.dumps(plan)]), default_registry())
    report = loop.run("make ratio reject short input", ctx)
    assert report.outcome() == "SUCCESS", report.render()
    assert loop.state is not None
    session = Session(workspace=str(root), owner="dana")
    session.task_state[STATE_KEY] = loop.state.to_json()
    SessionStore(root).save(session)
    return session.session_id


def run(root: Path, *args: str) -> int:
    return main(
        [
            "-w",
            str(root),
            "--policy",
            str(root / "config" / "policy.toml"),
            "--models-file",
            str(root / "config" / "models.toml"),
            *args,
        ]
    )


def test_from_a_real_agent_run_to_a_promoted_and_rolled_back_adapter(
    project: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _genuine_run(project)

    assert run(project, "adapt", "collect") == 0
    assert "1 pending approval, 0 excluded" in capsys.readouterr().out
    (candidate,) = CandidateStore(project).all()
    assert candidate["trajectory"]["verification"] == {"unit": "passed"}
    assert run(project, "adapt", "approve", candidate["id"]) == 0

    assert run(project, "adapt", "dataset") == 0
    dataset = capsys.readouterr().out.split("dataset ")[1].split(":")[0]

    assert (
        run(project, "adapt", "plan", "--name", "guards", "--base", "coder", "--dataset", dataset)
        == 0
    )
    spec = json.loads(capsys.readouterr().out)
    assert spec["base_model"]["version"] == "coder-2026-06-01" and spec["produces"] == "adapter"

    # Stand-in for what the trainer would write.
    artifact = tmp_path / "trained"
    artifact.mkdir()
    (artifact / "adapter_model.safetensors").write_bytes(b"stand-in weights")
    assert (
        run(
            project,
            "adapt",
            "register",
            "--job",
            spec["config_version"],
            "--serving-id",
            "coder-guards",
            "--artifact",
            str(artifact),
        )
        == 0
    )
    capsys.readouterr()

    # Stand-in for `aica eval run --adapter guards@1 --out report.json` against a live model.
    report = SuiteReport(
        provenance=Provenance(
            model="coder",
            model_version="coder-2026-06-01",
            adapter="coder-guards",
            suite="golden",
            suite_checksum="rev1",
        ),
        results=[
            TaskResult(
                task="guard-short-list@v1",
                kind="agent",
                checksum="a",
                passed=True,
                duration_ms=5,
                tool_calls=3,
            ),
            TaskResult(
                task="parameterize-sql-query@v1",
                kind="agent",
                checksum="b",
                passed=True,
                duration_ms=5,
                tool_calls=3,
                tags=["python", "security"],
            ),
        ],
    ).save(tmp_path / "report.json")
    assert run(project, "adapt", "evaluate", "guards@1", "--report", str(report)) == 0
    assert "gate_passed" in capsys.readouterr().out

    assert run(project, "adapt", "promote", "guards@1") == 0
    assert "coder now serves coder-guards" in capsys.readouterr().out
    assert run(project, "adapt", "status") == 0
    assert "* guards@1" in capsys.readouterr().out

    assert run(project, "adapt", "rollback", "coder") == 0
    assert "the base model, with no adapter" in capsys.readouterr().out
    assert AdapterRegistry(project).active_for("coder") is None
