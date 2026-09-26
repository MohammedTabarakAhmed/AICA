"""Practice runs (BRD 13): real agent runs kept only when independently verified."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aica.adaptation.curation import CandidateStore
from aica.adaptation.practice import (
    PRACTICE_KEY,
    UsageMeter,
    check_disjoint,
    run_practice,
)
from aica.agent.loop import STATE_KEY
from aica.chat.session import SessionStore
from aica.cli import main
from aica.evaluation.tasks import SuiteError, TaskSuite, load_suite, load_task
from aica.models.base import ModelResponse, Usage
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.policy.models import AdaptationPolicy

GOLDEN = Path(__file__).parents[1] / "evaluation" / "tasks"
TRAINING = Path(__file__).parents[1] / "evaluation" / "training"
FIX = json.loads(load_task(GOLDEN / "guard-short-list.toml").scripted[0])


def _task(task_id: str, plan: dict[str, object]) -> TaskSuite:
    """guard-short-list under another id, with the given plan as the model's reply."""
    base = load_task(GOLDEN / "guard-short-list.toml")
    task = base.model_copy(update={"id": task_id, "scripted": [json.dumps(plan)]})
    return TaskSuite(name="training", tasks=[task])


def _policy() -> Policy:
    return Policy(adaptation=AdaptationPolicy(collection_enabled=True))


def test_a_verified_run_is_kept_as_a_session_the_collector_reads(tmp_path: Path) -> None:
    suite = _task("train-ratio", FIX)
    report = run_practice(
        tmp_path, suite, lambda: ScriptedAdapter(list(suite.tasks[0].scripted)), _policy(), "ops"
    )

    [outcome] = report.outcomes
    assert outcome.passed and outcome.session_id and outcome.model == "scripted-model-v0"
    session = SessionStore(tmp_path).load(outcome.session_id)
    assert session.owner == "ops" and STATE_KEY in session.task_state
    meta = json.loads(session.task_state[PRACTICE_KEY])
    assert meta["task"] == "train-ratio@v1" and "passed" in meta["verification"]
    assert not (tmp_path / ".aica" / "adaptation" / "practice").exists() or not any(
        (tmp_path / ".aica" / "adaptation" / "practice").iterdir()
    )  # throwaway workspaces are removed

    policy = _policy()
    counts = CandidateStore(tmp_path).collect(policy, policy.principal("ops"))
    assert counts["found"] == 1 and counts["pending"] == 1  # passes the screen too
    assert "1/1 run(s) passed" in report.summary()


def test_a_run_that_does_not_fix_the_code_is_not_kept(tmp_path: Path) -> None:
    lazy = {
        "summary": "look and stop",
        "steps": [{"intent": "read", "tool": "fs.read", "arguments": {"path": "src/calc.py"}}],
        "verification": [],
    }
    suite = _task("train-lazy", lazy)
    report = run_practice(
        tmp_path, suite, lambda: ScriptedAdapter(list(suite.tasks[0].scripted)), _policy(), "ops"
    )
    [outcome] = report.outcomes
    assert not outcome.passed and outcome.session_id is None
    assert SessionStore(tmp_path).list_sessions() == []


def test_training_tasks_may_not_be_golden_tasks() -> None:
    golden = load_suite(GOLDEN)
    same_id = TaskSuite(name="t", tasks=[golden.tasks[0]])
    with pytest.raises(SuiteError, match="own exam"):
        check_disjoint(same_id, golden)
    renamed = golden.tasks[0].model_copy(update={"id": "sneaky-copy"})
    if renamed.checksum() == golden.tasks[0].checksum():  # id is outside the checksum
        with pytest.raises(SuiteError, match="duplicate"):
            check_disjoint(TaskSuite(name="t", tasks=[renamed]), golden)
    check_disjoint(load_suite(TRAINING, name="training"), golden)  # the shipped set is clean


def test_the_shipped_training_tasks_fail_as_shipped(tmp_path: Path) -> None:
    for task in load_suite(TRAINING, name="training").tasks:
        root = tmp_path / task.id
        task.materialize(root)
        passed, _ = task.run_verification(root)
        assert not passed, f"{task.id} passes before any fix; the agent would learn nothing"


def test_the_meter_counts_tokens_from_real_responses() -> None:
    class Counting(ScriptedAdapter):
        def chat(self, messages, *, temperature=0.2, max_tokens=None):  # type: ignore[no-untyped-def]
            return ModelResponse(
                content="ok",
                model="m",
                finish_reason="stop",
                usage=Usage(prompt_tokens=100, completion_tokens=20),
            )

    meter = UsageMeter(Counting())
    meter.chat([])
    meter.chat([])
    assert (meter.calls, meter.prompt_tokens, meter.completion_tokens) == (2, 200, 40)


def test_the_cli_refuses_to_practise_on_the_golden_suite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["-w", str(tmp_path), "adapt", "practice", "--tasks", str(GOLDEN)])
    assert code == 2
    assert "own exam" in capsys.readouterr().err
