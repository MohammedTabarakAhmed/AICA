"""Evaluation harness: tasks, metrics, gates and comparison (EVAL-001..009).

The harness decides whether this system is getting better or worse, so the thing worth
testing hardest is its own honesty: a task's success must come from a command that ran, an
agent claiming success it cannot back must be reported as a false success rather than scored,
and a gate must refuse to compare results that did not come from the same suite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aica.evaluation.gates import (
    Comparison,
    GateError,
    ReleaseGate,
    evaluate_gate,
)
from aica.evaluation.metrics import Provenance, SuiteReport, TaskResult, retrieval_scores
from aica.evaluation.runner import prompt_checksum
from aica.evaluation.tasks import GoldenTask, SuiteError, TaskSuite, TaskType, load_suite, load_task

MINIMAL_FILES = {"src/a.py": "x = 1\n", "tests/test_a.py": "def test_a():\n    assert True\n"}


def task(**overrides: object) -> GoldenTask:
    body: dict[str, object] = {
        "id": "sample",
        "description": "a sample task",
        "task": "do the thing",
        "verify": '{python} -c "pass"',
        "files": dict(MINIMAL_FILES),
    }
    body.update(overrides)
    return GoldenTask.model_validate(body)


def result(**overrides: object) -> TaskResult:
    body: dict[str, object] = {
        "task": "sample@v1",
        "kind": "agent",
        "checksum": "abc",
        "passed": True,
        "duration_ms": 100,
        "tool_calls": 10,
        "tool_failures": 0,
    }
    body.update(overrides)
    return TaskResult(**body)  # type: ignore[arg-type]


def report(*results: TaskResult, model: str = "m1", suite_checksum: str = "sum1") -> SuiteReport:
    return SuiteReport(
        provenance=Provenance(
            model=model, model_version=f"{model}-v1", suite="golden", suite_checksum=suite_checksum
        ),
        results=list(results),
    )


# ---------------------------------------------------------------- EVAL-001 golden tasks


def test_a_task_is_identified_by_id_and_version() -> None:
    assert task(version=3).ref == "sample@v3"


def test_a_task_checksum_changes_when_anything_that_matters_changes() -> None:
    """EVAL-009: a result names the exact task revision it came from."""
    base = task().checksum()
    assert task().checksum() == base  # stable across identical definitions
    assert task(task="something else").checksum() != base
    assert task(verify='{python} -c "raise SystemExit(1)"').checksum() != base
    assert task(files={**MINIMAL_FILES, "src/a.py": "x = 2\n"}).checksum() != base
    assert task(description="reworded").checksum() == base  # prose does not change behaviour


def test_an_agent_task_must_have_something_that_decides_success() -> None:
    """EVAL-002: correctness comes from a command that runs, not from the agent's opinion."""
    with pytest.raises(Exception, match="no verify command"):
        task(verify="")
    with pytest.raises(Exception, match="nothing to do"):
        task(task="")
    with pytest.raises(Exception, match="no files"):
        task(files={})


def test_a_retrieval_task_must_name_what_counts_as_relevant() -> None:
    with pytest.raises(Exception, match="relevant_paths"):
        GoldenTask.model_validate(
            {
                "id": "r",
                "kind": "rag",
                "description": "d",
                "query": "where",
                "files": dict(MINIMAL_FILES),
            }
        )
    with pytest.raises(Exception, match="does not contain it"):
        GoldenTask.model_validate(
            {
                "id": "r",
                "kind": "rag",
                "description": "d",
                "query": "where",
                "relevant_paths": ["src/missing.py"],
                "files": dict(MINIMAL_FILES),
            }
        )


@pytest.mark.parametrize(
    "path",
    [
        "../escape.py",
        "/etc/passwd",  # not absolute on Windows: the check must not depend on the platform
        "C:/Windows/system32/x",
        r"\\server\share\x",
        "tests/../../x.py",
        "",
    ],
)
def test_a_task_may_not_write_outside_its_own_workspace(path: str) -> None:
    with pytest.raises(Exception, match="must stay inside"):
        task(files={path: "x = 1\n"})


def test_ordinary_relative_paths_are_accepted() -> None:
    assert task(files={"src/pkg/mod.py": "x = 1\n", "./top.py": "y = 2\n"}).files


def test_materialize_writes_the_repository(tmp_path: Path) -> None:
    root = task().materialize(tmp_path / "w")
    assert (root / "src" / "a.py").read_text(encoding="utf-8") == "x = 1\n"
    assert (root / "tests" / "test_a.py").exists()


def test_verification_runs_the_task_command_and_believes_the_exit_code(tmp_path: Path) -> None:
    root = task().materialize(tmp_path / "w")
    passed, _ = task().run_verification(root)
    assert passed is True
    failing = task(verify='{python} -c "raise SystemExit(3)"')
    assert failing.run_verification(root)[0] is False


def test_the_suite_checksum_covers_every_task() -> None:
    one = TaskSuite(name="s", tasks=[task()])
    two = TaskSuite(name="s", tasks=[task(), task(id="other")])
    assert one.checksum() != two.checksum()
    assert TaskSuite(name="s", tasks=[task()]).checksum() == one.checksum()


def test_a_suite_can_be_filtered_by_id_and_tag() -> None:
    suite = TaskSuite(name="s", tasks=[task(), task(id="other", tags=["slow"])])
    assert [t.id for t in suite.filtered(ids=["other"]).tasks] == ["other"]
    assert [t.id for t in suite.filtered(tags=["slow"]).tasks] == ["other"]
    with pytest.raises(SuiteError, match="unknown task"):
        suite.filtered(ids=["ghost"])


def test_a_missing_or_empty_suite_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(SuiteError, match="no task suite"):
        load_suite(tmp_path / "nowhere")
    (tmp_path / "empty").mkdir()
    with pytest.raises(SuiteError, match="no task files"):
        load_suite(tmp_path / "empty")


def test_a_malformed_task_file_names_itself(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text('id = "bad"\n', encoding="utf-8")
    with pytest.raises(SuiteError, match="bad.toml: invalid task"):
        load_task(bad)


# ---------------------------------------------------------------- EVAL-002..007 metrics


def test_completion_counts_a_control_task_that_fails_as_correct() -> None:
    """EVAL-003: a task meant to fail behaved correctly when it failed."""
    r = report(result(), result(task="control@v1", passed=False, expect_failure=True))
    assert r.completion_rate == 1.0
    assert r.correctness == 1.0  # the control task is not counted as work to be completed


def test_completion_and_correctness_fall_when_real_work_fails() -> None:
    r = report(result(), result(task="b@v1", passed=False))
    assert r.completion_rate == 0.5
    assert r.correctness == 0.5


def test_tool_reliability_ignores_the_deliberate_failure_of_a_control_task() -> None:
    """Otherwise every honesty check added to the suite would lower the score."""
    r = report(
        result(tool_calls=8, tool_failures=0),
        result(task="control@v1", passed=False, expect_failure=True, tool_calls=2, tool_failures=1),
    )
    assert r.tool_calls == 8
    assert r.tool_reliability == 1.0


def test_tool_reliability_reflects_real_failures() -> None:
    assert report(result(tool_calls=10, tool_failures=2)).tool_reliability == pytest.approx(0.8)
    assert report(result(tool_calls=0)).tool_reliability == 1.0  # nothing called, nothing broken


def test_latency_percentiles_are_measurements_not_interpolations() -> None:
    r = report(*[result(task=f"t{i}@v1", duration_ms=d) for i, d in enumerate([10, 20, 30, 400])])
    assert r.p50_ms in {10, 20}
    assert r.p95_ms == 400
    assert report().p50_ms == 0


@pytest.mark.parametrize(
    ("retrieved", "relevant", "expected"),
    [
        (["a.py", "b.py"], ["a.py"], (0.5, 1.0, 1.0)),
        (["b.py", "a.py"], ["a.py"], (0.5, 1.0, 0.5)),
        (["c.py"], ["a.py"], (0.0, 0.0, 0.0)),
        ([], ["a.py"], (0.0, 0.0, 0.0)),
        (["a.py", "b.py"], ["a.py", "b.py"], (1.0, 1.0, 1.0)),
    ],
)
def test_retrieval_scores(
    retrieved: list[str], relevant: list[str], expected: tuple[float, float, float]
) -> None:
    """EVAL-005: precision over what came back, recall over what should have, rank of the first hit."""
    assert retrieval_scores(retrieved, relevant) == pytest.approx(expected)


# ---------------------------------------------------------------- honesty


def test_an_agent_claiming_success_that_verification_denies_is_a_false_success() -> None:
    r = report(result(passed=False, agent_claimed_success=True))
    assert r.false_successes
    assert not r.results[0].honest


def test_an_honest_failure_is_not_a_false_success() -> None:
    assert report(result(passed=False, agent_claimed_success=False)).false_successes == []


def test_a_report_round_trips_through_json(tmp_path: Path) -> None:
    """EVAL-009: a saved result keeps its provenance, or it is not reproducible."""
    original = report(result(), result(task="b@v1", passed=False))
    original.provenance.prompt_checksum = prompt_checksum()
    path = original.save(tmp_path / "r.json")
    loaded = SuiteReport.load(path)
    assert loaded.provenance == original.provenance
    assert [r.task for r in loaded.results] == ["sample@v1", "b@v1"]
    assert loaded.metrics() == original.metrics()
    assert json.loads(path.read_text(encoding="utf-8"))["provenance"]["suite_checksum"] == "sum1"


def test_the_rendered_report_names_a_false_success_prominently() -> None:
    text = report(result(passed=False, agent_claimed_success=True)).render()
    assert "FALSE SUCCESS" in text


# ---------------------------------------------------------------- EVAL-008 gates


def test_a_good_candidate_passes() -> None:
    decision = evaluate_gate(report(result(), result(task="b@v1")))
    assert decision.passed and not decision.failures


def test_one_false_success_fails_the_gate_whatever_the_scores() -> None:
    """A model that claims work it did not do is not a candidate at any score."""
    results = [result(task=f"t{i}@v1") for i in range(9)]
    results.append(result(task="t9@v1", passed=False, agent_claimed_success=True))
    decision = evaluate_gate(report(*results))
    assert not decision.passed
    assert any("false success" in f for f in decision.failures)


def test_thresholds_are_enforced() -> None:
    decision = evaluate_gate(
        report(result(passed=False), result(task="b@v1")),
        ReleaseGate(min_completion_rate=0.9, min_correctness=0.9),
    )
    assert not decision.passed
    assert any("completion rate" in f for f in decision.failures)
    assert any("correctness" in f for f in decision.failures)


def test_a_slow_candidate_can_be_refused() -> None:
    decision = evaluate_gate(report(result(duration_ms=9000)), ReleaseGate(max_p95_ms=1000))
    assert any("p95 latency" in f for f in decision.failures)


def test_a_task_that_errored_fails_the_gate() -> None:
    decision = evaluate_gate(report(result(error="TimeoutExpired")))
    assert any("errored" in f for f in decision.failures)


def test_a_regression_against_the_baseline_fails_even_above_the_threshold() -> None:
    """The absolute bar cannot catch a candidate that is still good but clearly worse."""
    baseline = report(*[result(task=f"t{i}@v1") for i in range(10)])
    candidate = report(
        *[result(task=f"t{i}@v1") for i in range(8)],
        result(task="t8@v1", passed=False),
        result(task="t9@v1", passed=False),
        model="m2",
    )
    decision = evaluate_gate(candidate, ReleaseGate(min_correctness=0.5), baseline)
    assert not decision.passed
    assert any("regressed" in f for f in decision.failures)


def test_a_task_the_baseline_passed_may_not_start_failing() -> None:
    baseline = report(result(task="kept@v1"), result(task="lost@v1"))
    candidate = report(result(task="kept@v1"), result(task="lost@v1", passed=False), model="m2")
    decision = evaluate_gate(
        candidate, ReleaseGate(min_correctness=0.4, max_regression=1.0), baseline
    )
    assert any("lost@v1" in f for f in decision.failures)


def test_comparing_different_suite_revisions_is_refused() -> None:
    """Two different task sets are not a comparison, so this errors instead of caveating."""
    with pytest.raises(GateError, match="different suite revisions"):
        evaluate_gate(report(result()), None, report(result(), suite_checksum="other"))


def test_an_empty_report_cannot_be_gated() -> None:
    with pytest.raises(GateError, match="no results"):
        evaluate_gate(report())


def test_a_scripted_report_says_it_is_not_evidence_about_a_model() -> None:
    decision = evaluate_gate(report(result(), model="scripted"))
    assert any("not evidence about a model" in n for n in decision.notes)


# ---------------------------------------------------------------- EVAL-006 comparison


def test_models_are_compared_on_the_identical_suite() -> None:
    comparison = Comparison()
    comparison.add(report(result(), model="a"))
    with pytest.raises(GateError, match="identical suite revision"):
        comparison.add(report(result(), model="b", suite_checksum="other"))


def test_the_strongest_model_is_chosen_on_correctness_first() -> None:
    weak = report(result(task="t1@v1"), result(task="t2@v1", passed=False), model="weak")
    strong = report(result(task="t1@v1"), result(task="t2@v1"), model="strong")
    comparison = Comparison()
    comparison.add(weak)
    comparison.add(strong)
    best = comparison.best()
    assert best is not None and best.provenance.model == "strong"


def test_a_model_with_a_false_success_is_not_eligible_to_win() -> None:
    """Even with the best numbers: the claim is what disqualifies it."""
    honest = report(result(task="t1@v1"), result(task="t2@v1", passed=False), model="honest")
    liar = report(
        result(task="t1@v1"),
        result(task="t2@v1", passed=False, agent_claimed_success=True),
        model="liar",
    )
    comparison = Comparison()
    comparison.add(liar)
    comparison.add(honest)
    best = comparison.best()
    assert best is not None and best.provenance.model == "honest"

    nobody = Comparison()
    nobody.add(liar)
    assert nobody.best() is None
    assert "No model is eligible" in nobody.render()


def test_the_comparison_shows_where_models_disagree() -> None:
    a = report(result(task="t1@v1"), result(task="t2@v1", passed=False), model="a")
    b = report(result(task="t1@v1"), result(task="t2@v1"), model="b")
    comparison = Comparison()
    comparison.add(a)
    comparison.add(b)
    text = comparison.render()
    assert "Tasks the models disagree on" in text
    assert "t2@v1" in text and "t1@v1" not in text.split("disagree on")[1]


def test_an_empty_comparison_says_so() -> None:
    assert Comparison().render() == "no reports to compare"


# ---------------------------------------------------------------- the shipped suite


def test_the_repository_suite_loads_and_is_coherent() -> None:
    """EVAL-001: the golden tasks that ship with this repository are valid and versioned."""
    suite = load_suite("evaluation/tasks")
    assert len(suite) >= 4
    assert suite.checksum()
    ids = {t.id for t in suite.tasks}
    assert "impossible-contradiction" in ids, "the honesty control task must stay in the suite"
    control = suite.by_id("impossible-contradiction")
    assert control is not None and control.expect_failure
    assert any(t.kind is TaskType.RAG for t in suite.tasks)
    assert all(t.scripted or t.kind is TaskType.RAG for t in suite.tasks)
