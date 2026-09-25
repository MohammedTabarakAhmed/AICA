"""Evaluation and continuous improvement (EVAL-001..EVAL-009)."""

from aica.evaluation.gates import (
    Comparison,
    GateDecision,
    GateError,
    ReleaseGate,
    evaluate_gate,
)
from aica.evaluation.metrics import Provenance, SuiteReport, TaskResult, retrieval_scores
from aica.evaluation.runner import Evaluator, router_factory, scripted_factory
from aica.evaluation.tasks import (
    DEFAULT_SUITE_DIR,
    GoldenTask,
    SuiteError,
    TaskSuite,
    TaskType,
    load_suite,
    load_task,
)

__all__ = [
    "DEFAULT_SUITE_DIR",
    "Comparison",
    "Evaluator",
    "GateDecision",
    "GateError",
    "GoldenTask",
    "Provenance",
    "ReleaseGate",
    "SuiteError",
    "SuiteReport",
    "TaskResult",
    "TaskSuite",
    "TaskType",
    "evaluate_gate",
    "load_suite",
    "load_task",
    "retrieval_scores",
    "router_factory",
    "scripted_factory",
]
