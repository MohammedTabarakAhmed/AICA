"""Agent trajectories as training candidates, and the screen they must pass (BRD 13).

A trajectory is one agent run as the session recorded it: the task, the plan with each
step's tool, arguments and status, and which verification checks were required and how
they ended. It is extracted from the persisted ``AgentState`` rather than reconstructed from
logs, so what is collected is exactly what resumed runs rely on.

``screen`` is deliberately two different questions:

* **Quality** - did this run actually succeed? Only runs whose required verification all
  passed are candidates. An unverified run that *claimed* success is precisely the example
  a model must not learn from (TEST-009).
* **Safety** - is it safe to train on? A run is **excluded, never redacted**, if it contains
  anything that looks like a secret, touches a restricted path, ran a destructive,
  privileged or external command, or carries a prompt-injection marker. Redaction is the
  right tool for a log a person reads; for training data it is the wrong one, because a
  pattern-based redactor only removes the formats it recognises and a model memorises the
  rest.

Every rejection names its reasons, so an administrator can see why the dataset is the size
it is.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aica.agent.events import StepStatus
from aica.agent.loop import STATE_KEY, AgentState
from aica.chat.session import SessionStore
from aica.policy.models import AdaptationPolicy
from aica.safety.commands import CommandClass, classify_command
from aica.safety.injection import scan_for_injection
from aica.safety.redaction import redact
from aica.testing.results import CheckStatus

# Arguments that name a repository path, across the built-in tools.
PATH_ARGUMENTS = ("path", "source", "destination", "file", "directory", "cwd")
UNSAFE_COMMANDS = {CommandClass.DESTRUCTIVE, CommandClass.PRIVILEGED, CommandClass.EXTERNAL}
# A path inside someone's home directory names that person, which makes it personal data
# about the developer rather than anything a model should learn.
_HOME_PATH = re.compile(r"(?i)(?:\b[a-z]:[\\/]+users[\\/]+|/home/|/users/)(?!public\b)[^\\/\s\"']+")


@dataclass(frozen=True)
class Step:
    intent: str
    tool: str
    arguments: dict[str, Any]
    status: str
    # Set when the arguments were filled in after earlier steps ran (see PlanStep): what the
    # plan said, and the request that produced the rest.
    planned_arguments: dict[str, Any] | None = None
    fill_prompt: str = ""

    @property
    def deferred(self) -> bool:
        return self.planned_arguments is not None

    def to_json(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "intent": self.intent,
            "tool": self.tool,
            "arguments": self.arguments,
            "status": self.status,
        }
        if self.deferred:  # absent otherwise, so earlier runs keep their ids
            data["planned_arguments"] = self.planned_arguments
            data["fill_prompt"] = self.fill_prompt
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Step:
        planned = data.get("planned_arguments")
        return cls(
            intent=str(data["intent"]),
            tool=str(data["tool"]),
            arguments=dict(data.get("arguments", {})),
            status=str(data["status"]),
            planned_arguments=dict(planned) if isinstance(planned, dict) else None,
            fill_prompt=str(data.get("fill_prompt", "")),
        )


@dataclass(frozen=True)
class Trajectory:
    session_id: str
    owner: str | None
    task: str
    summary: str
    model: str
    steps: tuple[Step, ...]
    verification: dict[str, str]
    superseded_failures: int = 0
    unresolved_failures: int = 0

    @property
    def id(self) -> str:
        """Content-addressed: the same run always has the same id, however often seen."""
        return hashlib.sha256(self.canonical().encode("utf-8")).hexdigest()[:16]

    def canonical(self) -> str:
        return json.dumps(self.to_json(include_id=False), sort_keys=True, ensure_ascii=False)

    def to_json(self, include_id: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "session_id": self.session_id,
            "owner": self.owner,
            "task": self.task,
            "summary": self.summary,
            "model": self.model,
            "steps": [s.to_json() for s in self.steps],
            "verification": self.verification,
            "superseded_failures": self.superseded_failures,
            "unresolved_failures": self.unresolved_failures,
        }
        if include_id:
            data["id"] = self.id
        return data

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Trajectory:
        return cls(
            session_id=str(data["session_id"]),
            owner=data.get("owner"),
            task=str(data["task"]),
            summary=str(data.get("summary", "")),
            model=str(data.get("model", "")),
            steps=tuple(Step.from_json(s) for s in data.get("steps", [])),
            verification={str(k): str(v) for k, v in data.get("verification", {}).items()},
            superseded_failures=int(data.get("superseded_failures", 0)),
            unresolved_failures=int(data.get("unresolved_failures", 0)),
        )

    # The text a training example would contain, for the safety scans.
    def texts(self) -> list[str]:
        out = [self.task, self.summary]
        for step in self.steps:
            out.append(step.intent)
            out.append(json.dumps(step.arguments, ensure_ascii=False))
            if step.fill_prompt:  # carries earlier results: repository content
                out.append(step.fill_prompt)
        return out


def from_state(session_id: str, owner: str | None, state: AgentState) -> Trajectory:
    plan = state.plan
    return Trajectory(
        session_id=session_id,
        owner=owner,
        task=state.task,
        summary=plan.summary,
        model=plan.model,
        steps=tuple(
            Step(
                s.intent,
                s.tool,
                dict(s.arguments),
                s.status.value,
                planned_arguments=(
                    dict(s.planned_arguments) if s.planned_arguments is not None else None
                ),
                fill_prompt=s.fill_prompt,
            )
            for s in plan.steps
            if not s.superseded
        ),
        verification={k: v.value for k, v in state.ledger.required.items()},
        superseded_failures=sum(1 for s in plan.steps if s.superseded),
        unresolved_failures=sum(
            1 for s in plan.steps if s.status is StepStatus.FAILED and not s.superseded
        ),
    )


def extract(root: str | Path) -> tuple[list[Trajectory], list[str]]:
    """Every agent run persisted in this workspace's sessions, plus unreadable ones by id."""
    store = SessionStore(Path(root))
    found: list[Trajectory] = []
    unreadable: list[str] = []
    for listed in store.list_sessions():
        session_id = listed["session_id"]
        try:
            session = store.load(session_id)
            raw = session.task_state.get(STATE_KEY)
            if not raw:
                continue
            found.append(from_state(session_id, session.owner, AgentState.from_json(raw)))
        except (KeyError, ValueError, TypeError):
            unreadable.append(session_id)
    return found, unreadable


@dataclass
class ScreenResult:
    quality: list[str] = field(default_factory=list)
    safety: list[str] = field(default_factory=list)

    @property
    def eligible(self) -> bool:
        return not self.quality and not self.safety

    @property
    def reasons(self) -> list[str]:
        return [f"quality: {r}" for r in self.quality] + [f"safety: {r}" for r in self.safety]


def _paths_in(arguments: dict[str, Any]) -> list[str]:
    return [
        str(arguments[k]).replace("\\", "/")
        for k in PATH_ARGUMENTS
        if isinstance(arguments.get(k), str)
    ]


def _restricted(path: str, patterns: list[str]) -> bool:
    candidates = {path, path.lstrip("./"), Path(path).name}
    return any(fnmatch.fnmatch(c, pattern) for c in candidates for pattern in patterns)


def screen(trajectory: Trajectory, policy: AdaptationPolicy) -> ScreenResult:
    """Decide whether a run may become a training candidate. Both lists empty = eligible."""
    result = ScreenResult()

    # ---- quality
    if not trajectory.steps:
        result.quality.append("the run has no steps")
    if not trajectory.verification:
        result.quality.append("no verification was required, so success was never shown")
    unmet = sorted(k for k, v in trajectory.verification.items() if v != CheckStatus.PASSED.value)
    if unmet:
        result.quality.append("verification did not pass: " + ", ".join(unmet))
    if trajectory.unresolved_failures:
        result.quality.append(
            f"{trajectory.unresolved_failures} step(s) failed and were not repaired"
        )
    unfinished = [s for s in trajectory.steps if s.status != StepStatus.SUCCEEDED.value]
    if unfinished and not trajectory.unresolved_failures:
        result.quality.append(f"{len(unfinished)} step(s) did not complete")

    # ---- safety: excluded, never redacted
    for text in trajectory.texts():
        found = redact(text)
        if found.redacted:
            result.safety.append("contains secret-like content (" + ", ".join(found.kinds) + ")")
            break
    for step in trajectory.steps:
        for path in _paths_in(step.arguments):
            if _restricted(path, policy.exclude_paths):
                result.safety.append(f"touches restricted path {path}")
        if step.arguments.get("allow_dirty") is True:
            # A run can ask for this where nothing enforces it (a workspace without Git); a
            # model that learned it would ask to overwrite developers' work (GIT-010).
            result.safety.append(f"overrides the uncommitted-change protection ({step.tool})")
        command = step.arguments.get("command")
        if isinstance(command, str) and command.strip():
            classification = classify_command(command)
            if classification.command_class in UNSAFE_COMMANDS:
                result.safety.append(
                    f"runs a {classification.command_class.value} command ({command[:80]})"
                )
            if classification.touches_secrets:
                result.safety.append(f"command references a secret file ({command[:80]})")
    for text in trajectory.texts():
        if _HOME_PATH.search(text):
            result.safety.append("contains a path inside a user's home directory")
            break
    for text in trajectory.texts():
        if scan_for_injection(text).findings:
            result.safety.append("carries a prompt-injection marker")
            break
    result.safety = list(dict.fromkeys(result.safety))
    return result
