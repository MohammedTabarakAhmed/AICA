"""Golden coding tasks (EVAL-001): versioned, self-contained, diffable.

A golden task is a small real repository plus the work to do in it and the command that
decides whether the work is done. Everything lives in one TOML file - the source files
inline - for three reasons:

* it is **versioned** with the code, so a task's history is visible in Git (EVAL-001);
* it is **self-contained**, so running the suite never depends on a fixture directory
  someone edited by hand;
* it carries its own **checksum**, so a result can name the exact task revision that
  produced it (EVAL-009).

The command in ``verify`` is what decides success - not the agent's own report. That is the
whole point of EVAL-002: correctness is measured by tests actually passing, in a workspace
this harness created, run as a separate process after the agent says it is finished.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

DEFAULT_SUITE_DIR = Path("evaluation/tasks")
MAX_FILE_CHARS = 20_000
MAX_FILES = 40
# The interpreter running the harness, substituted into a task's verify command so a task
# never hard-codes "python" and never reaches outside the environment it was started in.
PYTHON_PLACEHOLDER = "{python}"


def _is_contained(path: str) -> bool:
    """True when ``path`` can only ever land inside the task's own workspace.

    Both path flavours are checked, not just this platform's. ``Path("/etc/passwd")`` is *not*
    absolute on Windows, so a task authored there would validate happily and then escape when
    the suite ran on Linux. A golden task is a file people copy and edit, so the check has to
    hold wherever it ends up.
    """
    if not path or path.strip() != path.strip("/\\"):
        return False
    for flavour in (PurePosixPath, PureWindowsPath):
        candidate = flavour(path)
        if candidate.is_absolute() or candidate.anchor:
            return False
        if ".." in candidate.parts:
            return False
    return True


class TaskType(StrEnum):
    AGENT = "agent"  # the agent loop does work; tests decide success (EVAL-002/003)
    RAG = "rag"  # retrieval only; known relevant files decide quality (EVAL-005)


class SuiteError(RuntimeError):
    """A suite or task file could not be used."""


class GoldenTask(BaseModel):
    """One versioned task. ``extra="forbid"`` so a typo in a task file fails loudly."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9-]*$")
    version: int = Field(default=1, ge=1)
    kind: TaskType = TaskType.AGENT
    description: str = Field(min_length=1, max_length=500)
    tags: list[str] = Field(default_factory=list)

    # What the agent is told to do (AGENT tasks).
    task: str = ""
    # The command that decides success. Run in the task's workspace, as its own process.
    verify: str = ""
    verify_kind: str = "unit"
    # Bounds for this task's run, so one task cannot consume the whole suite's time.
    max_steps: int = Field(default=15, ge=1, le=200)
    max_seconds: int = Field(default=300, ge=1, le=3600)

    # What the retrieval is asked (RAG tasks), and which files genuinely answer it.
    query: str = ""
    relevant_paths: list[str] = Field(default_factory=list)
    retrieve: int = Field(default=5, ge=1, le=50)

    # The repository this task runs in: path -> contents.
    files: dict[str, str] = Field(default_factory=dict)
    # Canned model replies, used only when the suite is run against the scripted adapter to
    # test the harness itself. They are never used with a real model.
    #
    # These are JSON documents, so {python} is NOT substituted here - only in `verify`, which
    # is a shell string. An interpreter path spliced into encoded JSON breaks it on Windows,
    # where the path contains backslashes, and the plan then fails to parse.
    scripted: list[str] = Field(default_factory=list)
    # True when this task is expected to FAIL: a task the agent cannot complete, kept so the
    # harness is shown to report failure rather than inventing success (TEST-009).
    expect_failure: bool = False

    @model_validator(mode="after")
    def _coherent(self) -> GoldenTask:
        if len(self.files) > MAX_FILES:
            raise ValueError(
                f"task {self.id!r} has {len(self.files)} files; the limit is {MAX_FILES}"
            )
        for path, content in self.files.items():
            if not _is_contained(path):
                raise ValueError(f"task {self.id!r}: file path {path!r} must stay inside the task")
            if len(content) > MAX_FILE_CHARS:
                raise ValueError(f"task {self.id!r}: file {path!r} is too large for a golden task")
        if self.kind is TaskType.AGENT:
            if not self.task.strip():
                raise ValueError(f"task {self.id!r} is an agent task with nothing to do")
            if not self.verify.strip():
                raise ValueError(
                    f"task {self.id!r} has no verify command; correctness must be decided by "
                    "something that runs, not by the agent's own report (EVAL-002)"
                )
            if not self.files:
                raise ValueError(f"task {self.id!r} has no files to work on")
        if self.kind is TaskType.RAG:
            if not self.query.strip():
                raise ValueError(f"task {self.id!r} is a retrieval task with no query")
            if not self.relevant_paths:
                raise ValueError(
                    f"task {self.id!r} has no relevant_paths, so retrieval quality cannot be "
                    "measured against anything (EVAL-005)"
                )
            missing = [p for p in self.relevant_paths if p not in self.files]
            if missing:
                raise ValueError(
                    f"task {self.id!r} calls {', '.join(missing)} relevant but does not contain it"
                )
        return self

    @property
    def ref(self) -> str:
        """How a result names this task: id plus version, so revisions never blur together."""
        return f"{self.id}@v{self.version}"

    def checksum(self) -> str:
        """EVAL-009: a fingerprint of everything that affects the outcome."""
        digest = hashlib.sha256()
        for part in (
            self.id,
            str(self.version),
            self.kind.value,
            self.task,
            self.verify,
            self.query,
        ):
            digest.update(part.encode("utf-8"))
            digest.update(b"\x00")
        for path in sorted(self.files):
            digest.update(path.encode("utf-8"))
            digest.update(b"\x00")
            digest.update(self.files[path].encode("utf-8"))
            digest.update(b"\x00")
        for path in sorted(self.relevant_paths):
            digest.update(path.encode("utf-8"))
        return digest.hexdigest()[:16]

    def materialize(self, root: Path) -> Path:
        """Write this task's repository into ``root``. Nothing is shared between runs."""
        root.mkdir(parents=True, exist_ok=True)
        for path, content in self.files.items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        return root

    def verify_command(self) -> str:
        """The verify command with the running interpreter substituted in."""
        return self.verify.replace(PYTHON_PLACEHOLDER, f'"{sys.executable}"')

    def run_verification(self, root: Path, timeout: float | None = None) -> tuple[bool, str]:
        """Run the task's own command in its workspace. Exit code 0 is success, nothing else.

        This deliberately does not consult the agent's report. An agent that says it is done
        and a suite that is green are two different claims, and only the second one counts.
        """
        if not self.verify.strip():
            return False, "no verify command"
        try:
            done = subprocess.run(  # noqa: S602 - the command comes from a versioned task file
                self.verify_command(),
                cwd=root,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout or self.max_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return False, f"verification timed out after {timeout or self.max_seconds}s"
        except OSError as exc:
            return False, f"verification could not run: {exc}"
        output = (done.stdout + done.stderr)[-4000:]
        return done.returncode == 0, output


@dataclass
class TaskSuite:
    """A versioned set of golden tasks (EVAL-001)."""

    name: str
    tasks: list[GoldenTask] = field(default_factory=list)
    source: str = ""

    def __len__(self) -> int:
        return len(self.tasks)

    def of_kind(self, kind: TaskType) -> list[GoldenTask]:
        return [t for t in self.tasks if t.kind is kind]

    def by_id(self, task_id: str) -> GoldenTask | None:
        return next((t for t in self.tasks if t.id == task_id), None)

    def filtered(self, ids: list[str] | None = None, tags: list[str] | None = None) -> TaskSuite:
        tasks = list(self.tasks)
        if ids:
            unknown = set(ids) - {t.id for t in tasks}
            if unknown:
                raise SuiteError(f"unknown task(s): {', '.join(sorted(unknown))}")
            tasks = [t for t in tasks if t.id in set(ids)]
        if tags:
            wanted = set(tags)
            tasks = [t for t in tasks if wanted & set(t.tags)]
        return TaskSuite(name=self.name, tasks=tasks, source=self.source)

    def checksum(self) -> str:
        """EVAL-009: the suite fingerprint a result is recorded against."""
        digest = hashlib.sha256()
        for task in sorted(self.tasks, key=lambda t: t.id):
            digest.update(f"{task.ref}:{task.checksum()}".encode())
        return digest.hexdigest()[:16]

    def describe(self) -> str:
        lines = [f"{self.name}: {len(self.tasks)} task(s), suite checksum {self.checksum()}"]
        for task in self.tasks:
            flags = " [expected to fail]" if task.expect_failure else ""
            lines.append(f"  {task.ref:<28} {task.kind.value:<6} {task.description}{flags}")
        return "\n".join(lines)


def load_task(path: str | Path) -> GoldenTask:
    target = Path(path)
    try:
        raw: dict[str, Any] = tomllib.loads(target.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise SuiteError(f"{target}: could not read task: {exc}") from exc
    try:
        return GoldenTask.model_validate(raw)
    except Exception as exc:
        raise SuiteError(f"{target}: invalid task: {exc}") from exc


def load_suite(directory: str | Path | None = None, name: str = "golden") -> TaskSuite:
    """Load every ``*.toml`` in ``directory``. A missing directory is an error, not silence."""
    root = Path(directory or DEFAULT_SUITE_DIR)
    if not root.is_dir():
        raise SuiteError(f"no task suite at {root}")
    tasks = [load_task(p) for p in sorted(root.glob("*.toml"))]
    if not tasks:
        raise SuiteError(f"{root} contains no task files")
    duplicates = {t.id for t in tasks if [x.id for x in tasks].count(t.id) > 1}
    if duplicates:
        raise SuiteError(f"duplicate task id(s) in {root}: {', '.join(sorted(duplicates))}")
    return TaskSuite(name=name, tasks=tasks, source=str(root))


def git_available() -> bool:
    return shutil.which("git") is not None
