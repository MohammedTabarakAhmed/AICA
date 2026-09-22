"""Project conventions and persisted project context (CC-004, MEM-004).

Two things live here:

* **Detected conventions** - evidence read from the repository itself (languages present,
  build/test tooling, formatter settings such as line length and indentation, test layout).
  Detection is deterministic and never guesses: a convention is only reported when a file in
  the repository states it, and the file that stated it is recorded in ``evidence``.
* **Persisted project context** - conventions and preferences a user records for the project,
  stored in ``.aica/project.json`` so they survive across sessions (MEM-004).

Both render into one prompt block so completion and chat follow the project's conventions
rather than generic style (CC-004).
"""

from __future__ import annotations

import json
import re
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_CONTEXT_PATH = Path(".aica/project.json")

_LANGUAGES = {
    ".py": "Python",
    ".java": "Java",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".sql": "SQL",
}
_SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".aica",
}
_MAX_SCAN_FILES = 4000
_KNOWN_PY_FRAMEWORKS = {
    "django",
    "fastapi",
    "flask",
    "pydantic",
    "sqlalchemy",
    "httpx",
    "starlette",
    "celery",
}


@dataclass
class Conventions:
    """Conventions read out of the repository (CC-004)."""

    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    tooling: list[str] = field(default_factory=list)
    line_length: int | None = None
    indent: str | None = None  # "tab" or "<n> spaces"
    quote_style: str | None = None
    test_layout: str | None = None
    type_checked: bool = False
    evidence: dict[str, str] = field(default_factory=dict)

    def render(self) -> str:
        """The prompt block. Empty when nothing was detected, so no noise is added."""
        lines: list[str] = []
        if self.languages:
            lines.append(f"Languages: {', '.join(self.languages)}")
        if self.frameworks:
            lines.append(f"Frameworks/libraries: {', '.join(self.frameworks)}")
        if self.tooling:
            lines.append(f"Tooling: {', '.join(self.tooling)}")
        if self.line_length:
            lines.append(f"Maximum line length: {self.line_length}")
        if self.indent:
            lines.append(f"Indentation: {self.indent}")
        if self.quote_style:
            lines.append(f"String quotes: {self.quote_style}")
        if self.test_layout:
            lines.append(f"Tests: {self.test_layout}")
        if self.type_checked:
            lines.append("Type annotations are required (a static type checker is configured).")
        return "\n".join(lines)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_toml(path: Path) -> dict[str, object]:
    try:
        return tomllib.loads(_read(path))
    except (tomllib.TOMLDecodeError, ValueError):
        return {}


def _skipped(root: Path, path: Path) -> bool:
    try:
        parts = path.relative_to(root).parts[:-1]
    except ValueError:
        return True
    return any(part in _SKIP_DIRS for part in parts)


def _scan_languages(root: Path) -> tuple[list[str], Counter[str]]:
    counts: Counter[str] = Counter()
    seen = 0
    for path in root.rglob("*"):
        if seen >= _MAX_SCAN_FILES:
            break
        if _skipped(root, path) or not path.is_file():
            continue
        seen += 1
        language = _LANGUAGES.get(path.suffix.lower())
        if language:
            counts[language] += 1
    return [lang for lang, _ in counts.most_common(5)], counts


def _python_conventions(root: Path, conv: Conventions) -> None:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return
    data = _load_toml(pyproject)
    raw_tools = data.get("tool")
    tools: dict[str, object] = raw_tools if isinstance(raw_tools, dict) else {}
    raw_project = data.get("project")
    project: dict[str, object] = raw_project if isinstance(raw_project, dict) else {}

    ruff = tools.get("ruff")
    if isinstance(ruff, dict):
        conv.tooling.append("ruff")
        conv.evidence["ruff"] = "pyproject.toml [tool.ruff]"
        length = ruff.get("line-length")
        if isinstance(length, int):
            conv.line_length = length
            conv.evidence["line_length"] = "pyproject.toml [tool.ruff] line-length"
        fmt = ruff.get("format")
        if isinstance(fmt, dict) and isinstance(fmt.get("quote-style"), str):
            conv.quote_style = str(fmt["quote-style"])
    black = tools.get("black")
    if isinstance(black, dict):
        conv.tooling.append("black")
        length = black.get("line-length")
        if isinstance(length, int) and conv.line_length is None:
            conv.line_length = length
            conv.evidence["line_length"] = "pyproject.toml [tool.black] line-length"
    if isinstance(tools.get("mypy"), dict):
        conv.tooling.append("mypy")
        conv.type_checked = True
        conv.evidence["mypy"] = "pyproject.toml [tool.mypy]"
    if isinstance(tools.get("pytest"), dict) or "pytest" in _read(pyproject):
        conv.frameworks.append("pytest")

    deps = project.get("dependencies")
    if isinstance(deps, list):
        for raw in deps:
            if not isinstance(raw, str):
                continue
            name = re.split(r"[<>=!~\[ ;]", raw.strip(), maxsplit=1)[0].lower()
            if name in _KNOWN_PY_FRAMEWORKS:
                conv.frameworks.append(name)
                conv.evidence.setdefault("frameworks", "pyproject.toml [project] dependencies")


def _node_conventions(root: Path, conv: Conventions) -> None:
    pkg = root / "package.json"
    if not pkg.exists():
        return
    try:
        data = json.loads(_read(pkg) or "{}")
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    for name in ("react", "next", "vue", "angular", "express", "svelte"):
        if name in deps:
            conv.frameworks.append(name)
    for name, label in (
        ("eslint", "eslint"),
        ("prettier", "prettier"),
        ("typescript", "typescript"),
        ("vitest", "vitest"),
        ("jest", "jest"),
        ("@playwright/test", "playwright"),
    ):
        if name in deps:
            conv.tooling.append(label)
    if "typescript" in deps:
        conv.type_checked = True
    conv.evidence["node"] = "package.json dependencies"


def _editorconfig(root: Path, conv: Conventions) -> None:
    text = _read(root / ".editorconfig")
    if not text:
        return
    style = re.search(r"(?m)^\s*indent_style\s*=\s*(\w+)", text)
    size = re.search(r"(?m)^\s*indent_size\s*=\s*(\d+)", text)
    if style:
        width = size.group(1) if size else "4"
        conv.indent = "tab" if style.group(1).lower() == "tab" else f"{width} spaces"
        conv.evidence["indent"] = ".editorconfig"
    limit = re.search(r"(?m)^\s*max_line_length\s*=\s*(\d+)", text)
    if limit and conv.line_length is None:
        conv.line_length = int(limit.group(1))
        conv.evidence["line_length"] = ".editorconfig"


def _test_layout(root: Path, conv: Conventions) -> None:
    for directory in ("tests", "test", "src/test/java", "spec"):
        candidate = root / directory
        if candidate.is_dir():
            layout = f"{directory}/ directory"
            if (candidate / "integration").is_dir():
                layout += f" (unit at top level, integration in {directory}/integration)"
            conv.test_layout = layout
            conv.evidence["test_layout"] = f"{directory} directory present"
            return
    if next(root.glob("**/*_test.go"), None) is not None:
        conv.test_layout = "Go tests alongside sources (*_test.go)"
    elif next(root.glob("**/*.test.ts"), None) is not None:
        conv.test_layout = "tests alongside sources (*.test.ts)"


def _indent_from_sources(root: Path, counts: Counter[str], conv: Conventions) -> None:
    """Fall back to measuring indentation in the dominant language's files."""
    if conv.indent is not None or not counts:
        return
    dominant = counts.most_common(1)[0][0]
    suffixes = {ext for ext, lang in _LANGUAGES.items() if lang == dominant}
    widths: Counter[str] = Counter()
    scanned = 0
    for path in root.rglob("*"):
        if scanned >= 40:
            break
        if path.suffix.lower() not in suffixes or _skipped(root, path) or not path.is_file():
            continue
        scanned += 1
        for line in _read(path).splitlines()[:400]:
            if line.startswith("\t"):
                widths["tab"] += 1
            elif line.startswith("  ") and line.strip():
                lead = len(line) - len(line.lstrip(" "))
                widths["2 spaces" if lead % 4 else "4 spaces"] += 1
    if widths:
        conv.indent = widths.most_common(1)[0][0]
        conv.evidence["indent"] = f"measured from {scanned} {dominant} file(s)"


def detect_conventions(root: str | Path) -> Conventions:
    """Read the project's conventions from repository evidence (CC-004)."""
    root = Path(root)
    conv = Conventions()
    languages, counts = _scan_languages(root)
    conv.languages = languages
    _python_conventions(root, conv)
    _node_conventions(root, conv)
    for marker, label in (
        ("pom.xml", "maven"),
        ("build.gradle", "gradle"),
        ("build.gradle.kts", "gradle"),
        ("go.mod", "go modules"),
        ("Cargo.toml", "cargo"),
    ):
        if (root / marker).exists():
            conv.tooling.append(label)
            conv.evidence[label] = f"{marker} present"
    _editorconfig(root, conv)
    _test_layout(root, conv)
    _indent_from_sources(root, counts, conv)
    conv.tooling = list(dict.fromkeys(conv.tooling))
    conv.frameworks = list(dict.fromkeys(conv.frameworks))
    return conv


class ProjectContext(BaseModel):
    """MEM-004: project-scoped conventions and preferences that persist across sessions."""

    model_config = ConfigDict(extra="forbid")

    workspace: str = "."
    conventions: list[str] = Field(default_factory=list)
    preferences: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)

    def record_convention(self, text: str) -> bool:
        """Add a convention; returns False when it is empty or already recorded."""
        text = text.strip()
        if not text or text in self.conventions:
            return False
        self.conventions.append(text)
        return True

    def set_preference(self, key: str, value: str) -> None:
        self.preferences[key.strip()] = value.strip()

    def render(self) -> str:
        lines: list[str] = []
        if self.conventions:
            lines.append("Recorded project conventions:")
            lines.extend(f"- {c}" for c in self.conventions)
        if self.preferences:
            lines.append("Recorded preferences:")
            lines.extend(f"- {k}: {v}" for k, v in sorted(self.preferences.items()))
        if self.notes:
            lines.append("Project notes:")
            lines.extend(f"- {n}" for n in self.notes)
        return "\n".join(lines)


class ProjectContextStore:
    """Persists :class:`ProjectContext` in ``.aica/project.json`` (MEM-004)."""

    def __init__(self, root: str | Path, path: Path | None = None) -> None:
        self.root = Path(root).resolve()
        self.path = (path or self.root / DEFAULT_CONTEXT_PATH).resolve()

    def load(self) -> ProjectContext:
        if not self.path.exists():
            return ProjectContext(workspace=str(self.root))
        try:
            return ProjectContext.model_validate_json(self.path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            # A corrupt context file must not break the assistant; start from empty.
            return ProjectContext(workspace=str(self.root))

    def save(self, context: ProjectContext) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(context.model_dump_json(indent=1), encoding="utf-8")
        return self.path


def project_conventions_block(root: str | Path, context: ProjectContext | None = None) -> str:
    """The combined CC-004/MEM-004 prompt block: detected conventions + recorded context."""
    parts = [detect_conventions(root).render()]
    if context is not None:
        parts.append(context.render())
    body = "\n".join(p for p in parts if p.strip())
    if not body:
        return ""
    return (
        "Project conventions - follow these over generic style. They were read from this "
        "repository, so they describe how code here is actually written:\n" + body
    )
