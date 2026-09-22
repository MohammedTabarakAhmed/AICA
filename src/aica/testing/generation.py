"""Test generation for existing code (TEST-007).

Generation is advisory: this module returns a proposed test file, it never writes one.
Writing goes through ``fs.write``, which applies the workspace guard, the uncommitted-change
check (GIT-010) and audit. That keeps generated tests on the same approval path as any
other change.

The proposal is grounded three ways so the output fits the project rather than a generic
template: the target source is supplied verbatim, the project's detected conventions are
included (CC-004), and an existing test file is passed as a style exemplar when one exists.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from aica.models.base import ChatMessage, ModelAdapter
from aica.safety.injection import wrap_untrusted
from aica.safety.redaction import redact

MAX_SOURCE_CHARS = 20_000
MAX_EXEMPLAR_CHARS = 6_000

GENERATION_SYSTEM = """You write tests for an existing codebase.

Rules:
- Test the behaviour that the given source actually has. Never invent functions, modules or
  attributes that are not in the source or its imports.
- Cover the normal path, the boundary cases and the error/exception paths.
- Follow the project's existing test framework, imports, naming and layout exactly.
- Tests must be deterministic and must not reach the network, a database or the clock.
- Output the complete test file only: no explanation, no markdown fences."""

_FENCE_OPEN = re.compile(r"^```[\w-]*\n")
_FENCE_CLOSE = re.compile(r"\n```$")

# Per-language test path and framework conventions.
_LAYOUTS: dict[str, tuple[str, str]] = {
    ".py": ("pytest", "test_{stem}.py"),
    ".ts": ("vitest/jest", "{stem}.test.ts"),
    ".tsx": ("vitest/jest", "{stem}.test.tsx"),
    ".js": ("vitest/jest", "{stem}.test.js"),
    ".go": ("go test", "{stem}_test.go"),
    ".rs": ("cargo test", "{stem}_test.rs"),
    ".java": ("JUnit", "{stem}Test.java"),
}


class GenerationError(RuntimeError):
    """The model produced nothing usable for the requested target (TEST-007)."""


@dataclass(frozen=True)
class GeneratedTests:
    """A proposed test file. Nothing has been written to disk."""

    target_path: str  # the source file the tests cover
    test_path: str  # suggested path for the test file
    framework: str
    content: str
    model: str
    exists: bool = False  # a test file already exists at test_path

    def render(self) -> str:
        header = f"# proposed tests for {self.target_path} -> {self.test_path} [{self.framework}]"
        if self.exists:
            header += "\n# NOTE: this file already exists; review before overwriting (GIT-010)"
        return f"{header}\n{self.content}"


def suggest_test_path(source_path: str | Path, root: str | Path | None = None) -> tuple[str, str]:
    """Return (suggested test path, framework) for a source file, following project layout."""
    source = Path(str(source_path).replace("\\", "/"))
    framework, template = _LAYOUTS.get(source.suffix.lower(), ("pytest", "test_{stem}.py"))
    filename = template.format(stem=_stem_for(source, framework))
    # Go, Rust and Java keep tests next to (or mirroring) the source; others use tests/.
    if source.suffix.lower() in {".go", ".rs"}:
        return (source.parent / filename).as_posix(), framework
    if root is not None and (Path(root) / "tests").is_dir():
        return f"tests/{filename}", framework
    if source.parts and source.parts[0] in {"src", "lib", "app"}:
        return Path("tests", *source.parts[1:-1], filename).as_posix(), framework
    return (source.parent / filename).as_posix(), framework


def _stem_for(source: Path, framework: str) -> str:
    if framework == "JUnit":
        return source.stem[:1].upper() + source.stem[1:]
    return source.stem


def _strip_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = _FENCE_OPEN.sub("", stripped, count=1)
        stripped = _FENCE_CLOSE.sub("", stripped)
        if stripped.endswith("```"):
            stripped = stripped[:-3].rstrip()
    return stripped


def find_exemplar(root: str | Path, test_path: str) -> tuple[str, str] | None:
    """Find an existing test file to copy style from. Returns (path, content)."""
    root = Path(root)
    suffix = Path(test_path).suffix
    directory = root / Path(test_path).parent
    candidates = sorted(directory.glob(f"*{suffix}")) if directory.is_dir() else []
    for candidate in candidates:
        if candidate.name == Path(test_path).name or not candidate.is_file():
            continue
        try:
            content = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if content.strip():
            return (
                candidate.relative_to(root).as_posix(),
                content[:MAX_EXEMPLAR_CHARS],
            )
    return None


def generate_tests(
    adapter: ModelAdapter,
    source_path: str | Path,
    source_code: str,
    *,
    root: str | Path | None = None,
    conventions: str = "",
    focus: str = "",
    max_tokens: int = 2000,
) -> GeneratedTests:
    """TEST-007: propose a test file for ``source_path``.

    ``source_code`` is fenced as untrusted content: source under test may contain comments
    that read like instructions, and they are data (SAFE-007).
    """
    if not source_code.strip():
        raise GenerationError(f"{source_path}: source is empty; nothing to test")
    test_path, framework = suggest_test_path(source_path, root)
    display = Path(str(source_path).replace("\\", "/")).as_posix()

    parts = [
        f"Write tests for `{display}`.",
        f"Test framework: {framework}.",
        f"Write them to `{test_path}`.",
    ]
    if conventions.strip():
        parts.append(conventions.strip())
    if focus.strip():
        parts.append(f"Focus on: {focus.strip()}")
    exemplar = find_exemplar(root, test_path) if root is not None else None
    if exemplar is not None:
        parts.append(
            f"Existing test file `{exemplar[0]}` shows the project's test style; follow it:\n"
            + wrap_untrusted(exemplar[1], f"exemplar:{exemplar[0]}")
        )
    parts.append("Source under test:\n" + wrap_untrusted(source_code[:MAX_SOURCE_CHARS], display))

    response = adapter.chat(
        [
            ChatMessage(role="system", content=GENERATION_SYSTEM),
            ChatMessage(role="user", content="\n\n".join(parts)),
        ],
        temperature=0.1,
        max_tokens=max_tokens,
    )
    content = _strip_fences(redact(response.content).text)
    if not content.strip():
        raise GenerationError(f"{display}: model returned no test content")
    exists = root is not None and (Path(root) / test_path).exists()
    return GeneratedTests(
        target_path=display,
        test_path=test_path,
        framework=framework,
        content=content,
        model=response.model,
        exists=exists,
    )
