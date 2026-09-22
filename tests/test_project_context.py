"""CC-004 (project conventions) and MEM-004 (persisted project context)."""

from pathlib import Path

from aica.chat.session import Session
from aica.models.fake import ScriptedAdapter
from aica.workspace.project_context import (
    ProjectContext,
    ProjectContextStore,
    detect_conventions,
    project_conventions_block,
)


def _python_project(root: Path) -> Path:
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "tests" / "integration").mkdir()
    (root / "src" / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8"
    )
    (root / "pyproject.toml").write_text(
        "[project]\n"
        'name = "demo"\n'
        'dependencies = ["fastapi>=0.110", "pydantic>=2"]\n\n'
        "[tool.ruff]\nline-length = 96\n\n"
        '[tool.ruff.format]\nquote-style = "single"\n\n'
        "[tool.mypy]\nstrict = true\n\n"
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n',
        encoding="utf-8",
    )
    return root


# ---------------------------------------------------------------- CC-004 detection


def test_detects_conventions_from_repository_evidence(tmp_path: Path) -> None:
    conv = detect_conventions(_python_project(tmp_path))
    assert conv.languages == ["Python"]
    assert conv.line_length == 96
    assert conv.quote_style == "single"
    assert conv.type_checked is True
    assert "ruff" in conv.tooling and "mypy" in conv.tooling
    assert "fastapi" in conv.frameworks and "pytest" in conv.frameworks
    assert conv.test_layout is not None and "integration" in conv.test_layout
    # Every reported convention names the file it was read from.
    assert conv.evidence["line_length"].startswith("pyproject.toml")


def test_editorconfig_supplies_indent_and_line_length(tmp_path: Path) -> None:
    (tmp_path / "app.ts").write_text("export const a = 1;\n", encoding="utf-8")
    (tmp_path / ".editorconfig").write_text(
        "[*]\nindent_style = tab\nmax_line_length = 120\n", encoding="utf-8"
    )
    conv = detect_conventions(tmp_path)
    assert conv.indent == "tab"
    assert conv.line_length == 120
    assert conv.evidence["indent"] == ".editorconfig"


def test_node_project_frameworks_and_tooling(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"react": "18"}, "devDependencies": {"vitest": "1", "typescript": "5"}}',
        encoding="utf-8",
    )
    conv = detect_conventions(tmp_path)
    assert "react" in conv.frameworks
    assert "vitest" in conv.tooling and "typescript" in conv.tooling
    assert conv.type_checked is True


def test_indent_measured_from_sources_when_not_declared(tmp_path: Path) -> None:
    (tmp_path / "m.py").write_text("def f():\n    return 1\n" * 5, encoding="utf-8")
    conv = detect_conventions(tmp_path)
    assert conv.indent == "4 spaces"
    assert "measured" in conv.evidence["indent"]


def test_empty_directory_reports_nothing_rather_than_guessing(tmp_path: Path) -> None:
    conv = detect_conventions(tmp_path)
    assert conv.render() == ""
    assert project_conventions_block(tmp_path) == ""


def test_malformed_pyproject_does_not_raise(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("this is [ not toml", encoding="utf-8")
    assert detect_conventions(tmp_path).line_length is None


# ---------------------------------------------------------------- MEM-004 persistence


def test_project_context_round_trips(tmp_path: Path) -> None:
    store = ProjectContextStore(tmp_path)
    ctx = store.load()
    assert ctx.conventions == []
    assert ctx.record_convention("Use pytest, never unittest") is True
    assert ctx.record_convention("Use pytest, never unittest") is False  # no duplicates
    assert ctx.record_convention("   ") is False
    ctx.set_preference("commit_style", "imperative subject")
    path = store.save(ctx)
    assert path.exists()

    reloaded = ProjectContextStore(tmp_path).load()
    assert reloaded.conventions == ["Use pytest, never unittest"]
    assert reloaded.preferences["commit_style"] == "imperative subject"


def test_corrupt_context_file_falls_back_to_empty(tmp_path: Path) -> None:
    store = ProjectContextStore(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("{not json", encoding="utf-8")
    assert store.load().conventions == []


def test_context_survives_a_new_session(tmp_path: Path) -> None:
    """MEM-004: project context is project-scoped, not session-scoped."""
    store = ProjectContextStore(tmp_path)
    ctx = store.load()
    ctx.record_convention("Tests live in tests/")
    store.save(ctx)
    # A fresh session knows nothing; the project context still does.
    assert Session(workspace=str(tmp_path)).turns == []
    assert "Tests live in tests/" in ProjectContextStore(tmp_path).load().render()


# ---------------------------------------------------------------- CC-004 in prompts


def test_conventions_reach_the_chat_prompt(tmp_path: Path) -> None:
    from aica.chat.assistant import CodingAssistant

    _python_project(tmp_path)
    project = ProjectContext(workspace=str(tmp_path))
    project.record_convention("Never use bare except")
    adapter = ScriptedAdapter(["done"])
    assistant = CodingAssistant(adapter, workspace_root=tmp_path, project_context=project)

    assert "Maximum line length: 96" in assistant.conventions_block
    assert "Never use bare except" in assistant.conventions_block

    assistant.ask(Session(workspace=str(tmp_path)), "how do I add a route?")
    system = adapter.calls[0][0]
    assert system.role == "system"
    assert "Maximum line length: 96" in system.content
    assert "Never use bare except" in system.content


def test_conventions_reach_the_completion_prompt(tmp_path: Path) -> None:
    from aica.chat.assistant import CodingAssistant

    _python_project(tmp_path)
    adapter = ScriptedAdapter(["    return a - b"])
    assistant = CodingAssistant(adapter, workspace_root=tmp_path)
    answer = assistant.complete("def sub(a: int, b: int) -> int:\n", path="src/app.py")
    assert answer.text == "return a - b"  # surrounding whitespace is stripped by CC-001
    assert "Maximum line length: 96" in adapter.calls[0][0].content


def test_assistant_without_workspace_has_no_convention_block() -> None:
    from aica.chat.assistant import CodingAssistant

    assert CodingAssistant(ScriptedAdapter()).conventions_block == ""
