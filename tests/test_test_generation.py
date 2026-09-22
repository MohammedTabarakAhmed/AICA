"""TEST-007: test generation for existing code."""

import sys
from pathlib import Path

import pytest

from aica.models.fake import ScriptedAdapter
from aica.testing.generation import (
    GenerationError,
    find_exemplar,
    generate_tests,
    suggest_test_path,
)
from aica.tools import default_registry
from tests.test_tools_fs import make_ctx

SOURCE = '''def divide(a: float, b: float) -> float:
    """Divide a by b."""
    if b == 0:
        raise ZeroDivisionError("b must not be zero")
    return a / b
'''

PROPOSED = """import pytest

from src.calc import divide


def test_divides() -> None:
    assert divide(6, 3) == 2


def test_zero_divisor_raises() -> None:
    with pytest.raises(ZeroDivisionError):
        divide(1, 0)
"""


def _project(root: Path) -> Path:
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src" / "calc.py").write_text(SOURCE, encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "demo"\n\n[tool.ruff]\nline-length = 100\n', encoding="utf-8"
    )
    return root


# ---------------------------------------------------------------- path conventions


@pytest.mark.parametrize(
    ("source", "expected", "framework"),
    [
        ("src/calc.py", "tests/test_calc.py", "pytest"),
        ("src/users.ts", "tests/users.test.ts", "vitest/jest"),
        ("pkg/store.go", "pkg/store_test.go", "go test"),
        ("src/lib.rs", "src/lib_test.rs", "cargo test"),
        ("src/main/java/Order.java", "tests/Order Test.java".replace(" ", ""), "JUnit"),
    ],
)
def test_suggested_paths_follow_language_convention(
    tmp_path: Path, source: str, expected: str, framework: str
) -> None:
    (tmp_path / "tests").mkdir()
    path, detected = suggest_test_path(source, tmp_path)
    assert (path, detected) == (expected, framework)


def test_path_mirrors_src_layout_when_no_tests_directory(tmp_path: Path) -> None:
    path, _ = suggest_test_path("src/pkg/calc.py", tmp_path)
    assert path == "tests/pkg/test_calc.py"


def test_java_test_class_is_capitalised(tmp_path: Path) -> None:
    path, framework = suggest_test_path("src/order.java", tmp_path)
    assert path.endswith("OrderTest.java") and framework == "JUnit"


# ---------------------------------------------------------------- exemplar


def test_exemplar_is_an_existing_test_file(tmp_path: Path) -> None:
    _project(tmp_path)
    (tmp_path / "tests" / "test_existing.py").write_text(
        "def test_something() -> None:\n    assert True\n", encoding="utf-8"
    )
    exemplar = find_exemplar(tmp_path, "tests/test_calc.py")
    assert exemplar is not None
    assert exemplar[0] == "tests/test_existing.py"
    assert "test_something" in exemplar[1]


def test_no_exemplar_when_no_tests_exist(tmp_path: Path) -> None:
    _project(tmp_path)
    assert find_exemplar(tmp_path, "tests/test_calc.py") is None


# ---------------------------------------------------------------- generation


def test_generated_tests_are_returned_not_written(tmp_path: Path) -> None:
    _project(tmp_path)
    adapter = ScriptedAdapter([PROPOSED])
    result = generate_tests(adapter, "src/calc.py", SOURCE, root=tmp_path)

    assert result.test_path == "tests/test_calc.py"
    assert result.framework == "pytest"
    assert result.model == "scripted-model-v0"
    assert "ZeroDivisionError" in result.content
    assert result.exists is False
    # TEST-007 is advisory: generation must not touch the filesystem.
    assert not (tmp_path / "tests" / "test_calc.py").exists()


def test_prompt_carries_source_conventions_and_exemplar(tmp_path: Path) -> None:
    _project(tmp_path)
    (tmp_path / "tests" / "test_existing.py").write_text(
        "def test_style_marker() -> None:\n    assert True\n", encoding="utf-8"
    )
    adapter = ScriptedAdapter([PROPOSED])
    generate_tests(
        adapter,
        "src/calc.py",
        SOURCE,
        root=tmp_path,
        conventions="Maximum line length: 100",
        focus="the zero divisor path",
    )
    sent = "\n".join(m.content for m in adapter.calls[0])
    assert "Maximum line length: 100" in sent
    assert "the zero divisor path" in sent
    assert "test_style_marker" in sent  # exemplar style
    assert "UNTRUSTED" in sent  # SAFE-007: source under test is data
    assert "ZeroDivisionError" in sent  # the real source, not a summary


def test_markdown_fences_are_stripped(tmp_path: Path) -> None:
    _project(tmp_path)
    adapter = ScriptedAdapter(["```python\n" + PROPOSED + "```"])
    result = generate_tests(adapter, "src/calc.py", SOURCE, root=tmp_path)
    assert result.content.startswith("import pytest")
    assert "```" not in result.content


def test_existing_test_file_is_flagged(tmp_path: Path) -> None:
    _project(tmp_path)
    (tmp_path / "tests" / "test_calc.py").write_text("# old\n", encoding="utf-8")
    result = generate_tests(ScriptedAdapter([PROPOSED]), "src/calc.py", SOURCE, root=tmp_path)
    assert result.exists is True
    assert "already exists" in result.render()


def test_empty_source_is_refused(tmp_path: Path) -> None:
    with pytest.raises(GenerationError, match="nothing to test"):
        generate_tests(ScriptedAdapter([PROPOSED]), "src/calc.py", "   ", root=tmp_path)


def test_empty_model_output_is_refused(tmp_path: Path) -> None:
    with pytest.raises(GenerationError, match="no test content"):
        generate_tests(ScriptedAdapter(["   "]), "src/calc.py", SOURCE, root=tmp_path)


# ---------------------------------------------------------------- generated tests actually run


def test_generated_tests_pass_when_written_and_executed(tmp_path: Path) -> None:
    """The generated file is written through fs.write (approval path) and then really run."""
    _project(tmp_path)
    (tmp_path / "src" / "__init__.py").write_text("", encoding="utf-8")
    result = generate_tests(ScriptedAdapter([PROPOSED]), "src/calc.py", SOURCE, root=tmp_path)

    ctx = make_ctx(tmp_path)
    registry = default_registry()
    registry.call("fs.write", {"path": result.test_path, "content": result.content}, ctx)
    assert (tmp_path / result.test_path).exists()

    run = registry.call(
        "test.run",
        {"command": f'"{sys.executable}" -m pytest tests -q -p no:cacheprovider'},
        ctx,
    )
    assert run.ok, run.output
    assert run.data["passed"] == 2
