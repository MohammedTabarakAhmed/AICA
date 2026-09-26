import json
from pathlib import Path

from aica.testing import (
    CheckStatus,
    VerificationLedger,
    analyze_failures,
    commands_for,
    discover,
    parse_output,
)
from aica.tools import default_registry
from tests.test_tools_fs import make_ctx

PYTEST_FAIL = """============================= test session starts =============================
collected 5 items

tests/test_math.py ..F..                                                 [100%]

================================== FAILURES ===================================
____________________________ test_division ____________________________
tests/test_math.py:14: in test_division
    assert divide(1, 0) == 0
E   ZeroDivisionError: division by zero
=========================== short test summary info ===========================
FAILED tests/test_math.py::test_division - ZeroDivisionError: division by zero
========================= 1 failed, 4 passed in 0.31s =========================
"""

PYTEST_PASS = "===== 12 passed, 2 skipped in 1.10s =====\nTOTAL   552   16   97%\n"


# ---------------------------------------------------------------- discovery


def test_discovers_pytest_from_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname="x"\n[tool.ruff]\n[tool.mypy]\n[tool.pytest.ini_options]\n',
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    cmds = discover(tmp_path)
    kinds = {c.kind: c for c in cmds}
    assert "unit" in kinds and "pytest" in kinds["unit"].command
    assert "lint" in kinds and "ruff" in kinds["lint"].command
    assert "typecheck" in kinds and "mypy" in kinds["typecheck"].command
    assert all(c.reason for c in cmds)  # every choice is justified


def test_prefers_project_venv_python(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options]\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    venv = tmp_path / ".venv" / "bin"
    venv.mkdir(parents=True)
    (venv / "python").write_text("", encoding="utf-8")
    expected = f"{Path('.venv', 'bin', 'python')} -m pytest"
    assert expected in discover(tmp_path)[0].command


def test_discovers_node_scripts(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps(
            {
                "scripts": {
                    "test": "vitest run",
                    "test:e2e": "playwright test",
                    "lint": "eslint .",
                },
                "devDependencies": {"@playwright/test": "^1"},
            }
        ),
        encoding="utf-8",
    )
    cmds = {c.kind: c.command for c in discover(tmp_path)}
    assert cmds["unit"] == "npm run test"
    assert cmds["e2e"] == "npm run test:e2e"
    assert cmds["lint"] == "npm run lint"


def test_discovers_go_rust_maven(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    assert any(c.command == "go test -v ./..." for c in discover(tmp_path))
    (tmp_path / "go.mod").unlink()
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
    assert any(c.command == "cargo test --no-fail-fast" for c in discover(tmp_path))
    (tmp_path / "Cargo.toml").unlink()
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    assert any("mvn" in c.command for c in discover(tmp_path))


def test_no_false_discovery_in_empty_repo(tmp_path: Path) -> None:
    assert discover(tmp_path) == []


def test_kind_filter(tmp_path: Path) -> None:
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    assert all(c.kind == "lint" for c in commands_for(tmp_path, ["lint"]))


# ---------------------------------------------------------------- parsing


def test_parse_pytest_failure() -> None:
    o = parse_output("unit", "pytest", PYTEST_FAIL, "", 1)
    assert o.status is CheckStatus.FAILED and not o.ok
    assert o.passed == 4 and o.failed == 1
    assert o.failures[0].test == "test_division"
    assert o.failures[0].file == "tests/test_math.py"
    assert "ZeroDivisionError" in o.failures[0].message
    assert "test_division" in analyze_failures(o)


def test_parse_pytest_pass_with_coverage() -> None:
    o = parse_output("unit", "pytest", PYTEST_PASS, "", 0)
    assert o.ok and o.passed == 12 and o.skipped == 2
    assert o.coverage_percent == 97.0


def test_failing_counts_override_zero_exit_code() -> None:
    """A runner that exits 0 while reporting failures must not be believed (TEST-009)."""
    o = parse_output("unit", "pytest", "== 1 failed, 3 passed ==", "", 0)
    assert o.status is CheckStatus.FAILED and not o.ok


def test_parse_jest_and_maven_and_cargo() -> None:
    jest = parse_output(
        "unit", "npm test", "Tests:       2 failed, 1 skipped, 7 passed, 10 total", "", 1
    )
    assert jest.failed == 2 and jest.passed == 7 and jest.skipped == 1
    mvn = parse_output(
        "unit", "mvn test", "Tests run: 10, Failures: 1, Errors: 1, Skipped: 2", "", 1
    )
    assert mvn.failed == 2 and mvn.skipped == 2 and mvn.passed == 6
    cargo = parse_output(
        "unit", "cargo test", "test result: FAILED. 3 passed; 1 failed; 2 ignored", "", 101
    )
    assert cargo.passed == 3 and cargo.failed == 1 and cargo.skipped == 2


def test_timeout_is_error_not_failure() -> None:
    o = parse_output("unit", "pytest", "", "", None)
    assert o.status is CheckStatus.ERROR


# ---------------------------------------------------------------- TEST-009 ledger


def test_ledger_blocks_success_until_all_checks_pass() -> None:
    led = VerificationLedger()
    led.require("unit")
    led.require("lint")
    assert not led.can_report_success
    assert "VERIFICATION INCOMPLETE" in led.disclosure()

    led.record(parse_output("unit", "pytest", PYTEST_PASS, "", 0))
    assert not led.can_report_success  # lint still not run
    assert "lint: not_run" in led.disclosure()

    led.record(parse_output("lint", "ruff check", "All checks passed!", "", 0))
    assert led.can_report_success
    assert "All required verification passed" in led.disclosure()


def test_failure_then_fix_clears_the_check() -> None:
    led = VerificationLedger()
    led.require("unit")
    led.record(parse_output("unit", "pytest", PYTEST_FAIL, "", 1))
    assert not led.can_report_success
    led.record(parse_output("unit", "pytest", PYTEST_PASS, "", 0))
    assert led.can_report_success


def test_later_failure_overrides_earlier_pass() -> None:
    led = VerificationLedger()
    led.require("unit")
    led.record(parse_output("unit", "pytest", PYTEST_PASS, "", 0))
    led.record(parse_output("unit", "pytest", PYTEST_FAIL, "", 1))
    assert not led.can_report_success


def test_skipped_check_is_disclosed_not_hidden() -> None:
    led = VerificationLedger()
    led.require("e2e")
    led.skip("e2e", "no browser available in this environment")
    assert not led.can_report_success
    assert "e2e: skipped" in led.disclosure()
    assert "no browser available" in led.disclosure()


def test_empty_ledger_cannot_claim_success() -> None:
    led = VerificationLedger()
    assert not led.can_report_success
    assert "No verification" in led.disclosure()


# ---------------------------------------------------------------- tools


def test_test_tools_discover_and_run(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[tool.pytest.ini_options]\ntestpaths=['tests']\n", encoding="utf-8"
    )
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_ok.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n", encoding="utf-8")
    ctx = make_ctx(tmp_path)
    reg = default_registry()
    disc = reg.call("test.discover", {}, ctx)
    assert any(c["kind"] == "unit" for c in disc.data["commands"])
    import sys

    res = reg.call("test.run", {"command": f"{sys.executable} -m pytest -q", "kind": "unit"}, ctx)
    assert res.ok and res.data["passed"] == 1 and res.data["status"] == "passed"


def test_test_tool_reports_failures_with_locations(tmp_path: Path) -> None:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_bad.py").write_text("def test_bad():\n    assert 1 == 2\n", encoding="utf-8")
    ctx = make_ctx(tmp_path)
    import sys

    res = default_registry().call(
        "test.run", {"command": f"{sys.executable} -m pytest -q", "kind": "unit"}, ctx
    )
    assert not res.ok and res.data["failed"] == 1
    assert res.data["failures"][0]["test"] == "test_bad"
    assert "test_bad" in res.data["analysis"]


def test_a_run_where_no_tests_ran_shows_why_and_the_discovered_command(tmp_path: Path) -> None:
    """Found live: `python -m pytest` hit an interpreter without pytest, the tool said only
    "0 passed, 0 failed", and the model guessed its way to a `pip install`."""
    import sys

    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_ok.py").write_text("def test_ok():\n    pass\n", encoding="utf-8")
    broken = (
        f'"{sys.executable}" -c "import sys; '
        "sys.stderr.write('No module named pytest'); sys.exit(1)\""
    )
    res = default_registry().call(
        "test.run", {"command": broken, "kind": "unit"}, make_ctx(tmp_path)
    )
    assert not res.ok
    assert "No tests ran" in res.output
    assert "No module named pytest" in res.output
    assert "omit `command` to use it" in res.output  # the discovered command is offered
