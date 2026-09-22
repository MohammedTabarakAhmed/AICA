"""Test-command discovery (TEST-001).

Commands are discovered from what the repository actually contains — never assumed.
Each candidate records why it was chosen so the agent can report its reasoning.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TestCommand:
    kind: str  # unit | integration | e2e | lint | typecheck | build
    command: str
    framework: str
    reason: str  # the evidence that selected it
    cwd: str = "."


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _python_runner(root: Path) -> str:
    """Prefer the project virtual environment so tests run against project dependencies.

    The interpreter path is rendered with the platform separator: cmd.exe does not accept
    a forward-slash path as the leading token of a command.
    """
    for parts in ((".venv", "Scripts", "python.exe"), (".venv", "bin", "python")):
        if (root / Path(*parts)).exists():
            return f"{Path(*parts)} -m"
    return "python -m"


def discover(root: str | Path) -> list[TestCommand]:
    root = Path(root)
    found: list[TestCommand] = []
    pyproject = root / "pyproject.toml"
    py = _python_runner(root)

    # ---- Python
    if pyproject.exists():
        content = _read(pyproject)
        if "pytest" in content or (root / "tests").is_dir() or (root / "test").is_dir():
            found.append(
                TestCommand("unit", f"{py} pytest", "pytest", "pyproject.toml/tests directory")
            )
        for directory in ("tests/integration", "tests/integration_tests", "integration_tests"):
            if (root / directory).is_dir():
                found.append(
                    TestCommand(
                        "integration",
                        f"{py} pytest {directory}",
                        "pytest",
                        f"{directory} directory present",
                    )
                )
                break
        for directory in ("tests/e2e", "tests/end_to_end"):
            if (root / directory).is_dir():
                found.append(
                    TestCommand(
                        "e2e",
                        f"{py} pytest {directory}",
                        "pytest",
                        f"{directory} directory present",
                    )
                )
                break
        if "ruff" in content:
            found.append(
                TestCommand(
                    "lint", f"{py} ruff check .", "ruff", "ruff configured in pyproject.toml"
                )
            )
        if "mypy" in content:
            found.append(
                TestCommand("typecheck", f"{py} mypy", "mypy", "mypy configured in pyproject.toml")
            )
    elif (root / "tests").is_dir() and list(root.glob("**/test_*.py"))[:1]:
        found.append(TestCommand("unit", f"{py} pytest", "pytest", "test_*.py files present"))
    if (root / "tox.ini").exists():
        found.append(TestCommand("integration", "tox", "tox", "tox.ini present"))
    if (root / "manage.py").exists():
        found.append(
            TestCommand(
                "unit", f"{py.replace(' -m', '')} manage.py test", "django", "manage.py present"
            )
        )

    # ---- Node / TypeScript
    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(_read(pkg) or "{}")
        except json.JSONDecodeError:
            data = {}
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        runner = "npm run"
        if (root / "pnpm-lock.yaml").exists():
            runner = "pnpm run"
        elif (root / "yarn.lock").exists():
            runner = "yarn"
        for script, kind in (
            ("test", "unit"),
            ("test:unit", "unit"),
            ("test:integration", "integration"),
            ("test:e2e", "e2e"),
            ("e2e", "e2e"),
            ("lint", "lint"),
            ("typecheck", "typecheck"),
            ("build", "build"),
        ):
            if script in scripts:
                cmd = f"{runner} {script}" if runner != "yarn" else f"yarn {script}"
                found.append(TestCommand(kind, cmd, "npm-script", f"package.json scripts.{script}"))
        deps = (
            {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            if isinstance(data, dict)
            else {}
        )
        if "@playwright/test" in deps and not any(f.kind == "e2e" for f in found):
            found.append(
                TestCommand(
                    "e2e", "npx playwright test", "playwright", "@playwright/test dependency"
                )
            )
        if "vitest" in deps and not any(
            f.framework == "npm-script" and f.kind == "unit" for f in found
        ):
            found.append(TestCommand("unit", "npx vitest run", "vitest", "vitest dependency"))
        if "jest" in deps and not any(f.kind == "unit" for f in found):
            found.append(TestCommand("unit", "npx jest", "jest", "jest dependency"))

    # ---- JVM
    if (root / "pom.xml").exists():
        found.append(TestCommand("unit", "mvn -B test", "maven", "pom.xml present"))
        if "failsafe" in _read(root / "pom.xml"):
            found.append(
                TestCommand(
                    "integration", "mvn -B verify", "maven-failsafe", "failsafe plugin in pom.xml"
                )
            )
    if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        wrapper = "./gradlew" if (root / "gradlew").exists() else "gradle"
        found.append(TestCommand("unit", f"{wrapper} test", "gradle", "build.gradle present"))

    # ---- Go / Rust
    if (root / "go.mod").exists():
        found.append(TestCommand("unit", "go test ./...", "go-test", "go.mod present"))
        found.append(TestCommand("lint", "go vet ./...", "go-vet", "go.mod present"))
    if (root / "Cargo.toml").exists():
        found.append(TestCommand("unit", "cargo test", "cargo", "Cargo.toml present"))
        found.append(
            TestCommand("lint", "cargo clippy -- -D warnings", "clippy", "Cargo.toml present")
        )

    # ---- Make
    makefile = root / "Makefile"
    if makefile.exists():
        targets = set(re.findall(r"^([A-Za-z0-9_.-]+):", _read(makefile), re.M))
        for target, kind in (
            ("test", "unit"),
            ("integration-test", "integration"),
            ("e2e", "e2e"),
            ("lint", "lint"),
        ):
            if target in targets and not any(f.kind == kind for f in found):
                found.append(
                    TestCommand(kind, f"make {target}", "make", f"Makefile target {target}")
                )

    # De-duplicate by command, keeping first (most specific) occurrence.
    seen: set[str] = set()
    unique: list[TestCommand] = []
    for f in found:
        if f.command not in seen:
            seen.add(f.command)
            unique.append(f)
    return unique


def commands_for(root: str | Path, kinds: list[str] | None = None) -> list[TestCommand]:
    cmds = discover(root)
    if kinds:
        return [c for c in cmds if c.kind in kinds]
    return cmds
