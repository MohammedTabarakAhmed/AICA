"""`aica review` and POST /review over a real git repository (REV-001..007).

The unit tests in ``test_review.py`` exercise the reviewer against a diff string. These
drive the surfaces end to end: a real working tree, a real ``git diff``, the real CLI
argument parsing and exit codes, and the real ASGI app. Only the model is scripted.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.cli import main

fastapi_testclient = pytest.importorskip("fastapi.testclient", reason="the api extra is needed")
TestClient = fastapi_testclient.TestClient

TOKEN = "test-token-abcdefghijklmnop"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

ORIGINAL = "def total(items):\n    return sum(i.price for i in items)\n"
CHANGED = (
    "def total(items):\n"
    "    return sum(i.price * i.quantity for i in items)\n"
    "\n"
    "def connect(user_id):\n"
    '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
)

FINDINGS = json.dumps(
    [
        {
            "file": "src/invoice.py",
            "line": 2,
            "severity": "high",
            "category": "bug",
            "title": "quantity may be absent on legacy items",
            "detail": "Items created before the migration have no quantity attribute.",
            "suggestion": "Default the quantity to 1.",
        }
    ]
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "invoice.py").write_text(ORIGINAL, encoding="utf-8")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n", encoding="utf-8"
    )
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "init")
    (tmp_path / "src" / "invoice.py").write_text(CHANGED, encoding="utf-8")
    return tmp_path


def run(repo: Path, *args: str) -> int:
    return main(["-w", str(repo), "--policy", str(repo / "config" / "policy.toml"), *args])


@pytest.fixture
def scripted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route every model call to a scripted adapter that returns FINDINGS then empty."""
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    monkeypatch.setattr(
        ModelGateway,
        "get",
        lambda self, name=None: ScriptedAdapter(
            [FINDINGS, "[]", "[]", "[]", "Fix the quantity default before merging."],
            name="review-model",
        ),
    )


# ---------------------------------------------------------------------- CLI
def test_cli_review_reports_findings_and_exits_2(
    repo: Path, scripted: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """A high-severity finding is a non-zero exit, so a pre-merge hook can gate on it."""
    assert run(repo, "review", "--no-summary") == 2
    out = capsys.readouterr().out
    assert "src/invoice.py:2" in out
    assert "quantity may be absent" in out
    # The static security scan found the interpolated SQL without being asked to.
    assert "CWE-89" in out
    assert "## CRITICAL" in out and "## HIGH" in out


def test_cli_review_exit_code_respects_fail_on(
    repo: Path, scripted: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert (
        run(repo, "review", "--check", "conventions", "--fail-on", "critical", "--no-summary") == 0
    )
    capsys.readouterr()


def test_cli_review_json_output_is_machine_readable(
    repo: Path, scripted: None, capsys: pytest.CaptureFixture[str]
) -> None:
    run(repo, "review", "--json", "--no-summary")
    payload = json.loads(capsys.readouterr().out)
    assert payload["complete"] is True
    assert payload["files_reviewed"] == ["src/invoice.py"]
    assert set(payload["by_file"]) == {"src/invoice.py"}
    assert payload["counts"]["critical"] >= 1
    assert all(f["location"].startswith("src/invoice.py:") for f in payload["findings"])


def test_cli_review_with_no_changes_is_clean(
    repo: Path, scripted: None, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "src" / "invoice.py").write_text(ORIGINAL, encoding="utf-8")
    assert run(repo, "review") == 0
    assert "no changes to review" in capsys.readouterr().err


def test_cli_review_without_a_model_still_runs_static_checks(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The network policy denies the model; the deterministic checks still report.

    Exit 6, not 2: the static findings are real, but the correctness and convention
    checks did not run, so this is an incomplete review and must not be reported as a
    pass either way.
    """
    assert run(repo, "review", "--no-summary") == 6
    captured = capsys.readouterr()
    assert "model unavailable" in captured.err
    assert "CWE-89" in captured.out  # the static scan still ran
    assert "model: none" in captured.out
    assert "INCOMPLETE" in captured.out


def test_cli_review_static_only_checks_are_complete_without_a_model(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Asking only for the checks that need no model gives a complete review."""
    assert run(repo, "review", "--check", "security", "--check", "tests", "--no-summary") == 2
    out = capsys.readouterr().out
    assert "INCOMPLETE" not in out
    assert "CWE-89" in out


def test_cli_review_strict_fails_when_no_model_is_available(
    repo: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(repo, "review", "--strict") == 6
    assert "--strict forbids" in capsys.readouterr().err


def test_cli_review_exits_6_when_a_check_could_not_run(
    repo: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """An incomplete review is not a passing review, and has its own exit code."""
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    monkeypatch.setattr(
        ModelGateway,
        "get",
        lambda self, name=None: ScriptedAdapter(["not json at all"] * 6, name="broken-model"),
    )
    assert run(repo, "review", "--no-summary") == 6
    assert "INCOMPLETE" in capsys.readouterr().out


def test_cli_review_writes_nothing_and_is_audited(repo: Path, scripted: None) -> None:
    before = (repo / "src" / "invoice.py").read_text(encoding="utf-8")
    status_before = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout
    run(repo, "review", "--no-summary")
    assert (repo / "src" / "invoice.py").read_text(encoding="utf-8") == before
    status_after = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout
    # `.aica/` appears because the review was audited; no tracked file changed.
    tracked = [line for line in status_after.splitlines() if ".aica" not in line]
    assert tracked == status_before.splitlines()

    events = [
        json.loads(line)
        for path in sorted((repo / ".aica" / "audit").glob("*.jsonl"))
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    review_events = [e for e in events if e["action"] == "review.completed"]
    assert len(review_events) == 1
    assert review_events[0]["details"]["complete"] is True
    assert review_events[0]["outcome"] == "success"


# ---------------------------------------------------------------------- HTTP
@pytest.fixture
def client(repo: Path, scripted: None) -> Iterator[TestClient]:
    from aica.api.app import ApiSettings, create_app

    app = create_app(
        ApiSettings(
            workspace=repo,
            policy_file=str(repo / "config" / "policy.toml"),
            token=TOKEN,
        )
    )
    with TestClient(app) as test_client:
        yield test_client


def test_review_endpoint_requires_a_token(client: TestClient) -> None:
    assert client.post("/review", json={}).status_code == 401


def test_review_endpoint_reviews_the_working_tree(client: TestClient) -> None:
    response = client.post("/review", json={"summarize": False}, headers=HEADERS)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["complete"] is True
    assert payload["files_reviewed"] == ["src/invoice.py"]
    assert any(f["category"] == "security" for f in payload["findings"])
    assert all(f["line"] > 0 for f in payload["findings"])
    assert payload["model_selection"].startswith("review:")


def test_review_endpoint_accepts_a_supplied_diff(client: TestClient) -> None:
    diff = (
        "diff --git a/src/invoice.py b/src/invoice.py\n"
        "--- a/src/invoice.py\n+++ b/src/invoice.py\n"
        "@@ -1,2 +1,2 @@\n def total(items):\n-    return 0\n+    return sum(i.price for i in items)\n"
    )
    response = client.post(
        "/review",
        json={"diff": diff, "checks": ["correctness"], "summarize": False},
        headers=HEADERS,
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["checks_run"] == ["correctness"]
    assert payload["files_reviewed"] == ["src/invoice.py"]


def test_review_endpoint_rejects_an_unknown_check(client: TestClient) -> None:
    response = client.post("/review", json={"checks": ["vibes"]}, headers=HEADERS)
    assert response.status_code == 422


def test_review_endpoint_reports_incompleteness_rather_than_an_empty_pass(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from aica.api.app import ApiSettings, create_app
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    monkeypatch.setattr(
        ModelGateway,
        "get",
        lambda self, name=None: ScriptedAdapter(["nonsense"] * 6, name="broken-model"),
    )
    app = create_app(
        ApiSettings(workspace=repo, policy_file=str(repo / "config" / "policy.toml"), token=TOKEN)
    )
    with TestClient(app) as client:
        payload = client.post(
            "/review", json={"checks": ["correctness"], "summarize": False}, headers=HEADERS
        ).json()
    assert payload["complete"] is False
    assert "correctness" in payload["checks_failed"]


# ------------------------------------------------- untracked files (REV-001, new files)
def test_review_includes_new_untracked_files(
    repo: Path, scripted: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """An agent's most common output is a new file, which `git diff` cannot see."""
    (repo / "src" / "shipping.py").write_text(
        "def rate(weight):\n    if weight <= 0:\n        raise ValueError(weight)\n    return weight * 2\n",
        encoding="utf-8",
    )
    run(repo, "review", "--json", "--no-summary")
    captured = capsys.readouterr()
    assert "including 1 untracked file(s)" in captured.err
    payload = json.loads(captured.out)
    assert "src/shipping.py" in payload["files_reviewed"]
    # It is reviewed as a real change: the test-adequacy check reports on it.
    assert any(f["file"] == "src/shipping.py" for f in payload["findings"])


def test_no_untracked_flag_excludes_new_files(
    repo: Path, scripted: None, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "src" / "shipping.py").write_text("def rate(w):\n    return w\n", encoding="utf-8")
    run(repo, "review", "--json", "--no-summary", "--no-untracked")
    payload = json.loads(capsys.readouterr().out)
    assert payload["files_reviewed"] == ["src/invoice.py"]


def test_reviewing_untracked_files_does_not_stage_them(repo: Path, scripted: None) -> None:
    """Synthesising the diff must not touch the index (GIT-010)."""
    (repo / "src" / "shipping.py").write_text("def rate(w):\n    return w\n", encoding="utf-8")
    run(repo, "review", "--no-summary")
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, check=True
    ).stdout
    assert "?? src/shipping.py" in status  # still untracked, not staged as "A "
    staged = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert staged.strip() == ""


def test_binary_untracked_files_are_skipped_not_mangled(
    repo: Path, scripted: None, capsys: pytest.CaptureFixture[str]
) -> None:
    (repo / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x01\x02\xff\xfe")
    run(repo, "review", "--json", "--no-summary")
    payload = json.loads(capsys.readouterr().out)
    assert "logo.png" not in payload["files_reviewed"]


def test_review_endpoint_includes_untracked_files_by_default(
    repo: Path, client: TestClient
) -> None:
    (repo / "src" / "shipping.py").write_text(
        "def rate(weight):\n    return weight * 2\n", encoding="utf-8"
    )
    payload = client.post("/review", json={"summarize": False}, headers=HEADERS).json()
    assert "src/shipping.py" in payload["files_reviewed"]
