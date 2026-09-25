"""INT-003 web application, driven in a real Chromium against a real server.

The API runs under uvicorn on a loopback port; only the model is scripted. The browser signs
in, creates a session, runs a task, watches its live events, keeps one of two hunks of the
agent's edit (CC-005), and decides a pending approval (UX-008) - and the effects are checked
on disk and in the queue, not just on screen.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.admin.approval_queue import ApprovalQueue, DecisionState
from aica.approvals import ApprovalRequest
from aica.policy import ActionCategory

pytestmark = pytest.mark.integration

playwright_api = pytest.importorskip("playwright.sync_api", reason="needs the browser extra")
uvicorn = pytest.importorskip("uvicorn", reason="needs the api extra")

TOKEN = "web-ui-token-abcdefghijklmnop"
ORIGINAL = "def a():\n    return 1\n\n\ndef b():\n    return 2\n\n\ndef c():\n    return 3\n"
FINAL = "def a():\n    return 10\n\n\ndef b():\n    return 2\n\n\ndef c():\n    return 30\n"
PLAN = json.dumps(
    {
        "summary": "change a and c",
        "steps": [
            {
                "intent": "edit two functions",
                "tool": "fs.write",
                "arguments": {"path": "src/funcs.py", "content": FINAL},
            }
        ],
        "verification": [],
    }
)
HOSTILE = "<img src=x onerror=\"document.title='pwned'\">"

# CHAT-007: a pasted diff with a model-found bug and an interpolated SQL string the static
# security scan must find on its own.
REVIEW_DIFF = (
    "diff --git a/src/invoice.py b/src/invoice.py\n"
    "--- a/src/invoice.py\n"
    "+++ b/src/invoice.py\n"
    "@@ -1,2 +1,5 @@\n"
    " def total(items):\n"
    "-    return sum(i.price for i in items)\n"
    "+    return sum(i.price * i.quantity for i in items)\n"
    "+\n"
    "+def connect(user_id):\n"
    '+    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
)
REVIEW_SCRIPT = [
    json.dumps(
        [
            {
                "file": "src/invoice.py",
                "line": 2,
                "severity": "high",
                "category": "bug",
                "title": HOSTILE,
                "detail": "Items created before the migration have no quantity attribute.",
                "suggestion": "Default the quantity to 1.",
            },
            {
                "file": "src/elsewhere.py",
                "line": 9,
                "severity": "low",
                "category": "bug",
                "title": "a finding outside the change",
                "detail": "It must be discarded, and the page must say so.",
            },
        ]
    ),
    "[]",
    "[]",
    "[]",
    "Fix the quantity default before merging.",
]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "funcs.py").write_text(ORIGINAL, encoding="utf-8", newline="")
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n", encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def script() -> list[str]:
    """What the scripted model answers, in order. Tests override it by parametrizing."""
    return [PLAN]


@pytest.fixture
def server(workspace: Path, script: list[str], monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    from aica.api.app import ApiSettings, create_app
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    monkeypatch.setattr(
        ModelGateway, "get", lambda self, name=None: ScriptedAdapter(list(script), name="scripted")
    )
    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "config" / "policy.toml"),
            token=TOKEN,
            actor="reviewer",
        )
    )
    port = _free_port()
    instance = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    )
    thread = threading.Thread(target=instance.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not instance.started:
        if time.monotonic() > deadline:
            pytest.fail("the API server did not start")
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    instance.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def page(server: str) -> Iterator[object]:
    with playwright_api.sync_playwright() as pw:
        try:
            browser = pw.chromium.launch()
        except Exception as exc:  # pragma: no cover - depends on the machine
            pytest.skip(f"chromium is not installed for playwright: {exc}")
        context = browser.new_context()
        tab = context.new_page()
        problems: list[str] = []
        tab.on("console", lambda m: problems.append(m.text) if m.type == "error" else None)
        tab.on("pageerror", lambda e: problems.append(str(e)))
        tab.problems = problems  # type: ignore[attr-defined]
        yield tab
        browser.close()


def test_the_web_app_runs_a_task_and_decides_changes_and_approvals(
    server: str, page: object, workspace: Path, tmp_path: Path
) -> None:
    from playwright.sync_api import Page, expect

    assert isinstance(page, Page)
    ApprovalQueue(workspace).submit(
        ApprovalRequest(
            action="rm -rf build", categories=(ActionCategory.DESTRUCTIVE,), tool="shell.run"
        ),
        requested_by="dana",
    )

    # Sign in: "/" redirects to the page, which asks for the token.
    page.goto(server + "/")
    assert page.url.endswith("/ui/")
    expect(page.locator("#login-form")).to_be_visible()
    page.fill("#token", TOKEN)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#workspace")).to_contain_text("reviewer")

    # UX-008: the pending approval is announced before anything else is done.
    expect(page.locator("#approvals-banner")).to_contain_text("1 request")
    expect(page.locator("#approvals-badge")).to_be_visible()

    # A session and a task. The task text is hostile markup: it must render as text.
    page.click("#new-session")
    expect(page.locator("#session-pane")).to_be_visible()
    page.fill("#task-text", HOSTILE)
    page.click("#task-form button[type=submit]")
    expect(page.locator("#task-state")).to_have_text("finished", timeout=30_000)
    expect(page.locator("#task-title")).to_have_text(HOSTILE)
    assert page.title() == "AICA"
    assert page.locator("main img").count() == 0

    # UX-001..003: live events were shown; UX-009: the result is shown.
    expect(page.locator("#task-events li").first).to_be_visible()
    expect(page.locator("#report-outcome")).to_be_visible()

    # CC-005: keep the first hunk only.
    file_box = page.locator(".file", has_text="src/funcs.py")
    expect(file_box.locator(".hunk")).to_have_count(2)
    file_box.locator(".hunk input[type=checkbox]").nth(1).uncheck()
    file_box.get_by_role("button", name="Keep ticked hunks").click()
    expect(file_box.locator(".decision")).to_have_text("partial")
    text = (workspace / "src" / "funcs.py").read_text(encoding="utf-8")
    assert "return 10" in text and "return 30" not in text and "return 3\n" in text

    page.screenshot(
        path=str(
            Path(__import__("os").environ.get("AICA_SCREENSHOT_DIR", tmp_path)) / "web-ui-task.png"
        ),
        full_page=True,
    )

    # UX-008 / API-014: decide the approval from the page.
    page.click("#approvals-badge")
    item = page.locator(".approval").first
    expect(item.locator(".chip")).to_have_text("destructive")
    item.locator("input[type=text]").fill("checked with the team")
    item.get_by_role("button", name="Approve").click()
    expect(page.locator("#approvals")).to_contain_text("Nothing is waiting")
    expect(page.locator("#approvals-banner")).to_be_hidden()
    (decided,) = ApprovalQueue(workspace).all()
    assert decided.state is DecisionState.APPROVED and decided.decided_by == "reviewer"

    # UX-007: models are listed.
    page.click("button[data-view=models]")
    expect(page.locator("#models tr").first).to_be_visible()

    problems = page.problems  # type: ignore[attr-defined]
    assert not problems, problems  # no script errors and no CSP violations


def test_a_wrong_token_is_refused_by_the_page(server: str, page: object) -> None:
    from playwright.sync_api import Page, expect

    assert isinstance(page, Page)
    page.goto(server + "/ui/")
    page.fill("#token", "not-the-token")
    page.click("#login-form button[type=submit]")
    expect(page.locator("#login-error")).to_contain_text("not accepted")
    expect(page.locator("#app")).to_be_hidden()


def _sign_in(page: object, server: str) -> None:
    from playwright.sync_api import Page, expect

    assert isinstance(page, Page)
    page.goto(server + "/ui/")
    page.fill("#token", TOKEN)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#workspace")).to_contain_text("reviewer")


@pytest.mark.parametrize("script", [REVIEW_SCRIPT])
def test_the_web_app_renders_review_findings(server: str, page: object, tmp_path: Path) -> None:
    """CHAT-007: findings are shown structured - severity, location, provenance, suggestion."""
    from playwright.sync_api import Page, expect

    assert isinstance(page, Page)
    _sign_in(page, server)
    page.click("button[data-view=review]")
    page.fill("#review-diff", REVIEW_DIFF)
    page.click("#review-form button[type=submit]")

    expect(page.locator("#review-status")).to_have_text("3 findings", timeout=30_000)
    expect(page.locator("#review-incomplete")).to_be_hidden()
    expect(page.locator("#review-counts")).to_contain_text("1 critical")
    expect(page.locator("#review-counts")).to_contain_text("2 high")
    expect(page.locator("#review-summary")).to_contain_text("Fix the quantity default")

    # REV-006: grouped by file, worst first; REV-007: each finding carries its location.
    box = page.locator(".review-file", has_text="src/invoice.py")
    findings = box.locator(".finding")
    expect(findings).to_have_count(3)
    # The static security scan, which needs no model.
    expect(findings.nth(0).locator(".sev")).to_have_text("critical")
    expect(findings.nth(0)).to_contain_text("CWE-89")
    expect(findings.nth(0).locator(".location")).to_have_text("src/invoice.py:5")
    expect(findings.nth(0)).to_contain_text("security-scan")
    # The model's finding, with its suggestion and which model said it.
    model_finding = findings.filter(has_text="Default the quantity to 1.")
    expect(model_finding.locator(".location")).to_have_text("src/invoice.py:2")
    expect(model_finding).to_contain_text("REV-002 - correctness - scripted")
    # The deterministic test-adequacy check (REV-004): logic changed, no test covers it.
    expect(findings.filter(has_text="no test covering this file")).to_contain_text("REV-004")

    # Model output is untrusted (SAFE-007): hostile markup in a title renders as text.
    expect(model_finding.locator(".finding-head strong")).to_have_text(HOSTILE)
    assert page.title() == "AICA"
    assert page.locator("main img").count() == 0

    # The finding outside the change was dropped, and the page says so rather than hiding it.
    expect(page.locator("#review-dropped")).to_contain_text("1 proposed finding was discarded")
    expect(page.locator("#review-findings")).not_to_contain_text("outside the change")

    page.screenshot(
        path=str(
            Path(__import__("os").environ.get("AICA_SCREENSHOT_DIR", tmp_path))
            / "web-ui-review.png"
        ),
        full_page=True,
    )

    problems = page.problems  # type: ignore[attr-defined]
    assert not problems, problems


@pytest.mark.parametrize("script", [["this is not a list of findings"] * 5])
def test_an_incomplete_review_is_not_shown_as_clean(server: str, page: object) -> None:
    """A review whose checks failed says so; an empty result is not presented as a pass."""
    from playwright.sync_api import Page, expect

    assert isinstance(page, Page)
    _sign_in(page, server)
    page.click("button[data-view=review]")
    page.fill(
        "#review-diff",
        REVIEW_DIFF.replace(
            '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")', "    pass"
        ),
    )
    page.click("#review-form button[type=submit]")

    expect(page.locator("#review-status")).to_have_text("incomplete", timeout=30_000)
    expect(page.locator("#review-incomplete")).to_be_visible()
    expect(page.locator("#review-incomplete")).to_contain_text("do not mean the change is clean")
    expect(page.locator("#review-findings")).not_to_contain_text("No findings.")

    # Unticking every check is refused on the page, before any request is made.
    for box in page.locator("input[name=review-check]").all():
        box.uncheck()
    page.click("#review-form button[type=submit]")
    expect(page.locator("#review-error")).to_have_text("Choose at least one check.")
