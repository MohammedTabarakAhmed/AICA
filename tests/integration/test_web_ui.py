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
def server(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    from aica.api.app import ApiSettings, create_app
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    monkeypatch.setattr(
        ModelGateway, "get", lambda self, name=None: ScriptedAdapter([PLAN], name="scripted")
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
