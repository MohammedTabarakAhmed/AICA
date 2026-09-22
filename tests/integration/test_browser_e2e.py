"""Browser automation against a real application (WEB-001..WEB-006, TEST-004).

A real HTTP server on loopback, a real Chromium browser, real clicks and a real screenshot.
Nothing is stubbed: the login flow below actually runs in a browser, the console error is
actually raised by page JavaScript, and the generated E2E test is executed by pytest as a
child process to prove it works.

The server binds to 127.0.0.1 on an ephemeral port and serves only strings defined in this
file, so the suite needs no external network (SAFE-005).
"""

from __future__ import annotations

import http.server
import json
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.approvals import AllowAllApprover
from aica.audit import AuditLog, EventCategory, InMemoryAuditSink
from aica.models.fake import ScriptedAdapter
from aica.policy import Policy
from aica.testing.browser_tests import generate_browser_test
from aica.tools import ToolContext, default_registry
from aica.tools.browser import SESSIONS
from aica.workspace import WorkspaceGuard

pytestmark = pytest.mark.integration

playwright = pytest.importorskip("playwright", reason="browser tools need the playwright extra")

LOGIN_PAGE = """<!doctype html>
<html><head><title>Demo Login</title></head><body>
<h1 id="heading">Sign in</h1>
<form id="login" onsubmit="return false">
  <input id="user" name="user" placeholder="user">
  <input id="pass" name="pass" type="password" placeholder="password">
  <button id="submit" type="submit">Log in</button>
</form>
<div id="result"></div>
<script>
document.getElementById('submit').addEventListener('click', function () {
  var user = document.getElementById('user').value;
  var el = document.getElementById('result');
  if (user === 'ada') {
    el.textContent = 'Welcome, ada';
    el.id = 'welcome';
  } else {
    el.textContent = 'Unknown user';
  }
});
</script>
</body></html>
"""

BROKEN_PAGE = """<!doctype html>
<html><head><title>Broken</title></head><body>
<h1 id="heading">Broken page</h1>
<script>
console.error('inventory lookup failed: SKU-42 missing');
fetch('/does-not-exist').catch(function () {});
undefinedFunctionCall();
</script>
</body></html>
"""


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's interface
        pages = {"/": LOGIN_PAGE, "/login": LOGIN_PAGE, "/broken": BROKEN_PAGE}
        body = pages.get(self.path.split("?")[0])
        if body is None:
            self.send_error(404)
            return
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args: object) -> None:
        return  # keep the test output clean


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def ctx(tmp_path: Path) -> Iterator[ToolContext]:
    policy = Policy()
    context = ToolContext(
        workspace=WorkspaceGuard(tmp_path, policy.autonomy.allowed_directories),
        policy=policy,
        audit=AuditLog(InMemoryAuditSink(), actor="browser-integration", session_id="b1"),
        approver=AllowAllApprover(),
    )
    try:
        yield context
    finally:
        SESSIONS.close_all()  # never leak a browser process out of a test


def test_real_login_flow_in_a_real_browser(ctx: ToolContext, server: str) -> None:
    """WEB-001/WEB-002: navigate an authorized app, interact, and check what it rendered."""
    registry = default_registry()
    opened = registry.call("browser.open", {"url": f"{server}/login"}, ctx)
    session = opened.data["session"]
    assert opened.data["title"] == "Demo Login"

    assert (
        "Sign in"
        in registry.call("browser.read", {"session": session, "selector": "#heading"}, ctx).output
    )

    registry.call("browser.fill", {"session": session, "selector": "#user", "value": "ada"}, ctx)
    registry.call(
        "browser.fill", {"session": session, "selector": "#pass", "value": "s3cret!"}, ctx
    )
    registry.call("browser.click", {"session": session, "selector": "#submit"}, ctx)

    welcome = registry.call("browser.read", {"session": session, "selector": "#welcome"}, ctx)
    assert welcome.output.strip() == "Welcome, ada"

    closed = registry.call("browser.close", {"session": session}, ctx)
    assert len(SESSIONS) == 0
    actions = closed.data["actions"]
    assert [a["action"] for a in actions][:4] == ["navigate", "expect", "fill", "fill"]


def test_password_is_not_written_to_the_audit_log(ctx: ToolContext, server: str) -> None:
    """A value typed into a login form must not end up in the audit trail."""
    registry = default_registry()
    session = registry.call("browser.open", {"url": f"{server}/login"}, ctx).data["session"]
    registry.call(
        "browser.fill",
        {"session": session, "selector": "#pass", "value": "api_key=AKIAIOSFODNN7EXAMPLE"},
        ctx,
    )
    trail = json.dumps(
        [e.model_dump(mode="json") for e in ctx.audit.sink.events]  # type: ignore[attr-defined]
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in trail


def test_evidence_captures_console_errors_and_a_screenshot(ctx: ToolContext, server: str) -> None:
    """WEB-003: the page's own errors are collected, not just its text."""
    registry = default_registry()
    session = registry.call("browser.open", {"url": f"{server}/broken"}, ctx).data["session"]
    registry.call("browser.read", {"session": session}, ctx)  # let the page settle

    evidence = registry.call("browser.evidence", {"session": session, "name": "broken-page"}, ctx)
    shot = evidence.data["screenshot"]
    assert shot and (ctx.workspace.root / shot).is_file()
    assert (ctx.workspace.root / shot).stat().st_size > 0

    console = "\n".join(evidence.data["console"])
    assert "inventory lookup failed: SKU-42 missing" in console
    # A thrown ReferenceError surfaces as a page error; a 404 surfaces as an HTTP error.
    assert evidence.data["error_count"] >= 1
    assert any("undefinedFunctionCall" in e for e in evidence.data["errors"])
    assert any("does-not-exist" in r for r in evidence.data["http_errors"])
    assert any("404" in r for r in evidence.data["http_errors"])
    assert evidence.data["problem_count"] >= 2
    assert "http errors" in evidence.output

    assert any(e.category is EventCategory.BROWSER for e in ctx.audit.sink.events)  # type: ignore[attr-defined]


def test_a_missing_element_fails_with_a_readable_error(ctx: ToolContext, server: str) -> None:
    registry = default_registry()
    session = registry.call("browser.open", {"url": f"{server}/login"}, ctx).data["session"]
    with pytest.raises(Exception, match="could not click"):
        registry.call(
            "browser.click",
            {"session": session, "selector": "#not-there", "timeout_seconds": 1},
            ctx,
        )


def test_navigation_within_a_session_is_policy_checked(ctx: ToolContext, server: str) -> None:
    registry = default_registry()
    session = registry.call("browser.open", {"url": f"{server}/login"}, ctx).data["session"]
    with pytest.raises(PermissionError, match="not permitted"):
        registry.call("browser.navigate", {"session": session, "url": "https://example.com/"}, ctx)
    # The session survives a refused navigation and is still on the allowed page.
    assert "Sign in" in registry.call("browser.read", {"session": session}, ctx).output


def test_generated_e2e_test_actually_passes(ctx: ToolContext, server: str, tmp_path: Path) -> None:
    """WEB-004/WEB-005: record a flow, generate a test from it, then really run the test."""
    pytest.importorskip(
        "pytest_playwright", reason="running generated tests needs pytest-playwright"
    )
    registry = default_registry()
    session = registry.call("browser.open", {"url": f"{server}/login"}, ctx).data["session"]
    registry.call("browser.fill", {"session": session, "selector": "#user", "value": "ada"}, ctx)
    registry.call("browser.click", {"session": session, "selector": "#submit"}, ctx)
    page_text = registry.call(
        "browser.read", {"session": session, "selector": "#welcome"}, ctx
    ).output
    actions = registry.call("browser.close", {"session": session}, ctx).data["actions"]

    generated = generate_browser_test(
        None, actions, name="login flow", base_url=server, page_text=page_text
    )
    e2e = tmp_path / "tests" / "e2e"
    e2e.mkdir(parents=True)
    (e2e / "test_generated.py").write_text(generated.content, encoding="utf-8")

    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(e2e),
            "-q",
            "-p",
            "no:cacheprovider",
            f"--base-url={server}",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stdout + run.stderr


def test_agent_can_drive_the_browser_through_a_plan(ctx: ToolContext, server: str) -> None:
    """The browser tools are ordinary tools, so the agent loop can plan with them."""
    from aica.agent.loop import AgentLoop

    plan = json.dumps(
        {
            "summary": "check the login page renders",
            "steps": [
                {
                    "intent": "open the app",
                    "tool": "browser.open",
                    "arguments": {"url": f"{server}/login"},
                }
            ],
            "verification": [],
        }
    )
    report = AgentLoop(ScriptedAdapter([plan]), default_registry()).run("check login", ctx)
    assert report.steps_used == 1
    assert len(SESSIONS) == 1  # the plan opened a session; the fixture closes it
    assert report.succeeded is False  # nothing was verified, so no success claim
