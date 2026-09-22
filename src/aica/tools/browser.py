"""Browser automation tools (WEB-001..WEB-006).

Playwright drives a real browser so the agent can exercise a running application the way a
user does, and collect the evidence a human reviewer needs: what the page said, what the
console logged, which requests failed, and a screenshot.

The controls are policy, not convention:

* **WEB-001** every navigation resolves its host through ``BrowserPolicy``. Loopback is the
  development case and is allowed by default; any other host must be allowlisted.
* **WEB-006** a non-local target also passes the EXTERNAL approval gate, and a production
  environment classification adds the PRODUCTION gate (applied by ``require_approval``).
* Every action is audited (MCP-006) and every session records its actions, which is what
  makes WEB-005 test generation possible.

Playwright is an optional dependency: importing this module never requires it, and the tools
fail with a clear, actionable message when it is missing.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from aica.audit import EventCategory, Outcome
from aica.policy.models import ActionCategory
from aica.safety.redaction import redact
from aica.tools.base import Tool, ToolContext, ToolError, ToolResult

if TYPE_CHECKING:  # pragma: no cover - typing only
    from playwright.sync_api import Browser, ConsoleMessage, Page, Playwright

MAX_TEXT_CHARS = 20_000
MAX_MESSAGES = 200
INSTALL_HINT = (
    "playwright is not installed. Install it with:\n"
    "  pip install 'playwright>=1.48,<2'\n"
    "  python -m playwright install chromium"
)


class BrowserUnavailable(ToolError):
    """Playwright (or a browser binary) is not installed."""


@dataclass
class RecordedAction:
    """One interaction, kept so a test can be generated from the session (WEB-005)."""

    action: str  # navigate | click | fill | press | select | expect
    target: str = ""  # selector or URL
    value: str = ""
    timestamp: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, str]:
        return {"action": self.action, "target": self.target, "value": self.value}


@dataclass
class BrowserSession:
    """One open browser. Held out of ``ToolContext`` so a context stays serialisable."""

    id: str
    engine: str
    playwright: Playwright
    browser: Browser
    page: Page
    console: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    failed_requests: list[str] = field(default_factory=list)  # network-level failures
    http_errors: list[str] = field(default_factory=list)  # responses with status >= 400
    actions: list[RecordedAction] = field(default_factory=list)
    start_url: str = ""

    def record(self, action: str, target: str = "", value: str = "") -> None:
        self.actions.append(RecordedAction(action=action, target=target, value=value))

    def close(self) -> None:
        """Tear down, recording rather than raising: a teardown error must not mask the
        real failure that led here, and both halves must be attempted regardless."""
        for closer in (self.browser.close, self.playwright.stop):
            try:
                closer()
            except Exception as exc:  # noqa: BLE001 - teardown is best effort
                self.errors.append(f"teardown: {exc}"[:500])


class SessionRegistry:
    """Process-wide open sessions. Explicit ``close`` is required; ``close_all`` is the net."""

    def __init__(self) -> None:
        self._sessions: dict[str, BrowserSession] = {}

    def add(self, session: BrowserSession) -> None:
        self._sessions[session.id] = session

    def get(self, session_id: str) -> BrowserSession:
        session = self._sessions.get(session_id)
        if session is None:
            known = ", ".join(self._sessions) or "none"
            raise ToolError(f"unknown browser session {session_id!r} (open: {known})")
        return session

    def close(self, session_id: str) -> None:
        session = self._sessions.pop(session_id, None)
        if session is not None:
            session.close()

    def close_all(self) -> None:
        for session_id in list(self._sessions):
            self.close(session_id)

    def __len__(self) -> int:
        return len(self._sessions)


SESSIONS = SessionRegistry()


def _require_playwright() -> Any:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise BrowserUnavailable(INSTALL_HINT) from exc
    return sync_playwright


def _check_url(url: str, ctx: ToolContext, tool: str) -> str:
    """WEB-001/WEB-006: resolve the target against policy before the browser goes anywhere."""
    policy = ctx.policy.browser
    if not policy.enabled:
        raise PermissionError("browser tools are disabled by policy ([browser].enabled = false)")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ToolError(f"unsupported URL scheme {parsed.scheme!r}: use http or https")
    host = parsed.hostname or ""
    if not host:
        raise ToolError(f"no host in URL {url!r}")
    if not policy.is_host_allowed(host):
        raise PermissionError(
            f"browser navigation to {host!r} is not permitted; add it to "
            f"[browser].allowed_hosts (SAFE-005/WEB-001)"
        )
    if not policy.is_local(host):
        # Reaching anything beyond the developer's own machine is an external action.
        ctx.require_approval(tool, f"browse to {url}", [ActionCategory.EXTERNAL], url=url)
    return url


def _record(ctx: ToolContext, action: str, ok: bool = True, **details: object) -> None:
    ctx.audit.record(
        category=EventCategory.BROWSER,
        action=action,
        outcome=Outcome.SUCCESS if ok else Outcome.FAILURE,
        tool="browser",
        details=dict(details),
        session_id=ctx.session_id,
    )


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _SessionArgs(_Args):
    session: str = Field(description="browser session id from browser.open")


# ------------------------------------------------------------------ WEB-001


class BrowserOpen(Tool):
    name: ClassVar[str] = "browser.open"
    description: ClassVar[str] = (
        "Open a browser on an authorized application URL and return a session id. "
        "Non-local hosts must be allowlisted in policy and require approval."
    )

    class Args(_Args):
        url: str = Field(min_length=1, max_length=2000)
        engine: str | None = Field(default=None, pattern="^(chromium|firefox|webkit)$")
        headless: bool | None = None
        viewport_width: int = Field(default=1280, ge=320, le=3840)
        viewport_height: int = Field(default=800, ge=240, le=2160)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        url = _check_url(args.url, ctx, self.name)
        policy = ctx.policy.browser
        engine = args.engine or policy.engine
        headless = policy.headless if args.headless is None else args.headless

        sync_playwright = _require_playwright()
        pw = sync_playwright().start()
        try:
            launcher = getattr(pw, engine)
            browser = launcher.launch(headless=headless)
            page = browser.new_page(
                viewport={"width": args.viewport_width, "height": args.viewport_height}
            )
        except Exception as exc:
            pw.stop()
            raise BrowserUnavailable(f"could not start {engine}: {exc}\n\n{INSTALL_HINT}") from exc

        session = BrowserSession(
            id=uuid.uuid4().hex[:8],
            engine=engine,
            playwright=pw,
            browser=browser,
            page=page,
            start_url=url,
        )
        _attach_listeners(session)
        try:
            page.goto(url, timeout=policy.max_seconds * 1000)
        except Exception as exc:
            session.close()
            raise ToolError(f"could not load {url}: {exc}") from exc
        session.record("navigate", url)
        SESSIONS.add(session)
        _record(ctx, f"open {url}", engine=engine, session=session.id)
        return ToolResult(
            output=f"session {session.id} [{engine}] {page.title()} <{page.url}>",
            data={"session": session.id, "url": page.url, "title": page.title(), "engine": engine},
        )


def _attach_listeners(session: BrowserSession) -> None:
    """WEB-003: capture console output, page errors and failed requests as they happen."""

    def on_console(message: ConsoleMessage) -> None:
        if len(session.console) < MAX_MESSAGES:
            session.console.append(f"[{message.type}] {redact(message.text).text}"[:1000])

    def on_page_error(error: Any) -> None:
        if len(session.errors) < MAX_MESSAGES:
            session.errors.append(redact(str(error)).text[:1000])

    def on_request_failed(request: Any) -> None:
        if len(session.failed_requests) < MAX_MESSAGES:
            failure = getattr(request, "failure", None)
            session.failed_requests.append(f"{request.method} {request.url} - {failure}"[:1000])

    def on_response(response: Any) -> None:
        # Playwright's "requestfailed" fires only for network-level failures, so a 404 or a
        # 500 would otherwise go unreported - and a broken status code is exactly the
        # evidence a reviewer needs (WEB-003).
        status = getattr(response, "status", 0)
        if status >= 400 and len(session.http_errors) < MAX_MESSAGES:
            session.http_errors.append(f"{status} {response.url}"[:1000])

    session.page.on("console", on_console)
    session.page.on("pageerror", on_page_error)
    session.page.on("requestfailed", on_request_failed)
    session.page.on("response", on_response)


class BrowserNavigate(Tool):
    name: ClassVar[str] = "browser.navigate"
    description: ClassVar[str] = "Navigate an open session to another authorized URL."

    class Args(_SessionArgs):
        url: str = Field(min_length=1, max_length=2000)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        url = _check_url(args.url, ctx, self.name)
        session = SESSIONS.get(args.session)
        try:
            session.page.goto(url, timeout=ctx.policy.browser.max_seconds * 1000)
        except Exception as exc:
            raise ToolError(f"could not load {url}: {exc}") from exc
        session.record("navigate", url)
        _record(ctx, f"navigate {url}", session=session.id)
        return ToolResult(
            output=f"{session.page.title()} <{session.page.url}>",
            data={"url": session.page.url, "title": session.page.title()},
        )


# ------------------------------------------------------------------ WEB-002


class BrowserClick(Tool):
    name: ClassVar[str] = "browser.click"
    description: ClassVar[str] = "Click an element identified by a CSS or text selector."

    class Args(_SessionArgs):
        selector: str = Field(min_length=1, max_length=500)
        timeout_seconds: float | None = Field(default=None, gt=0, le=600)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        session = SESSIONS.get(args.session)
        timeout = (args.timeout_seconds or ctx.policy.browser.max_seconds) * 1000
        try:
            session.page.click(args.selector, timeout=timeout)
        except Exception as exc:
            raise ToolError(f"could not click {args.selector!r}: {_brief(exc)}") from exc
        session.record("click", args.selector)
        _record(ctx, f"click {args.selector}", session=session.id)
        return ToolResult(
            output=f"clicked {args.selector} (now at {session.page.url})",
            data={"url": session.page.url, "title": session.page.title()},
        )


class BrowserFill(Tool):
    name: ClassVar[str] = "browser.fill"
    description: ClassVar[str] = "Type a value into an input, textarea or contenteditable element."

    class Args(_SessionArgs):
        selector: str = Field(min_length=1, max_length=500)
        value: str = Field(max_length=10_000)
        timeout_seconds: float | None = Field(default=None, gt=0, le=600)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        session = SESSIONS.get(args.session)
        timeout = (args.timeout_seconds or ctx.policy.browser.max_seconds) * 1000
        try:
            session.page.fill(args.selector, args.value, timeout=timeout)
        except Exception as exc:
            raise ToolError(f"could not fill {args.selector!r}: {_brief(exc)}") from exc
        session.record("fill", args.selector, args.value)
        # The value may be a credential typed into a login form: never audit it raw.
        _record(
            ctx, f"fill {args.selector}", session=session.id, value=redact(args.value).text[:200]
        )
        return ToolResult(output=f"filled {args.selector}", data={"selector": args.selector})


class BrowserPress(Tool):
    name: ClassVar[str] = "browser.press"
    description: ClassVar[str] = "Press a key (Enter, Tab, Escape, ...) on an element or the page."

    class Args(_SessionArgs):
        key: str = Field(min_length=1, max_length=40)
        selector: str = Field(default="body", max_length=500)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        session = SESSIONS.get(args.session)
        try:
            session.page.press(
                args.selector, args.key, timeout=ctx.policy.browser.max_seconds * 1000
            )
        except Exception as exc:
            raise ToolError(f"could not press {args.key!r}: {_brief(exc)}") from exc
        session.record("press", args.selector, args.key)
        _record(ctx, f"press {args.key}", session=session.id)
        return ToolResult(output=f"pressed {args.key}", data={"url": session.page.url})


# ------------------------------------------------------------------ WEB-003


class BrowserRead(Tool):
    name: ClassVar[str] = "browser.read"
    description: ClassVar[str] = (
        "Read the page: visible text, a specific element's text, or the HTML. "
        "This is how the agent checks what the application actually rendered."
    )

    class Args(_SessionArgs):
        selector: str | None = Field(default=None, max_length=500)
        html: bool = False

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        session = SESSIONS.get(args.session)
        try:
            if args.html:
                content = (
                    session.page.inner_html(args.selector)
                    if args.selector
                    else session.page.content()
                )
            else:
                content = (
                    session.page.inner_text(args.selector)
                    if args.selector
                    else session.page.inner_text("body")
                )
        except Exception as exc:
            raise ToolError(f"could not read {args.selector or 'page'}: {_brief(exc)}") from exc
        text = redact(content).text[:MAX_TEXT_CHARS]
        session.record("expect", args.selector or "body", text[:120])
        return ToolResult(
            output=text,
            data={"url": session.page.url, "title": session.page.title(), "length": len(content)},
        )


class BrowserEvidence(Tool):
    name: ClassVar[str] = "browser.evidence"
    description: ClassVar[str] = (
        "Collect evidence from the session: screenshot, console output, page errors and "
        "failed network requests. Use this to show what happened, or to diagnose a failure."
    )

    class Args(_SessionArgs):
        screenshot: bool = True
        full_page: bool = True
        name: str = Field(default="evidence", max_length=80, pattern=r"^[A-Za-z0-9._-]+$")

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        session = SESSIONS.get(args.session)
        shot: str | None = None
        if args.screenshot:
            directory = ctx.workspace.root / ctx.policy.browser.screenshot_dir
            directory.mkdir(parents=True, exist_ok=True)
            target = directory / f"{args.name}-{session.id}-{int(time.time())}.png"
            try:
                session.page.screenshot(path=str(target), full_page=args.full_page)
            except Exception as exc:
                raise ToolError(f"could not capture a screenshot: {_brief(exc)}") from exc
            shot = _relative(target, ctx)
        lines = [f"url: {session.page.url}", f"title: {session.page.title()}"]
        if shot:
            lines.append(f"screenshot: {shot}")
        lines.append(f"console ({len(session.console)}):")
        lines += [f"  {m}" for m in session.console[-20:]]
        lines.append(f"page errors ({len(session.errors)}):")
        lines += [f"  {m}" for m in session.errors[-20:]]
        lines.append(f"failed requests ({len(session.failed_requests)}):")
        lines += [f"  {m}" for m in session.failed_requests[-20:]]
        lines.append(f"http errors ({len(session.http_errors)}):")
        lines += [f"  {m}" for m in session.http_errors[-20:]]
        _record(
            ctx,
            "evidence",
            session=session.id,
            errors=len(session.errors),
            failed_requests=len(session.failed_requests),
            http_errors=len(session.http_errors),
        )
        return ToolResult(
            output="\n".join(lines),
            data={
                "url": session.page.url,
                "title": session.page.title(),
                "screenshot": shot,
                "console": session.console[-MAX_MESSAGES:],
                "errors": session.errors[-MAX_MESSAGES:],
                "failed_requests": session.failed_requests[-MAX_MESSAGES:],
                "http_errors": session.http_errors[-MAX_MESSAGES:],
                "error_count": len(session.errors),
                "problem_count": (
                    len(session.errors) + len(session.failed_requests) + len(session.http_errors)
                ),
            },
        )


class BrowserClose(Tool):
    name: ClassVar[str] = "browser.close"
    description: ClassVar[str] = "Close a browser session and release its resources."

    class Args(_SessionArgs):
        pass

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        session = SESSIONS.get(args.session)
        actions = [a.as_dict() for a in session.actions]
        SESSIONS.close(args.session)
        _record(ctx, f"close {args.session}", actions=len(actions))
        return ToolResult(
            output=f"closed session {args.session} after {len(actions)} action(s)",
            data={"session": args.session, "actions": actions},
        )


def _brief(exc: Exception) -> str:
    """Playwright errors carry a long call log; the first lines are the useful part."""
    text = str(exc).strip()
    lines = [line for line in text.splitlines() if line.strip()]
    return " | ".join(lines[:3])[:600]


def _relative(path: Path, ctx: ToolContext) -> str:
    try:
        return path.relative_to(ctx.workspace.root).as_posix()
    except ValueError:
        return str(path)


BROWSER_TOOLS: list[Tool] = [
    BrowserOpen(),
    BrowserNavigate(),
    BrowserClick(),
    BrowserFill(),
    BrowserPress(),
    BrowserRead(),
    BrowserEvidence(),
    BrowserClose(),
]
