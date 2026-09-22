"""Browser/E2E test generation and update (WEB-005, WEB-004).

A browser session records every interaction it performs, so a test can be written from what
actually happened rather than from a guess about what the page contains. Two paths:

* :func:`render_playwright_test` turns recorded actions into a runnable test deterministically,
  with no model involved. This is the one to trust: the selectors are the ones that worked.
* :func:`generate_browser_test` asks the model to improve that draft - better names, sensible
  assertions, grouping - and falls back to the deterministic render if the reply is unusable.

Updating an existing test (WEB-005's second half) is :func:`update_browser_test`, which gives
the model the current file and the new recording and requires the result to still look like a
test before returning it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from aica.models.base import ChatMessage, ModelAdapter, ModelError
from aica.safety.injection import wrap_untrusted
from aica.safety.redaction import redact

MAX_FILE_CHARS = 20_000

BROWSER_TEST_SYSTEM = """You write browser end-to-end tests with Playwright's sync Python API
(pytest style).

Rules:
- Use only the selectors and URLs given to you. Never invent a selector, a URL or a field.
- Keep the recorded order. Every recorded interaction must appear in the test.
- Add assertions that check what the page actually showed, using the observed text.
- Wait by asserting on state, never with sleeps. No network access beyond the given URL.
- One test function unless the recording clearly covers separate flows.
- Output the complete test file only: no explanation, no markdown fences."""

_FENCE_OPEN = re.compile(r"^```[\w-]*\n")
_FENCE_CLOSE = re.compile(r"\n```$")
_LOOKS_LIKE_TEST = re.compile(r"\bdef\s+test_\w+|\btest\s*\(", re.MULTILINE)


class BrowserTestError(ValueError):
    """The recording or the generated test is unusable (WEB-005)."""


@dataclass(frozen=True)
class GeneratedBrowserTest:
    test_path: str
    content: str
    model: str | None  # None = deterministic render, no model involved
    actions: int

    @property
    def generated(self) -> bool:
        return self.model is not None


def _escape(value: str) -> str:
    """Safe for a single-quoted Python string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")


def render_playwright_test(
    actions: list[dict[str, str]],
    *,
    name: str = "recorded_flow",
    base_url: str | None = None,
) -> str:
    """Deterministically turn recorded actions into a runnable pytest-playwright test."""
    if not actions:
        raise BrowserTestError("no recorded actions: nothing to turn into a test")
    slug = re.sub(r"\W+", "_", name).strip("_").lower() or "recorded_flow"
    lines = [
        '"""Generated from a recorded browser session (WEB-005)."""',
        "",
        "from playwright.sync_api import Page, expect",
        "",
        "",
        f"def test_{slug}(page: Page) -> None:",
    ]
    body: list[str] = []
    for action in actions:
        kind = action.get("action", "")
        target = action.get("target", "")
        value = action.get("value", "")
        if kind == "navigate":
            url = target
            if base_url and url.startswith(base_url):
                url = url[len(base_url) :] or "/"
            body.append(f"    page.goto('{_escape(url)}')")
        elif kind == "click":
            body.append(f"    page.click('{_escape(target)}')")
        elif kind == "fill":
            # A recorded value may be a credential: never bake one into a test file.
            safe = redact(value).text
            body.append(f"    page.fill('{_escape(target)}', '{_escape(safe)}')")
        elif kind == "press":
            body.append(f"    page.press('{_escape(target)}', '{_escape(value)}')")
        elif kind == "expect" and value.strip():
            snippet = redact(value).text.strip().splitlines()[0][:80]
            if snippet:
                body.append(
                    f"    expect(page.locator('{_escape(target)}'))"
                    f".to_contain_text('{_escape(snippet)}')"
                )
    if not body:
        raise BrowserTestError("recorded actions contained nothing executable")
    return "\n".join([*lines, *body, ""])


def _strip_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = _FENCE_OPEN.sub("", stripped, count=1)
        stripped = _FENCE_CLOSE.sub("", stripped)
        if stripped.endswith("```"):
            stripped = stripped[:-3].rstrip()
    return stripped


def suggest_browser_test_path(name: str = "recorded_flow", root: str | Path | None = None) -> str:
    slug = re.sub(r"\W+", "_", name).strip("_").lower() or "recorded_flow"
    if root is not None and (Path(root) / "tests" / "e2e").is_dir():
        return f"tests/e2e/test_{slug}.py"
    return f"tests/e2e/test_{slug}.py"


def generate_browser_test(
    adapter: ModelAdapter | None,
    actions: list[dict[str, str]],
    *,
    name: str = "recorded_flow",
    base_url: str | None = None,
    root: str | Path | None = None,
    page_text: str = "",
) -> GeneratedBrowserTest:
    """WEB-005: propose an E2E test for a recorded flow. Nothing is written to disk.

    The deterministic render is always computed first and is the fallback, so this never
    returns a test built on selectors that were never exercised.
    """
    draft = render_playwright_test(actions, name=name, base_url=base_url)
    test_path = suggest_browser_test_path(name, root)
    if adapter is None:
        return GeneratedBrowserTest(test_path, draft, None, len(actions))

    prompt = [
        f"Recorded flow: {name}",
        f"Base URL: {base_url or '(none)'}",
        "Deterministic draft built from the recording - keep every step it contains:",
        draft,
    ]
    if page_text.strip():
        prompt.append(
            "Text the page showed at the end of the flow (use it for assertions):\n"
            + wrap_untrusted(redact(page_text).text[:4000], "page-text")
        )
    prompt.append("Rewrite this into a clean, well-named test.")

    try:
        response = adapter.chat(
            [
                ChatMessage(role="system", content=BROWSER_TEST_SYSTEM),
                ChatMessage(role="user", content="\n\n".join(prompt)),
            ],
            temperature=0.1,
            max_tokens=1500,
        )
    except ModelError:
        return GeneratedBrowserTest(test_path, draft, None, len(actions))

    content = _strip_fences(redact(response.content).text)
    if not _LOOKS_LIKE_TEST.search(content):
        # The model returned prose or something else: keep the draft that is known to run.
        return GeneratedBrowserTest(test_path, draft, None, len(actions))
    return GeneratedBrowserTest(test_path, content, response.model, len(actions))


def update_browser_test(
    adapter: ModelAdapter,
    existing: str,
    actions: list[dict[str, str]],
    *,
    name: str = "recorded_flow",
    base_url: str | None = None,
    reason: str = "",
) -> str:
    """WEB-005: update an existing E2E test for a changed flow.

    Raises :class:`BrowserTestError` rather than returning something that no longer looks like
    a test - silently replacing a suite with prose would be worse than failing.
    """
    if not existing.strip():
        raise BrowserTestError("existing test file is empty; generate a new test instead")
    draft = render_playwright_test(actions, name=name, base_url=base_url)
    prompt = (
        (f"Why the test needs updating: {reason}\n\n" if reason.strip() else "")
        + "Current test file:\n"
        + wrap_untrusted(existing[:MAX_FILE_CHARS], "existing-test")
        + "\n\nThe flow as it now actually behaves:\n"
        + draft
        + "\n\nUpdate the test to match the new behaviour. Keep the parts that still apply, "
        "keep the file's existing style, and change only what the new recording requires."
    )
    try:
        response = adapter.chat(
            [
                ChatMessage(role="system", content=BROWSER_TEST_SYSTEM),
                ChatMessage(role="user", content=prompt),
            ],
            temperature=0.0,
            max_tokens=2000,
        )
    except ModelError as exc:
        raise BrowserTestError(f"model unavailable: {exc}") from exc
    content = _strip_fences(redact(response.content).text)
    if not _LOOKS_LIKE_TEST.search(content):
        raise BrowserTestError("the model's reply does not contain a test; not updating the file")
    return content
