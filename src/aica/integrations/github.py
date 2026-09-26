"""GitHub REST client for an approved connector (INT-006).

Deliberately small: the operations the repository tools need and nothing else, so the
connector cannot do more than the tools expose. Every response field it returns is data
from a third party; the tools fence it as untrusted before a model sees it (SAFE-007).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx

from aica.integrations.repositories import RepositoryError
from aica.safety.redaction import redact

MAX_DIFF_CHARS = 60_000
_API_VERSION = "2022-11-28"


class GitHubClient:
    def __init__(
        self,
        api_url: str,
        repository: str,
        token: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.repository = repository
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": _API_VERSION,
            "User-Agent": "aica-repository-connector",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            base_url=api_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport
        )

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------ transport
    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        accept: str | None = None,
    ) -> httpx.Response:
        headers = {"Accept": accept} if accept else None
        try:
            resp = self._client.request(method, path, json=json, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise RepositoryError(f"GitHub unreachable: {exc.__class__.__name__}: {exc}") from exc
        if resp.status_code >= 400:
            raise RepositoryError(self._describe_error(resp))
        return resp

    @staticmethod
    def _describe_error(resp: httpx.Response) -> str:
        try:
            body = resp.json()
            message = str(body.get("message", "")) if isinstance(body, dict) else ""
            errors = body.get("errors") if isinstance(body, dict) else None
            if errors:
                message += f" {errors}"
        except ValueError:
            message = resp.text[:300]
        hint = {
            401: " (the token is missing, expired or wrong)",
            403: " (the token lacks permission, or a rate limit was hit)",
            404: " (not found - or not visible to this token)",
            422: " (GitHub rejected the request as invalid)",
        }.get(resp.status_code, "")
        return redact(f"GitHub HTTP {resp.status_code}: {message.strip()}{hint}").text

    def _repo(self, suffix: str = "") -> str:
        return f"/repos/{self.repository}{suffix}"

    # ------------------------------------------------------------------ reads
    def repository_info(self) -> dict[str, Any]:
        d = self._request("GET", self._repo()).json()
        return {
            "full_name": d.get("full_name"),
            "default_branch": d.get("default_branch"),
            "private": d.get("private"),
            "visibility": d.get("visibility"),
            "description": d.get("description") or "",
            "url": d.get("html_url"),
        }

    def pull_requests(self, state: str = "open", limit: int = 20) -> list[dict[str, Any]]:
        rows = self._request(
            "GET", self._repo("/pulls"), params={"state": state, "per_page": limit}
        ).json()
        return [self._pr_summary(p) for p in rows[:limit]]

    def pull_request(self, number: int, *, include_diff: bool = True) -> dict[str, Any]:
        d = self._request("GET", self._repo(f"/pulls/{number}")).json()
        pr = self._pr_summary(d)
        pr.update(
            body=d.get("body") or "",
            mergeable=d.get("mergeable"),
            additions=d.get("additions"),
            deletions=d.get("deletions"),
            changed_files=d.get("changed_files"),
        )
        if include_diff:
            diff = self._request(
                "GET", self._repo(f"/pulls/{number}"), accept="application/vnd.github.diff"
            ).text
            pr["diff_truncated"] = len(diff) > MAX_DIFF_CHARS
            pr["diff"] = diff[:MAX_DIFF_CHARS]
        return pr

    def issue(self, number: int) -> dict[str, Any]:
        d = self._request("GET", self._repo(f"/issues/{number}")).json()
        return {
            "number": d.get("number"),
            "title": d.get("title") or "",
            "state": d.get("state"),
            "author": (d.get("user") or {}).get("login"),
            "labels": [label.get("name") for label in d.get("labels") or []],
            "body": d.get("body") or "",
            "is_pull_request": "pull_request" in d,
            "url": d.get("html_url"),
        }

    def branch_exists(self, branch: str) -> bool:
        # The ref endpoint, not /branches/: branch names such as "fix/x" contain slashes.
        try:
            self._request("GET", self._repo(f"/git/ref/heads/{quote(branch, safe='/')}"))
        except RepositoryError as exc:
            if "HTTP 404" in str(exc):
                return False
            raise
        return True

    # ------------------------------------------------------------------ writes
    def create_pull_request(
        self, *, title: str, body: str, head: str, base: str, draft: bool = True
    ) -> dict[str, Any]:
        d = self._request(
            "POST",
            self._repo("/pulls"),
            json={"title": title, "body": body, "head": head, "base": base, "draft": draft},
        ).json()
        return {"number": d.get("number"), "url": d.get("html_url"), "draft": d.get("draft")}

    def comment(self, number: int, body: str, *, marker: str | None = None) -> dict[str, Any]:
        """Post a comment; with ``marker``, update the newest comment carrying it instead.

        The marker lets a CI run keep one review comment current rather than adding one per
        push. Anyone can copy a marker into their own comment, and GitHub refuses to let us
        edit that, so a refused update falls back to posting a new comment.
        """
        # Pull requests are issues for comments; one endpoint serves both.
        if marker:
            for existing in reversed(self._comments(number)):
                if str(existing.get("body") or "").startswith(marker):
                    try:
                        d = self._request(
                            "PATCH",
                            self._repo(f"/issues/comments/{existing['id']}"),
                            json={"body": body},
                        ).json()
                    except RepositoryError:
                        break
                    return {"id": d.get("id"), "url": d.get("html_url"), "updated": True}
        d = self._request(
            "POST", self._repo(f"/issues/{number}/comments"), json={"body": body}
        ).json()
        return {"id": d.get("id"), "url": d.get("html_url"), "updated": False}

    def _comments(self, number: int, pages: int = 5) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for page in range(1, pages + 1):
            batch = self._request(
                "GET",
                self._repo(f"/issues/{number}/comments"),
                params={"per_page": 100, "page": page},
            ).json()
            found.extend(batch)
            if len(batch) < 100:
                break
        return found

    @staticmethod
    def _pr_summary(p: dict[str, Any]) -> dict[str, Any]:
        return {
            "number": p.get("number"),
            "title": p.get("title") or "",
            "state": p.get("state"),
            "draft": p.get("draft"),
            "author": (p.get("user") or {}).get("login"),
            "head": (p.get("head") or {}).get("ref"),
            "base": (p.get("base") or {}).get("ref"),
            "url": p.get("html_url"),
        }
