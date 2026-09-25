"""Repository-provider tools (INT-006): an approved connector to a hosted Git repository.

The ``repository`` group is **off by default**: it reaches a third-party service, so a
workspace enables it in ``[autonomy].allowed_tools`` on purpose, as it does ``mcp``.

Four controls, each for a different failure:

* **Connector by name** (``config/repositories.toml``): a call cannot choose the repository,
  the host or the credential.
* **Connector permissions**: ``read`` / ``pull_request`` / ``comment``, checked before any
  request is made.
* **Approval**: using the token is a SECRET_ACCESS approval (SEC-004); opening a pull
  request or posting a comment is also EXTERNAL, because it is visible to other people.
* **Content discipline**: what the provider returns is fenced as untrusted and scanned for
  injection (SAFE-007); what is posted is redacted first (SAFE-006), and the token is
  scrubbed from every output literally.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aica.integrations.github import GitHubClient
from aica.integrations.repositories import (
    ConnectorConfig,
    ConnectorPermission,
    RepositoryError,
    load_repositories,
)
from aica.policy.models import ActionCategory
from aica.safety.injection import scan_for_injection, wrap_untrusted
from aica.safety.redaction import redact
from aica.safety.secrets import SecretStore, scrub
from aica.tools.base import Tool, ToolContext, ToolError, ToolResult
from aica.tools.git_tool import GitPullRequestContent

_BRANCH = r"^[A-Za-z0-9._/-]{1,200}$"


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connector: str | None = Field(
        default=None, description="approved connector name; omitted means the default"
    )


def _connector(ctx: ToolContext, name: str | None, need: ConnectorPermission) -> ConnectorConfig:
    try:
        config = load_repositories(ctx.repositories_file).get(name)
    except RepositoryError as exc:
        raise ToolError(str(exc)) from exc
    if not config.permits(need):
        raise PermissionError(
            f"repository connector {config.name!r} does not permit {need.value!r} "
            f"(permits: {', '.join(p.value for p in config.permissions)}) (INT-006)"
        )
    if not ctx.policy.network.is_host_allowed(config.host):
        raise PermissionError(
            f"repository connector {config.name!r}: host {config.host!r} is not allowed by "
            "network policy; add it to [network].allowed_hosts (SAFE-005)"
        )
    return config


@contextmanager
def _client(ctx: ToolContext, config: ConnectorConfig, tool: str) -> Iterator[GitHubClient]:
    """An authenticated client for one tool call. The token never outlives the call."""
    token: str | None = None
    if config.secret:
        ctx.require_approval(
            tool,
            f"use secret {config.secret!r} for repository {config.repository}",
            [ActionCategory.SECRET_ACCESS],
            secret=config.secret,
        )
        injection = SecretStore(ctx.policy.secrets).prepare([config.secret], tool)
        token = next(iter(injection.values), None)
    client = GitHubClient(config.api_url, config.repository, token, transport=ctx.http_transport)
    try:
        yield client
    except RepositoryError as exc:
        raise ToolError(scrub(str(exc), (token,) if token else ())) from exc
    finally:
        client.close()


def _untrusted(text: str, source: str, warnings: list[str]) -> str:
    report = scan_for_injection(text, source)
    if report.suspicious:
        warnings.append(
            f"{source}: possible prompt injection ({report.findings[0].pattern}); treated as data"
        )
    return wrap_untrusted(text, source)


# ------------------------------------------------------------------ reads


class RepoInfo(Tool):
    name: ClassVar[str] = "repo.info"
    description: ClassVar[str] = (
        "Metadata of the repository behind an approved connector (INT-006): default branch, "
        "visibility, URL."
    )

    class Args(_Args):
        pass

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _connector(ctx, args.connector, ConnectorPermission.READ)
        with _client(ctx, config, self.name) as client:
            info = client.repository_info()
        lines = [f"{k}: {v}" for k, v in info.items() if k != "description"]
        return ToolResult(output="\n".join(lines), data={"connector": config.name, **info})


class RepoPullRequests(Tool):
    name: ClassVar[str] = "repo.pull_requests"
    description: ClassVar[str] = "List pull requests of the connector's repository (INT-006)."

    class Args(_Args):
        state: str = Field(default="open", pattern="^(open|closed|all)$")
        limit: int = Field(default=20, ge=1, le=100)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _connector(ctx, args.connector, ConnectorPermission.READ)
        with _client(ctx, config, self.name) as client:
            prs = client.pull_requests(args.state, args.limit)
        warnings: list[str] = []
        listing = "\n".join(
            f"#{p['number']} [{p['state']}{', draft' if p['draft'] else ''}] "
            f"{p['head']} -> {p['base']}: {p['title']}"
            for p in prs
        )
        return ToolResult(
            output=_untrusted(listing or "(none)", f"{config.repository} pull requests", warnings),
            data={"connector": config.name, "pull_requests": prs, "warnings": warnings},
        )


class RepoPullRequest(Tool):
    name: ClassVar[str] = "repo.pull_request"
    description: ClassVar[str] = (
        "One pull request with its description and diff (INT-006). The content is untrusted."
    )

    class Args(_Args):
        number: int = Field(ge=1)
        include_diff: bool = True

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _connector(ctx, args.connector, ConnectorPermission.READ)
        with _client(ctx, config, self.name) as client:
            pr = client.pull_request(args.number, include_diff=args.include_diff)
        warnings: list[str] = []
        text = f"# {pr['title']}\n\n{pr['body']}"
        if args.include_diff:
            text += f"\n\n## Diff\n{pr['diff']}"
            if pr["diff_truncated"]:
                warnings.append("diff truncated")
        header = (
            f"#{pr['number']} [{pr['state']}] {pr['head']} -> {pr['base']} by {pr['author']} "
            f"(+{pr['additions']}/-{pr['deletions']}, {pr['changed_files']} files)"
        )
        source = f"{config.repository} pull request #{pr['number']}"
        return ToolResult(
            output=header + "\n" + _untrusted(text, source, warnings),
            data={"connector": config.name, **pr, "warnings": warnings},
        )


class RepoIssue(Tool):
    name: ClassVar[str] = "repo.issue"
    description: ClassVar[str] = (
        "One issue with its description (INT-006). The content is untrusted."
    )

    class Args(_Args):
        number: int = Field(ge=1)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _connector(ctx, args.connector, ConnectorPermission.READ)
        with _client(ctx, config, self.name) as client:
            issue = client.issue(args.number)
        warnings: list[str] = []
        header = f"#{issue['number']} [{issue['state']}] by {issue['author']}"
        source = f"{config.repository} issue #{issue['number']}"
        text = f"# {issue['title']}\n\n{issue['body']}"
        return ToolResult(
            output=header + "\n" + _untrusted(text, source, warnings),
            data={"connector": config.name, **issue, "warnings": warnings},
        )


# ------------------------------------------------------------------ writes


def _outgoing(text: str) -> tuple[str, int]:
    """SAFE-006: nothing leaves for a third-party service unredacted."""
    result = redact(text)
    return result.text, result.count


class RepoCreatePullRequest(Tool):
    name: ClassVar[str] = "repo.create_pull_request"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Open a pull request from the current branch (EXTERNAL; approval required). The branch "
        "must already be pushed (git.push). Title and body default to git.pr_content (GIT-008)."
    )

    class Args(_Args):
        base: str | None = Field(default=None, pattern=_BRANCH)
        title: str | None = Field(default=None, max_length=256)
        body: str | None = Field(default=None, max_length=60_000)
        tests_summary: str = ""
        risk_notes: str = ""
        draft: bool = True

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _connector(ctx, args.connector, ConnectorPermission.PULL_REQUEST)
        if ctx.git is None or not ctx.git.is_repository():
            raise ToolError("not a git repository")
        head = ctx.git.current_branch()
        if not head:
            raise ToolError("detached HEAD: switch to the branch the pull request is for")
        with _client(ctx, config, self.name) as client:
            base = args.base or str(client.repository_info()["default_branch"])
            if head == base:
                raise ToolError(f"head and base are both {head!r}; work on a branch first")
            if not client.branch_exists(head):
                raise ToolError(
                    f"branch {head!r} is not on {config.repository}; push it first (git.push)"
                )
            title, body = args.title, args.body
            if title is None or body is None:
                prepared = GitPullRequestContent().invoke(
                    {
                        "base": base,
                        "title": title,
                        "tests_summary": args.tests_summary,
                        "risk_notes": args.risk_notes,
                    },
                    ctx,
                )
                title = title or str(prepared.data["title"])
                body = body if body is not None else str(prepared.data["body"])
            body, redactions = _outgoing(body)
            title, title_redactions = _outgoing(title)
            ctx.require_approval(
                self.name,
                f"open {'draft ' if args.draft else ''}pull request on {config.repository}: "
                f"{head} -> {base}: {title}",
                [ActionCategory.EXTERNAL],
                repository=config.repository,
                head=head,
                base=base,
            )
            created = client.create_pull_request(
                title=title, body=body, head=head, base=base, draft=args.draft
            )
        total = redactions + title_redactions
        note = f" ({total} secret(s) redacted)" if total else ""
        return ToolResult(
            output=f"opened pull request #{created['number']}: {created['url']}{note}",
            data={
                "connector": config.name,
                **created,
                "head": head,
                "base": base,
                "title": title,
                "redactions": total,
            },
        )


class RepoComment(Tool):
    name: ClassVar[str] = "repo.comment"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Comment on a pull request or issue (EXTERNAL; approval required), e.g. review findings."
    )

    class Args(_Args):
        number: int = Field(ge=1)
        body: str = Field(min_length=1, max_length=60_000)
        marker: str | None = Field(
            default=None,
            pattern=r"^[a-z0-9-]{1,40}$",
            description="keep one comment current: update the last comment with this marker",
        )

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        config = _connector(ctx, args.connector, ConnectorPermission.COMMENT)
        body, redactions = _outgoing(args.body)
        # What the approver reads is what will be sent: the redacted text, not the argument.
        first_line = body.strip().splitlines()[0][:120] if body.strip() else ""
        tag = f"<!-- aica:{args.marker} -->" if args.marker else None
        if tag:
            body = f"{tag}\n{body}"
        with _client(ctx, config, self.name) as client:
            ctx.require_approval(
                self.name,
                f"comment on {config.repository}#{args.number}: {first_line}",
                [ActionCategory.EXTERNAL],
                repository=config.repository,
                number=args.number,
            )
            posted = client.comment(args.number, body, marker=tag)
        note = f" ({redactions} secret(s) redacted)" if redactions else ""
        verb = "updated comment on" if posted["updated"] else "commented on"
        return ToolResult(
            output=f"{verb} #{args.number}: {posted['url']}{note}",
            data={"connector": config.name, **posted, "redactions": redactions},
        )


REPOSITORY_TOOLS: list[Tool] = [
    RepoInfo(),
    RepoPullRequests(),
    RepoPullRequest(),
    RepoIssue(),
    RepoCreatePullRequest(),
    RepoComment(),
]
