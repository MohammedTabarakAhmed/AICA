"""Git tools (GIT-001..GIT-010, SAFE-003).

Read operations are always available inside the authorized repository. Mutations go
through policy: protected branches require approval with the diff shown (GIT-007,
SAFE-003); force operations and history rewrites are classified destructive; clone and
push touch the network and require approval (EXTERNAL). ``git`` is invoked with fixed
argv and never through a shell.
"""

from __future__ import annotations

import subprocess  # noqa: S404 - fixed argv git invocations
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from aica.audit import EventCategory, Outcome
from aica.policy.models import ActionCategory
from aica.tools.base import Tool, ToolContext, ToolError, ToolResult

_BRANCH_RE = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,200}$"


def _git(ctx: ToolContext, *args: str, check: bool = True) -> str:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
            ["git", *args],  # noqa: S607 - git resolved from PATH by design
            cwd=ctx.workspace.root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ToolError(f"git {' '.join(args)}: {exc}") from exc
    if check and proc.returncode != 0:
        raise ToolError(f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}")
    return proc.stdout


def _require_repo(ctx: ToolContext) -> None:
    if ctx.git is None or not ctx.git.is_repository():
        raise ToolError("workspace is not a Git repository (GIT-001)")


def _record(ctx: ToolContext, action: str, ok: bool = True, **details: object) -> None:
    ctx.audit.record(
        category=EventCategory.GIT,
        action=action,
        outcome=Outcome.SUCCESS if ok else Outcome.FAILURE,
        tool="git",
        details=dict(details),
        session_id=ctx.session_id,
    )


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid")


# ------------------------------------------------------------------ GIT-002


class GitStatus(Tool):
    name: ClassVar[str] = "git.status"
    description: ClassVar[str] = "Current branch, staged/modified/untracked/conflicted files."

    class Args(_Args):
        pass

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        _require_repo(ctx)
        assert ctx.git is not None
        st = ctx.git.status()
        lines = [f"branch: {st.branch or '(detached)'}"]
        for label, items in (
            ("staged", st.staged),
            ("modified", st.modified),
            ("untracked", st.untracked),
            ("conflicted", st.conflicted),
        ):
            for p in items:
                lines.append(f"{label}: {p}")
        return ToolResult(
            output="\n".join(lines),
            data={
                "branch": st.branch,
                "staged": list(st.staged),
                "modified": list(st.modified),
                "untracked": list(st.untracked),
                "conflicted": list(st.conflicted),
                "clean": st.is_clean,
            },
        )


class GitLog(Tool):
    name: ClassVar[str] = "git.log"
    description: ClassVar[str] = "Recent commit history."

    class Args(_Args):
        max_count: int = Field(default=20, ge=1, le=500)
        path: str | None = None

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        _require_repo(ctx)
        argv = [
            "log",
            f"--max-count={args.max_count}",
            "--pretty=format:%h%x09%an%x09%ad%x09%s",
            "--date=short",
        ]
        if args.path:
            argv += ["--", ctx.workspace.resolve(args.path).relative.as_posix()]
        out = _git(ctx, *argv, check=False)
        commits = [
            dict(zip(("hash", "author", "date", "subject"), line.split("\t", 3), strict=False))
            for line in out.splitlines()
            if line
        ]
        return ToolResult(output=out, data={"commits": commits})


class GitBranches(Tool):
    name: ClassVar[str] = "git.branches"
    description: ClassVar[str] = "List local branches and the current one."

    class Args(_Args):
        pass

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        _require_repo(ctx)
        out = _git(ctx, "branch", "--format=%(refname:short)", check=False)
        assert ctx.git is not None
        branches = [b for b in out.splitlines() if b]
        return ToolResult(
            output="\n".join(branches),
            data={
                "branches": branches,
                "current": ctx.git.current_branch(),
                "protected": ctx.policy.git.protected_branches,
            },
        )


# ------------------------------------------------------------------ GIT-003


class GitCreateBranch(Tool):
    name: ClassVar[str] = "git.create_branch"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = "Create and switch to a new working branch."

    class Args(_Args):
        name: str = Field(pattern=_BRANCH_RE)
        start_point: str | None = None

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        _require_repo(ctx)
        if ctx.policy.git.is_protected(args.name):
            raise ToolError(f"{args.name} is a protected branch name")
        argv = ["switch", "-c", args.name] + ([args.start_point] if args.start_point else [])
        _git(ctx, *argv)
        _record(ctx, f"create_branch {args.name}")
        return ToolResult(output=f"switched to new branch {args.name}", data={"branch": args.name})


class GitSwitch(Tool):
    name: ClassVar[str] = "git.switch"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Switch to an existing branch (refuses if uncommitted changes would be lost)."
    )

    class Args(_Args):
        name: str = Field(pattern=_BRANCH_RE)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        _require_repo(ctx)
        assert ctx.git is not None
        st = ctx.git.status()
        if st.modified or st.staged or st.conflicted:
            raise ToolError(
                "uncommitted changes present; commit or stash before switching (GIT-010)"
            )
        _git(ctx, "switch", args.name)
        _record(ctx, f"switch {args.name}")
        return ToolResult(output=f"switched to {args.name}", data={"branch": args.name})


# ------------------------------------------------------------------ GIT-005


MAX_UNTRACKED_BYTES = 200_000
AGENT_STATE_DIR = ".aica"


def _untracked_diff(ctx: ToolContext, path: str | None) -> tuple[str, list[str]]:
    """Synthesise all-added diffs for untracked files, so new files can be reviewed.

    ``git diff`` does not show a file Git has never seen, which means the output an agent
    most often produces - a brand new module - is invisible to anything reading the diff.
    Staging the file with ``git add -N`` would make it visible, but writing to the index
    to answer a read-only question is exactly the kind of side effect GIT-010 exists to
    prevent. The file's whole content is added by definition, so the diff is synthesised
    from it instead: no index is touched and no git command is run.

    Binary, empty and oversized files are skipped: a text diff has nothing to say about
    them, and ``untracked_included`` in the result names exactly which files were added,
    so a caller can see what the review did and did not cover.
    """
    assert ctx.git is not None
    prefix = ctx.workspace.resolve(path).relative.as_posix() if path else None
    blocks: list[str] = []
    included: list[str] = []
    for relative in sorted(ctx.git.status().untracked):
        # The agent's own state directory is never part of the user's change. It is
        # git-ignored in a configured repository, but a workspace without a .gitignore
        # would otherwise offer the audit log and the control plane up for review.
        if relative == AGENT_STATE_DIR or relative.startswith(AGENT_STATE_DIR + "/"):
            continue
        if prefix and not (relative == prefix or relative.startswith(prefix + "/")):
            continue
        try:
            resolved = ctx.workspace.resolve(relative)
        except (PermissionError, ValueError):
            continue  # outside the authorized directories: not ours to review
        target = resolved.absolute
        if not target.is_file():
            continue
        try:
            if target.stat().st_size > MAX_UNTRACKED_BYTES:
                continue
            content = target.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable: nothing a text diff can say about it
        lines = content.splitlines()
        if not lines:
            continue
        body = "\n".join(f"+{line}" for line in lines)
        blocks.append(
            f"diff --git a/{relative} b/{relative}\n"
            f"new file mode 100644\n--- /dev/null\n+++ b/{relative}\n"
            f"@@ -0,0 +1,{len(lines)} @@\n{body}\n"
        )
        included.append(relative)
    return "".join(blocks), included


class GitDiff(Tool):
    name: ClassVar[str] = "git.diff"
    description: ClassVar[str] = (
        "Unified diff of the working tree (or staged changes / a specific path)."
    )

    class Args(_Args):
        staged: bool = False
        path: str | None = None
        base: str | None = Field(
            default=None, description="compare against this ref instead of the index"
        )
        include_untracked: bool = Field(
            default=False,
            description="also emit new, untracked files as all-added diffs (REV-001)",
        )

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        _require_repo(ctx)
        argv = ["diff", "--no-color"]
        if args.staged:
            argv.append("--cached")
        if args.base:
            argv.append(args.base)
        if args.path:
            argv += ["--", ctx.workspace.resolve(args.path).relative.as_posix()]
        out = _git(ctx, *argv)
        untracked: list[str] = []
        if args.include_untracked and not args.staged and not args.base:
            extra, untracked = _untracked_diff(ctx, args.path)
            out += extra
        stat = _git(
            ctx,
            "diff",
            "--stat",
            *(["--cached"] if args.staged else []),
            *([args.base] if args.base else []),
            check=False,
        )
        return ToolResult(
            output=out,
            data={
                "diff": out,
                "stat": stat,
                "changed": bool(out),
                "untracked_included": untracked,
            },
        )


# ------------------------------------------------------------------ GIT-007


class GitCommit(Tool):
    name: ClassVar[str] = "git.commit"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Stage the given paths (or all changes) and commit. Protected branches require approval with the diff shown."
    )

    class Args(_Args):
        message: str = Field(min_length=3, max_length=5000)
        paths: list[str] = Field(
            default_factory=list,
            description="paths to stage; empty = all tracked+untracked changes",
        )

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        _require_repo(ctx)
        assert ctx.git is not None
        branch = ctx.git.current_branch()
        if args.paths:
            _git(
                ctx,
                "add",
                "--",
                *[ctx.workspace.resolve(p).relative.as_posix() for p in args.paths],
            )
        else:
            _git(ctx, "add", "-A")
        diff = _git(ctx, "diff", "--cached", "--no-color")
        if not diff.strip():
            raise ToolError("nothing to commit")
        if branch is not None and ctx.policy.git.is_protected(branch):
            # SAFE-003: show the diff before a protected commit.
            ctx.require_approval(
                self.name,
                f"commit to protected branch {branch}",
                [ActionCategory.PROTECTED_BRANCH_COMMIT],
                diff=diff[:20_000],
                message=args.message,
            )
        _git(ctx, "commit", "-q", "-m", args.message)
        sha = _git(ctx, "rev-parse", "--short", "HEAD").strip()
        _record(ctx, f"commit {sha}", branch=branch, message=args.message)
        return ToolResult(
            output=f"[{branch}] {sha} {args.message.splitlines()[0]}",
            data={"commit": sha, "branch": branch, "diff": diff},
        )


# ------------------------------------------------------------------ GIT-009


class GitRevert(Tool):
    name: ClassVar[str] = "git.revert"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Create a revert commit for a commit made by the agent (non-destructive undo)."
    )

    class Args(_Args):
        commit: str = Field(pattern=r"^[0-9a-fA-F]{4,40}$")

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        _require_repo(ctx)
        assert ctx.git is not None
        branch = ctx.git.current_branch()
        if branch is not None and ctx.policy.git.is_protected(branch):
            ctx.require_approval(
                self.name,
                f"revert {args.commit} on protected branch {branch}",
                [ActionCategory.PROTECTED_BRANCH_COMMIT],
            )
        _git(ctx, "revert", "--no-edit", args.commit)
        sha = _git(ctx, "rev-parse", "--short", "HEAD").strip()
        _record(ctx, f"revert {args.commit} -> {sha}")
        return ToolResult(output=f"reverted {args.commit} in {sha}", data={"commit": sha})


class GitDiscardChanges(Tool):
    name: ClassVar[str] = "git.discard"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Discard uncommitted changes in given paths (DESTRUCTIVE; approval required)."
    )

    class Args(_Args):
        paths: list[str] = Field(min_length=1)

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        _require_repo(ctx)
        rels = [ctx.workspace.resolve(p).relative.as_posix() for p in args.paths]
        ctx.require_approval(
            self.name,
            f"discard uncommitted changes in {', '.join(rels)}",
            [ActionCategory.DESTRUCTIVE],
        )
        _git(ctx, "checkout", "--", *rels)
        _record(ctx, "discard", paths=rels)
        return ToolResult(output="discarded: " + ", ".join(rels), data={"paths": rels})


# ------------------------------------------------------------------ GIT-008


class GitPullRequestContent(Tool):
    name: ClassVar[str] = "git.pr_content"
    description: ClassVar[str] = (
        "Prepare pull-request title/description from commits and diff stat against a base branch."
    )

    class Args(_Args):
        base: str = Field(pattern=_BRANCH_RE)
        title: str | None = None
        tests_summary: str = ""
        risk_notes: str = ""

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        _require_repo(ctx)
        assert ctx.git is not None
        head = ctx.git.current_branch() or "HEAD"
        commits = _git(
            ctx, "log", f"{args.base}..{head}", "--pretty=format:- %s", check=False
        ).strip()
        stat = _git(ctx, "diff", "--stat", f"{args.base}...{head}", check=False).strip()
        title = args.title or (commits.splitlines()[0][2:] if commits else f"Changes from {head}")
        body = (
            f"## Summary\n{commits or '(no commits)'}\n\n"
            f"## Changes\n```\n{stat or '(no changes)'}\n```\n\n"
            f"## Tests\n{args.tests_summary or 'Not recorded.'}\n\n"
            f"## Risk notes\n{args.risk_notes or 'None noted.'}\n"
        )
        return ToolResult(
            output=f"# {title}\n\n{body}",
            data={"title": title, "body": body, "base": args.base, "head": head},
        )


# ------------------------------------------------------------------ GIT-001


class GitClone(Tool):
    name: ClassVar[str] = "git.clone"
    mutating: ClassVar[bool] = True
    description: ClassVar[str] = (
        "Clone an authorized repository into the workspace (EXTERNAL; approval and network policy apply)."
    )

    class Args(_Args):
        url: str = Field(min_length=4, max_length=2000)
        directory: str

    def run(self, args: BaseModel, ctx: ToolContext) -> ToolResult:
        assert isinstance(args, self.Args)
        from urllib.parse import urlparse

        host = urlparse(args.url).hostname or ""
        if host and not ctx.policy.network.is_host_allowed(host):
            raise PermissionError(f"host {host!r} not allowed by network policy (SAFE-005)")
        dest = ctx.workspace.resolve(args.directory).absolute
        if dest.exists():
            raise ToolError(f"{args.directory} already exists")
        ctx.require_approval(
            self.name, f"clone {args.url} -> {args.directory}", [ActionCategory.EXTERNAL]
        )
        _git(ctx, "clone", "--quiet", args.url, str(dest))
        _record(ctx, f"clone {args.url}", directory=args.directory)
        return ToolResult(
            output=f"cloned into {args.directory}", data={"directory": args.directory}
        )


GIT_TOOLS: list[Tool] = [
    GitStatus(),
    GitLog(),
    GitBranches(),
    GitCreateBranch(),
    GitSwitch(),
    GitDiff(),
    GitCommit(),
    GitRevert(),
    GitDiscardChanges(),
    GitPullRequestContent(),
    GitClone(),
]
