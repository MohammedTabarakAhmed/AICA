"""AICA command-line interface (INT-002).

Commands:
  aica index [--force] [subdir]      index the repository (RAG-001/006)
  aica search <query> [--mode ...]   search the repository (RAG-003/004/008)
  aica deps --path P | --symbol S    dependency/reference view (RAG-005)
  aica ask <question>                repository-aware chat (CHAT-001..005, streams)
  aica complete --file F --line N    code completion at a cursor (CC-001..003)
  aica debug --log F                 diagnose a failure from a log/traceback (CHAT-004)
  aica conventions [--set K=V]       project conventions and context (CC-004, MEM-004)
  aica commit-message                model-written, validated commit message (GIT-006)
  aica gen-tests --file F            propose tests for a file (TEST-007)
  aica review [--base REF]           review a change for bugs, conventions, tests, security (REV-001..007)
  aica task <description>            run an agent task end to end (AG-001..010)
  aica browse --url U                inspect a running app in a real browser (WEB-001..005)
  aica db schema|query|explain       controlled database access (DB-001..007)
  aica mcp list|tools|call           MCP servers and their tools (MCP-001/005/007)
  aica serve [--port N]              run the HTTP API (API-001..011)
  aica eval run|gate|compare         golden-task evaluation (EVAL-001..009)
  aica test [--kind unit]            discover and run tests (TEST-001..009)
  aica run <command>                 policy-checked command execution (EXEC-001..007)
  aica git status|diff|branches      Git inspection (GIT-002/005)
  aica models                        list approved models (MM-001/013)
  aica sessions [--resume ID]        session history (MEM-001/003)
  aica policy                        show the effective policy
  aica audit [--limit N]             recent audit events (EXEC-007/MCP-006)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aica import __version__
from aica.agent.events import AgentEvent, CallbackSink, EventType
from aica.agent.loop import STATE_KEY, AgentLoop, AgentState
from aica.agent.plan import PlanError
from aica.agent.subagents import Delegation, SubagentRole
from aica.approvals import AllowAllApprover, ApprovalRequired, ConsoleApprover
from aica.audit import AuditLog, JsonlAuditSink
from aica.chat.assistant import CodingAssistant
from aica.chat.commit_message import InvalidCommitMessage, suggest_commit_message
from aica.chat.session import Session, SessionStore
from aica.database.connections import DatabaseError, load_databases
from aica.database.migrations import MigrationError, generate_migration
from aica.mcp.config import MCPConfigError, load_mcp_config
from aica.models.base import ModelError
from aica.models.gateway import ModelGateway
from aica.models.routing import ModelRouter, TaskKind
from aica.policy import load_policy
from aica.policy.budget import RunBudget
from aica.rag.index import RepositoryIndex
from aica.review.findings import Severity, severity_rank
from aica.review.reviewer import DEFAULT_CHECKS, CodeReviewer, ReviewCheck, ReviewRequest
from aica.testing.browser_tests import generate_browser_test
from aica.testing.generation import GenerationError, generate_tests
from aica.tools import ToolContext, default_registry
from aica.tools.base import ToolArgumentError, ToolError, ToolNotAllowed
from aica.tools.mcp_tool import MCPSession
from aica.workspace import GitGuard, WorkspaceGuard
from aica.workspace.project_context import (
    ProjectContextStore,
    detect_conventions,
    project_conventions_block,
)

# Indexes opened during a CLI invocation, closed before main() returns so the SQLite
# connections are not left dangling.
_OPEN_INDEXES: list[RepositoryIndex] = []


def _context(args: argparse.Namespace) -> tuple[ToolContext, RepositoryIndex]:
    root = Path(args.workspace).resolve()
    policy = load_policy(args.policy)
    ws = WorkspaceGuard(root, policy.autonomy.allowed_directories)
    git = GitGuard(ws.root, policy.git)
    audit = AuditLog(
        JsonlAuditSink(root / ".aica" / "audit"),
        actor=args.actor,
        session_id=getattr(args, "session", None),
    )
    approver = AllowAllApprover() if getattr(args, "yes", False) else ConsoleApprover()
    index = RepositoryIndex(ws)
    _OPEN_INDEXES.append(index)
    ctx = ToolContext(
        workspace=ws,
        policy=policy,
        audit=audit,
        git=git if git.is_repository() else None,
        approver=approver,
        session_id=getattr(args, "session", None),
        index=index,
    )
    return ctx, index


def _adapter(  # type: ignore[no-untyped-def]
    args: argparse.Namespace, ctx: ToolContext, task: TaskKind = TaskKind.GENERAL
):
    """The model for this kind of work, through the router (MM-002/004/009/010/012).

    ``--model`` still wins: a name given on the command line is honoured, and the fallback
    chain is appended only when that model is not pinned. Without ``--model`` the routing
    rules in config/models.toml decide, and the choice is recorded in the audit log.
    """
    gateway = ModelGateway.from_file(ctx.policy.network, getattr(args, "models_file", None))
    router = ModelRouter(
        gateway, gateway.routing, audit=ctx.audit, session_id=getattr(args, "session", None)
    )
    selection = router.select(task, requested=getattr(args, "model", None))
    if getattr(args, "verbose_model", False):
        print(f"[model] {selection.describe()}", file=sys.stderr)
    return selection.adapter, gateway


def _print_results(results: list[object]) -> None:
    from aica.rag.index import SearchResult

    for r in results:
        assert isinstance(r, SearchResult)
        print(f"\n=== {r.location}  [{r.language}/{r.kind}]  score={r.score}")
        print(r.text if len(r.text) < 1500 else r.text[:1500] + "\n... [truncated]")


# ------------------------------------------------------------------ commands


def cmd_index(args: argparse.Namespace) -> int:
    ctx, index = _context(args)
    stats = index.index_repository(args.subdir, force=args.force)
    print(
        f"indexed {stats.files_indexed} file(s), unchanged {stats.files_unchanged}, "
        f"skipped {stats.files_skipped}, removed {stats.files_removed}"
    )
    print(f"{stats.chunks} chunks in {stats.duration_ms} ms")
    for k, v in index.stats().items():
        print(f"{k}: {v}")
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    ctx, index = _context(args)
    if index.stats()["files"] == 0:
        print("index is empty; run `aica index` first", file=sys.stderr)
        return 2
    if args.mode == "lexical":
        results = index.search_lexical(args.query, args.limit)
    elif args.mode == "semantic":
        results = index.search_semantic(args.query, args.limit)
    elif args.mode == "symbol":
        results = index.search_symbol(args.query, args.limit)
    else:
        results = index.search(args.query, args.limit, depth=args.depth)
    if not results:
        print("(no matches)")
        return 1
    _print_results(list(results))
    return 0


def cmd_deps(args: argparse.Namespace) -> int:
    ctx, index = _context(args)
    if args.path:
        rel = ctx.workspace.resolve(args.path).relative.as_posix()
        n = index.neighbors(rel)
        print(f"{rel}\n  imports:     {', '.join(n['imports']) or '(none)'}")
        print(f"  imported by: {', '.join(n['imported_by']) or '(none)'}")
    if args.symbol:
        defs = index.search_symbol(args.symbol, 10)
        refs = index.references_to(args.symbol, 15)
        print(f"definitions of {args.symbol}:")
        for d in defs:
            print(f"  {d.location}")
        print(f"references to {args.symbol}:")
        for r in refs:
            print(f"  {r.location}")
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    ctx, index = _context(args)
    store = SessionStore(ctx.workspace.root)
    session = (
        store.load(args.session) if args.session else Session(workspace=str(ctx.workspace.root))
    )
    try:
        adapter, _ = _adapter(args, ctx, TaskKind.CHAT)
    except (ModelError, PermissionError) as exc:
        print(f"model unavailable: {exc}", file=sys.stderr)
        return 3
    session.model_name = adapter.info.name
    session.policy_version = ctx.policy.version
    assistant = CodingAssistant(
        adapter,
        index,
        depth=args.depth,
        workspace_root=ctx.workspace.root,
        project_context=ProjectContextStore(ctx.workspace.root).load(),
    )
    question = " ".join(args.question)
    if args.no_stream:
        answer = assistant.ask(session, question)
        print(answer.text)
        if answer.sources:
            print("\nsources: " + ", ".join(answer.sources))
    else:
        for delta in assistant.ask_stream(session, question):
            sys.stdout.write(delta)
            sys.stdout.flush()
        print()
    path = store.save(session)
    print(
        f"\n[session {session.session_id} | model {adapter.info.version} | saved {path.name}]",
        file=sys.stderr,
    )
    return 0


def cmd_complete(args: argparse.Namespace) -> int:
    ctx, index = _context(args)
    resolved = ctx.workspace.resolve(args.file)
    text = resolved.absolute.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    cut = sum(len(line) for line in lines[: args.line])
    prefix, suffix = text[:cut], text[cut:]
    try:
        adapter, _ = _adapter(args, ctx, TaskKind.COMPLETION)
    except (ModelError, PermissionError) as exc:
        print(f"model unavailable: {exc}", file=sys.stderr)
        return 3
    answer = CodingAssistant(
        adapter,
        index,
        workspace_root=ctx.workspace.root,
        project_context=ProjectContextStore(ctx.workspace.root).load(),
    ).complete(prefix, suffix, path=resolved.relative.as_posix(), max_tokens=args.max_tokens)
    print(answer.text)
    return 0


def cmd_debug(args: argparse.Namespace) -> int:
    """CHAT-004: diagnose a failure from a log file or stdin."""
    ctx, index = _context(args)
    if args.log == "-":
        log = sys.stdin.read()
    else:
        log = ctx.workspace.resolve(args.log).absolute.read_text(encoding="utf-8", errors="replace")
    if not log.strip():
        print("empty log", file=sys.stderr)
        return 2
    store = SessionStore(ctx.workspace.root)
    session = (
        store.load(args.session) if args.session else Session(workspace=str(ctx.workspace.root))
    )
    try:
        adapter, _ = _adapter(args, ctx, TaskKind.CHAT)
    except (ModelError, PermissionError) as exc:
        print(f"model unavailable: {exc}", file=sys.stderr)
        return 3
    assistant = CodingAssistant(
        adapter,
        index,
        workspace_root=ctx.workspace.root,
        project_context=ProjectContextStore(ctx.workspace.root).load(),
    )
    answer, diagnosis = assistant.debug(session, log, " ".join(args.question))
    print("## Log analysis\n" + diagnosis.render())
    print("\n## Diagnosis\n" + answer.text)
    if answer.sources:
        print("\nsources: " + ", ".join(answer.sources))
    store.save(session)
    return 0


def cmd_conventions(args: argparse.Namespace) -> int:
    """CC-004 detected conventions and MEM-004 recorded project context."""
    ctx, _ = _context(args)
    store = ProjectContextStore(ctx.workspace.root)
    context = store.load()
    changed = False
    for item in args.record or []:
        if context.record_convention(item):
            changed = True
    for pair in args.set or []:
        if "=" not in pair:
            print(f"--set expects KEY=VALUE, got {pair!r}", file=sys.stderr)
            return 2
        key, value = pair.split("=", 1)
        context.set_preference(key, value)
        changed = True
    if changed:
        print(f"saved {store.save(context)}")
    conventions = detect_conventions(ctx.workspace.root)
    print("# Detected conventions")
    print(conventions.render() or "(none detected)")
    if conventions.evidence:
        print("\nevidence:")
        for key, value in sorted(conventions.evidence.items()):
            print(f"  {key}: {value}")
    print("\n# Recorded project context (MEM-004)")
    print(context.render() or "(none recorded)")
    return 0


def cmd_commit_message(args: argparse.Namespace) -> int:
    """GIT-006: propose a validated commit message for the current diff."""
    ctx, _ = _context(args)
    registry = default_registry()
    payload = {"staged": True} if args.staged else {}
    diff = registry.call("git.diff", payload, ctx).output
    if not diff.strip():
        print("no changes to describe", file=sys.stderr)
        return 1
    try:
        adapter, _ = _adapter(args, ctx, TaskKind.COMMIT_MESSAGE)
    except (ModelError, PermissionError) as exc:
        print(f"model unavailable: {exc}", file=sys.stderr)
        adapter = None
    try:
        message = (
            suggest_commit_message(adapter, diff, context=" ".join(args.context or []))
            if not args.strict
            else _strict_commit_message(adapter, diff, " ".join(args.context or []))
        )
    except InvalidCommitMessage as exc:
        print(f"could not produce a valid commit message: {exc}", file=sys.stderr)
        return 3
    print(message.text)
    origin = f"model {message.model}" if message.generated else "deterministic fallback (no model)"
    print(f"\n[{origin}]", file=sys.stderr)
    return 0


def _strict_commit_message(adapter: object, diff: str, context: str):  # type: ignore[no-untyped-def]
    from aica.chat.commit_message import generate_commit_message

    if adapter is None:
        raise InvalidCommitMessage("no model available and --strict forbids the fallback")
    return generate_commit_message(adapter, diff, context=context)  # type: ignore[arg-type]


def cmd_gen_tests(args: argparse.Namespace) -> int:
    """TEST-007: propose a test file for a source file. Nothing is written."""
    ctx, index = _context(args)
    resolved = ctx.workspace.resolve(args.file)
    source = resolved.absolute.read_text(encoding="utf-8", errors="replace")
    try:
        adapter, _ = _adapter(args, ctx, TaskKind.TESTING)
    except (ModelError, PermissionError) as exc:
        print(f"model unavailable: {exc}", file=sys.stderr)
        return 3
    try:
        result = generate_tests(
            adapter,
            resolved.relative.as_posix(),
            source,
            root=ctx.workspace.root,
            conventions=project_conventions_block(
                ctx.workspace.root, ProjectContextStore(ctx.workspace.root).load()
            ),
            focus=" ".join(args.focus or []),
        )
    except GenerationError as exc:
        print(str(exc), file=sys.stderr)
        return 3
    print(result.content)
    print(
        f"\n[proposed {result.test_path} | {result.framework} | model {result.model}"
        + (" | FILE EXISTS" if result.exists else "")
        + "]\nNot written. Review, then apply with `aica` filesystem tools.",
        file=sys.stderr,
    )
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    """REV-001..007: review a change. Read-only - nothing is edited, staged or committed.

    The exit code is the useful part for a pre-merge hook: 0 clean, 2 findings at or above
    ``--fail-on``, 6 when the review could not be completed. 6 is deliberately distinct: a
    review that failed halfway is not a review that passed, and a gate that cannot tell the
    two apart is worse than no gate (TEST-009).
    """
    ctx, _ = _context(args)
    registry = default_registry()
    payload: dict[str, object] = {}
    if args.staged:
        payload["staged"] = True
    if args.base:
        payload["base"] = args.base
    if args.path:
        payload["path"] = args.path
    # New files are the bulk of what an agent produces, and `git diff` cannot see them
    # until they are staged. Reviewing them is the default here; --no-untracked opts out.
    payload["include_untracked"] = not args.no_untracked
    result = registry.call("git.diff", payload, ctx)
    diff = result.output
    if not diff.strip():
        print("no changes to review", file=sys.stderr)
        return 0
    included = result.data.get("untracked_included") or []
    if included:
        print(f"including {len(included)} untracked file(s) in the review", file=sys.stderr)

    try:
        adapter, _ = _adapter(args, ctx, TaskKind.REVIEW)
    except (ModelError, PermissionError) as exc:
        if args.strict:
            print(
                f"model unavailable and --strict forbids a static-only review: {exc}",
                file=sys.stderr,
            )
            return 6
        print(f"model unavailable: {exc}; running the static checks only", file=sys.stderr)
        adapter = None

    checks = tuple(ReviewCheck(name) for name in args.check) if args.check else DEFAULT_CHECKS
    reviewer = CodeReviewer(
        adapter,
        root=ctx.workspace.root,
        conventions=project_conventions_block(
            ctx.workspace.root, ProjectContextStore(ctx.workspace.root).load()
        ),
    )
    report = reviewer.review(
        ReviewRequest(
            diff=diff,
            checks=checks,
            focus=" ".join(args.focus or []),
            summarize=not args.no_summary,
        )
    )
    ctx.audit.record(
        category="task",
        action="review.completed",
        outcome="success" if report.complete else "failure",
        model=report.model,
        details={
            "files": len(report.files_reviewed),
            "findings": len(report.findings),
            "counts": report.counts(),
            "complete": report.complete,
            "checks_failed": sorted(report.checks_failed),
            "model": report.model,
        },
    )

    print(report.to_json() if args.json else report.render(show_dropped=args.show_dropped))
    if not report.complete:
        return 6
    threshold = Severity(args.fail_on)
    blocking = [f for f in report.findings if severity_rank(f.severity) <= severity_rank(threshold)]
    return 2 if blocking else 0


def cmd_task(args: argparse.Namespace) -> int:
    """AG-001..AG-010: plan and carry out a task, streaming progress (UX-001..003)."""
    ctx, index = _context(args)
    store = SessionStore(ctx.workspace.root)
    session = (
        store.load(args.session) if args.session else Session(workspace=str(ctx.workspace.root))
    )
    try:
        adapter, _ = _adapter(args, ctx, TaskKind.PLANNING)
    except (ModelError, PermissionError) as exc:
        print(f"model unavailable: {exc}", file=sys.stderr)
        return 3
    session.model_name = adapter.info.name
    session.policy_version = ctx.policy.version

    task = " ".join(args.task)
    state: AgentState | None = None
    if args.resume:
        raw = session.task_state.get(STATE_KEY)
        if not raw:
            print(f"session {session.session_id} has no task to resume", file=sys.stderr)
            return 2
        state = AgentState.from_json(raw)
        task = task or state.task

    budget = RunBudget(
        max_steps=args.max_steps or ctx.policy.autonomy.max_steps,
        max_seconds=float(args.max_seconds or ctx.policy.autonomy.max_seconds),
        token=ctx.cancel,
    )

    def show(event: AgentEvent) -> None:
        print(event.render(), file=sys.stderr, flush=True)
        if event.type is EventType.PLAN_CREATED and not args.quiet:
            print(event.data.get("plan", ""), file=sys.stderr, flush=True)

    delegation = None
    if args.delegate:
        # AG-008. The subagents share this run's budget and cancellation token, so enabling
        # delegation buys the agent specialists, never more autonomy.
        roles = {SubagentRole(r) for r in (args.delegate_role or [])} or None
        delegation = Delegation(adapter, sink=CallbackSink(show), roles=roles)
    loop = AgentLoop(adapter, default_registry(), sink=CallbackSink(show), delegation=delegation)

    # Ground the planner in the repository and the project's own conventions.
    context = ""
    if index.stats()["files"]:
        results = index.search(task, 6, depth=args.depth)
        context = CodingAssistant.render_context(results)
    conventions = project_conventions_block(
        ctx.workspace.root, ProjectContextStore(ctx.workspace.root).load()
    )

    if args.plan_only:
        from aica.agent.plan import Planner

        try:
            plan = Planner(adapter, default_registry()).create(
                task, ctx, context=context, conventions=conventions
            )
        except PlanError as exc:
            print(f"could not produce a plan: {exc}", file=sys.stderr)
            return 3
        print(plan.render())
        return 0

    report = loop.run(
        task, ctx, budget=budget, context=context, conventions=conventions, state=state
    )

    # AG-005/NFR-002: persist the run so it can be resumed after this process exits.
    if loop.state is not None:
        session.task_state[STATE_KEY] = loop.state.to_json()
    session.add("user", task)
    session.add("assistant", report.render(), model=report.model)
    saved = store.save(session)

    print(report.render(include_diffs=args.show_diffs))
    print(
        f"\n[session {session.session_id} | saved {saved.name} | resume with "
        f"`aica task --session {session.session_id} --resume`]",
        file=sys.stderr,
    )
    return 0 if report.succeeded else 1


def cmd_browse(args: argparse.Namespace) -> int:
    """WEB-001..WEB-005: open an authorized application, collect evidence, optionally
    generate an E2E test for the flow. Nothing is written unless --write-test is given."""
    ctx, _ = _context(args)
    registry = default_registry()
    try:
        opened = registry.call(
            "browser.open",
            {"url": args.url, **({"engine": args.engine} if args.engine else {})},
            ctx,
        )
    except (ApprovalRequired, ToolNotAllowed, PermissionError) as exc:
        print(str(exc), file=sys.stderr)
        return 4
    except ToolError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    session = str(opened.data["session"])
    exit_code = 0
    try:
        print(opened.output)
        for selector in args.click or []:
            registry.call("browser.click", {"session": session, "selector": selector}, ctx)
            print(f"clicked {selector}")
        for pair in args.fill or []:
            if "=" not in pair:
                print(f"--fill expects SELECTOR=VALUE, got {pair!r}", file=sys.stderr)
                return 2
            selector, value = pair.split("=", 1)
            registry.call(
                "browser.fill", {"session": session, "selector": selector, "value": value}, ctx
            )
            print(f"filled {selector}")

        read = registry.call(
            "browser.read",
            {"session": session, **({"selector": args.read} if args.read else {})},
            ctx,
        )
        print("\n--- page text ---")
        print(read.output[:4000])

        evidence = registry.call(
            "browser.evidence", {"session": session, "screenshot": not args.no_screenshot}, ctx
        )
        print("\n--- evidence ---")
        print(evidence.output)
        if evidence.data.get("problem_count"):
            exit_code = 1  # the page reported errors: surface that in the exit status

        if args.gen_test:
            actions = registry.call("browser.close", {"session": session}, ctx).data["actions"]
            try:
                adapter, _ = _adapter(args, ctx, TaskKind.TESTING)
            except (ModelError, PermissionError):
                adapter = None  # the deterministic render still works without a model
            generated = generate_browser_test(
                adapter,
                list(actions),
                name=args.gen_test,
                base_url=_origin(args.url),
                root=ctx.workspace.root,
                page_text=read.output,
            )
            print("\n--- generated test ---")
            print(generated.content)
            origin = f"model {generated.model}" if generated.generated else "deterministic render"
            if args.write_test:
                written = registry.call(
                    "fs.write",
                    {"path": generated.test_path, "content": generated.content},
                    ctx,
                )
                print(f"\nwrote {generated.test_path}", file=sys.stderr)
                assert written.ok
            else:
                print(
                    f"\n[proposed {generated.test_path} | {origin}] not written; "
                    "pass --write-test to save it",
                    file=sys.stderr,
                )
    finally:
        try:
            registry.call("browser.close", {"session": session}, ctx)
        except ToolError:
            pass  # already closed by --gen-test
    return exit_code


def _origin(url: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def cmd_db(args: argparse.Namespace) -> int:
    """DB-001..DB-006: schema inspection, read-only queries, plans and migration proposals.

    Writes are deliberately not exposed here: they go through `db.execute`, which the agent
    calls under the approval gate, so a typo at a shell prompt cannot change a database.
    """
    ctx, _ = _context(args)
    ctx.databases_file = args.databases_file
    registry = default_registry()
    try:
        if args.subcommand == "connections":
            print(registry.call("db.connections", {}, ctx).output)
            return 0

        payload: dict[str, object] = {}
        if args.connection:
            payload["connection"] = args.connection

        if args.subcommand == "schema":
            if args.table:
                payload["table"] = args.table
            print(registry.call("db.schema", payload, ctx).output)
            return 0

        if args.subcommand in {"query", "explain"}:
            if not args.sql:
                print(f"{args.subcommand} needs --sql", file=sys.stderr)
                return 2
            payload["sql"] = args.sql
            if args.parameter:
                payload["parameters"] = list(args.parameter)
            if args.subcommand == "explain":
                payload["analyze"] = args.analyze
                print(registry.call("db.explain", payload, ctx).output)
                return 0
            if args.max_rows:
                payload["max_rows"] = args.max_rows
            result = registry.call("db.query", payload, ctx)
            print(result.output)
            return 0

        # migration
        if not args.describe:
            print("migration needs --describe", file=sys.stderr)
            return 2
        connection = load_databases(args.databases_file).get(args.connection)
        schema_text = ""
        try:
            schema_text = registry.call("db.schema", payload, ctx).output
        except (ToolError, DatabaseError):
            pass  # a migration can still be proposed without the current schema
        try:
            adapter, _ = _adapter(args, ctx, TaskKind.CODING)
        except (ModelError, PermissionError) as exc:
            print(f"model unavailable: {exc}", file=sys.stderr)
            return 3
        try:
            migration = generate_migration(
                adapter, " ".join(args.describe), connection.dialect, schema=schema_text
            )
        except MigrationError as exc:
            print(f"could not produce a usable migration: {exc}", file=sys.stderr)
            return 3
        print(migration.render())
        print("\n--- review ---", file=sys.stderr)
        print(migration.review(), file=sys.stderr)
        print(
            f"\n[proposed {migration.filename} | model {migration.model}] not applied; "
            "review it, then apply each statement with the db.execute tool under approval.",
            file=sys.stderr,
        )
        return 0
    except (ApprovalRequired, ToolNotAllowed, PermissionError) as exc:
        print(str(exc), file=sys.stderr)
        return 4
    except (ToolError, DatabaseError) as exc:
        print(str(exc), file=sys.stderr)
        return 3


def cmd_mcp(args: argparse.Namespace) -> int:
    """MCP-001/MCP-007: inspect the approved MCP servers and call one of their tools.

    Tool descriptions come from a third party and are shown as data. Calling a tool from a
    server that is not marked trusted goes through the approval gate, exactly as it does when
    the agent calls it.
    """
    ctx, _ = _context(args)
    try:
        config = load_mcp_config(args.mcp_file)
    except MCPConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.subcommand == "list":
        if not config.servers:
            print("(no MCP servers configured; see config/mcp.toml.example)")
            return 1
        for server in config.servers:
            trust = "trusted" if server.trusted else "approval per call"
            state = "" if server.enabled else "  (disabled)"
            print(f"{server.name:<24} [{trust}]{state}  {server.render_command()}")
            if server.description:
                print(f"    {server.description}")
        return 0

    session = MCPSession(config, workspace_root=str(ctx.workspace.root))
    try:
        if args.server:
            session.connect(args.server)
        else:
            session.connect_all()

        if args.subcommand == "tools":
            print(session.catalogue())
            return 1 if session.errors and not session.tools else 0

        # call
        if not args.tool:
            print("call needs --tool", file=sys.stderr)
            return 2
        arguments: dict[str, object] = {}
        if args.arguments:
            try:
                parsed = json.loads(args.arguments)
            except json.JSONDecodeError as exc:
                print(f"--arguments must be a JSON object: {exc}", file=sys.stderr)
                return 2
            if not isinstance(parsed, dict):
                print("--arguments must be a JSON object", file=sys.stderr)
                return 2
            arguments = parsed

        wanted = args.tool if args.tool.startswith("mcp.") else None
        candidates = [t for tools in session.tools.values() for t in tools]
        tool = next((t for t in candidates if t.name == wanted or t.remote.name == args.tool), None)
        if tool is None:
            known = ", ".join(t.name for t in candidates) or "none"
            print(f"unknown MCP tool {args.tool!r}; available: {known}", file=sys.stderr)
            return 2
        try:
            result = tool.invoke(arguments, ctx)
        except ApprovalRequired as exc:
            print(str(exc), file=sys.stderr)
            return 4
        except (ToolError, ToolArgumentError) as exc:
            print(str(exc), file=sys.stderr)
            return 3
        print(result.output)
        return 0 if result.ok else 1
    finally:
        session.close()


def cmd_serve(args: argparse.Namespace) -> int:
    """API-001..API-011: run the HTTP API over this workspace.

    Loopback by default, and always token-authenticated: the surface can write files and run
    commands, so it is never opened accidentally.
    """
    try:
        import uvicorn

        from aica.api.app import TOKEN_ENV, ApiSettings, create_app
    except ImportError:
        print(
            'the HTTP API needs the api extra:\n  pip install -e ".[api]"',
            file=sys.stderr,
        )
        return 3

    root = Path(args.workspace).resolve()
    settings = ApiSettings(
        workspace=root,
        policy_file=args.policy,
        models_file=args.models_file,
        databases_file=getattr(args, "databases_file", None),
        token=args.token or "",
        actor=args.actor,
    )
    app = create_app(settings)
    token = app.state.token

    if args.host != "127.0.0.1":
        print(
            f"WARNING: binding to {args.host} exposes file writes and command execution "
            "beyond this machine. Ensure the policy and the token are appropriate.",
            file=sys.stderr,
        )
    print(f"workspace: {root}")
    print(f"listening: http://{args.host}:{args.port}")
    if not settings.resolved_token():
        print(f"\nGenerated API token (set {TOKEN_ENV} to choose your own):\n  {token}\n")
    print("Authorize requests with:  Authorization: Bearer <token>")
    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)
    return 0


def cmd_test(args: argparse.Namespace) -> int:
    ctx, _ = _context(args)
    registry = default_registry()
    if args.discover_only:
        result = registry.call("test.discover", {}, ctx)
        print(result.output)
        return 0
    payload: dict[str, object] = {"kind": args.kind}
    if args.command:
        payload["command"] = args.command
    try:
        result = registry.call("test.run", payload, ctx)
    except (ApprovalRequired, ToolNotAllowed, PermissionError) as exc:
        print(str(exc), file=sys.stderr)
        return 4
    print(result.output)
    return 0 if result.ok else 1


def cmd_run(args: argparse.Namespace) -> int:
    ctx, _ = _context(args)
    if not args.command:
        print("no command given", file=sys.stderr)
        return 2
    registry = default_registry()
    try:
        result = registry.call(
            "shell.run", {"command": " ".join(args.command), "timeout_seconds": args.timeout}, ctx
        )
    except (ApprovalRequired, ToolNotAllowed, PermissionError) as exc:
        print(str(exc), file=sys.stderr)
        return 4
    print(result.output)
    exit_code = result.data.get("exit_code")
    return int(exit_code) if isinstance(exit_code, int) else 1


def cmd_git(args: argparse.Namespace) -> int:
    ctx, _ = _context(args)
    registry = default_registry()
    tool = {
        "status": "git.status",
        "diff": "git.diff",
        "branches": "git.branches",
        "log": "git.log",
    }[args.subcommand]
    result = registry.call(tool, {}, ctx)
    print(result.output or "(no output)")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    """EVAL-001..009: run the golden suite, gate a candidate, or compare models."""
    from aica.evaluation import (
        Comparison,
        Evaluator,
        GateError,
        Provenance,
        ReleaseGate,
        SuiteError,
        SuiteReport,
        evaluate_gate,
        load_suite,
        router_factory,
        scripted_factory,
    )
    from aica.evaluation.runner import ModelFactory

    if args.eval_command == "gate":
        try:
            candidate = SuiteReport.load(args.candidate)
            baseline = SuiteReport.load(args.baseline) if args.baseline else None
            decision = evaluate_gate(
                candidate,
                ReleaseGate(
                    min_completion_rate=args.min_completion,
                    min_correctness=args.min_correctness,
                    min_tool_reliability=args.min_tool_reliability,
                ),
                baseline,
            )
        except (OSError, ValueError, GateError) as exc:
            print(f"gate could not be evaluated: {exc}", file=sys.stderr)
            return 2
        print(decision.render())
        return 0 if decision.passed else 1

    if args.eval_command == "compare":
        comparison = Comparison()
        try:
            for path in args.report:
                comparison.add(SuiteReport.load(path))
        except (OSError, ValueError, GateError) as exc:
            print(f"cannot compare: {exc}", file=sys.stderr)
            return 2
        print(comparison.render())
        return 0

    # run
    ctx, index = _context(args)
    index.close()  # each task gets its own workspace and its own index
    try:
        suite = load_suite(args.suite).filtered(args.task or None, args.tag or None)
    except SuiteError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    if args.list:
        print(suite.describe())
        return 0

    provenance = Provenance(model="scripted", model_version="scripted")
    factory: ModelFactory = scripted_factory
    if not args.scripted:
        try:
            gateway = ModelGateway.from_file(ctx.policy.network, getattr(args, "models_file", None))
            router = ModelRouter(gateway, gateway.routing, audit=ctx.audit)
            selection = router.select(TaskKind.PLANNING, requested=args.model)
        except (ModelError, PermissionError) as exc:
            print(f"model unavailable: {exc}", file=sys.stderr)
            print("use --scripted to exercise the harness itself without a model", file=sys.stderr)
            return 3
        factory = router_factory(router)
        provenance = Provenance(
            model=selection.name,
            model_version=selection.version,
            adapter=gateway.config_for(selection.name).adapter,
        )

    report = Evaluator(policy=ctx.policy).run(suite, factory, provenance)
    print(report.render())
    if args.out:
        saved = report.save(args.out)
        print(f"\n[report written to {saved}]", file=sys.stderr)
    if provenance.model == "scripted":
        print(
            "\n[scripted run: this measures the harness and the tools, not a model]",
            file=sys.stderr,
        )
    # A false success is the one outcome that must not be reported as a clean run.
    return 1 if report.false_successes else 0


def cmd_models(args: argparse.Namespace) -> int:
    ctx, _ = _context(args)
    gateway = ModelGateway.from_file(ctx.policy.network, getattr(args, "models_file", None))
    default = gateway.default_name()
    models = gateway.list_models()
    if not models:
        print("no models configured (config/models.toml)")
        return 1
    for info in models:
        mark = "*" if info.name == default else " "
        print(f"{mark} {info.describe()}")
    unusable = [i for i in gateway.list_models(include_unusable=True) if i not in models]
    if unusable:
        print("\nnot available (MM-001 status or disabled):")
        for info in unusable:
            print(f"  {info.describe()}")
    routing = gateway.routing
    if routing.rules or routing.fallbacks:
        print("\nrouting (MM-004/MM-009):")
        for rule in routing.rules:
            detail = rule.model or "(requirements only)"
            if rule.min_context:
                detail += f", min context {rule.min_context}"
            print(f"  {rule.task.value:<14} -> {detail}")
        if routing.fallbacks:
            print(f"  fallbacks       -> {', '.join(routing.fallbacks)}")
    print(
        "\n* = project default. Credentials come from environment variables; endpoints must pass network policy."
    )
    return 0


def cmd_sessions(args: argparse.Namespace) -> int:
    ctx, _ = _context(args)
    store = SessionStore(ctx.workspace.root)
    if args.show:
        session = store.load(args.show)
        print(f"# {session.title or '(untitled)'}  [{session.session_id}]")
        for k, v in session.reproducibility().items():
            print(f"{k}: {v}")
        if session.summary:
            print(f"\nsummary:\n{session.summary}")
        for turn in session.turns:
            marker = turn.model or turn.role
            print(f"\n--- {turn.role} ({marker}) {turn.timestamp:%Y-%m-%d %H:%M}\n{turn.content}")
        return 0
    rows = store.list_sessions()
    if not rows:
        print("(no sessions)")
        return 1
    for r in rows:
        print(
            f"{r['session_id']}  {r['updated']}  turns={r['turns']:<4} model={r['model']:<16} {r['title']}"
        )
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    ctx, _ = _context(args)
    p = ctx.policy
    print(f"version: {p.version}")
    print(f"environment: {p.autonomy.environment.value}")
    print(
        f"max_steps: {p.autonomy.max_steps}  max_seconds: {p.autonomy.max_seconds}  max_test_retries: {p.autonomy.max_test_retries}"
    )
    print(f"allowed_tools: {', '.join(p.autonomy.allowed_tools)}")
    print(f"tool deny: {', '.join(p.tools.deny) or '(none)'}")
    print(f"tool allow (narrowing): {', '.join(p.tools.allow) or '(all in allowed groups)'}")
    print(f"denied in production: {', '.join(p.tools.deny_in_production) or '(none)'}")
    if p.secrets.definitions:
        from aica.safety.secrets import SecretStore

        for entry in SecretStore(p.secrets).describe():
            state = "available" if entry["available"] else "NOT SET"
            tools = ", ".join(entry["allowed_tools"]) or "(no tool)"  # type: ignore[arg-type]
            print(f"secret {entry['name']}: {entry['env_var']} [{state}] -> {tools}")
    else:
        print("secrets: (none declared)")
    print(f"allowed_directories: {', '.join(p.autonomy.allowed_directories)}")
    print(
        f"network: {p.network.mode.value}  hosts: {', '.join(p.network.allowed_hosts) or '(none)'}"
    )
    print(f"approval required: {', '.join(c.value for c in p.approval.require_for) or '(none)'}")
    print(f"blocked: {', '.join(c.value for c in p.approval.block) or '(none)'}")
    print(
        f"protected branches: {', '.join(p.git.protected_branches)}  force_push: {p.git.allow_force_push}"
    )
    print(f"\ntools available: {', '.join(t.name for t in default_registry().allowed(ctx))}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    ctx, _ = _context(args)
    sink = JsonlAuditSink(ctx.workspace.root / ".aica" / "audit")
    events = list(sink.read_all())[-args.limit :]
    if not events:
        print("(no audit events)")
        return 1
    for e in events:
        print(
            f"{e.timestamp:%Y-%m-%d %H:%M:%S}  {e.category.value:<16} {e.outcome.value:<17} {e.action[:70]}"
        )
    return 0


# ------------------------------------------------------------------ parser


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aica", description="Enterprise AI Coding Assistant Agent")
    p.add_argument("--version", action="version", version=f"aica {__version__}")
    p.add_argument(
        "-w", "--workspace", default=".", help="workspace root (default: current directory)"
    )
    p.add_argument("--policy", default=None, help="policy file (default: config/policy.toml)")
    p.add_argument("--models-file", default=None, help="models file (default: config/models.toml)")
    p.add_argument("--actor", default="local-user", help="actor recorded in the audit log")
    p.add_argument(
        "--verbose-model",
        action="store_true",
        help="print which model was routed to, and why (MM-009/MM-012)",
    )
    p.add_argument(
        "-y", "--yes", action="store_true", help="auto-approve sensitive actions (use deliberately)"
    )
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("index", help="index the repository")
    sp.add_argument("subdir", nargs="?", default=None)
    sp.add_argument("--force", action="store_true")
    sp.set_defaults(func=cmd_index)

    sp = sub.add_parser("search", help="search the repository")
    sp.add_argument("query")
    sp.add_argument("--mode", default="hybrid", choices=["hybrid", "lexical", "semantic", "symbol"])
    sp.add_argument("--limit", type=int, default=8)
    sp.add_argument("--depth", default="normal", choices=["shallow", "normal", "deep"])
    sp.set_defaults(func=cmd_search)

    sp = sub.add_parser("deps", help="dependencies and references")
    sp.add_argument("--path")
    sp.add_argument("--symbol")
    sp.set_defaults(func=cmd_deps)

    sp = sub.add_parser("ask", help="ask a repository-aware question")
    sp.add_argument("question", nargs="+")
    sp.add_argument("--model")
    sp.add_argument("--session")
    sp.add_argument("--depth", default="normal", choices=["shallow", "normal", "deep"])
    sp.add_argument("--no-stream", action="store_true")
    sp.set_defaults(func=cmd_ask)

    sp = sub.add_parser("complete", help="code completion at a cursor position")
    sp.add_argument("--file", required=True)
    sp.add_argument("--line", type=int, required=True, help="complete after this line number")
    sp.add_argument("--model")
    sp.add_argument("--max-tokens", type=int, default=256)
    sp.set_defaults(func=cmd_complete)

    sp = sub.add_parser("debug", help="diagnose a failure from a log or traceback")
    sp.add_argument("--log", required=True, help="log file path, or - for stdin")
    sp.add_argument("question", nargs="*", default=[])
    sp.add_argument("--model")
    sp.add_argument("--session")
    sp.add_argument("--depth", default="normal", choices=["shallow", "normal", "deep"])
    sp.set_defaults(func=cmd_debug)

    sp = sub.add_parser("conventions", help="show detected conventions and project context")
    sp.add_argument("--record", action="append", help="record a project convention (repeatable)")
    sp.add_argument("--set", action="append", help="record a preference as KEY=VALUE (repeatable)")
    sp.set_defaults(func=cmd_conventions)

    sp = sub.add_parser("commit-message", help="propose a validated commit message")
    sp.add_argument("--staged", action="store_true", help="describe staged changes only")
    sp.add_argument("--strict", action="store_true", help="fail instead of using the fallback")
    sp.add_argument("--context", action="append", help="task context for the message")
    sp.add_argument("--model")
    sp.set_defaults(func=cmd_commit_message)

    sp = sub.add_parser("gen-tests", help="propose tests for a file (nothing is written)")
    sp.add_argument("--file", required=True)
    sp.add_argument("--focus", action="append", help="behaviour to focus on")
    sp.add_argument("--model")
    sp.set_defaults(func=cmd_gen_tests)

    sp = sub.add_parser("review", help="review a change (REV-001..007); nothing is written")
    sp.add_argument("--base", help="review the change against this ref instead of the index")
    sp.add_argument("--staged", action="store_true", help="review staged changes only")
    sp.add_argument("--path", help="restrict the diff to this path")
    sp.add_argument(
        "--no-untracked",
        action="store_true",
        help="do not review new, untracked files (they are included by default)",
    )
    sp.add_argument(
        "--check",
        action="append",
        choices=[c.value for c in ReviewCheck],
        help="run only these checks (repeatable; default: all)",
    )
    sp.add_argument("--focus", action="append", help="what the reviewer wants attention on")
    sp.add_argument("--json", action="store_true", help="machine-readable report")
    sp.add_argument("--show-dropped", action="store_true", help="list findings that were discarded")
    sp.add_argument("--no-summary", action="store_true", help="skip the prose summary call")
    sp.add_argument(
        "--fail-on",
        default=Severity.HIGH.value,
        choices=[s.value for s in Severity],
        help="exit 2 when a finding at or above this severity is reported (default: high)",
    )
    sp.add_argument("--strict", action="store_true", help="fail rather than review without a model")
    sp.add_argument("--model")
    sp.set_defaults(func=cmd_review)

    sp = sub.add_parser("task", help="run an agent task (plan, execute, verify, report)")
    sp.add_argument("task", nargs="*", default=[], help="what to do, in plain language")
    sp.add_argument("--model")
    sp.add_argument("--session", help="session to record into, or to resume from")
    sp.add_argument("--resume", action="store_true", help="continue the session's saved task")
    sp.add_argument("--plan-only", action="store_true", help="show the plan and stop")
    sp.add_argument("--max-steps", type=int, help="override the policy step limit")
    sp.add_argument("--max-seconds", type=int, help="override the policy time limit")
    sp.add_argument("--show-diffs", action="store_true", help="include diffs in the report")
    sp.add_argument("--quiet", action="store_true", help="do not echo the plan")
    sp.add_argument("--depth", default="normal", choices=["shallow", "normal", "deep"])
    sp.add_argument(
        "--delegate",
        action="store_true",
        help="allow the agent to delegate sub-tasks to specialist subagents (AG-008)",
    )
    sp.add_argument(
        "--delegate-role",
        action="append",
        choices=[r.value for r in SubagentRole],
        help="restrict delegation to these roles (repeatable; default: all)",
    )
    sp.set_defaults(func=cmd_task)

    sp = sub.add_parser("browse", help="inspect a running application in a real browser")
    sp.add_argument("--url", required=True)
    sp.add_argument("--engine", choices=["chromium", "firefox", "webkit"])
    sp.add_argument("--click", action="append", help="CSS selector to click (repeatable)")
    sp.add_argument("--fill", action="append", help="SELECTOR=VALUE to type (repeatable)")
    sp.add_argument("--read", help="selector whose text to print (default: whole page)")
    sp.add_argument("--no-screenshot", action="store_true")
    sp.add_argument("--gen-test", metavar="NAME", help="generate an E2E test for this flow")
    sp.add_argument("--write-test", action="store_true", help="save the generated test")
    sp.add_argument("--model")
    sp.set_defaults(func=cmd_browse)

    sp = sub.add_parser("db", help="controlled database access")
    sp.add_argument(
        "subcommand", choices=["connections", "schema", "query", "explain", "migration"]
    )
    sp.add_argument("--connection", help="configured connection name (default: the config default)")
    sp.add_argument("--databases-file", help="databases file (default: config/databases.toml)")
    sp.add_argument("--table", help="schema: describe this table")
    sp.add_argument("--sql", help="query/explain: the statement to run")
    sp.add_argument("--parameter", action="append", help="bound parameter (repeatable)")
    sp.add_argument("--max-rows", type=int)
    sp.add_argument(
        "--analyze", action="store_true", help="explain: run EXPLAIN ANALYZE (reads only)"
    )
    sp.add_argument("--describe", nargs="*", help="migration: the change to make")
    sp.add_argument("--model")
    sp.set_defaults(func=cmd_db)

    sp = sub.add_parser("mcp", help="MCP servers and their tools")
    sp.add_argument("subcommand", choices=["list", "tools", "call"])
    sp.add_argument("--server", help="limit to one configured server")
    sp.add_argument("--tool", help="call: the tool name (bare, or mcp.<server>.<tool>)")
    sp.add_argument("--arguments", help="call: a JSON object of arguments")
    sp.add_argument("--mcp-file", help="MCP config file (default: config/mcp.toml)")
    sp.set_defaults(func=cmd_mcp)

    sp = sub.add_parser("serve", help="run the HTTP API over this workspace")
    sp.add_argument("--host", default="127.0.0.1", help="bind address (default: loopback only)")
    sp.add_argument("--port", type=int, default=8000)
    sp.add_argument("--token", help="bearer token (default: $AICA_API_TOKEN, else generated)")
    sp.add_argument("--databases-file", help="databases file for db.* tools")
    sp.add_argument(
        "--log-level", default="info", choices=["critical", "error", "warning", "info", "debug"]
    )
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("test", help="discover and run tests")
    sp.add_argument(
        "--kind",
        default="unit",
        choices=["unit", "integration", "e2e", "lint", "typecheck", "build"],
    )
    sp.add_argument("--command")
    sp.add_argument("--discover-only", action="store_true")
    sp.set_defaults(func=cmd_test)

    sp = sub.add_parser("run", help="run a policy-checked command")
    sp.add_argument("--timeout", type=float, default=300.0)
    # REMAINDER so flags belonging to the target command (e.g. `run rm -rf x`) are not
    # parsed as aica's own options.
    sp.add_argument("command", nargs=argparse.REMAINDER)
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("git", help="Git inspection")
    sp.add_argument("subcommand", choices=["status", "diff", "branches", "log"])
    sp.set_defaults(func=cmd_git)

    sp = sub.add_parser("eval", help="golden-task evaluation (EVAL-001..009)")
    eval_sub = sp.add_subparsers(dest="eval_command", required=True)

    ep = eval_sub.add_parser("run", help="run the golden suite and report metrics")
    ep.add_argument("--suite", default=None, help="task directory (default: evaluation/tasks)")
    ep.add_argument("--task", action="append", help="run only this task id (repeatable)")
    ep.add_argument("--tag", action="append", help="run only tasks with this tag (repeatable)")
    ep.add_argument("--model", default=None, help="model to evaluate (default: routing policy)")
    ep.add_argument(
        "--scripted",
        action="store_true",
        help="use each task's canned replies: exercises the harness, not a model",
    )
    ep.add_argument("--out", default=None, help="write the JSON report here")
    ep.add_argument("--list", action="store_true", help="list the tasks and stop")
    ep.set_defaults(func=cmd_eval)

    gp = eval_sub.add_parser("gate", help="decide whether a candidate may be promoted (EVAL-008)")
    gp.add_argument("--candidate", required=True, help="candidate report (JSON)")
    gp.add_argument("--baseline", default=None, help="approved report to compare against")
    gp.add_argument("--min-completion", type=float, default=0.8)
    gp.add_argument("--min-correctness", type=float, default=0.8)
    gp.add_argument("--min-tool-reliability", type=float, default=0.9)
    gp.set_defaults(func=cmd_eval)

    cp = eval_sub.add_parser("compare", help="compare models on the same suite (EVAL-006)")
    cp.add_argument("--report", action="append", required=True, help="report JSON (repeatable)")
    cp.set_defaults(func=cmd_eval)

    sp = sub.add_parser("models", help="list approved models")
    sp.set_defaults(func=cmd_models)

    sp = sub.add_parser("sessions", help="list or show sessions")
    sp.add_argument("--show", help="session id to display")
    sp.set_defaults(func=cmd_sessions)

    sp = sub.add_parser("policy", help="show the effective policy")
    sp.set_defaults(func=cmd_policy)

    sp = sub.add_parser("audit", help="show recent audit events")
    sp.add_argument("--limit", type=int, default=25)
    sp.set_defaults(func=cmd_audit)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _OPEN_INDEXES.clear()
    try:
        result = args.func(args)
        return int(result)
    except ApprovalRequired as exc:
        print(
            f"\n{exc}\nDenied — rerun with --yes to approve, or adjust config/policy.toml.",
            file=sys.stderr,
        )
        return 4
    except PermissionError as exc:
        print(f"policy denied: {exc}", file=sys.stderr)
        return 5
    except KeyboardInterrupt:
        print("\ncancelled", file=sys.stderr)
        return 130
    finally:
        for idx in _OPEN_INDEXES:
            idx.close()
        _OPEN_INDEXES.clear()


if __name__ == "__main__":
    raise SystemExit(main())
