"""HTTP API (API-001..API-011, BRD section 15).

The API is a second surface over the same machinery the CLI uses - not a second
implementation of it. Every endpoint builds a ``ToolContext`` and calls the same tools, so
the workspace guard, the approval gates, the uncommitted-change protection and the audit log
apply identically whether a request arrives over HTTP or a developer types a command.

Because this surface can write files and run commands, it is locked down by default:

* **A bearer token is required** on every endpoint except ``/health``. The token comes from
  ``AICA_API_TOKEN``; when that is unset one is generated at startup and printed, so the
  server is never accidentally open.
* **Loopback by default.** ``aica serve`` binds 127.0.0.1 unless a host is given explicitly.
* **Approvals are explicit.** A request may not silently auto-approve: a client that wants
  unattended execution has to say so per task, and that choice is audited like any other.

Requests and responses are pydantic models, so the API contract and the tool contracts come
from the same schemas (MCP-003's validation, reused at the edge).
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from aica.admin.controls import ControlError, ControlPlane, TargetKind
from aica.admin.rbac import Permission
from aica.admin.reporting import (
    AuditQuery,
    RetentionScope,
    apply_retention,
    iter_events,
    plan_workspace_retention,
    summarize,
)
from aica.admin.reporting import search as audit_search
from aica.agent.loop import STATE_KEY, AgentLoop, AgentState
from aica.api.tasks import TaskManager, event_payload
from aica.approvals import AllowAllApprover, ApprovalRequired, Approver, DenyAllApprover
from aica.audit import AuditLog, EventCategory, JsonlAuditSink, Outcome
from aica.chat.assistant import CodingAssistant
from aica.chat.session import Session, SessionStore
from aica.models.base import ModelError, ModelInfo
from aica.models.gateway import ModelGateway
from aica.models.routing import ModelRouter, Selection, TaskKind
from aica.policy import Policy, load_policy
from aica.policy.budget import RunBudget
from aica.rag.index import RepositoryIndex
from aica.review.reviewer import DEFAULT_CHECKS, CodeReviewer, ReviewCheck, ReviewRequest
from aica.tools import ToolContext, default_registry
from aica.tools.base import ToolArgumentError, ToolError, ToolNotAllowed
from aica.workspace import GitGuard, WorkspaceGuard
from aica.workspace.project_context import ProjectContextStore, project_conventions_block

TOKEN_ENV = "AICA_API_TOKEN"  # noqa: S105 - the name of an environment variable, not a secret
API_TITLE = "AICA"


class ApiSettings(BaseModel):
    """Server-side configuration. Never taken from a request."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    workspace: Path
    policy_file: str | None = None
    models_file: str | None = None
    databases_file: str | None = None
    token: str = ""
    actor: str = "api-user"

    def resolved_token(self) -> str:
        return self.token or os.environ.get(TOKEN_ENV, "")


# ------------------------------------------------------------------ request models


class CreateSessionRequest(BaseModel):
    """API-001: create an agent session with repository, branch, model and policy context."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(default="", max_length=200)
    model: str | None = Field(default=None, description="approved model name (MM-002)")
    branch: str | None = Field(default=None, max_length=200)


class RunTaskRequest(BaseModel):
    """API-002: start or resume agent execution."""

    model_config = ConfigDict(extra="forbid")

    task: str = Field(min_length=1, max_length=4000)
    # MM-002: a model named here is used as asked. MM-004: without one, the kind of work
    # decides, through the routing rules in config/models.toml.
    model: str | None = None
    task_kind: TaskKind = TaskKind.PLANNING
    max_steps: int | None = Field(default=None, ge=1, le=1000)
    max_seconds: int | None = Field(default=None, ge=1, le=86_400)
    depth: str = Field(default="normal", pattern="^(shallow|normal|deep)$")
    resume: bool = False
    # SAFE-001: unattended approval is opt-in per task and recorded in the audit trail.
    auto_approve: bool = False


class SearchRequest(BaseModel):
    """API-006: repository context search."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(min_length=1, max_length=1000)
    limit: int = Field(default=8, ge=1, le=100)
    depth: str = Field(default="normal", pattern="^(shallow|normal|deep)$")
    mode: str = Field(default="hybrid", pattern="^(hybrid|lexical|semantic|symbol)$")


class ToolCallRequest(BaseModel):
    """The shape behind API-007..API-010: a named tool with validated arguments."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)
    auto_approve: bool = False


class ReviewRequestBody(BaseModel):
    """API-016 (BRD section 11): review a change. Read-only - nothing is written."""

    model_config = ConfigDict(extra="forbid")

    diff: str = Field(default="", max_length=400_000)
    base: str | None = Field(default=None, max_length=200)
    staged: bool = False
    path: str | None = Field(default=None, max_length=1000)
    checks: list[str] | None = None
    include_untracked: bool = True  # new files are invisible to `git diff` until staged
    focus: str = Field(default="", max_length=2000)
    summarize: bool = True
    model: str | None = None


class ControlRequest(BaseModel):
    """SEC-007: switch a tool, model or integration off (or back on) immediately."""

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(pattern="^(tool|model|integration)$")
    name: str = Field(min_length=1, max_length=200)
    disabled: bool = True
    reason: str = Field(default="", max_length=1000)


class RetentionRequest(BaseModel):
    """ADM-009 / SEC-005: how long to keep audit files, and whether to actually delete."""

    model_config = ConfigDict(extra="forbid")

    keep_days: int = Field(default=90, ge=1, le=3650)
    scope: str = Field(default="all", pattern="^(audit|sessions|context|all)$")
    apply: bool = False  # a destructive default would be the wrong one


class ApprovalDecision(BaseModel):
    """API: approve or reject a pending sensitive action (BRD section 15 'Approval')."""

    model_config = ConfigDict(extra="forbid")

    approved: bool
    note: str = Field(default="", max_length=1000)


# ------------------------------------------------------------------ application


def create_app(settings: ApiSettings) -> FastAPI:
    """Build the application. One workspace per server process."""
    manager = TaskManager()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # Nothing to warm up; on the way out, stop any task still running so the process
        # does not leave worker threads behind holding a workspace.
        yield
        manager.shutdown()

    app = FastAPI(title=API_TITLE, version="0.0.1", description=__doc__, lifespan=lifespan)
    token = settings.resolved_token() or secrets.token_urlsafe(32)
    app.state.settings = settings
    app.state.manager = manager
    app.state.token = token

    def require_token(
        authorization: Annotated[str | None, Header()] = None,
    ) -> None:
        """Every endpoint but /health needs the bearer token."""
        expected = f"Bearer {app.state.token}"
        if not authorization or not secrets.compare_digest(authorization, expected):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="a valid bearer token is required",
                headers={"WWW-Authenticate": "Bearer"},
            )

    guard = [Depends(require_token)]

    # ------------------------------------------------------------------ helpers
    def build_context(
        session_id: str | None = None, *, auto_approve: bool = False
    ) -> tuple[ToolContext, RepositoryIndex]:
        root = settings.workspace.resolve()
        policy: Policy = load_policy(settings.policy_file)
        workspace = WorkspaceGuard(root, policy.autonomy.allowed_directories)
        git = GitGuard(workspace.root, policy.git)
        approver: Approver = AllowAllApprover() if auto_approve else DenyAllApprover()
        # A task started here runs on a worker thread and takes the index with it, so the
        # connection has to outlive the request thread that opened it.
        index = RepositoryIndex(workspace, allow_thread_handoff=True)
        ctx = ToolContext(
            workspace=workspace,
            policy=policy,
            audit=AuditLog(
                JsonlAuditSink(root / ".aica" / "audit"),
                actor=settings.actor,
                session_id=session_id,
            ),
            git=git if git.is_repository() else None,
            approver=approver,
            session_id=session_id,
            index=index,
            databases_file=settings.databases_file,
            controls=ControlPlane(
                root, actor=settings.actor, rbac=policy.rbac, project=policy.project
            ),
            principal=policy.principal(settings.actor),  # ADM-001, ADM-002
            audit_directory=root / ".aica" / "audit",  # ADM-005
        )
        return ctx, index

    def store() -> SessionStore:
        return SessionStore(settings.workspace.resolve())

    def gateway_for() -> ModelGateway:
        policy = load_policy(settings.policy_file)
        return ModelGateway.from_file(
            policy.network,
            settings.models_file,
            controls=ControlPlane(settings.workspace.resolve(), actor=settings.actor),
        )

    def select_model(
        model: str | None,
        task_kind: TaskKind = TaskKind.PLANNING,
        audit: AuditLog | None = None,
        session_id: str | None = None,
    ) -> Selection:
        """API-013: pin a model by name, or let the routing policy choose (MM-002/004/009)."""
        gateway = gateway_for()
        router = ModelRouter(gateway, gateway.routing, audit=audit, session_id=session_id)
        return router.select(task_kind, requested=model)

    def load_session(session_id: str) -> Session:
        try:
            return store().load(session_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown session {session_id}") from exc

    def call_tool(request: ToolCallRequest, session_id: str | None = None) -> dict[str, Any]:
        ctx, index = build_context(session_id, auto_approve=request.auto_approve)
        try:
            result = default_registry().call(request.tool, request.arguments, ctx)
        except ApprovalRequired as exc:
            # 409: the request was understood and refused pending a human decision.
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (ToolNotAllowed, PermissionError) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ToolArgumentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"unknown tool {request.tool!r}") from exc
        except ToolError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        finally:
            index.close()
        return {"ok": result.ok, "output": result.output, "data": result.data}

    # ------------------------------------------------------------------ health
    @app.get("/health")
    def health() -> dict[str, str]:
        """The only unauthenticated endpoint: liveness, and nothing about the workspace."""
        return {"status": "ok", "service": API_TITLE}

    # ------------------------------------------------------------------ API-001
    @app.post("/sessions", status_code=201, dependencies=guard)
    def create_session(request: CreateSessionRequest) -> dict[str, Any]:
        policy = load_policy(settings.policy_file)
        session = Session(
            workspace=str(settings.workspace.resolve()),
            title=request.title,
            model_name=request.model,
            policy_version=policy.version,
        )
        if request.branch:
            session.task_state["branch"] = request.branch
        store().save(session)
        return {
            "session_id": session.session_id,
            "workspace": session.workspace,
            "model": session.model_name,
            "branch": request.branch,
            "policy_version": session.policy_version,
        }

    # ------------------------------------------------------------------ API-011
    @app.get("/sessions", dependencies=guard)
    def list_sessions() -> dict[str, Any]:
        return {"sessions": store().list_sessions()}

    @app.get("/sessions/{session_id}", dependencies=guard)
    def get_session(session_id: str) -> dict[str, Any]:
        session = load_session(session_id)
        return {
            "session_id": session.session_id,
            "title": session.title,
            "model": session.model_name,
            "summary": session.summary,
            "reproducibility": session.reproducibility(),
            "turns": [
                {
                    "role": t.role,
                    "content": t.content,
                    "model": t.model,
                    "timestamp": t.timestamp.isoformat(),
                }
                for t in session.turns
            ],
            "tasks": [r.summary() for r in manager.list(session_id)],
        }

    # ------------------------------------------------------------------ API-002
    @app.post("/sessions/{session_id}/tasks", status_code=202, dependencies=guard)
    def run_task(session_id: str, request: RunTaskRequest) -> dict[str, Any]:
        session = load_session(session_id)
        ctx, index = build_context(session_id, auto_approve=request.auto_approve)
        try:
            selection = select_model(
                request.model or session.model_name,
                request.task_kind,
                audit=ctx.audit,
                session_id=session_id,
            )
        except (ModelError, PermissionError) as exc:
            index.close()
            raise HTTPException(status_code=503, detail=f"model unavailable: {exc}") from exc
        adapter = selection.adapter

        state: AgentState | None = None
        if request.resume:
            raw = session.task_state.get(STATE_KEY)
            if not raw:
                index.close()
                raise HTTPException(
                    status_code=409, detail=f"session {session_id} has no task state to resume"
                )
            state = AgentState.from_json(raw)

        policy = ctx.policy
        budget = RunBudget(
            max_steps=request.max_steps or policy.autonomy.max_steps,
            max_seconds=float(request.max_seconds or policy.autonomy.max_seconds),
        )
        try:
            context = ""
            if index.stats()["files"]:
                context = CodingAssistant.render_context(
                    index.search(request.task, 6, depth=request.depth)
                )
            conventions = project_conventions_block(
                ctx.workspace.root, ProjectContextStore(ctx.workspace.root).load()
            )
        except Exception:
            index.close()
            raise
        loop = AgentLoop(adapter, default_registry())
        record = manager.start(
            loop,
            request.task,
            ctx,
            session_id=session_id,
            budget=budget,
            context=context,
            conventions=conventions,
            state=state,
            # The task borrows this index for its whole run; the request cannot close it.
            on_finish=index.close,
        )
        # MM-012: the caller is told exactly which model this run went to, and what it would
        # fall back to, rather than having to infer it from the finished report.
        session.model_name = selection.name
        store().save(session)
        return {
            "task_id": record.id,
            "session_id": session_id,
            "state": record.state.value,
            "model": {
                "name": selection.name,
                "version": selection.version,
                "task_kind": selection.task.value,
                "reason": selection.reason,
                "fallbacks": selection.fallbacks,
            },
        }

    @app.get("/tasks", dependencies=guard)
    def list_tasks(session_id: str | None = None) -> dict[str, Any]:
        return {"tasks": [r.summary() for r in manager.list(session_id)]}

    @app.get("/tasks/{task_id}", dependencies=guard)
    def get_task(task_id: str) -> dict[str, Any]:
        record = manager.get(task_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"unknown task {task_id}")
        return record.detail()

    # ------------------------------------------------------------------ API-003
    @app.get("/tasks/{task_id}/events", dependencies=guard)
    def stream_events(task_id: str, request: Request, timeout: float = 300.0) -> StreamingResponse:
        """Server-sent events: model output, plan, tool calls, tests and status."""
        record = manager.get(task_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"unknown task {task_id}")

        def publish() -> Iterator[str]:
            for event in manager.stream(task_id, timeout=timeout):
                yield f"event: {event.type.value}\ndata: {json.dumps(event_payload(event))}\n\n"
            final = manager.get(task_id)
            if final is not None:
                yield f"event: state\ndata: {json.dumps(final.summary())}\n\n"

        return StreamingResponse(
            publish(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ------------------------------------------------------------------ API-004/005
    @app.post("/tasks/{task_id}/cancel", dependencies=guard)
    def cancel_task(task_id: str) -> dict[str, Any]:
        if manager.get(task_id) is None:
            raise HTTPException(status_code=404, detail=f"unknown task {task_id}")
        return {"task_id": task_id, "cancelled": manager.cancel(task_id)}

    @app.post("/tasks/{task_id}/pause", dependencies=guard)
    def pause_task(task_id: str) -> dict[str, Any]:
        record = manager.get(task_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"unknown task {task_id}")
        paused = manager.pause(task_id)
        if paused:
            record.wait(timeout=30.0)
            if record.agent_state is not None:
                session = load_session(record.session_id)
                session.task_state[STATE_KEY] = record.agent_state.to_json()
                store().save(session)
        return {"task_id": task_id, "paused": paused, "state": record.state.value}

    @app.post("/tasks/{task_id}/resume", status_code=202, dependencies=guard)
    def resume_task(task_id: str) -> dict[str, Any]:
        record = manager.get(task_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"unknown task {task_id}")
        if not record.resumable:
            raise HTTPException(
                status_code=409,
                detail=f"task {task_id} is {record.state.value} and cannot be resumed",
            )
        return run_task(
            record.session_id, RunTaskRequest(task=record.task, resume=True, auto_approve=False)
        )

    # ------------------------------------------------------------------ models
    @app.get("/models", dependencies=guard)
    def list_models(include_unusable: bool = False) -> dict[str, Any]:
        """API-012/UX-007: the approved models, their capabilities and the routing rules.

        A surface needs this *before* it starts a task: which models may be chosen, what each
        one can do and how large its context is (MM-001, MM-013), plus which model a kind of
        work would go to if nothing is chosen (MM-004/MM-009). ``include_unusable`` also lists
        entries that exist but may not be used, with the status that explains why, so a user
        sees "pending approval" instead of a model that silently is not there.
        """
        gateway = gateway_for()

        def described(info: ModelInfo) -> dict[str, Any]:
            return {
                "name": info.name,
                "family": info.family,
                "version": info.version,
                "context_window": info.context_window,
                "capabilities": [c.value for c in info.capabilities],
                "status": info.status.value,
                "usable": info.status.usable,
                "pinned": info.pinned,
                "adapter": info.adapter,
            }

        usable = gateway.list_models()
        listed = gateway.list_models(include_unusable=True) if include_unusable else usable
        routing = gateway.routing
        rules = [
            {
                "task": rule.task.value,
                "model": rule.model,
                "fallbacks": rule.fallbacks,
                "min_context": rule.min_context,
                "require": [c.value for c in rule.require],
            }
            for rule in routing.rules
        ]
        # What each kind of work would actually resolve to today, which is not always what the
        # rule names: an unapproved or too-small model is skipped, and the reason is reported.
        router = ModelRouter(gateway, routing)
        resolved: dict[str, Any] = {}
        for kind in TaskKind:
            try:
                candidates, rejected, reason = router.candidates(kind)
            except ModelError as exc:  # pragma: no cover - defensive
                resolved[kind.value] = {"error": str(exc)}
                continue
            resolved[kind.value] = {
                "model": candidates[0] if candidates else None,
                "fallbacks": candidates[1:],
                "reason": reason,
                "unavailable": rejected,
            }
        return {
            "default": gateway.default_name(),
            "models": [described(i) for i in listed],
            "routing": {"fallbacks": routing.fallbacks, "rules": rules, "resolves_to": resolved},
        }

    # ------------------------------------------------------------------ API-006
    @app.post("/context/search", dependencies=guard)
    def search_context(request: SearchRequest) -> dict[str, Any]:
        ctx, index = build_context()
        try:
            if index.stats()["files"] == 0:
                raise HTTPException(status_code=409, detail="the repository index is empty")
            if request.mode == "lexical":
                results = index.search_lexical(request.query, request.limit)
            elif request.mode == "semantic":
                results = index.search_semantic(request.query, request.limit)
            elif request.mode == "symbol":
                results = index.search_symbol(request.query, request.limit)
            else:
                results = index.search(request.query, request.limit, depth=request.depth)
            return {
                "results": [
                    {
                        "location": r.location,
                        "path": r.path,
                        "start_line": r.start_line,
                        "end_line": r.end_line,
                        "symbol": r.symbol,
                        "language": r.language,
                        "score": r.score,
                        "text": r.text,
                    }
                    for r in results
                ]
            }
        finally:
            index.close()

    # ------------------------------------------------------------------ API-007..010
    @app.post("/files", dependencies=guard)
    def apply_change(request: ToolCallRequest) -> dict[str, Any]:
        """API-007: create/update/delete authorized files, through the filesystem tools."""
        _require_prefix(request.tool, "fs.")
        return call_tool(request)

    @app.post("/commands", dependencies=guard)
    def run_command(request: ToolCallRequest) -> dict[str, Any]:
        """API-008: execute an approved command in the task workspace."""
        _require_prefix(request.tool, "shell.")
        return call_tool(request)

    @app.post("/tests", dependencies=guard)
    def run_tests(request: ToolCallRequest) -> dict[str, Any]:
        """API-009: start configured verification."""
        _require_prefix(request.tool, "test.")
        return call_tool(request)

    @app.post("/git", dependencies=guard)
    def git_operation(request: ToolCallRequest) -> dict[str, Any]:
        """API-010: status/branch/diff/commit/PR preparation."""
        _require_prefix(request.tool, "git.")
        return call_tool(request)

    @app.post("/review", dependencies=guard)
    def review_change(request: ReviewRequestBody) -> dict[str, Any]:
        """REV-001..007: review a diff, or the working tree when no diff is supplied.

        Read-only. The response carries the grouped findings and, importantly, ``complete``:
        a client must not treat an empty ``findings`` list from an incomplete review as
        approval, and the payload says which checks failed so it does not have to guess.
        """
        ctx, index = build_context()
        try:
            diff = request.diff
            if not diff.strip():
                arguments: dict[str, Any] = {}
                if request.staged:
                    arguments["staged"] = True
                if request.base:
                    arguments["base"] = request.base
                if request.path:
                    arguments["path"] = request.path
                arguments["include_untracked"] = request.include_untracked
                diff = default_registry().call("git.diff", arguments, ctx).output
            try:
                checks = (
                    tuple(ReviewCheck(name) for name in request.checks)
                    if request.checks
                    else DEFAULT_CHECKS
                )
            except ValueError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc

            try:
                selection = select_model(request.model, TaskKind.REVIEW, audit=ctx.audit)
                adapter = selection.adapter
                chosen = selection.describe()
            except (ModelError, PermissionError) as exc:
                adapter, chosen = None, f"unavailable: {exc}"

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
                    focus=request.focus,
                    summarize=request.summarize,
                )
            )
            ctx.audit.record(
                category=EventCategory.TASK,
                action="review.completed",
                outcome=Outcome.SUCCESS if report.complete else Outcome.FAILURE,
                model=report.model,
                details={
                    "files": len(report.files_reviewed),
                    "findings": len(report.findings),
                    "counts": report.counts(),
                    "complete": report.complete,
                },
            )
            return {**report.to_dict(), "model_selection": chosen}
        finally:
            index.close()

    @app.post("/tools/{tool_name}", dependencies=guard)
    def call_any_tool(tool_name: str, request: ToolCallRequest) -> dict[str, Any]:
        """Any other registered tool, under the same policy (database, browser, MCP)."""
        if tool_name != request.tool:
            raise HTTPException(status_code=422, detail="tool name in path and body must match")
        return call_tool(request)

    @app.get("/tools", dependencies=guard)
    def list_tools() -> dict[str, Any]:
        """MCP-002: the tools this policy exposes, with their argument contracts."""
        ctx, index = build_context()
        try:
            return {"tools": default_registry().schemas(ctx)}
        finally:
            index.close()

    # ------------------------------------------------------------------ approvals
    @app.get("/approvals", dependencies=guard)
    def list_approvals() -> dict[str, Any]:
        """Pending approvals.

        A request-scoped approver cannot hold state between requests, so an action needing
        approval is refused with 409 and the client re-sends it with ``auto_approve`` after a
        human decides. This endpoint reports that contract rather than pretending to hold a
        queue that does not exist.
        """
        return {
            "pending": [],
            "contract": (
                "An action requiring approval is refused with HTTP 409 and the reason. "
                "Re-send the same request with auto_approve=true to record an approved "
                "decision, which is audited."
            ),
        }

    @app.post("/approvals/{decision_id}", dependencies=guard)
    def decide_approval(decision_id: str, decision: ApprovalDecision) -> dict[str, Any]:
        ctx, index = build_context()
        try:
            from aica.audit import EventCategory, Outcome

            ctx.audit.record(
                category=EventCategory.APPROVAL,
                action=f"decision on {decision_id}",
                outcome=Outcome.SUCCESS if decision.approved else Outcome.PENDING_APPROVAL,
                details={"approved": decision.approved, "note": decision.note},
            )
        finally:
            index.close()
        return {"decision_id": decision_id, "approved": decision.approved, "recorded": True}

    # ------------------------------------------------------------------ administration
    @app.get("/admin/controls", dependencies=guard)
    def list_controls() -> dict[str, Any]:
        """SEC-007: what is currently switched off."""
        plane = ControlPlane(
            settings.workspace.resolve(),
            actor=settings.actor,
            rbac=load_policy(settings.policy_file).rbac,
        )
        try:
            return {
                "disabled": [json.loads(e.model_dump_json()) for e in plane.load()],
            }
        except ControlError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/admin/controls", dependencies=guard)
    def set_control(request: ControlRequest) -> dict[str, Any]:
        """SEC-007 / ADM-003 / ADM-004: disable or re-enable, in effect on the next call."""
        plane = ControlPlane(
            settings.workspace.resolve(),
            actor=settings.actor,
            rbac=load_policy(settings.policy_file).rbac,
        )
        try:
            kind = TargetKind(request.kind)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        try:
            if request.disabled:
                entry = plane.disable(kind, request.name, request.reason)
                changed, description = True, entry.describe()
            else:
                changed = plane.enable(kind, request.name, request.reason)
                description = f"{kind.value} {request.name!r} " + (
                    "re-enabled" if changed else "was not disabled"
                )
        except ControlError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return {"changed": changed, "detail": description}

    @app.get("/admin/history", dependencies=guard)
    def admin_history(limit: int = 50) -> dict[str, Any]:
        """ADM-010: administrative changes, attributable and reviewable."""
        plane = ControlPlane(
            settings.workspace.resolve(),
            actor=settings.actor,
            rbac=load_policy(settings.policy_file).rbac,
        )
        return {
            "changes": [
                json.loads(r.model_dump_json()) for r in plane.history(max(1, min(limit, 1000)))
            ]
        }

    # ------------------------------------------------------------------ audit
    def _audit_dir() -> Path:
        return settings.workspace.resolve() / ".aica" / "audit"

    @app.get("/audit", dependencies=guard)
    def read_audit(
        limit: int = 50,
        actor: str | None = None,
        category: str | None = None,
        outcome: str | None = None,
        tool: str | None = None,
        model: str | None = None,
        session_id: str | None = None,
        days: int | None = None,
        text: str | None = None,
    ) -> dict[str, Any]:
        """API-015 / ADM-007: search the audit trail, not just tail it.

        Every filter is a field the record already carries, so a search can only ever
        narrow what the log says - it cannot surface anything the record does not hold.
        """
        try:
            query = AuditQuery(
                actor=actor,
                category=EventCategory(category) if category else None,
                outcome=Outcome(outcome) if outcome else None,
                tool=tool,
                model=model,
                session_id=session_id,
                since=(datetime.now(UTC) - timedelta(days=days)) if days else None,
                text=text,
                limit=max(1, min(limit, 1000)),
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        events = audit_search(iter_events(_audit_dir()), query)
        return {
            "count": len(events),
            "events": [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "category": e.category.value,
                    "action": e.action,
                    "outcome": e.outcome.value,
                    "actor": e.actor,
                    "tool": e.tool,
                    "model": e.model,
                    "target": e.target,
                    "session_id": e.session_id,
                    "duration_ms": e.duration_ms,
                }
                for e in events
            ],
        }

    @app.get("/admin/usage", dependencies=guard)
    def usage(days: int = 30) -> dict[str, Any]:
        """ADM-006: usage and activity, counted from the audit log rather than a second meter."""
        since = datetime.now(UTC) - timedelta(days=max(1, min(days, 3650)))
        return summarize(iter_events(_audit_dir()), since=since).to_dict()

    @app.post("/admin/retention", dependencies=guard)
    def retention(request: RetentionRequest) -> dict[str, Any]:
        """ADM-009 / SEC-005: remove audit files outside the window. Dry run by default."""
        try:
            plans = plan_workspace_retention(
                settings.workspace.resolve(), request.keep_days, RetentionScope(request.scope)
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        payload: dict[str, Any] = {
            "applied": False,
            "scopes": [
                {
                    "scope": plan.scope.value,
                    "cutoff": plan.cutoff.isoformat(),
                    "would_remove": [p.name for p in plan.remove],
                    "keeping": len(plan.keep),
                    "bytes": plan.removed_bytes,
                }
                for plan in plans
            ],
        }
        if not request.apply:
            return payload
        policy = load_policy(settings.policy_file)
        try:
            policy.rbac.principal(settings.actor).require(
                Permission.ADMINISTER, "apply audit retention"
            )
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        removed = sum(apply_retention(plan) for plan in plans)
        payload.update(applied=True, removed=removed)
        return payload

    @app.get("/policy", dependencies=guard)
    def read_policy() -> dict[str, Any]:
        policy = load_policy(settings.policy_file)
        return {
            "version": policy.version,
            "environment": policy.autonomy.environment.value,
            "max_steps": policy.autonomy.max_steps,
            "max_seconds": policy.autonomy.max_seconds,
            "allowed_tools": policy.autonomy.allowed_tools,
            "allowed_directories": policy.autonomy.allowed_directories,
            "tool_deny": policy.tools.deny,
            "tool_allow": policy.tools.allow,
            "tool_deny_in_production": policy.tools.deny_in_production,
            "network_mode": policy.network.mode.value,
            "require_approval_for": [c.value for c in policy.approval.require_for],
            "blocked": [c.value for c in policy.approval.block],
            "protected_branches": policy.git.protected_branches,
        }

    return app


def _require_prefix(tool: str, prefix: str) -> None:
    if not tool.startswith(prefix):
        raise HTTPException(
            status_code=422,
            detail=f"this endpoint accepts {prefix}* tools; use /tools/{{name}} for others",
        )
