"""HTTP API (API-001..API-011, BRD section 15).

Requests go through the real ASGI application with FastAPI's TestClient, so routing,
validation, authentication, status codes and streaming are all genuinely exercised. Only the
model is scripted.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.api.app import ApiSettings, create_app
from aica.api.tasks import TaskState

fastapi_testclient = pytest.importorskip("fastapi.testclient", reason="the api extra is needed")
TestClient = fastapi_testclient.TestClient

TOKEN = "test-token-abcdefghijklmnop"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

PLAN = json.dumps(
    {
        "summary": "look at the invoice module",
        "steps": [
            {"intent": "read it", "tool": "fs.read", "arguments": {"path": "src/invoice.py"}}
        ],
        "verification": [],
    }
)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "invoice.py").write_text(
        "def compute_total(items):\n    return sum(items)\n", encoding="utf-8"
    )
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "policy.toml").write_text(
        "version = 1\n[autonomy]\nmax_steps = 10\n[network]\nmode = 'deny'\n", encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def client(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """An app wired to a scripted model, so tasks run without a provider."""
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    monkeypatch.setattr(
        ModelGateway, "get", lambda self, name=None: ScriptedAdapter([PLAN], name="api-model")
    )
    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "config" / "policy.toml"),
            token=TOKEN,
        )
    )
    with TestClient(app) as test_client:
        yield test_client


def create_session(client: TestClient, **body: object) -> str:
    response = client.post("/sessions", json=body, headers=HEADERS)
    assert response.status_code == 201, response.text
    return str(response.json()["session_id"])


# ---------------------------------------------------------------- authentication


def test_health_is_the_only_open_endpoint(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "ok"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/sessions"),
        ("post", "/sessions"),
        ("get", "/models"),
        ("get", "/tools"),
        ("get", "/audit"),
        ("get", "/policy"),
        ("post", "/context/search"),
        ("get", "/tasks"),
    ],
)
def test_every_other_endpoint_requires_a_token(client: TestClient, method: str, path: str) -> None:
    call = getattr(client, method)
    response = call(path, json={}) if method == "post" else call(path)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_a_wrong_token_is_rejected(client: TestClient) -> None:
    response = client.get("/sessions", headers={"Authorization": "Bearer not-the-token"})
    assert response.status_code == 401


def test_a_token_is_generated_when_none_is_configured(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The server must never come up with an empty token."""
    monkeypatch.delenv("AICA_API_TOKEN", raising=False)
    app = create_app(ApiSettings(workspace=workspace))
    assert len(app.state.token) >= 32
    with TestClient(app) as unauthenticated:
        assert unauthenticated.get("/sessions").status_code == 401


# ---------------------------------------------------------------- API-001/011


def test_create_and_read_back_a_session(client: TestClient) -> None:
    response = client.post(
        "/sessions",
        json={"title": "add validation", "model": "api-model", "branch": "work"},
        headers=HEADERS,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["model"] == "api-model" and body["branch"] == "work"

    listed = client.get("/sessions", headers=HEADERS).json()["sessions"]
    assert any(s["session_id"] == body["session_id"] for s in listed)

    detail = client.get(f"/sessions/{body['session_id']}", headers=HEADERS).json()
    assert detail["title"] == "add validation"
    assert "reproducibility" in detail


def test_unknown_session_is_404(client: TestClient) -> None:
    assert client.get("/sessions/nope", headers=HEADERS).status_code == 404


def test_malformed_session_request_is_422(client: TestClient) -> None:
    response = client.post("/sessions", json={"unexpected": True}, headers=HEADERS)
    assert response.status_code == 422


# ---------------------------------------------------------------- API-002/003


def test_run_a_task_and_stream_its_events(client: TestClient) -> None:
    session_id = create_session(client)
    response = client.post(
        f"/sessions/{session_id}/tasks",
        json={"task": "look at the invoice module"},
        headers=HEADERS,
    )
    assert response.status_code == 202
    task_id = response.json()["task_id"]

    # API-003: the stream replays from the beginning, so nothing is missed.
    with client.stream("GET", f"/tasks/{task_id}/events?timeout=30", headers=HEADERS) as stream:
        assert stream.headers["content-type"].startswith("text/event-stream")
        body = "".join(stream.iter_text())
    assert "event: task_started" in body
    assert "event: plan_created" in body
    assert "event: task_finished" in body

    detail = client.get(f"/tasks/{task_id}", headers=HEADERS).json()
    assert detail["state"] == TaskState.FINISHED.value
    assert detail["report"]["outcome"] in {"SUCCESS", "INCOMPLETE"}
    assert "fs.read" in detail["plan"]


def test_tasks_are_listed_per_session(client: TestClient) -> None:
    session_id = create_session(client)
    task_id = client.post(
        f"/sessions/{session_id}/tasks", json={"task": "read it"}, headers=HEADERS
    ).json()["task_id"]
    client.get(f"/tasks/{task_id}", headers=HEADERS)

    listed = client.get(f"/tasks?session_id={session_id}", headers=HEADERS).json()["tasks"]
    assert [t["task_id"] for t in listed] == [task_id]
    assert client.get("/tasks?session_id=other", headers=HEADERS).json()["tasks"] == []


def test_task_on_an_unknown_session_is_404(client: TestClient) -> None:
    response = client.post("/sessions/ghost/tasks", json={"task": "x"}, headers=HEADERS)
    assert response.status_code == 404


def test_resume_without_saved_state_is_409(client: TestClient) -> None:
    session_id = create_session(client)
    response = client.post(
        f"/sessions/{session_id}/tasks",
        json={"task": "continue", "resume": True},
        headers=HEADERS,
    )
    assert response.status_code == 409


def test_unknown_task_endpoints_are_404(client: TestClient) -> None:
    assert client.get("/tasks/ghost", headers=HEADERS).status_code == 404
    assert client.post("/tasks/ghost/cancel", headers=HEADERS).status_code == 404
    assert client.post("/tasks/ghost/pause", headers=HEADERS).status_code == 404
    assert client.get("/tasks/ghost/events", headers=HEADERS).status_code == 404


# ---------------------------------------------------------------- API-004/005


def test_cancel_reports_whether_it_took_effect(client: TestClient) -> None:
    session_id = create_session(client)
    task_id = client.post(
        f"/sessions/{session_id}/tasks", json={"task": "read it"}, headers=HEADERS
    ).json()["task_id"]
    client.get(f"/tasks/{task_id}", headers=HEADERS)
    # The scripted task finishes almost immediately, so a later cancel is a no-op - and the
    # response says so rather than pretending it stopped something.
    body = client.post(f"/tasks/{task_id}/cancel", headers=HEADERS).json()
    assert body["task_id"] == task_id and isinstance(body["cancelled"], bool)


def test_pause_persists_state_and_resume_continues(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """API-005/UX-006: pause stops at a step boundary and keeps what is needed to continue."""
    from aica.agent.loop import STATE_KEY
    from aica.chat.session import SessionStore
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    slow_plan = json.dumps(
        {
            "summary": "several steps",
            "steps": [
                {"intent": "read", "tool": "fs.read", "arguments": {"path": "src/invoice.py"}}
                for _ in range(6)
            ],
            "verification": [],
        }
    )
    monkeypatch.setattr(
        ModelGateway, "get", lambda self, name=None: ScriptedAdapter([slow_plan], name="api-model")
    )
    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "config" / "policy.toml"),
            token=TOKEN,
        )
    )
    with TestClient(app) as client:
        session_id = create_session(client)
        task_id = client.post(
            f"/sessions/{session_id}/tasks",
            json={"task": "read it repeatedly", "max_steps": 6},
            headers=HEADERS,
        ).json()["task_id"]

        paused = client.post(f"/tasks/{task_id}/pause", headers=HEADERS).json()
        assert paused["state"] in {TaskState.PAUSED.value, TaskState.FINISHED.value}

        if paused["state"] == TaskState.PAUSED.value:
            # The state needed to continue was written to the session.
            session = SessionStore(workspace).load(session_id)
            assert STATE_KEY in session.task_state
            resumed = client.post(f"/tasks/{task_id}/resume", headers=HEADERS)
            assert resumed.status_code == 202
            assert resumed.json()["task_id"] != task_id  # a new run, continuing the old state


def test_resuming_a_finished_task_is_409(client: TestClient) -> None:
    session_id = create_session(client)
    task_id = client.post(
        f"/sessions/{session_id}/tasks", json={"task": "read it"}, headers=HEADERS
    ).json()["task_id"]
    client.get(f"/tasks/{task_id}/events?timeout=30", headers=HEADERS)
    assert client.post(f"/tasks/{task_id}/resume", headers=HEADERS).status_code == 409


# ---------------------------------------------------------------- API-006


def test_repository_search(client: TestClient, workspace: Path) -> None:
    empty = client.post("/context/search", json={"query": "total"}, headers=HEADERS)
    assert empty.status_code == 409  # nothing indexed yet, said plainly

    indexed = client.post(
        "/tools/repo.index",
        json={"tool": "repo.index", "arguments": {}},
        headers=HEADERS,
    )
    assert indexed.status_code == 200

    results = client.post(
        "/context/search", json={"query": "compute total", "limit": 5}, headers=HEADERS
    ).json()["results"]
    assert any(r["path"] == "src/invoice.py" for r in results)
    assert all(":" in r["location"] for r in results)


# ---------------------------------------------------------------- API-007..010


def test_apply_a_file_change(client: TestClient, workspace: Path) -> None:
    response = client.post(
        "/files",
        json={
            "tool": "fs.write",
            "arguments": {"path": "src/new.py", "content": "x = 1\n"},
            "auto_approve": True,
        },
        headers=HEADERS,
    )
    assert response.status_code == 200
    assert (workspace / "src" / "new.py").read_text(encoding="utf-8") == "x = 1\n"
    assert "diff" in response.json()["data"]


def test_run_a_command(client: TestClient) -> None:
    response = client.post(
        "/commands",
        json={"tool": "shell.run", "arguments": {"command": "echo hello"}},
        headers=HEADERS,
    )
    assert response.status_code == 200
    assert "hello" in response.json()["output"]


def test_run_tests_endpoint(client: TestClient) -> None:
    response = client.post(
        "/tests",
        json={
            "tool": "test.run",
            "arguments": {"command": f'"{sys.executable}" -c "print(1)"', "kind": "unit"},
        },
        headers=HEADERS,
    )
    assert response.status_code == 200


def test_git_endpoint(client: TestClient, workspace: Path) -> None:
    for args in (
        ["git", "init", "-q", "-b", "work"],
        ["git", "config", "user.email", "t@example.com"],
        ["git", "config", "user.name", "T"],
    ):
        subprocess.run(args, cwd=workspace, check=True)
    response = client.post("/git", json={"tool": "git.status", "arguments": {}}, headers=HEADERS)
    assert response.status_code == 200


def test_endpoints_reject_tools_from_another_family(client: TestClient) -> None:
    """A command must not be smuggled through the file endpoint."""
    response = client.post(
        "/files",
        json={"tool": "shell.run", "arguments": {"command": "echo hi"}},
        headers=HEADERS,
    )
    assert response.status_code == 422
    assert "fs." in response.json()["detail"]


def test_tool_path_and_body_must_agree(client: TestClient) -> None:
    response = client.post(
        "/tools/fs.read",
        json={"tool": "fs.write", "arguments": {}},
        headers=HEADERS,
    )
    assert response.status_code == 422


# ---------------------------------------------------------------- guards over HTTP


def test_a_destructive_command_is_refused_without_approval(
    client: TestClient, workspace: Path
) -> None:
    """SAFE-001: the HTTP surface cannot bypass the approval gate."""
    response = client.post(
        "/commands",
        json={"tool": "shell.run", "arguments": {"command": "rm -rf src"}},
        headers=HEADERS,
    )
    assert response.status_code == 409
    assert (workspace / "src").exists()


def test_a_path_outside_the_workspace_is_refused(client: TestClient) -> None:
    response = client.post(
        "/files",
        json={"tool": "fs.read", "arguments": {"path": "../../../etc/hosts"}},
        headers=HEADERS,
    )
    assert response.status_code in {400, 403}


def test_invalid_tool_arguments_are_422(client: TestClient) -> None:
    response = client.post(
        "/files", json={"tool": "fs.read", "arguments": {"wrong": 1}}, headers=HEADERS
    )
    assert response.status_code == 422


def test_unknown_tool_is_404(client: TestClient) -> None:
    response = client.post(
        "/tools/nope.nope", json={"tool": "nope.nope", "arguments": {}}, headers=HEADERS
    )
    assert response.status_code == 404


# ---------------------------------------------------------------- models, tools, audit


def test_models_are_listed(client: TestClient) -> None:
    body = client.get("/models", headers=HEADERS).json()
    assert "models" in body and "default" in body


def test_tools_expose_their_schemas(client: TestClient) -> None:
    tools = client.get("/tools", headers=HEADERS).json()["tools"]
    names = {t["name"] for t in tools}
    assert {"fs.read", "git.status", "test.run"} <= names
    assert all("parameters" in t for t in tools)


def test_audit_records_api_activity(client: TestClient) -> None:
    client.post(
        "/commands",
        json={"tool": "shell.run", "arguments": {"command": "echo audited"}},
        headers=HEADERS,
    )
    events = client.get("/audit?limit=20", headers=HEADERS).json()["events"]
    assert any("echo audited" in e["action"] for e in events)
    assert all("actor" in e for e in events)


def test_policy_is_visible(client: TestClient) -> None:
    body = client.get("/policy", headers=HEADERS).json()
    assert body["max_steps"] == 10
    assert body["network_mode"] == "deny"


def test_approval_contract_is_documented(client: TestClient) -> None:
    body = client.get("/approvals", headers=HEADERS).json()
    assert "409" in body["contract"]
    decision = client.post(
        "/approvals/some-id", json={"approved": True, "note": "ok"}, headers=HEADERS
    )
    assert decision.status_code == 200 and decision.json()["recorded"] is True


def test_a_task_can_use_a_repository_tool(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A task runs on a worker thread; the index it inherits must still work there.

    This is the regression test for a cross-thread SQLite failure that made every `repo.*`
    step inside an HTTP-started task fail, and leaked the connection when it was closed.
    """
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    plan = json.dumps(
        {
            "summary": "index and search from inside the task",
            "steps": [
                {"intent": "index", "tool": "repo.index", "arguments": {}},
                {
                    "intent": "search",
                    "tool": "repo.search",
                    "arguments": {"query": "compute total", "limit": 3},
                },
            ],
            "verification": [],
        }
    )
    monkeypatch.setattr(
        ModelGateway, "get", lambda self, name=None: ScriptedAdapter([plan], name="api-model")
    )
    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "config" / "policy.toml"),
            token=TOKEN,
        )
    )
    with TestClient(app) as client:
        session_id = create_session(client)
        task_id = client.post(
            f"/sessions/{session_id}/tasks", json={"task": "search the repo"}, headers=HEADERS
        ).json()["task_id"]
        client.get(f"/tasks/{task_id}/events?timeout=60", headers=HEADERS)

        detail = client.get(f"/tasks/{task_id}", headers=HEADERS).json()
        assert detail["state"] == TaskState.FINISHED.value
        assert "cleanup_error" not in detail, detail.get("cleanup_error")
        assert detail.get("error") is None
        # Both repository steps really ran on the worker thread.
        assert "[x] s1" in detail["plan"] and "[x] s2" in detail["plan"]


# ---------------------------------------------------------------- API-012 / API-013


REGISTRY = """
default = "main"

[[models]]
name = "main"
family = "deepseek"
version = "main-20250101"
base_url = "https://api.deepseek.com"
context_window = 128000
capabilities = ["chat", "streaming", "tools"]
pinned = true

[[models]]
name = "reviewer"
family = "glm"
version = "reviewer-20250101"
base_url = "https://api.deepseek.com"
context_window = 200000
capabilities = ["chat", "streaming"]

[[models]]
name = "waiting"
family = "kimi"
version = "waiting-1"
base_url = "https://api.deepseek.com"
capabilities = ["chat", "streaming"]
status = "pending"
notes = "not approved yet"

[[routing.rules]]
task = "review"
model = "reviewer"

[[routing.rules]]
task = "planning"
model = "main"
"""


@pytest.fixture
def registry_client(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """An app with a real multi-model registry; the adapters themselves stay scripted."""
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    monkeypatch.setattr(
        ModelGateway, "get", lambda self, name=None: ScriptedAdapter([PLAN], name=str(name))
    )
    models_file = workspace / "config" / "models.toml"
    models_file.write_text(REGISTRY, encoding="utf-8")
    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "config" / "policy.toml"),
            models_file=str(models_file),
            token=TOKEN,
        )
    )
    with TestClient(app) as test_client:
        yield test_client


def test_the_models_endpoint_reports_capabilities_status_and_routing(
    registry_client: TestClient,
) -> None:
    """API-012/UX-007: enough to choose a model before starting, and to see why not."""
    body = registry_client.get("/models", headers=HEADERS).json()
    assert body["default"] == "main"
    models = {m["name"]: m for m in body["models"]}
    assert set(models) == {"main", "reviewer"}  # "waiting" is not usable, so not offered
    assert models["main"]["version"] == "main-20250101"
    assert models["main"]["pinned"] is True
    assert models["main"]["capabilities"] == ["chat", "streaming", "tools"]
    assert models["reviewer"]["context_window"] == 200000

    routing = body["routing"]
    assert {"task": "review", "model": "reviewer"}.items() <= routing["rules"][0].items()
    # What each kind of work resolves to today - the question a UI actually needs answered.
    assert routing["resolves_to"]["review"]["model"] == "reviewer"
    assert routing["resolves_to"]["planning"]["model"] == "main"
    assert routing["resolves_to"]["embeddings"]["model"] is None  # nothing can embed


def test_a_model_awaiting_approval_is_shown_with_its_status_when_asked(
    registry_client: TestClient,
) -> None:
    body = registry_client.get("/models?include_unusable=true", headers=HEADERS).json()
    waiting = next(m for m in body["models"] if m["name"] == "waiting")
    assert waiting["status"] == "pending" and waiting["usable"] is False


def test_a_task_can_pin_the_model_by_name(registry_client: TestClient) -> None:
    """API-013/MM-002: a named model is used as asked, and reported back exactly."""
    session = create_session(registry_client)
    response = registry_client.post(
        f"/sessions/{session}/tasks",
        json={"task": "read the invoice module", "model": "reviewer"},
        headers=HEADERS,
    )
    assert response.status_code == 202, response.text
    chosen = response.json()["model"]
    assert chosen["name"] == "reviewer"
    assert chosen["version"] == "reviewer-20250101"  # MM-012: the exact version
    assert "requested by name" in chosen["reason"]


def test_a_task_without_a_model_is_routed_by_the_kind_of_work(
    registry_client: TestClient,
) -> None:
    """API-013/MM-004: the routing rules decide, and the answer says which rule applied."""
    session = create_session(registry_client)
    response = registry_client.post(
        f"/sessions/{session}/tasks",
        json={"task": "review the invoice module", "task_kind": "review"},
        headers=HEADERS,
    )
    assert response.status_code == 202, response.text
    chosen = response.json()["model"]
    assert chosen["name"] == "reviewer"
    assert chosen["task_kind"] == "review"
    assert "routing rule" in chosen["reason"]

    # The session now records what answered for it (MM-012).
    detail = registry_client.get(f"/sessions/{session}", headers=HEADERS).json()
    assert detail["model"] == "reviewer"


def test_a_pinned_model_is_offered_no_fallback(registry_client: TestClient) -> None:
    session = create_session(registry_client)
    response = registry_client.post(
        f"/sessions/{session}/tasks",
        json={"task": "plan something", "model": "main"},
        headers=HEADERS,
    )
    assert response.json()["model"]["fallbacks"] == []


def test_asking_for_a_model_that_is_not_approved_is_refused(registry_client: TestClient) -> None:
    session = create_session(registry_client)
    response = registry_client.post(
        f"/sessions/{session}/tasks",
        json={"task": "do something", "model": "waiting"},
        headers=HEADERS,
    )
    assert response.status_code == 503
    assert "pending" in response.json()["detail"]


def test_an_unknown_task_kind_is_rejected(registry_client: TestClient) -> None:
    session = create_session(registry_client)
    response = registry_client.post(
        f"/sessions/{session}/tasks",
        json={"task": "do something", "task_kind": "telepathy"},
        headers=HEADERS,
    )
    assert response.status_code == 422
