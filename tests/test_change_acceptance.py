"""Accept / reject / partial accept of an agent's changes (CC-005)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from aica.review.acceptance import (
    ChangedSinceTask,
    fingerprint,
    hunks,
    merge,
    require_unchanged,
)

fastapi_testclient = pytest.importorskip("fastapi.testclient", reason="the api extra is needed")
TestClient = fastapi_testclient.TestClient

TOKEN = "test-token-abcdefghijklmnop"
HEADERS = {"Authorization": f"Bearer {TOKEN}"}

ORIGINAL = "def a():\n    return 1\n\n\ndef b():\n    return 2\n\n\ndef c():\n    return 3\n"
FINAL = "def a():\n    return 10\n\n\ndef b():\n    return 2\n\n\ndef c():\n    return 30\n"


# ------------------------------------------------------------------ hunks
def test_an_edit_splits_into_independent_hunks() -> None:
    found = hunks(ORIGINAL, FINAL)
    assert [(h.old_lines, h.new_lines) for h in found] == [
        (["    return 1"], ["    return 10"]),
        (["    return 3"], ["    return 30"]),
    ]
    assert [h.old_start for h in found] == [2, 10]


@pytest.mark.parametrize(
    ("accepted", "expected"),
    [
        (set(), ORIGINAL),
        ({0, 1}, FINAL),
        ({0}, ORIGINAL.replace("return 1\n", "return 10\n")),
        ({1}, ORIGINAL.replace("return 3\n", "return 30\n")),
    ],
)
def test_merge_keeps_exactly_the_accepted_hunks(accepted: set[int], expected: str) -> None:
    assert merge(ORIGINAL, FINAL, accepted) == expected


def test_merge_preserves_crlf_line_endings() -> None:
    original, final = ORIGINAL.replace("\n", "\r\n"), FINAL.replace("\n", "\r\n")
    assert merge(original, final, {0}) == ORIGINAL.replace("return 1\n", "return 10\n").replace(
        "\n", "\r\n"
    )


def test_merge_rejects_an_unknown_hunk() -> None:
    with pytest.raises(ValueError, match="no such hunk"):
        merge(ORIGINAL, FINAL, {7})


def test_a_file_edited_since_the_task_is_refused() -> None:
    require_unchanged("x.py", FINAL, fingerprint(FINAL))
    with pytest.raises(ChangedSinceTask):
        require_unchanged("x.py", FINAL + "# mine\n", fingerprint(FINAL))
    with pytest.raises(ChangedSinceTask):
        require_unchanged("x.py", None, fingerprint(FINAL))


# ------------------------------------------------------------------ HTTP
PLAN = json.dumps(
    {
        "summary": "edit two functions and add a file",
        "steps": [
            {
                "intent": "change a and c",
                "tool": "fs.write",
                "arguments": {"path": "src/funcs.py", "content": FINAL},
            },
            {
                "intent": "add a helper",
                "tool": "fs.write",
                "arguments": {"path": "src/helper.py", "content": "X = 1\n"},
            },
        ],
        "verification": [],
    }
)


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
def client(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    from aica.api.app import ApiSettings, create_app
    from aica.models.fake import ScriptedAdapter
    from aica.models.gateway import ModelGateway

    monkeypatch.setattr(ModelGateway, "get", lambda self, name=None: ScriptedAdapter([PLAN]))
    app = create_app(
        ApiSettings(
            workspace=workspace,
            policy_file=str(workspace / "config" / "policy.toml"),
            token=TOKEN,
            actor="reviewer",
        )
    )
    with TestClient(app) as test_client:
        yield test_client


def _finished_task(client: TestClient) -> str:
    session_id = client.post("/sessions", json={}, headers=HEADERS).json()["session_id"]
    started = client.post(
        f"/sessions/{session_id}/tasks", json={"task": "edit"}, headers=HEADERS
    ).json()
    task_id = str(started["task_id"])
    client.app.state.manager.get(task_id).wait(timeout=30)  # type: ignore[attr-defined]
    return task_id


def _decide(client: TestClient, task_id: str, path: str, accept: object) -> object:
    return client.post(
        f"/tasks/{task_id}/changes/decide",
        json={"path": path, "accept": accept},
        headers=HEADERS,
    )


def test_changes_are_listed_as_hunks(client: TestClient) -> None:
    task_id = _finished_task(client)
    files = {
        f["path"]: f
        for f in client.get(f"/tasks/{task_id}/changes", headers=HEADERS).json()["files"]
    }
    funcs = files["src/funcs.py"]
    assert funcs["action"] == "modified" and funcs["decidable"] is True
    assert len(funcs["hunks"]) == 2 and funcs["decision"] == "pending"
    assert files["src/helper.py"]["hunks"] is None  # created: whole-file only


def test_partial_accept_keeps_only_the_chosen_hunk(client: TestClient, workspace: Path) -> None:
    task_id = _finished_task(client)
    response = _decide(client, task_id, "src/funcs.py", [0])
    assert response.status_code == 200, response.text  # type: ignore[attr-defined]
    text = (workspace / "src" / "funcs.py").read_text(encoding="utf-8")
    assert "return 10" in text and "return 3\n" in text and "return 30" not in text
    # A decision is final.
    assert _decide(client, task_id, "src/funcs.py", "all").status_code == 409  # type: ignore[attr-defined]


def test_reject_restores_the_original_and_removes_a_created_file(
    client: TestClient, workspace: Path
) -> None:
    task_id = _finished_task(client)
    assert _decide(client, task_id, "src/funcs.py", "none").status_code == 200  # type: ignore[attr-defined]
    assert (workspace / "src" / "funcs.py").read_text(encoding="utf-8") == ORIGINAL
    assert _decide(client, task_id, "src/helper.py", "none").status_code == 200  # type: ignore[attr-defined]
    assert not (workspace / "src" / "helper.py").exists()


def test_accept_changes_nothing_on_disk(client: TestClient, workspace: Path) -> None:
    task_id = _finished_task(client)
    assert _decide(client, task_id, "src/funcs.py", "all").status_code == 200  # type: ignore[attr-defined]
    assert (workspace / "src" / "funcs.py").read_text(encoding="utf-8") == FINAL


def test_a_file_edited_after_the_task_cannot_be_rejected(
    client: TestClient, workspace: Path
) -> None:
    task_id = _finished_task(client)
    (workspace / "src" / "funcs.py").write_text(FINAL + "# my own work\n", encoding="utf-8")
    listed = client.get(f"/tasks/{task_id}/changes", headers=HEADERS).json()["files"]
    assert next(f for f in listed if f["path"] == "src/funcs.py")["decidable"] is False
    response = _decide(client, task_id, "src/funcs.py", "none")
    assert response.status_code == 409  # type: ignore[attr-defined]
    assert "# my own work" in (workspace / "src" / "funcs.py").read_text(encoding="utf-8")


def test_partial_accept_of_a_created_file_is_refused(client: TestClient) -> None:
    task_id = _finished_task(client)
    assert _decide(client, task_id, "src/helper.py", [0]).status_code == 422  # type: ignore[attr-defined]


def test_decisions_are_audited(client: TestClient) -> None:
    task_id = _finished_task(client)
    _decide(client, task_id, "src/funcs.py", "none")
    audit = client.get("/audit", params={"text": "change decision"}, headers=HEADERS).json()
    assert audit["count"] >= 1


def test_an_unknown_path_is_404(client: TestClient) -> None:
    task_id = _finished_task(client)
    assert _decide(client, task_id, "src/other.py", "all").status_code == 404  # type: ignore[attr-defined]
