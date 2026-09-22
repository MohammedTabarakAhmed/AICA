"""CHAT-004: debugging from logs, stack traces and error output."""

from pathlib import Path

from aica.chat.assistant import CodingAssistant
from aica.chat.diagnostics import MAX_LOG_CHARS, parse_log
from aica.chat.session import Session
from aica.models.fake import ScriptedAdapter
from aica.rag.index import RepositoryIndex
from aica.workspace import WorkspaceGuard

PY_TRACEBACK = """Traceback (most recent call last):
  File "/app/main.py", line 12, in <module>
    run()
  File "/app/service/handler.py", line 44, in run
    return parse(payload)
  File "/usr/lib/python3.12/json/decoder.py", line 355, in raw_decode
    raise JSONDecodeError("Expecting value", s, err.value) from None
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
"""

NODE_TRACE = """TypeError: Cannot read properties of undefined (reading 'id')
    at getUser (/srv/app/src/users.ts:31:18)
    at handler (/srv/app/src/routes.ts:12:5)
    at node:internal/process/task_queues:95:5
"""

JAVA_TRACE = """Exception in thread "main" java.lang.NullPointerException: name is null
\tat com.example.OrderService.total(OrderService.java:88)
\tat com.example.Main.main(Main.java:14)
"""


def _project(root: Path) -> Path:
    (root / "service").mkdir()
    (root / "main.py").write_text("from service.handler import run\n\nrun()\n", encoding="utf-8")
    (root / "service" / "handler.py").write_text(
        "import json\n\n\ndef run(payload=''):\n    return parse(payload)\n\n\n"
        "def parse(payload):\n    return json.loads(payload)\n",
        encoding="utf-8",
    )
    return root


# ---------------------------------------------------------------- parsing


def test_python_traceback_frames_and_error(tmp_path: Path) -> None:
    diag = parse_log(PY_TRACEBACK)
    assert diag.error_type == "json.decoder.JSONDecodeError"
    assert diag.error_message is not None and "Expecting value" in diag.error_message
    assert [f.location for f in diag.frames] == [
        "/app/main.py:12",
        "/app/service/handler.py:44",
        "/usr/lib/python3.12/json/decoder.py:355",
    ]
    assert [f.symbol for f in diag.frames] == ["<module>", "run", "raw_decode"]


def test_project_frames_exclude_library_code(tmp_path: Path) -> None:
    _project(tmp_path)
    log = PY_TRACEBACK.replace("/app/", f"{tmp_path.as_posix()}/")
    diag = parse_log(log, tmp_path)
    locations = [f.location for f in diag.project_frames]
    assert locations == ["main.py:12", "service/handler.py:44"]
    # The deepest project frame is the culprit, not the stdlib frame below it.
    assert diag.culprit is not None
    assert diag.culprit.location == "service/handler.py:44"


def test_node_stack_is_parsed(tmp_path: Path) -> None:
    diag = parse_log(NODE_TRACE)
    assert [f.location for f in diag.frames][:2] == [
        "/srv/app/src/users.ts:31",
        "/srv/app/src/routes.ts:12",
    ]
    assert diag.frames[0].symbol == "getUser"


def test_java_stack_and_exception_are_parsed() -> None:
    diag = parse_log(JAVA_TRACE)
    assert diag.error_type == "java.lang.NullPointerException"
    assert diag.error_message == "name is null"
    assert [f.location for f in diag.frames] == ["OrderService.java:88", "Main.java:14"]


def test_compiler_style_diagnostics_are_parsed() -> None:
    diag = parse_log("src/app.ts:10:5 - error TS2322: Type 'string' is not assignable\n")
    assert diag.frames[0].location == "src/app.ts:10"


def test_pytest_failure_lines_are_parsed(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_y(): assert False\n", encoding="utf-8")
    diag = parse_log("FAILED tests/test_x.py::test_y - AssertionError: boom\n", tmp_path)
    frame = diag.frames[0]
    assert frame.file == "tests/test_x.py" and frame.symbol == "test_y"
    assert frame.project is True


def test_secrets_in_logs_are_redacted() -> None:
    diag = parse_log("ValueError: token=ghp_abcdefghijklmnopqrstuvwxyz0123 rejected")
    assert diag.error_message is not None
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123" not in diag.error_message


def test_long_log_is_truncated_to_the_tail() -> None:
    log = ("noise line\n" * 20_000) + PY_TRACEBACK
    diag = parse_log(log)
    assert diag.truncated is True
    assert diag.error_type == "json.decoder.JSONDecodeError"  # the tail was kept
    assert f"last {MAX_LOG_CHARS}" in diag.render()


def test_unrecognised_log_reports_no_findings() -> None:
    diag = parse_log("everything is fine\nstill fine\n")
    assert diag.frames == [] and diag.error_type is None
    assert "No file references" in diag.render()


def test_queries_prefer_implicated_symbols(tmp_path: Path) -> None:
    _project(tmp_path)
    diag = parse_log(PY_TRACEBACK.replace("/app/", f"{tmp_path.as_posix()}/"), tmp_path)
    queries = diag.queries()
    assert queries[0] == "run"  # deepest project frame's symbol first
    assert any("Expecting value" in q for q in queries)


# ---------------------------------------------------------------- CHAT-004 end to end


def test_debug_retrieves_the_implicated_file_and_records_the_log(tmp_path: Path) -> None:
    _project(tmp_path)
    index = RepositoryIndex(WorkspaceGuard(tmp_path))
    try:
        index.index_repository()
        adapter = ScriptedAdapter(
            ["The payload is empty, so json.loads fails at service/handler.py:8."]
        )
        assistant = CodingAssistant(adapter, index, workspace_root=tmp_path)
        session = Session(workspace=str(tmp_path))
        log = PY_TRACEBACK.replace("/app/", f"{tmp_path.as_posix()}/")

        answer, diag = assistant.debug(session, log, "why does this fail?")

        assert diag.culprit is not None and diag.culprit.file == "service/handler.py"
        assert any(r.path == "service/handler.py" for r in answer.retrieved)
        assert "service/handler.py:8" in answer.citations
        # CHAT-006/SAFE-007: the log is attached and fenced as untrusted data.
        assert session.attachments[0].kind == "log"
        assert "UNTRUSTED" in session.attachments[0].as_context()
        # The structured analysis is in the prompt the model saw.
        sent = "\n".join(m.content for m in adapter.calls[0])
        assert "Most likely origin: service/handler.py:44" in sent
    finally:
        index.close()


def test_debug_without_an_index_still_diagnoses(tmp_path: Path) -> None:
    adapter = ScriptedAdapter(["Check the JSON payload."])
    assistant = CodingAssistant(adapter, None, workspace_root=tmp_path)
    answer, diag = assistant.debug(Session(), PY_TRACEBACK)
    assert answer.retrieved == []
    assert diag.error_type == "json.decoder.JSONDecodeError"


def test_search_file_prefers_the_chunk_covering_the_line(tmp_path: Path) -> None:
    _project(tmp_path)
    index = RepositoryIndex(WorkspaceGuard(tmp_path))
    try:
        index.index_repository()
        hits = index.search_file("service/handler.py", 8, 2)
        assert hits, "expected chunks for the implicated file"
        assert hits[0].start_line <= 8 <= hits[0].end_line
        assert index.search_file("does/not/exist.py") == []
    finally:
        index.close()


def test_custom_exception_without_an_error_suffix_is_recognised() -> None:
    """Project exceptions are often not named *Error (N818 is disabled here)."""
    log = (
        "Traceback (most recent call last):\n"
        '  File "src/aica/chat/commit_message.py", line 72, in validate_commit_message\n'
        "aica.chat.commit_message.InvalidCommitMessage: subject too short: 'wip'\n"
    )
    diag = parse_log(log)
    assert diag.error_type == "aica.chat.commit_message.InvalidCommitMessage"
    assert diag.error_message == "subject too short: 'wip'"


def test_prose_does_not_override_a_real_exception() -> None:
    log = "Note: retrying the request\n" + PY_TRACEBACK + "Hint: check the payload\n"
    diag = parse_log(log)
    assert diag.error_type == "json.decoder.JSONDecodeError"
