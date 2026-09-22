"""GIT-006: model-generated commit messages, validated before use."""

import subprocess
from pathlib import Path

import pytest

from aica.chat.commit_message import (
    SUBJECT_LIMIT,
    CommitMessage,
    InvalidCommitMessage,
    fallback_message,
    generate_commit_message,
    suggest_commit_message,
    summarize_diff,
    validate_commit_message,
)
from aica.models.base import ModelError
from aica.models.fake import ScriptedAdapter
from aica.tools import default_registry
from tests.test_tools_fs import make_ctx

DIFF = """diff --git a/src/app.py b/src/app.py
index 111..222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,5 @@
 def add(a, b):
-    return a + b
+    if a is None:
+        raise ValueError("a is required")
+    return a + b
"""

GOOD = "Reject a missing left operand in add\n\nRaise ValueError instead of returning None + b.\n"


# ---------------------------------------------------------------- validation


def test_valid_message_is_parsed() -> None:
    msg = validate_commit_message(GOOD)
    assert msg.subject == "Reject a missing left operand in add"
    assert msg.body.startswith("Raise ValueError")
    assert msg.generated is False  # validation alone does not mark it model-generated


@pytest.mark.parametrize(
    "text",
    [
        "",
        "   \n\n",
        "wip",
        "Fix",
        "Update.",
        "Add support for the new retrieval pipeline including the dependency graph walker and the symbol table",
    ],
)
def test_unusable_messages_are_rejected(text: str) -> None:
    with pytest.raises(InvalidCommitMessage):
        validate_commit_message(text)


def test_subject_limit_boundary() -> None:
    subject = "A" * SUBJECT_LIMIT
    assert validate_commit_message(subject).subject == subject
    with pytest.raises(InvalidCommitMessage, match="exceeds"):
        validate_commit_message("A" * (SUBJECT_LIMIT + 1))


def test_fences_headings_and_trailers_are_stripped() -> None:
    msg = validate_commit_message(
        "```\n# Add retry to the indexer\n\nRetry transient SQLite locks.\n"
        "Co-Authored-By: someone <x@example.com>\n```"
    )
    assert msg.subject == "Add retry to the indexer"
    assert "Co-Authored-By" not in msg.text


def test_long_body_line_is_rejected() -> None:
    with pytest.raises(InvalidCommitMessage, match="body line"):
        validate_commit_message("Add a guard to the parser\n\n" + "x" * 200)


# ---------------------------------------------------------------- diff summary / fallback


def test_summarize_diff_counts_paths_and_lines() -> None:
    paths, added, removed = summarize_diff(DIFF)
    assert paths == ["src/app.py"]
    assert (added, removed) == (3, 1)


def test_fallback_message_is_deterministic_and_marked() -> None:
    msg = fallback_message(DIFF)
    assert msg.subject == "Update src/app.py"
    assert msg.generated is False
    assert "+3/-1" in msg.body
    assert msg == fallback_message(DIFF)


def test_fallback_for_empty_diff() -> None:
    assert fallback_message("").subject == "Update working tree"


# ---------------------------------------------------------------- generation


def test_generated_message_records_the_model() -> None:
    adapter = ScriptedAdapter([GOOD])
    msg = generate_commit_message(adapter, DIFF, context="harden add()")
    assert msg.subject == "Reject a missing left operand in add"
    assert msg.generated is True and msg.model == "scripted-model-v0"
    sent = "\n".join(m.content for m in adapter.calls[0])
    assert "harden add()" in sent
    assert "UNTRUSTED" in sent  # SAFE-007: the diff is data, not instructions
    assert "1 file(s), +3/-1" in sent


def test_invalid_proposal_is_retried_then_accepted() -> None:
    adapter = ScriptedAdapter(["wip", GOOD])
    msg = generate_commit_message(adapter, DIFF)
    assert msg.generated is True
    assert len(adapter.calls) == 2
    # The rejection reason is fed back to the model.
    assert "rejected" in adapter.calls[1][-1].content


def test_generation_fails_when_the_model_never_complies() -> None:
    adapter = ScriptedAdapter(["wip", "wip"])
    with pytest.raises(InvalidCommitMessage, match="did not produce a valid"):
        generate_commit_message(adapter, DIFF)


def test_empty_diff_is_refused() -> None:
    with pytest.raises(InvalidCommitMessage, match="empty diff"):
        generate_commit_message(ScriptedAdapter([GOOD]), "   ")


def test_secrets_in_a_proposal_are_redacted() -> None:
    adapter = ScriptedAdapter(
        ["Rotate the deployment token\n\nkey=ghp_abcdefghijklmnopqrstuvwxyz0123\n"]
    )
    msg = generate_commit_message(adapter, DIFF)
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123" not in msg.text


def test_suggest_falls_back_when_generation_is_impossible() -> None:
    class Broken(ScriptedAdapter):
        def chat(self, messages, **kwargs):  # type: ignore[no-untyped-def]
            raise ModelError("no endpoint configured")

    msg = suggest_commit_message(Broken(), DIFF)
    assert msg.generated is False and msg.subject == "Update src/app.py"
    assert suggest_commit_message(None, DIFF).generated is False


def test_suggest_uses_the_model_when_it_works() -> None:
    assert suggest_commit_message(ScriptedAdapter([GOOD]), DIFF).generated is True


# ---------------------------------------------------------------- with git.commit (GIT-007)


def test_generated_message_is_accepted_by_git_commit(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", "-b", "work"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=tmp_path, check=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=tmp_path, check=True)
    (tmp_path / "src" / "app.py").write_text(
        'def add(a, b):\n    if a is None:\n        raise ValueError("a is required")\n    return a + b\n',
        encoding="utf-8",
    )

    ctx = make_ctx(tmp_path)
    registry = default_registry()
    diff = registry.call("git.diff", {}, ctx).output
    message: CommitMessage = suggest_commit_message(ScriptedAdapter([GOOD]), diff)
    assert message.generated is True

    result = registry.call("git.commit", {"message": message.text}, ctx)
    assert result.ok
    log = subprocess.run(
        ["git", "log", "-1", "--pretty=%s%n%b"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert log.splitlines()[0] == "Reject a missing left operand in add"
