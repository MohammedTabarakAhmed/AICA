import subprocess
from pathlib import Path

import pytest

from aica.policy import GitPolicy
from aica.workspace import (
    GitGuard,
    PathNotAuthorized,
    ProtectedBranch,
    UserChangesPresent,
    WorkspaceGuard,
)

# ---------------------------------------------------------------- paths (FS-001..005)


def test_paths_inside_workspace_resolve(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x = 1\n")
    g = WorkspaceGuard(tmp_path)
    r = g.resolve("src/a.py")
    assert r.relative == Path("src/a.py") and not r.sensitive
    assert g.is_authorized(tmp_path / "src")


def test_escape_attempts_rejected(tmp_path: Path) -> None:
    g = WorkspaceGuard(tmp_path)
    with pytest.raises(PathNotAuthorized):
        g.resolve("../outside.txt")
    with pytest.raises(PathNotAuthorized):
        g.resolve(tmp_path.parent / "elsewhere")
    assert not g.is_authorized("a/../../b")


def test_allowed_subdirectories_restrict_further(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "infra").mkdir()
    g = WorkspaceGuard(tmp_path, ["app"])
    assert g.is_authorized("app/x.py")
    assert not g.is_authorized("infra/x.tf")
    with pytest.raises(PathNotAuthorized):
        WorkspaceGuard(tmp_path, [".."])


@pytest.mark.parametrize(
    ("rel", "sensitive"),
    [
        (".env", True),
        (".env.local", True),
        ("config/secrets.yaml", True),
        ("certs/server.pem", True),
        (".ssh/config", True),
        (".git/config", True),
        ("src/env.py", False),
        ("README.md", False),
        ("docs/secret_santa_notes.md", False),
    ],
)
def test_sensitive_detection(rel: str, sensitive: bool) -> None:
    assert WorkspaceGuard.is_sensitive(Path(rel)) is sensitive


# ---------------------------------------------------------------- git (GIT-010, GIT-003)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "a.txt").write_text("one\n")
    (tmp_path / "b.txt").write_text("two\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def test_clean_repo_allows_modification(repo: Path) -> None:
    g = GitGuard(repo)
    assert g.is_repository()
    assert g.status().is_clean
    g.assert_safe_to_modify(["a.txt"])  # no raise


def test_uncommitted_change_blocks_modification(repo: Path) -> None:
    (repo / "a.txt").write_text("edited by developer\n")
    g = GitGuard(repo)
    st = g.status()
    assert "a.txt" in st.modified and not st.is_clean
    with pytest.raises(UserChangesPresent) as exc:
        g.assert_safe_to_modify(["a.txt", "b.txt"])
    assert exc.value.paths == ["a.txt"]
    g.assert_safe_to_modify(["b.txt"])  # untouched file is fine
    g.assert_safe_to_modify(["a.txt"], allow_dirty=True)  # explicit authorization


def test_untracked_and_staged_are_detected(repo: Path) -> None:
    (repo / "new.txt").write_text("n\n")
    (repo / "b.txt").write_text("staged\n")
    _git(repo, "add", "b.txt")
    st = GitGuard(repo).status()
    assert "new.txt" in st.untracked and "b.txt" in st.staged


def test_directory_target_matches_children(repo: Path) -> None:
    (repo / "pkg").mkdir()
    (repo / "pkg" / "m.py").write_text("x\n")
    assert GitGuard(repo).conflicting_user_changes(["pkg"]) == ["pkg/m.py"]


def test_protected_branch_detection(repo: Path) -> None:
    g = GitGuard(repo, GitPolicy())
    assert g.current_branch() == "main"
    with pytest.raises(ProtectedBranch):
        g.assert_not_protected_branch()
    _git(repo, "checkout", "-q", "-b", "feature/x")
    GitGuard(repo).assert_not_protected_branch()


def test_non_repo_is_not_protected(tmp_path: Path) -> None:
    g = GitGuard(tmp_path)
    assert not g.is_repository()
    g.assert_safe_to_modify(["anything"])  # nothing to compare against
