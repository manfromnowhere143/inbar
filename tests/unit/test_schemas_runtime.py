from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from fieldtrue.runtime import DirtyRepositoryError, collect_runtime_identity
from fieldtrue.schemas import export_schemas, schema_documents, verify_schemas

_GIT = shutil.which("git")
if _GIT is None:
    raise RuntimeError("git executable is required for runtime tests")


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(  # noqa: S603 - executable is resolved once from the test environment
        [_GIT, *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _clean_git_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / "uv.lock").write_text("lock-version = 1\n")
    (repo / "tracked.txt").write_text("frozen\n")
    _git(repo, "add", ".")
    _git(
        repo,
        "-c",
        "user.name=Proof Test",
        "-c",
        "user.email=proof@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    return repo


def test_schema_export_detects_stale_missing_and_unexpected_files(tmp_path: Path) -> None:
    documents = schema_documents()
    assert "approval_receipt.schema.json" in documents
    paths = export_schemas(tmp_path)
    assert len(paths) == len(documents)
    assert verify_schemas(tmp_path) == []

    paths[0].write_text("{}\n")
    (paths[0].parent / "unexpected.json").write_text("{}\n")
    errors = verify_schemas(tmp_path)
    assert any("stale schema" in error for error in errors)
    assert any("unexpected schema" in error for error in errors)
    paths[1].unlink()
    assert any("missing schema" in error for error in verify_schemas(tmp_path))


def test_runtime_identity_binds_clean_git_tree_lock_and_command(tmp_path: Path) -> None:
    repo = _clean_git_repo(tmp_path)
    identity = collect_runtime_identity(
        repo,
        command=("mission", "run"),
    )
    assert len(identity.git_commit) == 40
    assert len(identity.git_tree) == 40
    assert not identity.repository_dirty
    assert identity.command == ("mission", "run")

    (repo / "tracked.txt").write_text("changed\n")
    with pytest.raises(DirtyRepositoryError, match="clean Git"):
        collect_runtime_identity(repo, command=("mission", "run"))
    dirty = collect_runtime_identity(
        repo,
        command=("mission", "run"),
        require_clean=False,
    )
    assert dirty.repository_dirty


def test_runtime_requires_lockfile(tmp_path: Path) -> None:
    repo = _clean_git_repo(tmp_path)
    (repo / "uv.lock").unlink()
    with pytest.raises(FileNotFoundError, match=r"uv\.lock"):
        collect_runtime_identity(repo, command=("run",), require_clean=False)
