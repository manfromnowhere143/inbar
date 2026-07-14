"""Runtime identity bound into every execution receipt."""

from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from fieldtrue.canonical import sha256_bytes, sha256_file
from fieldtrue.domain import GitObjectId, Sha256


class DirtyRepositoryError(RuntimeError):
    """A confirmatory run must not start from uncommitted code."""


class RuntimeIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    git_commit: GitObjectId
    git_tree: GitObjectId
    repository_dirty: bool
    dirty_state_hash: Sha256
    lockfile_hash: Sha256
    python_version: str
    platform: str
    command: tuple[str, ...]


def _git(repo_root: Path, *arguments: str) -> str:
    git = shutil.which("git")
    if git is None:
        raise FileNotFoundError("git is required to bind runtime identity")
    completed = subprocess.run(  # noqa: S603 - callers supply fixed internal Git commands
        [git, *arguments],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def collect_runtime_identity(
    repo_root: Path,
    *,
    command: tuple[str, ...],
    require_clean: bool = True,
) -> RuntimeIdentity:
    status = _git(repo_root, "status", "--porcelain=v1", "--untracked-files=all")
    dirty = bool(status)
    if require_clean and dirty:
        raise DirtyRepositoryError("confirmatory execution requires a clean Git worktree")
    lock_path = repo_root / "uv.lock"
    if not lock_path.is_file():
        raise FileNotFoundError("uv.lock must exist before execution")
    return RuntimeIdentity(
        git_commit=_git(repo_root, "rev-parse", "HEAD"),
        git_tree=_git(repo_root, "rev-parse", "HEAD^{tree}"),
        repository_dirty=dirty,
        dirty_state_hash=sha256_bytes(status.encode()),
        lockfile_hash=sha256_file(lock_path),
        python_version=sys.version.split()[0],
        platform=platform.platform(),
        command=command,
    )
