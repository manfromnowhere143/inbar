from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import fieldtrue.git_trust as git_trust_module
from fieldtrue.git_trust import (
    GitTrustError,
    git_environment,
    trusted_git_executable,
    verify_repository_trust,
)


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603 - tests use a fixed trusted Git path
        ["/usr/bin/git", *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        env=git_environment(),
        text=True,
    ).stdout.strip()


def _repository(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Inbar Test")
    _git(repo, "config", "user.email", "inbar@example.invalid")
    (repo / "evidence.txt").write_text("first\n", encoding="utf-8")
    _git(repo, "add", "evidence.txt")
    _git(repo, "commit", "--quiet", "-m", "first")
    return repo


def test_git_trust_ignores_path_and_inherited_git_redirection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repository(tmp_path)
    fake_git = tmp_path / "git"
    fake_git.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("GIT_DIR", "/does/not/exist")
    monkeypatch.setenv("GIT_WORK_TREE", "/does/not/exist")
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", "/does/not/exist")
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/does/not/exist")

    git = trusted_git_executable()
    verify_repository_trust(repo, git)

    assert git == "/usr/bin/git"
    assert {key for key in git_environment() if key.startswith("GIT_")} == {
        "GIT_ATTR_NOSYSTEM",
        "GIT_ALLOW_PROTOCOL",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_KEY_1",
        "GIT_CONFIG_KEY_2",
        "GIT_CONFIG_KEY_3",
        "GIT_CONFIG_KEY_4",
        "GIT_CONFIG_KEY_5",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_VALUE_1",
        "GIT_CONFIG_VALUE_2",
        "GIT_CONFIG_VALUE_3",
        "GIT_CONFIG_VALUE_4",
        "GIT_CONFIG_VALUE_5",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_PAGER",
        "GIT_PROTOCOL_FROM_USER",
        "GIT_TERMINAL_PROMPT",
    }
    assert {
        key: git_environment()[key]
        for key in (
            "GIT_CONFIG_KEY_2",
            "GIT_CONFIG_KEY_3",
            "GIT_CONFIG_KEY_4",
            "GIT_CONFIG_KEY_5",
            "GIT_CONFIG_VALUE_2",
            "GIT_CONFIG_VALUE_3",
            "GIT_CONFIG_VALUE_4",
            "GIT_CONFIG_VALUE_5",
        )
    } == {
        "GIT_CONFIG_KEY_2": "core.trustctime",
        "GIT_CONFIG_KEY_3": "core.checkStat",
        "GIT_CONFIG_KEY_4": "core.ignoreStat",
        "GIT_CONFIG_KEY_5": "core.fileMode",
        "GIT_CONFIG_VALUE_2": "true",
        "GIT_CONFIG_VALUE_3": "default",
        "GIT_CONFIG_VALUE_4": "false",
        "GIT_CONFIG_VALUE_5": "true",
    }


def test_git_trust_rejects_unsafe_executable(tmp_path: Path) -> None:
    executable = tmp_path / "git"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o777)

    with pytest.raises(GitTrustError, match="unsafe ownership or mode"):
        trusted_git_executable(executable)

    with pytest.raises(GitTrustError, match="unavailable"):
        trusted_git_executable(tmp_path / "missing")


def test_git_trust_rejects_unresolvable_repository_state(tmp_path: Path) -> None:
    with pytest.raises(GitTrustError, match="repository root cannot be resolved"):
        verify_repository_trust(tmp_path / "missing", trusted_git_executable())

    repo = _repository(tmp_path)
    with pytest.raises(GitTrustError, match="trust state cannot be verified"):
        verify_repository_trust(repo, str(tmp_path / "missing-git"))

    with pytest.raises(GitTrustError, match="empty fixture path"):
        git_trust_module._resolved_git_path(repo, "", "fixture")
    with pytest.raises(GitTrustError, match="fixture path cannot be resolved"):
        git_trust_module._resolved_git_path(repo, "missing", "fixture")


def test_git_trust_rejects_linked_worktrees(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    worktree = tmp_path / "linked-worktree"
    _git(repo, "worktree", "add", "--quiet", "--detach", str(worktree))

    with pytest.raises(GitTrustError, match="directory is redirected"):
        verify_repository_trust(worktree, trusted_git_executable())


def test_git_trust_rejects_shallow_history(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    (repo / "evidence.txt").write_text("second\n", encoding="utf-8")
    _git(repo, "add", "evidence.txt")
    _git(repo, "commit", "--quiet", "-m", "second")
    clone = tmp_path / "shallow"
    subprocess.run(  # noqa: S603 - fixed trusted Git path and test-controlled arguments
        ["/usr/bin/git", "clone", "--quiet", "--depth", "1", f"file://{repo}", str(clone)],
        check=True,
        env={**git_environment(), "GIT_ALLOW_PROTOCOL": "file"},
    )

    with pytest.raises(GitTrustError, match="shallow Git history"):
        verify_repository_trust(clone, trusted_git_executable())


def test_git_trust_rejects_a_redirected_object_directory(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    objects = repo / ".git" / "objects"
    redirected = tmp_path / "redirected-objects"
    objects.replace(redirected)
    objects.symlink_to(redirected, target_is_directory=True)

    with pytest.raises(GitTrustError, match="metadata is redirected"):
        verify_repository_trust(repo, trusted_git_executable())


@pytest.mark.parametrize("relative", ["objects/pack", "refs", "index"])
def test_git_trust_rejects_redirected_metadata_descendants(
    relative: str,
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    source = repo / ".git" / relative
    redirected = tmp_path / f"redirected-{source.name}"
    source.replace(redirected)
    source.symlink_to(redirected, target_is_directory=redirected.is_dir())

    with pytest.raises(GitTrustError, match="metadata is redirected"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_hard_linked_metadata(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    external = tmp_path / "linked-config"
    external.hardlink_to(repo / ".git" / "config")

    with pytest.raises(GitTrustError, match="metadata is redirected"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_unsafe_metadata_permissions(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    (repo / ".git" / "refs" / "heads" / _git(repo, "branch", "--show-current")).chmod(0o666)

    with pytest.raises(GitTrustError, match="unsafe ownership or mode"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_execution_capable_local_config(
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    marker = tmp_path / "fsmonitor-executed"
    monitor = tmp_path / "fsmonitor.sh"
    monitor.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n", encoding="utf-8")
    monitor.chmod(0o755)
    _git(repo, "config", "core.fsmonitor", str(monitor))

    with pytest.raises(GitTrustError, match="execution-capable or authority-weakening"):
        verify_repository_trust(repo, trusted_git_executable())

    subprocess.run(  # noqa: S603 - fixed trusted Git path
        [trusted_git_executable(), "status", "--short"],
        cwd=repo,
        check=True,
        capture_output=True,
        env=git_environment(),
    )
    assert not marker.exists()


def test_git_trust_rejects_execution_capable_worktree_config(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    marker = tmp_path / "filter-executed"
    script = tmp_path / "filter.sh"
    script.write_text(f"#!/bin/sh\ntouch '{marker}'\ncat\n", encoding="utf-8")
    script.chmod(0o755)
    _git(repo, "config", "extensions.worktreeConfig", "true")
    _git(repo, "config", "--worktree", "filter.evil.clean", str(script))

    with pytest.raises(GitTrustError, match="execution-capable or authority-weakening"):
        verify_repository_trust(repo, trusted_git_executable())
    assert not marker.exists()


def test_git_trust_accepts_actions_checkout_disabled_sparse_config(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    _git(repo, "sparse-checkout", "disable")
    _git(repo, "config", "--local", "--unset-all", "extensions.worktreeConfig")

    verify_repository_trust(repo, trusted_git_executable())

    assert (repo / ".git" / "config.worktree").read_text(encoding="ascii") == (
        "[core]\n"
        "\tsparseCheckout = false\n"
        "\tsparseCheckoutCone = false\n"
        "[index]\n"
        "\tsparse = false\n"
    )


@pytest.mark.parametrize(
    "content",
    [
        (
            b"[core]\r\n\tsparseCheckout = false\r\n\tsparseCheckoutCone = false\r\n"
            b"[index]\r\n\tsparse = false\r\n"
        ),
    ],
)
def test_git_trust_accepts_known_disabled_worktree_config_variants(
    content: bytes,
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    (repo / ".git" / "config.worktree").write_bytes(content)

    verify_repository_trust(repo, trusted_git_executable())


@pytest.mark.parametrize("extension_value", ["false", "true"])
def test_git_trust_rejects_disabled_worktree_config_when_extension_is_present(
    extension_value: str,
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    _git(repo, "sparse-checkout", "disable")
    _git(repo, "config", "--local", "extensions.worktreeConfig", extension_value)

    with pytest.raises(GitTrustError, match="authority-weakening local Git config"):
        verify_repository_trust(repo, trusted_git_executable())


@pytest.mark.parametrize(
    "content",
    [
        b"[index]\n\tsparse = false\n",
        b"[core]\n\tsparseCheckout = false\n",
        (
            b"[core]\n\tsparseCheckout = true\n\tsparseCheckoutCone = false\n"
            b"[index]\n\tsparse = false\n"
        ),
        (
            b"[core]\n\tsparseCheckout = false\n\tsparseCheckoutCone = false\n"
            b"\thooksPath = /tmp/evil\n[index]\n\tsparse = false\n"
        ),
        b"[include]\n\tpath = /tmp/evil\n",
        b'[includeIf "gitdir:/tmp/**"]\n\tpath = /tmp/evil\n',
        (
            b"[core]\n\tsparseCheckout = false\n\tsparseCheckout = false\n"
            b"\tsparseCheckoutCone = false\n[index]\n\tsparse = false\n"
        ),
        b"\xff",
        b"x" * 4097,
    ],
)
def test_git_trust_rejects_noncanonical_disabled_worktree_config(
    content: bytes,
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    (repo / ".git" / "config.worktree").write_bytes(content)

    with pytest.raises(GitTrustError, match="worktree-config state is forbidden"):
        verify_repository_trust(repo, trusted_git_executable())


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "fifo", "permissions"])
def test_git_trust_rejects_unsafe_disabled_worktree_config_file(
    fault: str,
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    worktree_config = repo / ".git" / "config.worktree"
    external = tmp_path / "external-config"
    external.write_text("[index]\n\tsparse = false\n", encoding="ascii")
    if fault == "symlink":
        worktree_config.symlink_to(external)
    elif fault == "hardlink":
        worktree_config.hardlink_to(external)
    elif fault == "fifo":
        os.mkfifo(worktree_config)
    else:
        worktree_config.write_text("[index]\n\tsparse = false\n", encoding="ascii")
        worktree_config.chmod(0o666)

    with pytest.raises(GitTrustError, match=r"metadata is redirected|unsafe ownership or mode"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_worktree_config_substitution_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repository(tmp_path)
    _git(repo, "sparse-checkout", "disable")
    _git(repo, "config", "--local", "--unset-all", "extensions.worktreeConfig")
    git_dir = repo / ".git"
    worktree_config = git_dir / "config.worktree"
    expected_directory = git_dir.lstat()
    original_stat = git_trust_module.os.stat
    substituted = False

    def substitute(path: object, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal substituted
        if path == "config.worktree" and kwargs.get("dir_fd") is not None and not substituted:
            substituted = True
            with worktree_config.open("ab") as handle:
                handle.write(b"\n")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(git_trust_module.os, "stat", substitute)

    with pytest.raises(GitTrustError, match="changed while being read"):
        git_trust_module._read_stable_worktree_config(git_dir, expected_directory)


def test_git_trust_rejects_worktree_config_creation_during_absence_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repository(tmp_path)
    git_dir = repo / ".git"
    worktree_config = git_dir / "config.worktree"
    expected_directory = git_dir.lstat()
    original_stat = git_trust_module.os.stat
    created = False

    def create(path: object, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal created
        if path == "config.worktree" and kwargs.get("dir_fd") is not None and not created:
            created = True
            worktree_config.write_text("[index]\n\tsparse = false\n", encoding="ascii")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(git_trust_module.os, "stat", create)

    with pytest.raises(GitTrustError, match="changed while being read"):
        git_trust_module._read_stable_worktree_config(git_dir, expected_directory)


def test_git_trust_rejects_git_directory_substitution_during_config_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repository(tmp_path)
    _git(repo, "sparse-checkout", "disable")
    _git(repo, "config", "--local", "--unset-all", "extensions.worktreeConfig")
    git_dir = repo / ".git"
    displaced = tmp_path / "displaced-git"
    expected_directory = git_dir.lstat()
    original_stat = git_trust_module.os.stat
    substituted = False

    def substitute(path: object, *args: object, **kwargs: object) -> os.stat_result:
        nonlocal substituted
        if Path(path) == git_dir and not substituted:
            substituted = True
            git_dir.rename(displaced)
            git_dir.symlink_to(displaced, target_is_directory=True)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(git_trust_module.os, "stat", substitute)

    with pytest.raises(GitTrustError, match="directory changed while being read"):
        git_trust_module._read_stable_worktree_config(git_dir, expected_directory)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("core.worktree", "../../escape"),
        ("includeIf.gitdir:../**.path", "../evil-config"),
    ],
)
def test_git_trust_rejects_repository_redirection_before_repo_aware_commands(
    key: str,
    value: str,
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    _git(repo, "config", "--local", key, value)

    with pytest.raises(GitTrustError, match="authority-weakening local Git config"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_partial_clone_configuration(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    _git(repo, "config", "remote.origin.promisor", "true")
    _git(repo, "config", "remote.origin.partialCloneFilter", "blob:none")

    with pytest.raises(GitTrustError, match="execution-capable or authority-weakening"):
        verify_repository_trust(repo, trusted_git_executable())


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("core.trustctime", "false"),
        ("core.checkStat", "minimal"),
        ("core.ignoreStat", "true"),
        ("core.autocrlf", "true"),
        ("core.eol", "crlf"),
        ("core.safecrlf", "false"),
    ],
)
def test_git_trust_rejects_authority_weakening_local_config(
    key: str,
    value: str,
    tmp_path: Path,
) -> None:
    repo = _repository(tmp_path)
    _git(repo, "config", "--local", key, value)

    with pytest.raises(GitTrustError, match="authority-weakening local Git config"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_local_exclude_patterns(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    exclude = repo / ".git" / "info" / "exclude"
    exclude.write_text("# comments remain allowed\nconftest.py\n", encoding="utf-8")

    with pytest.raises(GitTrustError, match="local exclude patterns"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_indented_local_exclude_comment(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    exclude = repo / ".git" / "info" / "exclude"
    exclude.write_text(" #hidden.py\n", encoding="utf-8")

    with pytest.raises(GitTrustError, match="local exclude patterns"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_local_attributes(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    attributes = repo / ".git" / "info" / "attributes"
    attributes.write_text("*.txt -text\n", encoding="utf-8")

    with pytest.raises(GitTrustError, match="local-attribute state is forbidden"):
        verify_repository_trust(repo, trusted_git_executable())


@pytest.mark.parametrize(
    "relative",
    [".gitattributes", ".GITATTRIBUTES", "nested/.gitattributes"],
)
def test_git_trust_rejects_tracked_attributes(relative: str, tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    attributes = repo / relative
    attributes.parent.mkdir(parents=True, exist_ok=True)
    attributes.write_text("*.txt -text\n", encoding="utf-8")
    _git(repo, "add", relative)
    _git(repo, "commit", "--quiet", "-m", "add attributes")

    with pytest.raises(GitTrustError, match="tracked Git attribute files"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_ignored_worktree_attributes(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    (repo / ".gitignore").write_text(".gitattributes\n", encoding="utf-8")
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "--quiet", "-m", "ignore attributes")
    (repo / ".gitattributes").write_text("*.txt text\n", encoding="utf-8")

    with pytest.raises(GitTrustError, match="worktree Git attribute files"):
        verify_repository_trust(repo, trusted_git_executable())


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_git_trust_rejects_hidden_index_flags(flag: str, tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    _git(repo, "update-index", flag, "evidence.txt")

    with pytest.raises(GitTrustError, match="Git index flags"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_intent_to_add_index_entry(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    (repo / "candidate.txt").write_text("candidate\n", encoding="utf-8")
    _git(repo, "add", "--intent-to-add", "candidate.txt")

    with pytest.raises(GitTrustError, match="Git index differs from HEAD"):
        verify_repository_trust(repo, trusted_git_executable())


def test_git_trust_rejects_gitlinks(tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    head = _git(repo, "rev-parse", "HEAD")
    _git(repo, "update-index", "--add", "--cacheinfo", f"160000,{head},child")

    with pytest.raises(GitTrustError, match="symlinks, or submodules are forbidden"):
        verify_repository_trust(repo, trusted_git_executable())


@pytest.mark.parametrize("state", ["replacement", "graft", "alternate"])
def test_git_trust_rejects_history_redirection(state: str, tmp_path: Path) -> None:
    repo = _repository(tmp_path)
    first = _git(repo, "rev-parse", "HEAD")
    (repo / "evidence.txt").write_text("second\n", encoding="utf-8")
    _git(repo, "add", "evidence.txt")
    _git(repo, "commit", "--quiet", "-m", "second")
    second = _git(repo, "rev-parse", "HEAD")
    if state == "replacement":
        _git(repo, "replace", first, second)
    elif state == "graft":
        graft = repo / ".git" / "info" / "grafts"
        graft.parent.mkdir(parents=True, exist_ok=True)
        graft.write_text(f"{second} {first}\n", encoding="utf-8")
    else:
        alternates = repo / ".git" / "objects" / "info" / "alternates"
        alternates.parent.mkdir(parents=True, exist_ok=True)
        alternates.write_text(f"{tmp_path / 'external-objects'}\n", encoding="utf-8")

    with pytest.raises(GitTrustError, match="forbidden"):
        verify_repository_trust(repo, trusted_git_executable())
