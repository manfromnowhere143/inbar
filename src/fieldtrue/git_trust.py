"""Fail-closed Git provenance primitives for authority-bearing repository reads."""

from __future__ import annotations

import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Final

TRUSTED_GIT_PATH: Final = Path("/usr/bin/git")
_GIT_TIMEOUT_SECONDS: Final = 10
_GIT_METADATA_ENTRY_LIMIT: Final = 1_000_000
_LOCAL_CONFIG_BYTE_LIMIT: Final = 1024 * 1024
_WORKTREE_CONFIG_BYTE_LIMIT: Final = 4096
_SAFE_PATH: Final = "/usr/bin:/bin"
_INDEX_ENTRY = re.compile(r"^H (?:100644|100755) (?:[0-9a-f]{40}|[0-9a-f]{64}) 0\t.+$")
_CURRENT_DISABLED_WORKTREE_CONFIG: Final = frozenset(
    {
        ("core.sparsecheckout", "false"),
        ("core.sparsecheckoutcone", "false"),
        ("index.sparse", "false"),
    }
)
_FORBIDDEN_CONFIG = re.compile(
    r"^(?:"
    r"core\.(?:alternaterefscommand|askpass|attributesfile|autocrlf|checkstat|editor|eol|"
    r"excludesfile|fsmonitor|gitproxy|hookspath|ignorestat|pager|safecrlf|sshcommand|"
    r"trustctime|worktree)|"
    r"credential\..*|"
    r"diff\.external|diff\..*\.(?:command|textconv)|"
    r"extensions\.worktreeconfig|"
    r"filter\..*\.(?:clean|process|required|smudge)|"
    r"gpg\.(?:program|ssh\.program)|"
    r"include\.path|includeif\..*\.path|"
    r"merge\..*\.driver|sequence\.editor"
    r"|remote\..*\.(?:partialclonefilter|promisor)|extensions\.partialclone"
    r")$",
    re.IGNORECASE,
)


class GitTrustError(ValueError):
    """Git history cannot be treated as an authority source."""


def trusted_git_executable(path: Path = TRUSTED_GIT_PATH) -> str:
    """Return a fixed system Git only when ownership and mode are trustworthy."""

    try:
        metadata = path.lstat()
    except OSError as error:
        raise GitTrustError("trusted system Git is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & stat.S_IXUSR
    ):
        raise GitTrustError("trusted system Git has unsafe ownership or mode")
    return str(path)


def git_environment() -> dict[str, str]:
    """Build an environment that cannot redirect Git repository or object state."""

    environment = {
        key: os.environ[key] for key in ("SYSTEMROOT", "TEMP", "TMP", "TMPDIR") if key in os.environ
    }
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_COUNT": "6",
            "GIT_CONFIG_KEY_0": "core.fsmonitor",
            "GIT_CONFIG_KEY_1": "core.hooksPath",
            "GIT_CONFIG_KEY_2": "core.trustctime",
            "GIT_CONFIG_KEY_3": "core.checkStat",
            "GIT_CONFIG_KEY_4": "core.ignoreStat",
            "GIT_CONFIG_KEY_5": "core.fileMode",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_VALUE_0": "false",
            "GIT_CONFIG_VALUE_1": os.devnull,
            "GIT_CONFIG_VALUE_2": "true",
            "GIT_CONFIG_VALUE_3": "default",
            "GIT_CONFIG_VALUE_4": "false",
            "GIT_CONFIG_VALUE_5": "true",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_PAGER": "cat",
            "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": "/nonexistent",
            "LC_ALL": "C",
            "PATH": _SAFE_PATH,
        }
    )
    return environment


def _git_output(git: str, repo_root: Path, *arguments: str) -> str:
    try:
        return subprocess.run(  # noqa: S603 - caller supplies a verified fixed Git path
            [git, *arguments],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=git_environment(),
            timeout=_GIT_TIMEOUT_SECONDS,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise GitTrustError("Git repository trust state cannot be verified") from error


def _resolved_git_path(repo_root: Path, raw_path: str, label: str) -> Path:
    if not raw_path:
        raise GitTrustError(f"Git returned an empty {label} path")
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    try:
        return candidate.resolve(strict=True)
    except OSError as error:
        raise GitTrustError(f"Git {label} path cannot be resolved") from error


def _reject_legacy_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise GitTrustError(f"Git {label} state cannot be verified") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size != 0
    ):
        raise GitTrustError(f"Git {label} state is forbidden")


def _stable_stat_fields(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_stable_git_file(
    git_dir: Path,
    expected_directory: os.stat_result,
    *,
    name: str,
    byte_limit: int,
    label: str,
) -> bytes | None:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise GitTrustError(f"Git {label} state cannot be verified")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        directory_descriptor = os.open(git_dir, directory_flags)
    except OSError as error:
        raise GitTrustError(f"Git {label} state cannot be verified") from error
    try:
        directory_before = os.fstat(directory_descriptor)
        if (
            _stable_stat_fields(directory_before) != _stable_stat_fields(expected_directory)
            or not stat.S_ISDIR(directory_before.st_mode)
            or directory_before.st_uid not in {0, os.geteuid()}
            or directory_before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise GitTrustError(f"Git {label} directory changed before inspection")
        try:
            descriptor = os.open(name, file_flags, dir_fd=directory_descriptor)
        except FileNotFoundError:
            try:
                os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise GitTrustError(f"Git {label} changed while being read") from None
            directory_after = os.fstat(directory_descriptor)
            current_directory = os.stat(git_dir, follow_symlinks=False)
            if _stable_stat_fields(directory_before) != _stable_stat_fields(
                directory_after
            ) or _stable_stat_fields(directory_after) != _stable_stat_fields(current_directory):
                raise GitTrustError(f"Git {label} directory changed while being read") from None
            return None
        except OSError as error:
            raise GitTrustError(f"Git {label} state cannot be verified") from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid not in {0, os.geteuid()}
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or before.st_size > byte_limit
            ):
                raise GitTrustError(f"Git {label} state is forbidden")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(byte_limit + 1)
            after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        finally:
            os.close(descriptor)
        directory_after = os.fstat(directory_descriptor)
        current_directory = os.stat(git_dir, follow_symlinks=False)
    except GitTrustError:
        raise
    except OSError as error:
        raise GitTrustError(f"Git {label} state cannot be verified") from error
    finally:
        os.close(directory_descriptor)
    if _stable_stat_fields(before) != _stable_stat_fields(after) or _stable_stat_fields(
        after
    ) != _stable_stat_fields(current):
        raise GitTrustError(f"Git {label} changed while being read")
    if _stable_stat_fields(directory_before) != _stable_stat_fields(
        directory_after
    ) or _stable_stat_fields(directory_after) != _stable_stat_fields(current_directory):
        raise GitTrustError(f"Git {label} directory changed while being read")
    if len(data) != before.st_size or len(data) > byte_limit:
        raise GitTrustError(f"Git {label} changed while being read")
    return data


def _read_stable_worktree_config(
    git_dir: Path,
    expected_directory: os.stat_result,
) -> bytes | None:
    return _read_stable_git_file(
        git_dir,
        expected_directory,
        name="config.worktree",
        byte_limit=_WORKTREE_CONFIG_BYTE_LIMIT,
        label="worktree-config",
    )


def _config_records(
    git: str,
    data: bytes,
    *,
    label: str,
) -> tuple[tuple[str, bytes], ...]:
    try:
        result = subprocess.run(  # noqa: S603 - caller supplies a verified fixed Git path
            [git, "config", "--file", "-", "--no-includes", "--null", "--list"],
            check=True,
            capture_output=True,
            env=git_environment(),
            input=data,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except OSError as error:
        raise GitTrustError("Git repository trust state cannot be verified") from error
    except subprocess.SubprocessError as error:
        raise GitTrustError(f"Git {label} state is forbidden") from error
    if result.stdout == b"":
        return ()
    if not result.stdout.endswith(b"\0"):
        raise GitTrustError(f"Git {label} state is forbidden")
    records: list[tuple[str, bytes]] = []
    for record in result.stdout[:-1].split(b"\0"):
        raw_key, separator, raw_value = record.partition(b"\n")
        if separator != b"\n":
            raise GitTrustError(f"Git {label} state is forbidden")
        try:
            key = raw_key.decode("ascii").casefold()
        except UnicodeDecodeError as error:
            raise GitTrustError(f"Git {label} state is forbidden") from error
        if not key:
            raise GitTrustError(f"Git {label} state is forbidden")
        records.append((key, raw_value))
    return tuple(records)


def _worktree_config_entries(git: str, data: bytes) -> frozenset[tuple[str, str]]:
    records = _config_records(git, data, label="worktree-config")
    entries: dict[str, str] = {}
    for key, raw_value in records:
        try:
            value = raw_value.decode("ascii").casefold()
        except UnicodeDecodeError as error:
            raise GitTrustError("Git worktree-config state is forbidden") from error
        if key in entries:
            raise GitTrustError("Git worktree-config state is forbidden")
        entries[key] = value
    return frozenset(entries.items())


def _verify_disabled_worktree_config(
    git_dir: Path,
    expected_directory: os.stat_result,
    git: str,
) -> None:
    data = _read_stable_worktree_config(git_dir, expected_directory)
    if data is None or data == b"":
        return
    if _worktree_config_entries(git, data) != _CURRENT_DISABLED_WORKTREE_CONFIG:
        raise GitTrustError("Git worktree-config state is forbidden")


def _local_config_keys(
    git_dir: Path,
    expected_directory: os.stat_result,
    git: str,
) -> tuple[str, ...]:
    data = _read_stable_git_file(
        git_dir,
        expected_directory,
        name="config",
        byte_limit=_LOCAL_CONFIG_BYTE_LIMIT,
        label="local-config",
    )
    if data is None:
        raise GitTrustError("Git local-config state is unavailable")
    return tuple(key for key, _value in _config_records(git, data, label="local-config"))


def _git_metadata_entry_is_directory(metadata: os.stat_result) -> bool:
    is_directory = stat.S_ISDIR(metadata.st_mode)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or (not is_directory and not stat.S_ISREG(metadata.st_mode))
        or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1)
    ):
        raise GitTrustError("Git metadata is redirected or nonregular")
    if metadata.st_uid not in {0, os.geteuid()} or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise GitTrustError("Git metadata has unsafe ownership or mode")
    return is_directory


def _verify_git_metadata_tree(git_dir: Path) -> None:
    directories = [git_dir]
    discovered = 0
    while directories:
        current = directories.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    discovered += 1
                    if discovered > _GIT_METADATA_ENTRY_LIMIT:
                        raise GitTrustError("Git metadata exceeds the trust scan limit")
                    metadata = entry.stat(follow_symlinks=False)
                    is_directory = _git_metadata_entry_is_directory(metadata)
                    if entry.name.endswith(".promisor"):
                        raise GitTrustError("Git promisor object state is forbidden")
                    if is_directory:
                        directories.append(Path(entry.path))
        except GitTrustError:
            raise
        except OSError as error:
            raise GitTrustError("Git metadata tree cannot be verified") from error


def _verify_info_exclude(git_dir: Path) -> None:
    path = git_dir / "info" / "exclude"
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return
    except OSError as error:
        raise GitTrustError("Git local exclude state cannot be verified") from error
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise GitTrustError("Git local exclude state is not UTF-8") from error
    if len(data) > 64 * 1024 or any(line.strip() and not line.startswith("#") for line in lines):
        raise GitTrustError("Git local exclude patterns are forbidden")


def verify_repository_trust(repo_root: Path, git: str) -> None:
    """Reject executable config and every supported Git history redirection surface."""

    try:
        root = repo_root.resolve(strict=True)
    except OSError as error:
        raise GitTrustError("repository root cannot be resolved") from error
    expected_git_dir = root / ".git"
    try:
        expected_metadata = expected_git_dir.lstat()
    except OSError as error:
        raise GitTrustError("repository .git directory is unavailable") from error
    if (
        stat.S_ISLNK(expected_metadata.st_mode)
        or not stat.S_ISDIR(expected_metadata.st_mode)
        or expected_metadata.st_uid not in {0, os.geteuid()}
        or expected_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise GitTrustError("Git repository or object directory is redirected")
    _verify_git_metadata_tree(expected_git_dir)
    _verify_info_exclude(expected_git_dir)
    _reject_legacy_file(expected_git_dir / "info" / "attributes", "local-attribute")
    local_config = _local_config_keys(expected_git_dir, expected_metadata, git)
    forbidden_keys = sorted(key for key in local_config if _FORBIDDEN_CONFIG.fullmatch(key))
    if forbidden_keys:
        raise GitTrustError(
            "execution-capable or authority-weakening local Git config is forbidden: "
            + ", ".join(forbidden_keys)
        )
    _verify_disabled_worktree_config(expected_git_dir, expected_metadata, git)
    discovered_root = _resolved_git_path(
        root,
        _git_output(git, root, "rev-parse", "--show-toplevel"),
        "worktree",
    )
    git_dir = _resolved_git_path(
        root,
        _git_output(git, root, "rev-parse", "--absolute-git-dir"),
        "directory",
    )
    common_dir = _resolved_git_path(
        root,
        _git_output(git, root, "rev-parse", "--git-common-dir"),
        "common directory",
    )
    if discovered_root != root or git_dir != expected_git_dir or common_dir != expected_git_dir:
        raise GitTrustError("Git repository or object directory is redirected")
    objects_path = Path(_git_output(git, root, "rev-parse", "--git-path", "objects"))
    if not objects_path.is_absolute():
        objects_path = root / objects_path
    try:
        objects_metadata = objects_path.lstat()
        objects_resolved = objects_path.resolve(strict=True)
    except OSError as error:
        raise GitTrustError("Git object directory cannot be verified") from error
    if (
        objects_path != expected_git_dir / "objects"
        or objects_resolved != expected_git_dir / "objects"
        or stat.S_ISLNK(objects_metadata.st_mode)
        or not stat.S_ISDIR(objects_metadata.st_mode)
    ):
        raise GitTrustError("Git object directory is redirected")
    if _git_output(git, root, "rev-parse", "--is-shallow-repository") != "false":
        raise GitTrustError("shallow Git history cannot certify authority")
    if _git_output(git, root, "replace", "--list"):
        raise GitTrustError("Git replacement objects are forbidden")
    tree_state = _git_output(git, root, "ls-tree", "-r", "HEAD")
    if any(line.startswith(("120000 ", "160000 ")) for line in tree_state.splitlines()):
        raise GitTrustError("Git symlinks and submodules are forbidden in an authority repository")
    tracked_paths = (line.partition("\t")[2] for line in tree_state.splitlines())
    if any(
        path.casefold() == ".gitattributes" or path.casefold().endswith("/.gitattributes")
        for path in tracked_paths
    ):
        raise GitTrustError("tracked Git attribute files are forbidden in an authority repository")
    attribute_pathspec = ":(icase,glob)**/.gitattributes"
    visible_attributes = _git_output(
        git,
        root,
        "ls-files",
        "--others",
        "--exclude-standard",
        "--",
        attribute_pathspec,
    )
    ignored_attributes = _git_output(
        git,
        root,
        "ls-files",
        "--others",
        "--ignored",
        "--exclude-standard",
        "--",
        attribute_pathspec,
    )
    if visible_attributes or ignored_attributes:
        raise GitTrustError("worktree Git attribute files are forbidden")
    index_state = _git_output(git, root, "ls-files", "--stage", "-v")
    if any(_INDEX_ENTRY.fullmatch(line) is None for line in index_state.splitlines()):
        raise GitTrustError("Git index flags, stages, symlinks, or submodules are forbidden")
    if _git_output(git, root, "diff-index", "--cached", "--name-only", "HEAD", "--"):
        raise GitTrustError("Git index differs from HEAD")

    for arguments, label in (
        (("rev-parse", "--git-path", "info/grafts"), "graft"),
        (("rev-parse", "--git-path", "objects/info/alternates"), "alternate-object"),
    ):
        path = Path(_git_output(git, root, *arguments))
        if not path.is_absolute():
            path = root / path
        _reject_legacy_file(path, label)


def trusted_repository_git(repo_root: Path, path: Path = TRUSTED_GIT_PATH) -> str:
    """Return trusted Git after validating the exact repository trust boundary."""

    git = trusted_git_executable(path)
    verify_repository_trust(repo_root, git)
    return git
