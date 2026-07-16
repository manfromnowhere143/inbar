"""Hash-authenticated, snapshot-local Python runners for research control execution."""

from __future__ import annotations

import io
import json
import os
import platform
import re
import secrets
import shutil
import ssl
import stat
import subprocess
import tomllib
import urllib.request
import zipfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

import certifi
from packaging.markers import InvalidMarker, Marker, UndefinedEnvironmentName, default_environment
from packaging.tags import Tag, compatible_tags, cpython_tags, platform_tags
from packaging.utils import InvalidWheelFilename, canonicalize_name, parse_wheel_filename

from fieldtrue.canonical import sha256_bytes, sha256_value

MAX_RUNNER_FILE_BYTES = 128 * 1024 * 1024
MAX_RUNNER_TREE_BYTES = 1024 * 1024 * 1024
MAX_RUNNER_TREE_ENTRIES = 25_000
MAX_AUTHENTICATED_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_LOCK_PACKAGE_ENTRIES = 256
MAX_LOCKED_DISTRIBUTIONS = 128
MAX_WHEEL_BYTES = 32 * 1024 * 1024
MAX_AUTHENTICATED_WHEEL_SET_BYTES = 128 * 1024 * 1024
MAX_WHEEL_ENTRIES = 10_000
MAX_WHEEL_EXPANDED_BYTES = 128 * 1024 * 1024
MAX_WHEEL_COMPRESSION_RATIO = 1_000
_STABLE_METADATA_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
    "st_uid",
    "st_gid",
)
_DIRECTORY_BINDING_FIELDS = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
_UNSAFE_WRITE_BITS = stat.S_IWGRP | stat.S_IWOTH
RUNNER_PYTHON = (3, 12)
RUNNER_PYTHON_FULL_VERSION = "3.12.13"
PINNED_PYTHON_BUILD = "20260623"
PINNED_PYTHON_RELEASE = "https://github.com/astral-sh/python-build-standalone/releases/tag/20260623"
PINNED_PYTHON_ARTIFACTS: dict[tuple[str, str], tuple[str, str, str, str, int]] = {
    ("darwin", "arm64"): (
        "cpython-3.12.13-macos-aarch64-none",
        "cpython-3.12.13+20260623-aarch64-apple-darwin-install_only_stripped.tar.gz",
        "https://github.com/astral-sh/python-build-standalone/releases/download/20260623/"
        "cpython-3.12.13%2B20260623-aarch64-apple-darwin-install_only_stripped.tar.gz",
        "41df7d3ae4757e84b97874f76d634268456aaa271740d33f968d826374998fb7",
        25_003_823,
    ),
    ("darwin", "x86_64"): (
        "cpython-3.12.13-macos-x86_64-none",
        "cpython-3.12.13+20260623-x86_64-apple-darwin-install_only_stripped.tar.gz",
        "https://github.com/astral-sh/python-build-standalone/releases/download/20260623/"
        "cpython-3.12.13%2B20260623-x86_64-apple-darwin-install_only_stripped.tar.gz",
        "a6bbea996c5f14eb55ab275889d2df45408deec504b4a7219d7b59c045b2555e",
        24_690_991,
    ),
    ("linux", "aarch64"): (
        "cpython-3.12.13-linux-aarch64-gnu",
        "cpython-3.12.13+20260623-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz",
        "https://github.com/astral-sh/python-build-standalone/releases/download/20260623/"
        "cpython-3.12.13%2B20260623-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz",
        "b85154b9c7ca9de3f85f2c9f032d503151db16ef198de86b885fc61890c075ed",
        29_210_487,
    ),
    ("linux", "x86_64"): (
        "cpython-3.12.13-linux-x86_64-gnu",
        "cpython-3.12.13+20260623-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
        "https://github.com/astral-sh/python-build-standalone/releases/download/20260623/"
        "cpython-3.12.13%2B20260623-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz",
        "10a452caac7041357805f0c19a60576df53f1ab06d1abfc9200f1f0157cb3bd1",
        34_159_178,
    ),
}
PINNED_UV_VERSION = "0.11.28"
PINNED_UV_SHA256 = {
    ("darwin", "arm64"): "0e71bad1f36bc9762cdecef1932f68ea3db541e45495c60dd474e1c860e21edf",
    ("darwin", "x86_64"): "583ea84ad16ff33f7d22353bc64dee4500a8ba01f514f91f11ad1f2cf7db4569",
    ("linux", "aarch64"): "b9f74e398b6b15826a4b68b5a83d039036d47df64013e7faf1a9974ec199c144",
    ("linux", "x86_64"): "1cb9cd0a1749debf6049d7d2bb933882cc52d81016326ee6d99a786d6c988b03",
}
PINNED_UV_TARGET = {
    ("darwin", "arm64"): "aarch64-apple-darwin",
    ("darwin", "x86_64"): "x86_64-apple-darwin",
    ("linux", "aarch64"): "aarch64-unknown-linux-gnu",
    ("linux", "x86_64"): "x86_64-unknown-linux-gnu",
}


class RunnerTrustError(RuntimeError):
    """A runner input, artifact, executable, or environment failed closed."""


@dataclass(frozen=True)
class StableMetadataBinding:
    device: int
    inode: int
    mode: int
    nlink: int
    size: int
    mtime_ns: int
    ctime_ns: int
    owner_uid: int
    owner_gid: int


@dataclass(frozen=True)
class DirectoryBinding:
    path: Path
    metadata: StableMetadataBinding


@dataclass(frozen=True)
class ExecutableBinding:
    lexical_path: Path
    resolved_path: Path
    sha256: str
    size: int
    mode: int
    owner_uid: int
    owner_gid: int
    lexical_metadata: StableMetadataBinding | None = None
    resolved_metadata: StableMetadataBinding | None = None
    lexical_link_target: str | None = None
    directory_chain: tuple[DirectoryBinding, ...] = ()


@dataclass(frozen=True)
class PinnedUvBinding:
    executable: ExecutableBinding
    version: str
    target: str


@dataclass(frozen=True)
class HostToolBinding:
    trust_root: str
    system: str
    machine: str
    release: str
    version: str
    tool: ExecutableBinding | None


@dataclass(frozen=True)
class LockedWheel:
    distribution: str
    version: str
    url: str
    sha256: str
    size: int
    filename: str


@dataclass(frozen=True)
class AuthenticatedRunner:
    root: Path
    snapshot_root: Path
    python_path: Path
    site_packages: Path
    interpreter_root: Path
    scratch_root: Path
    uv: PinnedUvBinding
    python: ExecutableBinding
    python_artifact_sha256: str
    host_tool: HostToolBinding
    python_version: str
    lock_sha256: str
    artifact_set_sha256: str
    environment_sha256: str
    excluded_tree_paths: tuple[str, ...]
    distribution_versions: tuple[tuple[str, str], ...]
    mutable_child_directories: tuple[str, ...] = ()

    def distribution_version(self, name: str) -> str:
        canonical_name = canonicalize_name(name)
        matches = [
            version
            for distribution, version in self.distribution_versions
            if distribution == canonical_name
        ]
        if len(matches) != 1:
            raise RunnerTrustError(f"runner distribution is not unique: {canonical_name}")
        return matches[0]


def _metadata_matches(
    first: os.stat_result,
    *others: os.stat_result,
    fields: tuple[str, ...] = _STABLE_METADATA_FIELDS,
) -> bool:
    return all(
        getattr(first, field) == getattr(other, field) for other in others for field in fields
    )


def _stable_metadata_binding(metadata: os.stat_result) -> StableMetadataBinding:
    return StableMetadataBinding(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        nlink=metadata.st_nlink,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
        owner_uid=metadata.st_uid,
        owner_gid=metadata.st_gid,
    )


def _directory_chain_binding(
    directory: Path,
    *,
    allowed_owner_uids: frozenset[int],
    stop: Path | None = None,
) -> tuple[DirectoryBinding, ...] | None:
    """Bind every lexical and resolved directory used to reach one path."""

    try:
        lexical = directory.absolute()
        resolved = directory.resolve(strict=True)
        lexical_stop = stop.absolute() if stop is not None else None
        resolved_stop = stop.resolve(strict=True) if stop is not None else None
    except OSError:
        return None
    if resolved_stop is not None and not (
        resolved == resolved_stop or resolved.is_relative_to(resolved_stop)
    ):
        return None

    paths: list[Path] = []
    for start, candidates in (
        (lexical, tuple(path for path in (lexical_stop, resolved_stop) if path is not None)),
        (resolved, tuple(path for path in (resolved_stop, lexical_stop) if path is not None)),
    ):
        selected_stop = next(
            (
                candidate
                for candidate in candidates
                if start == candidate or start.is_relative_to(candidate)
            ),
            None,
        )
        if stop is not None and selected_stop is None:
            return None
        current = start
        while True:
            paths.append(current)
            if (
                selected_stop is not None and current == selected_stop
            ) or current == current.parent:
                break
            current = current.parent

    ordered_paths = tuple(dict.fromkeys(paths))
    bindings: list[DirectoryBinding] = []
    for path in ordered_paths:
        try:
            metadata = path.lstat()
        except OSError:
            return None
        if not _directory_metadata_is_trusted(
            metadata,
            allowed_owner_uids=allowed_owner_uids,
        ):
            return None
        bindings.append(DirectoryBinding(path=path, metadata=_stable_metadata_binding(metadata)))
    try:
        if any(
            _stable_metadata_binding(binding.path.lstat()) != binding.metadata
            for binding in bindings
        ):
            return None
    except OSError:
        return None
    return tuple(bindings)


def _directory_metadata_is_trusted(
    metadata: os.stat_result,
    *,
    allowed_owner_uids: frozenset[int],
) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid in allowed_owner_uids
        and not metadata.st_mode & _UNSAFE_WRITE_BITS
    )


def _trusted_directory_chain(
    directory: Path,
    *,
    allowed_owner_uids: frozenset[int],
    stop: Path | None = None,
) -> bool:
    return (
        _directory_chain_binding(
            directory,
            allowed_owner_uids=allowed_owner_uids,
            stop=stop,
        )
        is not None
    )


def stable_regular_bytes(path: Path, *, maximum_bytes: int) -> bytes | None:
    """Read one regular file while binding descriptor and path metadata."""

    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or maximum_bytes < 0
        or not hasattr(os, "O_NOFOLLOW")
    ):
        return None
    try:
        initial_path = path.lstat()
        if (
            not stat.S_ISREG(initial_path.st_mode)
            or initial_path.st_nlink != 1
            or initial_path.st_size < 0
            or initial_path.st_size > maximum_bytes
        ):
            return None
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except OSError:
        return None
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size < 0
            or opened.st_size > maximum_bytes
            or not _metadata_matches(initial_path, opened)
        ):
            return None
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(maximum_bytes + 1)
        final_descriptor = os.fstat(descriptor)
        final_path = path.lstat()
    except OSError:
        return None
    finally:
        os.close(descriptor)
    if (
        not _metadata_matches(
            initial_path,
            opened,
            final_descriptor,
            final_path,
        )
        or len(data) != initial_path.st_size
        or len(data) > maximum_bytes
    ):
        return None
    return data


def bind_executable(
    path: Path,
    *,
    required_root: Path | None = None,
) -> ExecutableBinding | None:
    """Bind an executable and every directory used to resolve its path."""

    invoking_uid = os.getuid()
    allowed_owner_uids = (
        frozenset({invoking_uid}) if required_root is not None else frozenset({0, invoking_uid})
    )
    try:
        lexical = path.absolute()
        lexical_before = lexical.lstat()
        if (
            not (stat.S_ISREG(lexical_before.st_mode) or stat.S_ISLNK(lexical_before.st_mode))
            or lexical_before.st_nlink != 1
            or lexical_before.st_uid not in allowed_owner_uids
        ):
            return None
        resolved_required = (
            required_root.resolve(strict=True) if required_root is not None else None
        )
        if required_root is not None and not _directory_metadata_is_trusted(
            required_root.lstat(),
            allowed_owner_uids=allowed_owner_uids,
        ):
            return None
        if required_root is not None and not lexical.is_relative_to(required_root.absolute()):
            return None
        resolved = lexical.resolve(strict=True)
        lexical_link_target = os.readlink(lexical) if stat.S_ISLNK(lexical_before.st_mode) else None
        if resolved_required is not None and not (
            resolved == resolved_required or resolved.is_relative_to(resolved_required)
        ):
            return None
        lexical_chain = _directory_chain_binding(
            lexical.parent,
            allowed_owner_uids=allowed_owner_uids,
            stop=required_root,
        )
        resolved_chain = _directory_chain_binding(
            resolved.parent,
            allowed_owner_uids=allowed_owner_uids,
            stop=required_root,
        )
        if lexical_chain is None or resolved_chain is None:
            return None
        directory_by_path: dict[Path, DirectoryBinding] = {}
        for binding in (*lexical_chain, *resolved_chain):
            existing = directory_by_path.get(binding.path)
            if existing is not None and existing != binding:
                return None
            directory_by_path[binding.path] = binding
        directory_chain = tuple(directory_by_path.values())
        target_before = resolved.lstat()
        if (
            not stat.S_ISREG(target_before.st_mode)
            or target_before.st_nlink != 1
            or target_before.st_size < 0
            or target_before.st_size > MAX_RUNNER_FILE_BYTES
            or target_before.st_uid not in allowed_owner_uids
            or target_before.st_mode & _UNSAFE_WRITE_BITS
            or not target_before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            return None
        data = stable_regular_bytes(resolved, maximum_bytes=MAX_RUNNER_FILE_BYTES)
        target_after = resolved.lstat()
        lexical_after = lexical.lstat()
        lexical_link_after = os.readlink(lexical) if stat.S_ISLNK(lexical_after.st_mode) else None
        rebound_lexical_chain = _directory_chain_binding(
            lexical.parent,
            allowed_owner_uids=allowed_owner_uids,
            stop=required_root,
        )
        rebound_resolved_chain = _directory_chain_binding(
            resolved.parent,
            allowed_owner_uids=allowed_owner_uids,
            stop=required_root,
        )
    except OSError:
        return None
    rebound_directory_by_path: dict[Path, DirectoryBinding] = {}
    if rebound_lexical_chain is None or rebound_resolved_chain is None:
        return None
    for binding in (*rebound_lexical_chain, *rebound_resolved_chain):
        existing = rebound_directory_by_path.get(binding.path)
        if existing is not None and existing != binding:
            return None
        rebound_directory_by_path[binding.path] = binding
    if (
        data is None
        or not _metadata_matches(target_before, target_after)
        or not _metadata_matches(lexical_before, lexical_after)
        or lexical_link_after != lexical_link_target
        or tuple(rebound_directory_by_path.values()) != directory_chain
    ):
        return None
    return ExecutableBinding(
        lexical_path=lexical,
        resolved_path=resolved,
        sha256=sha256_bytes(data),
        size=len(data),
        mode=stat.S_IMODE(target_after.st_mode),
        owner_uid=target_after.st_uid,
        owner_gid=target_after.st_gid,
        lexical_metadata=_stable_metadata_binding(lexical_after),
        resolved_metadata=_stable_metadata_binding(target_after),
        lexical_link_target=lexical_link_target,
        directory_chain=directory_chain,
    )


def resolve_pinned_uv(path: Path | None = None) -> PinnedUvBinding:
    """Resolve and execute only the official per-platform uv 0.11.28 binary."""

    platform_key = (platform.system().casefold(), platform.machine().casefold())
    expected_hash = PINNED_UV_SHA256.get(platform_key)
    expected_target = PINNED_UV_TARGET.get(platform_key)
    if expected_hash is None or expected_target is None:
        raise RunnerTrustError("uv trust is unsupported on this execution platform")
    candidate = path
    if candidate is None:
        discovered = shutil.which("uv")
        if discovered is None:
            raise RunnerTrustError("uv is not available on the execution PATH")
        candidate = Path(discovered)
    binding = bind_executable(candidate)
    if binding is None:
        raise RunnerTrustError("resolved uv executable is not a stable regular file")
    if binding.sha256 != expected_hash:
        raise RunnerTrustError("uv executable does not match the pinned official release")
    try:
        completed = subprocess.run(  # noqa: S603 - executable bytes match the pinned release
            (str(binding.resolved_path), "--version"),
            check=True,
            capture_output=True,
            text=True,
            env={"HOME": "/nonexistent", "LC_ALL": "C", "PATH": os.defpath},
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RunnerTrustError("uv version identity cannot be verified") from error
    version = completed.stdout.strip()
    if (
        re.fullmatch(
            rf"uv {re.escape(PINNED_UV_VERSION)} "
            rf"\([0-9a-f]+ 2026-07-07 {re.escape(expected_target)}\)",
            version,
        )
        is None
    ):
        raise RunnerTrustError("uv returned an invalid version identity")
    rebound = bind_executable(binding.lexical_path)
    if rebound != binding:
        raise RunnerTrustError("uv executable changed during version verification")
    return PinnedUvBinding(executable=binding, version=version, target=expected_target)


def _bind_host_tool(path: Path) -> ExecutableBinding | None:
    directory_chain = _directory_chain_binding(
        path.parent,
        allowed_owner_uids=frozenset({0}),
    )
    if not hasattr(os, "O_NOFOLLOW") or directory_chain is None:
        return None
    descriptor: int | None = None
    try:
        lexical = path.absolute()
        before = lexical.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_nlink < 1
            or before.st_size < 0
            or before.st_size > MAX_RUNNER_FILE_BYTES
            or before.st_mode & _UNSAFE_WRITE_BITS
            or not before.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ):
            return None
        descriptor = os.open(
            lexical,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if not _metadata_matches(before, opened):
            return None
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(MAX_RUNNER_FILE_BYTES + 1)
        after = os.fstat(descriptor)
        current = lexical.lstat()
        rebound_directory_chain = _directory_chain_binding(
            path.parent,
            allowed_owner_uids=frozenset({0}),
        )
    except OSError:
        return None
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    if (
        len(data) != before.st_size
        or len(data) > MAX_RUNNER_FILE_BYTES
        or not _metadata_matches(before, opened, after, current)
        or rebound_directory_chain != directory_chain
    ):
        return None
    return ExecutableBinding(
        lexical_path=lexical,
        resolved_path=lexical,
        sha256=sha256_bytes(data),
        size=len(data),
        mode=stat.S_IMODE(after.st_mode),
        owner_uid=after.st_uid,
        owner_gid=after.st_gid,
        lexical_metadata=_stable_metadata_binding(current),
        resolved_metadata=_stable_metadata_binding(after),
        directory_chain=directory_chain,
    )


def host_tool_binding() -> HostToolBinding:
    """Bind the operating-system tool used by uv to relocate standalone CPython."""

    system = platform.system()
    common = {
        "system": system,
        "machine": platform.machine(),
        "release": platform.release(),
        "version": platform.version(),
    }
    if system.casefold() == "darwin":
        tool = _bind_host_tool(Path("/usr/bin/install_name_tool"))
        if tool is None:
            raise RunnerTrustError("macOS install_name_tool trust binding failed")
        return HostToolBinding(
            trust_root="host-os-macos-load-command-relocation",
            tool=tool,
            **common,
        )
    if system.casefold() == "linux":
        return HostToolBinding(
            trust_root="host-os-linux-dynamic-loader",
            tool=None,
            **common,
        )
    raise RunnerTrustError("runner host-tool trust is unsupported on this platform")


def ensure_private_directory(path: Path) -> bool:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        before = path.lstat()
        after = path.lstat()
    except OSError:
        return False
    return _directory_metadata_is_trusted(
        after,
        allowed_owner_uids=frozenset({os.getuid()}),
    ) and _metadata_matches(before, after, fields=_DIRECTORY_BINDING_FIELDS)


def authenticated_artifact_bytes(
    *,
    url: str,
    expected_sha256: str,
    expected_size: int,
    cache_root: Path,
    cache_namespace: str,
    allowed_redirect_hosts: frozenset[str] | None = None,
    signed_query_redirect_hosts: frozenset[str] = frozenset(),
    download_timeout_seconds: int = 120,
) -> bytes:
    """Load immutable artifact bytes while treating every persistent cache byte as hostile."""

    try:
        parsed = urlsplit(url)
        encoded_filename = PurePosixPath(parsed.path).name
        filename = unquote(encoded_filename)
        valid_authority = (
            parsed.scheme == "https"
            and parsed.hostname is not None
            and parsed.port is None
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError as error:
        raise RunnerTrustError("artifact URL authority is invalid") from error
    if (
        not valid_authority
        or parsed.query
        or parsed.fragment
        or "/" in filename
        or "\\" in filename
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,255}", filename)
        or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        or isinstance(expected_size, bool)
        or not 0 < expected_size <= MAX_AUTHENTICATED_ARTIFACT_BYTES
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", cache_namespace) is None
    ):
        raise RunnerTrustError("authenticated artifact contract is invalid")
    redirect_hosts = allowed_redirect_hosts or frozenset({str(parsed.hostname)})
    if (
        not redirect_hosts
        or any(
            re.fullmatch(r"[A-Za-z0-9.-]+", host) is None
            for host in redirect_hosts | signed_query_redirect_hosts
        )
        or not signed_query_redirect_hosts.issubset(redirect_hosts)
        or isinstance(download_timeout_seconds, bool)
        or not 1 <= download_timeout_seconds <= 300
    ):
        raise RunnerTrustError("authenticated artifact redirect policy is invalid")
    namespace = cache_root / cache_namespace
    if not ensure_private_directory(cache_root) or not ensure_private_directory(namespace):
        raise RunnerTrustError("authenticated artifact cache is not private")
    cache_path = namespace / f"{expected_sha256}-{filename}"
    cached = stable_regular_bytes(cache_path, maximum_bytes=expected_size)
    if (
        cached is not None
        and len(cached) == expected_size
        and sha256_bytes(cached) == expected_sha256
    ):
        return cached

    context = ssl.create_default_context(cafile=certifi.where())
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        with urllib.request.urlopen(  # noqa: S310 - URL authority and digest are frozen above
            url,
            context=context,
            timeout=download_timeout_seconds,
        ) as response:
            final = urlsplit(response.geturl())
            if (
                final.scheme != "https"
                or final.hostname not in redirect_hosts
                or final.port is not None
                or final.username is not None
                or final.password is not None
                or final.fragment
                or (final.query and final.hostname not in signed_query_redirect_hosts)
            ):
                raise RunnerTrustError("authenticated artifact redirected across authority")
            downloaded = bytes(response.read(expected_size + 1))
    except (OSError, ValueError) as error:
        raise RunnerTrustError("authenticated artifact download failed") from error
    if len(downloaded) != expected_size or sha256_bytes(downloaded) != expected_sha256:
        raise RunnerTrustError("authenticated artifact bytes differ from the frozen digest")

    temporary = namespace / f".{expected_sha256}.{secrets.token_hex(16)}.tmp"
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        view = memoryview(downloaded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RunnerTrustError("authenticated artifact cache write failed")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, cache_path)
        persisted = stable_regular_bytes(cache_path, maximum_bytes=expected_size)
    except OSError as error:
        raise RunnerTrustError("authenticated artifact cache write failed") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
    if (
        persisted is None
        or len(persisted) != expected_size
        or sha256_bytes(persisted) != expected_sha256
    ):
        raise RunnerTrustError("authenticated artifact cache did not preserve exact bytes")
    return persisted


def _marker_environment() -> dict[str, str]:
    environment = default_environment()
    environment.update(
        {
            "implementation_name": "cpython",
            "implementation_version": RUNNER_PYTHON_FULL_VERSION,
            "platform_python_implementation": "CPython",
            "python_full_version": RUNNER_PYTHON_FULL_VERSION,
            "python_version": ".".join(str(part) for part in RUNNER_PYTHON),
        }
    )
    return {key: str(value) for key, value in environment.items()}


def resolve_locked_packages(
    lock: dict[str, object],
    root_distributions: frozenset[str],
) -> dict[str, dict[str, object]]:
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise RunnerTrustError("dependency lock has no package inventory")
    if len(packages) > MAX_LOCK_PACKAGE_ENTRIES:
        raise RunnerTrustError("dependency lock package inventory count exceeded")
    by_name: dict[str, list[dict[str, object]]] = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            raise RunnerTrustError("dependency lock package inventory is invalid")
        by_name.setdefault(canonicalize_name(package["name"]), []).append(package)

    selected: dict[str, dict[str, object]] = {}
    pending = list(root_distributions)
    marker_environment = _marker_environment()
    while pending:
        name = canonicalize_name(pending.pop())
        if name in selected:
            continue
        candidates = by_name.get(name)
        if candidates is None or len(candidates) != 1:
            raise RunnerTrustError(f"locked runner distribution is not unique: {name}")
        if len(selected) >= MAX_LOCKED_DISTRIBUTIONS:
            raise RunnerTrustError("locked runner distribution count exceeded")
        package = candidates[0]
        dependencies = package.get("dependencies", [])
        if (
            package.get("source") != {"registry": "https://pypi.org/simple"}
            or not isinstance(package.get("version"), str)
            or not isinstance(dependencies, list)
        ):
            raise RunnerTrustError(f"locked runner distribution is not registry-bound: {name}")
        selected[name] = package
        for dependency in dependencies:
            if not isinstance(dependency, dict) or not isinstance(dependency.get("name"), str):
                raise RunnerTrustError(f"locked runner dependency is invalid: {name}")
            marker = dependency.get("marker")
            if marker is not None:
                if not isinstance(marker, str):
                    raise RunnerTrustError(f"locked runner marker is invalid: {name}")
                try:
                    applies = Marker(marker).evaluate(environment=marker_environment)
                except (InvalidMarker, UndefinedEnvironmentName) as error:
                    raise RunnerTrustError(
                        f"locked runner marker cannot evaluate: {name}"
                    ) from error
                if not applies:
                    continue
            pending.append(dependency["name"])
    return selected


def _target_tags(target_platform_tags: tuple[str, ...] | None = None) -> tuple[Tag, ...]:
    platform_key = (platform.system().casefold(), platform.machine().casefold())
    if platform_key not in PINNED_UV_TARGET:
        raise RunnerTrustError("runner wheel tags are unsupported on this platform")
    platforms = tuple(platform_tags()) if target_platform_tags is None else target_platform_tags
    if not platforms:
        raise RunnerTrustError("runner wheel platform tags are unavailable")
    tags = (
        *cpython_tags(python_version=RUNNER_PYTHON, platforms=platforms),
        *compatible_tags(
            python_version=RUNNER_PYTHON,
            interpreter="cp312",
            platforms=platforms,
        ),
    )
    return tuple(dict.fromkeys(tags))


def resolve_locked_wheels(
    lock: dict[str, object],
    *,
    root_distributions: frozenset[str],
    target_platform_tags: tuple[str, ...] | None = None,
) -> tuple[LockedWheel, ...]:
    """Resolve one exact compatible wheel for a CPython 3.12 dependency closure."""

    packages = resolve_locked_packages(lock, root_distributions)
    tag_rank = {tag: index for index, tag in enumerate(_target_tags(target_platform_tags))}
    selected: list[LockedWheel] = []
    selected_bytes = 0
    for distribution, package in sorted(packages.items()):
        version = package.get("version")
        wheels = package.get("wheels")
        if not isinstance(version, str) or not isinstance(wheels, list):
            raise RunnerTrustError(f"locked runner wheels are missing: {distribution}")
        compatible: list[tuple[int, LockedWheel]] = []
        for wheel in wheels:
            if not isinstance(wheel, dict):
                raise RunnerTrustError(f"locked wheel entry is invalid: {distribution}")
            url = wheel.get("url")
            digest = wheel.get("hash")
            size = wheel.get("size")
            if (
                not isinstance(url, str)
                or not isinstance(digest, str)
                or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None
                or not isinstance(size, int)
                or isinstance(size, bool)
                or not 0 < size <= MAX_WHEEL_BYTES
            ):
                raise RunnerTrustError(f"locked wheel binding is invalid: {distribution}")
            try:
                parsed = urlsplit(url)
                valid_authority = (
                    parsed.scheme == "https"
                    and parsed.hostname == "files.pythonhosted.org"
                    and parsed.port is None
                    and parsed.username is None
                    and parsed.password is None
                    and not parsed.query
                    and not parsed.fragment
                )
            except ValueError as error:
                raise RunnerTrustError(f"locked wheel URL is invalid: {distribution}") from error
            if not valid_authority:
                raise RunnerTrustError(f"locked wheel authority is invalid: {distribution}")
            filename = PurePosixPath(parsed.path).name
            try:
                wheel_name, wheel_version, _build, wheel_tags = parse_wheel_filename(filename)
            except InvalidWheelFilename as error:
                raise RunnerTrustError(
                    f"locked wheel filename is invalid: {distribution}"
                ) from error
            if canonicalize_name(wheel_name) != distribution or str(wheel_version) != version:
                raise RunnerTrustError(f"locked wheel identity differs: {distribution}")
            ranks = [tag_rank[tag] for tag in wheel_tags if tag in tag_rank]
            if ranks:
                compatible.append(
                    (
                        min(ranks),
                        LockedWheel(
                            distribution=distribution,
                            version=version,
                            url=url,
                            sha256=digest.removeprefix("sha256:"),
                            size=size,
                            filename=filename,
                        ),
                    )
                )
        if not compatible:
            raise RunnerTrustError(f"no compatible locked wheel exists: {distribution}")
        compatible.sort(key=lambda item: (item[0], item[1].url))
        if len(compatible) > 1 and compatible[0][0] == compatible[1][0]:
            raise RunnerTrustError(
                f"compatible locked wheel selection is ambiguous: {distribution}"
            )
        selected_wheel = compatible[0][1]
        selected_bytes += selected_wheel.size
        if selected_bytes > MAX_AUTHENTICATED_WHEEL_SET_BYTES:
            raise RunnerTrustError("authenticated wheel set byte limit exceeded")
        selected.append(selected_wheel)
    return tuple(selected)


def _wheel_output_parts(member_name: str) -> tuple[str, ...] | None:
    if "\\" in member_name or "\x00" in member_name:
        return None
    pure = PurePosixPath(member_name)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        return None
    parts = pure.parts
    if parts[0].endswith(".data"):
        if len(parts) < 3 or parts[1] not in {"purelib", "platlib"}:
            return None
        parts = parts[2:]
    return tuple(parts) if parts else None


def extract_authenticated_wheels(
    artifacts: tuple[tuple[LockedWheel, bytes], ...],
    site_packages: Path,
) -> None:
    if site_packages.exists() or site_packages.is_symlink():
        raise RunnerTrustError("authenticated site-packages already exists")
    try:
        site_packages.mkdir(mode=0o700, parents=True)
    except OSError as error:
        raise RunnerTrustError("authenticated site-packages cannot be created") from error
    files: set[str] = set()
    directories: set[str] = set()
    expanded_bytes = 0
    entry_count = 0
    try:
        for _wheel, data in artifacts:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                entry_count += len(infos)
                if entry_count > MAX_WHEEL_ENTRIES:
                    raise RunnerTrustError("authenticated wheel entry count exceeded")
                for info in infos:
                    if info.flag_bits & 0x1:
                        raise RunnerTrustError("authenticated wheel contains encrypted bytes")
                    parts = _wheel_output_parts(info.filename)
                    if parts is None:
                        raise RunnerTrustError("authenticated wheel path is unsafe")
                    mode = info.external_attr >> 16
                    file_type = stat.S_IFMT(mode)
                    is_directory = info.is_dir()
                    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                        raise RunnerTrustError("authenticated wheel contains a special file")
                    if (is_directory and file_type == stat.S_IFREG) or (
                        not is_directory and file_type == stat.S_IFDIR
                    ):
                        raise RunnerTrustError("authenticated wheel entry type is incoherent")
                    if (
                        info.file_size < 0
                        or info.file_size > MAX_WHEEL_BYTES
                        or info.compress_size < 0
                        or (
                            info.file_size
                            and info.compress_size == 0
                            and info.compress_type != zipfile.ZIP_STORED
                        )
                        or (
                            info.compress_size
                            and info.file_size / info.compress_size > MAX_WHEEL_COMPRESSION_RATIO
                        )
                    ):
                        raise RunnerTrustError("authenticated wheel expansion is unsafe")
                    expanded_bytes += info.file_size
                    if expanded_bytes > MAX_WHEEL_EXPANDED_BYTES:
                        raise RunnerTrustError("authenticated wheel expansion exceeded")
                    key = "/".join(parts).casefold()
                    target = site_packages.joinpath(*parts)
                    for parent in target.parents:
                        if parent == site_packages:
                            break
                        parent_key = parent.relative_to(site_packages).as_posix().casefold()
                        if parent_key in files:
                            raise RunnerTrustError("authenticated wheel path collides with a file")
                        directories.add(parent_key)
                    if is_directory:
                        if key in files:
                            raise RunnerTrustError("authenticated wheel directory collides")
                        directories.add(key)
                        target.mkdir(mode=0o700, parents=True, exist_ok=True)
                        continue
                    if key in files or key in directories or target.exists() or target.is_symlink():
                        raise RunnerTrustError("authenticated wheel file collides")
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with archive.open(info, "r") as source:
                        payload = source.read(info.file_size + 1)
                    if len(payload) != info.file_size:
                        raise RunnerTrustError("authenticated wheel member is truncated")
                    descriptor = os.open(
                        target,
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0),
                        0o400,
                    )
                    try:
                        view = memoryview(payload)
                        while view:
                            written = os.write(descriptor, view)
                            if written <= 0:
                                raise RunnerTrustError("authenticated wheel extraction failed")
                            view = view[written:]
                    finally:
                        os.close(descriptor)
                    files.add(key)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        if isinstance(error, RunnerTrustError):
            raise
        raise RunnerTrustError("authenticated wheel extraction failed") from error
    if not files:
        raise RunnerTrustError("authenticated wheel set extracted no files")


def _directory_tree_entry(
    path: str,
    metadata: os.stat_result,
    *,
    mutable_child: bool = False,
) -> dict[str, object]:
    entry: dict[str, object] = {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "kind": "directory",
        "mode": stat.S_IMODE(metadata.st_mode),
        "mutable_child": mutable_child,
        "owner_gid": metadata.st_gid,
        "owner_uid": metadata.st_uid,
        "path": path,
    }
    if not mutable_child:
        entry.update(
            ctime_ns=metadata.st_ctime_ns,
            mtime_ns=metadata.st_mtime_ns,
            nlink=metadata.st_nlink,
            size=metadata.st_size,
        )
    return entry


def _symlink_tree_entry(
    path: str,
    target: str,
    metadata: os.stat_result,
) -> dict[str, object]:
    return {
        "ctime_ns": metadata.st_ctime_ns,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "kind": "symlink",
        "mode": stat.S_IMODE(metadata.st_mode),
        "mtime_ns": metadata.st_mtime_ns,
        "nlink": metadata.st_nlink,
        "owner_gid": metadata.st_gid,
        "owner_uid": metadata.st_uid,
        "path": path,
        "size": metadata.st_size,
        "target": target,
    }


def tree_digest(
    root: Path,
    *,
    excluded_relative_paths: tuple[str, ...] = (),
    mutable_child_directories: tuple[str, ...] = (),
) -> str | None:
    """Bind the owned, non-writable runner tree and its path inventory."""

    excluded = tuple(PurePosixPath(relative) for relative in excluded_relative_paths)
    mutable_directories = tuple(PurePosixPath(relative) for relative in mutable_child_directories)
    if (
        tuple(path.as_posix() for path in excluded) != excluded_relative_paths
        or tuple(sorted(excluded_relative_paths)) != excluded_relative_paths
        or len(set(excluded_relative_paths)) != len(excluded_relative_paths)
        or any(path.is_absolute() or ".." in path.parts or not path.parts for path in excluded)
        or tuple(path.as_posix() for path in mutable_directories) != mutable_child_directories
        or tuple(sorted(mutable_child_directories)) != mutable_child_directories
        or len(set(mutable_child_directories)) != len(mutable_child_directories)
        or any(
            path.is_absolute() or ".." in path.parts or (not path.parts and path.as_posix() != ".")
            for path in mutable_directories
        )
    ):
        return None
    mutable_child_directory_set = set(mutable_child_directories)
    allowed_mutable_directories = {
        path.parent.as_posix() if path.parent.parts else "." for path in excluded
    }
    if not mutable_child_directory_set.issubset(allowed_mutable_directories):
        return None

    def is_excluded(relative_path: PurePosixPath) -> bool:
        return any(
            relative_path == excluded_path or relative_path.is_relative_to(excluded_path)
            for excluded_path in excluded
        )

    def inventory() -> list[Path] | None:
        if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
            return None
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        discovered: list[Path] = []
        discovered_entries = 1
        root_descriptor: int | None = None

        def visit(
            directory_descriptor: int,
            prefix: PurePosixPath,
        ) -> bool:
            nonlocal discovered_entries
            before = os.fstat(directory_descriptor)
            children: list[tuple[str, PurePosixPath, os.stat_result]] = []
            with os.scandir(directory_descriptor) as iterator:
                for child in iterator:
                    relative = prefix / child.name
                    if is_excluded(relative):
                        continue
                    discovered_entries += 1
                    if discovered_entries > MAX_RUNNER_TREE_ENTRIES:
                        return False
                    metadata = child.stat(follow_symlinks=False)
                    if stat.S_ISDIR(metadata.st_mode) and not _directory_metadata_is_trusted(
                        metadata,
                        allowed_owner_uids=allowed_owner_uids,
                    ):
                        return False
                    children.append((child.name, relative, metadata))
            if not _metadata_matches(before, os.fstat(directory_descriptor)):
                return False

            for name, relative, metadata in sorted(children, key=lambda item: item[0]):
                discovered.append(root.joinpath(*relative.parts))
                if not stat.S_ISDIR(metadata.st_mode):
                    continue
                child_descriptor = os.open(name, directory_flags, dir_fd=directory_descriptor)
                try:
                    opened = os.fstat(child_descriptor)
                    if not _metadata_matches(metadata, opened) or not visit(
                        child_descriptor,
                        relative,
                    ):
                        return False
                    settled = os.fstat(child_descriptor)
                    current = os.stat(
                        name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                    if not _metadata_matches(opened, settled, current):
                        return False
                finally:
                    os.close(child_descriptor)
            return _metadata_matches(before, os.fstat(directory_descriptor))

        try:
            root_descriptor = os.open(root, directory_flags)
            opened_root = os.fstat(root_descriptor)
            if not _metadata_matches(root_before, opened_root) or not visit(
                root_descriptor,
                PurePosixPath(),
            ):
                return None
            return sorted(discovered, key=lambda path: path.relative_to(root).as_posix())
        except (OSError, RuntimeError, ValueError):
            return None
        finally:
            if root_descriptor is not None:
                with suppress(OSError):
                    os.close(root_descriptor)

    invoking_uid = os.getuid()
    allowed_owner_uids = frozenset({invoking_uid})
    try:
        resolved_root = root.resolve(strict=True)
        root_before = root.lstat()
    except OSError:
        return None
    if not _directory_metadata_is_trusted(
        root_before,
        allowed_owner_uids=allowed_owner_uids,
    ):
        return None
    paths = inventory()
    if paths is None:
        return None

    entries: list[dict[str, object]] = [
        _directory_tree_entry(
            ".",
            root_before,
            mutable_child="." in mutable_child_directory_set,
        )
    ]
    total_bytes = 0
    for path in paths:
        relative = path.relative_to(root).as_posix()
        try:
            before = path.lstat()
        except OSError:
            return None
        if stat.S_ISDIR(before.st_mode):
            if not _directory_metadata_is_trusted(
                before,
                allowed_owner_uids=allowed_owner_uids,
            ):
                return None
            try:
                after = path.lstat()
            except OSError:
                return None
            directory_fields = (
                _DIRECTORY_BINDING_FIELDS
                if relative in mutable_child_directory_set
                else _STABLE_METADATA_FIELDS
            )
            if not _metadata_matches(
                before,
                after,
                fields=directory_fields,
            ):
                return None
            entries.append(
                _directory_tree_entry(
                    relative,
                    after,
                    mutable_child=relative in mutable_child_directory_set,
                )
            )
            continue
        if stat.S_ISLNK(before.st_mode):
            if before.st_uid != invoking_uid or before.st_nlink != 1:
                return None
            try:
                target_text = os.readlink(path)
                target = path.resolve(strict=True)
                after = path.lstat()
            except OSError:
                return None
            if not target.is_relative_to(resolved_root) or not _metadata_matches(before, after):
                return None
            entries.append(_symlink_tree_entry(relative, target_text, after))
            continue
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != invoking_uid
            or before.st_mode & _UNSAFE_WRITE_BITS
        ):
            return None
        data = stable_regular_bytes(path, maximum_bytes=MAX_RUNNER_FILE_BYTES)
        try:
            after = path.lstat()
        except OSError:
            return None
        if data is None or not _metadata_matches(before, after):
            return None
        total_bytes += len(data)
        if total_bytes > MAX_RUNNER_TREE_BYTES:
            return None
        entries.append(
            {
                "ctime_ns": after.st_ctime_ns,
                "device": after.st_dev,
                "inode": after.st_ino,
                "kind": "file",
                "mode": stat.S_IMODE(after.st_mode),
                "mtime_ns": after.st_mtime_ns,
                "nlink": after.st_nlink,
                "owner_gid": after.st_gid,
                "owner_uid": after.st_uid,
                "path": relative,
                "sha256": sha256_bytes(data),
                "size": len(data),
            }
        )

    final_paths = inventory()
    try:
        root_after = root.lstat()
    except OSError:
        return None
    if (
        final_paths is None
        or tuple(path.relative_to(root).as_posix() for path in final_paths)
        != tuple(path.relative_to(root).as_posix() for path in paths)
        or not _directory_metadata_is_trusted(
            root_after,
            allowed_owner_uids=allowed_owner_uids,
        )
        or not _metadata_matches(
            root_before,
            root_after,
            fields=(
                _DIRECTORY_BINDING_FIELDS
                if "." in mutable_child_directory_set
                else _STABLE_METADATA_FIELDS
            ),
        )
    ):
        return None
    return sha256_value(
        {
            "schema_version": "fieldtrue.authenticated-runner-tree.v2",
            "entries": entries,
        }
    )


def _write_exclusive_stable_bytes(path: Path, data: bytes, *, mode: int = 0o400) -> None:
    descriptor: int | None = None
    try:
        if path.exists() or path.is_symlink():
            raise RunnerTrustError("authenticated mirror destination already exists")
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            mode,
        )
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise RunnerTrustError("authenticated mirror write failed")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
    except OSError as error:
        raise RunnerTrustError("authenticated mirror write failed") from error
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    if stable_regular_bytes(path, maximum_bytes=len(data)) != data:
        raise RunnerTrustError("authenticated mirror did not preserve exact bytes")


def _same_uv_binding(candidate: PinnedUvBinding, expected: PinnedUvBinding) -> bool:
    return (
        candidate.executable == expected.executable
        and candidate.version == expected.version
        and candidate.target == expected.target
    )


def _install_pinned_python(
    root: Path,
    *,
    uv: PinnedUvBinding,
    artifact_cache_root: Path,
) -> tuple[Path, Path, Path, str, HostToolBinding]:
    platform_key = (platform.system().casefold(), platform.machine().casefold())
    artifact = PINNED_PYTHON_ARTIFACTS.get(platform_key)
    if artifact is None:
        raise RunnerTrustError("pinned Python is unsupported on this platform")
    target, filename, url, expected_sha256, expected_size = artifact
    archive = authenticated_artifact_bytes(
        url=url,
        expected_sha256=expected_sha256,
        expected_size=expected_size,
        cache_root=artifact_cache_root,
        cache_namespace=PINNED_PYTHON_BUILD,
        allowed_redirect_hosts=frozenset({"github.com", "release-assets.githubusercontent.com"}),
        signed_query_redirect_hosts=frozenset({"release-assets.githubusercontent.com"}),
    )

    mirror_root = root / "python-mirror"
    mirror_release = mirror_root / PINNED_PYTHON_BUILD
    uv_cache = root / "uv-cache"
    install_root = root / "python-install"
    runner_home = root / "runner-home"
    scratch_root = root / "runner-scratch"
    transient_roots = (mirror_root, uv_cache, install_root, runner_home, scratch_root)
    if any(path.exists() or path.is_symlink() for path in transient_roots):
        raise RunnerTrustError("private Python installation roots already exist")
    try:
        mirror_release.mkdir(mode=0o700, parents=True)
        uv_cache.mkdir(mode=0o700)
        runner_home.mkdir(mode=0o700)
        scratch_root.mkdir(mode=0o700)
    except OSError as error:
        raise RunnerTrustError("private Python installation roots cannot be created") from error
    staged_archive = mirror_release / filename
    _write_exclusive_stable_bytes(staged_archive, archive)
    try:
        mirror_uri = mirror_root.resolve(strict=True).as_uri()
    except (OSError, ValueError) as error:
        raise RunnerTrustError("private Python mirror URI cannot be bound") from error

    host_tool = host_tool_binding()
    if not _same_uv_binding(resolve_pinned_uv(), uv):
        raise RunnerTrustError("pinned uv changed before private Python installation")
    environment = {
        "HOME": str(runner_home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TEMP": str(scratch_root),
        "TMP": str(scratch_root),
        "TMPDIR": str(scratch_root),
        "UV_CACHE_DIR": str(uv_cache),
        "UV_NO_CONFIG": "1",
        "UV_NO_PROGRESS": "1",
        "UV_NO_SYSTEM_CONFIG": "1",
        "UV_OFFLINE": "1",
        "UV_PYTHON_CPYTHON_BUILD": PINNED_PYTHON_BUILD,
        "UV_PYTHON_INSTALL_BIN": "0",
        "UV_PYTHON_INSTALL_DIR": str(install_root),
    }
    try:
        installation = subprocess.run(  # noqa: S603 - executable bytes match pinned uv
            (
                str(uv.executable.resolved_path),
                "python",
                "install",
                "--offline",
                "--no-config",
                "--no-bin",
                "--reinstall",
                "--mirror",
                mirror_uri,
                target,
            ),
            cwd=root,
            check=False,
            capture_output=True,
            env=environment,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise RunnerTrustError("offline pinned Python installation failed") from error
    if (
        installation.returncode != 0
        or len(installation.stdout) + len(installation.stderr) > 1024 * 1024
        or stable_regular_bytes(staged_archive, maximum_bytes=expected_size) != archive
        or not _same_uv_binding(resolve_pinned_uv(), uv)
        or host_tool_binding() != host_tool
    ):
        raise RunnerTrustError("offline pinned Python installation failed closed")

    interpreter_root = install_root / target
    python_path = interpreter_root / "bin" / "python3.12"
    build_bytes = stable_regular_bytes(interpreter_root / "BUILD", maximum_bytes=64)
    if build_bytes != PINNED_PYTHON_BUILD.encode("ascii"):
        raise RunnerTrustError("installed Python build identity differs")
    if bind_executable(python_path, required_root=interpreter_root) is None:
        raise RunnerTrustError("installed Python executable cannot be bound")
    install_lock = install_root / ".lock"
    try:
        install_lock_metadata = install_lock.lstat()
        if (
            not stat.S_ISREG(install_lock_metadata.st_mode)
            or install_lock_metadata.st_nlink != 1
            or install_lock_metadata.st_uid != os.getuid()
            or stable_regular_bytes(install_lock, maximum_bytes=1024) is None
        ):
            raise RunnerTrustError("private Python install lock is unsafe")
        install_lock.unlink()
        shutil.rmtree(mirror_root)
        shutil.rmtree(uv_cache)
        shutil.rmtree(runner_home)
    except RunnerTrustError:
        raise
    except OSError as error:
        raise RunnerTrustError("private Python transient roots cannot be removed") from error
    return interpreter_root, python_path, scratch_root, expected_sha256, host_tool


def prepare_authenticated_runner(
    root: Path,
    snapshot_root: Path,
    *,
    root_distributions: frozenset[str],
    required_imports: tuple[str, ...] = ("pytest",),
    artifact_cache_root: Path | None = None,
    mutable_output_paths: tuple[Path, ...] = (),
) -> AuthenticatedRunner:
    """Create a fresh private CPython runner from exact lock and snapshot bytes."""

    try:
        resolved_root = root.resolve(strict=True)
        resolved_snapshot = snapshot_root.resolve(strict=True)
        root_metadata = root.lstat()
    except OSError as error:
        raise RunnerTrustError("authenticated runner root is unavailable") from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or root_metadata.st_uid != os.getuid()
        or root_metadata.st_mode & _UNSAFE_WRITE_BITS
        or not resolved_snapshot.is_relative_to(resolved_root)
        or not _trusted_directory_chain(
            snapshot_root,
            allowed_owner_uids=frozenset({os.getuid()}),
            stop=root,
        )
    ):
        raise RunnerTrustError("authenticated runner root is not private and snapshot-local")
    if not root_distributions:
        raise RunnerTrustError("authenticated runner requires a root distribution set")
    if any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name) is None for name in required_imports):
        raise RunnerTrustError("authenticated runner import inventory is invalid")
    excluded_paths = {"runner-scratch"}
    mutable_directories: set[str] = set()
    for output_path in mutable_output_paths:
        lexical = output_path if output_path.is_absolute() else root / output_path
        try:
            relative = lexical.absolute().relative_to(root.absolute()).as_posix()
        except ValueError as error:
            raise RunnerTrustError("mutable runner output is outside the private root") from error
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or not pure.parts:
            raise RunnerTrustError("mutable runner output path is invalid")
        parent = lexical.parent
        if lexical.is_symlink() or not _trusted_directory_chain(
            parent,
            allowed_owner_uids=frozenset({os.getuid()}),
            stop=root,
        ):
            raise RunnerTrustError("mutable runner output boundary is unsafe")
        if not lexical.exists():
            parent_relative = parent.absolute().relative_to(root.absolute()).as_posix()
            mutable_directories.add(parent_relative or ".")
        excluded_paths.add(pure.as_posix())
    excluded_tree_paths = tuple(sorted(excluded_paths))
    mutable_child_directories = tuple(sorted(mutable_directories))
    lock_bytes = stable_regular_bytes(
        snapshot_root / "uv.lock",
        maximum_bytes=16 * 1024 * 1024,
    )
    if lock_bytes is None:
        raise RunnerTrustError("committed dependency lock cannot be read safely")
    try:
        lock = tomllib.loads(lock_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RunnerTrustError("committed dependency lock is invalid") from error
    lock_sha256 = sha256_bytes(lock_bytes)
    wheels = resolve_locked_wheels(lock, root_distributions=root_distributions)
    cache_root = artifact_cache_root or (
        Path.home() / ".cache" / "inbar" / "authenticated-artifacts" / "wheels"
    )
    artifacts: list[tuple[LockedWheel, bytes]] = []
    for wheel in wheels:
        data = authenticated_artifact_bytes(
            url=wheel.url,
            expected_sha256=wheel.sha256,
            expected_size=wheel.size,
            cache_root=cache_root,
            cache_namespace=lock_sha256,
        )
        artifacts.append((wheel, data))
    artifact_set_sha256 = sha256_value(
        {
            "schema_version": "fieldtrue.authenticated-runner-artifacts.v1",
            "lock_sha256": lock_sha256,
            "wheels": [
                {
                    "distribution": wheel.distribution,
                    "filename": wheel.filename,
                    "sha256": wheel.sha256,
                    "size": wheel.size,
                    "url": wheel.url,
                    "version": wheel.version,
                }
                for wheel in wheels
            ],
        }
    )

    uv = resolve_pinned_uv()
    (
        interpreter_root,
        python_path,
        scratch_root,
        python_artifact_sha256,
        host_tool,
    ) = _install_pinned_python(root, uv=uv, artifact_cache_root=cache_root)
    if cache_root.is_relative_to(resolved_root):
        shutil.rmtree(cache_root, ignore_errors=True)

    site_packages = root / "authenticated-site-packages"
    extract_authenticated_wheels(tuple(artifacts), site_packages)
    python_binding = bind_executable(python_path, required_root=interpreter_root)
    if python_binding is None:
        raise RunnerTrustError("pinned Python is not a stable private executable")
    distribution_versions = tuple(sorted((wheel.distribution, wheel.version) for wheel in wheels))
    probe_script = (
        "import importlib,importlib.metadata,json,platform,sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "[importlib.import_module(name) for name in json.loads(sys.argv[2])];"
        "print(json.dumps({'base_prefix':sys.base_prefix,'distributions':"
        "{name:importlib.metadata.version(name) for name in json.loads(sys.argv[3])},"
        "'dont_write_bytecode':sys.flags.dont_write_bytecode,'isolated':"
        "sys.flags.isolated,'machine':platform.machine(),'no_site':sys.flags.no_site,"
        "'prefix':sys.prefix,'safe_path':sys.flags.safe_path,'system':platform.system(),"
        "'version':list(sys.version_info[:3])},sort_keys=True,separators=(',',':')))"
    )
    probe_environment = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TEMP": str(scratch_root),
        "TMP": str(scratch_root),
        "TMPDIR": str(scratch_root),
    }
    try:
        probe_output = subprocess.run(  # noqa: S603 - exact authenticated CPython executable
            (
                str(python_path),
                "-I",
                "-B",
                "-S",
                "-c",
                probe_script,
                str(site_packages),
                json.dumps(required_imports),
                json.dumps([name for name, _version in distribution_versions]),
            ),
            cwd=snapshot_root,
            check=True,
            capture_output=True,
            text=True,
            env=probe_environment,
            timeout=30,
        )
        identity = json.loads(probe_output.stdout)
        expected_prefix = str(interpreter_root.resolve(strict=True))
    except (
        OSError,
        subprocess.SubprocessError,
        json.JSONDecodeError,
    ) as error:
        raise RunnerTrustError("authenticated runner import probe failed") from error
    if (
        not isinstance(identity, dict)
        or set(identity)
        != {
            "base_prefix",
            "distributions",
            "dont_write_bytecode",
            "isolated",
            "machine",
            "no_site",
            "prefix",
            "safe_path",
            "system",
            "version",
        }
        or identity.get("version") != [3, 12, 13]
        or identity.get("prefix") != expected_prefix
        or identity.get("base_prefix") != expected_prefix
        or identity.get("system") != platform.system()
        or str(identity.get("machine", "")).casefold() != platform.machine().casefold()
        or identity.get("isolated") != 1
        or identity.get("no_site") != 1
        or identity.get("dont_write_bytecode") != 1
        or identity.get("safe_path") is not True
        or identity.get("distributions") != dict(distribution_versions)
        or len(probe_output.stdout) + len(probe_output.stderr) > 16 * 1024
        or not _same_uv_binding(resolve_pinned_uv(), uv)
        or host_tool_binding() != host_tool
        or bind_executable(python_path, required_root=interpreter_root) != python_binding
    ):
        raise RunnerTrustError("authenticated runner identity is not exact")
    environment_sha256 = tree_digest(
        root,
        excluded_relative_paths=excluded_tree_paths,
        mutable_child_directories=mutable_child_directories,
    )
    if environment_sha256 is None:
        raise RunnerTrustError("authenticated runner environment cannot be bound")
    runner = AuthenticatedRunner(
        root=root,
        snapshot_root=snapshot_root,
        python_path=python_path,
        site_packages=site_packages,
        interpreter_root=interpreter_root,
        scratch_root=scratch_root,
        uv=uv,
        python=python_binding,
        python_artifact_sha256=python_artifact_sha256,
        host_tool=host_tool,
        python_version=RUNNER_PYTHON_FULL_VERSION,
        lock_sha256=lock_sha256,
        artifact_set_sha256=artifact_set_sha256,
        environment_sha256=environment_sha256,
        excluded_tree_paths=excluded_tree_paths,
        distribution_versions=distribution_versions,
        mutable_child_directories=mutable_child_directories,
    )
    if not runner_is_unchanged(runner):
        raise RunnerTrustError("authenticated runner changed during preparation")
    return runner


def _runner_directories_are_trusted(runner: AuthenticatedRunner) -> bool:
    invoking_uid = os.getuid()
    allowed_owner_uids = frozenset({invoking_uid})
    try:
        root = runner.root.resolve(strict=True)
        directories = (
            runner.root,
            runner.snapshot_root,
            runner.interpreter_root,
            runner.site_packages,
            runner.scratch_root,
        )
        resolved_directories = tuple(path.resolve(strict=True) for path in directories)
        python_path = runner.python_path.resolve(strict=True)
    except OSError:
        return False
    resolved_interpreter = resolved_directories[2]
    if any(
        resolved != root and not resolved.is_relative_to(root) for resolved in resolved_directories
    ) or not python_path.is_relative_to(resolved_interpreter):
        return False
    return all(
        _trusted_directory_chain(
            path,
            allowed_owner_uids=allowed_owner_uids,
            stop=runner.root,
        )
        for path in directories
    )


def runner_is_unchanged(runner: AuthenticatedRunner) -> bool:
    """Rebind the host tool, interpreter, lock, and complete private runner tree."""

    try:
        directories_are_trusted = _runner_directories_are_trusted(runner)
        discovered_uv = resolve_pinned_uv()
        direct_uv = resolve_pinned_uv(runner.uv.executable.lexical_path)
        python = bind_executable(runner.python_path, required_root=runner.interpreter_root)
        lock_bytes = stable_regular_bytes(
            runner.snapshot_root / "uv.lock",
            maximum_bytes=16 * 1024 * 1024,
        )
        python_artifact = PINNED_PYTHON_ARTIFACTS.get(
            (platform.system().casefold(), platform.machine().casefold())
        )
        return (
            python_artifact is not None
            and python_artifact[3] == runner.python_artifact_sha256
            and directories_are_trusted
            and _same_uv_binding(discovered_uv, runner.uv)
            and _same_uv_binding(direct_uv, runner.uv)
            and host_tool_binding() == runner.host_tool
            and python is not None
            and python == runner.python
            and lock_bytes is not None
            and sha256_bytes(lock_bytes) == runner.lock_sha256
            and tree_digest(
                runner.root,
                excluded_relative_paths=runner.excluded_tree_paths,
                mutable_child_directories=runner.mutable_child_directories,
            )
            == runner.environment_sha256
        )
    except (OSError, RunnerTrustError):
        return False
