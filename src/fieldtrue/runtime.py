"""Runtime identity bound into every execution receipt."""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import os
import platform
import site
import stat
import subprocess
import sys
import sysconfig
import tomllib
from collections import deque
from contextlib import suppress
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Final, Literal

from packaging.markers import InvalidMarker, Marker
from packaging.utils import canonicalize_name
from pydantic import (
    BaseModel,
    ConfigDict,
    SerializerFunctionWrapHandler,
    ValidationError,
    model_serializer,
    model_validator,
)
from pydantic_core import PydanticSerializationError

from fieldtrue.canonical import sha256_bytes, sha256_value
from fieldtrue.domain import GitObjectId, Sha256
from fieldtrue.git_trust import git_environment, trusted_repository_git

_PROVENANCE_STATE_LEGACY: Final = "legacy-unbound"
_PROVENANCE_STATE_OBSERVED: Final = "observed-v1"
_PROVENANCE_HASH_FIELDS: Final = (
    "python_interpreter_provenance_sha256",
    "startup_provenance_sha256",
    "environment_provenance_sha256",
    "fieldtrue_source_sha256",
    "loaded_module_closure_sha256",
    "dependency_closure_sha256",
)
_FORBIDDEN_STARTUP_ENVIRONMENT: Final = frozenset(
    {
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONCASEOK",
        "PYTHONEXECUTABLE",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONWARNINGS",
    }
)
_STARTUP_MODULES: Final = frozenset({"sitecustomize", "usercustomize"})
_MAX_ENVIRONMENT_ENTRIES: Final = 4096
_MAX_ENVIRONMENT_NAME_BYTES: Final = 256
_MAX_ENVIRONMENT_VALUE_BYTES: Final = 64 * 1024
_MAX_ENVIRONMENT_BYTES: Final = 4 * 1024 * 1024
_MAX_SOURCE_ENTRIES: Final = 4096
_MAX_SOURCE_BYTES: Final = 128 * 1024 * 1024
_MAX_MODULE_ENTRIES: Final = 8192
_MAX_MODULE_BYTES: Final = 512 * 1024 * 1024
_MAX_DEPENDENCY_COUNT: Final = 128
_MAX_DEPENDENCY_FILES: Final = 20_000
_MAX_DEPENDENCY_BYTES: Final = 512 * 1024 * 1024
_MAX_SINGLE_FILE_BYTES: Final = 128 * 1024 * 1024
_MAX_RECORD_BYTES: Final = 16 * 1024 * 1024
_MAX_LOCK_BYTES: Final = 16 * 1024 * 1024
_STABLE_STAT_FIELDS: Final = (
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


class DirtyRepositoryError(RuntimeError):
    """A confirmatory run must not start from uncommitted code."""


class RuntimeProvenanceError(RuntimeError):
    """The running process cannot emit a bounded, uncontaminated identity."""


class RuntimeIdentity(BaseModel):
    """A receipt description, not proof against a compromised interpreter or OS TCB.

    Historical receipts parse as ``legacy-unbound``. New confirmatory authority must call
    :meth:`require_observed_provenance` and refuse that legacy state. ``observed-v1`` binds
    what this already-running process could inspect; it does not elevate self-observation
    into independent attestation.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        revalidate_instances="always",
        json_schema_extra={
            "allOf": [
                {
                    "oneOf": [
                        {
                            "properties": {
                                "provenance_state": {"const": _PROVENANCE_STATE_LEGACY},
                                **{field: {"type": "null"} for field in _PROVENANCE_HASH_FIELDS},
                            }
                        },
                        {
                            "properties": {
                                "provenance_state": {"const": _PROVENANCE_STATE_OBSERVED},
                                **{
                                    field: {
                                        "type": "string",
                                        "pattern": "^[0-9a-f]{64}$",
                                    }
                                    for field in _PROVENANCE_HASH_FIELDS
                                },
                            },
                            "required": ["provenance_state", *_PROVENANCE_HASH_FIELDS],
                        },
                    ]
                }
            ]
        },
    )

    git_commit: GitObjectId
    git_tree: GitObjectId
    repository_dirty: bool
    dirty_state_hash: Sha256
    lockfile_hash: Sha256
    python_version: str
    platform: str
    command: tuple[str, ...]
    provenance_state: Literal["legacy-unbound", "observed-v1"] = _PROVENANCE_STATE_LEGACY
    python_interpreter_provenance_sha256: Sha256 | None = None
    startup_provenance_sha256: Sha256 | None = None
    environment_provenance_sha256: Sha256 | None = None
    fieldtrue_source_sha256: Sha256 | None = None
    loaded_module_closure_sha256: Sha256 | None = None
    dependency_closure_sha256: Sha256 | None = None

    @model_validator(mode="after")
    def _consistent_provenance(self) -> RuntimeIdentity:
        hashes = tuple(getattr(self, field) for field in _PROVENANCE_HASH_FIELDS)
        if self.provenance_state == _PROVENANCE_STATE_LEGACY and any(
            value is not None for value in hashes
        ):
            raise ValueError("legacy-unbound runtime identity cannot claim provenance hashes")
        if self.provenance_state == _PROVENANCE_STATE_OBSERVED and any(
            value is None for value in hashes
        ):
            raise ValueError("observed-v1 runtime identity requires every provenance hash")
        return self

    @model_serializer(mode="wrap")
    def _serialize_compatible(
        self,
        handler: SerializerFunctionWrapHandler,
    ) -> dict[str, object]:
        value = handler(self)
        if not isinstance(value, dict):
            raise TypeError("runtime identity serializer must produce one object")
        if self.provenance_state == _PROVENANCE_STATE_LEGACY:
            value.pop("provenance_state", None)
            for field in _PROVENANCE_HASH_FIELDS:
                value.pop(field, None)
        return value

    def require_observed_provenance(self) -> None:
        """Refuse a historical identity at a new confirmatory authority boundary."""

        try:
            value = self.model_dump(
                mode="python",
                round_trip=True,
                warnings="error",
            )
            validated = RuntimeIdentity.model_validate(value, strict=True)
        except (PydanticSerializationError, ValidationError) as error:
            raise RuntimeProvenanceError(
                "runtime identity failed full strict provenance revalidation"
            ) from error
        if validated.provenance_state != _PROVENANCE_STATE_OBSERVED:
            raise RuntimeProvenanceError(
                "new confirmatory authority requires observed-v1 runtime provenance"
            )


@dataclass(frozen=True)
class _ObservedExecutionProvenance:
    python_interpreter_provenance_sha256: str
    startup_provenance_sha256: str
    environment_provenance_sha256: str
    fieldtrue_source_sha256: str
    loaded_module_closure_sha256: str
    dependency_closure_sha256: str


def _git(repo_root: Path, git: str, *arguments: str, exact: bool = False) -> str:
    completed = subprocess.run(  # noqa: S603 - callers supply fixed internal Git commands
        [git, *arguments],
        cwd=repo_root,
        check=True,
        capture_output=True,
        env=git_environment(),
        timeout=10,
        text=True,
    )
    return completed.stdout if exact else completed.stdout.strip()


def _stable_regular_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    if maximum_bytes < 0 or not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeProvenanceError("stable no-follow file reads are unavailable")
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum_bytes
        ):
            raise RuntimeProvenanceError("runtime provenance file is unsafe or exceeds its bound")
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(descriptor)
        if any(getattr(before, field) != getattr(opened, field) for field in _STABLE_STAT_FIELDS):
            raise RuntimeProvenanceError("runtime provenance file changed before it was opened")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        current = path.lstat()
    except RuntimeProvenanceError:
        raise
    except OSError as error:
        raise RuntimeProvenanceError("runtime provenance file cannot be read") from error
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
    if (
        len(data) > maximum_bytes
        or len(data) != before.st_size
        or any(getattr(before, field) != getattr(after, field) for field in _STABLE_STAT_FIELDS)
        or any(getattr(after, field) != getattr(current, field) for field in _STABLE_STAT_FIELDS)
    ):
        raise RuntimeProvenanceError("runtime provenance file changed while it was read")
    return data


def _resolved_roots(repo_root: Path) -> tuple[tuple[str, Path], ...]:
    candidates = (
        ("repository", repo_root),
        ("environment", Path(sys.prefix)),
        ("base-runtime", Path(sys.base_prefix)),
    )
    roots: list[tuple[str, Path]] = []
    for label, candidate in candidates:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise RuntimeProvenanceError("runtime provenance root cannot be resolved") from error
        if not resolved.is_dir():
            raise RuntimeProvenanceError("runtime provenance root is not a directory")
        if all(resolved != existing for _, existing in roots):
            roots.append((label, resolved))
    return tuple(roots)


def _logical_path(path: Path, roots: tuple[tuple[str, Path], ...]) -> str:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeProvenanceError("runtime provenance path cannot be resolved") from error
    for label, root in roots:
        if resolved == root:
            return label
        if resolved.is_relative_to(root):
            return f"{label}/{resolved.relative_to(root).as_posix()}"
    raise RuntimeProvenanceError("loaded runtime code originates outside the bound closure")


def _logical_search_path(path: Path, roots: tuple[tuple[str, Path], ...]) -> dict[str, object]:
    try:
        resolved = path.resolve(strict=False)
    except OSError as error:
        raise RuntimeProvenanceError("Python search path cannot be normalized") from error
    for label, root in roots:
        if resolved == root or resolved.is_relative_to(root):
            suffix = "" if resolved == root else f"/{resolved.relative_to(root).as_posix()}"
            return {"path": f"{label}{suffix}", "exists": resolved.exists()}
    raise RuntimeProvenanceError("Python search path escapes the bound runtime closure")


def _snapshot_environment() -> tuple[tuple[str, str], ...]:
    entries = tuple(sorted(os.environ.items()))
    if len(entries) > _MAX_ENVIRONMENT_ENTRIES:
        raise RuntimeProvenanceError("process environment exceeds the provenance entry bound")
    total = 0
    for name, value in entries:
        try:
            name_size = len(name.encode("utf-8"))
            value_size = len(value.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise RuntimeProvenanceError("process environment is not strict UTF-8") from error
        if (
            not name
            or name_size > _MAX_ENVIRONMENT_NAME_BYTES
            or value_size > _MAX_ENVIRONMENT_VALUE_BYTES
        ):
            raise RuntimeProvenanceError("process environment exceeds the provenance field bound")
        total += name_size + value_size
    if total > _MAX_ENVIRONMENT_BYTES:
        raise RuntimeProvenanceError("process environment exceeds the provenance byte bound")
    contaminated = sorted(
        name for name, value in entries if name in _FORBIDDEN_STARTUP_ENVIRONMENT and value
    )
    if contaminated:
        raise RuntimeProvenanceError(
            "runtime startup environment is contaminated: " + ", ".join(contaminated)
        )
    return entries


def _environment_provenance(entries: tuple[tuple[str, str], ...]) -> str:
    return sha256_value(
        {
            "schema_version": "inbar.runtime-environment-observation.v1",
            "entries": [
                {
                    "name_sha256": sha256_bytes(name.encode("utf-8")),
                    "value_sha256": sha256_bytes(value.encode("utf-8")),
                    "value_bytes": len(value.encode("utf-8")),
                }
                for name, value in entries
            ],
        }
    )


def _callable_identity(value: object) -> dict[str, str]:
    value_type = type(value)
    return {
        "module": str(getattr(value, "__module__", value_type.__module__)),
        "qualname": str(getattr(value, "__qualname__", value_type.__qualname__)),
        "type_module": value_type.__module__,
        "type_qualname": value_type.__qualname__,
    }


def _startup_provenance(
    repo_root: Path,
    roots: tuple[tuple[str, Path], ...],
) -> str:
    contaminated = sorted(name for name in _STARTUP_MODULES if name in sys.modules)
    if contaminated:
        raise RuntimeProvenanceError(
            "unbound Python startup module was loaded: " + ", ".join(contaminated)
        )
    try:
        current_directory = Path.cwd().resolve(strict=True)
        expected_directory = repo_root.resolve(strict=True)
    except OSError as error:
        raise RuntimeProvenanceError("runtime working directory cannot be resolved") from error
    if current_directory != expected_directory:
        raise RuntimeProvenanceError("runtime identity must be collected from the repository root")

    search_paths: list[dict[str, object]] = []
    for raw_path in sys.path:
        candidate = current_directory if raw_path == "" else Path(raw_path)
        search_paths.append(_logical_search_path(candidate, roots))

    site_directories: set[Path] = set()
    try:
        for raw_path in site.getsitepackages():
            site_directories.add(Path(raw_path))
    except AttributeError:
        pass
    for raw_path in sys.path:
        if raw_path and Path(raw_path).name in {"site-packages", "dist-packages"}:
            site_directories.add(Path(raw_path))
    pth_files: list[dict[str, object]] = []
    pth_bytes = 0
    for directory in sorted(site_directories, key=lambda item: str(item)):
        if not directory.exists():
            continue
        try:
            candidates = sorted(directory.glob("*.pth"), key=lambda item: item.name)
        except OSError as error:
            raise RuntimeProvenanceError(
                "Python startup path files cannot be enumerated"
            ) from error
        for candidate in candidates:
            data = _stable_regular_bytes(candidate, maximum_bytes=1024 * 1024)
            pth_bytes += len(data)
            if pth_bytes > 16 * 1024 * 1024:
                raise RuntimeProvenanceError("Python startup path files exceed the byte bound")
            pth_files.append(
                {
                    "path": _logical_path(candidate, roots),
                    "sha256": sha256_bytes(data),
                    "size": len(data),
                }
            )

    flag_names = (
        "debug",
        "inspect",
        "interactive",
        "optimize",
        "dont_write_bytecode",
        "no_user_site",
        "no_site",
        "ignore_environment",
        "verbose",
        "bytes_warning",
        "quiet",
        "hash_randomization",
        "isolated",
        "dev_mode",
        "utf8_mode",
        "warn_default_encoding",
        "safe_path",
        "int_max_str_digits",
    )
    return sha256_value(
        {
            "schema_version": "inbar.runtime-startup-observation.v1",
            "flags": {name: getattr(sys.flags, name) for name in flag_names},
            "meta_path": [_callable_identity(value) for value in sys.meta_path],
            "path_hooks": [_callable_identity(value) for value in sys.path_hooks],
            "search_paths": search_paths,
            "path_files": pth_files,
            "user_site_enabled": site.ENABLE_USER_SITE,
            "argv_sha256": sha256_value(tuple(sys.argv)),
        }
    )


def _executable_manifest(path: Path, roots: tuple[tuple[str, Path], ...]) -> dict[str, object]:
    try:
        lexical = path.absolute()
        before = lexical.lstat()
        link_target = os.readlink(lexical) if stat.S_ISLNK(before.st_mode) else None
        resolved = lexical.resolve(strict=True)
        data = _stable_regular_bytes(resolved, maximum_bytes=_MAX_SINGLE_FILE_BYTES)
        current = lexical.lstat()
        current_link = os.readlink(lexical) if stat.S_ISLNK(current.st_mode) else None
    except RuntimeProvenanceError:
        raise
    except OSError as error:
        raise RuntimeProvenanceError("Python executable closure cannot be read") from error
    if any(getattr(before, field) != getattr(current, field) for field in _STABLE_STAT_FIELDS):
        raise RuntimeProvenanceError("Python executable path changed while it was observed")
    if link_target != current_link:
        raise RuntimeProvenanceError("Python executable link changed while it was observed")
    return {
        "logical_path_sha256": sha256_bytes(str(lexical).encode("utf-8")),
        "resolved_path": _logical_path(resolved, roots),
        "sha256": sha256_bytes(data),
        "size": len(data),
        "link_target_sha256": (
            sha256_bytes(link_target.encode("utf-8")) if link_target is not None else None
        ),
    }


def _interpreter_provenance(roots: tuple[tuple[str, Path], ...]) -> str:
    raw_paths = [Path(sys.executable)]
    base_executable = getattr(sys, "_base_executable", None)
    if isinstance(base_executable, str) and base_executable:
        raw_paths.append(Path(base_executable))
    library_candidates = []
    library_directory = sysconfig.get_config_var("LIBDIR")
    library_name = sysconfig.get_config_var("LDLIBRARY")
    if isinstance(library_directory, str) and isinstance(library_name, str):
        library_candidates.append(Path(library_directory) / library_name)
    framework = sysconfig.get_config_var("PYTHONFRAMEWORK")
    if isinstance(framework, str) and framework:
        library_candidates.append(Path(sys.base_prefix) / framework)
    raw_paths.extend(path for path in library_candidates if path.is_file())

    manifests: list[dict[str, object]] = []
    seen: set[Path] = set()
    for path in raw_paths:
        try:
            lexical = path.absolute()
            path.resolve(strict=True)
        except OSError as error:
            raise RuntimeProvenanceError("Python interpreter path cannot be resolved") from error
        if lexical in seen:
            continue
        seen.add(lexical)
        manifests.append(_executable_manifest(path, roots))
    if not manifests:
        raise RuntimeProvenanceError("Python interpreter closure is empty")
    return sha256_value(
        {
            "schema_version": "inbar.runtime-interpreter-observation.v1",
            "implementation": platform.python_implementation(),
            "version": tuple(sys.version_info[:3]),
            "cache_tag": sys.implementation.cache_tag,
            "executables": manifests,
        }
    )


def _tree_provenance(root: Path) -> str:
    try:
        root = root.resolve(strict=True)
    except OSError as error:
        raise RuntimeProvenanceError("fieldtrue source root cannot be resolved") from error
    if not root.is_dir():
        raise RuntimeProvenanceError("fieldtrue source root is not a directory")
    directories = [root]
    entries: list[dict[str, object]] = []
    total_bytes = 0
    discovered = 0
    while directories:
        current = directories.pop()
        try:
            with os.scandir(current) as children:
                ordered = sorted(children, key=lambda entry: entry.name)
        except OSError as error:
            raise RuntimeProvenanceError("fieldtrue source closure cannot be enumerated") from error
        for entry in ordered:
            discovered += 1
            if discovered > _MAX_SOURCE_ENTRIES:
                raise RuntimeProvenanceError("fieldtrue source closure exceeds the entry bound")
            try:
                entry_stat = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise RuntimeProvenanceError(
                    "fieldtrue source entry cannot be inspected"
                ) from error
            path = Path(entry.path)
            if stat.S_ISDIR(entry_stat.st_mode):
                directories.append(path)
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                raise RuntimeProvenanceError("fieldtrue source closure contains a nonregular entry")
            data = _stable_regular_bytes(path, maximum_bytes=_MAX_SINGLE_FILE_BYTES)
            total_bytes += len(data)
            if total_bytes > _MAX_SOURCE_BYTES:
                raise RuntimeProvenanceError("fieldtrue source closure exceeds the byte bound")
            entries.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": sha256_bytes(data),
                    "size": len(data),
                }
            )
    entries.sort(key=lambda entry: str(entry["path"]))
    return sha256_value(
        {"schema_version": "inbar.fieldtrue-source-observation.v1", "entries": entries}
    )


def _fieldtrue_source_provenance(repo_root: Path) -> str:
    expected_root = repo_root / "src" / "fieldtrue"
    try:
        executing_root = Path(__file__).resolve(strict=True).parent
        resolved_expected = expected_root.resolve(strict=True)
    except OSError as error:
        raise RuntimeProvenanceError("executing fieldtrue source cannot be resolved") from error
    if executing_root != resolved_expected:
        raise RuntimeProvenanceError(
            "executing fieldtrue source is outside the selected repository"
        )
    return _tree_provenance(resolved_expected)


def _marker_applies(raw_marker: object) -> bool:
    if raw_marker is None:
        return True
    if not isinstance(raw_marker, str) or len(raw_marker) > 4096:
        raise RuntimeProvenanceError("dependency lock contains an invalid marker")
    try:
        return Marker(raw_marker).evaluate()
    except (InvalidMarker, KeyError, TypeError, ValueError) as error:
        raise RuntimeProvenanceError("dependency lock marker cannot be evaluated") from error


def _locked_runtime_dependencies(lock_data: bytes) -> tuple[tuple[str, str], ...]:
    try:
        document = tomllib.loads(lock_data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RuntimeProvenanceError("dependency lock is not canonical UTF-8 TOML") from error
    packages = document.get("package")
    if document.get("version") != 1 or not isinstance(packages, list) or len(packages) > 512:
        raise RuntimeProvenanceError("dependency lock has an unsupported structure")
    package_rows: list[dict[str, object]] = []
    for value in packages:
        if not isinstance(value, dict):
            raise RuntimeProvenanceError("dependency lock package row is invalid")
        package_rows.append(value)
    roots = [row for row in package_rows if row.get("name") == "fieldtrue"]
    if len(roots) != 1 or roots[0].get("source") != {"editable": "."}:
        raise RuntimeProvenanceError("dependency lock does not identify one local fieldtrue root")
    dependencies = roots[0].get("dependencies")
    if not isinstance(dependencies, list):
        raise RuntimeProvenanceError("dependency lock omits fieldtrue runtime dependencies")

    queue: deque[object] = deque(dependencies)
    selected: dict[str, str] = {}
    while queue:
        requested = queue.popleft()
        if not isinstance(requested, dict) or not _marker_applies(requested.get("marker")):
            if isinstance(requested, dict):
                continue
            raise RuntimeProvenanceError("dependency lock edge is invalid")
        raw_name = requested.get("name")
        requested_version = requested.get("version")
        if not isinstance(raw_name, str):
            raise RuntimeProvenanceError("dependency lock edge omits a package name")
        name = canonicalize_name(raw_name)
        candidates = [
            row
            for row in package_rows
            if isinstance(row.get("name"), str)
            and canonicalize_name(str(row["name"])) == name
            and (requested_version is None or row.get("version") == requested_version)
        ]
        if len(candidates) != 1:
            raise RuntimeProvenanceError("dependency lock edge does not resolve uniquely")
        candidate = candidates[0]
        version = candidate.get("version")
        if not isinstance(version, str) or not version or len(version) > 128:
            raise RuntimeProvenanceError("dependency lock package version is invalid")
        previous = selected.get(name)
        if previous is not None:
            if previous != version:
                raise RuntimeProvenanceError("dependency lock selects conflicting package versions")
            continue
        selected[name] = version
        if len(selected) > _MAX_DEPENDENCY_COUNT:
            raise RuntimeProvenanceError("dependency closure exceeds the package bound")
        child_dependencies = candidate.get("dependencies", [])
        if not isinstance(child_dependencies, list):
            raise RuntimeProvenanceError("dependency lock package dependencies are invalid")
        queue.extend(child_dependencies)
    return tuple(sorted(selected.items()))


def _record_digest(raw_digest: str) -> bytes:
    if not raw_digest.startswith("sha256="):
        raise RuntimeProvenanceError("dependency RECORD uses an unsupported content hash")
    encoded = raw_digest.removeprefix("sha256=")
    if not encoded or len(encoded) > 128:
        raise RuntimeProvenanceError("dependency RECORD content hash is malformed")
    try:
        return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, binascii.Error) as error:
        raise RuntimeProvenanceError("dependency RECORD content hash is malformed") from error


def _distribution_name(distribution: metadata.Distribution) -> str:
    try:
        value = distribution.metadata["Name"]
    except KeyError as error:
        raise RuntimeProvenanceError("installed dependency metadata omits its name") from error
    if not isinstance(value, str):
        raise RuntimeProvenanceError("installed dependency metadata name is invalid")
    return value


def _dependency_record_candidate(
    base: Path,
    raw_path: str,
    *,
    runtime_prefix: Path,
) -> Path:
    logical = PurePosixPath(raw_path)
    components = raw_path.split("/")
    if (
        not raw_path
        or logical.is_absolute()
        or "\\" in raw_path
        or any(component in {"", "."} for component in components)
    ):
        raise RuntimeProvenanceError("installed dependency RECORD path is unsafe")
    script_parts = logical.parts
    is_console_script = ".." in script_parts
    if is_console_script and (
        len(script_parts) != 5
        or script_parts[:4] != ("..", "..", "..", "bin")
        or script_parts[4] in {"", ".", ".."}
    ):
        raise RuntimeProvenanceError("installed dependency RECORD traversal is unsafe")
    candidate = base.joinpath(*logical.parts)
    try:
        resolved_base = base.resolve(strict=True)
        resolved_prefix = runtime_prefix.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
    except OSError as error:
        raise RuntimeProvenanceError(
            "installed dependency RECORD file cannot be resolved"
        ) from error
    if is_console_script:
        if resolved_candidate != resolved_prefix / "bin" / script_parts[4]:
            raise RuntimeProvenanceError(
                "installed dependency console script escapes the runtime bin directory"
            )
    elif not resolved_candidate.is_relative_to(resolved_base):
        raise RuntimeProvenanceError(
            "installed dependency RECORD file escapes its installation root"
        )
    return candidate


def _distribution_manifest(
    distribution: metadata.Distribution,
    *,
    expected_name: str,
    expected_version: str,
    roots: tuple[tuple[str, Path], ...],
    runtime_prefix: Path | None = None,
) -> tuple[dict[str, object], int, int]:
    actual_name = _distribution_name(distribution)
    if canonicalize_name(actual_name) != expected_name or distribution.version != expected_version:
        raise RuntimeProvenanceError("installed dependency differs from the selected lock version")
    files = distribution.files
    if files is None or len(files) > _MAX_DEPENDENCY_FILES:
        raise RuntimeProvenanceError("installed dependency has no bounded RECORD file list")
    record_candidates = [path for path in files if path.as_posix().endswith(".dist-info/RECORD")]
    if len(record_candidates) != 1:
        raise RuntimeProvenanceError("installed dependency does not have exactly one RECORD")
    record_path = Path(str(distribution.locate_file(record_candidates[0])))
    record_data = _stable_regular_bytes(record_path, maximum_bytes=_MAX_RECORD_BYTES)
    try:
        rows = list(csv.reader(io.StringIO(record_data.decode("utf-8")), strict=True))
    except (UnicodeDecodeError, csv.Error) as error:
        raise RuntimeProvenanceError(
            "installed dependency RECORD is not valid UTF-8 CSV"
        ) from error
    if len(rows) != len(files) or len(rows) > _MAX_DEPENDENCY_FILES:
        raise RuntimeProvenanceError("installed dependency RECORD census is inconsistent")

    base = Path(str(distribution.locate_file(".")))
    selected_prefix = runtime_prefix or Path(sys.prefix)
    entries: list[dict[str, object]] = []
    names: set[str] = set()
    total_bytes = 0
    record_logical = record_candidates[0].as_posix()
    for row in rows:
        if len(row) != 3:
            raise RuntimeProvenanceError("installed dependency RECORD row is malformed")
        raw_path, raw_hash, raw_size = row
        if raw_path in names:
            raise RuntimeProvenanceError("installed dependency RECORD path is unsafe")
        names.add(raw_path)
        candidate = _dependency_record_candidate(
            base,
            raw_path,
            runtime_prefix=selected_prefix,
        )
        _logical_path(candidate, roots)
        data = _stable_regular_bytes(candidate, maximum_bytes=_MAX_SINGLE_FILE_BYTES)
        total_bytes += len(data)
        if total_bytes > _MAX_DEPENDENCY_BYTES:
            raise RuntimeProvenanceError("installed dependency exceeds the byte bound")
        if raw_path == record_logical:
            if raw_hash or raw_size:
                raise RuntimeProvenanceError("dependency RECORD must leave its own hash empty")
        else:
            if not raw_size.isascii() or not raw_size.isdigit() or int(raw_size) != len(data):
                raise RuntimeProvenanceError("installed dependency differs from its RECORD size")
            if _record_digest(raw_hash) != hashlib.sha256(data).digest():
                raise RuntimeProvenanceError("installed dependency differs from its RECORD hash")
        entries.append({"path": raw_path, "sha256": sha256_bytes(data), "size": len(data)})
    if names != {path.as_posix() for path in files}:
        raise RuntimeProvenanceError("installed dependency RECORD path census is inconsistent")
    entries.sort(key=lambda entry: str(entry["path"]))
    return (
        {
            "name": expected_name,
            "version": expected_version,
            "record_sha256": sha256_bytes(record_data),
            "files": entries,
        },
        len(entries),
        total_bytes,
    )


def _dependency_provenance(
    lock_data: bytes,
    roots: tuple[tuple[str, Path], ...],
) -> str:
    locked = _locked_runtime_dependencies(lock_data)
    installed: dict[str, list[metadata.Distribution]] = {}
    try:
        for distribution in metadata.distributions():
            name = str(canonicalize_name(_distribution_name(distribution)))
            if any(name == locked_name for locked_name, _ in locked):
                installed.setdefault(name, []).append(distribution)
    except (OSError, UnicodeError) as error:
        raise RuntimeProvenanceError(
            "installed dependency metadata cannot be enumerated"
        ) from error
    manifests: list[dict[str, object]] = []
    total_files = 0
    total_bytes = 0
    for name, version in locked:
        candidates = installed.get(name, [])
        if len(candidates) != 1:
            raise RuntimeProvenanceError("locked dependency is missing or installed more than once")
        manifest, file_count, byte_count = _distribution_manifest(
            candidates[0],
            expected_name=name,
            expected_version=version,
            roots=roots,
        )
        total_files += file_count
        total_bytes += byte_count
        if total_files > _MAX_DEPENDENCY_FILES or total_bytes > _MAX_DEPENDENCY_BYTES:
            raise RuntimeProvenanceError("dependency closure exceeds its aggregate bound")
        manifests.append(manifest)
    return sha256_value(
        {
            "schema_version": "inbar.runtime-dependency-observation.v1",
            "packages": manifests,
        }
    )


def _module_provenance(
    repo_root: Path,
    roots: tuple[tuple[str, Path], ...],
    *,
    modules: tuple[tuple[str, object], ...] | None = None,
) -> str:
    modules = tuple(sorted(sys.modules.items())) if modules is None else modules
    if len(modules) > _MAX_MODULE_ENTRIES:
        raise RuntimeProvenanceError("loaded module closure exceeds the entry bound")
    expected_fieldtrue_root = (repo_root / "src" / "fieldtrue").resolve(strict=True)
    file_cache: dict[Path, tuple[str, int]] = {}
    total_bytes = 0
    manifests: list[dict[str, object]] = []
    for name, module in modules:
        if not isinstance(name, str) or len(name.encode("utf-8")) > 512:
            raise RuntimeProvenanceError("loaded module name exceeds the provenance bound")
        if module is None:
            manifests.append({"name": name, "kind": "missing"})
            continue
        raw_file = getattr(module, "__file__", None)
        specification = getattr(module, "__spec__", None)
        origin = getattr(specification, "origin", None)
        if raw_file is None:
            if origin in {"built-in", "frozen"}:
                manifests.append({"name": name, "kind": str(origin)})
                continue
            namespace_paths = getattr(module, "__path__", None)
            if namespace_paths is not None:
                logical_paths = sorted(
                    _logical_path(Path(raw_path), roots) for raw_path in namespace_paths
                )
                manifests.append({"name": name, "kind": "namespace", "paths": logical_paths})
                continue
            if name == "__main__":
                manifests.append(
                    {
                        "name": name,
                        "kind": "runtime-entrypoint-memory",
                        "type": _callable_identity(module),
                    }
                )
                continue
            if isinstance(module, ModuleType):
                parent_name, separator, _ = name.rpartition(".")
                parent = sys.modules.get(parent_name) if separator else None
                parent_file = getattr(parent, "__file__", None)
                if not isinstance(parent_file, str) or not parent_file:
                    raise RuntimeProvenanceError(
                        f"loaded in-memory module has no bound origin: {name}"
                    )
                manifests.append(
                    {
                        "name": name,
                        "kind": "parent-generated",
                        "parent": parent_name,
                        "type": _callable_identity(module),
                    }
                )
                continue
            manifests.append(
                {
                    "name": name,
                    "kind": "memory-alias",
                    "type": _callable_identity(module),
                }
            )
            continue
        if not isinstance(raw_file, str) or not raw_file:
            raise RuntimeProvenanceError("loaded module file path is invalid")
        if raw_file.startswith("<") and raw_file.endswith(">"):
            if name != "__main__":
                raise RuntimeProvenanceError("loaded virtual module has no bound origin")
            manifests.append({"name": name, "kind": "virtual", "origin": raw_file})
            continue
        path = Path(raw_file)
        if name == "fieldtrue" or name.startswith("fieldtrue."):
            try:
                resolved = path.resolve(strict=True)
            except OSError as error:
                raise RuntimeProvenanceError(
                    "loaded fieldtrue module cannot be resolved"
                ) from error
            if not resolved.is_relative_to(expected_fieldtrue_root):
                raise RuntimeProvenanceError(
                    "loaded fieldtrue module is outside the selected repository"
                )
        try:
            resolved_path = path.resolve(strict=True)
        except OSError as error:
            raise RuntimeProvenanceError("loaded module file cannot be resolved") from error
        if resolved_path not in file_cache:
            data = _stable_regular_bytes(path, maximum_bytes=_MAX_SINGLE_FILE_BYTES)
            total_bytes += len(data)
            if total_bytes > _MAX_MODULE_BYTES:
                raise RuntimeProvenanceError("loaded module closure exceeds the byte bound")
            file_cache[resolved_path] = (sha256_bytes(data), len(data))
        digest, size = file_cache[resolved_path]
        manifest: dict[str, object] = {
            "name": name,
            "kind": "file",
            "path": _logical_path(path, roots),
            "sha256": digest,
            "size": size,
        }
        raw_cached = getattr(module, "__cached__", None)
        if isinstance(raw_cached, str) and raw_cached and Path(raw_cached).exists():
            cache_path = Path(raw_cached)
            resolved_cache = cache_path.resolve(strict=True)
            if resolved_cache not in file_cache:
                cache_data = _stable_regular_bytes(
                    cache_path,
                    maximum_bytes=_MAX_SINGLE_FILE_BYTES,
                )
                total_bytes += len(cache_data)
                if total_bytes > _MAX_MODULE_BYTES:
                    raise RuntimeProvenanceError("loaded module closure exceeds the byte bound")
                file_cache[resolved_cache] = (sha256_bytes(cache_data), len(cache_data))
            cache_digest, cache_size = file_cache[resolved_cache]
            manifest["cached"] = {
                "path": _logical_path(cache_path, roots),
                "sha256": cache_digest,
                "size": cache_size,
            }
        manifests.append(manifest)
    return sha256_value(
        {"schema_version": "inbar.loaded-module-observation.v1", "modules": manifests}
    )


def _observe_execution_provenance(
    repo_root: Path,
    *,
    lock_data: bytes,
    environment: tuple[tuple[str, str], ...],
) -> _ObservedExecutionProvenance:
    roots = _resolved_roots(repo_root)
    return _ObservedExecutionProvenance(
        python_interpreter_provenance_sha256=_interpreter_provenance(roots),
        startup_provenance_sha256=_startup_provenance(repo_root, roots),
        environment_provenance_sha256=_environment_provenance(environment),
        fieldtrue_source_sha256=_fieldtrue_source_provenance(repo_root),
        dependency_closure_sha256=_dependency_provenance(lock_data, roots),
        loaded_module_closure_sha256=_module_provenance(repo_root, roots),
    )


def collect_runtime_identity(
    repo_root: Path,
    *,
    command: tuple[str, ...],
    require_clean: bool = True,
) -> RuntimeIdentity:
    python_version = sys.version.split()[0]
    platform_identity = platform.platform()
    initial_environment = _snapshot_environment()
    git = trusted_repository_git(repo_root)
    commit = _git(repo_root, git, "rev-parse", "HEAD")
    tree = _git(repo_root, git, "rev-parse", f"{commit}^{{tree}}")
    status = _git(
        repo_root,
        git,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        exact=True,
    )
    dirty = bool(status)
    if require_clean and dirty:
        raise DirtyRepositoryError("confirmatory execution requires a clean Git worktree")
    lock_path = repo_root / "uv.lock"
    try:
        lock_data = _stable_regular_bytes(lock_path, maximum_bytes=_MAX_LOCK_BYTES)
    except RuntimeProvenanceError as error:
        if not lock_path.exists():
            raise FileNotFoundError("uv.lock must exist before execution") from error
        raise
    lockfile_hash = sha256_bytes(lock_data)
    provenance = _observe_execution_provenance(
        repo_root,
        lock_data=lock_data,
        environment=initial_environment,
    )

    trusted_repository_git(repo_root)
    final_commit = _git(repo_root, git, "rev-parse", "HEAD")
    final_status = _git(
        repo_root,
        git,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        exact=True,
    )
    try:
        final_lock_data = _stable_regular_bytes(lock_path, maximum_bytes=_MAX_LOCK_BYTES)
    except RuntimeProvenanceError as error:
        raise DirtyRepositoryError(
            "uv.lock changed while runtime identity was collected"
        ) from error
    final_environment = _snapshot_environment()
    final_provenance = _observe_execution_provenance(
        repo_root,
        lock_data=final_lock_data,
        environment=final_environment,
    )
    settled_environment = _snapshot_environment()
    if final_commit != commit:
        raise DirtyRepositoryError("Git HEAD changed while runtime identity was collected")
    if final_status != status:
        raise DirtyRepositoryError("Git worktree changed while runtime identity was collected")
    if final_lock_data != lock_data:
        raise DirtyRepositoryError("uv.lock changed while runtime identity was collected")
    if final_environment != initial_environment or settled_environment != initial_environment:
        raise RuntimeProvenanceError("process environment changed while identity was collected")
    if final_provenance != provenance:
        raise RuntimeProvenanceError("execution closure changed while identity was collected")
    return RuntimeIdentity(
        git_commit=commit,
        git_tree=tree,
        repository_dirty=dirty,
        dirty_state_hash=sha256_bytes(status.encode()),
        lockfile_hash=lockfile_hash,
        python_version=python_version,
        platform=platform_identity,
        command=command,
        provenance_state=_PROVENANCE_STATE_OBSERVED,
        python_interpreter_provenance_sha256=(provenance.python_interpreter_provenance_sha256),
        startup_provenance_sha256=provenance.startup_provenance_sha256,
        environment_provenance_sha256=provenance.environment_provenance_sha256,
        fieldtrue_source_sha256=provenance.fieldtrue_source_sha256,
        loaded_module_closure_sha256=provenance.loaded_module_closure_sha256,
        dependency_closure_sha256=provenance.dependency_closure_sha256,
    )
