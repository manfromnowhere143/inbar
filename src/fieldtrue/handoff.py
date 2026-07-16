"""Deterministic recovery context rendered from verified mission state."""

from __future__ import annotations

import html
import json
import math
import os
import stat
import sys
import unicodedata
from collections.abc import Sequence
from importlib.abc import MetaPathFinder
from importlib.machinery import ModuleSpec
from pathlib import Path, PurePosixPath
from types import CodeType, ModuleType
from typing import Any, Literal, NamedTuple, NoReturn, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

# Mission validation imports this lazily; bind it before freezing the authority closure.
import fieldtrue.verification as _verification_module
from fieldtrue.canonical import atomic_write, sha256_bytes, sha256_value
from fieldtrue.domain import GitObjectId, Identifier
from fieldtrue.memory import (
    MemoryEventType,
    MemoryStatus,
    ResearchMemoryRecord,
    load_memory_records_bytes,
)
from fieldtrue.mission import validate_mission
from fieldtrue.schemas import schema_documents

_LAZY_AUTHORITY_MODULES = (_verification_module,)
_HANDOFF_PATH = "HANDOFF.md"
_MEMORY_PATH = "memory/research_engine_extraction.jsonl"
_RENDERER_PATH = "src/fieldtrue/handoff.py"
_RENDERER_CONTRACT = "inbar.generated-handoff.v2"
_MAX_INPUT_BYTES = 16 * 1024 * 1024
_MAX_RECOVERY_INPUT_BYTES = 64 * 1024 * 1024
_MAX_RECOVERY_INPUT_DIRECTORIES = 4096
_MAX_RECOVERY_INPUT_ENTRIES = 8192
_MAX_RECOVERY_INPUT_FILES = 4096
_MAX_RECOVERY_INPUT_DEPTH = 64
_SOURCE_VERDICT_EVENT_ID = "iter001-public-substrate-verdict-v1"
_ENGINE_BOUNDARY_EVENT_ID = "future-research-engine-shortcut-v2-lessons-v1"
_LEGACY_CHECKPOINT_EVENT_ID = "iter001-shortcut-v2-implementation-checkpoint-v1"
_LEGACY_HANDOFF_EVENT_ID = "iter001-shortcut-v2-activation-gates-v1"
_RECOVERY_CHECKPOINT_CONTRACT = "inbar.handoff-checkpoint.v1"
_RECOVERY_HANDOFF_CONTRACT = "inbar.handoff-state.v1"
_RECOVERY_STAGE = "mission-handoff"
_EXPECTED_BOOTSTRAP_BLOCKERS = ("iter001-acquisition-contract",)
_EXPECTED_BOOTSTRAP_DETAIL = (
    "Iteration 001 acquisition contract failed: canonical control authority is not sealed"
)
RECOVERY_CHECKPOINT_ACTION = (
    "Hardened the deterministic Inbar recovery contract and verified its internal consistency."
)
RECOVERY_CHECKPOINT_OUTCOME = (
    "Recovery inputs and the blocked mission state are reproducibly bound to committed evidence."
)
RECOVERY_CHECKPOINT_AUTHORITY_EFFECT = (
    "No authority was granted; iter001-acquisition-contract remains blocked."
)
RECOVERY_HANDOFF_STATE = (
    "Inbar remains in bootstrap with iter001-acquisition-contract blocked and no mission "
    "authority active."
)
RECOVERY_HANDOFF_NEXT_ACTION = (
    "Complete and prospectively seal iter001-acquisition-contract before exercising any denied "
    "authority."
)
_SOURCE_PATHS = (
    "mission/contract.json",
    "mission/loop.json",
    "mission/name.json",
    "protocol/acquisition/iter001_contract.json",
)
_EXPECTED_MISSION_CHECK_IDS = (
    "owner-boundary",
    "active-identity",
    "execution-authority",
    "mission-stage",
    "research-engine-deferred",
    "publication-gates",
    "publication-transition-evidence",
    "gate-falsification",
    "gate-control-registry",
    "preregistration-first",
    "hypothesis-status",
    "iter001-acquisition-contract",
    "dataset-lock",
    "iteration-amendment-001",
    "verification-correction-001",
    "claim-registry",
    "research-memory",
    "research-memory-git-anchors",
    "signer-anchor",
    "schemas",
    "lockfile",
    "provider-independence",
)
_LEGACY_FORBIDDEN_ACTIONS = (
    "corpus admission",
    "target creation",
    "training",
    "cloud spend",
    "physical action",
    "truth release",
    "scientific verdict",
    "canonical seal",
    "publication",
)
_CANONICAL_FORBIDDEN_ACTIONS = (
    "production data access or download",
    "corpus admission",
    "target creation",
    "training",
    "GPU, cloud, paid provider, or other resource spend",
    "large dataset staging",
    "real-target evaluation",
    "physical action",
    (
        "flight, live spacecraft, live robot, destructive test, deployment, or other "
        "live-system command authority"
    ),
    "financial operation or transaction",
    "credential, secret, key, or allowance operation",
    "truth release",
    "scientific verdict",
    "active-diagnosis performance claim",
    "recovery or safety claim",
    "cross-hardware transfer claim",
    "product or economic-value claim",
    "customer or commercial claims",
    "canonical seal",
    "publication",
    "repository visibility, licensing, or public code release",
)
_RECOVERY_EXCLUDED_ROOTS = frozenset({".git", ".local", ".venv", "data", "dist"})
_RECOVERY_CACHE_DIRECTORIES = frozenset(
    {
        ".cache",
        ".hypothesis",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "htmlcov",
    }
)
_RECOVERY_CACHE_ROOT_FILES = frozenset({".coverage"})

try:
    _IMPORTED_RENDERER_BYTES: bytes | None = Path(__file__).resolve(strict=True).read_bytes()
except OSError:
    _IMPORTED_RENDERER_BYTES = None
_IMPORTED_MODULE_CODE = sys._getframe().f_code
_CANONICAL_REMAINING_GATES = (
    "signed mechanism ontology and biconditional prediction-key mappings",
    "closed mechanism-target and target-subset schemas before affected truth access",
    "signed extractor registry and complete feature inventories with opaque-media disposition",
    "signed census, fold, rule-registry, release-plan, and freeze receipts",
    (
        "dedicated per-job X25519 generation, possession preflight, isolation, atomic durable "
        "global salt claims, and demonstrable process and key destruction"
    ),
    (
        "atomic no-replace publication and complete prepared, publication, open, and "
        "phase-completion receipt chains"
    ),
    "global prediction barrier followed by fresh holdout-evaluation contexts without refitting",
    "independent full-registry recomputation and target-manifest commitment reveal",
    "V2 admission integration, new control-suite authority, and terminal binding",
    (
        "canonical fitted-execution wrapper for release receipt, operation count, time, "
        "resources, bytes, labor, and direct cost"
    ),
    (
        "signed target-independent input and provenance roots for selectors, features, local "
        "mappings, and chronology"
    ),
    (
        "prospective confirmation of candidate incident-list domains and final inner "
        "target-record shape"
    ),
)


class HandoffError(ValueError):
    """The recovery state cannot be rendered or does not match its generated form."""


class _BoundModuleSource(NamedTuple):
    name: str
    module: ModuleType
    repository_path: str
    imported_path: str
    imported_bytes: bytes
    loader_code: CodeType


class _RecoveryFileSnapshot(NamedTuple):
    path: str
    sha256: str
    size: int
    metadata: tuple[int, ...]


class _RecoveryDirectorySnapshot(NamedTuple):
    path: str
    entries: tuple[str, ...]
    metadata: tuple[int, ...]


class _RecoveryManifest(NamedTuple):
    files: tuple[_RecoveryFileSnapshot, ...]
    directories: tuple[_RecoveryDirectorySnapshot, ...]
    total_bytes: int
    total_entries: int


class _RejectUnboundFieldtrueImports(MetaPathFinder):
    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        del path, target
        if (
            fullname == "fieldtrue" or fullname.startswith("fieldtrue.")
        ) and fullname not in _BOUND_FIELDTRUE_MODULE_NAMES:
            raise HandoffError(f"unbound Fieldtrue module import during handoff: {fullname}")
        return None


def _capture_bound_fieldtrue_modules() -> tuple[_BoundModuleSource, ...]:
    imported_source_root = Path(__file__).resolve(strict=True).parents[1]
    captured: list[_BoundModuleSource] = []
    for name, module_value in sorted(sys.modules.items()):
        if name != "fieldtrue" and not name.startswith("fieldtrue."):
            continue
        if not isinstance(module_value, ModuleType):
            raise RuntimeError(f"loaded Fieldtrue module has no module object: {name}")
        module_path_value = getattr(module_value, "__file__", None)
        loader = getattr(getattr(module_value, "__spec__", None), "loader", None)
        get_code = getattr(loader, "get_code", None)
        if not isinstance(module_path_value, str) or not callable(get_code):
            raise RuntimeError(f"loaded Fieldtrue module has no source-code loader: {name}")
        module_path = Path(module_path_value).resolve(strict=True)
        try:
            source_relative = module_path.relative_to(imported_source_root)
        except ValueError as error:
            raise RuntimeError(
                f"loaded Fieldtrue module is outside the source root: {name}"
            ) from error
        if module_path.suffix != ".py":
            raise RuntimeError(f"loaded Fieldtrue module is not Python source: {name}")
        loader_code = get_code(name)
        if not isinstance(loader_code, CodeType):
            raise RuntimeError(f"loaded Fieldtrue module has no executable module code: {name}")
        captured.append(
            _BoundModuleSource(
                name=name,
                module=module_value,
                repository_path=(
                    PurePosixPath("src") / PurePosixPath(source_relative.as_posix())
                ).as_posix(),
                imported_path=str(module_path),
                imported_bytes=module_path.read_bytes(),
                loader_code=loader_code,
            )
        )
    if not captured or not any(item.name == __name__ for item in captured):
        raise RuntimeError("handoff authority module closure could not be captured")
    captured_names = {item.name for item in captured}
    required_names = {module.__name__ for module in _LAZY_AUTHORITY_MODULES}
    if not required_names <= captured_names:
        raise RuntimeError("lazy mission authority modules were not captured")
    return tuple(captured)


_BOUND_FIELDTRUE_MODULES = _capture_bound_fieldtrue_modules()
_BOUND_FIELDTRUE_MODULE_NAMES = frozenset(item.name for item in _BOUND_FIELDTRUE_MODULES)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _CheckpointValidation(_StrictModel):
    branch_coverage_percent: float = Field(ge=0.0, le=100.0)
    expected_blockers: list[Identifier]
    formatted_files_checked: int = Field(ge=0)
    lock_packages_resolved: int = Field(ge=0)
    mission_checks: int = Field(gt=0)
    mission_check_ids: list[Identifier] | None = None
    post_commit_test_seconds: float = Field(gt=0.0)
    python_3_11_shortcut_tests: int = Field(ge=0)
    python_3_14_shortcut_tests: int = Field(ge=0)
    reproducible_package_build: Literal["pass"]
    ruff: Literal["pass"]
    runtime_dependency_audit: Literal["no known vulnerabilities"]
    schemas: Literal["verified"]
    strict_mypy_source_files: int = Field(gt=0)
    tests_passed: int = Field(gt=0)
    tests_skipped: int = Field(ge=0)
    unexpected_blockers: list[Identifier]

    @model_validator(mode="after")
    def blocker_lists_are_unique(self) -> Self:
        if len(self.expected_blockers) != len(set(self.expected_blockers)):
            raise ValueError("checkpoint expected blockers must be unique")
        if len(self.unexpected_blockers) != len(set(self.unexpected_blockers)):
            raise ValueError("checkpoint unexpected blockers must be unique")
        if set(self.expected_blockers) & set(self.unexpected_blockers):
            raise ValueError("checkpoint blocker classes must be disjoint")
        if self.mission_check_ids is not None and len(self.mission_check_ids) != len(
            set(self.mission_check_ids)
        ):
            raise ValueError("checkpoint mission check IDs must be unique")
        return self


class _CheckpointPayload(_StrictModel):
    action: str = Field(min_length=1)
    authority_effect: str = Field(min_length=1)
    handoff_contract: Literal["inbar.handoff-checkpoint.v1"] | None = None
    implementation_commit: GitObjectId
    outcome: str = Field(min_length=1)
    validation: _CheckpointValidation


class _HandoffPayload(_StrictModel):
    forbidden_until_activation: list[str] = Field(min_length=1)
    handoff_contract: Literal["inbar.handoff-state.v1"] | None = None
    next_action: str = Field(min_length=1)
    remaining_gates: list[str] = Field(min_length=1)
    state: str = Field(min_length=1)

    @model_validator(mode="after")
    def lists_are_unique(self) -> Self:
        for label, values in (
            ("forbidden actions", self.forbidden_until_activation),
            ("remaining gates", self.remaining_gates),
        ):
            if len(values) != len(set(values)):
                raise ValueError(f"handoff {label} must be unique")
        if tuple(self.remaining_gates) != _CANONICAL_REMAINING_GATES:
            raise ValueError("handoff remaining gates differ from the canonical blocked set")
        return self


class _SourceVerdictPayload(_StrictModel):
    compute_consequence: str = Field(min_length=1)
    finding: Literal["KILL_PUBLIC_SUBSTRATE"]
    product_wedge: str = Field(min_length=1)
    source_architecture: list[str] = Field(min_length=1)


class _EngineBoundaryPayload(_StrictModel):
    build_timing: str = Field(min_length=1)
    finding: list[str] = Field(min_length=1)
    ownership: Literal["Daniel Wahnich"]
    system_boundary: str = Field(min_length=1)


def _directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise HandoffError("handoff snapshots require directory no-follow support")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise HandoffError("handoff snapshots require file no-follow support")
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


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


def _bounded_directory_names(descriptor: int, maximum: int, label: str) -> tuple[str, ...]:
    names: list[str] = []
    try:
        with os.scandir(descriptor) as entries:
            for entry in entries:
                if len(names) >= maximum:
                    raise HandoffError(f"{label} entry count exceeds the manifest limit")
                names.append(entry.name)
    except OSError as error:
        raise HandoffError(f"{label} cannot be enumerated") from error
    return tuple(sorted(names))


def _directory_snapshot(
    repo_root: Path, relative: str, label: str
) -> tuple[tuple[str, ...], tuple[int, ...]]:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {".", ".."} for part in pure.parts):
        raise HandoffError(f"{label} has an unsafe repository path")
    descriptor: int | None = None
    try:
        descriptor = os.open(repo_root, _directory_flags())
        for part in pure.parts:
            nested_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = nested_descriptor
    except OSError as error:
        if descriptor is not None:
            os.close(descriptor)
        raise HandoffError(f"{label} is unavailable or traverses a symbolic link") from error
    assert descriptor is not None
    try:
        before = os.fstat(descriptor)
        names = _bounded_directory_names(descriptor, _MAX_RECOVERY_INPUT_ENTRIES, label)
        after = os.fstat(descriptor)
    except OSError as error:
        raise HandoffError(f"{label} cannot be enumerated") from error
    finally:
        os.close(descriptor)
    if _stable_stat_fields(before) != _stable_stat_fields(after):
        raise HandoffError(f"{label} changed while being enumerated")
    return names, _stable_stat_fields(after)


def _read_regular_file_snapshot(
    repo_root: Path, relative: str, label: str
) -> tuple[bytes, tuple[int, ...]]:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or not pure.parts or any(part in {".", ".."} for part in pure.parts):
        raise HandoffError(f"{label} has an unsafe repository path")
    try:
        root_descriptor = os.open(repo_root, _directory_flags())
    except OSError as error:
        raise HandoffError(f"{label} is unavailable") from error
    parent_descriptor = os.dup(root_descriptor)
    os.close(root_descriptor)
    try:
        for part in pure.parts[:-1]:
            nested_descriptor = os.open(part, _directory_flags(), dir_fd=parent_descriptor)
            os.close(parent_descriptor)
            parent_descriptor = nested_descriptor
        descriptor = os.open(pure.parts[-1], _file_flags(), dir_fd=parent_descriptor)
    except OSError as error:
        os.close(parent_descriptor)
        raise HandoffError(f"{label} is unavailable or traverses a symbolic link") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise HandoffError(f"{label} must be a regular file")
        if before.st_nlink != 1:
            raise HandoffError(f"{label} must not be hard linked")
        if before.st_size > _MAX_INPUT_BYTES:
            raise HandoffError(f"{label} exceeds the handoff input limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(_MAX_INPUT_BYTES + 1)
        after = os.fstat(descriptor)
        current = os.stat(pure.parts[-1], dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError as error:
        raise HandoffError(f"{label} cannot be read") from error
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)
    stable_state = (
        _stable_stat_fields(before) == _stable_stat_fields(after) == _stable_stat_fields(current)
    )
    if (
        not stable_state
        or not stat.S_ISREG(current.st_mode)
        or len(data) != before.st_size
        or len(data) > _MAX_INPUT_BYTES
    ):
        raise HandoffError(f"{label} changed while being read")
    return data, _stable_stat_fields(after)


def _read_regular_file(repo_root: Path, relative: str, label: str) -> bytes:
    return _read_regular_file_snapshot(repo_root, relative, label)[0]


def _is_recovery_excluded(relative: PurePosixPath, *, directory: bool) -> bool:
    if not relative.parts:
        return False
    if relative.parts[0] in _RECOVERY_EXCLUDED_ROOTS:
        return True
    if directory and relative.name in _RECOVERY_CACHE_DIRECTORIES:
        return True
    path = relative.as_posix()
    if path in {_HANDOFF_PATH, _MEMORY_PATH}:
        return True
    return len(relative.parts) == 1 and relative.name in _RECOVERY_CACHE_ROOT_FILES


def _read_manifest_file(
    directory_descriptor: int,
    name: str,
    relative: PurePosixPath,
    initial: os.stat_result,
) -> tuple[_RecoveryFileSnapshot, int]:
    try:
        descriptor = os.open(name, _file_flags(), dir_fd=directory_descriptor)
    except OSError as error:
        raise HandoffError(
            f"recovery input is unavailable or traverses a symbolic link: {relative.as_posix()}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if _stable_stat_fields(initial) != _stable_stat_fields(before):
            raise HandoffError(f"recovery input changed before reading: {relative.as_posix()}")
        if not stat.S_ISREG(before.st_mode):
            raise HandoffError(f"recovery input must be a regular file: {relative.as_posix()}")
        if before.st_nlink != 1:
            raise HandoffError(f"recovery input must not be hard linked: {relative.as_posix()}")
        if before.st_size > _MAX_INPUT_BYTES:
            raise HandoffError(f"recovery input exceeds the per-file limit: {relative.as_posix()}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(_MAX_INPUT_BYTES + 1)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except OSError as error:
        raise HandoffError(f"recovery input cannot be read: {relative.as_posix()}") from error
    finally:
        os.close(descriptor)
    if (
        not (
            _stable_stat_fields(before)
            == _stable_stat_fields(after)
            == _stable_stat_fields(current)
        )
        or not stat.S_ISREG(current.st_mode)
        or current.st_nlink != 1
        or len(data) != before.st_size
        or len(data) > _MAX_INPUT_BYTES
    ):
        raise HandoffError(f"recovery input changed while being read: {relative.as_posix()}")
    return (
        _RecoveryFileSnapshot(
            path=relative.as_posix(),
            sha256=sha256_bytes(data),
            size=len(data),
            metadata=_stable_stat_fields(after),
        ),
        len(data),
    )


def _recovery_manifest(repo_root: Path) -> _RecoveryManifest:
    files: list[_RecoveryFileSnapshot] = []
    directories: list[_RecoveryDirectorySnapshot] = []
    total_bytes = 0
    total_entries = 0

    def walk(descriptor: int, relative: PurePosixPath, depth: int) -> None:
        nonlocal total_bytes, total_entries
        if depth > _MAX_RECOVERY_INPUT_DEPTH:
            raise HandoffError("recovery input depth exceeds the manifest limit")
        try:
            before = os.fstat(descriptor)
            label = relative.as_posix() or "."
            remaining_entries = _MAX_RECOVERY_INPUT_ENTRIES - total_entries
            names = _bounded_directory_names(descriptor, remaining_entries, label)
        except OSError as error:
            raise HandoffError(f"recovery directory cannot be enumerated: {label}") from error
        if not stat.S_ISDIR(before.st_mode):
            raise HandoffError("recovery input root must be a directory")
        total_entries += len(names)
        included_names: list[str] = []
        for name in names:
            child = relative / name if relative.parts else PurePosixPath(name)
            try:
                initial = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise HandoffError(
                    f"recovery input cannot be inspected: {child.as_posix()}"
                ) from error
            is_directory = stat.S_ISDIR(initial.st_mode)
            if _is_recovery_excluded(child, directory=is_directory):
                continue
            included_names.append(name)
            if is_directory:
                try:
                    nested_descriptor = os.open(name, _directory_flags(), dir_fd=descriptor)
                except OSError as error:
                    raise HandoffError(
                        f"recovery directory traverses a symbolic link: {child.as_posix()}"
                    ) from error
                try:
                    if _stable_stat_fields(os.fstat(nested_descriptor)) != _stable_stat_fields(
                        initial
                    ):
                        raise HandoffError(
                            f"recovery directory changed before traversal: {child.as_posix()}"
                        )
                    walk(nested_descriptor, child, depth + 1)
                finally:
                    os.close(nested_descriptor)
                current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if _stable_stat_fields(current) != _stable_stat_fields(initial):
                    raise HandoffError(
                        f"recovery directory changed during traversal: {child.as_posix()}"
                    )
            elif stat.S_ISREG(initial.st_mode):
                file_snapshot, size = _read_manifest_file(descriptor, name, child, initial)
                files.append(file_snapshot)
                total_bytes += size
                if len(files) > _MAX_RECOVERY_INPUT_FILES:
                    raise HandoffError("recovery input file count exceeds the manifest limit")
                if total_bytes > _MAX_RECOVERY_INPUT_BYTES:
                    raise HandoffError("recovery input bytes exceed the manifest limit")
            elif stat.S_ISLNK(initial.st_mode):
                raise HandoffError(f"recovery input traverses a symbolic link: {child.as_posix()}")
            else:
                raise HandoffError(
                    f"recovery input must be a regular file or directory: {child.as_posix()}"
                )
        try:
            final_names = _bounded_directory_names(descriptor, len(names), label)
            after = os.fstat(descriptor)
        except OSError as error:
            label = relative.as_posix() or "."
            raise HandoffError(f"recovery directory cannot be resnapshotted: {label}") from error
        if names != final_names or _stable_stat_fields(before) != _stable_stat_fields(after):
            label = relative.as_posix() or "."
            raise HandoffError(f"recovery directory changed during traversal: {label}")
        directories.append(
            _RecoveryDirectorySnapshot(
                path=relative.as_posix() or ".",
                entries=tuple(included_names),
                metadata=_stable_stat_fields(after),
            )
        )
        if len(directories) > _MAX_RECOVERY_INPUT_DIRECTORIES:
            raise HandoffError("recovery input directory count exceeds the manifest limit")

    try:
        root_descriptor = os.open(repo_root, _directory_flags())
    except OSError as error:
        raise HandoffError("recovery input root is unavailable") from error
    try:
        walk(root_descriptor, PurePosixPath(), 0)
    finally:
        os.close(root_descriptor)
    return _RecoveryManifest(
        files=tuple(sorted(files, key=lambda item: item.path)),
        directories=tuple(sorted(directories, key=lambda item: item.path)),
        total_bytes=total_bytes,
        total_entries=total_entries,
    )


def _loaded_fieldtrue_module_names() -> frozenset[str]:
    return frozenset(
        name
        for name, module in sys.modules.items()
        if (name == "fieldtrue" or name.startswith("fieldtrue.")) and isinstance(module, ModuleType)
    )


def _verify_bound_module_sources(repo_root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for binding in _BOUND_FIELDTRUE_MODULES:
        if sys.modules.get(binding.name) is not binding.module:
            raise HandoffError(f"bound Fieldtrue module identity changed: {binding.name}")
        source = _read_regular_file(
            repo_root,
            binding.repository_path,
            f"bound module {binding.name}",
        )
        if source != binding.imported_bytes:
            if binding.name == __name__:
                raise HandoffError(
                    "imported handoff renderer source differs from repository source"
                )
            raise HandoffError(
                f"imported Fieldtrue module source differs from repository source: {binding.name}"
            )
        try:
            compiled = compile(
                source,
                binding.imported_path,
                "exec",
                dont_inherit=True,
                optimize=sys.flags.optimize,
            )
        except (OSError, SyntaxError, ValueError) as error:
            raise HandoffError(
                f"repository Fieldtrue module source cannot be compiled: {binding.name}"
            ) from error
        if compiled != binding.loader_code:
            raise HandoffError(
                f"imported Fieldtrue module loader code differs from repository source: "
                f"{binding.name}"
            )
        if binding.name == __name__ and compiled != _IMPORTED_MODULE_CODE:
            raise HandoffError("executing handoff renderer code differs from repository source")
        hashes[binding.repository_path] = sha256_bytes(source)
    return hashes


def _verify_module_population(initial_names: frozenset[str]) -> None:
    current_names = _loaded_fieldtrue_module_names()
    new_unbound = sorted((current_names - initial_names) - _BOUND_FIELDTRUE_MODULE_NAMES)
    if new_unbound:
        raise HandoffError(
            "unbound Fieldtrue modules loaded during handoff rendering: " + ", ".join(new_unbound)
        )
    for binding in _BOUND_FIELDTRUE_MODULES:
        if sys.modules.get(binding.name) is not binding.module:
            raise HandoffError(f"bound Fieldtrue module identity changed: {binding.name}")


def _reject_nonfinite_json(value: str, label: str) -> NoReturn:
    raise HandoffError(f"{label} contains nonfinite JSON value {value}")


def _finite_json_float(value: str, label: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        _reject_nonfinite_json(value, label)
    return parsed


def _json_object(repo_root: Path, relative: str, label: str) -> tuple[dict[str, Any], bytes]:
    data = _read_regular_file(repo_root, relative, label)

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise HandoffError(f"{label} contains duplicate object keys")
            value[key] = item
        return value

    try:
        parsed = json.loads(
            data,
            object_pairs_hook=object_pairs,
            parse_constant=lambda value: _reject_nonfinite_json(value, label),
            parse_float=lambda value: _finite_json_float(value, label),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HandoffError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(parsed, dict):
        raise HandoffError(f"{label} must be a JSON object")
    return parsed, data


def _required_string(value: dict[str, Any], key: str, label: str) -> str:
    observed = value.get(key)
    if not isinstance(observed, str) or not observed:
        raise HandoffError(f"{label}.{key} must be a nonempty string")
    return _single_line(observed, f"{label}.{key}")


def _single_line(value: str, label: str) -> str:
    if not value or value != value.strip() or any(character in value for character in "\r\n"):
        raise HandoffError(f"{label} must be one trimmed line")
    if any(
        unicodedata.category(character).startswith("C")
        or unicodedata.category(character) in {"Zl", "Zp"}
        for character in value
    ):
        raise HandoffError(f"{label} contains a control character")
    return value


def _markdown_text(value: str) -> str:
    escaped = html.escape(value, quote=False).replace("\\", "\\\\")
    for character in "`*_{}[]#|":
        escaped = escaped.replace(character, f"\\{character}")
    return escaped


def _code_text(value: str) -> str:
    return html.escape(value, quote=False).replace("`", "&#96;")


def _validate_display_payloads(
    checkpoint: _CheckpointPayload,
    handoff: _HandoffPayload,
    source: _SourceVerdictPayload,
    engine: _EngineBoundaryPayload,
) -> None:
    values = [
        checkpoint.action,
        checkpoint.authority_effect,
        checkpoint.outcome,
        handoff.next_action,
        handoff.state,
        source.compute_consequence,
        source.product_wedge,
        engine.build_timing,
        engine.system_boundary,
        *handoff.forbidden_until_activation,
        *handoff.remaining_gates,
        *source.source_architecture,
        *engine.finding,
    ]
    for index, value in enumerate(values):
        _single_line(value, f"display value {index}")


def _reject_corrected_records(
    selected: tuple[ResearchMemoryRecord, ...],
    records: tuple[ResearchMemoryRecord, ...],
) -> None:
    corrections = {
        record.corrects_event_id
        for record in records
        if record.event_type == MemoryEventType.CORRECTION and record.corrects_event_id is not None
    }
    corrected = sorted(record.event_id for record in selected if record.event_id in corrections)
    if corrected:
        raise HandoffError(f"selected recovery events were corrected: {', '.join(corrected)}")


def _record_index(records: tuple[ResearchMemoryRecord, ...]) -> dict[str, ResearchMemoryRecord]:
    return {record.event_id: record for record in records}


def _latest_handoff(records: tuple[ResearchMemoryRecord, ...]) -> ResearchMemoryRecord:
    candidates = [
        record
        for record in records
        if record.mission_id == "inbar" and record.event_type == MemoryEventType.HANDOFF
    ]
    if not candidates:
        raise HandoffError("research memory has no Inbar handoff event")
    record = max(candidates, key=lambda item: item.sequence)
    if record.status != MemoryStatus.BLOCKED:
        raise HandoffError("latest Inbar handoff must preserve blocked activation state")
    return record


def _linked_checkpoint(
    handoff: ResearchMemoryRecord,
    records: dict[str, ResearchMemoryRecord],
) -> ResearchMemoryRecord:
    checkpoint_id = handoff.links.get("checkpoint")
    if checkpoint_id is None:
        raise HandoffError("latest Inbar handoff does not link a checkpoint")
    checkpoint = records.get(checkpoint_id)
    if checkpoint is None or checkpoint.sequence >= handoff.sequence:
        raise HandoffError("latest Inbar handoff checkpoint link is not an earlier event")
    if checkpoint.event_type != MemoryEventType.EXECUTION or checkpoint.status != MemoryStatus.PASS:
        raise HandoffError("latest Inbar handoff must link a passing execution checkpoint")
    return checkpoint


def _exact_event(
    records: dict[str, ResearchMemoryRecord],
    event_id: str,
    *,
    event_type: MemoryEventType,
    status: MemoryStatus,
) -> ResearchMemoryRecord:
    record = records.get(event_id)
    if record is None or record.event_type != event_type or record.status != status:
        raise HandoffError(f"required research-memory event is invalid: {event_id}")
    return record


def _parse_payload(model: type[_StrictModel], payload: dict[str, Any], label: str) -> _StrictModel:
    try:
        return model.model_validate(payload)
    except ValidationError as error:
        raise HandoffError(f"{label} payload violates its exact contract") from error


def _require_recovery_evidence(
    record: ResearchMemoryRecord,
    implementation_commit: str,
    required_roles: frozenset[str],
) -> None:
    observed_roles = {evidence.role for evidence in record.evidence}
    if not required_roles <= observed_roles:
        raise HandoffError(f"{record.event_id} lacks required Git-anchored evidence roles")
    for evidence in record.evidence:
        if (
            urlsplit(evidence.uri).scheme
            or evidence.git_commit != implementation_commit
            or evidence.sha256 is None
        ):
            raise HandoffError(f"{record.event_id} recovery evidence is not commit and byte bound")


def _validate_recovery_contract(
    handoff_record: ResearchMemoryRecord,
    checkpoint_record: ResearchMemoryRecord,
    handoff: _HandoffPayload,
    checkpoint: _CheckpointPayload,
) -> bool:
    for record in (checkpoint_record, handoff_record):
        if record.mission_id != "inbar" or record.schema_version != "daniel.research-memory.v2":
            raise HandoffError("recovery records must use the current Inbar memory identity")
    legacy_pair = (
        checkpoint_record.event_id == _LEGACY_CHECKPOINT_EVENT_ID
        and handoff_record.event_id == _LEGACY_HANDOFF_EVENT_ID
    )
    if legacy_pair:
        if (
            checkpoint_record.stage != "iter001-shortcut-v2-implementation"
            or handoff_record.stage != "iter001-shortcut-v2-implementation"
            or checkpoint.handoff_contract is not None
            or handoff.handoff_contract is not None
            or tuple(handoff.forbidden_until_activation) != _LEGACY_FORBIDDEN_ACTIONS
            or set(handoff_record.links) != {"checkpoint"}
        ):
            raise HandoffError("legacy recovery pair differs from its frozen contract")
    elif (
        checkpoint_record.stage != _RECOVERY_STAGE
        or handoff_record.stage != _RECOVERY_STAGE
        or checkpoint.handoff_contract != _RECOVERY_CHECKPOINT_CONTRACT
        or handoff.handoff_contract != _RECOVERY_HANDOFF_CONTRACT
        or checkpoint.validation.mission_check_ids is None
        or checkpoint.action != RECOVERY_CHECKPOINT_ACTION
        or checkpoint.outcome != RECOVERY_CHECKPOINT_OUTCOME
        or checkpoint.authority_effect != RECOVERY_CHECKPOINT_AUTHORITY_EFFECT
        or handoff.state != RECOVERY_HANDOFF_STATE
        or handoff.next_action != RECOVERY_HANDOFF_NEXT_ACTION
        or tuple(handoff.forbidden_until_activation) != _CANONICAL_FORBIDDEN_ACTIONS
        or handoff_record.links
        != {
            "checkpoint": checkpoint_record.event_id,
            "engine_boundary": _ENGINE_BOUNDARY_EVENT_ID,
            "source_verdict": _SOURCE_VERDICT_EVENT_ID,
        }
    ):
        raise HandoffError("latest recovery pair lacks the versioned handoff contract")
    _require_recovery_evidence(
        checkpoint_record,
        checkpoint.implementation_commit,
        frozenset({"source", "verifier"}),
    )
    _require_recovery_evidence(
        handoff_record,
        checkpoint.implementation_commit,
        frozenset({"source"}),
    )
    return legacy_pair


def _render(repo_root: Path) -> bytes:
    initial_module_names = _loaded_fieldtrue_module_names()
    bound_module_hashes = _verify_bound_module_sources(repo_root)
    recovery_manifest = _recovery_manifest(repo_root)
    sources: dict[str, dict[str, Any]] = {}
    source_bytes: dict[str, bytes] = {}
    source_hashes: dict[str, str] = {}
    for relative in _SOURCE_PATHS:
        source_value, data = _json_object(repo_root, relative, relative)
        sources[relative] = source_value
        source_bytes[relative] = data
        source_hashes[relative] = sha256_bytes(data)

    renderer_bytes = _read_regular_file(repo_root, _RENDERER_PATH, _RENDERER_PATH)
    if _IMPORTED_RENDERER_BYTES is None:
        raise HandoffError("imported handoff renderer source bytes are unavailable")
    if renderer_bytes != _IMPORTED_RENDERER_BYTES:
        raise HandoffError("imported handoff renderer source differs from repository source")
    try:
        compiled_renderer = compile(
            renderer_bytes,
            str(Path(__file__).resolve(strict=True)),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
    except (OSError, SyntaxError, ValueError) as error:
        raise HandoffError("repository handoff renderer source cannot be compiled") from error
    if compiled_renderer != _IMPORTED_MODULE_CODE:
        raise HandoffError("executing handoff renderer code differs from repository source")
    renderer_hash = sha256_bytes(renderer_bytes)

    memory_bytes = _read_regular_file(repo_root, _MEMORY_PATH, _MEMORY_PATH)
    try:
        records = load_memory_records_bytes(memory_bytes)
    except ValueError as error:
        raise HandoffError("research memory is invalid") from error
    if not records:
        raise HandoffError("research memory is empty")
    by_id = _record_index(records)
    handoff_record = _latest_handoff(records)
    checkpoint_record = _linked_checkpoint(handoff_record, by_id)
    checkpoint = _parse_payload(
        _CheckpointPayload, checkpoint_record.payload, "implementation checkpoint"
    )
    handoff = _parse_payload(_HandoffPayload, handoff_record.payload, "handoff")
    assert isinstance(checkpoint, _CheckpointPayload)
    assert isinstance(handoff, _HandoffPayload)
    legacy_recovery = _validate_recovery_contract(
        handoff_record, checkpoint_record, handoff, checkpoint
    )
    if not legacy_recovery and handoff_record.sequence != records[-1].sequence:
        raise HandoffError("versioned handoff must be the final research-memory event")
    source_record = _exact_event(
        by_id,
        handoff_record.links.get("source_verdict", _SOURCE_VERDICT_EVENT_ID),
        event_type=MemoryEventType.FINDING,
        status=MemoryStatus.NEGATIVE,
    )
    engine_record = _exact_event(
        by_id,
        handoff_record.links.get("engine_boundary", _ENGINE_BOUNDARY_EVENT_ID),
        event_type=MemoryEventType.FINDING,
        status=MemoryStatus.RECORDED,
    )
    _reject_corrected_records(
        (handoff_record, checkpoint_record, source_record, engine_record), records
    )

    source = _parse_payload(_SourceVerdictPayload, source_record.payload, "source verdict")
    engine = _parse_payload(_EngineBoundaryPayload, engine_record.payload, "engine boundary")
    assert isinstance(source, _SourceVerdictPayload)
    assert isinstance(engine, _EngineBoundaryPayload)
    _validate_display_payloads(checkpoint, handoff, source, engine)
    for label, summary in (
        ("handoff summary", handoff_record.summary),
        ("checkpoint summary", checkpoint_record.summary),
        ("source verdict summary", source_record.summary),
        ("engine boundary summary", engine_record.summary),
    ):
        _single_line(summary, label)

    if checkpoint_record.source_commit != checkpoint.implementation_commit:
        raise HandoffError("checkpoint source commit differs from its implementation commit")
    if handoff_record.source_commit != checkpoint.implementation_commit:
        raise HandoffError("handoff source commit differs from its linked implementation commit")

    mission_report = validate_mission(repo_root)
    all_checks_passed = all(check.passed for check in mission_report.checks)
    if mission_report.passed != all_checks_passed:
        raise HandoffError("mission validation aggregate is internally inconsistent")
    observed_check_ids = tuple(check.check_id for check in mission_report.checks)
    if len(observed_check_ids) != len(set(observed_check_ids)):
        raise HandoffError("mission validation contains duplicate check IDs")
    failed_checks = sorted(
        (check for check in mission_report.checks if not check.passed),
        key=lambda check: check.check_id,
    )
    observed_failures = [check.check_id for check in failed_checks]
    expected_failures = sorted(checkpoint.validation.expected_blockers)
    if checkpoint.validation.unexpected_blockers:
        raise HandoffError("checkpoint records unexpected mission blockers")
    if expected_failures != list(_EXPECTED_BOOTSTRAP_BLOCKERS):
        raise HandoffError("checkpoint blocker policy differs from the bootstrap renderer")
    if observed_failures != expected_failures:
        raise HandoffError("current mission blockers differ from the linked checkpoint")
    if len(failed_checks) != 1 or failed_checks[0].detail != _EXPECTED_BOOTSTRAP_DETAIL:
        raise HandoffError("registered bootstrap blocker has an unexpected failure cause")
    if len(mission_report.checks) != checkpoint.validation.mission_checks:
        raise HandoffError("current mission check count differs from the linked checkpoint")
    if observed_check_ids != _EXPECTED_MISSION_CHECK_IDS:
        raise HandoffError("mission validation check inventory differs from the handoff contract")
    if (
        checkpoint.validation.mission_check_ids is not None
        and tuple(checkpoint.validation.mission_check_ids) != observed_check_ids
    ):
        raise HandoffError("current mission check IDs differ from the linked checkpoint")

    schemas = schema_documents()
    schema_directory_snapshot = _directory_snapshot(
        repo_root, "protocol/schemas", "schema directory"
    )
    observed_schema_paths = {
        name for name in schema_directory_snapshot[0] if name.endswith(".json")
    }
    if observed_schema_paths != set(schemas):
        raise HandoffError("committed schema inventory differs from runtime contracts")
    schema_bytes: dict[str, bytes] = {}
    for filename, expected in sorted(schemas.items()):
        schema_relative = f"protocol/schemas/{filename}"
        observed = _read_regular_file(repo_root, schema_relative, f"schema {filename}")
        if observed != expected:
            raise HandoffError(f"committed schema is stale: {filename}")
        schema_bytes[filename] = observed
    schema_hashes = {filename: sha256_bytes(content) for filename, content in schema_bytes.items()}

    mission_contract = sources["mission/contract.json"]
    mission_loop = sources["mission/loop.json"]
    mission_name = sources["mission/name.json"]
    acquisition = sources["protocol/acquisition/iter001_contract.json"]
    mission_id = _required_string(mission_contract, "mission_id", "mission contract")
    mission_name_value = _required_string(mission_contract, "name", "mission contract")
    owner = _required_string(mission_contract, "owner", "mission contract")
    legacy_namespace = _required_string(
        mission_contract, "legacy_protocol_namespace", "mission contract"
    )
    preferred_command = _required_string(mission_name, "canonical_slug", "mission name")
    name_status = _required_string(mission_name, "status", "mission name")
    iteration_id = _required_string(acquisition, "iteration_id", "acquisition contract")
    authority = _required_string(acquisition, "control_authority_status", "acquisition contract")
    stage = _required_string(mission_loop, "current_stage", "mission loop")
    publication = mission_loop.get("publication_transition")
    if not isinstance(publication, dict):
        raise HandoffError("mission loop publication transition must be an object")
    publication_status = _required_string(publication, "status", "publication transition")
    research_engine_policy = _required_string(
        mission_contract, "research_engine_policy", "mission contract"
    )
    if mission_id != "inbar" or mission_name_value != "Inbar" or preferred_command != "inbar":
        raise HandoffError("active Inbar identity contracts disagree")
    if authority != "bootstrap" or publication_status != "blocked":
        raise HandoffError("handoff renderer cannot imply activated or published authority")

    mission_checks = [
        {"check_id": check.check_id, "detail": check.detail, "passed": check.passed}
        for check in mission_report.checks
    ]
    input_digest = sha256_value(
        {
            "domain": "inbar.generated-handoff-inputs.v3",
            "renderer_contract": _RENDERER_CONTRACT,
            "renderer_sha256": renderer_hash,
            "bound_module_artifacts": bound_module_hashes,
            "recovery_directories": [
                {
                    "entries": list(item.entries),
                    "path": item.path,
                }
                for item in recovery_manifest.directories
            ],
            "recovery_artifacts": [
                {
                    "path": item.path,
                    "sha256": item.sha256,
                    "size": item.size,
                }
                for item in recovery_manifest.files
            ],
            "source_artifacts": source_hashes,
            "memory_sha256": sha256_bytes(memory_bytes),
            "schema_artifacts": schema_hashes,
            "mission_checks": mission_checks,
            "handoff_event_hash": handoff_record.event_hash,
            "checkpoint_event_hash": checkpoint_record.event_hash,
        }
    )
    passed_checks = len(mission_report.checks) - len(observed_failures)
    validation = checkpoint.validation
    failure_arguments = " ".join(
        f"--expect-failure {check_id}" for check_id in validation.expected_blockers
    )
    versioned_authority_lines = (
        []
        if legacy_recovery
        else [
            "`iter001-acquisition-contract` remains blocked. This handoff grants no authority.",
            "",
        ]
    )

    lines = [
        f"# {_markdown_text(mission_name_value)} Mission Handoff",
        "",
        "Generated deterministically from verified mission contracts, schemas, and append-only",
        "research memory. Do not hand-edit this file.",
        "",
        "## Resume identity",
        "",
        f"- Mission: `{_code_text(mission_id)}` ({_markdown_text(mission_name_value)})",
        f"- Owner: {_markdown_text(owner)}",
        f"- Preferred command: `{_code_text(preferred_command)}`",
        f"- Legacy protocol namespace: `{_code_text(legacy_namespace)}`",
        f"- Name status: `{_code_text(name_status)}`",
        "",
        "## Scientific state",
        "",
        f"- Iteration: `{_code_text(iteration_id)}`",
        f"- Lifecycle stage: `{_code_text(stage)}`",
        f"- Source-role verdict: `{_code_text(source.finding)}`",
        f"- Source verdict event: `{_code_text(source_record.event_id)}`",
        f"- Source verdict event hash: `{_code_text(source_record.event_hash)}`",
        f"- Source verdict summary: {_markdown_text(source_record.summary)}",
        "- Source architecture: "
        + ", ".join(_markdown_text(item) for item in source.source_architecture),
        f"- Compute consequence: {_markdown_text(source.compute_consequence)}",
        f"- Product boundary: {_markdown_text(source.product_wedge)}",
        f"- Canonical control authority: `{_code_text(authority)}`",
        f"- Publication transition: `{_code_text(publication_status)}`",
        (
            f"- Active handoff: `{_code_text(handoff_record.event_id)}` at sequence "
            f"{handoff_record.sequence}"
        ),
        f"- Active handoff event hash: `{_code_text(handoff_record.event_hash)}`",
        f"- Handoff status: `{_code_text(handoff_record.status.value)}`",
        f"- State: {_markdown_text(handoff.state)}",
        "",
        *versioned_authority_lines,
        "## Linked checkpoint",
        "",
        f"- Checkpoint event: `{_code_text(checkpoint_record.event_id)}`",
        f"- Checkpoint event hash: `{_code_text(checkpoint_record.event_hash)}`",
        f"- Implementation commit: `{_code_text(checkpoint.implementation_commit)}`",
        f"- Action: {_markdown_text(checkpoint.action)}",
        f"- Outcome: {_markdown_text(checkpoint.outcome)}",
        f"- Authority effect: {_markdown_text(checkpoint.authority_effect)}",
        "",
        "## Historical checkpoint validation",
        "",
        (
            "These are ledger-recorded validation assertions for implementation commit "
            f"`{_code_text(checkpoint.implementation_commit)}`. They are not live test results."
        ),
        "",
        f"- Tests: {validation.tests_passed} passed, {validation.tests_skipped} skipped",
        f"- Branch-aware coverage: {validation.branch_coverage_percent:.2f} percent",
        f"- Ruff: `{validation.ruff}`",
        f"- Strict mypy source files: {validation.strict_mypy_source_files}",
        f"- Reproducible package build: `{validation.reproducible_package_build}`",
        f"- Runtime dependency audit: {validation.runtime_dependency_audit}",
        f"- Python 3.11 shortcut tests: {validation.python_3_11_shortcut_tests}",
        f"- Python 3.14 shortcut tests: {validation.python_3_14_shortcut_tests}",
        "",
        "## Current verified recovery state",
        "",
        f"- Generated schemas: {len(schemas)}",
        (f"- Mission checks: {passed_checks} passed, {len(observed_failures)} registered blocker"),
        f"- Research-memory events: {len(records)}",
        f"- Research-memory head: `{records[-1].event_hash}`",
        f"- Renderer contract: `{_RENDERER_CONTRACT}`",
        f"- Renderer source SHA-256: `{renderer_hash}`",
        f"- Generated-input digest: `{input_digest}`",
        "",
        "## Remaining activation gates",
        "",
    ]
    lines.extend(
        f"{index}. {_markdown_text(gate)}" for index, gate in enumerate(handoff.remaining_gates, 1)
    )
    forbidden_heading = (
        "## Recorded forbidden actions" if legacy_recovery else "## Currently denied authorities"
    )
    lines.extend(["", forbidden_heading, ""])
    if legacy_recovery:
        lines.extend(
            [
                "This frozen legacy list is non-exhaustive. Every denied authority in the linked",
                "checkpoint remains forbidden.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "This explicit list is non-exhaustive. Every additional denial in committed",
                "mission, safety, resource, claim, release, and publication contracts remains",
                "binding.",
                "",
                "Closing activation gates grants no authority automatically. Every affected",
                "transition still requires its own prospective signed authority.",
                "",
            ]
        )
    lines.extend(f"- {_markdown_text(action)}" for action in handoff.forbidden_until_activation)
    lines.extend(
        [
            "",
            "## Next action",
            "",
            f"- {_markdown_text(handoff.next_action)}",
            "",
            "## Future research engine",
            "",
            f"- Policy: `{_code_text(research_engine_policy)}`",
            f"- Boundary: {_markdown_text(engine.system_boundary)}",
            f"- Build timing: {_markdown_text(engine.build_timing)}",
            "",
            "## Resume verification",
            "",
            "```bash",
            "uv sync --link-mode copy --reinstall --group dev --frozen",
            "uv run inbar memory verify",
            "uv run inbar schemas check",
            f"uv run inbar mission validate {failure_arguments}",
            "uv run inbar handoff check",
            "uv run pytest --cov",
            "git status --short --branch",
            "```",
            "",
            "`CONTINUITY.md` contains durable context only. This file is the dynamic "
            "recovery state.",
            "",
        ]
    )
    rendered = "\n".join(lines).encode("utf-8")
    if validate_mission(repo_root) != mission_report:
        raise HandoffError("mission validation changed during handoff rendering")
    for relative, expected in source_bytes.items():
        if _read_regular_file(repo_root, relative, relative) != expected:
            raise HandoffError(f"handoff source changed during rendering: {relative}")
    if _read_regular_file(repo_root, _RENDERER_PATH, _RENDERER_PATH) != renderer_bytes:
        raise HandoffError("handoff renderer changed during rendering")
    if _read_regular_file(repo_root, _MEMORY_PATH, _MEMORY_PATH) != memory_bytes:
        raise HandoffError("research memory changed during handoff rendering")
    for filename, expected in schema_bytes.items():
        schema_relative = f"protocol/schemas/{filename}"
        if _read_regular_file(repo_root, schema_relative, f"schema {filename}") != expected:
            raise HandoffError(f"schema changed during handoff rendering: {filename}")
    if _directory_snapshot(repo_root, "protocol/schemas", "schema directory") != (
        schema_directory_snapshot
    ):
        raise HandoffError("schema directory changed during handoff rendering")
    if _recovery_manifest(repo_root) != recovery_manifest:
        raise HandoffError("recovery input manifest changed during handoff rendering")
    _verify_module_population(initial_module_names)
    return rendered


def render_handoff(repo_root: Path) -> bytes:
    """Render the exact handoff bytes without reading the existing handoff file."""

    root = repo_root.resolve(strict=True)
    import_guard = _RejectUnboundFieldtrueImports()
    sys.meta_path.insert(0, import_guard)
    try:
        return _render(root)
    except HandoffError:
        raise
    except (OSError, ValueError) as error:
        raise HandoffError("handoff inputs could not be verified") from error
    finally:
        if import_guard in sys.meta_path:
            sys.meta_path.remove(import_guard)


def write_handoff(repo_root: Path) -> Path:
    """Atomically write the deterministic handoff document."""

    root = repo_root.resolve(strict=True)
    path = root / _HANDOFF_PATH
    atomic_write(path, render_handoff(root))
    check_handoff(root)
    return path


def check_handoff(repo_root: Path) -> None:
    """Fail when the committed handoff differs from current verified machine state."""

    root = repo_root.resolve(strict=True)
    actual = _read_regular_file(root, _HANDOFF_PATH, _HANDOFF_PATH)
    expected = render_handoff(root)
    final = _read_regular_file(root, _HANDOFF_PATH, _HANDOFF_PATH)
    if actual != final or final != expected:
        raise HandoffError("HANDOFF.md is stale; run `uv run inbar handoff render`")
