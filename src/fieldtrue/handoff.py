"""Deterministic recovery context rendered from verified mission state."""

from __future__ import annotations

import base64
import hashlib
import html
import json
import math
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Mapping, Sequence
from contextlib import suppress
from importlib.abc import MetaPathFinder
from importlib.machinery import ModuleSpec
from pathlib import Path, PurePosixPath
from types import CodeType, ModuleType
from typing import IO, Any, Literal, NamedTuple, NoReturn, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

# Mission validation imports this lazily; bind it before freezing the authority closure.
import fieldtrue.verification as _verification_module
from fieldtrue.canonical import atomic_write, canonical_json_pretty, sha256_bytes, sha256_value
from fieldtrue.domain import (
    EngineeringValidationArtifact,
    EngineeringValidationReceipt,
    GitObjectId,
    Identifier,
)
from fieldtrue.git_trust import (
    TRUSTED_GIT_PATH,
    GitTrustError,
    git_environment,
    trusted_repository_git,
)
from fieldtrue.memory import (
    AccessClass,
    LabelAccess,
    MemoryEventType,
    MemoryStatus,
    ResearchMemoryRecord,
    load_memory_records_bytes,
)
from fieldtrue.mission import validate_mission
from fieldtrue.schemas import schema_documents

_HANDOFF_AUTHORITY_MODULE_NAMES = (
    "fieldtrue",
    "fieldtrue.acquisition",
    "fieldtrue.active_selection",
    "fieldtrue.adapters",
    "fieldtrue.adapters.adapt",
    "fieldtrue.approvals",
    "fieldtrue.canonical",
    "fieldtrue.causal_laboratory",
    "fieldtrue.census",
    "fieldtrue.census_execution",
    "fieldtrue.control_authority",
    "fieldtrue.control_observation",
    "fieldtrue.control_protocol",
    "fieldtrue.domain",
    "fieldtrue.git_trust",
    "fieldtrue.graded_laboratory",
    "fieldtrue.handoff",
    "fieldtrue.masking",
    "fieldtrue.memory",
    "fieldtrue.method_campaign",
    "fieldtrue.mission",
    "fieldtrue.planning",
    "fieldtrue.readiness",
    "fieldtrue.receipts",
    "fieldtrue.runner_trust",
    "fieldtrue.runtime",
    "fieldtrue.schemas",
    "fieldtrue.shortcut_contracts",
    "fieldtrue.shortcut_v2_crossfit",
    "fieldtrue.shortcut_v2_hashing",
    "fieldtrue.shortcut_v2_ontology",
    "fieldtrue.shortcut_v2_release",
    "fieldtrue.shortcut_v2_target",
    "fieldtrue.shortcut_v2_tree",
    "fieldtrue.splits",
    "fieldtrue.terminal_authority",
    _verification_module.__name__,
)
_HANDOFF_AUTHORITY_MODULE_NAME_SET = frozenset(_HANDOFF_AUTHORITY_MODULE_NAMES)
_HANDOFF_ALLOWED_PRELOADED_MODULE_NAMES = frozenset(
    {
        "fieldtrue.adapters.local_replay",
        "fieldtrue.cli",
        "fieldtrue.control_launcher",
        "fieldtrue.control_producer",
        "fieldtrue.diagnosis",
        "fieldtrue.experiment",
        "fieldtrue.ports",
        # A producer tool, not an authority source: nothing in the renderer's import closure
        # depends on it, so it is captured as bound wrapper source rather than bound authority.
        "fieldtrue.memory_cycle",
        # A retrospective engineering replay, not an authority source. Its tests preload it before
        # handoff tests, so the renderer binds its wrapper bytes without importing or trusting it.
        "fieldtrue.susceptibility_replay",
        # The terminal prediction boundary, not an authority source: nothing in the renderer's
        # import closure reaches it, so listing it as authority would assert a module is bound that
        # is not loaded. Its own tests preload it before handoff tests, so it is captured here as
        # bound wrapper source rather than bound authority.
        "fieldtrue.shortcut_v2_terminal",
        "fieldtrue.validation_producer",
    }
)
_HANDOFF_PATH = "HANDOFF.md"
_MEMORY_PATH = "memory/research_engine_extraction.jsonl"
_RENDERER_PATH = "src/fieldtrue/handoff.py"
_RENDERER_CONTRACT = "inbar.generated-handoff.v5"
_SNAPSHOT_WORKER_CONTRACT = "inbar.handoff-snapshot-worker.v1"
_SNAPSHOT_WORKER_TIMEOUT_SECONDS = 300
_MAX_SNAPSHOT_WORKER_OUTPUT_BYTES = 2 * 16 * 1024 * 1024
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
_RECOVERY_CHECKPOINT_CONTRACT_V2 = "inbar.handoff-checkpoint.v2"
_RECOVERY_HANDOFF_CONTRACT = "inbar.handoff-state.v1"
_RECOVERY_STAGE = "mission-handoff"
_EXPECTED_BOOTSTRAP_BLOCKERS = ("iter001-acquisition-contract",)
_EXPECTED_BOOTSTRAP_DETAIL = (
    "Iteration 001 acquisition contract failed: canonical control authority is not sealed"
)
_CURRENT_SOURCE_FINDING = "BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE"
_CURRENT_SOURCE_RECONNAISSANCE_SCOPE = "dated_enumerated_non_systematic"
_CURRENT_SOURCE_EXTERNAL_EVIDENCE_STATUS = "not_independently_reconstructible"
_CURRENT_SOURCE_ADMISSIBILITY_BOUNDARY = (
    "Existing real-world evidence remains admissible only after prospective review against every "
    "frozen field and independent-audit requirement."
)
_CURRENT_SOURCE_SUMMARY = (
    "The current protocol blocks the present public-source-only route and requires prospective "
    "review before any physical evidence is admitted."
)
_CURRENT_SOURCE_COMPUTE_CONSEQUENCE = "GPU training remains blocked."
_CURRENT_SOURCE_PRODUCT_WEDGE = (
    "Proposed Phase A offline and shadow-mode pre-action evidence dossier compiler with ranked "
    "human-reviewable safe-test recommendations; no command or outcome-truth authority."
)
_CURRENT_SOURCE_ARCHITECTURE = (
    "physical admission",
    "causal laboratory",
    "independent reality and controls",
)
_CURRENT_SOURCE_AUDIT_PATH = "docs/research/ITER001_SOURCE_ROLE_AUDIT.md"
_CURRENT_SOURCE_CORRECTION_LINK = "scope_correction"
_VALIDATION_RECEIPT_MEDIA_TYPE = "application/json"
_VALIDATION_JUNIT_MEDIA_TYPE = "application/xml"
_VALIDATION_COVERAGE_MEDIA_TYPE = "application/json"
_VALIDATION_LOG_MEDIA_TYPE = "text/plain; charset=utf-8"
_VALIDATION_CREDENTIAL_RE = re.compile(
    rb"BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|"
    rb"(AKIA|ASIA)[0-9A-Z]{16}|"
    rb"gh[pousr]_[A-Za-z0-9_]{20,}|"
    rb"github_pat_[A-Za-z0-9_]{20,}|"
    rb"sk-proj-[A-Za-z0-9_-]{20,}|"
    rb"sk-ant-[A-Za-z0-9_-]{20,}|"
    rb"AIza[0-9A-Za-z_-]{35}|"
    rb"glpat-[A-Za-z0-9_-]{20,}|"
    rb"xox[baprs]-[0-9A-Za-z-]{20,}|"
    rb"(sk|rk)_(live|test)_[0-9A-Za-z]{16,}|"
    rb"npm_[0-9A-Za-z]{36}|"
    rb"pypi-[0-9A-Za-z_-]{40,}|"
    rb"hf_[0-9A-Za-z]{20,}|"
    rb"ya29\.[0-9A-Za-z_-]{20,}|"
    rb"sk-[A-Za-z0-9]{20,}"
)
_MAX_VALIDATION_RECEIPT_BYTES = 2 * 1024 * 1024
_MAX_VALIDATION_LOG_BYTES = 8 * 1024 * 1024
_MAX_VALIDATION_STRUCTURED_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_CREDIBILITY_GATE_CONTROL_BYTES = 1024 * 1024
_CREDIBILITY_GATE_CONTROL_PATH = "protocol/gate_controls/credibility_v1.json"
_CREDIBILITY_GATE_CONTROL_ROLES = (
    "positive_control",
    "negative_control",
    "placebo_control",
)
_COVERAGE_PERCENT_TOLERANCE = 1e-10
_MAX_GIT_METADATA_BYTES = 4 * 1024 * 1024
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


class _TrackedRecoveryFileBinding(NamedTuple):
    executable: bool
    sha256: str
    size: int


class _RejectUnboundFieldtrueImports(MetaPathFinder):
    def __init__(self, allowed_names: frozenset[str]) -> None:
        self._allowed_names = allowed_names

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None,
        target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        del path, target
        if (
            fullname == "fieldtrue" or fullname.startswith("fieldtrue.")
        ) and fullname not in self._allowed_names:
            raise HandoffError(f"unbound Fieldtrue module import during handoff: {fullname}")
        return None


def _capture_module_source(
    name: str,
    module_value: ModuleType,
    imported_source_root: Path,
) -> _BoundModuleSource:
    module_path_value = getattr(module_value, "__file__", None)
    loader = getattr(getattr(module_value, "__spec__", None), "loader", None)
    get_code = getattr(loader, "get_code", None)
    if not isinstance(module_path_value, str) or not callable(get_code):
        raise RuntimeError(f"loaded Fieldtrue module has no source-code loader: {name}")
    module_path = Path(module_path_value).resolve(strict=True)
    try:
        source_relative = module_path.relative_to(imported_source_root)
    except ValueError as error:
        raise RuntimeError(f"loaded Fieldtrue module is outside the source root: {name}") from error
    if module_path.suffix != ".py":
        raise RuntimeError(f"loaded Fieldtrue module is not Python source: {name}")
    loader_code = get_code(name)
    if not isinstance(loader_code, CodeType):
        raise RuntimeError(f"loaded Fieldtrue module has no executable module code: {name}")
    repository_path = (PurePosixPath("src") / PurePosixPath(source_relative.as_posix())).as_posix()
    return _BoundModuleSource(
        name=name,
        module=module_value,
        repository_path=repository_path,
        imported_path=str(module_path),
        imported_bytes=module_path.read_bytes(),
        loader_code=loader_code,
    )


def _capture_bound_fieldtrue_modules() -> tuple[_BoundModuleSource, ...]:
    imported_source_root = Path(__file__).resolve(strict=True).parents[1]
    captured: list[_BoundModuleSource] = []
    repository_paths: set[str] = set()
    for name in _HANDOFF_AUTHORITY_MODULE_NAMES:
        module_value = sys.modules.get(name)
        if not isinstance(module_value, ModuleType):
            raise RuntimeError(f"configured Fieldtrue authority module is not loaded: {name}")
        binding = _capture_module_source(name, module_value, imported_source_root)
        repository_path = binding.repository_path
        if repository_path in repository_paths:
            raise RuntimeError(
                f"Fieldtrue authority modules share a source path: {repository_path}"
            )
        repository_paths.add(repository_path)
        captured.append(binding)
    if tuple(item.name for item in captured) != _HANDOFF_AUTHORITY_MODULE_NAMES:
        raise RuntimeError("handoff authority module closure differs from its fixed contract")
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


class _CheckpointValidationReceipt(_StrictModel):
    receipt_id: Identifier
    path: str = Field(min_length=1)
    git_commit: GitObjectId
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bytes: int = Field(ge=1, le=_MAX_VALIDATION_RECEIPT_BYTES)
    media_type: Literal["application/json"]

    @field_validator("path")
    @classmethod
    def path_is_normalized(cls, value: str) -> str:
        path = PurePosixPath(value)
        if (
            urlsplit(value).scheme
            or "\\" in value
            or path.is_absolute()
            or not path.parts
            or "." in path.parts
            or ".." in path.parts
            or path.as_posix() != value
        ):
            raise ValueError("validation receipt path must be a normalized repository path")
        return value

    @model_validator(mode="after")
    def path_matches_receipt_identity(self) -> Self:
        expected = f"evidence/validation/{self.receipt_id}/receipt.json"
        if self.path != expected:
            raise ValueError("validation receipt path does not match its receipt ID")
        return self


class _CheckpointPayload(_StrictModel):
    action: str = Field(min_length=1)
    authority_effect: str = Field(min_length=1)
    handoff_contract: (
        Literal["inbar.handoff-checkpoint.v1", "inbar.handoff-checkpoint.v2"] | None
    ) = None
    implementation_commit: GitObjectId
    outcome: str = Field(min_length=1)
    validation: _CheckpointValidation | None = None
    validation_receipt: _CheckpointValidationReceipt | None = None

    @model_validator(mode="after")
    def validation_contract_is_versioned(self) -> Self:
        if self.handoff_contract == _RECOVERY_CHECKPOINT_CONTRACT_V2:
            if (
                "validation" in self.model_fields_set
                or self.validation is not None
                or "validation_receipt" not in self.model_fields_set
                or self.validation_receipt is None
            ):
                raise ValueError("checkpoint-v2 requires only a validation receipt link")
        elif (
            "validation" not in self.model_fields_set
            or self.validation is None
            or "validation_receipt" in self.model_fields_set
            or self.validation_receipt is not None
        ):
            raise ValueError("legacy checkpoint contracts require inline validation only")
        return self


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


class _LegacySourceVerdictPayload(_StrictModel):
    compute_consequence: str = Field(min_length=1)
    finding: Literal["KILL_PUBLIC_SUBSTRATE"]
    product_wedge: str = Field(min_length=1)
    source_architecture: list[str] = Field(min_length=1)


class _CurrentSourceVerdictPayload(_StrictModel):
    admissibility_boundary: Literal[
        "Existing real-world evidence remains admissible only after prospective review against "
        "every frozen field and independent-audit requirement."
    ]
    compute_consequence: str = Field(min_length=1)
    external_evidence_status: Literal["not_independently_reconstructible"]
    finding: Literal["BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE"]
    product_wedge: str = Field(min_length=1)
    reconnaissance_scope: Literal["dated_enumerated_non_systematic"]
    source_architecture: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def bounded_decision_is_exact(self) -> Self:
        if (
            self.compute_consequence != _CURRENT_SOURCE_COMPUTE_CONSEQUENCE
            or self.product_wedge != _CURRENT_SOURCE_PRODUCT_WEDGE
            or tuple(self.source_architecture) != _CURRENT_SOURCE_ARCHITECTURE
        ):
            raise ValueError("current source verdict differs from its frozen bounded decision")
        return self


_SourceVerdictPayload = _LegacySourceVerdictPayload | _CurrentSourceVerdictPayload


class _EngineBoundaryPayload(_StrictModel):
    build_timing: str = Field(min_length=1)
    finding: list[str] = Field(min_length=1)
    ownership: Literal["Daniel Wahnich"]
    system_boundary: str = Field(min_length=1)


class _VerifiedValidationReceipt(NamedTuple):
    receipt: EngineeringValidationReceipt
    evidence_commit: str
    receipt_sha256: str
    artifact_bindings: tuple[tuple[str, str, int], ...]


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


def _loaded_fieldtrue_modules() -> dict[str, ModuleType]:
    candidates = {
        name: module
        for name, module in sys.modules.items()
        if name == "fieldtrue" or name.startswith("fieldtrue.")
    }
    invalid = sorted(
        name for name, module in candidates.items() if not isinstance(module, ModuleType)
    )
    if invalid:
        raise HandoffError("invalid loaded Fieldtrue module entries: " + ", ".join(invalid))
    return {name: module for name, module in candidates.items() if isinstance(module, ModuleType)}


def _capture_preloaded_wrapper_modules(
    initial_modules: Mapping[str, ModuleType],
) -> tuple[_BoundModuleSource, ...]:
    unknown = sorted(
        initial_modules.keys()
        - _HANDOFF_AUTHORITY_MODULE_NAME_SET
        - _HANDOFF_ALLOWED_PRELOADED_MODULE_NAMES
    )
    if unknown:
        raise HandoffError("unreviewed preloaded Fieldtrue modules: " + ", ".join(unknown))
    imported_source_root = Path(__file__).resolve(strict=True).parents[1]
    try:
        return tuple(
            _capture_module_source(name, initial_modules[name], imported_source_root)
            for name in sorted(initial_modules.keys() & _HANDOFF_ALLOWED_PRELOADED_MODULE_NAMES)
        )
    except (OSError, RuntimeError) as error:
        raise HandoffError("preloaded Fieldtrue wrapper source cannot be bound") from error


def _verify_module_sources(
    repo_root: Path,
    bindings: Sequence[_BoundModuleSource],
) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for binding in bindings:
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


def _verify_bound_module_sources(repo_root: Path) -> dict[str, str]:
    return _verify_module_sources(repo_root, _BOUND_FIELDTRUE_MODULES)


def _verify_module_population(initial_modules: Mapping[str, ModuleType]) -> None:
    current_modules = _loaded_fieldtrue_modules()
    changed_ambient = sorted(
        name for name, module in initial_modules.items() if current_modules.get(name) is not module
    )
    if changed_ambient:
        raise HandoffError(
            "preloaded Fieldtrue module identity changed during handoff: "
            + ", ".join(changed_ambient)
        )
    new_unbound = sorted(
        (current_modules.keys() - initial_modules.keys()) - _BOUND_FIELDTRUE_MODULE_NAMES
    )
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
    if isinstance(source, _CurrentSourceVerdictPayload):
        values.extend(
            (
                source.reconnaissance_scope,
                source.external_evidence_status,
                source.admissibility_boundary,
            )
        )
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


def _parse_source_payload(payload: dict[str, Any]) -> _SourceVerdictPayload:
    finding = payload.get("finding")
    model: type[_LegacySourceVerdictPayload] | type[_CurrentSourceVerdictPayload]
    if finding == "KILL_PUBLIC_SUBSTRATE":
        model = _LegacySourceVerdictPayload
    elif finding == _CURRENT_SOURCE_FINDING:
        model = _CurrentSourceVerdictPayload
    else:
        raise HandoffError("source verdict payload violates its exact contract")
    parsed = _parse_payload(model, payload, "source verdict")
    if not isinstance(parsed, _LegacySourceVerdictPayload | _CurrentSourceVerdictPayload):
        raise HandoffError("source verdict payload violates its exact contract")
    return parsed


def _expected_validation_plan(
    receipt_id: str,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    evidence_root = f"evidence/validation/{receipt_id}"
    return (
        ("uv-lock-check", ("uv", "lock", "--check")),
        ("ruff-check", ("uv", "run", "ruff", "check", ".")),
        ("ruff-format-check", ("uv", "run", "ruff", "format", "--check", ".")),
        ("mypy", ("uv", "run", "mypy", "src")),
        ("schemas-check", ("uv", "run", "inbar", "schemas", "check")),
        ("memory-verify", ("uv", "run", "inbar", "memory", "verify")),
        (
            "mission-validate",
            (
                "uv",
                "run",
                "inbar",
                "mission",
                "validate",
                "--expect-failure",
                "iter001-acquisition-contract",
            ),
        ),
        (
            "pytest-cov",
            (
                "uv",
                "run",
                "pytest",
                "--runxfail",
                "--cov",
                f"--cov-report=json:{evidence_root}/coverage.json",
                f"--junitxml={evidence_root}/pytest.junit.xml",
            ),
        ),
    )


def _git_bounded_output(
    repo_root: Path,
    git: str,
    arguments: Sequence[str],
    *,
    maximum_bytes: int,
    label: str,
    input_bytes: bytes | None = None,
) -> bytes:
    if maximum_bytes < 0:
        raise HandoffError(f"Git {label} has an invalid verification bound")
    process: subprocess.Popen[bytes] | None = None
    output_pipe: IO[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    try:
        with tempfile.TemporaryFile() as request:
            if input_bytes is not None:
                request.write(input_bytes)
                request.seek(0)
            process = subprocess.Popen(  # noqa: S603 - fixed trusted Git and validated arguments
                [git, *arguments],
                cwd=repo_root,
                stdin=request,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=git_environment(),
                bufsize=0,
            )
            output_pipe = process.stdout
            if output_pipe is None:
                raise HandoffError(f"Git could not verify {label}")
            os.set_blocking(output_pipe.fileno(), False)
            selector = selectors.DefaultSelector()
            selector.register(output_pipe, selectors.EVENT_READ)
            deadline = time.monotonic() + 30
            captured = bytearray()
            while selector.get_map():
                remaining_seconds = deadline - time.monotonic()
                if remaining_seconds <= 0:
                    raise subprocess.TimeoutExpired([git, *arguments], 30)
                events = selector.select(remaining_seconds)
                if not events:
                    raise subprocess.TimeoutExpired([git, *arguments], 30)
                for key, _event_mask in events:
                    read_bytes = min(64 * 1024, maximum_bytes - len(captured) + 1)
                    try:
                        chunk = os.read(key.fd, read_bytes)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    captured.extend(chunk)
                    if len(captured) > maximum_bytes:
                        raise HandoffError(f"Git {label} exceeds its verification bound")

            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise subprocess.TimeoutExpired([git, *arguments], 30)
            try:
                returncode = process.wait(timeout=remaining_seconds)
            except subprocess.TimeoutExpired as error:
                raise subprocess.TimeoutExpired([git, *arguments], 30) from error
            if returncode != 0:
                raise HandoffError(f"Git could not verify {label}")
            data = bytes(captured)
    except HandoffError:
        raise
    except (OSError, subprocess.SubprocessError) as error:
        raise HandoffError(f"Git could not verify {label}") from error
    finally:
        if process is not None:
            if process.poll() is None:
                with suppress(ProcessLookupError):
                    process.kill()
            process.wait()
        if selector is not None:
            selector.close()
        if output_pipe is not None:
            output_pipe.close()
    return data


def _git_metadata_text(repo_root: Path, git: str, arguments: Sequence[str], label: str) -> str:
    data = _git_bounded_output(
        repo_root,
        git,
        arguments,
        maximum_bytes=_MAX_GIT_METADATA_BYTES,
        label=label,
    )
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HandoffError(f"Git {label} is not UTF-8") from error


def _git_commit_tree(repo_root: Path, git: str, commit: str) -> str:
    tree = _git_metadata_text(
        repo_root, git, ("rev-parse", "--verify", f"{commit}^{{tree}}"), "commit tree"
    ).strip()
    if len(tree) not in {40, 64} or any(character not in "0123456789abcdef" for character in tree):
        raise HandoffError("Git returned an invalid commit tree")
    return tree


def _git_commit_parents(repo_root: Path, git: str, commit: str) -> tuple[str, ...]:
    line = _git_metadata_text(
        repo_root, git, ("show", "-s", "--format=%P", commit), "commit parents"
    ).strip()
    parents = tuple(line.split()) if line else ()
    if any(
        len(parent) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in parent)
        for parent in parents
    ):
        raise HandoffError("Git returned invalid commit parents")
    return parents


def _git_is_ancestor(repo_root: Path, git: str, ancestor: str, descendant: str) -> bool:
    try:
        result = subprocess.run(  # noqa: S603 - fixed trusted Git and validated object IDs
            [git, "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=repo_root,
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=git_environment(),
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HandoffError("Git could not verify validation lineage") from error
    if result.returncode not in {0, 1}:
        raise HandoffError("Git could not verify validation lineage")
    return result.returncode == 0


def _git_changed_paths(repo_root: Path, git: str, parent: str, commit: str) -> frozenset[str]:
    data = _git_bounded_output(
        repo_root,
        git,
        (
            "diff-tree",
            "--no-commit-id",
            "--no-renames",
            "--name-only",
            "-r",
            "-z",
            parent,
            commit,
        ),
        maximum_bytes=_MAX_GIT_METADATA_BYTES,
        label="validation commit path inventory",
    )
    raw_paths = data.split(b"\0")
    if raw_paths[-1:] == [b""]:
        raw_paths.pop()
    try:
        paths = tuple(path.decode("utf-8") for path in raw_paths)
    except UnicodeDecodeError as error:
        raise HandoffError("validation commit paths are not UTF-8") from error
    if len(paths) != len(set(paths)) or any(not path for path in paths):
        raise HandoffError("validation commit path inventory is ambiguous")
    return frozenset(paths)


def _normalized_repository_path(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or not path.parts
        or "." in path.parts
        or ".." in path.parts
        or path.as_posix() != value
    ):
        raise HandoffError(f"{label} is not a normalized repository path")
    return value


def _git_python_source_paths(
    repo_root: Path,
    git: str,
    commit: str,
) -> frozenset[str]:
    data = _git_bounded_output(
        repo_root,
        git,
        ("ls-tree", "-r", "-z", commit, "--", "src/fieldtrue"),
        maximum_bytes=_MAX_GIT_METADATA_BYTES,
        label="implementation Python source inventory",
    )
    raw_entries = data.split(b"\0")
    if raw_entries[-1:] == [b""]:
        raw_entries.pop()
    source_paths: list[str] = []
    for entry in raw_entries:
        if b"\t" not in entry:
            raise HandoffError("implementation Python source inventory is malformed")
        raw_metadata, raw_path = entry.split(b"\t", 1)
        try:
            mode, object_type, object_id = raw_metadata.decode("ascii").split()
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise HandoffError("implementation Python source inventory is malformed") from error
        if not path.endswith(".py"):
            continue
        _normalized_repository_path(path, "implementation Python source path")
        if (
            tuple(PurePosixPath(path).parts[:2]) != ("src", "fieldtrue")
            or mode != "100644"
            or object_type != "blob"
            or len(object_id) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in object_id)
        ):
            raise HandoffError(f"implementation Python source is not a regular 100644 blob: {path}")
        source_paths.append(path)
    if not source_paths or len(source_paths) != len(set(source_paths)):
        raise HandoffError("implementation Python source inventory is empty or ambiguous")
    return frozenset(source_paths)


def _git_batch_blob_size(header: bytes, expected_id: bytes) -> int:
    fields = header.split(b" ")
    if len(fields) != 3 or fields[0] != expected_id or fields[1] != b"blob":
        raise HandoffError("tracked recovery blob batch header is invalid")
    raw_size = fields[2]
    if (
        not raw_size
        or not raw_size.isascii()
        or not raw_size.isdigit()
        or len(raw_size) > len(str(_MAX_INPUT_BYTES))
    ):
        raise HandoffError("tracked recovery blob batch size is invalid")
    size = int(raw_size)
    if raw_size != str(size).encode("ascii"):
        raise HandoffError("tracked recovery blob batch size is invalid")
    if size > _MAX_INPUT_BYTES:
        raise HandoffError("tracked recovery blob exceeds the per-file limit")
    return size


def _git_blob_object_id(blob: bytes, hexadecimal_length: int) -> str:
    framed = b"blob " + str(len(blob)).encode("ascii") + b"\x00" + blob
    if hexadecimal_length == 40:
        return hashlib.sha1(framed, usedforsecurity=False).hexdigest()
    if hexadecimal_length == 64:
        return hashlib.sha256(framed).hexdigest()
    raise HandoffError("tracked recovery blob object ID length is invalid")


def _git_batch_blob_bindings(
    repo_root: Path,
    git: str,
    object_ids: Sequence[str],
) -> dict[str, tuple[int, str]]:
    if not object_ids or len(object_ids) != len(set(object_ids)):
        raise HandoffError("tracked recovery blob request is empty or ambiguous")
    if any(
        len(object_id) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in object_id)
        for object_id in object_ids
    ):
        raise HandoffError("tracked recovery blob request contains an invalid object ID")
    encoded_ids = tuple(object_id.encode("ascii") for object_id in object_ids)
    request = b"\n".join(encoded_ids) + b"\n"
    if len(request) > _MAX_GIT_METADATA_BYTES:
        raise HandoffError("tracked recovery blob request exceeds its verification bound")
    metadata = _git_bounded_output(
        repo_root,
        git,
        ("--no-replace-objects", "cat-file", "--batch-check"),
        maximum_bytes=_MAX_GIT_METADATA_BYTES,
        label="tracked recovery blob metadata batch",
        input_bytes=request,
    )

    cursor = 0
    total_bytes = 0
    sizes: dict[str, int] = {}
    for expected_id, encoded_id in zip(object_ids, encoded_ids, strict=True):
        header_end = metadata.find(b"\n", cursor)
        if header_end < 0:
            raise HandoffError("tracked recovery blob metadata batch is truncated")
        size = _git_batch_blob_size(metadata[cursor:header_end], encoded_id)
        total_bytes += size
        if total_bytes > _MAX_RECOVERY_INPUT_BYTES:
            raise HandoffError("tracked recovery blob batch exceeds the total input limit")
        sizes[expected_id] = size
        cursor = header_end + 1
    if cursor != len(metadata):
        raise HandoffError("tracked recovery blob metadata batch has trailing output")

    expected_output_bytes = sum(
        len(encoded_id) + len(b" blob ") + len(str(sizes[object_id])) + 1 + sizes[object_id] + 1
        for object_id, encoded_id in zip(object_ids, encoded_ids, strict=True)
    )
    output = _git_bounded_output(
        repo_root,
        git,
        ("--no-replace-objects", "cat-file", "--batch"),
        maximum_bytes=expected_output_bytes,
        label="tracked recovery blob content batch",
        input_bytes=request,
    )
    cursor = 0
    bindings: dict[str, tuple[int, str]] = {}
    for expected_id, encoded_id in zip(object_ids, encoded_ids, strict=True):
        header_end = output.find(b"\n", cursor)
        if header_end < 0:
            raise HandoffError("tracked recovery blob content batch is truncated")
        size = _git_batch_blob_size(output[cursor:header_end], encoded_id)
        if size != sizes[expected_id]:
            raise HandoffError("tracked recovery blob size changed between batch phases")
        content_start = header_end + 1
        content_end = content_start + size
        if content_end >= len(output):
            raise HandoffError("tracked recovery blob content batch is truncated")
        if output[content_end : content_end + 1] != b"\n":
            raise HandoffError("tracked recovery blob content batch framing is invalid")
        blob = output[content_start:content_end]
        if _git_blob_object_id(blob, len(expected_id)) != expected_id:
            raise HandoffError("tracked recovery blob content does not match its object ID")
        bindings[expected_id] = (size, sha256_bytes(blob))
        cursor = content_end + 1
    if cursor != len(output):
        raise HandoffError("tracked recovery blob content batch has trailing output")
    return bindings


def _git_eligible_recovery_files(
    repo_root: Path,
    git: str,
    commit: str,
) -> dict[str, _TrackedRecoveryFileBinding]:
    data = _git_bounded_output(
        repo_root,
        git,
        ("ls-tree", "-r", "-z", commit),
        maximum_bytes=_MAX_GIT_METADATA_BYTES,
        label="tracked recovery file inventory",
    )
    raw_entries = data.split(b"\0")
    if raw_entries[-1:] == [b""]:
        raw_entries.pop()
    objects: dict[str, tuple[bool, str]] = {}
    for entry in raw_entries:
        if b"\t" not in entry:
            raise HandoffError("tracked recovery file inventory is malformed")
        raw_metadata, raw_path = entry.split(b"\t", 1)
        try:
            mode, object_type, object_id = raw_metadata.decode("ascii").split()
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise HandoffError("tracked recovery file inventory is malformed") from error
        _normalized_repository_path(path, "tracked recovery file path")
        relative = PurePosixPath(path)
        excluded_by_parent = any(
            part in _RECOVERY_CACHE_DIRECTORIES for part in relative.parts[:-1]
        )
        if _is_recovery_excluded(relative, directory=False) or excluded_by_parent:
            continue
        if (
            mode not in {"100644", "100755"}
            or object_type != "blob"
            or len(object_id) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in object_id)
        ):
            raise HandoffError(f"tracked recovery input is not a regular blob: {path}")
        if path in objects:
            raise HandoffError("tracked recovery file inventory is ambiguous")
        objects[path] = (mode == "100755", object_id)
    if not objects:
        raise HandoffError("tracked recovery file inventory is empty")

    object_bindings = _git_batch_blob_bindings(
        repo_root,
        git,
        tuple(dict.fromkeys(object_id for _executable, object_id in objects.values())),
    )
    total_bytes = 0
    files: dict[str, _TrackedRecoveryFileBinding] = {}
    for path, (executable, object_id) in objects.items():
        size, digest = object_bindings[object_id]
        total_bytes += size
        if total_bytes > _MAX_RECOVERY_INPUT_BYTES:
            raise HandoffError("tracked recovery blobs exceed the total input limit")
        files[path] = _TrackedRecoveryFileBinding(
            executable=executable,
            sha256=digest,
            size=size,
        )
    return files


def _verify_recovery_manifest_git_binding(
    repo_root: Path,
    git: str,
    commit: str,
    manifest: _RecoveryManifest,
) -> None:
    expected = _git_eligible_recovery_files(repo_root, git, commit)
    observed = {
        item.path: _TrackedRecoveryFileBinding(
            executable=bool(item.metadata[2] & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)),
            sha256=item.sha256,
            size=item.size,
        )
        for item in manifest.files
    }
    if len(observed) != len(manifest.files):
        raise HandoffError("recovery manifest file inventory is ambiguous")
    if observed.keys() != expected.keys():
        raise HandoffError(
            "recovery manifest file inventory differs from the selected committed tree"
        )
    mode_mismatches = sorted(
        path
        for path, binding in observed.items()
        if binding.executable != expected[path].executable
    )
    if mode_mismatches:
        raise HandoffError(
            "recovery manifest executable modes differ from the selected committed tree"
        )
    content_mismatches = sorted(
        path
        for path, binding in observed.items()
        if (binding.sha256, binding.size) != (expected[path].sha256, expected[path].size)
    )
    if content_mismatches:
        raise HandoffError("recovery manifest content differs from the selected committed tree")


def _git_worktree_changed_paths(repo_root: Path, git: str) -> frozenset[str]:
    commands = (
        ("diff", "--no-renames", "--name-only", "-z", "HEAD", "--"),
        ("diff", "--cached", "--no-renames", "--name-only", "-z", "HEAD", "--"),
        ("ls-files", "--others", "--exclude-standard", "-z"),
    )
    observed: set[str] = set()
    for index, arguments in enumerate(commands):
        data = _git_bounded_output(
            repo_root,
            git,
            arguments,
            maximum_bytes=_MAX_GIT_METADATA_BYTES,
            label=f"handoff worktree path inventory {index}",
        )
        raw_paths = data.split(b"\0")
        if raw_paths[-1:] == [b""]:
            raw_paths.pop()
        try:
            paths = tuple(path.decode("utf-8") for path in raw_paths)
        except UnicodeDecodeError as error:
            raise HandoffError("handoff worktree paths are not UTF-8") from error
        if len(paths) != len(set(paths)):
            raise HandoffError("handoff worktree path inventory is ambiguous")
        for path in paths:
            observed.add(_normalized_repository_path(path, "handoff worktree path"))
    return frozenset(observed)


def _verify_v2_final_handoff_commit(
    repo_root: Path,
    git: str,
    evidence_commit: str,
    final_commit: str,
) -> None:
    if _git_commit_parents(repo_root, git, final_commit) != (evidence_commit,):
        raise HandoffError(
            "final handoff commit is not the single-parent child of the validation evidence commit"
        )
    expected_changes = frozenset({_MEMORY_PATH, _HANDOFF_PATH})
    if _git_changed_paths(repo_root, git, evidence_commit, final_commit) != expected_changes:
        raise HandoffError(
            "final handoff commit does not contain exactly research memory and HANDOFF.md"
        )
    evidence_memory = _git_blob(
        repo_root,
        git,
        evidence_commit,
        _MEMORY_PATH,
        maximum_bytes=_MAX_INPUT_BYTES,
    )
    final_memory = _git_blob(
        repo_root,
        git,
        final_commit,
        _MEMORY_PATH,
        maximum_bytes=_MAX_INPUT_BYTES,
    )
    _git_blob(
        repo_root,
        git,
        final_commit,
        _HANDOFF_PATH,
        maximum_bytes=_MAX_INPUT_BYTES,
    )
    if len(final_memory) <= len(evidence_memory) or not final_memory.startswith(evidence_memory):
        raise HandoffError(
            "final handoff memory is not a strict byte-prefix append of the evidence parent"
        )


def _verify_v2_finalization_topology(
    repo_root: Path,
    git: str,
    evidence_commit: str,
) -> bool:
    head = _git_head(repo_root, git)
    if head == evidence_commit:
        return True

    parents = _git_commit_parents(repo_root, git, head)
    if len(parents) == 1:
        final_commit = head
    elif len(parents) == 2:
        integration_base, final_commit = parents
        if integration_base == evidence_commit or not _git_is_ancestor(
            repo_root,
            git,
            integration_base,
            evidence_commit,
        ):
            raise HandoffError(
                "integration wrapper first parent is not a proper ancestor "
                "of the validation evidence commit"
            )
        if _git_commit_tree(repo_root, git, head) != _git_commit_tree(
            repo_root,
            git,
            final_commit,
        ):
            raise HandoffError("integration wrapper tree differs from its final handoff parent")
    else:
        raise HandoffError(
            "HEAD is neither the final handoff commit nor one transparent "
            "two-parent integration wrapper"
        )

    _verify_v2_final_handoff_commit(
        repo_root,
        git,
        evidence_commit,
        final_commit,
    )
    return False


def _verify_v2_checkout_state(repo_root: Path, git: str, evidence_commit: str) -> None:
    prospective = _verify_v2_finalization_topology(repo_root, git, evidence_commit)
    changes = _git_worktree_changed_paths(repo_root, git)
    if prospective:
        if not changes <= frozenset({_MEMORY_PATH, _HANDOFF_PATH}):
            raise HandoffError(
                "prospective handoff render has changes outside research memory and HANDOFF.md"
            )
    elif changes:
        raise HandoffError("final handoff checkout is not clean")


def _v2_evidence_commit_from_memory(memory_bytes: bytes) -> str | None:
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
    assert isinstance(checkpoint, _CheckpointPayload)
    if checkpoint.handoff_contract != _RECOVERY_CHECKPOINT_CONTRACT_V2:
        return None
    if checkpoint.validation_receipt is None:
        raise HandoffError("checkpoint-v2 validation receipt link is unavailable")
    return checkpoint.validation_receipt.git_commit


def _git_tree_paths(
    repo_root: Path,
    git: str,
    commit: str,
    path_prefix: str,
) -> frozenset[str]:
    data = _git_bounded_output(
        repo_root,
        git,
        ("ls-tree", "-r", "-z", "--name-only", commit, "--", path_prefix),
        maximum_bytes=_MAX_GIT_METADATA_BYTES,
        label=f"validation directory inventory {path_prefix}",
    )
    raw_paths = data.split(b"\0")
    if raw_paths[-1:] == [b""]:
        raw_paths.pop()
    try:
        paths = tuple(path.decode("utf-8") for path in raw_paths)
    except UnicodeDecodeError as error:
        raise HandoffError("validation directory paths are not UTF-8") from error
    if len(paths) != len(set(paths)) or any(not path for path in paths):
        raise HandoffError("validation directory inventory is ambiguous")
    return frozenset(paths)


def _git_blob(
    repo_root: Path,
    git: str,
    commit: str,
    path: str,
    *,
    maximum_bytes: int,
) -> bytes:
    entry = _git_bounded_output(
        repo_root,
        git,
        ("ls-tree", "-z", commit, "--", path),
        maximum_bytes=_MAX_GIT_METADATA_BYTES,
        label=f"validation artifact tree entry {path}",
    )
    records = entry.split(b"\0")
    if records[-1:] == [b""]:
        records.pop()
    if len(records) != 1 or b"\t" not in records[0]:
        raise HandoffError(f"validation artifact is not a unique committed blob: {path}")
    metadata, raw_path = records[0].split(b"\t", 1)
    try:
        observed_path = raw_path.decode("utf-8")
        mode, object_type, object_id = metadata.decode("ascii").split()
    except (UnicodeDecodeError, ValueError) as error:
        raise HandoffError(f"validation artifact tree entry is invalid: {path}") from error
    if (
        observed_path != path
        or mode != "100644"
        or object_type != "blob"
        or len(object_id) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in object_id)
    ):
        raise HandoffError(f"validation artifact tree entry is invalid: {path}")
    return _git_bounded_output(
        repo_root,
        git,
        ("cat-file", "blob", object_id),
        maximum_bytes=maximum_bytes,
        label=f"validation artifact blob {path}",
    )


def _validation_artifacts(
    receipt: EngineeringValidationReceipt,
) -> tuple[EngineeringValidationArtifact, ...]:
    artifacts = tuple(artifact for step in receipt.steps for artifact in (step.stdout, step.stderr))
    return (
        *artifacts,
        receipt.pytest_observation.junit_xml,
        receipt.pytest_observation.coverage_json,
    )


def _verify_validation_plan(receipt: EngineeringValidationReceipt) -> None:
    expected = _expected_validation_plan(receipt.receipt_id)
    observed = tuple((step.step_id, step.argv) for step in receipt.steps)
    if observed != expected:
        raise HandoffError("validation receipt command plan differs from the frozen core plan")
    evidence_root = f"evidence/validation/{receipt.receipt_id}"
    previous_finished_at = None
    for step in receipt.steps:
        if (
            step.working_directory != "."
            or step.expected_exit_code != 0
            or step.observed_exit_code != 0
            or step.result != "pass"
            or step.stdout.path != f"{evidence_root}/{step.step_id}.stdout.txt"
            or step.stderr.path != f"{evidence_root}/{step.step_id}.stderr.txt"
            or step.stdout.media_type != _VALIDATION_LOG_MEDIA_TYPE
            or step.stderr.media_type != _VALIDATION_LOG_MEDIA_TYPE
        ):
            raise HandoffError("validation receipt step evidence differs from the frozen core plan")
        if previous_finished_at is not None and step.started_at < previous_finished_at:
            raise HandoffError("validation receipt steps overlap or are chronologically reordered")
        previous_finished_at = step.finished_at
    if (
        receipt.pytest_observation.junit_xml.path != f"{evidence_root}/pytest.junit.xml"
        or receipt.pytest_observation.junit_xml.media_type != _VALIDATION_JUNIT_MEDIA_TYPE
        or receipt.pytest_observation.coverage_json.path != f"{evidence_root}/coverage.json"
        or receipt.pytest_observation.coverage_json.media_type != _VALIDATION_COVERAGE_MEDIA_TYPE
        or receipt.result != "pass"
    ):
        raise HandoffError("validation receipt structured evidence differs from the frozen plan")
    artifacts = _validation_artifacts(receipt)
    expected_artifact_paths = {
        *(f"{evidence_root}/{step_id}.stdout.txt" for step_id, _argv in expected),
        *(f"{evidence_root}/{step_id}.stderr.txt" for step_id, _argv in expected),
        f"{evidence_root}/pytest.junit.xml",
        f"{evidence_root}/coverage.json",
    }
    if len(artifacts) != 18 or {artifact.path for artifact in artifacts} != expected_artifact_paths:
        raise HandoffError("validation receipt does not contain the exact 18-artifact inventory")


def _xml_nonnegative_integer(value: str | None, label: str) -> int:
    if value is None or not value.isascii() or not value.isdecimal():
        raise HandoffError(f"JUnit {label} is not a nonnegative integer")
    return int(value)


def _xml_nonnegative_number(value: str | None, label: str) -> float:
    if value is None:
        raise HandoffError(f"JUnit {label} is missing")
    try:
        parsed = float(value)
    except ValueError as error:
        raise HandoffError(f"JUnit {label} is not numeric") from error
    if not math.isfinite(parsed) or parsed < 0:
        raise HandoffError(f"JUnit {label} is not finite and nonnegative")
    return parsed


def _junit_case_counts(cases: Sequence[ET.Element]) -> tuple[int, int, int, int]:
    failed = errors = skipped = 0
    for case in cases:
        _xml_nonnegative_number(case.get("time"), "testcase time")
        if "assertions" in case.attrib:
            _xml_nonnegative_integer(case.get("assertions"), "testcase assertions")
        outcomes = [child.tag for child in case if child.tag in {"failure", "error", "skipped"}]
        if len(outcomes) > 1 or any(
            child.tag not in {"failure", "error", "skipped", "system-out", "system-err"}
            for child in case
        ):
            raise HandoffError("JUnit testcase outcome is ambiguous")
        if outcomes == ["failure"]:
            failed += 1
        elif outcomes == ["error"]:
            errors += 1
        elif outcomes == ["skipped"]:
            skipped += 1
    passed = len(cases) - failed - errors - skipped
    return passed, failed, errors, skipped


def _cross_check_junit_aggregate(
    element: ET.Element,
    counts: tuple[int, int, int, int],
    label: str,
) -> None:
    passed, failed, errors, skipped = counts
    expected = {
        "tests": passed + failed + errors + skipped,
        "failures": failed,
        "errors": errors,
        "skipped": skipped,
    }
    for attribute, value in expected.items():
        if attribute in element.attrib and (
            _xml_nonnegative_integer(element.get(attribute), f"{label} {attribute}") != value
        ):
            raise HandoffError(f"JUnit {label} totals do not follow from its testcases")
    for attribute in ("disabled", "assertions"):
        if attribute in element.attrib:
            _xml_nonnegative_integer(element.get(attribute), f"{label} {attribute}")
    if "time" in element.attrib:
        _xml_nonnegative_number(element.get("time"), f"{label} time")


def _junit_node_identity(node_id: str) -> tuple[str, str]:
    parts = node_id.split("::")
    if len(parts) != 2:
        raise HandoffError("credibility control node identity is invalid")
    relative, function_name = parts
    pure = PurePosixPath(relative)
    if (
        pure.is_absolute()
        or ".." in pure.parts
        or not pure.parts
        or pure.parts[0] != "tests"
        or pure.suffix != ".py"
        or pure.as_posix() != relative
        or not function_name.startswith("test_")
    ):
        raise HandoffError("credibility control node identity is invalid")
    return ".".join(pure.with_suffix("").parts), function_name


def _recompute_junit(
    data: bytes,
    *,
    required_nodes: Sequence[str] = (),
) -> tuple[int, int, int, int]:
    if len(data) > _MAX_VALIDATION_STRUCTURED_ARTIFACT_BYTES:
        raise HandoffError("JUnit artifact exceeds its verification bound")
    try:
        document = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HandoffError("JUnit artifact is not strict UTF-8") from error
    upper = document.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise HandoffError("JUnit declarations are forbidden")
    try:
        root = ET.fromstring(  # noqa: S314 - bounded UTF-8 with entity declarations rejected
            document
        )
    except (ET.ParseError, ValueError) as error:
        raise HandoffError("JUnit artifact is not valid XML") from error
    if root.tag != "testsuites" or len(root) != 1 or root[0].tag != "testsuite":
        raise HandoffError("JUnit artifact must contain one direct pytest suite")
    suite = root[0]
    if any(
        child.tag not in {"properties", "testcase", "system-out", "system-err"} for child in suite
    ):
        raise HandoffError("JUnit suite must be flat and contain only pytest result elements")
    _xml_nonnegative_number(suite.get("time"), "suite time")
    cases = tuple(child for child in suite if child.tag == "testcase")
    identities: set[tuple[str, str]] = set()
    for case in cases:
        classname = case.get("classname")
        name = case.get("name")
        if classname is None or not classname.strip() or name is None or not name.strip():
            raise HandoffError("JUnit testcase identity is missing")
        identity = (classname, name)
        if identity in identities:
            raise HandoffError("JUnit testcase identity is duplicated")
        identities.add(identity)
    counts = _junit_case_counts(cases)
    _cross_check_junit_aggregate(suite, counts, "suite")
    _cross_check_junit_aggregate(root, counts, "root")
    if sum(counts) == 0:
        raise HandoffError("JUnit artifact contains no testcases")
    for node_id in required_nodes:
        classname, function_name = _junit_node_identity(node_id)
        matching = tuple(
            case
            for case in cases
            if case.get("classname") == classname
            and (
                case.get("name") == function_name
                or (case.get("name") or "").startswith(f"{function_name}[")
            )
        )
        if not matching or any(
            child.tag in {"failure", "error", "skipped"} for case in matching for child in case
        ):
            raise HandoffError(
                f"credibility control was not executed successfully in JUnit evidence: {node_id}"
            )
    return counts


def _credibility_control_nodes(repo_root: Path, git: str, subject_commit: str) -> tuple[str, ...]:
    data = _git_blob(
        repo_root,
        git,
        subject_commit,
        _CREDIBILITY_GATE_CONTROL_PATH,
        maximum_bytes=_MAX_CREDIBILITY_GATE_CONTROL_BYTES,
    )
    document = _json_bytes_object(data, "credibility control registry")
    controls = document.get("controls")
    if not isinstance(controls, list) or not controls:
        raise HandoffError("credibility control registry has no controls")
    nodes: set[str] = set()
    for control in controls:
        if not isinstance(control, dict):
            raise HandoffError("credibility control registry entry is invalid")
        for role in _CREDIBILITY_GATE_CONTROL_ROLES:
            node_id = control.get(role)
            if not isinstance(node_id, str):
                raise HandoffError("credibility control registry node is invalid")
            _junit_node_identity(node_id)
            nodes.add(node_id)
    return tuple(sorted(nodes))


def _json_bytes_object(data: bytes, label: str) -> dict[str, Any]:
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
    return parsed


def _integer_list(value: Any, label: str, *, positive: bool) -> tuple[int, ...]:
    if not isinstance(value, list) or any(
        isinstance(item, bool) or not isinstance(item, int) or (positive and item <= 0)
        for item in value
    ):
        raise HandoffError(f"coverage {label} is invalid")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise HandoffError(f"coverage {label} contains duplicates")
    return result


def _branch_list(value: Any, label: str) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, list):
        raise HandoffError(f"coverage {label} is invalid")
    branches: list[tuple[int, int]] = []
    for item in value:
        if (
            not isinstance(item, list)
            or len(item) != 2
            or any(isinstance(node, bool) or not isinstance(node, int) for node in item)
        ):
            raise HandoffError(f"coverage {label} is invalid")
        branches.append((item[0], item[1]))
    if len(branches) != len(set(branches)):
        raise HandoffError(f"coverage {label} contains duplicates")
    return tuple(branches)


def _summary_integer(summary: dict[str, Any], key: str, label: str) -> int:
    value = summary.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise HandoffError(f"coverage {label}.{key} is invalid")
    return value


def _verify_coverage_summary(
    summary: Any,
    *,
    covered_lines: int,
    num_statements: int,
    covered_branches: int,
    num_branches: int,
    label: str,
) -> None:
    if not isinstance(summary, dict):
        raise HandoffError(f"coverage {label} summary is invalid")
    expected = {
        "covered_lines": covered_lines,
        "num_statements": num_statements,
        "missing_lines": num_statements - covered_lines,
        "covered_branches": covered_branches,
        "num_branches": num_branches,
        "missing_branches": num_branches - covered_branches,
    }
    if any(_summary_integer(summary, key, label) != value for key, value in expected.items()):
        raise HandoffError(f"coverage {label} summary does not follow from raw observations")
    percentage = summary.get("percent_covered")
    if isinstance(percentage, bool) or not isinstance(percentage, int | float):
        raise HandoffError(f"coverage {label}.percent_covered is invalid")
    denominator = num_statements + num_branches
    expected_percentage = (
        100.0 if denominator == 0 else 100.0 * (covered_lines + covered_branches) / denominator
    )
    # Coverage.py's display string is presentation only; raw integer counts govern this verdict.
    if not math.isclose(
        float(percentage),
        expected_percentage,
        rel_tol=_COVERAGE_PERCENT_TOLERANCE,
        abs_tol=_COVERAGE_PERCENT_TOLERANCE,
    ):
        raise HandoffError(f"coverage {label} percentage does not follow from raw observations")


def _recompute_coverage(
    data: bytes,
    *,
    expected_paths: frozenset[str] | None = None,
) -> tuple[int, int, int, int]:
    if len(data) > _MAX_VALIDATION_STRUCTURED_ARTIFACT_BYTES:
        raise HandoffError("coverage artifact exceeds its verification bound")
    document = _json_bytes_object(data, "coverage artifact")
    meta = document.get("meta")
    files = document.get("files")
    totals = document.get("totals")
    if not isinstance(meta, dict) or meta.get("branch_coverage") is not True:
        raise HandoffError("coverage artifact is not branch-aware")
    if not isinstance(files, dict) or not files:
        raise HandoffError("coverage artifact contains no file observations")
    observed_paths: set[str] = set()
    covered_lines = num_statements = covered_branches = num_branches = 0
    for path, value in files.items():
        if not isinstance(path, str) or not path or not isinstance(value, dict):
            raise HandoffError("coverage file observation is invalid")
        _normalized_repository_path(path, "coverage file path")
        observed_paths.add(path)
        executed_lines = _integer_list(
            value.get("executed_lines"), f"{path}.executed_lines", positive=True
        )
        missing_lines = _integer_list(
            value.get("missing_lines"), f"{path}.missing_lines", positive=True
        )
        if set(executed_lines) & set(missing_lines):
            raise HandoffError(f"coverage {path} line observations overlap")
        executed_branches = _branch_list(
            value.get("executed_branches"), f"{path}.executed_branches"
        )
        missing_branches = _branch_list(value.get("missing_branches"), f"{path}.missing_branches")
        if set(executed_branches) & set(missing_branches):
            raise HandoffError(f"coverage {path} branch observations overlap")
        file_covered_lines = len(executed_lines)
        file_statements = file_covered_lines + len(missing_lines)
        file_covered_branches = len(executed_branches)
        file_branches = file_covered_branches + len(missing_branches)
        _verify_coverage_summary(
            value.get("summary"),
            covered_lines=file_covered_lines,
            num_statements=file_statements,
            covered_branches=file_covered_branches,
            num_branches=file_branches,
            label=path,
        )
        covered_lines += file_covered_lines
        num_statements += file_statements
        covered_branches += file_covered_branches
        num_branches += file_branches
    if expected_paths is not None and observed_paths != expected_paths:
        raise HandoffError(
            "coverage file inventory differs from the implementation Python source inventory"
        )
    _verify_coverage_summary(
        totals,
        covered_lines=covered_lines,
        num_statements=num_statements,
        covered_branches=covered_branches,
        num_branches=num_branches,
        label="totals",
    )
    return covered_lines, num_statements, covered_branches, num_branches


def _verify_checkpoint_v2_receipt(
    repo_root: Path,
    checkpoint_record: ResearchMemoryRecord,
    checkpoint: _CheckpointPayload,
    mission_report: Any,
) -> _VerifiedValidationReceipt:
    link = checkpoint.validation_receipt
    if checkpoint.handoff_contract != _RECOVERY_CHECKPOINT_CONTRACT_V2 or link is None:
        raise HandoffError("checkpoint-v2 validation receipt link is unavailable")
    verifier_refs = tuple(
        evidence for evidence in checkpoint_record.evidence if evidence.role == "verifier"
    )
    if len(verifier_refs) != 1:
        raise HandoffError("checkpoint-v2 requires one exact validation receipt evidence ref")
    evidence = verifier_refs[0]
    if (
        urlsplit(evidence.uri).scheme
        or evidence.uri != link.path
        or evidence.git_commit != link.git_commit
        or evidence.sha256 != link.sha256
        or evidence.media_type != link.media_type
    ):
        raise HandoffError("checkpoint-v2 receipt link differs from its verifier evidence ref")

    try:
        git = trusted_repository_git(repo_root, TRUSTED_GIT_PATH)
    except GitTrustError as error:
        raise HandoffError("checkpoint-v2 receipt Git state is untrusted") from error
    subject_commit = checkpoint.implementation_commit
    evidence_commit = link.git_commit
    if checkpoint_record.source_commit != subject_commit:
        raise HandoffError("checkpoint-v2 source commit differs from its implementation commit")
    if _git_commit_parents(repo_root, git, evidence_commit) != (subject_commit,):
        raise HandoffError(
            "validation evidence commit is not the single-parent child of its subject"
        )
    _verify_v2_finalization_topology(repo_root, git, evidence_commit)
    subject_tree = _git_commit_tree(repo_root, git, subject_commit)
    implementation_source_paths = _git_python_source_paths(
        repo_root,
        git,
        subject_commit,
    )

    receipt_data = _read_regular_file(repo_root, link.path, "validation receipt")
    if (
        not receipt_data
        or len(receipt_data) > _MAX_VALIDATION_RECEIPT_BYTES
        or len(receipt_data) != link.bytes
        or sha256_bytes(receipt_data) != link.sha256
        or _git_blob(
            repo_root,
            git,
            evidence_commit,
            link.path,
            maximum_bytes=_MAX_VALIDATION_RECEIPT_BYTES,
        )
        != receipt_data
    ):
        raise HandoffError("validation receipt bytes differ from their checkpoint binding")
    receipt_object = _json_bytes_object(receipt_data, "validation receipt")
    try:
        receipt = EngineeringValidationReceipt.model_validate(receipt_object)
    except ValidationError as error:
        raise HandoffError("validation receipt violates its domain contract") from error
    if canonical_json_pretty(receipt) != receipt_data:
        raise HandoffError("validation receipt is not canonical JSON")
    if (
        receipt.receipt_id != link.receipt_id
        or receipt.subject_commit != subject_commit
        or receipt.subject_tree != subject_tree
        or receipt.producer_actor_id != checkpoint_record.actor.actor_id
    ):
        raise HandoffError("validation receipt identity or same-operator binding is invalid")
    _verify_validation_plan(receipt)

    artifacts = _validation_artifacts(receipt)
    artifact_bindings: list[tuple[str, str, int]] = []
    artifact_data: dict[str, bytes] = {}
    for artifact in artifacts:
        data = _read_regular_file(repo_root, artifact.path, f"validation artifact {artifact.path}")
        maximum_bytes = (
            _MAX_VALIDATION_LOG_BYTES
            if artifact.media_type == _VALIDATION_LOG_MEDIA_TYPE
            else _MAX_VALIDATION_STRUCTURED_ARTIFACT_BYTES
        )
        if (
            len(data) > maximum_bytes
            or len(data) != artifact.bytes
            or sha256_bytes(data) != artifact.sha256
            or _git_blob(
                repo_root,
                git,
                evidence_commit,
                artifact.path,
                maximum_bytes=maximum_bytes,
            )
            != data
        ):
            raise HandoffError(
                f"validation artifact differs from its receipt binding: {artifact.path}"
            )
        if _VALIDATION_CREDENTIAL_RE.search(data) is not None:
            raise HandoffError(
                f"validation artifact contains a credential signature: {artifact.path}"
            )
        if artifact.media_type == _VALIDATION_LOG_MEDIA_TYPE:
            try:
                data.decode("utf-8")
            except UnicodeDecodeError as error:
                raise HandoffError(f"validation log is not valid UTF-8: {artifact.path}") from error
        artifact_bindings.append((artifact.path, artifact.sha256, artifact.bytes))
        artifact_data[artifact.path] = data
    for step in receipt.steps:
        if not artifact_data[step.stdout.path] and not artifact_data[step.stderr.path]:
            raise HandoffError(f"validation step has no recorded output: {step.step_id}")
    expected_changes = frozenset({link.path, *(artifact.path for artifact in artifacts)})
    evidence_root = f"evidence/validation/{receipt.receipt_id}"
    if _git_tree_paths(repo_root, git, evidence_commit, evidence_root) != expected_changes:
        raise HandoffError("validation evidence directory contains an unlisted artifact")
    if _git_changed_paths(repo_root, git, subject_commit, evidence_commit) != expected_changes:
        raise HandoffError(
            "validation evidence commit contains paths outside its exact receipt bundle"
        )

    junit_counts = _recompute_junit(
        artifact_data[receipt.pytest_observation.junit_xml.path],
        required_nodes=_credibility_control_nodes(repo_root, git, subject_commit),
    )
    observed_junit = (
        receipt.pytest_observation.tests_passed,
        receipt.pytest_observation.tests_failed,
        receipt.pytest_observation.tests_errors,
        receipt.pytest_observation.tests_skipped,
    )
    if junit_counts != observed_junit:
        raise HandoffError("validation receipt test counts do not follow from JUnit evidence")
    coverage_counts = _recompute_coverage(
        artifact_data[receipt.pytest_observation.coverage_json.path],
        expected_paths=implementation_source_paths,
    )
    observed_coverage = (
        receipt.pytest_observation.covered_lines,
        receipt.pytest_observation.num_statements,
        receipt.pytest_observation.covered_branches,
        receipt.pytest_observation.num_branches,
    )
    if coverage_counts != observed_coverage:
        raise HandoffError("validation receipt coverage counts do not follow from raw evidence")

    check_ids = tuple(check.check_id for check in mission_report.checks)
    failed_ids = tuple(check.check_id for check in mission_report.checks if not check.passed)
    mission_observation = receipt.mission_observation
    if (
        check_ids != _EXPECTED_MISSION_CHECK_IDS
        or mission_observation.mission_check_ids != _EXPECTED_MISSION_CHECK_IDS
        or mission_observation.expected_blockers != _EXPECTED_BOOTSTRAP_BLOCKERS
        or mission_observation.observed_blockers != failed_ids
        or mission_observation.missing_expected_blockers
        or mission_observation.unexpected_blockers
    ):
        raise HandoffError("validation receipt mission observation differs from live mission state")
    return _VerifiedValidationReceipt(
        receipt=receipt,
        evidence_commit=evidence_commit,
        receipt_sha256=link.sha256,
        artifact_bindings=tuple(artifact_bindings),
    )


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


def _require_checkpoint_v2_evidence(
    record: ResearchMemoryRecord,
    implementation_commit: str,
) -> None:
    if not any(evidence.role == "source" for evidence in record.evidence):
        raise HandoffError(f"{record.event_id} lacks required Git-anchored source evidence")
    verifier_count = 0
    for evidence in record.evidence:
        if urlsplit(evidence.uri).scheme or evidence.sha256 is None:
            raise HandoffError(f"{record.event_id} recovery evidence is not commit and byte bound")
        if evidence.role == "verifier":
            verifier_count += 1
            if evidence.git_commit is None:
                raise HandoffError(
                    f"{record.event_id} recovery evidence is not commit and byte bound"
                )
        elif evidence.git_commit != implementation_commit:
            raise HandoffError(f"{record.event_id} recovery evidence is not commit and byte bound")
    if verifier_count != 1:
        raise HandoffError(f"{record.event_id} requires one validation verifier evidence ref")


def _verify_current_source_verdict(
    repo_root: Path,
    records: dict[str, ResearchMemoryRecord],
    source_record: ResearchMemoryRecord,
    source: _CurrentSourceVerdictPayload,
    checkpoint: _CheckpointPayload,
) -> None:
    legacy_record = _exact_event(
        records,
        _SOURCE_VERDICT_EVENT_ID,
        event_type=MemoryEventType.FINDING,
        status=MemoryStatus.NEGATIVE,
    )
    legacy_payload = _parse_source_payload(legacy_record.payload)
    if not isinstance(legacy_payload, _LegacySourceVerdictPayload):
        raise HandoffError("legacy source verdict no longer has its frozen payload")
    evidence_refs = source_record.evidence
    evidence = evidence_refs[0] if len(evidence_refs) == 1 else None
    if (
        source_record.summary != _CURRENT_SOURCE_SUMMARY
        or source_record.source_commit != checkpoint.implementation_commit
        or source_record.sequence <= legacy_record.sequence
        or source_record.links != {_CURRENT_SOURCE_CORRECTION_LINK: _SOURCE_VERDICT_EVENT_ID}
        or evidence is None
        or evidence.role != "source"
        or evidence.uri != _CURRENT_SOURCE_AUDIT_PATH
        or urlsplit(evidence.uri).scheme
        or evidence.git_commit != checkpoint.implementation_commit
        or evidence.media_type != "text/markdown"
        or evidence.access != AccessClass.INTERNAL
        or evidence.label_access != LabelAccess.NONE
        or evidence.sha256 is None
    ):
        raise HandoffError("checkpoint-v2 source verdict differs from its exact bounded correction")
    try:
        git = trusted_repository_git(repo_root, TRUSTED_GIT_PATH)
    except GitTrustError as error:
        raise HandoffError("checkpoint-v2 source verdict Git state is untrusted") from error
    committed = _git_blob(
        repo_root,
        git,
        checkpoint.implementation_commit,
        _CURRENT_SOURCE_AUDIT_PATH,
        maximum_bytes=_MAX_INPUT_BYTES,
    )
    current = _read_regular_file(
        repo_root,
        _CURRENT_SOURCE_AUDIT_PATH,
        "current source-role audit",
    )
    if not committed or current != committed or sha256_bytes(committed) != evidence.sha256:
        raise HandoffError("checkpoint-v2 source verdict evidence is not content-valid at A")
    # Parsing already freezes every bounded payload field; retain the value to make that
    # dependency explicit at this verification boundary.
    if tuple(source.source_architecture) != _CURRENT_SOURCE_ARCHITECTURE:
        raise HandoffError("checkpoint-v2 source verdict architecture is not frozen")


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
    else:
        common_versioned_contract = (
            checkpoint_record.stage == _RECOVERY_STAGE
            and handoff_record.stage == _RECOVERY_STAGE
            and handoff.handoff_contract == _RECOVERY_HANDOFF_CONTRACT
            and checkpoint.action == RECOVERY_CHECKPOINT_ACTION
            and checkpoint.outcome == RECOVERY_CHECKPOINT_OUTCOME
            and checkpoint.authority_effect == RECOVERY_CHECKPOINT_AUTHORITY_EFFECT
            and handoff.state == RECOVERY_HANDOFF_STATE
            and handoff.next_action == RECOVERY_HANDOFF_NEXT_ACTION
            and tuple(handoff.forbidden_until_activation) == _CANONICAL_FORBIDDEN_ACTIONS
        )
        if checkpoint.handoff_contract == _RECOVERY_CHECKPOINT_CONTRACT:
            validation = checkpoint.validation
            links_are_exact = handoff_record.links == {
                "checkpoint": checkpoint_record.event_id,
                "engine_boundary": _ENGINE_BOUNDARY_EVENT_ID,
                "source_verdict": _SOURCE_VERDICT_EVENT_ID,
            }
            checkpoint_evidence_is_v2 = False
            validation_is_exact = (
                validation is not None and validation.mission_check_ids is not None
            )
        elif checkpoint.handoff_contract == _RECOVERY_CHECKPOINT_CONTRACT_V2:
            links_are_exact = (
                set(handoff_record.links) == {"checkpoint", "engine_boundary", "source_verdict"}
                and handoff_record.links.get("checkpoint") == checkpoint_record.event_id
                and handoff_record.links.get("engine_boundary") == _ENGINE_BOUNDARY_EVENT_ID
                and handoff_record.links.get("source_verdict") is not None
            )
            checkpoint_evidence_is_v2 = True
            validation_is_exact = (
                checkpoint.validation is None and checkpoint.validation_receipt is not None
            )
        else:
            links_are_exact = False
            checkpoint_evidence_is_v2 = False
            validation_is_exact = False
        if not common_versioned_contract or not links_are_exact or not validation_is_exact:
            raise HandoffError("latest recovery pair lacks the versioned handoff contract")
        if checkpoint_evidence_is_v2:
            _require_checkpoint_v2_evidence(checkpoint_record, checkpoint.implementation_commit)
        else:
            _require_recovery_evidence(
                checkpoint_record,
                checkpoint.implementation_commit,
                frozenset({"source", "verifier"}),
            )
    if legacy_pair:
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
    initial_modules = _loaded_fieldtrue_modules()
    wrapper_bindings = _capture_preloaded_wrapper_modules(initial_modules)
    bound_module_hashes = _verify_bound_module_sources(repo_root)
    wrapper_hashes = _verify_module_sources(repo_root, wrapper_bindings)
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

    source = _parse_source_payload(source_record.payload)
    engine = _parse_payload(_EngineBoundaryPayload, engine_record.payload, "engine boundary")
    assert isinstance(engine, _EngineBoundaryPayload)
    if checkpoint.handoff_contract == _RECOVERY_CHECKPOINT_CONTRACT_V2 and not isinstance(
        source, _CurrentSourceVerdictPayload
    ):
        raise HandoffError("checkpoint-v2 must link the current bounded source verdict")
    if checkpoint.handoff_contract == _RECOVERY_CHECKPOINT_CONTRACT_V2:
        if (
            source_record.mission_id != "inbar"
            or source_record.schema_version != "daniel.research-memory.v2"
        ):
            raise HandoffError("checkpoint-v2 source verdict has the wrong mission identity")
        assert isinstance(source, _CurrentSourceVerdictPayload)
        _verify_current_source_verdict(repo_root, by_id, source_record, source, checkpoint)
    if source_record.sequence >= handoff_record.sequence:
        raise HandoffError("source verdict must precede the handoff that selects it")
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
    verified_receipt: _VerifiedValidationReceipt | None = None
    if checkpoint.handoff_contract == _RECOVERY_CHECKPOINT_CONTRACT_V2:
        verified_receipt = _verify_checkpoint_v2_receipt(
            repo_root, checkpoint_record, checkpoint, mission_report
        )
        mission_observation = verified_receipt.receipt.mission_observation
        expected_failures = sorted(mission_observation.expected_blockers)
        checkpoint_mission_checks = len(mission_observation.mission_check_ids)
        checkpoint_mission_check_ids: tuple[str, ...] | None = mission_observation.mission_check_ids
    else:
        validation = checkpoint.validation
        if validation is None:
            raise HandoffError("checkpoint inline validation is unavailable")
        expected_failures = sorted(validation.expected_blockers)
        if validation.unexpected_blockers:
            raise HandoffError("checkpoint records unexpected mission blockers")
        checkpoint_mission_checks = validation.mission_checks
        checkpoint_mission_check_ids = (
            tuple(validation.mission_check_ids)
            if validation.mission_check_ids is not None
            else None
        )
    if expected_failures != list(_EXPECTED_BOOTSTRAP_BLOCKERS):
        raise HandoffError("checkpoint blocker policy differs from the bootstrap renderer")
    if observed_failures != expected_failures:
        # Name both sides. A bare mismatch message forces a reader to reproduce the whole render
        # to learn which check moved, which is impossible when the divergence is platform-specific
        # and appears only on a remote runner. The detail is drawn from committed contract state,
        # not from evidence content, so it discloses nothing a reader could not already recompute.
        observed_detail = ", ".join(observed_failures) or "none"
        expected_detail = ", ".join(expected_failures) or "none"
        raise HandoffError(
            "current mission blockers differ from the linked checkpoint: "
            f"observed [{observed_detail}], checkpoint expected [{expected_detail}]"
        )
    if len(failed_checks) != 1 or failed_checks[0].detail != _EXPECTED_BOOTSTRAP_DETAIL:
        raise HandoffError("registered bootstrap blocker has an unexpected failure cause")
    if len(mission_report.checks) != checkpoint_mission_checks:
        raise HandoffError("current mission check count differs from the linked checkpoint")
    if observed_check_ids != _EXPECTED_MISSION_CHECK_IDS:
        raise HandoffError("mission validation check inventory differs from the handoff contract")
    if (
        checkpoint_mission_check_ids is not None
        and checkpoint_mission_check_ids != observed_check_ids
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
    validation_receipt_digest = (
        None
        if verified_receipt is None
        else {
            "artifact_bindings": [
                {"bytes": size, "path": path, "sha256": digest}
                for path, digest, size in verified_receipt.artifact_bindings
            ],
            "evidence_commit": verified_receipt.evidence_commit,
            "receipt_id": verified_receipt.receipt.receipt_id,
            "receipt_sha256": verified_receipt.receipt_sha256,
        }
    )
    input_digest = sha256_value(
        {
            "domain": "inbar.generated-handoff-inputs.v6",
            "renderer_contract": _RENDERER_CONTRACT,
            "renderer_sha256": renderer_hash,
            "bound_module_artifacts": bound_module_hashes,
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
            "validation_receipt": validation_receipt_digest,
        }
    )
    passed_checks = len(mission_report.checks) - len(observed_failures)
    failure_arguments = " ".join(f"--expect-failure {check_id}" for check_id in expected_failures)
    if verified_receipt is None:
        validation = checkpoint.validation
        if validation is None:
            raise HandoffError("checkpoint inline validation is unavailable")
        validation_lines = [
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
        ]
    else:
        receipt = verified_receipt.receipt
        pytest_observation = receipt.pytest_observation
        coverage_denominator = pytest_observation.num_statements + pytest_observation.num_branches
        coverage_percent = (
            100.0
            * (pytest_observation.covered_lines + pytest_observation.covered_branches)
            / coverage_denominator
        )
        validation_lines = [
            "## Same-operator engineering validation",
            "",
            (
                "These observations were recomputed from the exact committed receipt bundle. "
                "They are not an independent attestation or a scientific result."
            ),
            "Bundle integrity does not prove command execution.",
            "",
            f"- Receipt: `{_code_text(receipt.receipt_id)}`",
            f"- Evidence commit: `{_code_text(verified_receipt.evidence_commit)}`",
            f"- Assurance scope: `{_code_text(receipt.assurance_scope)}`",
            f"- Independent attestation: `{str(receipt.independent_attestation).lower()}`",
            (
                f"- Tests: {pytest_observation.tests_passed} passed, "
                f"{pytest_observation.tests_failed} failed, "
                f"{pytest_observation.tests_errors} errors, "
                f"{pytest_observation.tests_skipped} skipped"
            ),
            f"- Recomputed statement-plus-branch coverage: {coverage_percent:.2f} percent",
            f"- Mission check inventory: {len(receipt.mission_observation.mission_check_ids)}",
            f"- Resource measurement: `{receipt.resource_accounting.measurement_status}`",
            f"- Scientific result: `{receipt.scientific_result}`",
            f"- Authority effect: `{receipt.authority_effect}`",
            "",
        ]
    source_limit_lines = (
        []
        if isinstance(source, _LegacySourceVerdictPayload)
        else [
            f"- Reconnaissance scope: `{_code_text(source.reconnaissance_scope)}`",
            f"- External evidence status: `{_code_text(source.external_evidence_status)}`",
            f"- Admissibility boundary: {_markdown_text(source.admissibility_boundary)}",
        ]
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
        *source_limit_lines,
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
        *validation_lines,
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
        "## Remaining Iteration 001 acquisition-authority gates",
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
    if _verify_bound_module_sources(repo_root) != bound_module_hashes:
        raise HandoffError("bound Fieldtrue module sources changed during handoff rendering")
    if _verify_module_sources(repo_root, wrapper_bindings) != wrapper_hashes:
        raise HandoffError("preloaded Fieldtrue wrapper sources changed during handoff rendering")
    _verify_module_population(initial_modules)
    return rendered


def _render_in_process(repo_root: Path) -> bytes:
    """Render inside the current process after binding its loaded authority closure."""

    root = repo_root.resolve(strict=True)
    import_guard = _RejectUnboundFieldtrueImports(_HANDOFF_AUTHORITY_MODULE_NAME_SET)
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


def _git_head(repo_root: Path, git: str) -> str:
    try:
        head = subprocess.run(  # noqa: S603 - fixed trusted Git and literal arguments
            [git, "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=git_environment(),
            timeout=10,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise HandoffError("snapshot source Git HEAD cannot be resolved") from error
    if len(head) not in {40, 64} or any(character not in "0123456789abcdef" for character in head):
        raise HandoffError("snapshot source Git HEAD is invalid")
    return head


def _manifest_content(
    manifest: _RecoveryManifest,
) -> tuple[tuple[str, str, int], ...]:
    return tuple((item.path, item.sha256, item.size) for item in manifest.files)


def _clear_snapshot_worktree(snapshot_root: Path) -> None:
    try:
        entries = tuple(os.scandir(snapshot_root))
    except OSError as error:
        raise HandoffError("snapshot worktree cannot be enumerated") from error
    for entry in entries:
        if entry.name == ".git":
            continue
        try:
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                shutil.rmtree(entry.path)
            else:
                os.unlink(entry.path)
        except OSError as error:
            raise HandoffError("snapshot worktree cannot be cleared") from error


def _write_snapshot_file(
    snapshot_root: Path,
    relative: str,
    data: bytes,
    metadata: tuple[int, ...],
) -> None:
    destination = snapshot_root.joinpath(*PurePosixPath(relative).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(destination, data)
    try:
        executable = metadata[2] & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        destination.chmod(0o700 if executable else 0o600, follow_symlinks=False)
    except OSError as error:
        raise HandoffError(f"snapshot file mode cannot be restored: {relative}") from error


def _materialize_repository_snapshot(
    repo_root: Path,
    snapshot_root: Path,
    *,
    git: str,
    head: str,
    recovery_manifest: _RecoveryManifest,
    memory_bytes: bytes,
    memory_metadata: tuple[int, ...],
) -> None:
    _verify_recovery_manifest_git_binding(repo_root, git, head, recovery_manifest)
    clone_environment = git_environment()
    clone_environment["GIT_ALLOW_PROTOCOL"] = "file"
    try:
        clone = subprocess.run(  # noqa: S603 - fixed trusted Git and local absolute paths
            [
                git,
                "clone",
                "--quiet",
                "--no-hardlinks",
                "--",
                str(repo_root),
                str(snapshot_root),
            ],
            cwd=snapshot_root.parent,
            check=False,
            capture_output=True,
            env=clone_environment,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise HandoffError("private handoff snapshot cannot be cloned") from error
    if clone.returncode != 0:
        raise HandoffError("private handoff snapshot cannot be cloned")
    try:
        snapshot_git = trusted_repository_git(snapshot_root, TRUSTED_GIT_PATH)
    except GitTrustError as error:
        raise HandoffError("private handoff snapshot Git state is untrusted") from error
    if _git_head(snapshot_root, snapshot_git) != head:
        raise HandoffError("private handoff snapshot resolved a different Git HEAD")

    _clear_snapshot_worktree(snapshot_root)
    for item in recovery_manifest.files:
        data, metadata = _read_regular_file_snapshot(
            repo_root,
            item.path,
            f"snapshot source {item.path}",
        )
        if metadata != item.metadata or len(data) != item.size or sha256_bytes(data) != item.sha256:
            raise HandoffError(f"snapshot source changed before materialization: {item.path}")
        _write_snapshot_file(snapshot_root, item.path, data, metadata)
    _write_snapshot_file(snapshot_root, _MEMORY_PATH, memory_bytes, memory_metadata)

    snapshot_manifest = _recovery_manifest(snapshot_root)
    if _manifest_content(snapshot_manifest) != _manifest_content(recovery_manifest):
        raise HandoffError("private handoff snapshot differs from the source manifest")
    _verify_recovery_manifest_git_binding(snapshot_root, snapshot_git, head, snapshot_manifest)
    observed_memory, _ = _read_regular_file_snapshot(
        snapshot_root,
        _MEMORY_PATH,
        "snapshot research memory",
    )
    if observed_memory != memory_bytes:
        raise HandoffError("private handoff snapshot research memory differs from its source")


def _worker_envelope(document: bytes) -> bytes:
    payload = {
        "contract": _SNAPSHOT_WORKER_CONTRACT,
        "document_base64": base64.b64encode(document).decode("ascii"),
        "document_sha256": sha256_bytes(document),
        "document_size": len(document),
        "status": "ok",
    }
    return (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
        + b"\n"
    )


def _worker_error_envelope(error: HandoffError) -> bytes:
    payload = {
        "contract": _SNAPSHOT_WORKER_CONTRACT,
        "error": str(error),
        "status": "error",
    }
    return (
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "ascii"
        )
        + b"\n"
    )


def _snapshot_worker_main(repo_root: Path) -> int:
    """Fresh-interpreter entry point. It is not a supported in-process rendering API."""

    try:
        output = _worker_envelope(_render_in_process(repo_root))
    except HandoffError as error:
        output = _worker_error_envelope(error)
    sys.stdout.buffer.write(output)
    return 0


def _decode_worker_output(output: bytes) -> bytes:
    if not output or len(output) > _MAX_SNAPSHOT_WORKER_OUTPUT_BYTES or not output.endswith(b"\n"):
        raise HandoffError("snapshot-bound handoff worker returned an invalid envelope")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate worker envelope field")
            value[key] = item
        return value

    try:
        envelope = json.loads(output, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise HandoffError("snapshot-bound handoff worker returned an invalid envelope") from error
    if not isinstance(envelope, dict) or envelope.get("contract") != _SNAPSHOT_WORKER_CONTRACT:
        raise HandoffError("snapshot-bound handoff worker returned an invalid envelope")
    if envelope.get("status") == "error" and set(envelope) == {"contract", "error", "status"}:
        worker_message = envelope.get("error")
        if (
            not isinstance(worker_message, str)
            or not worker_message
            or "\n" in worker_message
            or "\r" in worker_message
        ):
            raise HandoffError("snapshot-bound handoff worker returned an invalid error")
        raise HandoffError(worker_message)
    if (
        set(envelope)
        != {
            "contract",
            "document_base64",
            "document_sha256",
            "document_size",
            "status",
        }
        or envelope.get("status") != "ok"
    ):
        raise HandoffError("snapshot-bound handoff worker returned an invalid envelope")
    encoded = envelope.get("document_base64")
    expected_hash = envelope.get("document_sha256")
    expected_size = envelope.get("document_size")
    if (
        not isinstance(encoded, str)
        or not isinstance(expected_hash, str)
        or isinstance(expected_size, bool)
        or not isinstance(expected_size, int)
        or expected_size < 0
    ):
        raise HandoffError("snapshot-bound handoff worker returned an invalid document contract")
    try:
        document = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise HandoffError(
            "snapshot-bound handoff worker returned invalid document bytes"
        ) from error
    if len(document) != expected_size or sha256_bytes(document) != expected_hash:
        raise HandoffError("snapshot-bound handoff worker document integrity failed")
    return document


_SNAPSHOT_WORKER_BOOTSTRAP = """
import sys
from pathlib import Path

if any(name == "fieldtrue" or name.startswith("fieldtrue.") for name in sys.modules):
    raise SystemExit(97)
root = Path(sys.argv[1]).resolve(strict=True)
source_root = (root / "src").resolve(strict=True)
sys.path.insert(0, str(source_root))
import fieldtrue.handoff as handoff
raise SystemExit(handoff._snapshot_worker_main(root))
""".strip()


def _launch_snapshot_worker(snapshot_root: Path) -> bytes:
    environment = git_environment()
    # Authenticated historical controls need the operator's content-verified cache and uv path.
    for name in ("HOME", "PATH", "SSL_CERT_FILE", "TEMP", "TMP", "TMPDIR"):
        if name in os.environ:
            environment[name] = os.environ[name]
    environment["PYTHONHASHSEED"] = "0"
    environment["PYTHONNOUSERSITE"] = "1"
    try:
        result = subprocess.run(  # noqa: S603 - current interpreter and fixed bootstrap program
            [
                sys.executable,
                "-P",
                "-s",
                "-B",
                "-c",
                _SNAPSHOT_WORKER_BOOTSTRAP,
                str(snapshot_root),
            ],
            cwd=snapshot_root.parent,
            check=False,
            capture_output=True,
            env=environment,
            timeout=_SNAPSHOT_WORKER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise HandoffError("snapshot-bound handoff worker timed out") from error
    except OSError as error:
        raise HandoffError("snapshot-bound handoff worker could not start") from error
    if result.returncode != 0 or result.stderr:
        raise HandoffError("snapshot-bound handoff worker failed")
    return _decode_worker_output(result.stdout)


def _render_snapshot_bound(repo_root: Path) -> bytes:
    root = repo_root.resolve(strict=True)
    try:
        git = trusted_repository_git(root, TRUSTED_GIT_PATH)
    except GitTrustError as error:
        raise HandoffError("handoff source repository Git state is untrusted") from error
    head = _git_head(root, git)
    recovery_manifest = _recovery_manifest(root)
    memory_bytes, memory_metadata = _read_regular_file_snapshot(
        root,
        _MEMORY_PATH,
        _MEMORY_PATH,
    )
    v2_evidence_commit = _v2_evidence_commit_from_memory(memory_bytes)
    if v2_evidence_commit is not None:
        _verify_v2_checkout_state(root, git, v2_evidence_commit)
    worker_result: bytes | None = None
    worker_error: Exception | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="inbar-handoff-") as temporary:
            temporary_root = Path(temporary)
            snapshot_root = temporary_root / "repository"
            _materialize_repository_snapshot(
                root,
                snapshot_root,
                git=git,
                head=head,
                recovery_manifest=recovery_manifest,
                memory_bytes=memory_bytes,
                memory_metadata=memory_metadata,
            )
            worker_result = _launch_snapshot_worker(snapshot_root)
    except Exception as error:
        worker_error = error

    try:
        final_git = trusted_repository_git(root, TRUSTED_GIT_PATH)
        if final_git != git or _git_head(root, final_git) != head:
            raise HandoffError("handoff source Git state changed during snapshot rendering")
        if _recovery_manifest(root) != recovery_manifest:
            raise HandoffError("handoff source manifest changed during snapshot rendering")
        final_memory = _read_regular_file_snapshot(root, _MEMORY_PATH, _MEMORY_PATH)
        if final_memory != (memory_bytes, memory_metadata):
            raise HandoffError("research memory changed during snapshot rendering")
        if v2_evidence_commit is not None:
            _verify_v2_checkout_state(root, final_git, v2_evidence_commit)
    except GitTrustError as error:
        raise HandoffError("handoff source Git state changed during snapshot rendering") from error
    if worker_error is not None:
        if isinstance(worker_error, HandoffError):
            raise worker_error
        raise HandoffError("snapshot-bound handoff rendering failed") from worker_error
    if worker_result is None:
        raise HandoffError("snapshot-bound handoff worker returned no result")
    return worker_result


def render_handoff(repo_root: Path) -> bytes:
    """Render exact handoff bytes in a fresh interpreter over a private repository snapshot."""

    return _render_snapshot_bound(repo_root)


def write_handoff(repo_root: Path) -> Path:
    """Atomically write the deterministic handoff document."""

    root = repo_root.resolve(strict=True)
    path = root / _HANDOFF_PATH
    atomic_write(path, render_handoff(root))
    _check_handoff_content(root)
    return path


def _check_handoff_content(root: Path) -> bytes:
    actual = _read_regular_file(root, _HANDOFF_PATH, _HANDOFF_PATH)
    expected = render_handoff(root)
    final = _read_regular_file(root, _HANDOFF_PATH, _HANDOFF_PATH)
    if actual != final or final != expected:
        raise HandoffError("HANDOFF.md is stale; run `uv run inbar handoff render`")
    return expected


def check_handoff(repo_root: Path) -> None:
    """Require exact generated bytes and a clean finalized recovery commit when V2 is active."""

    root = repo_root.resolve(strict=True)
    expected = _check_handoff_content(root)
    memory_bytes = _read_regular_file(root, _MEMORY_PATH, _MEMORY_PATH)
    evidence_commit = _v2_evidence_commit_from_memory(memory_bytes)
    if evidence_commit is not None:
        try:
            git = trusted_repository_git(root, TRUSTED_GIT_PATH)
        except GitTrustError as error:
            raise HandoffError("final handoff Git state is untrusted") from error
        head = _git_head(root, git)
        if _verify_v2_finalization_topology(root, git, evidence_commit):
            raise HandoffError("final handoff commit has not been created from validation evidence")
        if _git_worktree_changed_paths(root, git):
            raise HandoffError("final handoff checkout is not clean")
        final_memory = _read_regular_file(root, _MEMORY_PATH, _MEMORY_PATH)
        try:
            final_git = trusted_repository_git(root, TRUSTED_GIT_PATH)
        except GitTrustError as error:
            raise HandoffError("final handoff Git state changed during verification") from error
        if final_git != git or _git_head(root, final_git) != head or final_memory != memory_bytes:
            raise HandoffError("final handoff Git or memory state changed during verification")
        if _verify_v2_finalization_topology(root, final_git, evidence_commit):
            raise HandoffError("final handoff topology changed during verification")
        if _git_worktree_changed_paths(root, final_git):
            raise HandoffError("final handoff checkout changed during verification")
    if (
        _read_regular_file(root, _HANDOFF_PATH, _HANDOFF_PATH) != expected
        or _read_regular_file(root, _MEMORY_PATH, _MEMORY_PATH) != memory_bytes
    ):
        raise HandoffError("final handoff inputs changed during verification")
