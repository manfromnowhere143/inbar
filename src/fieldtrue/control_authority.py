"""Outcome-bound admission-control execution and receipt generation.

The generator is intentionally separate from the acquisition validator.  It executes the
frozen controls in isolated pytest processes and requires each control to emit one machine
observation through :func:`record_control_observation` or
:func:`record_control_exception`.  A passing pytest exit code without that evidence cannot
produce a signed receipt.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, NoReturn, Self, TypeVar

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, Field, model_validator

import fieldtrue.runner_trust as runner_trust
from fieldtrue.acquisition import (
    _CONTROL_REQUIREMENTS,
    _REQUIRED_CONTROL_IDS,
    AcquisitionAdmissionReport,
    AcquisitionCandidateRegistry,
    AcquisitionContract,
    AcquisitionGateResult,
    AdmissionControlResult,
    AdmissionControlSuiteReceipt,
    ArtifactBinding,
    AttestationSubjectKind,
    attestation_subject_hash,
    issue_attestation,
)
from fieldtrue.canonical import (
    atomic_write,
    canonical_json_pretty,
    read_json,
    sha256_bytes,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import FrozenModel, GitObjectId, Identifier, Sha256
from fieldtrue.git_trust import GitTrustError, git_environment, trusted_repository_git
from fieldtrue.receipts import load_or_create_signing_key
from fieldtrue.runner_trust import (
    MAX_RUNNER_FILE_BYTES,
    MAX_RUNNER_TREE_BYTES,
    MAX_RUNNER_TREE_ENTRIES,
    RUNNER_PYTHON_FULL_VERSION,
    AuthenticatedRunner,
    RunnerTrustError,
)

_OBSERVATION_ENV = "FIELDTRUE_CONTROL_OBSERVATION_PATH"
_OUTCOME_ENV = "FIELDTRUE_CONTROL_PYTEST_OUTCOME_PATH"
_CONTROL_ENV = "FIELDTRUE_CONTROL_ID"
_NODE_ENV = "FIELDTRUE_CONTROL_NODE_ID"
_SUITE_ID: Literal["iter001-admission-controls-v1"] = "iter001-admission-controls-v1"
_GENERATOR_PATH = "src/fieldtrue/control_authority.py"
_SOURCE_PATHS = (
    ("validator", "src/fieldtrue/acquisition.py"),
    ("fixture_builder", "tests/acquisition_helpers.py"),
    ("control_test", "tests/unit/test_acquisition.py"),
    ("generator", _GENERATOR_PATH),
    ("dependency_lock", "uv.lock"),
)
_MAX_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_AGGREGATE_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_CONTROL_SIDECAR_BYTES = 4 * 1024 * 1024
_CAPTURE_READ_BYTES = 64 * 1024
_PROCESS_TERMINATION_GRACE_SECONDS = 0.25
_PROCESS_GROUP_POLL_SECONDS = 0.01
_RUNNER_ROOT_DISTRIBUTIONS = frozenset({"certifi", "networkx", "pydantic", "pynacl", "pytest"})
_RUNNER_SNAPSHOT_PATHS = (
    "pyproject.toml",
    "uv.lock",
    "src/fieldtrue",
    "tests/__init__.py",
    "tests/acquisition_helpers.py",
    "tests/unit/__init__.py",
    "tests/unit/test_acquisition.py",
)
_PARENT_SOURCE_MODULES = (
    ("fieldtrue.acquisition", "src/fieldtrue/acquisition.py"),
    ("fieldtrue.approvals", "src/fieldtrue/approvals.py"),
    ("fieldtrue.canonical", "src/fieldtrue/canonical.py"),
    ("fieldtrue.control_authority", "src/fieldtrue/control_authority.py"),
    ("fieldtrue.domain", "src/fieldtrue/domain.py"),
    ("fieldtrue.git_trust", "src/fieldtrue/git_trust.py"),
    ("fieldtrue.planning", "src/fieldtrue/planning.py"),
    ("fieldtrue.receipts", "src/fieldtrue/receipts.py"),
    ("fieldtrue.runner_trust", "src/fieldtrue/runner_trust.py"),
    ("fieldtrue.splits", "src/fieldtrue/splits.py"),
)

Verdict = Literal[
    "PASS_PILOT",
    "BLOCKED_ACQUISITION",
    "BLOCKED_RIGHTS",
    "INVALID",
    "KILL_CONSTRUCT",
]

ControlSidecarT = TypeVar("ControlSidecarT", bound=BaseModel)


class ControlAuthorityError(RuntimeError):
    """The production control evidence is incomplete, ambiguous, or untrusted."""


class FixtureFile(FrozenModel):
    path: str = Field(min_length=1)
    sha256: Sha256
    bytes: int = Field(ge=0)


class FixtureSnapshot(FrozenModel):
    algorithm: Literal["fieldtrue.fixture-tree.v1"] = "fieldtrue.fixture-tree.v1"
    files: tuple[FixtureFile, ...] = Field(min_length=1)
    root_sha256: Sha256

    @model_validator(mode="after")
    def root_is_derived(self) -> Self:
        expected = sha256_value([item.model_dump(mode="json") for item in self.files])
        if self.root_sha256 != expected:
            raise ValueError("fixture tree digest is not derived from its file inventory")
        paths = [item.path for item in self.files]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ValueError("fixture file inventory must be sorted and unique")
        return self


class ControlObservation(FrozenModel):
    schema_version: Literal["fieldtrue.control-observation.v1"] = "fieldtrue.control-observation.v1"
    control_id: Identifier
    pytest_node_id: str
    fixture: FixtureSnapshot
    report_sha256: Sha256
    report: dict[str, Any]
    observed_verdict: Verdict
    observed_gate_id: Identifier
    observed_failure_code: Identifier | None


class PytestPhase(FrozenModel):
    when: Literal["setup", "call", "teardown"]
    outcome: Literal["passed", "failed", "skipped"]
    was_xfail: bool


class PytestLifecycle(FrozenModel):
    schema_version: Literal["fieldtrue.pytest-control-lifecycle.v1"] = (
        "fieldtrue.pytest-control-lifecycle.v1"
    )
    requested_node_id: str
    collected_node_ids: tuple[str, ...]
    phases: tuple[PytestPhase, ...]
    exit_status: int


class GitBoundSource(FrozenModel):
    name: Identifier
    path: str
    git_blob: GitObjectId
    sha256: Sha256
    bytes: int = Field(ge=0)


class ControlExecutionEvidence(FrozenModel):
    schema_version: Literal["fieldtrue.control-execution-evidence.v1"] = (
        "fieldtrue.control-execution-evidence.v1"
    )
    execution_commit: GitObjectId
    execution_tree: GitObjectId
    control_id: Identifier
    pytest_node_id: str
    command: tuple[str, ...]
    observation: ControlObservation
    lifecycle: PytestLifecycle
    stdout_sha256: Sha256
    stderr_sha256: Sha256
    stdout: str
    stderr: str


class ControlManifestEntry(FrozenModel):
    control_id: Identifier
    pytest_node_id: str
    expected_verdict: Verdict
    expected_gate_id: Identifier
    expected_failure_code: Identifier | None
    evidence: ArtifactBinding


class ControlExecutionManifest(FrozenModel):
    schema_version: Literal["fieldtrue.control-execution-manifest.v1"] = (
        "fieldtrue.control-execution-manifest.v1"
    )
    suite_id: Literal["iter001-admission-controls-v1"]
    execution_commit: GitObjectId
    execution_tree: GitObjectId
    started_at: datetime
    finished_at: datetime
    repository_clean_before: Literal[True]
    repository_clean_after: Literal[True]
    dependency_mode: Literal["lock-hash-authenticated-wheels"]
    uv_executable: str
    uv_executable_sha256: Sha256
    uv_version: str
    python_executable_sha256: Sha256
    python_version: str
    runner_environment_sha256: Sha256
    artifact_set_sha256: Sha256
    environment_policy: tuple[str, ...]
    sources: tuple[GitBoundSource, ...]
    controls: tuple[ControlManifestEntry, ...]

    @model_validator(mode="after")
    def manifest_is_complete(self) -> Self:
        if self.started_at.tzinfo is None or self.finished_at.tzinfo is None:
            raise ValueError("execution timestamps must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("execution finish precedes its start")
        if tuple(item.control_id for item in self.controls) != _REQUIRED_CONTROL_IDS:
            raise ValueError("execution manifest does not cover the frozen controls exactly")
        if tuple((item.name, item.path) for item in self.sources) != _SOURCE_PATHS:
            raise ValueError("execution manifest source inventory is not exact")
        return self


def _control_requirement(control_id: str) -> tuple[str, Verdict, str, str | None]:
    try:
        node_id, verdict, gate_id, failure_code = _CONTROL_REQUIREMENTS[control_id]
    except KeyError as error:
        raise ControlAuthorityError(f"unknown admission control: {control_id}") from error
    return node_id, verdict, gate_id, failure_code  # type: ignore[return-value]


def snapshot_fixture_tree(root: Path) -> FixtureSnapshot:
    """Hash every regular file in one fixture tree; reject links and special files."""

    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ControlAuthorityError("control fixture root is not a directory")
    files: list[FixtureFile] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ControlAuthorityError(f"control fixture contains a symbolic link: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ControlAuthorityError(f"control fixture contains a special file: {relative}")
        files.append(
            FixtureFile(
                path=relative,
                sha256=sha256_file(path),
                bytes=path.stat().st_size,
            )
        )
    if not files:
        raise ControlAuthorityError("control fixture tree is empty")
    return FixtureSnapshot(
        files=tuple(files),
        root_sha256=sha256_value([item.model_dump(mode="json") for item in files]),
    )


def _gate(report: AcquisitionAdmissionReport, gate_id: str) -> AcquisitionGateResult:
    matches = [gate for gate in report.gates if gate.gate_id == gate_id]
    if len(matches) != 1:
        raise ControlAuthorityError(f"control report does not contain one {gate_id} gate")
    return matches[0]


def _failure_text(gate: AcquisitionGateResult) -> str:
    return canonical_json_pretty(gate.observed).decode("utf-8").lower()


def _supports_failure_code(
    report: AcquisitionAdmissionReport,
    gate_id: str,
    failure_code: str | None,
    *,
    fixture_root: Path,
) -> bool:
    if failure_code is None:
        return gate_id == "admission" and all(gate.status == "pass" for gate in report.gates)
    gate = _gate(report, gate_id)
    text = _failure_text(gate)
    tokens: dict[str, tuple[str, ...]] = {
        "duplicate-full-capture": ("identical full-capture bytes",),
        "nonphysical-root": ("not one claim-bearing physical root event",),
        "commercial-research-rights": ("commercial_research",),
        "model-visible-forbidden-field": ("forbidden fields are model-visible",),
        "one-modality": ("one-modality:", "insufficient distinct operational modality"),
        "duplicate-modality-content": (
            "modelvisibleprojection",
            "distinct operational modality",
        ),
        "stationary-image-proxy": ("stationary-image-proxy:",),
        "shuffled-modality": ("shuffled-modality:", "source sequence receipt"),
        "clock-transform-bound": ("clock alignment or missingness",),
        "truth-chronology": ("truth custody", "chronology"),
        "known-only-hypotheses": ("invalid hypothesisset",),
        "forbidden-role-overlap": ("forbidden role independence overlap",),
        "forged-approval": ("forged-approval:", "diagnostic approval"),
        "diagnostic-realization": ("diagnostic-realization:",),
        "recovery-realization": ("recovery and settled outcome are not cross-bound",),
        "shortcut-resolves-mechanism": ("resolving_rules", "source-identity"),
        "missing-no-op-comparator": ("comparators/no_op/implementation.txt",),
        "missing-random-safe-comparator": ("comparators/random_safe/implementation.txt",),
        "missing-cheapest-safe-comparator": ("comparators/cheapest_safe/implementation.txt",),
        "missing-wrong-safe-comparator": ("comparators/wrong_safe/implementation.txt",),
    }
    if failure_code == "count-intersection":
        checks = gate.observed.get("checks") if isinstance(gate.observed, dict) else None
        try:
            registry = AcquisitionCandidateRegistry.model_validate(
                read_json(fixture_root / "candidate_registry.json")
            )
        except (OSError, ValueError):
            return False
        candidate_ids = tuple(candidate.incident_id for candidate in registry.candidates)
        return (
            isinstance(checks, dict)
            and checks.get("complete_count") is False
            and len(candidate_ids) >= 30
            and report.candidate_registry_sha256 == sha256_value(registry)
            and report.candidate_incident_ids == tuple(sorted(candidate_ids))
            and len(report.eligible_incident_ids) < len(candidate_ids)
        )
    if failure_code == "duplicate-modality-content":
        return any(token in text for token in tokens[failure_code])
    if failure_code == "known-only-hypotheses":
        for dossier_path in sorted((fixture_root / "dossiers").glob("*.json")):
            dossier = read_json(dossier_path)
            if not isinstance(dossier, dict):
                continue
            binding = dossier.get("hypothesis_set")
            if not isinstance(binding, dict) or not isinstance(binding.get("path"), str):
                continue
            hypothesis_set = read_json(fixture_root / binding["path"])
            hypotheses = (
                hypothesis_set.get("hypotheses") if isinstance(hypothesis_set, dict) else None
            )
            if (
                isinstance(hypotheses, list)
                and hypotheses
                and not any(
                    isinstance(hypothesis, dict) and hypothesis.get("unknown") is True
                    for hypothesis in hypotheses
                )
            ):
                return all(token in text for token in tokens[failure_code])
        return False
    required = tokens.get(failure_code)
    return required is not None and all(token in text for token in required)


def _control_environment() -> tuple[str, str, Path] | None:
    values = (
        os.environ.get(_CONTROL_ENV),
        os.environ.get(_NODE_ENV),
        os.environ.get(_OBSERVATION_ENV),
    )
    if all(value is None for value in values):
        return None
    if any(value is None or not value for value in values):
        raise ControlAuthorityError("control observation environment is incomplete")
    control_id, node_id, output = values
    if control_id is None or node_id is None or output is None:
        raise ControlAuthorityError("control observation environment is incomplete")
    expected_node, _, _, _ = _control_requirement(control_id)
    if node_id != expected_node:
        raise ControlAuthorityError("control observation node differs from frozen authority")
    return control_id, node_id, Path(output)


def _write_exclusive(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def record_control_observation(
    input_root: Path,
    report: AcquisitionAdmissionReport,
) -> None:
    """Emit one generator-bound observation when a frozen control is executing.

    The function is a no-op in ordinary test runs.  In a production control run it derives
    the expected gate and failure from frozen authority and refuses mismatched semantics.
    """

    environment = _control_environment()
    if environment is None:
        return
    control_id, node_id, output_path = environment
    _, expected_verdict, gate_id, failure_code = _control_requirement(control_id)
    if report.verdict != expected_verdict:
        raise ControlAuthorityError(
            f"{control_id} observed {report.verdict}, expected {expected_verdict}"
        )
    if not _supports_failure_code(
        report,
        gate_id,
        failure_code,
        fixture_root=input_root,
    ):
        raise ControlAuthorityError(
            f"{control_id} did not demonstrate {gate_id}:{failure_code or 'none'}"
        )
    report_value = report.model_dump(mode="json")
    observation = ControlObservation(
        control_id=control_id,
        pytest_node_id=node_id,
        fixture=snapshot_fixture_tree(input_root),
        report_sha256=sha256_value(report_value),
        report=report_value,
        observed_verdict=report.verdict,
        observed_gate_id=gate_id,
        observed_failure_code=failure_code,
    )
    _write_exclusive(output_path, canonical_json_pretty(observation))


def record_control_exception(input_root: Path, error: BaseException) -> None:
    """Emit one validation-error observation for a frozen control that cannot return a report."""

    environment = _control_environment()
    if environment is None:
        return
    control_id, node_id, output_path = environment
    _, expected_verdict, gate_id, failure_code = _control_requirement(control_id)
    if expected_verdict != "INVALID" or failure_code is None:
        raise ControlAuthorityError("exception evidence is authorized only for INVALID controls")
    message = str(error).lower()
    exception_tokens = {
        "truth-chronology": ("truth", "chronology"),
        "known-only-hypotheses": ("known mechanism hypotheses",),
    }.get(failure_code)
    if exception_tokens is None or not all(token in message for token in exception_tokens):
        raise ControlAuthorityError(f"{control_id} exception did not demonstrate {failure_code}")
    report_value = {
        "exception_type": f"{type(error).__module__}.{type(error).__qualname__}",
        "message": str(error),
    }
    observation = ControlObservation(
        control_id=control_id,
        pytest_node_id=node_id,
        fixture=snapshot_fixture_tree(input_root),
        report_sha256=sha256_value(report_value),
        report=report_value,
        observed_verdict="INVALID",
        observed_gate_id=gate_id,
        observed_failure_code=failure_code,
    )
    _write_exclusive(output_path, canonical_json_pretty(observation))


_PYTEST_REQUESTED_NODE: str | None = None
_PYTEST_COLLECTED: list[str] = []
_PYTEST_PHASES: list[PytestPhase] = []


def pytest_configure(config: Any) -> None:
    """Initialize lifecycle capture when this module is loaded as an explicit pytest plugin."""

    del config
    global _PYTEST_REQUESTED_NODE, _PYTEST_COLLECTED, _PYTEST_PHASES
    requested = os.environ.get(_NODE_ENV)
    outcome_path = os.environ.get(_OUTCOME_ENV)
    if requested is None and outcome_path is None:
        return
    if not requested or not outcome_path:
        raise ControlAuthorityError("pytest control lifecycle environment is incomplete")
    _PYTEST_REQUESTED_NODE = requested
    _PYTEST_COLLECTED = []
    _PYTEST_PHASES = []


def pytest_collection_finish(session: Any) -> None:
    if _PYTEST_REQUESTED_NODE is None:
        return
    global _PYTEST_COLLECTED
    _PYTEST_COLLECTED = [item.nodeid for item in session.items]


def pytest_runtest_logreport(report: Any) -> None:
    if _PYTEST_REQUESTED_NODE is None or report.nodeid != _PYTEST_REQUESTED_NODE:
        return
    was_xfail = bool(getattr(report, "wasxfail", False))
    _PYTEST_PHASES.append(
        PytestPhase(when=report.when, outcome=report.outcome, was_xfail=was_xfail)
    )


def pytest_sessionfinish(session: Any, exitstatus: int) -> None:
    del session
    if _PYTEST_REQUESTED_NODE is None:
        return
    output = os.environ.get(_OUTCOME_ENV)
    if not output:
        raise ControlAuthorityError("pytest lifecycle output path is missing")
    lifecycle = PytestLifecycle(
        requested_node_id=_PYTEST_REQUESTED_NODE,
        collected_node_ids=tuple(_PYTEST_COLLECTED),
        phases=tuple(_PYTEST_PHASES),
        exit_status=int(exitstatus),
    )
    _write_exclusive(Path(output), canonical_json_pretty(lifecycle))


def _run_git(repo: Path, *arguments: str, text: bool = True) -> str | bytes:
    try:
        git = trusted_repository_git(repo)
    except GitTrustError as error:
        raise ControlAuthorityError("control authority Git trust failed") from error
    try:
        completed = subprocess.run(  # noqa: S603 - fixed executable and internal arguments
            (git, *arguments),
            cwd=repo,
            check=True,
            capture_output=True,
            text=text,
            env=git_environment(),
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ControlAuthorityError("control authority Git command failed") from error
    output: str | bytes = completed.stdout
    return output.strip() if text else output


def _assert_clean_repo(repo: Path) -> None:
    status = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ControlAuthorityError("admission controls require a clean repository")


def _git_identity(repo: Path) -> tuple[str, str]:
    commit = str(_run_git(repo, "rev-parse", "HEAD"))
    tree = str(_run_git(repo, "rev-parse", f"{commit}^{{tree}}"))
    if len(commit) not in (40, 64) or len(tree) not in (40, 64):
        raise ControlAuthorityError("Git returned an unsupported object identity")
    return commit, tree


def _git_bound_source(repo: Path, commit: str, name: str, relative: str) -> GitBoundSource:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or relative != pure.as_posix():
        raise ControlAuthorityError(f"invalid source path: {relative}")
    blob = str(_run_git(repo, "rev-parse", f"{commit}:{relative}"))
    object_type = str(_run_git(repo, "cat-file", "-t", blob))
    if object_type != "blob":
        raise ControlAuthorityError(f"bound source is not a Git blob: {relative}")
    committed = _run_git(repo, "cat-file", "blob", blob, text=False)
    assert isinstance(committed, bytes)
    working = (repo / relative).read_bytes()
    if working != committed:
        raise ControlAuthorityError(f"working bytes differ from HEAD: {relative}")
    return GitBoundSource(
        name=name,
        path=relative,
        git_blob=blob,
        sha256=sha256_bytes(committed),
        bytes=len(committed),
    )


def _assert_parent_process_trusted(repo: Path) -> None:
    if any(name in os.environ for name in ("PYTHONHOME", "PYTHONPATH")):
        raise ControlAuthorityError("parent Python startup injection environment is present")
    if any(sys.modules.get(name) is not None for name in ("sitecustomize", "usercustomize")):
        raise ControlAuthorityError("parent Python startup customization is loaded")
    for module_name, relative in _PARENT_SOURCE_MODULES:
        module = sys.modules.get(module_name)
        origin = getattr(module, "__file__", None) if module is not None else None
        if not isinstance(origin, str):
            raise ControlAuthorityError(f"parent source module has no file origin: {module_name}")
        candidate = Path(origin)
        expected = repo / relative
        try:
            if (
                candidate.is_symlink()
                or expected.is_symlink()
                or candidate.resolve(strict=True) != expected.resolve(strict=True)
                or not candidate.is_file()
            ):
                raise ControlAuthorityError(
                    f"parent source module origin is unexpected: {module_name}"
                )
        except OSError as error:
            raise ControlAuthorityError(
                f"parent source module origin cannot be verified: {module_name}"
            ) from error


def _sanitized_environment(
    *,
    control_id: str,
    node_id: str,
    observation_path: Path,
    outcome_path: Path,
) -> dict[str, str]:
    return {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "NO_COLOR": "1",
        "PATH": os.defpath,
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        _CONTROL_ENV: control_id,
        _NODE_ENV: node_id,
        _OBSERVATION_ENV: str(observation_path),
        _OUTCOME_ENV: str(outcome_path),
    }


def _resolve_uv_executable() -> str:
    try:
        return str(runner_trust.resolve_pinned_uv().executable.resolved_path)
    except RunnerTrustError as error:
        raise ControlAuthorityError(str(error)) from error


def _uv_version(executable: str) -> str:
    try:
        return runner_trust.resolve_pinned_uv(Path(executable)).version
    except RunnerTrustError as error:
        raise ControlAuthorityError(str(error)) from error


def _materialize_commit_snapshot(repo: Path, commit: str, destination: Path) -> bool:
    try:
        raw = _run_git(
            repo,
            "ls-tree",
            "-r",
            "-z",
            "--full-tree",
            commit,
            "--",
            *_RUNNER_SNAPSHOT_PATHS,
            text=False,
        )
    except ControlAuthorityError:
        return False
    if not isinstance(raw, bytes):
        return False
    records = raw.split(b"\0")
    if records[-1:] != [b""] or len(records) > MAX_RUNNER_TREE_ENTRIES:
        return False
    observed: set[str] = set()
    total_bytes = 0
    try:
        destination.mkdir(mode=0o700)
        for record in records[:-1]:
            header, raw_path = record.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            relative = raw_path.decode("utf-8")
            pure = PurePosixPath(relative)
            if (
                mode not in {"100644", "100755"}
                or object_type != "blob"
                or pure.is_absolute()
                or ".." in pure.parts
                or relative != pure.as_posix()
                or relative in observed
                or not any(
                    relative == prefix or relative.startswith(f"{prefix}/")
                    for prefix in _RUNNER_SNAPSHOT_PATHS
                )
            ):
                return False
            payload = _run_git(repo, "cat-file", "blob", object_id, text=False)
            if not isinstance(payload, bytes) or len(payload) > MAX_RUNNER_FILE_BYTES:
                return False
            total_bytes += len(payload)
            if total_bytes > MAX_RUNNER_TREE_BYTES:
                return False
            target = destination.joinpath(*pure.parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o500 if mode == "100755" else 0o400,
            )
            try:
                view = memoryview(payload)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        return False
                    view = view[written:]
            finally:
                os.close(descriptor)
            observed.add(relative)
    except (OSError, UnicodeDecodeError, ValueError):
        return False
    required_files = {"pyproject.toml", "uv.lock", "tests/unit/test_acquisition.py"}
    return required_files.issubset(observed) and any(
        path.startswith("src/fieldtrue/") for path in observed
    )


def _prepare_authenticated_runner(
    repo: Path,
    commit: str,
    root: Path,
) -> AuthenticatedRunner:
    _resolve_uv_executable()
    snapshot_root = root / "snapshot"
    if not _materialize_commit_snapshot(repo, commit, snapshot_root):
        raise ControlAuthorityError("committed control source snapshot cannot be materialized")
    try:
        return runner_trust.prepare_authenticated_runner(
            root,
            snapshot_root,
            root_distributions=_RUNNER_ROOT_DISTRIBUTIONS,
            required_imports=("nacl", "pytest"),
            artifact_cache_root=root / "artifact-cache",
        )
    except RunnerTrustError as error:
        raise ControlAuthorityError(str(error)) from error


def _authenticated_runner_is_unchanged(runner: AuthenticatedRunner) -> bool:
    return runner_trust.runner_is_unchanged(runner)


def _validate_lifecycle(lifecycle: PytestLifecycle, node_id: str) -> None:
    if lifecycle.requested_node_id != node_id or lifecycle.collected_node_ids != (node_id,):
        raise ControlAuthorityError("pytest collected a missing, extra, or substituted control")
    if lifecycle.exit_status != 0:
        raise ControlAuthorityError(
            f"pytest control failed with exit status {lifecycle.exit_status}"
        )
    if not lifecycle.phases:
        raise ControlAuthorityError("pytest emitted no lifecycle phases")
    if any(phase.outcome != "passed" or phase.was_xfail for phase in lifecycle.phases):
        raise ControlAuthorityError("pytest control skipped, xfailed, or failed")
    call_phases = [phase for phase in lifecycle.phases if phase.when == "call"]
    if len(call_phases) != 1:
        raise ControlAuthorityError("pytest control did not execute exactly one call phase")


def _artifact_binding(bundle_root: Path, path: Path) -> ArtifactBinding:
    relative = path.relative_to(bundle_root).as_posix()
    return ArtifactBinding(
        path=relative,
        sha256=sha256_file(path),
        bytes=path.stat().st_size,
        media_type="application/json",
    )


def _normalized_control_command(node_id: str) -> tuple[str, ...]:
    return (
        "<authenticated-cpython-3.12.13>",
        "-I",
        "-B",
        "-S",
        "-c",
        "<isolated-pytest-bootstrap>",
        "<execution-commit>/src",
        "<lock-hash-authenticated-site-packages>",
        "-p",
        "fieldtrue.control_authority",
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
        "--no-header",
        "--tb=short",
        node_id,
    )


def _signal_control_process_group(
    process: subprocess.Popen[bytes],
    signal_number: signal.Signals,
) -> None:
    try:
        os.killpg(process.pid, signal_number)
    except ProcessLookupError:
        return
    except OSError:
        if process.poll() is None:
            with suppress(ProcessLookupError):
                process.send_signal(signal_number)


def _control_process_group_exists(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return False
    except OSError as error:
        raise ControlAuthorityError("control process-group state cannot be verified") from error
    return True


def _wait_for_control_process_group_exit(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while _control_process_group_exists(process):
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            return False
        time.sleep(min(_PROCESS_GROUP_POLL_SECONDS, remaining_seconds))
    return True


def _terminate_remaining_control_process_group(process: subprocess.Popen[bytes]) -> None:
    if not _control_process_group_exists(process):
        return
    _signal_control_process_group(process, signal.SIGTERM)
    if _wait_for_control_process_group_exit(
        process,
        timeout_seconds=_PROCESS_TERMINATION_GRACE_SECONDS,
    ):
        return
    _signal_control_process_group(process, signal.SIGKILL)
    if not _wait_for_control_process_group_exit(
        process,
        timeout_seconds=_PROCESS_TERMINATION_GRACE_SECONDS,
    ):
        raise ControlAuthorityError("control descendant process group could not be terminated")


def _terminate_and_reap_control_process(process: subprocess.Popen[bytes]) -> None:
    _signal_control_process_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        _signal_control_process_group(process, signal.SIGKILL)
        try:
            process.wait(timeout=_PROCESS_TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired as error:
            raise ControlAuthorityError("control process could not be reaped") from error
    _terminate_remaining_control_process_group(process)


def _load_control_sidecar(
    path: Path,
    model: type[ControlSidecarT],
    *,
    label: str,
    missing_message: str,
) -> ControlSidecarT:
    data = runner_trust.stable_regular_bytes(path, maximum_bytes=_MAX_CONTROL_SIDECAR_BYTES)
    if data is None:
        try:
            path.lstat()
        except FileNotFoundError as error:
            raise ControlAuthorityError(missing_message) from error
        except OSError as error:
            raise ControlAuthorityError(f"control {label} cannot be inspected") from error
        raise ControlAuthorityError(f"control {label} is not a bounded stable regular file")
    try:
        return model.model_validate_json(data)
    except ValueError as error:
        raise ControlAuthorityError(f"control {label} is invalid") from error


def _run_bounded_control_process(
    command: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(  # noqa: S603 - runner and source are authenticated
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        start_new_session=True,
    )
    stdout_pipe = process.stdout
    stderr_pipe = process.stderr
    if stdout_pipe is None or stderr_pipe is None:
        _terminate_and_reap_control_process(process)
        raise ControlAuthorityError("control capture pipes were not created")

    stdout_capture = bytearray()
    stderr_capture = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout_seconds
    try:
        for pipe, capture in (
            (stdout_pipe, stdout_capture),
            (stderr_pipe, stderr_capture),
        ):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, capture)

        while selector.get_map():
            remaining_seconds = deadline - time.monotonic()
            if remaining_seconds <= 0:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            events = selector.select(remaining_seconds)
            if not events:
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            for key, _event_mask in events:
                capture = key.data
                stream_remaining = _MAX_CAPTURE_BYTES - len(capture)
                aggregate_remaining = _MAX_AGGREGATE_CAPTURE_BYTES - (
                    len(stdout_capture) + len(stderr_capture)
                )
                read_bytes = min(
                    _CAPTURE_READ_BYTES,
                    stream_remaining + 1,
                    aggregate_remaining + 1,
                )
                try:
                    chunk = os.read(key.fd, read_bytes)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                capture.extend(chunk)
                if (
                    len(capture) > _MAX_CAPTURE_BYTES
                    or len(stdout_capture) + len(stderr_capture) > _MAX_AGGREGATE_CAPTURE_BYTES
                ):
                    raise ControlAuthorityError("control output exceeded the capture bound")

        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise subprocess.TimeoutExpired(command, timeout_seconds)
        try:
            returncode = process.wait(timeout=remaining_seconds)
        except subprocess.TimeoutExpired as error:
            raise subprocess.TimeoutExpired(command, timeout_seconds) from error
        if _control_process_group_exists(process):
            _terminate_remaining_control_process_group(process)
            raise ControlAuthorityError("control left descendant processes after completion")
        return subprocess.CompletedProcess(
            command,
            returncode,
            bytes(stdout_capture),
            bytes(stderr_capture),
        )
    except BaseException:
        _terminate_and_reap_control_process(process)
        raise
    finally:
        selector.close()
        stdout_pipe.close()
        stderr_pipe.close()


def _run_control(
    staging: Path,
    *,
    commit: str,
    tree: str,
    control_id: str,
    runner: AuthenticatedRunner,
    timeout_seconds: int,
) -> tuple[AdmissionControlResult, ControlManifestEntry]:
    node_id, expected_verdict, expected_gate, expected_failure = _control_requirement(control_id)
    command = _normalized_control_command(node_id)
    bootstrap = (
        "import sys;sys.path[:0]=sys.argv[1:3];import pytest;"
        "raise SystemExit(pytest.main(sys.argv[3:]))"
    )
    execution_command = (
        str(runner.python_path),
        "-I",
        "-B",
        "-S",
        "-c",
        bootstrap,
        str(runner.snapshot_root / "src"),
        str(runner.site_packages),
        "-p",
        "fieldtrue.control_authority",
        "-p",
        "no:cacheprovider",
        "-o",
        "addopts=",
        "--no-header",
        "--tb=short",
        node_id,
    )
    with tempfile.TemporaryDirectory(prefix=f"fieldtrue-{control_id}-") as temporary_name:
        temporary = Path(temporary_name)
        observation_path = temporary / "observation.json"
        outcome_path = temporary / "pytest-lifecycle.json"
        try:
            completed = _run_bounded_control_process(
                execution_command,
                cwd=runner.snapshot_root,
                env=_sanitized_environment(
                    control_id=control_id,
                    node_id=node_id,
                    observation_path=observation_path,
                    outcome_path=outcome_path,
                ),
                timeout_seconds=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise ControlAuthorityError(f"control timed out: {control_id}") from error
        except ControlAuthorityError as error:
            raise ControlAuthorityError(f"{error}: {control_id}") from error
        if (
            len(completed.stdout) > _MAX_CAPTURE_BYTES
            or len(completed.stderr) > _MAX_CAPTURE_BYTES
            or len(completed.stdout) + len(completed.stderr) > _MAX_AGGREGATE_CAPTURE_BYTES
        ):
            raise ControlAuthorityError(f"control output exceeded the capture bound: {control_id}")
        lifecycle = _load_control_sidecar(
            outcome_path,
            PytestLifecycle,
            label=f"pytest lifecycle for {control_id}",
            missing_message=f"control emitted no pytest lifecycle: {control_id}",
        )
        _validate_lifecycle(lifecycle, node_id)
        if completed.returncode != 0:
            raise ControlAuthorityError(f"control process failed: {control_id}")
        observation = _load_control_sidecar(
            observation_path,
            ControlObservation,
            label=f"audit observation for {control_id}",
            missing_message=(
                f"control passed pytest but emitted no audit observation: {control_id}"
            ),
        )
        if (
            observation.control_id != control_id
            or observation.pytest_node_id != node_id
            or observation.observed_verdict != expected_verdict
            or observation.observed_gate_id != expected_gate
            or observation.observed_failure_code != expected_failure
            or observation.report_sha256 != sha256_value(observation.report)
        ):
            raise ControlAuthorityError(f"control observation differs from authority: {control_id}")
        stdout = completed.stdout.decode("utf-8", errors="strict")
        stderr = completed.stderr.decode("utf-8", errors="strict")
        evidence = ControlExecutionEvidence(
            execution_commit=commit,
            execution_tree=tree,
            control_id=control_id,
            pytest_node_id=node_id,
            command=command,
            observation=observation,
            lifecycle=lifecycle,
            stdout_sha256=sha256_bytes(completed.stdout),
            stderr_sha256=sha256_bytes(completed.stderr),
            stdout=stdout,
            stderr=stderr,
        )
    evidence_path = staging / "controls" / f"{control_id}.json"
    atomic_write(evidence_path, canonical_json_pretty(evidence), mode=0o444)
    binding = _artifact_binding(staging, evidence_path)
    result = AdmissionControlResult(
        control_id=control_id,
        fixture_sha256=observation.fixture.root_sha256,
        report_sha256=observation.report_sha256,
        evidence=binding,
        pytest_node_id=node_id,
        expected_verdict=expected_verdict,
        observed_verdict=observation.observed_verdict,
        expected_gate_id=expected_gate,
        observed_gate_id=observation.observed_gate_id,
        expected_failure_code=expected_failure,
        observed_failure_code=observation.observed_failure_code,
        passed=True,
    )
    manifest_entry = ControlManifestEntry(
        control_id=control_id,
        pytest_node_id=node_id,
        expected_verdict=expected_verdict,
        expected_gate_id=expected_gate,
        expected_failure_code=expected_failure,
        evidence=binding,
    )
    return result, manifest_entry


def _load_existing_key(path: Path) -> SigningKey:
    if not path.exists():
        raise ControlAuthorityError(f"governance signing key does not exist: {path}")
    return load_or_create_signing_key(path)


def _rename_no_replace(source: Path, target: Path) -> None:
    """Atomically publish a directory while refusing an existing destination."""

    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    target_bytes = os.fsencode(target)
    if sys.platform == "darwin":
        rename_exclusive = 0x00000004
        result = libc.renamex_np(source_bytes, target_bytes, rename_exclusive)
    elif sys.platform.startswith("linux"):
        at_fdcwd = -100
        rename_no_replace = 1
        result = libc.renameat2(
            at_fdcwd,
            source_bytes,
            at_fdcwd,
            target_bytes,
            rename_no_replace,
        )
    else:
        raise ControlAuthorityError("atomic no-replace publication is unsupported on this platform")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in (errno.EEXIST, errno.ENOTEMPTY):
            raise FileExistsError(target)
        raise OSError(error_number, os.strerror(error_number), target)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_bound_json(input_root: Path, binding: ArtifactBinding) -> dict[str, Any]:
    root = input_root.resolve(strict=True)
    candidate = root.joinpath(*PurePosixPath(binding.path).parts)
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        raise ControlAuthorityError(f"missing control artifact: {binding.path}") from error
    if candidate.is_symlink() or not resolved.is_file() or not resolved.is_relative_to(root):
        raise ControlAuthorityError(f"unsafe control artifact: {binding.path}")
    data = resolved.read_bytes()
    if len(data) != binding.bytes or sha256_bytes(data) != binding.sha256:
        raise ControlAuthorityError(f"control artifact binding mismatch: {binding.path}")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlAuthorityError(f"control artifact is not JSON: {binding.path}") from error
    if not isinstance(value, dict):
        raise ControlAuthorityError(f"control artifact is not an object: {binding.path}")
    return value


def _verify_control_attestation(
    receipt: AdmissionControlSuiteReceipt,
    contract: AcquisitionContract,
) -> None:
    attestation = receipt.attestation
    subject = receipt.model_dump(mode="json", exclude={"attestation"})
    attestation_body = attestation.model_dump(
        mode="json",
        exclude={"attestation_hash", "signature"},
    )
    expected_subject = attestation_subject_hash(AttestationSubjectKind.CONTROL_SUITE, subject)
    if (
        attestation.attestation_id != "iter001-admission-controls-attestation"
        or attestation.signer_id != "iter001-governance-root"
        or attestation.subject_kind != AttestationSubjectKind.CONTROL_SUITE
        or attestation.subject_sha256 != expected_subject
        or attestation.issued_at != receipt.executed_at
        or attestation.signer_public_key != contract.trust_anchor_public_key
        or sha256_value(attestation_body) != attestation.attestation_hash
    ):
        raise ControlAuthorityError("control-suite root attestation differs from authority")
    try:
        VerifyKey(bytes.fromhex(contract.trust_anchor_public_key)).verify(
            bytes.fromhex(attestation.attestation_hash),
            bytes.fromhex(attestation.signature),
        )
    except (BadSignatureError, ValueError) as error:
        raise ControlAuthorityError("control-suite root signature is invalid") from error


def _verify_execution_ancestry(repo: Path, commit: str, tree: str) -> None:
    try:
        object_type = str(_run_git(repo, "cat-file", "-t", commit))
        committed_tree = str(_run_git(repo, "rev-parse", f"{commit}^{{tree}}"))
        head = str(_run_git(repo, "rev-parse", "HEAD"))
    except (ControlAuthorityError, subprocess.SubprocessError) as error:
        raise ControlAuthorityError("control execution Git identity does not resolve") from error
    if object_type != "commit" or committed_tree != tree:
        raise ControlAuthorityError("control execution commit and tree are incoherent")
    try:
        git = trusted_repository_git(repo)
        ancestry = subprocess.run(  # noqa: S603 - fixed trusted Git ancestry query
            (git, "merge-base", "--is-ancestor", commit, head),
            cwd=repo,
            check=False,
            capture_output=True,
            env=git_environment(),
            timeout=10,
        )
    except (GitTrustError, OSError, subprocess.SubprocessError) as error:
        raise ControlAuthorityError("control execution Git ancestry cannot verify") from error
    if ancestry.returncode != 0:
        raise ControlAuthorityError("control execution commit is not an ancestor of HEAD")


def _verify_historical_sources(
    repo: Path,
    receipt: AdmissionControlSuiteReceipt,
    manifest: ControlExecutionManifest,
) -> None:
    receipt_bindings = {
        "validator": (receipt.validator_git_blob, receipt.validator_source_sha256),
        "fixture_builder": (
            receipt.fixture_builder_git_blob,
            receipt.fixture_builder_sha256,
        ),
        "control_test": (receipt.control_test_git_blob, receipt.control_test_sha256),
        "generator": (receipt.generator_git_blob, receipt.generator_sha256),
        "dependency_lock": (
            receipt.dependency_lock_git_blob,
            receipt.dependency_lock_sha256,
        ),
    }
    for source, (expected_blob, expected_sha256) in zip(
        manifest.sources,
        receipt_bindings.values(),
        strict=True,
    ):
        try:
            committed_blob = str(
                _run_git(repo, "rev-parse", f"{receipt.execution_commit}:{source.path}")
            )
            committed_bytes = _run_git(repo, "cat-file", "blob", committed_blob, text=False)
        except (ControlAuthorityError, subprocess.SubprocessError) as error:
            raise ControlAuthorityError(
                f"control authority source does not resolve: {source.path}"
            ) from error
        if not isinstance(committed_bytes, bytes):
            raise ControlAuthorityError("Git returned non-binary control source bytes")
        if (
            source.git_blob != committed_blob
            or source.git_blob != expected_blob
            or source.sha256 != sha256_bytes(committed_bytes)
            or source.sha256 != expected_sha256
            or source.bytes != len(committed_bytes)
        ):
            raise ControlAuthorityError(
                f"control authority source differs at execution commit: {source.path}"
            )


def _expected_control_command(manifest: ControlExecutionManifest, node_id: str) -> tuple[str, ...]:
    del manifest
    return _normalized_control_command(node_id)


def _verify_control_evidence(
    input_root: Path,
    receipt: AdmissionControlSuiteReceipt,
    manifest: ControlExecutionManifest,
) -> None:
    expected_paths = tuple(f"controls/{control_id}.json" for control_id in _REQUIRED_CONTROL_IDS)
    result_paths = tuple(result.evidence.path for result in receipt.controls)
    manifest_paths = tuple(entry.evidence.path for entry in manifest.controls)
    if (
        receipt.execution_manifest.path != "execution_manifest.json"
        or result_paths != expected_paths
        or manifest_paths != expected_paths
    ):
        raise ControlAuthorityError("control evidence path registry is not exact")
    for result, entry in zip(receipt.controls, manifest.controls, strict=True):
        if (
            entry.control_id != result.control_id
            or entry.pytest_node_id != result.pytest_node_id
            or entry.expected_verdict != result.expected_verdict
            or entry.expected_gate_id != result.expected_gate_id
            or entry.expected_failure_code != result.expected_failure_code
            or entry.evidence != result.evidence
        ):
            raise ControlAuthorityError("control manifest and receipt result differ")
        try:
            evidence = ControlExecutionEvidence.model_validate(
                _read_bound_json(input_root, result.evidence)
            )
        except ValueError as error:
            raise ControlAuthorityError(
                f"invalid machine evidence for control: {result.control_id}"
            ) from error
        observation = evidence.observation
        if (
            evidence.execution_commit != receipt.execution_commit
            or evidence.execution_tree != receipt.execution_tree
            or evidence.control_id != result.control_id
            or evidence.pytest_node_id != result.pytest_node_id
            or evidence.command != _expected_control_command(manifest, result.pytest_node_id)
            or observation.control_id != result.control_id
            or observation.pytest_node_id != result.pytest_node_id
            or observation.fixture.root_sha256 != result.fixture_sha256
            or observation.report_sha256 != result.report_sha256
            or observation.report_sha256 != sha256_value(observation.report)
            or observation.observed_verdict != result.observed_verdict
            or observation.observed_gate_id != result.observed_gate_id
            or observation.observed_failure_code != result.observed_failure_code
            or evidence.stdout_sha256 != sha256_bytes(evidence.stdout.encode("utf-8"))
            or evidence.stderr_sha256 != sha256_bytes(evidence.stderr.encode("utf-8"))
        ):
            raise ControlAuthorityError(
                f"machine evidence differs from receipt result: {result.control_id}"
            )
        _validate_lifecycle(evidence.lifecycle, result.pytest_node_id)


def verify_admission_control_bundle(
    repo_root: Path,
    input_root: Path,
    contract: AcquisitionContract,
) -> AdmissionControlSuiteReceipt:
    """Verify one production control bundle against Git and contract authority, read-only."""

    repo = repo_root.resolve(strict=True)
    root = input_root.resolve(strict=True)
    if not repo.is_dir() or not root.is_dir():
        raise ControlAuthorityError("control verifier requires repository and bundle directories")
    canonical_contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    try:
        canonical_contract = AcquisitionContract.model_validate(read_json(canonical_contract_path))
        receipt = AdmissionControlSuiteReceipt.model_validate(
            read_json(root / "control_suite_receipt.json")
        )
    except (OSError, ValueError) as error:
        raise ControlAuthorityError("control receipt or canonical contract is invalid") from error
    if canonical_contract != contract:
        raise ControlAuthorityError("selected acquisition contract is not canonical")
    if contract.authority_profile == "canonical" and contract.control_authority_status != "sealed":
        raise ControlAuthorityError("canonical control authority is not sealed")
    if (
        sha256_value(receipt) != contract.control_suite_sha256
        or receipt.validator_git_blob != contract.validator_git_blob
        or receipt.validator_source_sha256 != contract.validator_source_sha256
        or receipt.dependency_lock_sha256 != contract.dependency_lock_sha256
    ):
        raise ControlAuthorityError("control receipt differs from the acquisition contract")
    _verify_control_attestation(receipt, contract)
    try:
        manifest = ControlExecutionManifest.model_validate(
            _read_bound_json(root, receipt.execution_manifest)
        )
    except ValueError as error:
        raise ControlAuthorityError("control execution manifest is invalid") from error
    if (
        manifest.execution_commit != receipt.execution_commit
        or manifest.execution_tree != receipt.execution_tree
        or manifest.finished_at != receipt.executed_at
    ):
        raise ControlAuthorityError("control receipt and execution manifest differ")
    _verify_execution_ancestry(repo, receipt.execution_commit, receipt.execution_tree)
    _verify_historical_sources(repo, receipt, manifest)
    _verify_control_evidence(root, receipt, manifest)
    return receipt


def generate_admission_control_bundle(
    repo_root: Path,
    output_directory: Path,
    signing_key_path: Path,
    *,
    timeout_seconds: int = 600,
) -> Path:
    """Execute, bind, root-sign, and atomically publish the production control bundle."""

    repo = repo_root.resolve(strict=True)
    if output_directory.exists() or output_directory.is_symlink():
        raise FileExistsError(output_directory)
    _assert_parent_process_trusted(repo)
    output_parent = output_directory.parent.resolve(strict=True)
    target = output_parent / output_directory.name
    _assert_clean_repo(repo)
    commit, tree = _git_identity(repo)
    sources = tuple(_git_bound_source(repo, commit, name, path) for name, path in _SOURCE_PATHS)
    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract = AcquisitionContract.model_validate(read_json(contract_path))
    runner_temporary = tempfile.TemporaryDirectory(prefix="fieldtrue-control-runner-")
    try:
        runner = _prepare_authenticated_runner(repo, commit, Path(runner_temporary.name))
        started_at = datetime.now(UTC)
        staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=output_parent))
        published = False
        try:
            results: list[AdmissionControlResult] = []
            entries: list[ControlManifestEntry] = []
            for control_id in _REQUIRED_CONTROL_IDS:
                if not _authenticated_runner_is_unchanged(runner):
                    raise ControlAuthorityError("authenticated runner changed before control")
                result, entry = _run_control(
                    staging,
                    commit=commit,
                    tree=tree,
                    control_id=control_id,
                    runner=runner,
                    timeout_seconds=timeout_seconds,
                )
                if not _authenticated_runner_is_unchanged(runner):
                    raise ControlAuthorityError("authenticated runner changed after control")
                results.append(result)
                entries.append(entry)
            _assert_clean_repo(repo)
            if _git_identity(repo) != (commit, tree):
                raise ControlAuthorityError("repository identity changed during control execution")
            rebound_sources = tuple(
                _git_bound_source(repo, commit, name, path) for name, path in _SOURCE_PATHS
            )
            if rebound_sources != sources:
                raise ControlAuthorityError(
                    "authority source bytes changed during control execution"
                )
            if not _authenticated_runner_is_unchanged(runner):
                raise ControlAuthorityError("authenticated runner changed before signing")
            finished_at = datetime.now(UTC)
            manifest = ControlExecutionManifest(
                suite_id=_SUITE_ID,
                execution_commit=commit,
                execution_tree=tree,
                started_at=started_at,
                finished_at=finished_at,
                repository_clean_before=True,
                repository_clean_after=True,
                dependency_mode="lock-hash-authenticated-wheels",
                uv_executable=str(runner.uv.executable.resolved_path),
                uv_executable_sha256=runner.uv.executable.sha256,
                uv_version=runner.uv.version,
                python_executable_sha256=runner.python.sha256,
                python_version=RUNNER_PYTHON_FULL_VERSION,
                runner_environment_sha256=runner.environment_sha256,
                artifact_set_sha256=runner.artifact_set_sha256,
                environment_policy=(
                    "committed-source-snapshot",
                    "fresh-private-managed-python",
                    "lock-hash-authenticated-wheels",
                    "isolated-python-no-site",
                    "explicit-environment-allowlist",
                    "pytest-plugin-autoload-disabled",
                    "runner-rebound-before-and-after-each-control",
                ),
                sources=sources,
                controls=tuple(entries),
            )
            manifest_path = staging / "execution_manifest.json"
            atomic_write(manifest_path, canonical_json_pretty(manifest), mode=0o444)
            manifest_binding = _artifact_binding(staging, manifest_path)
            source_by_name = {item.name: item for item in sources}
            receipt_body: dict[str, Any] = {
                "schema_version": "fieldtrue.admission-control-suite-receipt.v1",
                "suite_id": _SUITE_ID,
                "validator_git_blob": source_by_name["validator"].git_blob,
                "validator_source_sha256": source_by_name["validator"].sha256,
                "fixture_builder_git_blob": source_by_name["fixture_builder"].git_blob,
                "fixture_builder_sha256": source_by_name["fixture_builder"].sha256,
                "control_test_git_blob": source_by_name["control_test"].git_blob,
                "control_test_sha256": source_by_name["control_test"].sha256,
                "generator_git_blob": source_by_name["generator"].git_blob,
                "generator_sha256": source_by_name["generator"].sha256,
                "dependency_lock_git_blob": source_by_name["dependency_lock"].git_blob,
                "dependency_lock_sha256": source_by_name["dependency_lock"].sha256,
                "execution_commit": commit,
                "execution_tree": tree,
                "execution_manifest": manifest_binding.model_dump(mode="json"),
                "executed_at": finished_at,
                "controls": [result.model_dump(mode="json") for result in results],
            }
            _assert_parent_process_trusted(repo)
            key = _load_existing_key(signing_key_path.resolve(strict=True))
            if key.verify_key.encode().hex() != contract.trust_anchor_public_key:
                raise ControlAuthorityError(
                    "governance signing key differs from the acquisition contract"
                )
            attestation = issue_attestation(
                key,
                attestation_id="iter001-admission-controls-attestation",
                signer_id="iter001-governance-root",
                subject_kind=AttestationSubjectKind.CONTROL_SUITE,
                subject_sha256=attestation_subject_hash(
                    AttestationSubjectKind.CONTROL_SUITE,
                    receipt_body,
                ),
                issued_at=finished_at,
            )
            receipt = AdmissionControlSuiteReceipt.model_validate(
                {**receipt_body, "attestation": attestation.model_dump(mode="json")}
            )
            receipt_path = staging / "control_suite_receipt.json"
            atomic_write(receipt_path, canonical_json_pretty(receipt), mode=0o444)
            _fsync_directory(staging / "controls")
            _fsync_directory(staging)
            _rename_no_replace(staging, target)
            published = True
            _fsync_directory(output_parent)
            return target / "control_suite_receipt.json"
        finally:
            if not published:
                shutil.rmtree(staging, ignore_errors=True)
    finally:
        runner_temporary.cleanup()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate the Iter001 admission-control receipt")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--signing-key",
        type=Path,
        default=Path(".local/keys/iter001-governance.ed25519"),
    )
    parser.add_argument("--timeout-seconds", type=int, default=600)
    return parser


def _die(message: str) -> NoReturn:
    raise SystemExit(message)


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.timeout_seconds <= 0:
        _die("--timeout-seconds must be positive")
    repo = arguments.repo.resolve()
    output = arguments.output
    if not output.is_absolute():
        output = repo / output
    signing_key = arguments.signing_key
    if not signing_key.is_absolute():
        signing_key = repo / signing_key
    try:
        receipt = generate_admission_control_bundle(
            repo,
            output,
            signing_key,
            timeout_seconds=arguments.timeout_seconds,
        )
    except (ControlAuthorityError, FileExistsError, OSError, subprocess.SubprocessError) as error:
        _die(f"admission-control generation failed: {error}")
    print(receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
