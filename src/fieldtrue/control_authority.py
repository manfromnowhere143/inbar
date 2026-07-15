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
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, NoReturn, Self

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import Field, model_validator

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
from fieldtrue.receipts import load_or_create_signing_key

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

Verdict = Literal[
    "PASS_PILOT",
    "BLOCKED_ACQUISITION",
    "BLOCKED_RIGHTS",
    "INVALID",
    "KILL_CONSTRUCT",
]


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
    dependency_mode: Literal["uv-offline-frozen"]
    uv_executable: str
    uv_executable_sha256: Sha256
    uv_version: str
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
    completed = subprocess.run(  # noqa: S603 - fixed executable and internal arguments
        ("git", "-C", str(repo), *arguments),  # noqa: S607 - fixed Git executable
        check=True,
        capture_output=True,
        text=text,
        env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
    )
    output: str | bytes = completed.stdout
    return output.strip() if text else output


def _assert_clean_repo(repo: Path) -> None:
    status = _run_git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise ControlAuthorityError("admission controls require a clean repository")


def _git_identity(repo: Path) -> tuple[str, str]:
    commit = str(_run_git(repo, "rev-parse", "HEAD"))
    tree = str(_run_git(repo, "rev-parse", "HEAD^{tree}"))
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


def _sanitized_environment(
    *,
    control_id: str,
    node_id: str,
    observation_path: Path,
    outcome_path: Path,
) -> dict[str, str]:
    environment = {
        "HOME": os.environ.get("HOME", str(Path.home())),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONHASHSEED": "0",
        "TZ": "UTC",
        "UV_FROZEN": "1",
        "UV_OFFLINE": "1",
        _CONTROL_ENV: control_id,
        _NODE_ENV: node_id,
        _OBSERVATION_ENV: str(observation_path),
        _OUTCOME_ENV: str(outcome_path),
    }
    for name in ("TMPDIR", "UV_CACHE_DIR"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    return environment


def _resolve_uv_executable() -> str:
    executable = shutil.which("uv", path=os.environ.get("PATH", os.defpath))
    if executable is None:
        raise ControlAuthorityError("uv is not available on the execution PATH")
    resolved = Path(executable).resolve(strict=True)
    if not resolved.is_file():
        raise ControlAuthorityError("resolved uv executable is not a regular file")
    return str(resolved)


def _uv_version(executable: str) -> str:
    completed = subprocess.run(  # noqa: S603 - resolved absolute executable, fixed argument
        (executable, "--version"),
        check=True,
        capture_output=True,
        text=True,
        env={
            "HOME": os.environ.get("HOME", str(Path.home())),
            "LANG": "C.UTF-8",
            "PATH": os.environ.get("PATH", os.defpath),
        },
    )
    version = completed.stdout.strip()
    if not version.startswith("uv ") or "\n" in version:
        raise ControlAuthorityError("uv returned an invalid version identity")
    return version


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


def _run_control(
    repo: Path,
    staging: Path,
    *,
    commit: str,
    tree: str,
    control_id: str,
    uv_executable: str,
    timeout_seconds: int,
) -> tuple[AdmissionControlResult, ControlManifestEntry]:
    node_id, expected_verdict, expected_gate, expected_failure = _control_requirement(control_id)
    command = (
        uv_executable,
        "run",
        "--offline",
        "--frozen",
        "python",
        "-m",
        "pytest",
        "-p",
        "fieldtrue.control_authority",
        "--no-header",
        "--tb=short",
        node_id,
    )
    with tempfile.TemporaryDirectory(prefix=f"fieldtrue-{control_id}-") as temporary_name:
        temporary = Path(temporary_name)
        observation_path = temporary / "observation.json"
        outcome_path = temporary / "pytest-lifecycle.json"
        try:
            completed = subprocess.run(  # noqa: S603 - fixed frozen command and authority node
                command,
                cwd=repo,
                env=_sanitized_environment(
                    control_id=control_id,
                    node_id=node_id,
                    observation_path=observation_path,
                    outcome_path=outcome_path,
                ),
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise ControlAuthorityError(f"control timed out: {control_id}") from error
        if len(completed.stdout) > _MAX_CAPTURE_BYTES or len(completed.stderr) > _MAX_CAPTURE_BYTES:
            raise ControlAuthorityError(f"control output exceeded the capture bound: {control_id}")
        if not outcome_path.is_file():
            raise ControlAuthorityError(f"control emitted no pytest lifecycle: {control_id}")
        lifecycle = PytestLifecycle.model_validate(read_json(outcome_path))
        _validate_lifecycle(lifecycle, node_id)
        if completed.returncode != 0:
            raise ControlAuthorityError(f"control process failed: {control_id}")
        if not observation_path.is_file():
            raise ControlAuthorityError(
                f"control passed pytest but emitted no audit observation: {control_id}"
            )
        observation = ControlObservation.model_validate(read_json(observation_path))
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
    except subprocess.SubprocessError as error:
        raise ControlAuthorityError("control execution Git identity does not resolve") from error
    if object_type != "commit" or committed_tree != tree:
        raise ControlAuthorityError("control execution commit and tree are incoherent")
    ancestry = subprocess.run(  # noqa: S603 - fixed Git ancestry query
        ("git", "-C", str(repo), "merge-base", "--is-ancestor", commit, head),  # noqa: S607
        check=False,
        capture_output=True,
        env={**os.environ, "GIT_NO_REPLACE_OBJECTS": "1"},
    )
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
        except subprocess.SubprocessError as error:
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
    return (
        manifest.uv_executable,
        "run",
        "--offline",
        "--frozen",
        "python",
        "-m",
        "pytest",
        "-p",
        "fieldtrue.control_authority",
        "--no-header",
        "--tb=short",
        node_id,
    )


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
    output_parent = output_directory.parent.resolve(strict=True)
    target = output_parent / output_directory.name
    _assert_clean_repo(repo)
    commit, tree = _git_identity(repo)
    sources = tuple(_git_bound_source(repo, commit, name, path) for name, path in _SOURCE_PATHS)
    contract_path = repo / "protocol" / "acquisition" / "iter001_contract.json"
    contract = AcquisitionContract.model_validate(read_json(contract_path))
    started_at = datetime.now(UTC)
    uv_executable = _resolve_uv_executable()
    uv_sha256 = sha256_file(Path(uv_executable))
    uv_version = _uv_version(uv_executable)
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.tmp-", dir=output_parent))
    published = False
    try:
        results: list[AdmissionControlResult] = []
        entries: list[ControlManifestEntry] = []
        for control_id in _REQUIRED_CONTROL_IDS:
            result, entry = _run_control(
                repo,
                staging,
                commit=commit,
                tree=tree,
                control_id=control_id,
                uv_executable=uv_executable,
                timeout_seconds=timeout_seconds,
            )
            results.append(result)
            entries.append(entry)
        _assert_clean_repo(repo)
        if _git_identity(repo) != (commit, tree):
            raise ControlAuthorityError("repository identity changed during control execution")
        rebound_sources = tuple(
            _git_bound_source(repo, commit, name, path) for name, path in _SOURCE_PATHS
        )
        if rebound_sources != sources:
            raise ControlAuthorityError("authority source bytes changed during control execution")
        if sha256_file(Path(uv_executable)) != uv_sha256:
            raise ControlAuthorityError("uv executable changed during control execution")
        finished_at = datetime.now(UTC)
        manifest = ControlExecutionManifest(
            suite_id=_SUITE_ID,
            execution_commit=commit,
            execution_tree=tree,
            started_at=started_at,
            finished_at=finished_at,
            repository_clean_before=True,
            repository_clean_after=True,
            dependency_mode="uv-offline-frozen",
            uv_executable=uv_executable,
            uv_executable_sha256=uv_sha256,
            uv_version=uv_version,
            environment_policy=(
                "explicit-allowlist",
                "pytest-plugin-autoload-disabled",
                "pythonhashseed-zero",
                "timezone-utc",
                "network-resolution-disabled-by-uv-offline",
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
