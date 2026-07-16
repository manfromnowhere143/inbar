"""Shared admission-control execution primitives and read-only fixture verification.

The signing producer lives in :mod:`fieldtrue.control_producer`, while pytest observation capture
lives in :mod:`fieldtrue.control_observation`. A passing pytest exit without a bound observation and
lifecycle record cannot contribute to a fixture receipt.
"""

from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import tempfile
import time
from contextlib import suppress
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self, TypeVar

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey
from pydantic import BaseModel, Field, model_validator

import fieldtrue.runner_trust as runner_trust
from fieldtrue.acquisition import (
    _CONTROL_REQUIREMENTS,
    _REQUIRED_CONTROL_IDS,
    AcquisitionContract,
    AdmissionControlResult,
    AdmissionControlSuiteReceipt,
    ArtifactBinding,
    AttestationSubjectKind,
    _acquisition_source_closure,
    attestation_subject_hash,
)
from fieldtrue.canonical import (
    atomic_write,
    canonical_json_pretty,
    read_json,
    sha256_bytes,
    sha256_file,
    sha256_value,
)
from fieldtrue.control_observation import (
    ControlObservation,
    PytestLifecycle,
)
from fieldtrue.control_protocol import CONTROL_PRODUCER_SNAPSHOT_PATHS
from fieldtrue.control_protocol import ControlAuthorityError as ControlAuthorityError
from fieldtrue.domain import FrozenModel, GitObjectId, Identifier, Sha256
from fieldtrue.git_trust import GitTrustError, git_environment, trusted_repository_git
from fieldtrue.runner_trust import (
    AuthenticatedRunner,
)

_OBSERVATION_ENV = "FIELDTRUE_CONTROL_OBSERVATION_PATH"
_OUTCOME_ENV = "FIELDTRUE_CONTROL_PYTEST_OUTCOME_PATH"
_CONTROL_ENV = "FIELDTRUE_CONTROL_ID"
_NODE_ENV = "FIELDTRUE_CONTROL_NODE_ID"
_SUITE_ID: Literal["iter001-admission-controls-v1"] = "iter001-admission-controls-v1"
_GENERATOR_PATH = "src/fieldtrue/control_producer.py"
_SOURCE_PATHS = (
    ("acquisition_contract", "protocol/acquisition/iter001_contract.json"),
    ("validator", "src/fieldtrue/acquisition.py"),
    ("fixture_builder", "tests/acquisition_helpers.py"),
    ("control_test", "tests/unit/test_acquisition.py"),
    ("project_config", "pyproject.toml"),
    ("tests_package_init", "tests/__init__.py"),
    ("unit_tests_package_init", "tests/unit/__init__.py"),
    ("observer", "src/fieldtrue/control_observation.py"),
    ("generator", _GENERATOR_PATH),
    ("launcher", "src/fieldtrue/control_launcher.py"),
    ("dependency_lock", "uv.lock"),
)
_MAX_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_AGGREGATE_CAPTURE_BYTES = 4 * 1024 * 1024
_MAX_CONTROL_SIDECAR_BYTES = 4 * 1024 * 1024
_CAPTURE_READ_BYTES = 64 * 1024
_PROCESS_TERMINATION_GRACE_SECONDS = 0.25
_PROCESS_GROUP_POLL_SECONDS = 0.01
_RUNNER_ROOT_DISTRIBUTIONS = frozenset({"certifi", "networkx", "pydantic", "pynacl", "pytest"})
_RUNNER_SNAPSHOT_PATHS = CONTROL_PRODUCER_SNAPSHOT_PATHS
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
    schema_version: Literal["fieldtrue.control-execution-manifest.v2"] = (
        "fieldtrue.control-execution-manifest.v2"
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
    source_closure_sha256: Sha256
    source_file_count: int = Field(ge=1)
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
        "fieldtrue.control_observation",
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
        "fieldtrue.control_observation",
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
    expected_attestation_id = "iter001-admission-controls-fixture-attestation"
    expected_signer_id = "iter001-control-fixture-root"
    expected_subject = attestation_subject_hash(AttestationSubjectKind.CONTROL_SUITE, subject)
    if (
        receipt.authority_profile != contract.authority_profile
        or attestation.attestation_id != expected_attestation_id
        or attestation.signer_id != expected_signer_id
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
        "acquisition_contract": (
            receipt.acquisition_contract_git_blob,
            receipt.acquisition_contract_sha256,
        ),
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
    for source in manifest.sources:
        receipt_binding = receipt_bindings.get(source.name)
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
            or source.sha256 != sha256_bytes(committed_bytes)
            or source.bytes != len(committed_bytes)
            or (receipt_binding is not None and (source.git_blob, source.sha256) != receipt_binding)
        ):
            raise ControlAuthorityError(
                f"control authority source differs at execution commit: {source.path}"
            )
    validator = next(source for source in manifest.sources if source.name == "validator")
    try:
        git = trusted_repository_git(repo)
        head = str(_run_git(repo, "rev-parse", "HEAD"))
        closure = _acquisition_source_closure(
            git,
            repo,
            git_environment(),
            authority_commit=receipt.execution_commit,
            repository_head=head,
            expected_validator_blob=validator.git_blob,
            expected_validator_sha256=validator.sha256,
        )
    except (GitTrustError, ValueError) as error:
        raise ControlAuthorityError("control source closure cannot be reconstructed") from error
    if (
        closure.closure_sha256 != manifest.source_closure_sha256
        or len(closure.sources) != manifest.source_file_count
    ):
        raise ControlAuthorityError("control source closure differs from the signed manifest")


def _verify_execution_contract_transition(
    repo: Path,
    receipt: AdmissionControlSuiteReceipt,
    contract: AcquisitionContract,
) -> None:
    try:
        blob = str(
            _run_git(
                repo,
                "rev-parse",
                f"{receipt.execution_commit}:protocol/acquisition/iter001_contract.json",
            )
        )
        raw = _run_git(repo, "cat-file", "blob", blob, text=False)
        if not isinstance(raw, bytes):
            raise ControlAuthorityError("Git returned non-binary execution contract bytes")
        execution_contract = AcquisitionContract.model_validate_json(raw, strict=True)
    except (ControlAuthorityError, ValueError) as error:
        raise ControlAuthorityError(
            "execution acquisition contract cannot be reconstructed"
        ) from error
    expected = execution_contract.model_copy(
        update={
            "control_suite_sha256": sha256_value(receipt),
            "validator_git_blob": receipt.validator_git_blob,
            "validator_source_sha256": receipt.validator_source_sha256,
            "dependency_lock_sha256": receipt.dependency_lock_sha256,
        }
    )
    if contract != expected:
        raise ControlAuthorityError(
            "selected acquisition contract differs beyond receipt-derived bindings"
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
    """Verify one V1 fixture control bundle against Git and contract authority, read-only."""

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
    if contract.authority_profile == "canonical":
        raise ControlAuthorityError("V1 control receipts are structurally test-fixture only")
    if receipt.authority_profile != contract.authority_profile:
        raise ControlAuthorityError("control receipt authority profile differs from the contract")
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
    _verify_execution_contract_transition(repo, receipt, contract)
    _verify_control_evidence(root, receipt, manifest)
    return receipt


if __name__ == "__main__":
    from fieldtrue.control_launcher import main

    raise SystemExit(main())
