"""Observation capture for frozen admission controls and pytest lifecycle evidence."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, Self, cast

from pydantic import Field, model_validator

from fieldtrue.acquisition import (
    _CONTROL_REQUIREMENTS,
    AcquisitionAdmissionReport,
    AcquisitionCandidateRegistry,
    AcquisitionGateResult,
)
from fieldtrue.canonical import (
    canonical_json_pretty,
    read_json,
    sha256_file,
    sha256_value,
)
from fieldtrue.control_protocol import ControlAuthorityError
from fieldtrue.domain import FrozenModel, Identifier, Sha256

_OBSERVATION_ENV = "FIELDTRUE_CONTROL_OBSERVATION_PATH"
_OUTCOME_ENV = "FIELDTRUE_CONTROL_PYTEST_OUTCOME_PATH"
_CONTROL_ENV = "FIELDTRUE_CONTROL_ID"
_NODE_ENV = "FIELDTRUE_CONTROL_NODE_ID"

Verdict = Literal[
    "PASS_PILOT",
    "BLOCKED_ACQUISITION",
    "BLOCKED_RIGHTS",
    "INVALID",
    "KILL_CONSTRUCT",
]


class ControlObservationError(ControlAuthorityError):
    """Control observation evidence is incomplete, ambiguous, or untrusted."""


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


def _control_requirement(control_id: str) -> tuple[str, Verdict, str, str | None]:
    try:
        node_id, verdict, gate_id, failure_code = _CONTROL_REQUIREMENTS[control_id]
    except KeyError as error:
        raise ControlObservationError(f"unknown admission control: {control_id}") from error
    return node_id, cast(Verdict, verdict), gate_id, failure_code


def snapshot_fixture_tree(root: Path) -> FixtureSnapshot:
    """Hash every regular file in one fixture tree; reject links and special files."""

    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ControlObservationError("control fixture root is not a directory")
    files: list[FixtureFile] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ControlObservationError(f"control fixture contains a symbolic link: {relative}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ControlObservationError(f"control fixture contains a special file: {relative}")
        files.append(
            FixtureFile(
                path=relative,
                sha256=sha256_file(path),
                bytes=path.stat().st_size,
            )
        )
    if not files:
        raise ControlObservationError("control fixture tree is empty")
    return FixtureSnapshot(
        files=tuple(files),
        root_sha256=sha256_value([item.model_dump(mode="json") for item in files]),
    )


def _gate(report: AcquisitionAdmissionReport, gate_id: str) -> AcquisitionGateResult:
    matches = [gate for gate in report.gates if gate.gate_id == gate_id]
    if len(matches) != 1:
        raise ControlObservationError(f"control report does not contain one {gate_id} gate")
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
        raise ControlObservationError("control observation environment is incomplete")
    control_id, node_id, output = values
    if control_id is None or node_id is None or output is None:
        raise ControlObservationError("control observation environment is incomplete")
    expected_node, _, _, _ = _control_requirement(control_id)
    if node_id != expected_node:
        raise ControlObservationError("control observation node differs from frozen authority")
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
    """Emit one observation when a frozen control is executing.

    The function is a no-op in ordinary test runs. In a control run it derives the expected
    gate and failure from frozen authority and refuses mismatched semantics.
    """

    environment = _control_environment()
    if environment is None:
        return
    control_id, node_id, output_path = environment
    _, expected_verdict, gate_id, failure_code = _control_requirement(control_id)
    if report.verdict != expected_verdict:
        raise ControlObservationError(
            f"{control_id} observed {report.verdict}, expected {expected_verdict}"
        )
    if not _supports_failure_code(
        report,
        gate_id,
        failure_code,
        fixture_root=input_root,
    ):
        raise ControlObservationError(
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
    """Emit one validation-error observation when a control cannot return a report."""

    environment = _control_environment()
    if environment is None:
        return
    control_id, node_id, output_path = environment
    _, expected_verdict, gate_id, failure_code = _control_requirement(control_id)
    if expected_verdict != "INVALID" or failure_code is None:
        raise ControlObservationError("exception evidence is authorized only for INVALID controls")
    message = str(error).lower()
    exception_tokens = {
        "truth-chronology": ("truth", "chronology"),
        "known-only-hypotheses": ("known mechanism hypotheses",),
    }.get(failure_code)
    if exception_tokens is None or not all(token in message for token in exception_tokens):
        raise ControlObservationError(f"{control_id} exception did not demonstrate {failure_code}")
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
    """Initialize lifecycle capture when loaded as an explicit pytest plugin."""

    del config
    global _PYTEST_REQUESTED_NODE, _PYTEST_COLLECTED, _PYTEST_PHASES
    requested = os.environ.get(_NODE_ENV)
    outcome_path = os.environ.get(_OUTCOME_ENV)
    if requested is None and outcome_path is None:
        return
    if not requested or not outcome_path:
        raise ControlObservationError("pytest control lifecycle environment is incomplete")
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
        raise ControlObservationError("pytest lifecycle output path is missing")
    lifecycle = PytestLifecycle(
        requested_node_id=_PYTEST_REQUESTED_NODE,
        collected_node_ids=tuple(_PYTEST_COLLECTED),
        phases=tuple(_PYTEST_PHASES),
        exit_status=int(exitstatus),
    )
    _write_exclusive(Path(output), canonical_json_pretty(lifecycle))
