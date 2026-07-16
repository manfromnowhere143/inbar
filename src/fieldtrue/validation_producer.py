"""Produce the engineering-validation receipt that the handoff verifier checks.

Inbar could verify an `EngineeringValidationReceipt` in exact detail but could not produce
one: the verifier is committed, the producer was not. Every existing receipt was made by
out-of-repo tooling, so a fresh clone could not regenerate the resume contract it boots from.
That is asymmetric verification in a mission whose stated invariant is that a signed report is
not authority unless a verifier can reconstruct it from sealed inputs.

This module closes that asymmetry. It executes the frozen command plan, binds every produced
artifact by content, and records only what it observed.

The receipt is a same-operator engineering observation. It is not independent attestation, not
a scientific result, and grants no authority. Those facts are typed literals on the receipt
rather than prose, so this producer cannot claim otherwise.
"""

from __future__ import annotations

import json
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from fieldtrue.canonical import canonical_json_pretty, sha256_bytes
from fieldtrue.domain import (
    EngineeringValidationArtifact,
    EngineeringValidationEnvironment,
    EngineeringValidationMissionObservation,
    EngineeringValidationPytestObservation,
    EngineeringValidationReceipt,
    EngineeringValidationResourceAccounting,
    EngineeringValidationStep,
    engineering_validation_plan_sha256,
)

EVIDENCE_ROOT: Final = "evidence/validation"
EXPECTED_BLOCKERS: Final = ("iter001-acquisition-contract",)
_TEXT_MEDIA_TYPE: Final = "text/plain; charset=utf-8"


class ValidationProducerError(RuntimeError):
    """The validation plan could not be executed or observed."""


def _evidence_dir(receipt_id: str) -> str:
    return f"{EVIDENCE_ROOT}/{receipt_id}"


def plan_argv(receipt_id: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """The frozen core validation plan.

    The pytest step writes its JUnit and coverage artifacts into this receipt's evidence
    directory, so the plan — and therefore its hash — is bound to the receipt id. `--runxfail`
    is required: an xfail-marked case must execute normally rather than be silently tolerated.
    """
    evidence = _evidence_dir(receipt_id)
    return (
        ("uv-lock-check", ("uv", "lock", "--check")),
        ("ruff-check", ("uv", "run", "ruff", "check", ".")),
        ("ruff-format-check", ("uv", "run", "ruff", "format", "--check", ".")),
        ("mypy", ("uv", "run", "mypy", "src")),
        ("schemas-check", ("uv", "run", "inbar", "schemas", "check")),
        ("memory-verify", ("uv", "run", "inbar", "memory", "verify")),
        (
            "mission-validate",
            ("uv", "run", "inbar", "mission", "validate", "--expect-failure", *EXPECTED_BLOCKERS),
        ),
        (
            "pytest-cov",
            (
                "uv",
                "run",
                "pytest",
                "--runxfail",
                "--cov",
                f"--cov-report=json:{evidence}/coverage.json",
                f"--junitxml={evidence}/pytest.junit.xml",
            ),
        ),
    )


def _artifact(
    repo_root: Path, relative_path: str, media_type: str
) -> EngineeringValidationArtifact:
    data = (repo_root / relative_path).read_bytes()
    return EngineeringValidationArtifact(
        path=relative_path,
        sha256=sha256_bytes(data),
        bytes=len(data),
        media_type=media_type,
    )


def _git(repo_root: Path, *args: str) -> str:
    return subprocess.run(  # noqa: S603 - fixed trusted Git identity query
        ["/usr/bin/git", *args],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _uv_version() -> str:
    # `uv` is resolved from PATH, exactly as the frozen plan's own steps invoke it. Recording a
    # version resolved differently from the binary that ran the plan would misdescribe the run.
    raw = subprocess.run(
        ["uv", "--version"],  # noqa: S607 - same PATH resolution as the frozen plan
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return raw.removeprefix("uv ").split()[0]


def _observe_pytest(repo_root: Path, receipt_id: str) -> EngineeringValidationPytestObservation:
    evidence = _evidence_dir(receipt_id)
    junit = _artifact(repo_root, f"{evidence}/pytest.junit.xml", "application/xml")
    coverage = _artifact(repo_root, f"{evidence}/coverage.json", "application/json")

    root = ET.fromstring((repo_root / f"{evidence}/pytest.junit.xml").read_bytes())  # noqa: S314
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        raise ValidationProducerError("JUnit evidence contains no testsuite")
    total = int(suite.get("tests", "0"))
    failures = int(suite.get("failures", "0"))
    errors = int(suite.get("errors", "0"))
    skipped = int(suite.get("skipped", "0"))
    if skipped:
        # The receipt types tests_skipped to zero. A skipped case is unobserved behaviour and
        # cannot be recorded as validation.
        raise ValidationProducerError(f"validation requires zero skipped tests, observed {skipped}")

    totals = json.loads((repo_root / f"{evidence}/coverage.json").read_bytes())["totals"]
    return EngineeringValidationPytestObservation(
        step_id="pytest-cov",
        junit_xml=junit,
        coverage_json=coverage,
        tests_passed=total - failures - errors - skipped,
        tests_failed=failures,
        tests_errors=errors,
        tests_skipped=0,
        covered_lines=totals["covered_lines"],
        num_statements=totals["num_statements"],
        covered_branches=totals["covered_branches"],
        num_branches=totals["num_branches"],
    )


def _observe_mission(repo_root: Path, receipt_id: str) -> EngineeringValidationMissionObservation:
    raw = (repo_root / f"{_evidence_dir(receipt_id)}/mission-validate.stdout.txt").read_bytes()
    report = json.loads(raw)
    checks = report["checks"]
    observed = tuple(check["check_id"] for check in checks if not check["passed"])
    return EngineeringValidationMissionObservation(
        step_id="mission-validate",
        mission_check_ids=tuple(check["check_id"] for check in checks),
        expected_blockers=EXPECTED_BLOCKERS,
        observed_blockers=observed,
        missing_expected_blockers=tuple(b for b in EXPECTED_BLOCKERS if b not in observed),
        unexpected_blockers=tuple(b for b in observed if b not in EXPECTED_BLOCKERS),
    )


def produce_validation_receipt(
    repo_root: Path,
    *,
    receipt_id: str,
    producer_actor_id: str,
) -> EngineeringValidationReceipt:
    """Execute the frozen plan and record exactly what was observed.

    The subject commit and tree are read before execution. A dirty tree is refused: a receipt
    that binds a commit while validating different bytes proves nothing about that commit.
    """
    if _git(repo_root, "status", "--porcelain"):
        raise ValidationProducerError(
            "refusing to validate a dirty tree; the receipt would bind bytes it did not test"
        )
    subject_commit = _git(repo_root, "rev-parse", "HEAD")
    subject_tree = _git(repo_root, "rev-parse", "HEAD^{tree}")

    evidence = repo_root / _evidence_dir(receipt_id)
    evidence.mkdir(parents=True, exist_ok=True)

    started_at = datetime.now(UTC)
    steps: list[EngineeringValidationStep] = []
    for step_id, argv in plan_argv(receipt_id):
        step_started = datetime.now(UTC)
        completed = subprocess.run(  # noqa: S603 - argv is the frozen committed plan
            list(argv), cwd=repo_root, capture_output=True, check=False
        )
        step_finished = datetime.now(UTC)
        stdout_rel = f"{_evidence_dir(receipt_id)}/{step_id}.stdout.txt"
        stderr_rel = f"{_evidence_dir(receipt_id)}/{step_id}.stderr.txt"
        (repo_root / stdout_rel).write_bytes(completed.stdout)
        (repo_root / stderr_rel).write_bytes(completed.stderr)
        steps.append(
            EngineeringValidationStep(
                step_id=step_id,
                argv=argv,
                working_directory=".",
                started_at=step_started,
                finished_at=step_finished,
                duration_ms=int((step_finished - step_started).total_seconds() * 1000),
                expected_exit_code=0,
                observed_exit_code=completed.returncode,
                result="pass" if completed.returncode == 0 else "fail",
                stdout=_artifact(repo_root, stdout_rel, _TEXT_MEDIA_TYPE),
                stderr=_artifact(repo_root, stderr_rel, _TEXT_MEDIA_TYPE),
            )
        )
    finished_at = datetime.now(UTC)

    # Re-verify the subject after execution. The pre-run clean check alone leaves a window in
    # which an edit during the run would make the receipt bind a commit whose bytes were never
    # the bytes tested. Only this run's own evidence artifacts may appear.
    if _git(repo_root, "rev-parse", "HEAD") != subject_commit:
        raise ValidationProducerError(
            "subject commit changed during validation; the receipt would describe the wrong tree"
        )
    # -uall lists every untracked file individually, so a collapsed directory entry can never
    # hide a stray path that merely shares an ancestor with the evidence directory.
    evidence_prefix = f"{_evidence_dir(receipt_id)}/"
    for line in _git(repo_root, "status", "--porcelain", "-uall").splitlines():
        changed_path = line[3:].strip().strip('"')
        if not changed_path.startswith(evidence_prefix):
            raise ValidationProducerError(
                "tree changed outside the evidence directory during validation: " + changed_path
            )

    step_tuple = tuple(steps)
    receipt = EngineeringValidationReceipt(
        schema_version="inbar.engineering-validation-receipt.v1",
        receipt_id=receipt_id,
        mission_id="inbar",
        subject_commit=subject_commit,
        subject_tree=subject_tree,
        plan_id="inbar.core-engineering-validation.v1",
        plan_sha256=engineering_validation_plan_sha256(step_tuple),
        started_at=started_at,
        finished_at=finished_at,
        producer_actor_id=producer_actor_id,
        assurance_scope="same-operator-engineering-observation-no-independent-attestation",
        independent_attestation=False,
        environment=EngineeringValidationEnvironment(
            platform=platform.platform(),
            machine=platform.machine(),
            python_version=platform.python_version(),
            uv_version=_uv_version(),
        ),
        steps=step_tuple,
        pytest_observation=_observe_pytest(repo_root, receipt_id),
        mission_observation=_observe_mission(repo_root, receipt_id),
        # Engineering validation is deliberately unmetered and the contract types it so.
        # This producer must not imply a measurement it did not make.
        resource_accounting=EngineeringValidationResourceAccounting(
            measurement_status="not_metered",
            direct_cost_usd=None,
            gpu_seconds=None,
            cloud_jobs=None,
            paid_calls=None,
        ),
        scientific_result="not_evaluated",
        authority_effect="none",
        result="pass" if all(step.result == "pass" for step in step_tuple) else "fail",
    )
    return receipt


def write_validation_receipt(repo_root: Path, *, receipt_id: str, producer_actor_id: str) -> Path:
    receipt = produce_validation_receipt(
        repo_root, receipt_id=receipt_id, producer_actor_id=producer_actor_id
    )
    path = repo_root / _evidence_dir(receipt_id) / "receipt.json"
    payload: dict[str, Any] = receipt.model_dump(mode="json")
    path.write_bytes(canonical_json_pretty(payload) + b"\n")
    return path


def _main(argv: list[str]) -> int:  # pragma: no cover - thin CLI seam
    if len(argv) != 2:
        sys.stderr.write("usage: validation_producer <receipt_id> <producer_actor_id>\n")
        return 2
    path = write_validation_receipt(Path.cwd(), receipt_id=argv[0], producer_actor_id=argv[1])
    sys.stdout.write(f"{path}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - thin CLI seam
    raise SystemExit(_main(sys.argv[1:]))


__all__ = [
    "EVIDENCE_ROOT",
    "EXPECTED_BLOCKERS",
    "ValidationProducerError",
    "plan_argv",
    "produce_validation_receipt",
    "write_validation_receipt",
]
