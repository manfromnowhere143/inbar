"""Controls for the engineering-validation receipt producer.

The producer's whole purpose is to close an asymmetry: the repo could verify a receipt but
never make one. A producer that can emit a receipt the verifier rejects, or that can describe
a run it did not perform, would reopen it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from fieldtrue.domain import engineering_validation_plan_sha256
from fieldtrue.validation_producer import (
    EXPECTED_BLOCKERS,
    ValidationProducerError,
    _observe_mission,
    _observe_pytest,
    plan_argv,
    produce_validation_receipt,
)

RECEIPT_ID = "inbar-core-validation-test"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _junit(tests: int, failures: int, errors: int, skipped: int) -> str:
    return (
        f'<testsuite name="pytest" tests="{tests}" failures="{failures}" '
        f'errors="{errors}" skipped="{skipped}"></testsuite>'
    )


def _coverage() -> str:
    return json.dumps(
        {
            "totals": {
                "covered_lines": 100,
                "num_statements": 110,
                "covered_branches": 40,
                "num_branches": 44,
            }
        }
    )


def _seed(root: Path, *, tests: int = 10, skipped: int = 0) -> None:
    evidence = root / f"evidence/validation/{RECEIPT_ID}"
    _write(evidence / "pytest.junit.xml", _junit(tests, 0, 0, skipped))
    _write(evidence / "coverage.json", _coverage())


# --- Plan controls -----------------------------------------------------------------


def test_plan_has_the_eight_frozen_steps_in_order() -> None:
    assert [step_id for step_id, _ in plan_argv(RECEIPT_ID)] == [
        "uv-lock-check",
        "ruff-check",
        "ruff-format-check",
        "mypy",
        "schemas-check",
        "memory-verify",
        "mission-validate",
        "pytest-cov",
    ]


def test_pytest_step_forces_xfail_cases_to_execute() -> None:
    # An xfail-marked case must run normally rather than be silently tolerated.
    argv = dict(plan_argv(RECEIPT_ID))["pytest-cov"]
    assert "--runxfail" in argv


def test_mission_step_expects_exactly_the_registered_blocker() -> None:
    argv = dict(plan_argv(RECEIPT_ID))["mission-validate"]
    assert argv[-len(EXPECTED_BLOCKERS) :] == EXPECTED_BLOCKERS
    assert EXPECTED_BLOCKERS == ("iter001-acquisition-contract",)


def test_plan_artifacts_are_bound_to_their_receipt_id() -> None:
    # Two receipts must not write into one another's evidence directory.
    a = dict(plan_argv("receipt-a"))["pytest-cov"]
    b = dict(plan_argv("receipt-b"))["pytest-cov"]
    assert a != b
    assert any("receipt-a" in item for item in a)
    assert any("receipt-b" in item for item in b)


def test_plan_hash_changes_when_the_plan_changes() -> None:
    from datetime import UTC, datetime

    from fieldtrue.domain import EngineeringValidationArtifact, EngineeringValidationStep

    now = datetime(2026, 7, 16, tzinfo=UTC)

    def step(argv: tuple[str, ...]) -> EngineeringValidationStep:
        art = EngineeringValidationArtifact(
            path="evidence/validation/x/a.txt", sha256="a" * 64, bytes=0, media_type="text/plain"
        )
        other = art.model_copy(update={"path": "evidence/validation/x/b.txt"})
        return EngineeringValidationStep(
            step_id="ruff-check",
            argv=argv,
            working_directory=".",
            started_at=now,
            finished_at=now,
            duration_ms=0,
            expected_exit_code=0,
            observed_exit_code=0,
            result="pass",
            stdout=art,
            stderr=other,
        )

    first = engineering_validation_plan_sha256((step(("uv", "run", "ruff", "check", ".")),))
    second = engineering_validation_plan_sha256((step(("uv", "run", "ruff", "check", "src")),))
    assert first != second


# --- Observation controls ----------------------------------------------------------


def test_skipped_tests_are_refused(tmp_path: Path) -> None:
    # tests_skipped is typed to zero. A skipped case is unobserved behaviour and cannot be
    # recorded as validation.
    _seed(tmp_path, skipped=3)
    with pytest.raises(ValidationProducerError, match="zero skipped tests"):
        _observe_pytest(tmp_path, RECEIPT_ID)


def test_junit_without_a_testsuite_is_refused(tmp_path: Path) -> None:
    evidence = tmp_path / f"evidence/validation/{RECEIPT_ID}"
    _write(evidence / "pytest.junit.xml", "<other></other>")
    _write(evidence / "coverage.json", _coverage())
    with pytest.raises(ValidationProducerError, match="no testsuite"):
        _observe_pytest(tmp_path, RECEIPT_ID)


def test_pytest_observation_reports_observed_counts(tmp_path: Path) -> None:
    _seed(tmp_path, tests=10)
    observed = _observe_pytest(tmp_path, RECEIPT_ID)
    assert observed.tests_passed == 10
    assert observed.tests_failed == 0
    assert observed.tests_errors == 0
    assert observed.tests_skipped == 0
    assert observed.num_statements == 110
    assert observed.covered_branches == 40
    assert observed.junit_xml.sha256 != observed.coverage_json.sha256


def test_pytest_observation_does_not_launder_failures(tmp_path: Path) -> None:
    evidence = tmp_path / f"evidence/validation/{RECEIPT_ID}"
    _write(evidence / "pytest.junit.xml", _junit(tests=10, failures=2, errors=1, skipped=0))
    _write(evidence / "coverage.json", _coverage())
    observed = _observe_pytest(tmp_path, RECEIPT_ID)
    assert observed.tests_failed == 2
    assert observed.tests_errors == 1
    assert observed.tests_passed == 7


def test_mission_observation_records_unexpected_blockers(tmp_path: Path) -> None:
    evidence = tmp_path / f"evidence/validation/{RECEIPT_ID}"
    report = {
        "checks": [
            {"check_id": "iter001-acquisition-contract", "passed": False},
            {"check_id": "claim-registry", "passed": False},
            {"check_id": "schemas", "passed": True},
        ]
    }
    _write(evidence / "mission-validate.stdout.txt", json.dumps(report))
    observed = _observe_mission(tmp_path, RECEIPT_ID)
    assert observed.observed_blockers == ("iter001-acquisition-contract", "claim-registry")
    assert observed.unexpected_blockers == ("claim-registry",)
    assert observed.missing_expected_blockers == ()


def test_mission_observation_records_a_missing_expected_blocker(tmp_path: Path) -> None:
    # An unexpectedly PASSING acquisition blocker is a finding, not a success: the gate that
    # holds the mission in bootstrap stopped holding. The producer must record that rather
    # than quietly emit a clean receipt.
    evidence = tmp_path / f"evidence/validation/{RECEIPT_ID}"
    report = {
        "checks": [
            {"check_id": "iter001-acquisition-contract", "passed": True},
            {"check_id": "schemas", "passed": True},
        ]
    }
    _write(evidence / "mission-validate.stdout.txt", json.dumps(report))
    observed = _observe_mission(tmp_path, RECEIPT_ID)
    assert observed.observed_blockers == ()
    assert observed.missing_expected_blockers == ("iter001-acquisition-contract",)


def test_observation_cannot_name_a_blocker_that_is_not_a_mission_check(tmp_path: Path) -> None:
    # The contract requires expected blockers to be real mission checks. A blocker that is not
    # even a registered check is an incoherent observation, not a finding.
    evidence = tmp_path / f"evidence/validation/{RECEIPT_ID}"
    report = {"checks": [{"check_id": "schemas", "passed": True}]}
    _write(evidence / "mission-validate.stdout.txt", json.dumps(report))
    with pytest.raises(ValidationError, match="must name registered mission checks"):
        _observe_mission(tmp_path, RECEIPT_ID)


# --- Subject-binding control -------------------------------------------------------


def test_dirty_tree_is_refused(tmp_path: Path) -> None:
    # A receipt that binds a commit while validating different bytes proves nothing about
    # that commit. This is the control that keeps the subject honest.
    import subprocess

    subprocess.run(["/usr/bin/git", "init", "-q"], cwd=tmp_path, check=True)
    subprocess.run(
        ["/usr/bin/git", "config", "user.email", "t@example.invalid"], cwd=tmp_path, check=True
    )
    subprocess.run(["/usr/bin/git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    (tmp_path / "a.txt").write_text("one", encoding="utf-8")
    subprocess.run(["/usr/bin/git", "add", "-A"], cwd=tmp_path, check=True)
    subprocess.run(["/usr/bin/git", "commit", "-qm", "init"], cwd=tmp_path, check=True)
    (tmp_path / "a.txt").write_text("two", encoding="utf-8")

    with pytest.raises(ValidationProducerError, match="dirty tree"):
        produce_validation_receipt(tmp_path, receipt_id=RECEIPT_ID, producer_actor_id="claude")
