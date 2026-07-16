from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from fieldtrue.canonical import sha256_value
from fieldtrue.domain import (
    READINESS_AUTHORIZED_NEXT_ACTIONS,
    READINESS_FORBIDDEN_NEXT_ACTIONS,
    CausalHypothesis,
    ClaimRecord,
    DiscriminatingTest,
    EngineeringValidationArtifact,
    EngineeringValidationEnvironment,
    EngineeringValidationMissionObservation,
    EngineeringValidationPytestObservation,
    EngineeringValidationReceipt,
    EngineeringValidationResourceAccounting,
    EngineeringValidationStep,
    EvidenceBundle,
    EvidenceItem,
    ExecutionAuthority,
    GateResult,
    GateStatus,
    HypothesisSet,
    JobResources,
    JobSpec,
    Modality,
    ReadinessReport,
    RecoveryPlan,
    ReviewAttestation,
    ReviewKind,
    SafetyEnvelope,
    SelectedTest,
    TruthRecord,
    VerificationResult,
    engineering_validation_plan_sha256,
)
from fieldtrue.domain import (
    TestObservation as DomainTestObservation,
)
from fieldtrue.domain import (
    TestOutcomeModel as DomainTestOutcomeModel,
)
from tests.helpers import APPROVAL_HASH, HASH_A, HASH_B, artifact, hypotheses, informative_test


def _validation_artifact(receipt_id: str, name: str) -> EngineeringValidationArtifact:
    return EngineeringValidationArtifact(
        path=f"evidence/validation/{receipt_id}/{name}",
        sha256=HASH_A,
        bytes=8,
        media_type="text/plain; charset=utf-8",
    )


def _validation_step(
    receipt_id: str,
    step_id: str,
    *,
    observed_exit_code: int = 0,
    result: str = "pass",
) -> EngineeringValidationStep:
    started_at = datetime(2026, 7, 16, 10, 0, tzinfo=UTC)
    return EngineeringValidationStep.model_validate(
        {
            "step_id": step_id,
            "argv": ("uv", "run", step_id),
            "working_directory": ".",
            "started_at": started_at,
            "finished_at": datetime(2026, 7, 16, 10, 1, tzinfo=UTC),
            "duration_ms": 60_000,
            "expected_exit_code": 0,
            "observed_exit_code": observed_exit_code,
            "result": result,
            "stdout": _validation_artifact(receipt_id, f"{step_id}.stdout.txt"),
            "stderr": _validation_artifact(receipt_id, f"{step_id}.stderr.txt"),
        }
    )


def _validation_receipt_values() -> dict[str, object]:
    receipt_id = "validation.fixture.v1"
    steps = (
        _validation_step(receipt_id, "pytest-cov"),
        _validation_step(receipt_id, "mission-validate"),
    )
    return {
        "schema_version": "inbar.engineering-validation-receipt.v1",
        "receipt_id": receipt_id,
        "mission_id": "inbar",
        "subject_commit": "1" * 40,
        "subject_tree": "2" * 40,
        "plan_id": "inbar.core-engineering-validation.v1",
        "plan_sha256": engineering_validation_plan_sha256(steps),
        "started_at": datetime(2026, 7, 16, 9, 59, tzinfo=UTC),
        "finished_at": datetime(2026, 7, 16, 10, 2, tzinfo=UTC),
        "producer_actor_id": "codex",
        "assurance_scope": ("same-operator-engineering-observation-no-independent-attestation"),
        "independent_attestation": False,
        "environment": EngineeringValidationEnvironment(
            platform="macOS-15",
            machine="arm64",
            python_version="3.12.13",
            uv_version="0.11.28",
        ),
        "steps": steps,
        "pytest_observation": EngineeringValidationPytestObservation(
            step_id="pytest-cov",
            junit_xml=_validation_artifact(receipt_id, "pytest.junit.xml"),
            coverage_json=_validation_artifact(receipt_id, "coverage.json"),
            tests_passed=1041,
            tests_failed=0,
            tests_errors=0,
            tests_skipped=0,
            covered_lines=901,
            num_statements=1000,
            covered_branches=450,
            num_branches=500,
        ),
        "mission_observation": EngineeringValidationMissionObservation(
            step_id="mission-validate",
            mission_check_ids=("owner-boundary", "iter001-acquisition-contract"),
            expected_blockers=("iter001-acquisition-contract",),
            observed_blockers=("iter001-acquisition-contract",),
            missing_expected_blockers=(),
            unexpected_blockers=(),
        ),
        "resource_accounting": EngineeringValidationResourceAccounting(
            measurement_status="not_metered",
            direct_cost_usd=None,
            gpu_seconds=None,
            cloud_jobs=None,
            paid_calls=None,
        ),
        "scientific_result": "not_evaluated",
        "authority_effect": "none",
        "result": "pass",
    }


def test_readiness_authority_contract_is_derived_from_the_verdict() -> None:
    report = ReadinessReport(
        dataset_id="fixture",
        gates=(
            GateResult(
                gate_id="fixture-gate",
                status=GateStatus.BLOCKED,
                observed=0,
                requirement="Fixture requirement.",
                detail="Fixture detail.",
            ),
        ),
        verdict="BLOCKED_EVIDENCE",
        authorized_next_action="unsafe caller-supplied action",
        forbidden_next_actions=("none",),
    )

    assert report.authorized_next_action == READINESS_AUTHORIZED_NEXT_ACTIONS[report.verdict]
    assert report.forbidden_next_actions == READINESS_FORBIDDEN_NEXT_ACTIONS
    with pytest.raises(ValidationError, match="Input should be"):
        ReadinessReport.model_validate({**report.model_dump(), "verdict": "UNREGISTERED_VERDICT"})


def test_claim_record_requires_unique_normalized_repository_evidence() -> None:
    values = {
        "claim_id": "claim.fixture.v1",
        "status": "blocked",
        "wording": "Fixture claim.",
        "scope": "Fixture only.",
        "evidence_refs": ("mission/contract.json",),
        "permitted_wording": "blocked",
        "forbidden_wording": "supported",
        "next_falsifier": "Fixture falsifier.",
    }

    assert ClaimRecord.model_validate(values).evidence_refs == ("mission/contract.json",)
    for references in (
        (),
        ("mission/contract.json", "mission/contract.json"),
        ("../contract.json",),
        ("mission/../contract.json",),
        ("mission//contract.json",),
        ("./contract.json",),
        (".",),
        ("..",),
        ("/absolute.json",),
        ("mission\\contract.json",),
        ("https://example.invalid/evidence",),
    ):
        with pytest.raises(ValidationError):
            ClaimRecord.model_validate({**values, "evidence_refs": references})

    successor = ClaimRecord.model_validate(
        {**values, "claim_id": "claim.fixture.v2", "supersedes_claim_id": "claim.fixture.v1"}
    )
    assert successor.supersedes_claim_id == "claim.fixture.v1"


def test_engineering_validation_receipt_binds_a_derived_plan_and_observations() -> None:
    values = _validation_receipt_values()
    receipt = EngineeringValidationReceipt.model_validate(values)

    assert receipt.plan_sha256 == engineering_validation_plan_sha256(receipt.steps)
    assert receipt.result == "pass"
    assert receipt.independent_attestation is False
    assert receipt.resource_accounting.direct_cost_usd is None

    with pytest.raises(ValidationError, match="plan hash"):
        EngineeringValidationReceipt.model_validate({**values, "plan_sha256": HASH_B})
    with pytest.raises(ValidationError, match="receipt result"):
        EngineeringValidationReceipt.model_validate({**values, "result": "fail"})
    with pytest.raises(ValidationError, match="Input should be False"):
        EngineeringValidationReceipt.model_validate({**values, "independent_attestation": True})
    with pytest.raises(ValidationError, match="Input should be None"):
        EngineeringValidationReceipt.model_validate(
            {
                **values,
                "resource_accounting": {
                    **receipt.resource_accounting.model_dump(),
                    "direct_cost_usd": "0",
                },
            }
        )


def test_engineering_validation_receipt_rejects_ambiguous_steps_and_artifacts() -> None:
    values = _validation_receipt_values()
    steps = values["steps"]
    assert isinstance(steps, tuple)
    duplicate_step = EngineeringValidationStep.model_validate(
        {
            **steps[1].model_dump(),
            "step_id": steps[0].step_id,
        }
    )
    with pytest.raises(ValidationError, match="step IDs"):
        EngineeringValidationReceipt.model_validate({**values, "steps": (steps[0], duplicate_step)})

    duplicate_artifact_step = EngineeringValidationStep.model_validate(
        {
            **steps[1].model_dump(),
            "stdout": steps[0].stdout.model_dump(),
        }
    )
    changed_steps = (steps[0], duplicate_artifact_step)
    with pytest.raises(ValidationError, match="artifact paths"):
        EngineeringValidationReceipt.model_validate(
            {
                **values,
                "steps": changed_steps,
                "plan_sha256": engineering_validation_plan_sha256(changed_steps),
            }
        )

    with pytest.raises(ValidationError, match="exit codes"):
        _validation_step(
            "validation.fixture.v1",
            "failing-step",
            observed_exit_code=1,
            result="pass",
        )

    with pytest.raises(ValidationError, match="duration differs"):
        EngineeringValidationStep.model_validate(
            {
                **steps[0].model_dump(),
                "duration_ms": 1,
            }
        )


def test_engineering_validation_receipt_fails_closed_on_observed_failures() -> None:
    values = _validation_receipt_values()
    mission = values["mission_observation"]
    assert isinstance(mission, EngineeringValidationMissionObservation)
    failed_mission = EngineeringValidationMissionObservation(
        **{
            **mission.model_dump(),
            "observed_blockers": ("iter001-acquisition-contract", "owner-boundary"),
            "unexpected_blockers": ("owner-boundary",),
        }
    )
    with pytest.raises(ValidationError, match="receipt result"):
        EngineeringValidationReceipt.model_validate(
            {**values, "mission_observation": failed_mission}
        )

    pytest_observation = values["pytest_observation"]
    assert isinstance(pytest_observation, EngineeringValidationPytestObservation)
    with pytest.raises(ValidationError, match="covered lines"):
        EngineeringValidationPytestObservation.model_validate(
            {
                **pytest_observation.model_dump(),
                "covered_lines": 1001,
            }
        )

    with pytest.raises(ValidationError, match="greater than 0"):
        EngineeringValidationPytestObservation.model_validate(
            {
                **pytest_observation.model_dump(),
                "tests_passed": 0,
                "tests_skipped": 1042,
            }
        )
    with pytest.raises(ValidationError, match="Input should be 0"):
        EngineeringValidationPytestObservation.model_validate(
            {
                **pytest_observation.model_dump(),
                "tests_skipped": 1,
            }
        )
    with pytest.raises(ValidationError, match="greater than 0"):
        EngineeringValidationPytestObservation.model_validate(
            {
                **pytest_observation.model_dump(),
                "covered_lines": 0,
                "num_statements": 0,
                "covered_branches": 0,
                "num_branches": 0,
            }
        )
    with pytest.raises(ValidationError, match=r"90\.01 percent"):
        EngineeringValidationPytestObservation.model_validate(
            {
                **pytest_observation.model_dump(),
                "covered_lines": 900,
            }
        )

    exact_floor = {
        **pytest_observation.model_dump(),
        "covered_lines": 4_501,
        "num_statements": 5_000,
        "covered_branches": 4_500,
        "num_branches": 5_000,
    }
    assert EngineeringValidationPytestObservation.model_validate(exact_floor)
    with pytest.raises(ValidationError, match=r"90\.01 percent"):
        EngineeringValidationPytestObservation.model_validate(
            {**exact_floor, "covered_lines": 4_500}
        )

    with pytest.raises(ValidationError, match="registered acquisition blocker"):
        EngineeringValidationMissionObservation.model_validate(
            {
                **mission.model_dump(),
                "expected_blockers": (),
                "observed_blockers": (),
            }
        )
    missing_mission = EngineeringValidationMissionObservation.model_validate(
        {
            **mission.model_dump(),
            "observed_blockers": (),
            "missing_expected_blockers": ("iter001-acquisition-contract",),
        }
    )
    with pytest.raises(ValidationError, match="receipt result"):
        EngineeringValidationReceipt.model_validate(
            {**values, "mission_observation": missing_mission}
        )

    receipt = EngineeringValidationReceipt.model_validate(values)
    outside = EngineeringValidationArtifact(
        path="evidence/outside/stdout.txt",
        sha256=HASH_A,
        bytes=8,
        media_type="text/plain",
    )
    altered_step = EngineeringValidationStep.model_validate(
        {**receipt.steps[0].model_dump(), "stdout": outside.model_dump()}
    )
    altered_steps = (altered_step, receipt.steps[1])
    with pytest.raises(ValidationError, match="receipt directory"):
        EngineeringValidationReceipt.model_validate(
            {
                **values,
                "steps": altered_steps,
                "plan_sha256": engineering_validation_plan_sha256(altered_steps),
            }
        )


def test_domain_records_reject_ambiguous_evidence_and_hypotheses() -> None:
    reviewed_at = datetime(2026, 7, 16, 10, 0, tzinfo=UTC)
    review_values = {
        "attestation_id": "review-1",
        "kind": ReviewKind.CAUSE,
        "producer_id": "producer",
        "reviewer_id": "reviewer",
        "subject_ids": ("mechanism-1",),
        "method": "fixture",
        "scope": "fixture",
        "evidence_refs": (artifact(),),
        "reviewed_at": reviewed_at,
    }
    with pytest.raises(ValidationError, match="subject IDs must be unique"):
        ReviewAttestation.model_validate(
            {**review_values, "subject_ids": ("mechanism-1", "mechanism-1")}
        )
    with pytest.raises(ValidationError, match="timestamp must be timezone-aware"):
        ReviewAttestation.model_validate(
            {**review_values, "reviewed_at": reviewed_at.replace(tzinfo=None)}
        )

    evidence = EvidenceItem(
        evidence_id="evidence-1",
        modality=Modality.TELEMETRY,
        artifact=artifact(),
        description="Fixture evidence.",
    )
    with pytest.raises(ValidationError, match="evidence IDs must be unique"):
        EvidenceBundle(
            incident_id="incident-1",
            system_family="family",
            system_id="system-1",
            mission_id="mission-1",
            evidence=(evidence, evidence),
            truth_commitment=HASH_A,
        )

    review = ReviewAttestation.model_validate(review_values)
    truth_values = {
        "incident_id": "incident-1",
        "commitment_nonce": HASH_A,
        "hardware_family": "family",
        "hardware_id": "hardware-1",
        "fault_family": "fault",
        "mechanism_ids": ("mechanism-1",),
        "cause_authority": "fixture",
        "verification_method": "fixture",
        "review_attestations": (review,),
    }
    with pytest.raises(ValidationError, match="mechanism IDs must be unique"):
        TruthRecord.model_validate(
            {**truth_values, "mechanism_ids": ("mechanism-1", "mechanism-1")}
        )
    with pytest.raises(ValidationError, match="review attestation IDs must be unique"):
        TruthRecord.model_validate({**truth_values, "review_attestations": (review, review)})

    with pytest.raises(ValidationError, match="hypothesis IDs must be unique"):
        HypothesisSet(
            incident_id="incident-1",
            proposer_id="engine",
            hypotheses=(
                CausalHypothesis(hypothesis_id="duplicate", description="a", prior=0.5),
                CausalHypothesis(
                    hypothesis_id="duplicate",
                    description="unknown",
                    prior=0.5,
                    unknown=True,
                ),
            ),
        )


def test_domain_records_reject_ambiguous_test_and_safety_contracts() -> None:
    test_values = informative_test().model_dump()
    outcomes = test_values["outcome_model"]
    assert isinstance(outcomes, tuple)

    duplicate_outcomes = (
        outcomes[0],
        {**outcomes[1], "outcome_id": outcomes[0]["outcome_id"]},
    )
    with pytest.raises(ValidationError, match="outcome IDs must be unique"):
        DiscriminatingTest.model_validate({**test_values, "outcome_model": duplicate_outcomes})

    empty_hypotheses = tuple({**outcome, "probability_by_hypothesis": {}} for outcome in outcomes)
    with pytest.raises(ValidationError, match="model at least one hypothesis"):
        DiscriminatingTest.model_validate({**test_values, "outcome_model": empty_hypotheses})

    second_probabilities = dict(outcomes[1]["probability_by_hypothesis"])
    second_probabilities.pop("unknown")
    inconsistent_hypotheses = (
        outcomes[0],
        {**outcomes[1], "probability_by_hypothesis": second_probabilities},
    )
    with pytest.raises(ValidationError, match="same hypotheses"):
        DiscriminatingTest.model_validate({**test_values, "outcome_model": inconsistent_hypotheses})

    with pytest.raises(ValidationError, match="preconditions must be unique"):
        DiscriminatingTest.model_validate(
            {**test_values, "preconditions": ("isolated", "isolated")}
        )

    envelope_values = {
        "envelope_id": "replay-envelope",
        "authority": ExecutionAuthority.REPLAY,
        "allowed_test_ids": ("test-1",),
        "max_risk": 0.2,
        "satisfied_preconditions": ("isolated",),
    }
    with pytest.raises(ValidationError, match="allowed test IDs must be unique"):
        SafetyEnvelope.model_validate({**envelope_values, "allowed_test_ids": ("test-1", "test-1")})
    with pytest.raises(ValidationError, match="satisfied preconditions must be unique"):
        SafetyEnvelope.model_validate(
            {
                **envelope_values,
                "satisfied_preconditions": ("isolated", "isolated"),
            }
        )

    observed_at = datetime(2026, 7, 16, 10, 0, tzinfo=UTC)
    observation_values = {
        "incident_id": "incident-1",
        "test_id": "test-1",
        "outcome_id": "outcome-1",
        "authority": ExecutionAuthority.REPLAY,
        "executor_id": "executor",
        "started_at": observed_at,
        "finished_at": observed_at,
        "observation_artifact": artifact(),
        "safety_envelope_id": "envelope-1",
        "candidate_sha256": HASH_A,
        "safety_envelope_sha256": HASH_B,
    }
    with pytest.raises(ValidationError, match="timestamps must be timezone-aware"):
        DomainTestObservation.model_validate(
            {**observation_values, "started_at": observed_at.replace(tzinfo=None)}
        )
    with pytest.raises(ValidationError, match="testbed observations require an approval"):
        DomainTestObservation.model_validate(
            {**observation_values, "authority": ExecutionAuthority.TESTBED}
        )

    command = ("python", "run.py")
    with pytest.raises(ValidationError, match="secret references must be unique"):
        JobSpec(
            job_id="job-duplicate-secrets",
            git_commit="1" * 40,
            oci_image_digest=f"sha256:{HASH_A}",
            command=command,
            command_sha256=sha256_value(command),
            allowlist_id="cpu-research-v1",
            allowlist_sha256=HASH_B,
            dataset_hashes=(HASH_A,),
            case_hashes=(HASH_A,),
            resources=JobResources(cpu=2, memory_gb=4),
            max_runtime_seconds=60,
            idempotency_key="job-duplicate-secrets-key",
            artifact_prefix="gs://bucket/jobs/job-duplicate-secrets",
            budget_usd="0",
            cost_estimate_usd="0",
            cost_estimate_source="local CPU",
            cost_estimated_at=observed_at,
            secret_references=(
                "secret://inbar/token@v1",
                "secret://inbar/token@v1",
            ),
            authority=ExecutionAuthority.REPLAY,
            approval_receipt_hash=APPROVAL_HASH,
        )


def test_validation_domain_rejects_invalid_step_observations() -> None:
    values = _validation_receipt_values()
    steps = values["steps"]
    assert isinstance(steps, tuple)
    step_values = steps[0].model_dump()
    started_at = step_values["started_at"]
    assert isinstance(started_at, datetime)

    counterexamples = (
        (
            {**step_values, "started_at": started_at.replace(tzinfo=None)},
            "timestamps must be timezone-aware",
        ),
        (
            {**step_values, "finished_at": started_at - timedelta(seconds=1)},
            "cannot finish before it starts",
        ),
        ({**step_values, "argv": ("uv", "bad\x00argument")}, "argv is invalid"),
        ({**step_values, "stdout": step_values["stderr"]}, "must differ"),
    )
    for candidate, message in counterexamples:
        with pytest.raises(ValidationError, match=message):
            EngineeringValidationStep.model_validate(candidate)


def test_validation_domain_rejects_inconsistent_structured_observations() -> None:
    values = _validation_receipt_values()
    pytest_observation = values["pytest_observation"]
    mission_observation = values["mission_observation"]
    assert isinstance(pytest_observation, EngineeringValidationPytestObservation)
    assert isinstance(mission_observation, EngineeringValidationMissionObservation)

    with pytest.raises(ValidationError, match="covered branches"):
        EngineeringValidationPytestObservation.model_validate(
            {**pytest_observation.model_dump(), "covered_branches": 501}
        )
    with pytest.raises(ValidationError, match="structured artifacts must differ"):
        EngineeringValidationPytestObservation.model_validate(
            {
                **pytest_observation.model_dump(),
                "coverage_json": pytest_observation.junit_xml.model_dump(),
            }
        )

    mission_values = mission_observation.model_dump()
    mission_counterexamples = (
        (
            {
                **mission_values,
                "mission_check_ids": (
                    "owner-boundary",
                    "iter001-acquisition-contract",
                    "owner-boundary",
                ),
            },
            "mission check IDs must be unique",
        ),
        (
            {
                **mission_values,
                "observed_blockers": (
                    "iter001-acquisition-contract",
                    "unknown-blocker",
                ),
                "unexpected_blockers": ("unknown-blocker",),
            },
            "must name registered mission checks",
        ),
        (
            {
                **mission_values,
                "observed_blockers": (),
                "missing_expected_blockers": (),
            },
            "missing expected blockers do not follow",
        ),
        (
            {
                **mission_values,
                "observed_blockers": (
                    "iter001-acquisition-contract",
                    "owner-boundary",
                ),
                "unexpected_blockers": (),
            },
            "unexpected blockers do not follow",
        ),
    )
    for candidate, message in mission_counterexamples:
        with pytest.raises(ValidationError, match=message):
            EngineeringValidationMissionObservation.model_validate(candidate)


def test_validation_domain_rejects_invalid_receipt_time_and_step_references() -> None:
    values = _validation_receipt_values()
    started_at = values["started_at"]
    steps = values["steps"]
    assert isinstance(started_at, datetime)
    assert isinstance(steps, tuple)

    with pytest.raises(ValidationError, match="timestamps must be timezone-aware"):
        EngineeringValidationReceipt.model_validate(
            {**values, "started_at": started_at.replace(tzinfo=None)}
        )
    with pytest.raises(ValidationError, match="cannot finish before it starts"):
        EngineeringValidationReceipt.model_validate(
            {**values, "finished_at": started_at - timedelta(seconds=1)}
        )

    incomplete_steps = (steps[0],)
    with pytest.raises(ValidationError, match="must reference recorded steps"):
        EngineeringValidationReceipt.model_validate(
            {
                **values,
                "steps": incomplete_steps,
                "plan_sha256": engineering_validation_plan_sha256(incomplete_steps),
            }
        )

    with pytest.raises(ValidationError, match="must fall inside the receipt time window"):
        EngineeringValidationReceipt.model_validate(
            {
                **values,
                "started_at": steps[0].started_at + timedelta(seconds=30),
            }
        )


def test_hypothesis_set_requires_one_unknown_and_normalized_priors() -> None:
    assert hypotheses().hypotheses[-1].unknown
    with pytest.raises(ValidationError, match="exactly one unknown"):
        HypothesisSet(
            incident_id="incident-1",
            proposer_id="engine",
            hypotheses=(
                CausalHypothesis(hypothesis_id="a", description="a", prior=0.5),
                CausalHypothesis(hypothesis_id="b", description="b", prior=0.5),
            ),
        )
    with pytest.raises(ValidationError, match="sum to 1"):
        HypothesisSet(
            incident_id="incident-1",
            proposer_id="engine",
            hypotheses=(
                CausalHypothesis(hypothesis_id="a", description="a", prior=0.4),
                CausalHypothesis(hypothesis_id="unknown", description="u", prior=0.4, unknown=True),
            ),
        )


def test_test_outcomes_must_form_distribution_for_every_hypothesis() -> None:
    with pytest.raises(ValidationError, match="must sum to 1"):
        DiscriminatingTest(
            test_id="bad-test",
            description="bad probabilities",
            authority=ExecutionAuthority.REPLAY,
            approved=True,
            cost_units=1,
            duration_seconds=1,
            risk=0,
            outcome_model=(
                DomainTestOutcomeModel(
                    outcome_id="one", probability_by_hypothesis={"a": 0.8, "unknown": 0.5}
                ),
                DomainTestOutcomeModel(
                    outcome_id="two", probability_by_hypothesis={"a": 0.3, "unknown": 0.5}
                ),
            ),
        )


def test_testbed_authority_requires_approval() -> None:
    with pytest.raises(ValidationError, match="approval"):
        informative_test(authority=ExecutionAuthority.TESTBED)
    test = informative_test(
        authority=ExecutionAuthority.TESTBED,
        approval_hash=APPROVAL_HASH,
    )
    assert test.approval_receipt_hash == APPROVAL_HASH
    with pytest.raises(ValidationError, match="approval"):
        SafetyEnvelope(
            envelope_id="testbed-envelope",
            authority=ExecutionAuthority.TESTBED,
            allowed_test_ids=(test.test_id,),
            max_risk=0.2,
        )


def test_recovery_verifier_must_be_independent() -> None:
    with pytest.raises(ValidationError, match="sole verifier"):
        VerificationResult(
            verification_id="verification-1",
            recovery_id="recovery-1",
            verifier_id="same-model",
            proposer_id="same-model",
            action_valid=True,
            target_valid=True,
            settled_success=True,
            abstained=False,
            outcome_artifacts=(artifact(),),
            scope="fixture",
        )


def test_job_spec_requires_immutable_image_and_consistent_accelerator() -> None:
    resources = JobResources(cpu=2, memory_gb=4)
    spec = JobSpec(
        job_id="job-1",
        git_commit="1" * 40,
        oci_image_digest=f"sha256:{HASH_A}",
        command=("python", "run.py"),
        command_sha256=sha256_value(("python", "run.py")),
        allowlist_id="cpu-research-v1",
        allowlist_sha256=HASH_B,
        dataset_hashes=(HASH_A,),
        case_hashes=(HASH_A,),
        resources=resources,
        max_runtime_seconds=60,
        idempotency_key="job-1-key",
        artifact_prefix="gs://bucket/jobs/job-1",
        budget_usd="0",
        cost_estimate_usd="0",
        cost_estimate_source="local CPU",
        cost_estimated_at=datetime.now(UTC),
        authority=ExecutionAuthority.REPLAY,
        approval_receipt_hash=APPROVAL_HASH,
    )
    assert spec.budget_usd == "0"
    with pytest.raises(ValidationError, match="String should match pattern"):
        JobSpec.model_validate({**spec.model_dump(), "oci_image_digest": "fieldtrue:latest"})
    with pytest.raises(ValidationError, match="provided together"):
        JobResources(cpu=2, memory_gb=4, accelerator_type="NVIDIA_L4", accelerator_count=0)
    with pytest.raises(ValidationError, match="exceeds"):
        JobSpec.model_validate({**spec.model_dump(), "cost_estimate_usd": "1", "budget_usd": "0"})
    with pytest.raises(ValidationError, match="command hash"):
        JobSpec.model_validate({**spec.model_dump(), "command_sha256": HASH_A})
    with pytest.raises(ValidationError, match="timezone-aware"):
        JobSpec.model_validate(
            {
                **spec.model_dump(),
                "cost_estimated_at": datetime.fromisoformat("2026-01-01"),
            }
        )


def test_review_attestations_are_independent_and_bound_to_registered_subjects() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="producer and reviewer"):
        ReviewAttestation(
            attestation_id="review-1",
            kind=ReviewKind.CAUSE,
            producer_id="same",
            reviewer_id="same",
            subject_ids=("mechanism-1",),
            method="fixture",
            scope="fixture",
            evidence_refs=(artifact(),),
            reviewed_at=now,
        )
    review = ReviewAttestation(
        attestation_id="review-1",
        kind=ReviewKind.CAUSE,
        producer_id="producer",
        reviewer_id="reviewer",
        subject_ids=("other-mechanism",),
        method="fixture",
        scope="fixture",
        evidence_refs=(artifact(),),
        reviewed_at=now,
    )
    with pytest.raises(ValidationError, match="unregistered subject"):
        TruthRecord(
            incident_id="incident-1",
            commitment_nonce=HASH_A,
            hardware_family="family",
            hardware_id="hardware",
            fault_family="fault",
            mechanism_ids=("mechanism-1",),
            cause_authority="fixture",
            verification_method="fixture",
            review_attestations=(review,),
        )


def test_selected_observation_recovery_and_verification_invariants() -> None:
    with pytest.raises(ValidationError, match="posterior must sum"):
        SelectedTest(
            incident_id="incident-1",
            test_id="test-1",
            expected_information_gain_bits=1,
            denominator=1,
            utility=1,
            posterior_before={"a": 0.2, "b": 0.2},
            planner_id="planner",
            candidate_sha256=HASH_A,
            safety_envelope_sha256=HASH_B,
        )
    now = datetime.now(UTC)
    observation = {
        "incident_id": "incident-1",
        "test_id": "test-1",
        "outcome_id": "outcome-1",
        "authority": ExecutionAuthority.REPLAY,
        "executor_id": "executor",
        "started_at": now,
        "finished_at": now,
        "observation_artifact": artifact(),
        "safety_envelope_id": "envelope-1",
        "candidate_sha256": HASH_A,
        "safety_envelope_sha256": HASH_B,
    }
    with pytest.raises(ValidationError, match="finish before"):
        DomainTestObservation.model_validate(
            {**observation, "finished_at": datetime(2025, 1, 1, tzinfo=UTC)}
        )
    with pytest.raises(ValidationError, match="testbed recovery"):
        RecoveryPlan(
            recovery_id="recovery-1",
            incident_id="incident-1",
            hypothesis_id="hypothesis-1",
            proposer_id="proposer",
            action="act",
            target="target",
            expected_settled_state={"state": "settled"},
            authority=ExecutionAuthority.TESTBED,
        )
    with pytest.raises(ValidationError, match="abstaining"):
        VerificationResult(
            verification_id="verification-1",
            recovery_id="recovery-1",
            verifier_id="verifier",
            proposer_id="proposer",
            action_valid=True,
            target_valid=True,
            settled_success=True,
            abstained=True,
            outcome_artifacts=(artifact(),),
            scope="fixture",
        )
    with pytest.raises(ValidationError, match="valid action and target"):
        VerificationResult(
            verification_id="verification-2",
            recovery_id="recovery-1",
            verifier_id="verifier",
            proposer_id="proposer",
            action_valid=False,
            target_valid=True,
            settled_success=True,
            abstained=False,
            outcome_artifacts=(artifact(),),
            scope="fixture",
        )
