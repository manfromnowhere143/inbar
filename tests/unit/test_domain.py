from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from fieldtrue.canonical import sha256_value
from fieldtrue.domain import (
    READINESS_AUTHORIZED_NEXT_ACTIONS,
    READINESS_FORBIDDEN_NEXT_ACTIONS,
    CausalHypothesis,
    DiscriminatingTest,
    ExecutionAuthority,
    GateResult,
    GateStatus,
    HypothesisSet,
    JobResources,
    JobSpec,
    ReadinessReport,
    RecoveryPlan,
    ReviewAttestation,
    ReviewKind,
    SafetyEnvelope,
    SelectedTest,
    TruthRecord,
    VerificationResult,
)
from fieldtrue.domain import (
    TestObservation as DomainTestObservation,
)
from fieldtrue.domain import (
    TestOutcomeModel as DomainTestOutcomeModel,
)
from tests.helpers import APPROVAL_HASH, HASH_A, HASH_B, artifact, hypotheses, informative_test


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
