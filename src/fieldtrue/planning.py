"""Safe expected-information-gain test selection."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from datetime import datetime

from fieldtrue.approvals import (
    ApprovalReceipt,
    ApprovalSubjectKind,
    ApprovalVerificationError,
    authorization_subject_hash,
    verify_approval,
)
from fieldtrue.canonical import sha256_value
from fieldtrue.domain import (
    DiscriminatingTest,
    ExecutionAuthority,
    HypothesisSet,
    Identifier,
    PlannerWeights,
    SafetyEnvelope,
    SelectedTest,
)


class NoEligibleTestError(ValueError):
    """No candidate is both approved and inside the safety envelope."""


class NonDiscriminatingTestError(ValueError):
    """Eligible tests exist but none carries positive information."""


def _normalized(distribution: Mapping[str, float]) -> dict[str, float]:
    if not distribution:
        raise ValueError("probability distribution cannot be empty")
    if any(value < 0 or not math.isfinite(value) for value in distribution.values()):
        raise ValueError("probabilities must be finite and non-negative")
    total = sum(distribution.values())
    if total <= 0:
        raise ValueError("probability mass must be positive")
    return {key: value / total for key, value in distribution.items()}


def entropy_bits(distribution: Mapping[str, float]) -> float:
    normalized = _normalized(distribution)
    return -sum(value * math.log2(value) for value in normalized.values() if value > 0)


def expected_information_gain_bits(
    posterior: Mapping[str, float],
    test: DiscriminatingTest,
) -> float:
    prior = _normalized(posterior)
    modeled = set(test.outcome_model[0].probability_by_hypothesis)
    if modeled != set(prior):
        missing = sorted(set(prior) - modeled)
        extra = sorted(modeled - set(prior))
        raise ValueError(f"test/hypothesis mismatch: missing={missing}, extra={extra}")

    expected_posterior_entropy = 0.0
    for outcome in test.outcome_model:
        probability_outcome = sum(
            prior[hypothesis_id] * outcome.probability_by_hypothesis[hypothesis_id]
            for hypothesis_id in prior
        )
        if probability_outcome <= 0:
            continue
        posterior_given_outcome = {
            hypothesis_id: (
                prior[hypothesis_id]
                * outcome.probability_by_hypothesis[hypothesis_id]
                / probability_outcome
            )
            for hypothesis_id in prior
        }
        expected_posterior_entropy += probability_outcome * entropy_bits(posterior_given_outcome)
    information_gain = entropy_bits(prior) - expected_posterior_entropy
    return max(0.0, information_gain)


def posterior_after_observation(
    posterior: Mapping[str, float],
    test: DiscriminatingTest,
    outcome_id: str,
) -> dict[str, float]:
    prior = _normalized(posterior)
    matches = [outcome for outcome in test.outcome_model if outcome.outcome_id == outcome_id]
    if len(matches) != 1:
        raise ValueError(f"unknown or duplicate outcome: {outcome_id}")
    likelihood = matches[0].probability_by_hypothesis
    if set(likelihood) != set(prior):
        raise ValueError("test does not model the current hypothesis set")
    unnormalized = {
        hypothesis_id: prior[hypothesis_id] * likelihood[hypothesis_id] for hypothesis_id in prior
    }
    return _normalized(unnormalized)


def _eligible(
    test: DiscriminatingTest,
    envelope: SafetyEnvelope,
    *,
    approval_receipt: ApprovalReceipt | None,
    expected_approval_signer: str | None,
    approval_time: datetime | None,
) -> bool:
    ordinary_checks = (
        test.approved
        and test.authority == envelope.authority
        and test.test_id in envelope.allowed_test_ids
        and test.risk <= envelope.max_risk
        and set(test.preconditions).issubset(envelope.satisfied_preconditions)
        and (
            envelope.approval_receipt_hash is None
            or test.approval_receipt_hash == envelope.approval_receipt_hash
        )
    )
    if not ordinary_checks:
        return False
    if test.authority != ExecutionAuthority.TESTBED:
        return True
    if approval_receipt is None or expected_approval_signer is None:
        return False
    subject_hash = authorization_subject_hash(
        ApprovalSubjectKind.TEST_EXECUTION,
        {
            "candidate": test.model_dump(mode="json", exclude={"approval_receipt_hash"}),
            "safety_envelope": envelope.model_dump(mode="json", exclude={"approval_receipt_hash"}),
        },
    )
    try:
        verified = verify_approval(
            approval_receipt,
            expected_signer_public_key=expected_approval_signer,
            expected_subject_kind=ApprovalSubjectKind.TEST_EXECUTION,
            expected_subject_sha256=subject_hash,
            expected_authority=ExecutionAuthority.TESTBED,
            required_risk=test.risk,
            at=approval_time,
        )
    except ApprovalVerificationError:
        return False
    return (
        test.approval_receipt_hash == verified.receipt_hash
        and envelope.approval_receipt_hash == verified.receipt_hash
    )


def select_discriminating_test(
    hypotheses: HypothesisSet,
    candidates: Sequence[DiscriminatingTest],
    envelope: SafetyEnvelope,
    *,
    planner_id: Identifier = "expected-information-gain-v1",
    weights: PlannerWeights | None = None,
    approval_receipt: ApprovalReceipt | None = None,
    expected_approval_signer: str | None = None,
    approval_time: datetime | None = None,
) -> SelectedTest:
    planner_weights = weights or PlannerWeights()
    posterior = {item.hypothesis_id: item.prior for item in hypotheses.hypotheses}
    scored: list[tuple[float, float, float, str, DiscriminatingTest, float, float]] = []
    for candidate in candidates:
        if not _eligible(
            candidate,
            envelope,
            approval_receipt=approval_receipt,
            expected_approval_signer=expected_approval_signer,
            approval_time=approval_time,
        ):
            continue
        gain = expected_information_gain_bits(posterior, candidate)
        denominator = max(
            candidate.cost_units
            + planner_weights.time_weight * candidate.duration_seconds
            + planner_weights.risk_weight * candidate.risk,
            planner_weights.denominator_floor,
        )
        utility = gain / denominator
        scored.append(
            (
                -utility,
                candidate.cost_units,
                candidate.risk,
                candidate.test_id,
                candidate,
                gain,
                denominator,
            )
        )
    if not scored:
        raise NoEligibleTestError("no candidate passed approval and safety checks")
    scored.sort(key=lambda item: item[:4])
    _, _, _, _, selected, gain, denominator = scored[0]
    if gain <= 0:
        raise NonDiscriminatingTestError("eligible tests have zero expected information gain")
    return SelectedTest(
        incident_id=hypotheses.incident_id,
        test_id=selected.test_id,
        expected_information_gain_bits=gain,
        denominator=denominator,
        utility=gain / denominator,
        posterior_before=posterior,
        planner_id=planner_id,
        candidate_sha256=sha256_value(selected),
        safety_envelope_sha256=sha256_value(envelope),
    )
