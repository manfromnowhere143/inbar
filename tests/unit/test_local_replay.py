from __future__ import annotations

from pathlib import Path

import pytest

from fieldtrue.adapters.local_replay import (
    DeterministicReplayExecutor,
    IndependentReplayVerifier,
)
from fieldtrue.canonical import sha256_value
from fieldtrue.domain import ExecutionAuthority, RecoveryPlan
from fieldtrue.planning import posterior_after_observation, select_discriminating_test
from tests.helpers import envelope, hypotheses, informative_test


def test_deterministic_replay_exercises_the_full_plumbing_loop(tmp_path: Path) -> None:
    candidate = informative_test()
    safety = envelope(candidate.test_id)
    selected = select_discriminating_test(hypotheses(), (candidate,), safety)
    executor = DeterministicReplayExecutor(
        {candidate.test_id: "voltage-recovers"},
        tmp_path / "observations",
    )
    assert executor.preview(selected, candidate, safety)["mutated_external_state"] is False
    observation = executor.execute(selected, candidate, safety)
    assert observation.candidate_sha256 == selected.candidate_sha256
    posterior = posterior_after_observation(
        selected.posterior_before,
        candidate,
        observation.outcome_id,
    )
    assert posterior["power-open"] > selected.posterior_before["power-open"]

    plan = RecoveryPlan(
        recovery_id="recovery-1",
        incident_id=selected.incident_id,
        hypothesis_id="power-open",
        proposer_id="recovery-proposer",
        action="isolate failed relay",
        target="relay R1",
        expected_settled_state={"bus_voltage": "nominal"},
        authority=ExecutionAuthority.REPLAY,
    )
    verifier = IndependentReplayVerifier(
        {plan.recovery_id: (True, True, True)},
        tmp_path / "verification",
    )
    result = verifier.verify(plan)
    assert result.settled_success
    assert result.verifier_id != result.proposer_id


def test_replay_rejects_post_selection_candidate_or_envelope_substitution(
    tmp_path: Path,
) -> None:
    candidate = informative_test()
    safety = envelope(candidate.test_id)
    selected = select_discriminating_test(hypotheses(), (candidate,), safety)
    executor = DeterministicReplayExecutor(
        {candidate.test_id: "voltage-recovers"},
        tmp_path,
    )
    substituted = candidate.model_copy(update={"preconditions": ("unverified-condition",)})
    with pytest.raises(PermissionError, match="bound to this candidate"):
        executor.execute(selected, substituted, safety)
    changed_envelope = safety.model_copy(update={"max_risk": 0.15})
    with pytest.raises(PermissionError, match="bound to this safety envelope"):
        executor.execute(selected, candidate, changed_envelope)


def test_replay_rejects_missing_or_unregistered_fixture_outcomes(tmp_path: Path) -> None:
    candidate = informative_test()
    safety = envelope(candidate.test_id)
    selected = select_discriminating_test(hypotheses(), (candidate,), safety)
    with pytest.raises(ValueError, match="no replay outcome"):
        DeterministicReplayExecutor({}, tmp_path).execute(selected, candidate, safety)
    with pytest.raises(ValueError, match="outside"):
        DeterministicReplayExecutor({candidate.test_id: "invented"}, tmp_path).execute(
            selected, candidate, safety
        )


def test_independent_verifier_requires_a_registered_oracle_outcome(tmp_path: Path) -> None:
    plan = RecoveryPlan(
        recovery_id="missing-recovery",
        incident_id="incident-1",
        hypothesis_id="unknown",
        proposer_id="proposer",
        action="abstain",
        target="none",
        expected_settled_state={"state": "unchanged"},
        authority=ExecutionAuthority.REPLAY,
    )
    with pytest.raises(ValueError, match="no independent outcome"):
        IndependentReplayVerifier({}, tmp_path).verify(plan)


def test_replay_rechecks_every_authority_condition_at_execution(tmp_path: Path) -> None:
    candidate = informative_test()
    safety = envelope(candidate.test_id)
    selected = select_discriminating_test(hypotheses(), (candidate,), safety)
    executor = DeterministicReplayExecutor({candidate.test_id: "voltage-recovers"}, tmp_path)

    wrong_id = selected.model_copy(update={"test_id": "other-test"})
    with pytest.raises(PermissionError, match="IDs differ"):
        executor.execute(wrong_id, candidate, safety)

    unapproved = candidate.model_copy(update={"approved": False})
    bound = selected.model_copy(update={"candidate_sha256": sha256_value(unapproved)})
    with pytest.raises(PermissionError, match="not approved"):
        executor.execute(bound, unapproved, safety)

    risky = candidate.model_copy(update={"risk": 0.9})
    bound = selected.model_copy(update={"candidate_sha256": sha256_value(risky)})
    with pytest.raises(PermissionError, match="risk limit"):
        executor.execute(bound, risky, safety)

    unsatisfied = candidate.model_copy(update={"preconditions": ("not-satisfied",)})
    bound = selected.model_copy(update={"candidate_sha256": sha256_value(unsatisfied)})
    with pytest.raises(PermissionError, match="preconditions"):
        executor.execute(bound, unsatisfied, safety)

    approved_candidate = candidate.model_copy(update={"approval_receipt_hash": "a" * 64})
    approved_envelope = safety.model_copy(update={"approval_receipt_hash": "b" * 64})
    bound = selected.model_copy(
        update={
            "candidate_sha256": sha256_value(approved_candidate),
            "safety_envelope_sha256": sha256_value(approved_envelope),
        }
    )
    with pytest.raises(PermissionError, match="approvals differ"):
        executor.execute(bound, approved_candidate, approved_envelope)
