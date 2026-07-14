"""Deterministic local execution and independent-oracle fixtures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fieldtrue.canonical import atomic_write, canonical_json, sha256_file, sha256_value
from fieldtrue.domain import (
    ArtifactRef,
    DiscriminatingTest,
    ExecutionAuthority,
    RecoveryPlan,
    SafetyEnvelope,
    SelectedTest,
    TestObservation,
    VerificationResult,
)


class DeterministicReplayExecutor:
    """Plumbing oracle; never evidence for a real-world performance claim."""

    def __init__(
        self,
        outcomes: dict[str, str],
        artifact_root: Path,
        *,
        executor_id: str = "deterministic-replay-executor-v1",
    ) -> None:
        self._outcomes = dict(outcomes)
        self._artifact_root = artifact_root
        self._executor_id = executor_id

    @property
    def executor_id(self) -> str:
        return self._executor_id

    def preview(
        self,
        selected: SelectedTest,
        candidate: DiscriminatingTest,
        envelope: SafetyEnvelope,
    ) -> dict[str, object]:
        self._assert_authorized(selected, candidate, envelope)
        return {
            "would_execute": True,
            "authority": ExecutionAuthority.REPLAY.value,
            "test_id": candidate.test_id,
            "mutated_external_state": False,
        }

    def execute(
        self,
        selected: SelectedTest,
        candidate: DiscriminatingTest,
        envelope: SafetyEnvelope,
    ) -> TestObservation:
        self._assert_authorized(selected, candidate, envelope)
        try:
            outcome = self._outcomes[candidate.test_id]
        except KeyError as error:
            raise ValueError(f"no replay outcome for {candidate.test_id}") from error
        if outcome not in {item.outcome_id for item in candidate.outcome_model}:
            raise ValueError("fixture outcome is outside the registered outcome model")
        started = datetime(2026, 1, 1, tzinfo=UTC)
        payload = {
            "incident_id": selected.incident_id,
            "test_id": selected.test_id,
            "outcome_id": outcome,
            "fixture_only": True,
        }
        artifact_path = self._artifact_root / f"{selected.incident_id}-{selected.test_id}.json"
        atomic_write(artifact_path, canonical_json(payload) + b"\n")
        artifact = ArtifactRef(
            artifact_id=f"{selected.incident_id}-{selected.test_id}-observation",
            uri=artifact_path.as_posix(),
            sha256=sha256_file(artifact_path),
            bytes=artifact_path.stat().st_size,
            media_type="application/json",
            source_authority=self.executor_id,
            clock_domain="deterministic-fixture-clock",
            license_ref="internal-fixture",
        )
        return TestObservation(
            incident_id=selected.incident_id,
            test_id=selected.test_id,
            outcome_id=outcome,
            authority=ExecutionAuthority.REPLAY,
            executor_id=self.executor_id,
            started_at=started,
            finished_at=started + timedelta(seconds=candidate.duration_seconds),
            observation_artifact=artifact,
            safety_envelope_id=envelope.envelope_id,
            candidate_sha256=selected.candidate_sha256,
            safety_envelope_sha256=selected.safety_envelope_sha256,
            approval_receipt_hash=candidate.approval_receipt_hash,
        )

    @staticmethod
    def _assert_authorized(
        selected: SelectedTest,
        candidate: DiscriminatingTest,
        envelope: SafetyEnvelope,
    ) -> None:
        if selected.test_id != candidate.test_id:
            raise PermissionError("selected and candidate test IDs differ")
        if selected.candidate_sha256 != sha256_value(candidate):
            raise PermissionError("selected test is not bound to this candidate")
        if selected.safety_envelope_sha256 != sha256_value(envelope):
            raise PermissionError("selected test is not bound to this safety envelope")
        if candidate.authority != ExecutionAuthority.REPLAY:
            raise PermissionError("local replay executor has replay authority only")
        if envelope.authority != ExecutionAuthority.REPLAY:
            raise PermissionError("safety envelope does not authorize replay")
        if not candidate.approved or candidate.test_id not in envelope.allowed_test_ids:
            raise PermissionError("test is not approved by the safety envelope")
        if candidate.risk > envelope.max_risk:
            raise PermissionError("test exceeds the safety envelope risk limit")
        if not set(candidate.preconditions).issubset(envelope.satisfied_preconditions):
            raise PermissionError("test preconditions are not satisfied")
        if (
            envelope.approval_receipt_hash is not None
            and candidate.approval_receipt_hash != envelope.approval_receipt_hash
        ):
            raise PermissionError("test and safety envelope approvals differ")


class IndependentReplayVerifier:
    def __init__(
        self,
        settled_outcomes: dict[str, tuple[bool, bool, bool]],
        artifact_root: Path,
        *,
        verifier_id: str = "independent-fixture-oracle-v1",
    ) -> None:
        self._settled_outcomes = dict(settled_outcomes)
        self._artifact_root = artifact_root
        self._verifier_id = verifier_id

    @property
    def verifier_id(self) -> str:
        return self._verifier_id

    def verify(self, plan: RecoveryPlan) -> VerificationResult:
        try:
            action_valid, target_valid, settled_success = self._settled_outcomes[plan.recovery_id]
        except KeyError as error:
            raise ValueError(f"no independent outcome for {plan.recovery_id}") from error
        payload = {
            "recovery_id": plan.recovery_id,
            "action_valid": action_valid,
            "target_valid": target_valid,
            "settled_success": settled_success,
            "fixture_only": True,
        }
        artifact_path = self._artifact_root / f"{plan.recovery_id}-verification.json"
        atomic_write(artifact_path, canonical_json(payload) + b"\n")
        artifact = ArtifactRef(
            artifact_id=f"{plan.recovery_id}-verification-artifact",
            uri=artifact_path.as_posix(),
            sha256=sha256_file(artifact_path),
            bytes=artifact_path.stat().st_size,
            media_type="application/json",
            source_authority=self.verifier_id,
            clock_domain="deterministic-fixture-clock",
            license_ref="internal-fixture",
        )
        return VerificationResult(
            verification_id=f"{plan.recovery_id}-verification",
            recovery_id=plan.recovery_id,
            verifier_id=self.verifier_id,
            proposer_id=plan.proposer_id,
            action_valid=action_valid,
            target_valid=target_valid,
            settled_success=settled_success,
            abstained=False,
            outcome_artifacts=(artifact,),
            scope="deterministic plumbing fixture only",
        )
