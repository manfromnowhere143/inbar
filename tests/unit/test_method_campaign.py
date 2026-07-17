"""Adversarial controls for the diagnosis-method port and the paired campaign.

The campaign's value is that injected ground truth lets a method be scored against truth it never
saw. That value is destroyed if the observation could carry the injected mechanism to the method,
if a method could name a key it was not offered, if a campaign could run without a signed compute
lease, if the reported aggregates were asserted rather than recomputed from the atomic records, or
if the paired design failed to attribute a passive/active difference to the discriminating test.
Each control below pins one of those failures shut.

The result itself is a scientific claim about the reference simulator only. These controls verify
its internal validity; they assert nothing about the physical world, and a simulator branch never
counts as a physical incident.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest
from nacl.signing import SigningKey
from pydantic import ValidationError

from fieldtrue.causal_laboratory import (
    REFERENCE_ONTOLOGY,
    UNKNOWN_MECHANISM_KEY,
    BranchKind,
    CausalLaboratoryError,
    issue_lab_compute_lease,
    reference_forward_telemetry,
)
from fieldtrue.method_campaign import (
    _BASELINE_COMMIT_TIME,
    ACTIVE_PERMITTED,
    AMENDMENT_DOCUMENT_SHA256,
    APPROVED_PROPOSAL_COMMIT,
    MACHINE_PROPOSAL_SHA256,
    OWNER_APPROVAL_RECEIPT_HASH,
    PASSIVE_PERMITTED,
    REFERENCE_BASELINE_CONFIG,
    REFERENCE_BASELINE_INITIAL_STATE,
    CampaignPlan,
    CampaignResult,
    ConditionOutcome,
    ConditionSummary,
    DiagnosisMethod,
    EpisodeOutcome,
    MethodBranchObservation,
    MethodCampaignError,
    MethodDiagnosis,
    MethodObservation,
    PlannedEpisode,
    ReferenceLikelihoodDiagnoser,
    _clamped,
    _mechanism_identifiable,
    recompute_campaign_result,
    run_campaign,
)

KEY = SigningKey(hashlib.sha256(b"inbar-test-method-campaign-signer").digest())
KEY_PUB = KEY.verify_key.encode().hex()
OTHER_KEY = SigningKey(hashlib.sha256(b"inbar-test-not-the-owner").digest())
ONTO = REFERENCE_ONTOLOGY
OH = ONTO.ontology_hash
BY_NAME = {c.name: c.key for c in ONTO.classes}
SORTED_KEYS = tuple(sorted(ONTO.known_keys))
NOW = datetime(2026, 7, 17, 12, 0, 0, tzinfo=UTC)
INJECTIONS = ("actuator_loss", "sensor_bias", "gain_drift", UNKNOWN_MECHANISM_KEY)


def _lease(
    *,
    ontology_hash: str = OH,
    not_before: datetime = NOW - timedelta(minutes=1),
    expires_at: datetime = NOW + timedelta(hours=1),
    signing_key: SigningKey = KEY,
):
    return issue_lab_compute_lease(
        signing_key,
        lease_id="lease-005-test",
        session_id="sess-005",
        ontology_hash=ontology_hash,
        not_before=not_before,
        expires_at=expires_at,
        nonce="a" * 64,
    )


def _balanced_plan(reps: int = 6) -> CampaignPlan:
    episodes = []
    index = 0
    for _ in range(reps):
        for name in INJECTIONS:
            index += 1
            episodes.append(
                PlannedEpisode(
                    episode_id=f"ep-{index:03d}",
                    injected_name=name,
                    snapshot_seed=1000 + index,
                    salt_hex=hashlib.sha256(f"salt-{index}".encode()).hexdigest(),
                )
            )
    return CampaignPlan(plan_id="plan-005-balanced", ontology_hash=OH, episodes=tuple(episodes))


def _run(plan: CampaignPlan, method: DiagnosisMethod, **kwargs):
    return run_campaign(
        plan=plan,
        method=method,
        ontology=ONTO,
        lease=_lease(),
        result_id="result-005",
        produced_at=NOW,
        expected_public_key=KEY_PUB,
        at=NOW,
        **kwargs,
    )


# --- The scientific result --------------------------------------------------------------


def test_the_targeted_test_strictly_improves_diagnosis_over_passive_observation() -> None:
    result, _ = _run(_balanced_plan(), ReferenceLikelihoodDiagnoser(ONTO))
    assert Decimal(result.active.diagnosis_accuracy) > Decimal(result.passive.diagnosis_accuracy)
    assert Decimal(result.paired_active_minus_passive_accuracy) > 0
    # The 95% episode-clustered interval excludes zero: the lift is not attributable to luck.
    assert Decimal(result.paired_interval_low) > 0
    assert result.active_strictly_helps is True


def test_the_lift_is_exactly_the_fault_that_is_invisible_at_rest() -> None:
    _, outcomes = _run(_balanced_plan(), ReferenceLikelihoodDiagnoser(ONTO))
    name_of = {c.key: c.name for c in ONTO.classes}
    for outcome in outcomes:
        name = name_of.get(outcome.injected_key, UNKNOWN_MECHANISM_KEY)
        if name == "actuator_loss":
            # Invisible under a no-op: the honest passive answer is to abstain, not guess.
            assert outcome.passive.abstained is True
            assert outcome.passive.diagnosis_correct is False
            assert outcome.active.diagnosis_correct is True
        elif name in {"sensor_bias", "gain_drift"}:
            # Visible even at rest: correct under both conditions, no probe needed.
            assert outcome.passive.diagnosis_correct is True
            assert outcome.active.diagnosis_correct is True
        else:
            # Genuinely unmodeled: passive abstains to unknown (correct), active commits unknown.
            assert outcome.injected_key == UNKNOWN_MECHANISM_KEY
            assert outcome.passive.diagnosis_correct is True
            assert outcome.active.diagnosis_correct is True


def test_the_baseline_is_calibrated_and_abstains_only_when_genuinely_ambiguous() -> None:
    result, _ = _run(_balanced_plan(), ReferenceLikelihoodDiagnoser(ONTO))
    # When it commits, it is right, and every passive abstention was on an unidentifiable case.
    assert result.passive.committed_accuracy == "1.000000"
    assert result.active.committed_accuracy == "1.000000"
    assert result.passive.abstention_correct_rate == "1.000000"
    # Unknown injections are handled correctly under both conditions.
    assert result.passive.unknown_injection_accuracy == "1.000000"
    assert result.active.unknown_injection_accuracy == "1.000000"


def test_the_result_is_recomputed_from_the_atomic_records() -> None:
    plan = _balanced_plan()
    method = ReferenceLikelihoodDiagnoser(ONTO)
    result, outcomes = _run(plan, method)
    recomputed = recompute_campaign_result(
        result_id="result-005",
        outcomes=outcomes,
        method_id=method.method_id,
        ontology=ONTO,
        plan=plan,
        lease=_lease(),
        produced_at=NOW,
    )
    assert recomputed == result


def test_the_campaign_is_deterministic() -> None:
    plan = _balanced_plan()
    first, _ = _run(plan, ReferenceLikelihoodDiagnoser(ONTO))
    second, _ = _run(plan, ReferenceLikelihoodDiagnoser(ONTO))
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_the_result_binds_every_authority() -> None:
    result, _ = _run(_balanced_plan(), ReferenceLikelihoodDiagnoser(ONTO))
    assert result.amendment_document_artifact_sha256 == AMENDMENT_DOCUMENT_SHA256
    assert result.machine_proposal_artifact_sha256 == MACHINE_PROPOSAL_SHA256
    assert result.owner_approval_receipt_hash == OWNER_APPROVAL_RECEIPT_HASH
    assert result.proposal_git_commit == APPROVED_PROPOSAL_COMMIT
    assert result.plan_hash == _balanced_plan().plan_hash
    assert result.compute_lease_hash == _lease().lease_hash


# --- Blindness: the observation cannot carry the injected truth -------------------------


def test_the_observation_type_cannot_transport_the_injected_truth() -> None:
    fields = set(MethodObservation.model_fields) | set(MethodBranchObservation.model_fields)
    for forbidden in ("injected_key", "sealed_mechanism", "commitment", "salt", "salt_hex"):
        assert forbidden not in fields


def test_passive_sees_only_the_no_op_and_active_adds_the_targeted_test() -> None:
    seen: list[tuple[BranchKind, ...]] = []

    class Recorder:
        method_id = "recorder"

        def diagnose(self, observation: MethodObservation) -> MethodDiagnosis:
            seen.append(tuple(b.kind for b in observation.branches))
            return MethodDiagnosis(
                method_id=self.method_id,
                known_keys=SORTED_KEYS,
                diagnosis_key=UNKNOWN_MECHANISM_KEY,
                confidence="0.500000",
                abstained=True,
                committed_at=_BASELINE_COMMIT_TIME,
            )

    plan = CampaignPlan(
        plan_id="plan-one",
        ontology_hash=OH,
        episodes=(
            PlannedEpisode(
                episode_id="ep-1", injected_name="sensor_bias", snapshot_seed=3, salt_hex="b" * 64
            ),
        ),
    )
    _run(plan, Recorder())
    assert seen[0] == PASSIVE_PERMITTED
    assert seen[1] == ACTIVE_PERMITTED
    assert BranchKind.BLOCKED_UNSAFE not in seen[0]
    assert BranchKind.BLOCKED_UNSAFE not in seen[1]


# --- A method that names a key it was not offered is rejected, its episode discarded ----


def test_a_method_that_diagnoses_a_fabricated_key_is_rejected() -> None:
    fabricated = "f" * 64

    class Cheater:
        method_id = "cheater"

        def diagnose(self, observation: MethodObservation) -> MethodDiagnosis:
            return MethodDiagnosis(
                method_id=self.method_id,
                known_keys=(fabricated, *SORTED_KEYS),
                diagnosis_key=fabricated,
                confidence="1.000000",
                abstained=False,
                committed_at=_BASELINE_COMMIT_TIME,
            )

    plan = CampaignPlan(
        plan_id="plan-cheat",
        ontology_hash=OH,
        episodes=(
            PlannedEpisode(
                episode_id="ep-1", injected_name="gain_drift", snapshot_seed=5, salt_hex="c" * 64
            ),
        ),
    )
    with pytest.raises(MethodCampaignError, match="outside the permitted candidate set"):
        _run(plan, Cheater())


# --- Lease gating: no lease, no run -----------------------------------------------------


def test_an_expired_lease_fails_closed() -> None:
    with pytest.raises(CausalLaboratoryError):
        run_campaign(
            plan=_balanced_plan(),
            method=ReferenceLikelihoodDiagnoser(ONTO),
            ontology=ONTO,
            lease=_lease(
                expires_at=NOW - timedelta(minutes=1), not_before=NOW - timedelta(hours=2)
            ),
            result_id="result-005",
            produced_at=NOW,
            expected_public_key=KEY_PUB,
            at=NOW,
        )


def test_a_lease_signed_by_a_non_owner_fails_closed() -> None:
    with pytest.raises(CausalLaboratoryError):
        run_campaign(
            plan=_balanced_plan(),
            method=ReferenceLikelihoodDiagnoser(ONTO),
            ontology=ONTO,
            lease=_lease(signing_key=OTHER_KEY),
            result_id="result-005",
            produced_at=NOW,
            expected_public_key=KEY_PUB,
            at=NOW,
        )


def test_a_lease_binding_the_wrong_ontology_fails_closed() -> None:
    with pytest.raises(CausalLaboratoryError):
        run_campaign(
            plan=_balanced_plan(),
            method=ReferenceLikelihoodDiagnoser(ONTO),
            ontology=ONTO,
            lease=_lease(ontology_hash="0" * 64),
            result_id="result-005",
            produced_at=NOW,
            expected_public_key=KEY_PUB,
            at=NOW,
        )


# --- Plan / time binding ----------------------------------------------------------------


def test_a_plan_binding_a_different_ontology_is_rejected() -> None:
    plan = CampaignPlan(
        plan_id="plan-wrong",
        ontology_hash="0" * 64,
        episodes=(
            PlannedEpisode(
                episode_id="ep-1", injected_name="sensor_bias", snapshot_seed=1, salt_hex="a" * 64
            ),
        ),
    )
    with pytest.raises(MethodCampaignError, match="does not bind the method ontology"):
        _run(plan, ReferenceLikelihoodDiagnoser(ONTO))


def test_a_plan_naming_an_unknown_mechanism_is_rejected() -> None:
    plan = CampaignPlan(
        plan_id="plan-badname",
        ontology_hash=OH,
        episodes=(
            PlannedEpisode(
                episode_id="ep-1",
                injected_name="not_a_mechanism",
                snapshot_seed=1,
                salt_hex="a" * 64,
            ),
        ),
    )
    with pytest.raises(MethodCampaignError, match="names an unknown mechanism"):
        _run(plan, ReferenceLikelihoodDiagnoser(ONTO))


def test_a_naive_production_time_is_rejected() -> None:
    with pytest.raises(MethodCampaignError, match="timezone-aware"):
        run_campaign(
            plan=_balanced_plan(),
            method=ReferenceLikelihoodDiagnoser(ONTO),
            ontology=ONTO,
            lease=_lease(),
            result_id="result-005",
            produced_at=datetime(2026, 7, 17, 12, 0, 0),  # noqa: DTZ001
            expected_public_key=KEY_PUB,
            at=NOW,
        )


def test_a_production_time_before_the_frozen_commitment_is_rejected() -> None:
    with pytest.raises(MethodCampaignError, match="precedes the frozen method commitment"):
        run_campaign(
            plan=_balanced_plan(),
            method=ReferenceLikelihoodDiagnoser(ONTO),
            ontology=ONTO,
            lease=_lease(),
            result_id="result-005",
            produced_at=_BASELINE_COMMIT_TIME - timedelta(seconds=1),
            expected_public_key=KEY_PUB,
            at=NOW,
        )


# --- Forward model and identifiability structure ----------------------------------------


def test_actuator_loss_is_invisible_at_rest_and_visible_under_a_probe() -> None:
    # Under the no-op action, actuator_loss and the nominal/unknown model predict the same
    # telemetry; under the probe they diverge. This is the identifiability the campaign exploits.
    no_op = (0,) * REFERENCE_BASELINE_CONFIG.steps
    probe = (100,) * REFERENCE_BASELINE_CONFIG.steps
    args = {
        "config": REFERENCE_BASELINE_CONFIG,
        "initial_state": REFERENCE_BASELINE_INITIAL_STATE,
    }
    actuator_at_rest = reference_forward_telemetry(
        mechanism_key=BY_NAME["actuator_loss"], action=no_op, **args
    )
    unknown_at_rest = reference_forward_telemetry(
        mechanism_key=UNKNOWN_MECHANISM_KEY, action=no_op, **args
    )
    assert actuator_at_rest == unknown_at_rest
    actuator_under_probe = reference_forward_telemetry(
        mechanism_key=BY_NAME["actuator_loss"], action=probe, **args
    )
    unknown_under_probe = reference_forward_telemetry(
        mechanism_key=UNKNOWN_MECHANISM_KEY, action=probe, **args
    )
    assert actuator_under_probe != unknown_under_probe


def test_identifiability_matches_the_paired_design() -> None:
    assert _mechanism_identifiable(BY_NAME["actuator_loss"], PASSIVE_PERMITTED, ONTO) is False
    assert _mechanism_identifiable(BY_NAME["actuator_loss"], ACTIVE_PERMITTED, ONTO) is True
    assert _mechanism_identifiable(UNKNOWN_MECHANISM_KEY, PASSIVE_PERMITTED, ONTO) is False
    assert _mechanism_identifiable(UNKNOWN_MECHANISM_KEY, ACTIVE_PERMITTED, ONTO) is True
    assert _mechanism_identifiable(BY_NAME["sensor_bias"], PASSIVE_PERMITTED, ONTO) is True
    assert _mechanism_identifiable(BY_NAME["gain_drift"], PASSIVE_PERMITTED, ONTO) is True


# --- Port and diagnosis contracts -------------------------------------------------------


def test_the_reference_baseline_satisfies_the_port() -> None:
    assert isinstance(ReferenceLikelihoodDiagnoser(ONTO), DiagnosisMethod)


def test_a_confident_unknown_diagnosis_is_not_an_abstention() -> None:
    diagnosis = MethodDiagnosis(
        method_id="m",
        known_keys=SORTED_KEYS,
        diagnosis_key=UNKNOWN_MECHANISM_KEY,
        confidence="0.990000",
        abstained=False,
        committed_at=_BASELINE_COMMIT_TIME,
    )
    assert diagnosis.diagnosis_key == UNKNOWN_MECHANISM_KEY
    assert diagnosis.abstained is False


def test_an_abstention_must_emit_the_reserved_unknown() -> None:
    with pytest.raises(ValidationError, match="must emit the reserved unknown"):
        MethodDiagnosis(
            method_id="m",
            known_keys=SORTED_KEYS,
            diagnosis_key=SORTED_KEYS[0],
            confidence="0.500000",
            abstained=True,
            committed_at=_BASELINE_COMMIT_TIME,
        )


def test_a_diagnosis_outside_the_carried_hypotheses_is_rejected() -> None:
    with pytest.raises(ValidationError, match="did not carry"):
        MethodDiagnosis(
            method_id="m",
            known_keys=SORTED_KEYS,
            diagnosis_key="e" * 64,
            confidence="1.000000",
            abstained=False,
            committed_at=_BASELINE_COMMIT_TIME,
        )


def test_a_blocked_unsafe_branch_is_never_a_permitted_observation() -> None:
    with pytest.raises(ValidationError, match="never a permitted observation"):
        MethodObservation(
            ontology_hash=OH,
            candidate_known_keys=SORTED_KEYS,
            branches=(
                MethodBranchObservation(kind=BranchKind.BLOCKED_UNSAFE, action=(0,), telemetry=()),
            ),
        )


def test_an_observation_may_not_repeat_a_branch_kind() -> None:
    branch = MethodBranchObservation(kind=BranchKind.NO_OP, action=(0,), telemetry=(1,))
    with pytest.raises(ValidationError, match="repeat a branch kind"):
        MethodObservation(
            ontology_hash=OH, candidate_known_keys=SORTED_KEYS, branches=(branch, branch)
        )


def test_the_diagnoser_rejects_a_mismatched_ontology() -> None:
    other = ReferenceLikelihoodDiagnoser(ONTO)
    observation = MethodObservation(
        ontology_hash="0" * 64,
        candidate_known_keys=SORTED_KEYS,
        branches=(MethodBranchObservation(kind=BranchKind.NO_OP, action=(0,), telemetry=(1,)),),
    )
    with pytest.raises(MethodCampaignError, match="observation ontology"):
        other.diagnose(observation)


# --- Aggregation helpers ----------------------------------------------------------------


def test_a_result_that_misbinds_the_amendment_document_is_rejected() -> None:
    result, _ = _run(_balanced_plan(), ReferenceLikelihoodDiagnoser(ONTO))
    payload = result.model_dump(mode="json")
    payload["amendment_document_artifact_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="approved amendment document"):
        CampaignResult.model_validate(payload)


def test_recompute_rejects_an_empty_outcome_set() -> None:
    with pytest.raises(MethodCampaignError, match="at least one episode outcome"):
        recompute_campaign_result(
            result_id="r",
            outcomes=(),
            method_id="m",
            ontology=ONTO,
            plan=_balanced_plan(),
            lease=_lease(),
            produced_at=NOW,
        )


def test_clamp_holds_metrics_within_range() -> None:
    assert _clamped(Decimal("1.5")) == Decimal(1)
    assert _clamped(Decimal("-1.5")) == Decimal(-1)
    assert _clamped(Decimal("0.25")) == Decimal("0.25")


def test_a_single_episode_campaign_has_a_degenerate_interval() -> None:
    plan = CampaignPlan(
        plan_id="plan-single",
        ontology_hash=OH,
        episodes=(
            PlannedEpisode(
                episode_id="ep-1", injected_name="actuator_loss", snapshot_seed=9, salt_hex="d" * 64
            ),
        ),
    )
    result, _ = _run(plan, ReferenceLikelihoodDiagnoser(ONTO))
    # One actuator_loss episode: passive abstains (wrong), active correct -> paired diff exactly 1,
    # and with a single cluster the interval collapses to the point estimate.
    assert result.paired_active_minus_passive_accuracy == "1.000000"
    assert result.paired_interval_low == "1.000000"
    assert result.paired_interval_high == "1.000000"


def test_an_observation_rejects_duplicate_candidate_keys() -> None:
    with pytest.raises(ValidationError, match="candidate known keys must be unique"):
        MethodObservation(
            ontology_hash=OH,
            candidate_known_keys=(SORTED_KEYS[0], SORTED_KEYS[0]),
            branches=(MethodBranchObservation(kind=BranchKind.NO_OP, action=(0,), telemetry=(1,)),),
        )


def test_a_diagnosis_rejects_duplicate_known_keys() -> None:
    with pytest.raises(ValidationError, match="method known keys must be unique"):
        MethodDiagnosis(
            method_id="m",
            known_keys=(SORTED_KEYS[0], SORTED_KEYS[0]),
            diagnosis_key=UNKNOWN_MECHANISM_KEY,
            confidence="0.500000",
            abstained=True,
            committed_at=_BASELINE_COMMIT_TIME,
        )


def test_a_diagnosis_rejects_a_naive_commitment_time() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        MethodDiagnosis(
            method_id="m",
            known_keys=SORTED_KEYS,
            diagnosis_key=UNKNOWN_MECHANISM_KEY,
            confidence="0.500000",
            abstained=True,
            committed_at=datetime(2026, 7, 17, 0, 0, 0),  # noqa: DTZ001
        )


def test_the_diagnoser_rejects_observation_candidate_keys_that_differ_from_the_ontology() -> None:
    diagnoser = ReferenceLikelihoodDiagnoser(ONTO)
    observation = MethodObservation(
        ontology_hash=OH,
        candidate_known_keys=(SORTED_KEYS[0], "a" * 64),
        branches=(MethodBranchObservation(kind=BranchKind.NO_OP, action=(0,), telemetry=(1,)),),
    )
    with pytest.raises(MethodCampaignError, match="candidate keys differ from the ontology"):
        diagnoser.diagnose(observation)


def test_a_plan_rejects_duplicate_episode_ids() -> None:
    episode = PlannedEpisode(
        episode_id="ep-dup", injected_name="sensor_bias", snapshot_seed=1, salt_hex="a" * 64
    )
    with pytest.raises(ValidationError, match="episode ids must be unique"):
        CampaignPlan(plan_id="p", ontology_hash=OH, episodes=(episode, episode))


def _condition_outcome(condition: str, episode_id: str, injected_key: str) -> ConditionOutcome:
    return ConditionOutcome(
        episode_id=episode_id,
        condition=condition,  # type: ignore[arg-type]
        injected_key=injected_key,
        injected_was_unknown=False,
        identifiable=True,
        diagnosis_key=injected_key,
        diagnosis_correct=True,
        abstained=False,
        confidence="1.000000",
    )


def test_an_episode_outcome_requires_the_passive_active_pair() -> None:
    with pytest.raises(ValidationError, match="one passive and one active"):
        EpisodeOutcome(
            episode_id="ep-1",
            injected_key=SORTED_KEYS[0],
            passive=_condition_outcome("active", "ep-1", SORTED_KEYS[0]),
            active=_condition_outcome("active", "ep-1", SORTED_KEYS[0]),
            passive_episode_hash="a" * 64,
            active_episode_hash="b" * 64,
        )


def test_an_episode_outcome_requires_a_shared_episode_id() -> None:
    with pytest.raises(ValidationError, match="share the episode id"):
        EpisodeOutcome(
            episode_id="ep-1",
            injected_key=SORTED_KEYS[0],
            passive=_condition_outcome("passive", "ep-OTHER", SORTED_KEYS[0]),
            active=_condition_outcome("active", "ep-1", SORTED_KEYS[0]),
            passive_episode_hash="a" * 64,
            active_episode_hash="b" * 64,
        )


def test_an_episode_outcome_requires_a_shared_injected_key() -> None:
    with pytest.raises(ValidationError, match="share the injected key"):
        EpisodeOutcome(
            episode_id="ep-1",
            injected_key=SORTED_KEYS[0],
            passive=_condition_outcome("passive", "ep-1", SORTED_KEYS[1]),
            active=_condition_outcome("active", "ep-1", SORTED_KEYS[0]),
            passive_episode_hash="a" * 64,
            active_episode_hash="b" * 64,
        )


def test_a_result_that_misbinds_the_machine_proposal_is_rejected() -> None:
    result, _ = _run(_balanced_plan(), ReferenceLikelihoodDiagnoser(ONTO))
    payload = result.model_dump(mode="json")
    payload["machine_proposal_artifact_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="approved machine proposal"):
        CampaignResult.model_validate(payload)


def test_a_result_that_misbinds_the_owner_receipt_is_rejected() -> None:
    result, _ = _run(_balanced_plan(), ReferenceLikelihoodDiagnoser(ONTO))
    payload = result.model_dump(mode="json")
    payload["owner_approval_receipt_hash"] = "0" * 64
    with pytest.raises(ValidationError, match="owner-approval receipt"):
        CampaignResult.model_validate(payload)


def test_a_result_that_misbinds_the_proposal_commit_is_rejected() -> None:
    result, _ = _run(_balanced_plan(), ReferenceLikelihoodDiagnoser(ONTO))
    payload = result.model_dump(mode="json")
    payload["proposal_git_commit"] = "0" * 40
    with pytest.raises(ValidationError, match="approved proposal commit"):
        CampaignResult.model_validate(payload)


def test_a_condition_summary_rejects_a_malformed_metric() -> None:
    with pytest.raises(ValidationError):
        ConditionSummary(
            condition="passive",
            episodes=1,
            diagnosis_accuracy="1.5",
            abstention_rate="0.000000",
            abstention_correct_rate="0.000000",
            committed_accuracy="1.000000",
            committed_mean_confidence="1.000000",
            unknown_injection_accuracy="1.000000",
        )
