"""Typed domain contracts. No provider or simulator imports belong here."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from fieldtrue.canonical import sha256_value

Identifier = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitObjectId = Annotated[str, StringConstraints(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")]
Ed25519PublicKey = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
HexSignature = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{128}$")]
Probability = Annotated[float, Field(ge=0.0, le=1.0)]
NonNegativeFloat = Annotated[float, Field(ge=0.0)]
PositiveFloat = Annotated[float, Field(gt=0.0)]
SecretReference = Annotated[
    str,
    StringConstraints(pattern=r"^secret://[A-Za-z0-9][A-Za-z0-9._/-]{1,255}@[A-Za-z0-9._-]+$"),
]

READINESS_AUTHORIZED_NEXT_ACTIONS = {
    "PASS": "Freeze grouped splits and execute the cheap deterministic baseline ladder.",
    "BLOCKED_EVIDENCE": (
        "Acquire additional independently verified physical incidents and reviewed safe test "
        "actions; ADAPT remains parser and evidence-plane validation only."
    ),
    "INVALID": "Repair ingestion or source integrity and rerun under an explicit amendment.",
}
READINESS_FORBIDDEN_NEXT_ACTIONS = (
    "GPU or learned-model training",
    "active-diagnosis performance claim",
    "recovery or safety claim",
    "cross-hardware transfer claim",
    "product or economic-value claim",
)


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Modality(StrEnum):
    TELEMETRY = "telemetry"
    COMMAND_LOG = "command_log"
    EVENT_LOG = "event_log"
    CONFIGURATION = "configuration"
    PROCEDURE = "procedure"
    SCHEMATIC = "schematic"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    NDE = "nondestructive_evaluation"
    SIMULATION = "simulation"
    OPERATOR_NOTE = "operator_note"


class ExecutionAuthority(StrEnum):
    REPLAY = "replay"
    SIMULATOR = "simulator"
    TESTBED = "testbed"


class ClaimStatus(StrEnum):
    UNTESTED = "untested"
    SUPPORTED = "supported"
    REFUTED = "refuted"
    NULL = "null"
    BLOCKED = "blocked"
    INVALID = "invalid"
    CORRECTED = "corrected"


class VerdictClass(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    NULL = "null"
    BLOCKED = "blocked"
    INVALID = "invalid"
    VOID = "void"
    INTERRUPTED = "interrupted"
    INFRASTRUCTURE_NULL = "infrastructure_null"


class GateStatus(StrEnum):
    PASS = "pass"  # noqa: S105 - research verdict, not a credential
    BLOCKED = "blocked"
    INVALID = "invalid"
    NOT_RUN = "not_run"


class ReviewKind(StrEnum):
    CAUSE = "cause"
    AMBIGUITY = "ambiguity"
    SAFE_TEST = "safe_test"


class ArtifactRef(FrozenModel):
    artifact_id: Identifier
    uri: str = Field(min_length=1)
    sha256: Sha256
    bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1)
    source_authority: str = Field(min_length=1)
    clock_domain: str | None = None
    license_ref: str = Field(min_length=1)
    lineage_sha256: tuple[Sha256, ...] = ()


class ReviewAttestation(FrozenModel):
    attestation_id: Identifier
    kind: ReviewKind
    producer_id: Identifier
    reviewer_id: Identifier
    subject_ids: tuple[Identifier, ...] = Field(min_length=1)
    method: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    evidence_refs: tuple[ArtifactRef, ...] = Field(min_length=1)
    reviewed_at: datetime

    @model_validator(mode="after")
    def review_is_independent_and_well_formed(self) -> Self:
        if self.producer_id == self.reviewer_id:
            raise ValueError("review producer and reviewer must differ")
        if len(self.subject_ids) != len(set(self.subject_ids)):
            raise ValueError("review subject IDs must be unique")
        if self.reviewed_at.tzinfo is None or self.reviewed_at.utcoffset() is None:
            raise ValueError("review timestamp must be timezone-aware")
        return self


class EvidenceItem(FrozenModel):
    evidence_id: Identifier
    modality: Modality
    artifact: ArtifactRef
    observed_start: str | None = None
    observed_end: str | None = None
    description: str = Field(min_length=1)


class EvidenceBundle(FrozenModel):
    schema_version: Literal["fieldtrue.evidence-bundle.v1"] = "fieldtrue.evidence-bundle.v1"
    incident_id: Identifier
    system_family: str = Field(min_length=1)
    system_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    context: dict[str, Any] = Field(default_factory=dict)
    evidence: tuple[EvidenceItem, ...] = Field(min_length=1)
    truth_commitment: Sha256
    truth_commitment_scheme: Literal["sha256-canonical-truth-with-256bit-nonce"] = (
        "sha256-canonical-truth-with-256bit-nonce"
    )

    @model_validator(mode="after")
    def unique_evidence_ids(self) -> Self:
        identifiers = [item.evidence_id for item in self.evidence]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("evidence IDs must be unique inside a bundle")
        return self


class TruthRecord(FrozenModel):
    """Adjudication-only record; never an input to a hypothesis engine."""

    schema_version: Literal["fieldtrue.truth-record.v1"] = "fieldtrue.truth-record.v1"
    incident_id: Identifier
    commitment_nonce: Sha256
    hardware_family: str = Field(min_length=1)
    hardware_id: str = Field(min_length=1)
    fault_family: str = Field(min_length=1)
    mechanism_ids: tuple[Identifier, ...] = Field(min_length=1)
    cause_authority: str = Field(min_length=1)
    verification_method: str = Field(min_length=1)
    injection_method: str | None = None
    injection_times: tuple[str, ...] = ()
    competing_hypothesis_ids: tuple[Identifier, ...] = ()
    safe_discriminating_test_ids: tuple[Identifier, ...] = ()
    settled_outcome_refs: tuple[ArtifactRef, ...] = ()
    review_attestations: tuple[ReviewAttestation, ...] = ()
    notes: tuple[str, ...] = ()

    @model_validator(mode="after")
    def identifiers_and_reviews_are_consistent(self) -> Self:
        groups = {
            ReviewKind.CAUSE: self.mechanism_ids,
            ReviewKind.AMBIGUITY: self.competing_hypothesis_ids,
            ReviewKind.SAFE_TEST: self.safe_discriminating_test_ids,
        }
        for label, identifiers in (
            ("mechanism", self.mechanism_ids),
            ("competing hypothesis", self.competing_hypothesis_ids),
            ("safe test", self.safe_discriminating_test_ids),
        ):
            if len(identifiers) != len(set(identifiers)):
                raise ValueError(f"{label} IDs must be unique")
        attestation_ids = [item.attestation_id for item in self.review_attestations]
        if len(attestation_ids) != len(set(attestation_ids)):
            raise ValueError("review attestation IDs must be unique")
        for attestation in self.review_attestations:
            if not set(attestation.subject_ids).issubset(groups[attestation.kind]):
                raise ValueError("review attestation names an unregistered subject")
        return self


class MechanismEdge(FrozenModel):
    cause: Identifier
    effect: Identifier
    relation: str = Field(min_length=1)
    lag_seconds: float | None = Field(default=None, ge=0.0)
    evidence_refs: tuple[Identifier, ...] = ()


class CausalHypothesis(FrozenModel):
    hypothesis_id: Identifier
    description: str = Field(min_length=1)
    prior: Probability
    unknown: bool = False
    mechanism_edges: tuple[MechanismEdge, ...] = ()
    supporting_evidence_ids: tuple[Identifier, ...] = ()
    contradicting_evidence_ids: tuple[Identifier, ...] = ()
    disposition: str = "active"


class HypothesisSet(FrozenModel):
    incident_id: Identifier
    hypotheses: tuple[CausalHypothesis, ...] = Field(min_length=2)
    proposer_id: Identifier

    @model_validator(mode="after")
    def validate_distribution(self) -> Self:
        identifiers = [item.hypothesis_id for item in self.hypotheses]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("hypothesis IDs must be unique")
        total = sum(item.prior for item in self.hypotheses)
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"hypothesis priors must sum to 1, got {total}")
        if sum(item.unknown for item in self.hypotheses) != 1:
            raise ValueError("exactly one unknown hypothesis is required")
        return self


class TestOutcomeModel(FrozenModel):
    outcome_id: Identifier
    probability_by_hypothesis: dict[Identifier, Probability]


class DiscriminatingTest(FrozenModel):
    test_id: Identifier
    description: str = Field(min_length=1)
    authority: ExecutionAuthority
    approved: bool
    cost_units: NonNegativeFloat
    duration_seconds: NonNegativeFloat
    risk: Probability
    preconditions: tuple[str, ...] = ()
    outcome_model: tuple[TestOutcomeModel, ...] = Field(min_length=1)
    approval_receipt_hash: Sha256 | None = None

    @model_validator(mode="after")
    def validate_outcome_model(self) -> Self:
        outcomes = [outcome.outcome_id for outcome in self.outcome_model]
        if len(outcomes) != len(set(outcomes)):
            raise ValueError("test outcome IDs must be unique")
        hypothesis_ids = set(self.outcome_model[0].probability_by_hypothesis)
        if not hypothesis_ids:
            raise ValueError("test must model at least one hypothesis")
        for outcome in self.outcome_model:
            if set(outcome.probability_by_hypothesis) != hypothesis_ids:
                raise ValueError("every outcome must model the same hypotheses")
        for hypothesis_id in hypothesis_ids:
            total = sum(
                outcome.probability_by_hypothesis[hypothesis_id] for outcome in self.outcome_model
            )
            if abs(total - 1.0) > 1e-9:
                raise ValueError(
                    f"outcome probabilities for {hypothesis_id} must sum to 1, got {total}"
                )
        if self.authority == ExecutionAuthority.TESTBED and self.approval_receipt_hash is None:
            raise ValueError("testbed candidates require an approval receipt")
        if len(self.preconditions) != len(set(self.preconditions)):
            raise ValueError("test preconditions must be unique")
        return self


class SafetyEnvelope(FrozenModel):
    envelope_id: Identifier
    authority: ExecutionAuthority
    allowed_test_ids: tuple[Identifier, ...] = Field(min_length=1)
    max_risk: Probability
    satisfied_preconditions: tuple[str, ...] = ()
    approval_receipt_hash: Sha256 | None = None

    @model_validator(mode="after")
    def physical_testbed_requires_approval(self) -> Self:
        if self.authority == ExecutionAuthority.TESTBED and self.approval_receipt_hash is None:
            raise ValueError("testbed authority requires an approval receipt")
        if len(self.allowed_test_ids) != len(set(self.allowed_test_ids)):
            raise ValueError("allowed test IDs must be unique")
        if len(self.satisfied_preconditions) != len(set(self.satisfied_preconditions)):
            raise ValueError("satisfied preconditions must be unique")
        return self


class PlannerWeights(FrozenModel):
    time_weight: NonNegativeFloat = 1.0
    risk_weight: NonNegativeFloat = 1.0
    denominator_floor: PositiveFloat = 1e-9


class SelectedTest(FrozenModel):
    incident_id: Identifier
    test_id: Identifier
    expected_information_gain_bits: NonNegativeFloat
    denominator: PositiveFloat
    utility: NonNegativeFloat
    posterior_before: dict[Identifier, Probability]
    planner_id: Identifier
    candidate_sha256: Sha256
    safety_envelope_sha256: Sha256

    @model_validator(mode="after")
    def posterior_is_normalized(self) -> Self:
        if not self.posterior_before or abs(sum(self.posterior_before.values()) - 1.0) > 1e-9:
            raise ValueError("selected-test posterior must sum to one")
        return self


class TestObservation(FrozenModel):
    incident_id: Identifier
    test_id: Identifier
    outcome_id: Identifier
    authority: ExecutionAuthority
    executor_id: Identifier
    started_at: datetime
    finished_at: datetime
    observation_artifact: ArtifactRef
    safety_envelope_id: Identifier
    candidate_sha256: Sha256
    safety_envelope_sha256: Sha256
    approval_receipt_hash: Sha256 | None = None

    @model_validator(mode="after")
    def timestamps_are_ordered(self) -> Self:
        for value in (self.started_at, self.finished_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("test timestamps must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("test cannot finish before it starts")
        if self.authority == ExecutionAuthority.TESTBED and self.approval_receipt_hash is None:
            raise ValueError("testbed observations require an approval receipt")
        return self


class RecoveryPlan(FrozenModel):
    recovery_id: Identifier
    incident_id: Identifier
    hypothesis_id: Identifier
    proposer_id: Identifier
    action: str = Field(min_length=1)
    target: str = Field(min_length=1)
    expected_settled_state: dict[str, Any] = Field(min_length=1)
    authority: ExecutionAuthority
    approval_receipt_hash: Sha256 | None = None

    @model_validator(mode="after")
    def testbed_recovery_requires_approval(self) -> Self:
        if self.authority == ExecutionAuthority.TESTBED and self.approval_receipt_hash is None:
            raise ValueError("testbed recovery requires an approval receipt")
        return self


class VerificationResult(FrozenModel):
    verification_id: Identifier
    recovery_id: Identifier
    verifier_id: Identifier
    proposer_id: Identifier
    action_valid: bool
    target_valid: bool
    settled_success: bool
    abstained: bool
    outcome_artifacts: tuple[ArtifactRef, ...] = Field(min_length=1)
    scope: str = Field(min_length=1)

    @model_validator(mode="after")
    def verifier_is_independent(self) -> Self:
        if self.verifier_id == self.proposer_id:
            raise ValueError("recovery proposer cannot be the sole verifier")
        if self.abstained and (self.action_valid or self.target_valid or self.settled_success):
            raise ValueError("an abstaining verifier cannot report successful outcomes")
        if self.settled_success and not (self.action_valid and self.target_valid):
            raise ValueError("settled success requires valid action and target")
        return self


class MonitorSpecification(FrozenModel):
    monitor_id: Identifier
    mechanism_id: Identifier
    validity_domain: dict[str, Any]
    detection_rule: dict[str, Any]
    abstention_rule: dict[str, Any]
    calibration_artifact: ArtifactRef
    max_false_alarms_per_hour: NonNegativeFloat
    max_latency_ms: PositiveFloat
    max_memory_mb: PositiveFloat
    lineage_sha256: tuple[Sha256, ...] = Field(min_length=1)


class AssuranceCertificate(FrozenModel):
    """Scoped evidence packet, not a regulatory or universal safety certificate."""

    certificate_id: Identifier
    incident_id: Identifier
    hypothesis_set_hash: Sha256
    selected_test_hash: Sha256
    observation_hash: Sha256
    recovery_plan_hash: Sha256
    verification_result_hash: Sha256
    monitor_spec_hash: Sha256 | None = None
    scope: str = Field(min_length=1)
    forbidden_claims: tuple[str, ...] = Field(min_length=1)


class JobResources(FrozenModel):
    cpu: PositiveFloat
    memory_gb: PositiveFloat
    accelerator_type: str | None = None
    accelerator_count: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def accelerator_is_consistent(self) -> Self:
        if (self.accelerator_type is None) != (self.accelerator_count == 0):
            raise ValueError("accelerator type and positive count must be provided together")
        return self


class JobSpec(FrozenModel):
    schema_version: Literal["fieldtrue.job-spec.v1"] = "fieldtrue.job-spec.v1"
    job_id: Identifier
    git_commit: GitObjectId
    oci_image_digest: Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
    command: tuple[str, ...] = Field(min_length=1)
    command_sha256: Sha256
    allowlist_id: Identifier
    allowlist_sha256: Sha256
    dataset_hashes: tuple[Sha256, ...] = Field(min_length=1)
    case_hashes: tuple[Sha256, ...] = Field(min_length=1)
    resources: JobResources
    max_runtime_seconds: int = Field(gt=0)
    idempotency_key: Identifier
    artifact_prefix: str = Field(min_length=1)
    budget_usd: Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$")]
    cost_estimate_usd: Annotated[
        str, StringConstraints(pattern=r"^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$")
    ]
    cost_estimate_source: str = Field(min_length=1)
    cost_estimated_at: datetime
    secret_references: tuple[SecretReference, ...] = ()
    authority: ExecutionAuthority
    approval_receipt_hash: Sha256

    @field_validator("cost_estimated_at")
    @classmethod
    def cost_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("cost estimate timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def job_is_budgeted_and_command_bound(self) -> Self:
        if Decimal(self.cost_estimate_usd) > Decimal(self.budget_usd):
            raise ValueError("job cost estimate exceeds its approved budget")
        if self.command_sha256 != sha256_value(self.command):
            raise ValueError("job command hash does not match the command")
        if len(self.secret_references) != len(set(self.secret_references)):
            raise ValueError("secret references must be unique")
        return self


class ClaimRecord(FrozenModel):
    claim_id: Identifier
    status: ClaimStatus
    wording: str = Field(min_length=1)
    scope: str = Field(min_length=1)
    evidence_refs: tuple[str, ...]
    permitted_wording: str = Field(min_length=1)
    forbidden_wording: str = Field(min_length=1)
    next_falsifier: str = Field(min_length=1)


class GateResult(FrozenModel):
    gate_id: Identifier
    status: GateStatus
    observed: Any
    requirement: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = ()
    detail: str = Field(min_length=1)


class ReadinessReport(FrozenModel):
    schema_version: Literal["fieldtrue.corpus-readiness.v1"] = "fieldtrue.corpus-readiness.v1"
    dataset_id: Identifier
    gates: tuple[GateResult, ...] = Field(min_length=1)
    verdict: Literal["PASS", "BLOCKED_EVIDENCE", "INVALID"]
    authorized_next_action: str
    forbidden_next_actions: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="before")
    @classmethod
    def derive_authority_contract(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        derived = dict(value)
        verdict = derived.get("verdict")
        if not isinstance(verdict, str):
            return derived
        action = READINESS_AUTHORIZED_NEXT_ACTIONS.get(verdict)
        if action is not None:
            derived["authorized_next_action"] = action
            derived["forbidden_next_actions"] = READINESS_FORBIDDEN_NEXT_ACTIONS
        return derived

    @model_validator(mode="after")
    def authority_contract_is_exact(self) -> Self:
        expected_action = READINESS_AUTHORIZED_NEXT_ACTIONS.get(self.verdict)
        if expected_action is None:
            raise ValueError("unsupported readiness verdict")
        if self.authorized_next_action != expected_action:
            raise ValueError("readiness action does not follow from the verdict")
        if self.forbidden_next_actions != READINESS_FORBIDDEN_NEXT_ACTIONS:
            raise ValueError("readiness forbidden-action contract is not exact")
        return self
