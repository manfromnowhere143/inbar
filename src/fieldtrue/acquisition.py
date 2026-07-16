"""Prospective physical-evidence acquisition and conjunctive admission contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise
from pathlib import Path, PurePosixPath
from types import CodeType
from typing import Annotated, Any, BinaryIO, Literal, Self, TypeVar
from urllib.parse import urlsplit

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, Field, StringConstraints, field_validator, model_validator

from fieldtrue.approvals import (
    ApprovalReceipt,
    ApprovalSubjectKind,
    ApprovalVerificationError,
    authorization_subject_hash,
    verify_approval,
)
from fieldtrue.canonical import (
    atomic_write,
    canonical_json_pretty,
    read_json,
    sha256_bytes,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import (
    DiscriminatingTest,
    Ed25519PublicKey,
    EvidenceBundle,
    ExecutionAuthority,
    FrozenModel,
    GitObjectId,
    HexSignature,
    HypothesisSet,
    Identifier,
    Modality,
    RecoveryPlan,
    SafetyEnvelope,
    SelectedTest,
    Sha256,
    TestObservation,
    TruthRecord,
    VerificationResult,
)
from fieldtrue.git_trust import GitTrustError, git_environment, trusted_repository_git
from fieldtrue.planning import (
    NoEligibleTestError,
    NonDiscriminatingTestError,
    select_discriminating_test,
)
from fieldtrue.splits import SplitLock, SplitUnit, validate_split_lock

Money = Annotated[str, StringConstraints(pattern=r"^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$")]


class AcquisitionAuditError(ValueError):
    """An acquisition artifact is malformed, unbound, or outside the audit root."""


@dataclass(frozen=True)
class AcquisitionSourceClosure:
    """Complete on-disk package source census anchored to one control execution commit."""

    authority_commit: str
    repository_head: str
    sources: tuple[tuple[str, str, str, str, int], ...]
    closure_sha256: str


class PermissionKind(StrEnum):
    ACQUIRE = "acquire"
    PROCESS = "process"
    RETAIN_RAW = "retain_raw"
    RETAIN_DERIVED = "retain_derived"
    PUBLISH_METADATA = "publish_metadata"
    INDEPENDENT_REVIEW = "independent_review"
    REDISTRIBUTE_RAW = "redistribute_raw"
    REDISTRIBUTE_DERIVED = "redistribute_derived"
    COMMERCIAL_RESEARCH = "commercial_research"


class PermissionDecision(StrEnum):
    ALLOWED = "allowed"
    PROHIBITED = "prohibited"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


class EvidenceTrack(StrEnum):
    PHYSICAL_ADMISSION = "physical_admission"
    CAUSAL_LABORATORY = "causal_laboratory"
    REALITY_CONTROL = "reality_control"


class Physicality(StrEnum):
    PHYSICAL = "physical"
    SIMULATED = "simulated"
    SYNTHETIC = "synthetic"
    HAND_DRAWN = "hand_drawn"


class SystemDomain(StrEnum):
    AEROSPACE = "aerospace"
    ROBOTICS = "robotics"
    INDUSTRIAL = "industrial"
    OTHER = "other"


class EvidencePlane(StrEnum):
    MODEL_VISIBLE = "model_visible"
    TRUTH_ONLY = "truth_only"
    EXCLUDED = "excluded"


_FORBIDDEN_MODEL_VISIBLE_FIELDS = (
    "filename",
    "path",
    "task",
    "site",
    "system_identity",
    "timestamp",
    "fault_label",
    "annotation",
    "truth_derived_metadata",
)


class RoleKind(StrEnum):
    SOURCE_STEWARD = "source_steward"
    RIGHTS_REVIEWER = "rights_reviewer"
    EVIDENCE_CURATOR = "evidence_curator"
    TRUTH_PRODUCER = "truth_producer"
    MECHANISM_REVIEWER = "mechanism_reviewer"
    HYPOTHESIS_PROPOSER = "hypothesis_proposer"
    TEST_PROPOSER = "test_proposer"
    SAFETY_REVIEWER = "safety_reviewer"
    TEST_SELECTOR = "test_selector"
    TEST_EXECUTOR = "test_executor"
    RECOVERY_PROPOSER = "recovery_proposer"
    RECOVERY_EXECUTOR = "recovery_executor"
    OUTCOME_VERIFIER = "outcome_verifier"
    STATISTICIAN = "statistician"


class ReviewPurpose(StrEnum):
    MECHANISM = "mechanism"
    AMBIGUITY = "ambiguity"
    SAFE_TEST = "safe_test"
    RECOVERY = "recovery"
    SETTLED_OUTCOME = "settled_outcome"


class AttestationSubjectKind(StrEnum):
    SOURCE_RIGHTS = "source_rights"
    PHYSICAL_PROVENANCE = "physical_provenance"
    MECHANISM_TRUTH = "mechanism_truth"
    REVIEW = "review"
    DIAGNOSTIC_EXECUTION = "diagnostic_execution"
    RECOVERY_EXECUTION = "recovery_execution"
    SETTLED_OUTCOME = "settled_outcome"
    PROTOCOL_REVIEW = "protocol_review"
    SHORTCUT_BASELINE = "shortcut_baseline"
    CONTROL_SUITE = "control_suite"
    MODEL_VISIBLE_PROJECTION = "model_visible_projection"
    RESOURCE_USAGE = "resource_usage"
    TRUTH_CUSTODY = "truth_custody"
    COMPARATOR_REGISTRY = "comparator_registry"
    CANDIDATE_REGISTRY = "candidate_registry"
    EVIDENCE_SEQUENCE = "evidence_sequence"
    ADMISSION_VERIFIER_CERTIFICATE = "admission_verifier_certificate"


class ArtifactBinding(FrozenModel):
    path: str = Field(min_length=1)
    sha256: Sha256
    bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def path_is_relative_and_normalized(cls, value: str) -> str:
        pure = PurePosixPath(value)
        if (
            pure.is_absolute()
            or not pure.parts
            or ".." in pure.parts
            or "." in pure.parts
            or value != pure.as_posix()
        ):
            raise ValueError("artifact path must be normalized and relative")
        return value


class SignedAttestation(FrozenModel):
    schema_version: Literal["fieldtrue.signed-attestation.v1"] = "fieldtrue.signed-attestation.v1"
    attestation_id: Identifier
    signer_id: Identifier
    subject_kind: AttestationSubjectKind
    subject_sha256: Sha256
    issued_at: datetime
    signer_public_key: Ed25519PublicKey
    attestation_hash: Sha256
    signature: HexSignature

    @field_validator("issued_at")
    @classmethod
    def issued_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("attestation timestamp must be timezone-aware")
        return value


class TrustedActor(FrozenModel):
    actor_id: Identifier
    independence_group_id: Identifier
    public_key: Ed25519PublicKey
    authorized_roles: tuple[RoleKind, ...] = Field(min_length=1)
    mandate: ArtifactBinding

    @model_validator(mode="after")
    def roles_are_unique(self) -> Self:
        if len(self.authorized_roles) != len(set(self.authorized_roles)):
            raise ValueError("trusted actor roles must be unique")
        return self


class ActorTrustRegistry(FrozenModel):
    schema_version: Literal["fieldtrue.actor-trust-registry.v1"] = (
        "fieldtrue.actor-trust-registry.v1"
    )
    registry_id: Identifier
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"]
    issued_at: datetime
    actors: tuple[TrustedActor, ...] = Field(min_length=1)
    signer_public_key: Ed25519PublicKey
    registry_hash: Sha256
    signature: HexSignature

    @model_validator(mode="after")
    def registry_is_structurally_unique(self) -> Self:
        if self.issued_at.tzinfo is None or self.issued_at.utcoffset() is None:
            raise ValueError("trust-registry timestamp must be timezone-aware")
        actor_ids = [actor.actor_id for actor in self.actors]
        public_keys = [actor.public_key for actor in self.actors]
        if len(actor_ids) != len(set(actor_ids)):
            raise ValueError("trusted actor IDs must be unique")
        if len(public_keys) != len(set(public_keys)):
            raise ValueError("independent actors cannot share signing keys")
        role_owners: dict[RoleKind, str] = {}
        for actor in self.actors:
            for role in actor.authorized_roles:
                if role in role_owners:
                    raise ValueError(f"trusted role has multiple owners: {role.value}")
                role_owners[role] = actor.actor_id
        if set(role_owners) != set(RoleKind):
            raise ValueError("trust registry must authorize every dossier role exactly once")
        return self


def _signed_body(value: BaseModel, *excluded: str) -> dict[str, Any]:
    return value.model_dump(mode="json", exclude=set(excluded))


def attestation_subject_hash(kind: AttestationSubjectKind, subject: Any) -> str:
    return sha256_value(
        {
            "domain": "fieldtrue.signed-attestation-subject.v1",
            "kind": kind.value,
            "subject": subject,
        }
    )


def issue_attestation(
    signing_key: SigningKey,
    *,
    attestation_id: Identifier,
    signer_id: Identifier,
    subject_kind: AttestationSubjectKind,
    subject_sha256: Sha256,
    issued_at: datetime,
) -> SignedAttestation:
    body: dict[str, Any] = {
        "schema_version": "fieldtrue.signed-attestation.v1",
        "attestation_id": attestation_id,
        "signer_id": signer_id,
        "subject_kind": subject_kind,
        "subject_sha256": subject_sha256,
        "issued_at": issued_at,
        "signer_public_key": signing_key.verify_key.encode().hex(),
    }
    attestation_hash = sha256_value(body)
    signature = signing_key.sign(bytes.fromhex(attestation_hash)).signature.hex()
    return SignedAttestation.model_validate(
        {**body, "attestation_hash": attestation_hash, "signature": signature}
    )


def issue_actor_trust_registry(
    signing_key: SigningKey,
    *,
    registry_id: Identifier,
    issued_at: datetime,
    actors: tuple[TrustedActor, ...],
) -> ActorTrustRegistry:
    body: dict[str, Any] = {
        "schema_version": "fieldtrue.actor-trust-registry.v1",
        "registry_id": registry_id,
        "iteration_id": "iter001_physical_causal_evidence_acquisition",
        "issued_at": issued_at,
        "actors": [actor.model_dump(mode="json") for actor in actors],
        "signer_public_key": signing_key.verify_key.encode().hex(),
    }
    registry_hash = sha256_value(body)
    signature = signing_key.sign(bytes.fromhex(registry_hash)).signature.hex()
    return ActorTrustRegistry.model_validate(
        {**body, "registry_hash": registry_hash, "signature": signature}
    )


class PermissionDisposition(FrozenModel):
    kind: PermissionKind
    decision: PermissionDecision
    scope: str = Field(min_length=1)
    basis: ArtifactBinding


class SourceResource(FrozenModel):
    resource_id: Identifier
    uri: str = Field(min_length=1)
    version: str = Field(min_length=1)
    sha256: Sha256
    bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1)
    staged_at: datetime
    staged_artifact: ArtifactBinding

    @field_validator("uri")
    @classmethod
    def uri_has_an_explicit_authority_scheme(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"https", "partner", "testbed"}:
            raise ValueError("source URI must use https, partner, or testbed")
        if parsed.fragment or parsed.username or parsed.password:
            raise ValueError("source URI cannot contain credentials or a fragment")
        if not parsed.netloc:
            raise ValueError("source URI must name an authority")
        return value

    @field_validator("staged_at")
    @classmethod
    def staged_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("source staging timestamp must be timezone-aware")
        return value


class SourceManifest(FrozenModel):
    schema_version: Literal["fieldtrue.source-manifest.v1"] = "fieldtrue.source-manifest.v1"
    source_id: Identifier
    source_authority: str = Field(min_length=1)
    source_version: str = Field(min_length=1)
    landing_page: str = Field(min_length=1)
    evidence_track: EvidenceTrack
    approved_at: datetime
    source_steward_id: Identifier
    source_steward_independence_group: Identifier
    rights_reviewer_id: Identifier
    rights_reviewer_independence_group: Identifier
    terms_artifact: ArtifactBinding
    permissions: tuple[PermissionDisposition, ...]
    rights_attestation: SignedAttestation
    resources: tuple[SourceResource, ...] = Field(min_length=1)
    restricted_fields: tuple[str, ...] = ()
    deletion_obligations: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def source_rights_are_complete_and_independent(self) -> Self:
        if self.approved_at.tzinfo is None or self.approved_at.utcoffset() is None:
            raise ValueError("source approval timestamp must be timezone-aware")
        if self.source_steward_id == self.rights_reviewer_id:
            raise ValueError("source steward and rights reviewer must differ")
        if self.source_steward_independence_group == self.rights_reviewer_independence_group:
            raise ValueError("source steward and rights reviewer must be independent")
        kinds = [item.kind for item in self.permissions]
        if len(kinds) != len(set(kinds)) or set(kinds) != set(PermissionKind):
            raise ValueError("source permissions must cover every permission kind exactly once")
        resource_ids = [item.resource_id for item in self.resources]
        if len(resource_ids) != len(set(resource_ids)):
            raise ValueError("source resource IDs must be unique")
        if len(self.restricted_fields) != len(set(self.restricted_fields)):
            raise ValueError("restricted fields must be unique")
        return self


class FieldPlaneAssignment(FrozenModel):
    field_name: str = Field(min_length=1)
    plane: EvidencePlane
    rationale: str = Field(min_length=1)


class PlaneSeparationReceipt(FrozenModel):
    schema_version: Literal["fieldtrue.plane-separation-receipt.v1"] = (
        "fieldtrue.plane-separation-receipt.v1"
    )
    source_id: Identifier
    source_manifest_sha256: Sha256
    source_fields: tuple[str, ...] = Field(min_length=1)
    assignments: tuple[FieldPlaneAssignment, ...] = Field(min_length=1)
    parser_coverage: ArtifactBinding
    evidence_manifest: ArtifactBinding
    truth_manifest: ArtifactBinding
    evidence_incident_ids_sha256: Sha256
    truth_incident_ids_sha256: Sha256
    produced_at: datetime

    @model_validator(mode="after")
    def every_source_field_is_assigned_once(self) -> Self:
        if self.produced_at.tzinfo is None or self.produced_at.utcoffset() is None:
            raise ValueError("plane-separation timestamp must be timezone-aware")
        fields = list(self.source_fields)
        assigned = [item.field_name for item in self.assignments]
        if len(fields) != len(set(fields)):
            raise ValueError("source field inventory must be unique")
        if len(assigned) != len(set(assigned)) or set(assigned) != set(fields):
            raise ValueError("every source field must be assigned to exactly one plane")
        return self


class PlaneIncidentManifest(FrozenModel):
    schema_version: Literal["fieldtrue.plane-incident-manifest.v1"] = (
        "fieldtrue.plane-incident-manifest.v1"
    )
    plane: Literal["model_visible", "truth_only"]
    incident_ids: tuple[Identifier, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def incident_ids_are_unique(self) -> Self:
        if len(self.incident_ids) != len(set(self.incident_ids)):
            raise ValueError("plane incident manifest IDs must be unique")
        return self


class LeakageArtifactScan(FrozenModel):
    artifact_sha256: Sha256
    artifact_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1)
    scan_mode: Literal["utf8_json", "opaque_stream"]
    forbidden_field_paths: tuple[str, ...]
    matched_identity_token_sha256: tuple[Sha256, ...]

    @model_validator(mode="after")
    def findings_are_canonical(self) -> Self:
        if self.forbidden_field_paths != tuple(sorted(set(self.forbidden_field_paths))):
            raise ValueError("leakage field findings must be sorted and unique")
        if self.matched_identity_token_sha256 != tuple(
            sorted(set(self.matched_identity_token_sha256))
        ):
            raise ValueError("leakage token findings must be sorted and unique")
        return self


class ModelVisibleLeakageScanReport(FrozenModel):
    schema_version: Literal["fieldtrue.model-visible-leakage-scan-report.v1"] = (
        "fieldtrue.model-visible-leakage-scan-report.v1"
    )
    scanner_id: Literal["fieldtrue-validator-leakage-scan-v1"] = (
        "fieldtrue-validator-leakage-scan-v1"
    )
    incident_id: Identifier
    input_artifacts_sha256: Sha256
    forbidden_field_set_sha256: Sha256
    identity_token_set_sha256: Sha256
    artifact_scans: tuple[LeakageArtifactScan, ...] = Field(min_length=1)
    leakage_detected: bool

    @model_validator(mode="after")
    def verdict_is_derived_from_findings(self) -> Self:
        detected = any(
            scan.forbidden_field_paths or scan.matched_identity_token_sha256
            for scan in self.artifact_scans
        )
        if self.leakage_detected != detected:
            raise ValueError("leakage verdict does not follow from scan findings")
        return self


class ModelVisibleProjection(FrozenModel):
    schema_version: Literal["fieldtrue.model-visible-projection.v1"] = (
        "fieldtrue.model-visible-projection.v1"
    )
    projection_id: Identifier
    incident_id: Identifier
    source_manifest_sha256: Sha256
    plane_separation_sha256: Sha256
    evidence_bundle_sha256: Sha256
    model_input_artifacts: tuple[ArtifactBinding, ...] = Field(min_length=2)
    excluded_fields: tuple[str, ...]
    projection_implementation: ArtifactBinding
    leakage_scan: ArtifactBinding
    leakage_detected: bool
    projected_at: datetime
    curator_id: Identifier
    attestation: SignedAttestation

    @model_validator(mode="after")
    def projection_contract_is_exact(self) -> Self:
        if self.projected_at.tzinfo is None or self.projected_at.utcoffset() is None:
            raise ValueError("model-visible projection timestamp must be timezone-aware")
        if self.excluded_fields != _FORBIDDEN_MODEL_VISIBLE_FIELDS:
            raise ValueError("model-visible projection exclusion set is incomplete")
        hashes = [artifact.sha256 for artifact in self.model_input_artifacts]
        if len(hashes) != len(set(hashes)):
            raise ValueError("model-visible projection duplicates an input content stream")
        return self


class RoleAssignment(FrozenModel):
    role: RoleKind
    actor_id: Identifier
    independence_group_id: Identifier
    conflict_disclosure: ArtifactBinding
    approval_public_key: Ed25519PublicKey


class BoundReview(FrozenModel):
    review_id: Identifier
    purpose: ReviewPurpose
    subject_sha256: Sha256
    producer_role: RoleKind
    reviewer_role: RoleKind
    reviewed_at: datetime
    evidence: tuple[ArtifactBinding, ...] = Field(min_length=1)
    attestation: SignedAttestation

    @field_validator("reviewed_at")
    @classmethod
    def review_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("review timestamp must be timezone-aware")
        return value


class ClockMap(FrozenModel):
    clock_domain: Identifier
    unit: str = Field(min_length=1)
    origin: str = Field(min_length=1)
    reference_clock_domain: Identifier
    scale_to_reference: float = Field(gt=0)
    offset_ns: int
    max_alignment_error_ns: int = Field(ge=0)
    missing_fraction: float = Field(ge=0.0, le=1.0)
    mapping_artifact: ArtifactBinding


class ClockCalibrationPair(FrozenModel):
    source_value: float
    reference_ns: int


class ClockMappingEvidence(FrozenModel):
    schema_version: Literal["fieldtrue.clock-mapping-evidence.v1"] = (
        "fieldtrue.clock-mapping-evidence.v1"
    )
    clock_domain: Identifier
    reference_clock_domain: Identifier
    calibration_pairs: tuple[ClockCalibrationPair, ...] = Field(min_length=2)
    expected_samples: int = Field(gt=0)
    observed_samples: int = Field(ge=0)
    method: str = Field(min_length=1)

    @model_validator(mode="after")
    def sample_counts_are_possible(self) -> Self:
        if self.observed_samples > self.expected_samples:
            raise ValueError("observed clock samples exceed expected samples")
        return self


class EvidenceTimeBinding(FrozenModel):
    evidence_id: Identifier
    clock_domain: Identifier
    normalized_start_ns: int
    normalized_end_ns: int

    @model_validator(mode="after")
    def interval_is_ordered(self) -> Self:
        if self.normalized_end_ns < self.normalized_start_ns:
            raise ValueError("evidence interval ends before it starts")
        return self


class EvidenceStreamSequence(FrozenModel):
    evidence_id: Identifier
    artifact_sha256: Sha256
    artifact_bytes: int = Field(gt=0)
    chunk_bytes: int = Field(gt=0, le=1024 * 1024)
    ordered_chunk_sha256: tuple[Sha256, ...] = Field(min_length=1)
    source_order_monotonic: bool


class EvidenceSequenceReceipt(FrozenModel):
    schema_version: Literal["fieldtrue.evidence-sequence-receipt.v1"] = (
        "fieldtrue.evidence-sequence-receipt.v1"
    )
    receipt_id: Identifier
    incident_id: Identifier
    produced_at: datetime
    source_steward_id: Identifier
    streams: tuple[EvidenceStreamSequence, ...] = Field(min_length=1)
    attestation: SignedAttestation

    @model_validator(mode="after")
    def sequence_streams_are_unique(self) -> Self:
        if self.produced_at.tzinfo is None or self.produced_at.utcoffset() is None:
            raise ValueError("sequence receipt timestamp must be timezone-aware")
        identifiers = [stream.evidence_id for stream in self.streams]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("sequence receipt evidence IDs must be unique")
        return self


class IncidentTimeline(FrozenModel):
    source_acquired_at: datetime
    truth_committed_at: datetime
    evidence_cutoff_at: datetime
    model_visible_cutoff_ns: int
    hypothesis_committed_at: datetime
    safe_test_reviewed_at: datetime
    test_started_at: datetime
    test_finished_at: datetime
    recovery_plan_committed_at: datetime
    recovery_started_at: datetime
    recovery_finished_at: datetime
    settled_window_started_at: datetime
    settled_window_finished_at: datetime
    outcome_verified_at: datetime
    truth_unsealed_at: datetime

    @model_validator(mode="after")
    def chronology_is_outcome_blind(self) -> Self:
        values = self.model_dump()
        for name, value in values.items():
            if name == "model_visible_cutoff_ns":
                continue
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{name} must be timezone-aware")
        ordered = (
            self.source_acquired_at,
            self.truth_committed_at,
            self.evidence_cutoff_at,
            self.hypothesis_committed_at,
            self.safe_test_reviewed_at,
            self.test_started_at,
            self.test_finished_at,
            self.recovery_plan_committed_at,
            self.recovery_started_at,
            self.recovery_finished_at,
            self.settled_window_started_at,
            self.settled_window_finished_at,
            self.outcome_verified_at,
        )
        if any(right < left for left, right in pairwise(ordered)):
            raise ValueError("incident chronology is not ordered")
        if self.truth_unsealed_at < self.settled_window_finished_at:
            raise ValueError("truth cannot be unsealed before the settled window ends")
        return self


class TruthCustodyReceipt(FrozenModel):
    schema_version: Literal["fieldtrue.truth-custody-receipt.v1"] = (
        "fieldtrue.truth-custody-receipt.v1"
    )
    custody_id: Identifier
    incident_id: Identifier
    truth_record_sha256: Sha256
    custodian_id: Identifier
    committed_at: datetime
    unsealed_at: datetime
    access_log: ArtifactBinding
    unauthorized_access_detected: bool
    attestation: SignedAttestation

    @model_validator(mode="after")
    def custody_window_is_ordered(self) -> Self:
        for value in (self.committed_at, self.unsealed_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("truth-custody timestamps must be timezone-aware")
        if self.unsealed_at <= self.committed_at:
            raise ValueError("truth unseal must follow its commitment")
        return self


class IncidentGroupRecord(FrozenModel):
    incident_id: Identifier
    root_incident_group_id: Identifier
    acquisition_session_id: Identifier
    independence_group_id: Identifier
    physicality: Physicality
    system_domain: SystemDomain
    system_family: str = Field(min_length=1)
    hardware_id: str = Field(min_length=1)
    fault_family: str = Field(min_length=1)
    configuration_id: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    acquisition_lineage_id: Identifier
    mission_id: str = Field(min_length=1)
    site_id: str = Field(min_length=1)
    claim_bearing: bool


class CandidateIncidentRoot(FrozenModel):
    incident_id: Identifier
    root_incident_group_id: Identifier
    source_id: Identifier
    physicality: Physicality
    discovered_at: datetime
    discovery_evidence: ArtifactBinding

    @field_validator("discovered_at")
    @classmethod
    def discovery_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("candidate discovery timestamp must be timezone-aware")
        return value


class AcquisitionCandidateRegistry(FrozenModel):
    schema_version: Literal["fieldtrue.acquisition-candidate-registry.v1"] = (
        "fieldtrue.acquisition-candidate-registry.v1"
    )
    registry_id: Identifier
    produced_at: datetime
    registrar_id: Identifier
    candidates: tuple[CandidateIncidentRoot, ...] = Field(min_length=1)
    attestation: SignedAttestation

    @model_validator(mode="after")
    def candidate_roots_are_unique(self) -> Self:
        if self.produced_at.tzinfo is None or self.produced_at.utcoffset() is None:
            raise ValueError("candidate registry timestamp must be timezone-aware")
        incident_ids = [candidate.incident_id for candidate in self.candidates]
        root_ids = [candidate.root_incident_group_id for candidate in self.candidates]
        if len(incident_ids) != len(set(incident_ids)):
            raise ValueError("candidate incident IDs must be unique")
        if len(root_ids) != len(set(root_ids)):
            raise ValueError("candidate physical roots must be unique")
        return self


class PhysicalProvenanceRecord(FrozenModel):
    schema_version: Literal["fieldtrue.physical-provenance.v1"] = "fieldtrue.physical-provenance.v1"
    provenance_id: Identifier
    incident_id: Identifier
    root_incident_group_id: Identifier
    acquisition_session_id: Identifier
    independence_group_id: Identifier
    acquisition_lineage_id: Identifier
    source_id: Identifier
    source_resource_id: Identifier
    system_family: str = Field(min_length=1)
    hardware_id: str = Field(min_length=1)
    configuration_id: str = Field(min_length=1)
    environment_id: str = Field(min_length=1)
    site_id: str = Field(min_length=1)
    acquired_at: datetime
    independently_initiated: bool
    baseline_restored_before: bool
    initiation_evidence: ArtifactBinding
    baseline_evidence: ArtifactBinding
    physical_capture: ArtifactBinding
    attestation: SignedAttestation

    @field_validator("acquired_at")
    @classmethod
    def acquisition_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("physical acquisition timestamp must be timezone-aware")
        return value


class DiagnosticActionContract(FrozenModel):
    schema_version: Literal["fieldtrue.diagnostic-action-contract.v1"] = (
        "fieldtrue.diagnostic-action-contract.v1"
    )
    action_contract_id: Identifier
    incident_id: Identifier
    test_id: Identifier
    command_sha256: Sha256
    expected_realized_action_sha256: Sha256
    parameter_bounds: ArtifactBinding
    abort_specification: ArtifactBinding
    max_duration_seconds: float = Field(gt=0)
    max_risk: float = Field(ge=0.0, le=1.0)
    max_cost_usd: Money
    committed_at: datetime

    @field_validator("committed_at")
    @classmethod
    def commitment_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("diagnostic action commitment must be timezone-aware")
        return value


class DiagnosticExecution(FrozenModel):
    schema_version: Literal["fieldtrue.diagnostic-execution.v1"] = (
        "fieldtrue.diagnostic-execution.v1"
    )
    execution_id: Identifier
    incident_id: Identifier
    test_id: Identifier
    executor_id: Identifier
    candidate_sha256: Sha256
    safety_envelope_sha256: Sha256
    observation_sha256: Sha256
    authority: ExecutionAuthority
    started_at: datetime
    commanded_at: datetime
    acknowledged_at: datetime
    realized_at: datetime
    finished_at: datetime
    approval_receipt_hash: Sha256
    action_contract: ArtifactBinding
    command: ArtifactBinding
    acknowledgement: ArtifactBinding
    realized_action: ArtifactBinding
    constraint_margins: ArtifactBinding
    abort_log: ArtifactBinding
    direct_cost_usd: Money
    adverse_events: tuple[str, ...] = ()
    attestation: SignedAttestation

    @model_validator(mode="after")
    def diagnostic_execution_is_ordered(self) -> Self:
        values = (
            self.started_at,
            self.commanded_at,
            self.acknowledged_at,
            self.realized_at,
            self.finished_at,
        )
        if any(value.tzinfo is None or value.utcoffset() is None for value in values):
            raise ValueError("diagnostic execution timestamps must be timezone-aware")
        if any(right < left for left, right in pairwise(values)):
            raise ValueError("diagnostic execution timestamps are not ordered")
        if self.realized_at == self.commanded_at:
            raise ValueError("commanded and realized action times must be distinct")
        return self


class IncidentResourcePlane(FrozenModel):
    schema_version: Literal["fieldtrue.incident-resource-plane.v1"] = (
        "fieldtrue.incident-resource-plane.v1"
    )
    incident_id: Identifier
    engineering_seconds: float | None = Field(default=None, ge=0)
    diagnostic_test_seconds: float | None = Field(default=None, ge=0)
    recovery_seconds: float | None = Field(default=None, ge=0)
    downtime_seconds: float | None = Field(default=None, ge=0)
    compute_seconds: float | None = Field(default=None, ge=0)
    diagnostic_action_cost_usd: Money | None = None
    recovery_action_cost_usd: Money | None = None
    realized_risk: float | None = Field(default=None, ge=0.0, le=1.0)
    measurement_artifact: ArtifactBinding


class RecoveryExecution(FrozenModel):
    schema_version: Literal["fieldtrue.recovery-execution.v1"] = "fieldtrue.recovery-execution.v1"
    execution_id: Identifier
    recovery_id: Identifier
    incident_id: Identifier
    executor_id: Identifier
    plan_sha256: Sha256
    authority: ExecutionAuthority
    started_at: datetime
    finished_at: datetime
    approval_receipt_hash: Sha256
    commanded_action: ArtifactBinding
    realized_action: ArtifactBinding
    cost_usd: Money
    adverse_events: tuple[str, ...] = ()
    attestation: SignedAttestation

    @model_validator(mode="after")
    def recovery_execution_is_ordered(self) -> Self:
        for value in (self.started_at, self.finished_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("recovery timestamps must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("recovery cannot finish before it starts")
        return self


class SettledOutcomeRecord(FrozenModel):
    schema_version: Literal["fieldtrue.settled-outcome.v1"] = "fieldtrue.settled-outcome.v1"
    outcome_id: Identifier
    incident_id: Identifier
    recovery_id: Identifier
    selected_test_sha256: Sha256
    test_observation_sha256: Sha256
    diagnostic_execution_sha256: Sha256
    recovery_execution_sha256: Sha256
    outcome_authority_id: Identifier
    outcome_authority_independence_group: Identifier
    settled_predicate: ArtifactBinding
    predicate_evaluation: ArtifactBinding
    recurrence_evidence: ArtifactBinding
    window_started_at: datetime
    window_finished_at: datetime
    recurrence_checked: bool
    constraints_satisfied: bool
    action_valid: bool
    target_valid: bool
    settled_success: bool
    outcome_artifacts: tuple[ArtifactBinding, ...] = Field(min_length=1)
    attestation: SignedAttestation

    @model_validator(mode="after")
    def settled_window_is_ordered(self) -> Self:
        for value in (self.window_started_at, self.window_finished_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("settled-window timestamps must be timezone-aware")
        if self.window_finished_at <= self.window_started_at:
            raise ValueError("settled window must have positive duration")
        return self


class IncidentDossier(FrozenModel):
    schema_version: Literal["fieldtrue.incident-dossier.v1"] = "fieldtrue.incident-dossier.v1"
    dossier_id: Identifier
    source_id: Identifier
    source_manifest_sha256: Sha256
    evidence_track: EvidenceTrack
    group: IncidentGroupRecord
    roles: tuple[RoleAssignment, ...]
    reviews: tuple[BoundReview, ...]
    clocks: tuple[ClockMap, ...] = Field(min_length=1)
    evidence_times: tuple[EvidenceTimeBinding, ...] = Field(min_length=1)
    timeline: IncidentTimeline
    physical_provenance: ArtifactBinding
    plane_separation_receipt: ArtifactBinding
    model_visible_projection: ArtifactBinding
    evidence_bundle: ArtifactBinding
    evidence_sequence: ArtifactBinding
    truth_record: ArtifactBinding
    truth_custody: ArtifactBinding
    hypothesis_set: ArtifactBinding
    discriminating_test: ArtifactBinding
    selected_test: ArtifactBinding
    safety_envelope: ArtifactBinding
    test_approval: ArtifactBinding
    test_observation: ArtifactBinding
    diagnostic_execution: ArtifactBinding
    recovery_plan: ArtifactBinding
    recovery_approval: ArtifactBinding
    recovery_execution: ArtifactBinding
    settled_outcome: ArtifactBinding
    verification_result: ArtifactBinding
    incident_resource_plane: ArtifactBinding

    @model_validator(mode="after")
    def dossier_registries_are_complete(self) -> Self:
        roles = [item.role for item in self.roles]
        if len(roles) != len(set(roles)) or set(roles) != set(RoleKind):
            raise ValueError("dossier must assign every role exactly once")
        reviews = [item.purpose for item in self.reviews]
        if len(reviews) != len(set(reviews)) or set(reviews) != set(ReviewPurpose):
            raise ValueError("dossier must bind every review purpose exactly once")
        clock_ids = [item.clock_domain for item in self.clocks]
        if len(clock_ids) != len(set(clock_ids)):
            raise ValueError("clock domains must be unique")
        evidence_ids = [item.evidence_id for item in self.evidence_times]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence time bindings must be unique")
        return self


class ResourceCeiling(FrozenModel):
    max_cpu_seconds: float = Field(gt=0)
    max_wall_seconds: float = Field(gt=0)
    max_peak_memory_bytes: int = Field(gt=0)
    max_downloaded_bytes: int = Field(ge=0)
    max_peak_staged_bytes: int = Field(ge=0)
    max_derived_bytes: int = Field(ge=0)
    max_gpu_seconds: float = Field(ge=0)
    max_cloud_jobs: int = Field(ge=0)
    max_paid_calls: int = Field(ge=0)
    max_cost_usd: Money


class ResourceUsage(FrozenModel):
    schema_version: Literal["fieldtrue.resource-usage.v1"] = "fieldtrue.resource-usage.v1"
    cpu_seconds: float = Field(ge=0)
    wall_seconds: float = Field(ge=0)
    peak_memory_bytes: int = Field(ge=0)
    downloaded_bytes: int = Field(ge=0)
    peak_staged_bytes: int = Field(ge=0)
    derived_bytes: int = Field(ge=0)
    gpu_seconds: float = Field(ge=0)
    cloud_jobs: int = Field(ge=0)
    paid_calls: int = Field(ge=0)
    cost_usd: Money
    measured_at: datetime
    measurement_method: str = Field(min_length=1)
    measurement_artifact: ArtifactBinding
    measurer_id: Identifier
    attestation: SignedAttestation

    @field_validator("measured_at")
    @classmethod
    def measured_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("resource measurement timestamp must be timezone-aware")
        return value


class AcquisitionSplitLocks(FrozenModel):
    schema_version: Literal["fieldtrue.acquisition-split-locks.v1"] = (
        "fieldtrue.acquisition-split-locks.v1"
    )
    hardware_family: ArtifactBinding
    hardware_identity: ArtifactBinding
    fault_family: ArtifactBinding


_REQUIRED_CONTROL_IDS = (
    "valid-conjunctive-pilot",
    "count-intersection",
    "root-clone-inflation",
    "simulated-as-physical",
    "rights-conflict",
    "metadata-leakage",
    "one-modality",
    "duplicate-modality",
    "stationary-image-proxy",
    "shuffled-modality",
    "clock-transform",
    "truth-chronology",
    "known-only-hypotheses",
    "role-overlap",
    "forged-approval",
    "recommendation-only-diagnostic",
    "asserted-recovery",
    "shortcut-baseline",
    "no-op-comparator",
    "random-safe-comparator",
    "cheapest-safe-comparator",
    "wrong-safe-comparator",
)

_CONTROL_REQUIREMENTS: dict[str, tuple[str, str, str, str | None]] = {
    "valid-conjunctive-pilot": (
        "tests/unit/test_acquisition.py::test_complete_conjunctive_pilot_passes",
        "PASS_PILOT",
        "admission",
        None,
    ),
    "count-intersection": (
        "tests/unit/test_acquisition.py::test_29_complete_dossiers_are_blocked_not_promoted_by_rows",
        "BLOCKED_ACQUISITION",
        "conjunctive-coverage",
        "count-intersection",
    ),
    "root-clone-inflation": (
        "tests/unit/test_acquisition.py::test_cloned_full_capture_is_rejected_after_valid_resigning",
        "INVALID",
        "artifact-integrity",
        "duplicate-full-capture",
    ),
    "simulated-as-physical": (
        "tests/unit/test_acquisition.py::test_simulated_event_cannot_enter_physical_admission",
        "INVALID",
        "artifact-integrity",
        "nonphysical-root",
    ),
    "rights-conflict": (
        "tests/unit/test_acquisition.py::test_commercial_research_right_unknown_is_a_distinct_block",
        "BLOCKED_RIGHTS",
        "source-rights",
        "commercial-research-rights",
    ),
    "metadata-leakage": (
        "tests/unit/test_acquisition.py::test_truth_metadata_in_model_visible_plane_is_invalid",
        "INVALID",
        "artifact-integrity",
        "model-visible-forbidden-field",
    ),
    "one-modality": (
        "tests/unit/test_acquisition.py::test_one_modality_case_is_invalid",
        "INVALID",
        "artifact-integrity",
        "one-modality",
    ),
    "duplicate-modality": (
        "tests/unit/test_acquisition.py::test_duplicated_modality_content_is_rejected_by_projection_contract",
        "INVALID",
        "artifact-integrity",
        "duplicate-modality-content",
    ),
    "stationary-image-proxy": (
        "tests/unit/test_acquisition.py::test_stationary_image_proxy_is_invalid",
        "INVALID",
        "artifact-integrity",
        "stationary-image-proxy",
    ),
    "shuffled-modality": (
        "tests/unit/test_acquisition.py::test_shuffled_modality_order_is_invalid",
        "INVALID",
        "artifact-integrity",
        "shuffled-modality",
    ),
    "clock-transform": (
        "tests/unit/test_acquisition.py::test_unbounded_clock_transform_is_invalid",
        "INVALID",
        "artifact-integrity",
        "clock-transform-bound",
    ),
    "truth-chronology": (
        "tests/unit/test_acquisition.py::test_truth_custody_opened_before_commitments_is_invalid",
        "INVALID",
        "artifact-integrity",
        "truth-chronology",
    ),
    "known-only-hypotheses": (
        "tests/unit/test_acquisition.py::test_known_only_hypothesis_set_is_invalid",
        "INVALID",
        "artifact-integrity",
        "known-only-hypotheses",
    ),
    "role-overlap": (
        "tests/unit/test_acquisition.py::test_outcome_verifier_independence_overlap_is_rejected",
        "INVALID",
        "artifact-integrity",
        "forbidden-role-overlap",
    ),
    "forged-approval": (
        "tests/unit/test_acquisition.py::test_forged_test_approval_is_invalid",
        "INVALID",
        "artifact-integrity",
        "forged-approval",
    ),
    "recommendation-only-diagnostic": (
        "tests/unit/test_acquisition.py::test_recommendation_only_diagnostic_without_distinct_realization_is_rejected",
        "INVALID",
        "artifact-integrity",
        "diagnostic-realization",
    ),
    "asserted-recovery": (
        "tests/unit/test_acquisition.py::test_asserted_recovery_without_distinct_realization_is_invalid",
        "INVALID",
        "artifact-integrity",
        "recovery-realization",
    ),
    "shortcut-baseline": (
        "tests/unit/test_acquisition.py::test_resolving_shortcut_kills_the_construct",
        "KILL_CONSTRUCT",
        "shortcut-baseline",
        "shortcut-resolves-mechanism",
    ),
    "no-op-comparator": (
        "tests/unit/test_acquisition.py::test_no_op_comparator_omission_is_invalid",
        "INVALID",
        "artifact-integrity",
        "missing-no-op-comparator",
    ),
    "random-safe-comparator": (
        "tests/unit/test_acquisition.py::test_random_safe_comparator_omission_is_invalid",
        "INVALID",
        "artifact-integrity",
        "missing-random-safe-comparator",
    ),
    "cheapest-safe-comparator": (
        "tests/unit/test_acquisition.py::test_cheapest_safe_comparator_omission_is_invalid",
        "INVALID",
        "artifact-integrity",
        "missing-cheapest-safe-comparator",
    ),
    "wrong-safe-comparator": (
        "tests/unit/test_acquisition.py::test_wrong_safe_comparator_omission_is_invalid",
        "INVALID",
        "artifact-integrity",
        "missing-wrong-safe-comparator",
    ),
}


class AdmissionControlResult(FrozenModel):
    control_id: Identifier
    fixture_sha256: Sha256
    report_sha256: Sha256
    evidence: ArtifactBinding
    pytest_node_id: str = Field(pattern=r"^tests/unit/test_acquisition\.py::test_[a-z0-9_]+$")
    expected_verdict: Literal[
        "PASS_PILOT",
        "BLOCKED_ACQUISITION",
        "BLOCKED_RIGHTS",
        "INVALID",
        "KILL_CONSTRUCT",
    ]
    observed_verdict: Literal[
        "PASS_PILOT",
        "BLOCKED_ACQUISITION",
        "BLOCKED_RIGHTS",
        "INVALID",
        "KILL_CONSTRUCT",
    ]
    expected_gate_id: Identifier
    observed_gate_id: Identifier
    expected_failure_code: Identifier | None
    observed_failure_code: Identifier | None
    passed: bool


class AdmissionControlSuiteReceipt(FrozenModel):
    schema_version: Literal["fieldtrue.admission-control-suite-receipt.v2"] = (
        "fieldtrue.admission-control-suite-receipt.v2"
    )
    suite_id: Literal["iter001-admission-controls-v1"]
    authority_profile: Literal["test_fixture"]
    acquisition_contract_git_blob: GitObjectId
    acquisition_contract_sha256: Sha256
    validator_git_blob: GitObjectId
    validator_source_sha256: Sha256
    fixture_builder_git_blob: GitObjectId
    fixture_builder_sha256: Sha256
    control_test_git_blob: GitObjectId
    control_test_sha256: Sha256
    generator_git_blob: GitObjectId
    generator_sha256: Sha256
    dependency_lock_git_blob: GitObjectId
    dependency_lock_sha256: Sha256
    execution_commit: GitObjectId
    execution_tree: GitObjectId
    execution_manifest: ArtifactBinding
    executed_at: datetime
    controls: tuple[AdmissionControlResult, ...]
    attestation: SignedAttestation

    @model_validator(mode="after")
    def suite_is_complete_and_passing(self) -> Self:
        if self.executed_at.tzinfo is None or self.executed_at.utcoffset() is None:
            raise ValueError("control-suite timestamp must be timezone-aware")
        identifiers = tuple(control.control_id for control in self.controls)
        if identifiers != _REQUIRED_CONTROL_IDS:
            raise ValueError("control suite does not cover the exact frozen control set")
        node_ids = [control.pytest_node_id for control in self.controls]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("control suite pytest nodes must be unique")
        for control in self.controls:
            node_id, verdict, gate_id, failure_code = _CONTROL_REQUIREMENTS[control.control_id]
            if (
                control.pytest_node_id != node_id
                or control.expected_verdict != verdict
                or control.expected_gate_id != gate_id
                or control.expected_failure_code != failure_code
            ):
                raise ValueError("control suite differs from the frozen control requirement")
            if (
                not control.passed
                or control.observed_verdict != control.expected_verdict
                or control.observed_gate_id != control.expected_gate_id
                or control.observed_failure_code != control.expected_failure_code
            ):
                raise ValueError("control suite contains an unexpected outcome")
        return self


_REQUIRED_SHORTCUT_RULE_IDS = (
    "source-identity",
    "task-identity",
    "system-identity",
    "site-identity",
    "path-and-filename",
    "timestamp",
    "fault-label",
    "annotation",
    "random-identity-embedding",
    "cheapest-deterministic-evidence-only",
)


class ShortcutRuleResult(FrozenModel):
    rule_id: Identifier
    implementation: ArtifactBinding
    evaluation: ArtifactBinding
    truth_access: bool
    resolves_mechanism_without_action: bool


class ShortcutBaselineReport(FrozenModel):
    schema_version: Literal["fieldtrue.shortcut-baseline-report.v1"] = (
        "fieldtrue.shortcut-baseline-report.v1"
    )
    report_id: Identifier
    incident_ids_sha256: Sha256
    evaluated_at: datetime
    results: tuple[ShortcutRuleResult, ...]
    statistician_id: Identifier
    attestation: SignedAttestation

    @model_validator(mode="after")
    def shortcut_registry_is_exact(self) -> Self:
        if self.evaluated_at.tzinfo is None or self.evaluated_at.utcoffset() is None:
            raise ValueError("shortcut report timestamp must be timezone-aware")
        identifiers = tuple(result.rule_id for result in self.results)
        if identifiers != _REQUIRED_SHORTCUT_RULE_IDS:
            raise ValueError("shortcut report does not cover the exact frozen rule set")
        if any(result.truth_access for result in self.results):
            raise ValueError("shortcut rules cannot access truth")
        return self


_REQUIRED_COMPARATOR_KINDS = (
    "no_op",
    "random_safe",
    "cheapest_safe",
    "wrong_safe",
)


class InterventionComparator(FrozenModel):
    kind: Literal["no_op", "random_safe", "cheapest_safe", "wrong_safe"]
    implementation: ArtifactBinding
    evaluation_plan: ArtifactBinding
    included: bool


class InterventionComparatorRegistry(FrozenModel):
    schema_version: Literal["fieldtrue.intervention-comparator-registry.v1"] = (
        "fieldtrue.intervention-comparator-registry.v1"
    )
    registry_id: Identifier
    incident_ids_sha256: Sha256
    committed_at: datetime
    statistician_id: Identifier
    comparators: tuple[InterventionComparator, ...]
    attestation: SignedAttestation

    @model_validator(mode="after")
    def comparator_set_is_exact(self) -> Self:
        if self.committed_at.tzinfo is None or self.committed_at.utcoffset() is None:
            raise ValueError("comparator-registry timestamp must be timezone-aware")
        if tuple(comparator.kind for comparator in self.comparators) != _REQUIRED_COMPARATOR_KINDS:
            raise ValueError("intervention comparator registry is incomplete")
        if not all(comparator.included for comparator in self.comparators):
            raise ValueError("an intervention comparator is omitted")
        return self


class ProtocolReviewRecord(FrozenModel):
    domain: Literal["aerospace", "robotics"]
    reviewer_id: Identifier
    review_artifact: ArtifactBinding
    reviewed_at: datetime
    approved_for_physical_execution: bool
    attestation: SignedAttestation

    @field_validator("reviewed_at")
    @classmethod
    def protocol_review_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("protocol-review timestamp must be timezone-aware")
        return value


class ProtocolReviewRegistry(FrozenModel):
    schema_version: Literal["fieldtrue.protocol-review-registry.v1"] = (
        "fieldtrue.protocol-review-registry.v1"
    )
    reviews: tuple[ProtocolReviewRecord, ...]

    @model_validator(mode="after")
    def domains_are_complete(self) -> Self:
        domains = [review.domain for review in self.reviews]
        if sorted(domains) != ["aerospace", "robotics"]:
            raise ValueError("protocol reviews must cover aerospace and robotics exactly once")
        if not all(review.approved_for_physical_execution for review in self.reviews):
            raise ValueError("protocol review has not approved physical execution")
        return self


_ITER001_CANONICAL_TRUST_ANCHOR_PUBLIC_KEY = (
    "b0f514d7b91caa7c43ea58ffae42ebeea48164d24948723a8c805f780df38962"
)


class AcquisitionContract(FrozenModel):
    schema_version: Literal["fieldtrue.acquisition-contract.v1"] = (
        "fieldtrue.acquisition-contract.v1"
    )
    authority_profile: Literal["canonical", "test_fixture"]
    control_authority_status: Literal["bootstrap", "sealed", "test_fixture"]
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"]
    preregistration_path: Literal[
        "experiments/iter001_physical_causal_evidence_acquisition/HYPOTHESIS.md"
    ]
    preregistration_commit: GitObjectId
    preregistration_sha256: Sha256
    required_permissions: tuple[PermissionKind, ...]
    minimum_complete_physical_incidents: int
    minimum_system_families: int
    minimum_hardware_identities: int
    minimum_identities_per_system_family: int
    minimum_fault_families: int
    minimum_incidents_per_system_family: int
    minimum_incidents_per_fault_family: int
    minimum_incidents_per_hardware_identity: int
    maximum_family_share: float
    minimum_faults_per_system_family: int
    minimum_system_families_per_fault: int
    required_domains: tuple[SystemDomain, ...]
    minimum_operational_modalities: int
    max_clock_alignment_error_ns: int = Field(ge=0)
    max_clock_missing_fraction: float = Field(ge=0.0, le=1.0)
    trust_anchor_public_key: Ed25519PublicKey
    validator_git_blob: GitObjectId
    validator_source_sha256: Sha256
    dependency_lock_sha256: Sha256
    control_suite_sha256: Sha256
    resource_ceiling: ResourceCeiling

    @model_validator(mode="after")
    def contract_matches_preregistration(self) -> Self:
        required_permissions = {
            PermissionKind.ACQUIRE,
            PermissionKind.PROCESS,
            PermissionKind.RETAIN_RAW,
            PermissionKind.RETAIN_DERIVED,
            PermissionKind.PUBLISH_METADATA,
            PermissionKind.INDEPENDENT_REVIEW,
            PermissionKind.REDISTRIBUTE_DERIVED,
            PermissionKind.COMMERCIAL_RESEARCH,
        }
        exact = {
            "minimum_complete_physical_incidents": 30,
            "minimum_system_families": 3,
            "minimum_hardware_identities": 6,
            "minimum_identities_per_system_family": 2,
            "minimum_fault_families": 3,
            "minimum_incidents_per_system_family": 6,
            "minimum_incidents_per_fault_family": 6,
            "minimum_incidents_per_hardware_identity": 3,
            "maximum_family_share": 0.5,
            "minimum_faults_per_system_family": 2,
            "minimum_system_families_per_fault": 2,
            "minimum_operational_modalities": 2,
            "max_clock_alignment_error_ns": 100_000_000,
            "max_clock_missing_fraction": 0.05,
        }
        for field_name, expected in exact.items():
            if getattr(self, field_name) != expected:
                raise ValueError(f"{field_name} cannot weaken or alter the frozen preregistration")
        if set(self.required_permissions) != required_permissions:
            raise ValueError("required permissions do not match the preregistration")
        if set(self.required_domains) != {SystemDomain.AEROSPACE, SystemDomain.ROBOTICS}:
            raise ValueError("aerospace and robotics domains are both required")
        if self.authority_profile == "canonical" and (
            self.preregistration_path
            != "experiments/iter001_physical_causal_evidence_acquisition/HYPOTHESIS.md"
            or self.preregistration_commit != "52d71e16a75df12adf47e943fd5c329f6e04d5c0"
            or self.preregistration_sha256
            != "47a1920b1b5326601c7404d17a6aac0df3309c2433fa76f56f0dffedf2511ad8"
            or self.trust_anchor_public_key != _ITER001_CANONICAL_TRUST_ANCHOR_PUBLIC_KEY
        ):
            raise ValueError(
                "canonical authority differs from its frozen trust and preregistration"
            )
        if self.authority_profile == "test_fixture" and self.control_authority_status != (
            "test_fixture"
        ):
            raise ValueError("test-fixture contracts require test-fixture control authority")
        if (
            self.authority_profile == "test_fixture"
            and self.trust_anchor_public_key == _ITER001_CANONICAL_TRUST_ANCHOR_PUBLIC_KEY
        ):
            raise ValueError("test-fixture contracts require a distinct noncanonical trust key")
        if self.authority_profile == "canonical" and self.control_authority_status == (
            "test_fixture"
        ):
            raise ValueError("canonical contracts cannot use test-fixture control authority")
        if self.control_authority_status == "sealed" and (
            self.validator_git_blob == "0" * 40
            or self.validator_source_sha256 == "0" * 64
            or self.control_suite_sha256 == "0" * 64
        ):
            raise ValueError("sealed control authority contains a placeholder binding")
        ceiling = self.resource_ceiling
        if (
            ceiling.max_cpu_seconds != 14_400
            or ceiling.max_wall_seconds != 7_200
            or ceiling.max_peak_memory_bytes != 16 * 1024**3
            or ceiling.max_downloaded_bytes != 1024**3
            or ceiling.max_peak_staged_bytes != 2 * 1024**3
            or ceiling.max_derived_bytes != 2 * 1024**3
            or ceiling.max_gpu_seconds != 0
            or ceiling.max_cloud_jobs != 0
            or ceiling.max_paid_calls != 0
            or Decimal(ceiling.max_cost_usd) != 0
        ):
            raise ValueError("resource ceiling does not match the preregistration")
        return self


class AcquisitionGateResult(FrozenModel):
    gate_id: Identifier
    status: Literal["pass", "blocked", "invalid"]
    observed: Any
    requirement: str = Field(min_length=1)
    detail: str = Field(min_length=1)


_ACTIONS = {
    "PASS_PILOT": "Freeze per-axis splits and preregister the cheap deterministic baseline phase.",
    "BLOCKED_ACQUISITION": (
        "Acquire additional prospective physical dossiers under separate resource and safety "
        "authorities; training remains forbidden."
    ),
    "BLOCKED_RIGHTS": (
        "Resolve rights in writing or replace the affected source; staging remains forbidden."
    ),
    "KILL_CONSTRUCT": (
        "Stop learned-model work and preserve the deterministic shortcut result as a full-weight "
        "construct failure."
    ),
    "INVALID": (
        "Repair integrity, chronology, role, approval, or proof defects under an explicit "
        "amendment."
    ),
}


class AcquisitionAdmissionReport(FrozenModel):
    schema_version: Literal["fieldtrue.acquisition-admission-report.v1"] = (
        "fieldtrue.acquisition-admission-report.v1"
    )
    authority_profile: Literal["canonical", "test_fixture"]
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"]
    contract_sha256: Sha256
    validator_git_blob: GitObjectId
    validator_source_sha256: Sha256
    trust_registry_sha256: Sha256
    control_suite_sha256: Sha256
    candidate_registry_sha256: Sha256
    comparator_registry_sha256: Sha256
    split_locks_sha256: Sha256
    corpus_sha256: Sha256
    resource_usage_sha256: Sha256
    candidate_incident_ids: tuple[Identifier, ...]
    eligible_incident_ids: tuple[Identifier, ...]
    gates: tuple[AcquisitionGateResult, ...]
    verdict: Literal[
        "PASS_PILOT",
        "BLOCKED_ACQUISITION",
        "BLOCKED_RIGHTS",
        "KILL_CONSTRUCT",
        "INVALID",
    ]
    authorized_next_action: str
    forbidden_next_actions: tuple[str, ...]

    @model_validator(mode="after")
    def authority_is_derived_from_verdict(self) -> Self:
        gate_ids = tuple(gate.gate_id for gate in self.gates)
        expected_gate_ids = (
            "artifact-integrity",
            "source-rights",
            "resource-ceiling",
            "conjunctive-coverage",
            "shortcut-baseline",
        )
        if gate_ids != expected_gate_ids:
            raise ValueError("admission report gate registry is not exact")
        gates = {gate.gate_id: gate for gate in self.gates}
        if (
            gates["artifact-integrity"].status not in {"pass", "invalid"}
            or gates["resource-ceiling"].status not in {"pass", "invalid"}
            or gates["source-rights"].status not in {"pass", "blocked"}
            or gates["conjunctive-coverage"].status not in {"pass", "blocked"}
            or gates["shortcut-baseline"].status not in {"pass", "blocked"}
        ):
            raise ValueError("admission report uses an impossible gate status")
        derived_verdict = (
            "INVALID"
            if gates["artifact-integrity"].status != "pass"
            or gates["resource-ceiling"].status != "pass"
            else "BLOCKED_RIGHTS"
            if gates["source-rights"].status != "pass"
            else "KILL_CONSTRUCT"
            if gates["conjunctive-coverage"].status == "pass"
            and gates["shortcut-baseline"].status == "blocked"
            else "PASS_PILOT"
            if gates["conjunctive-coverage"].status == "pass"
            else "BLOCKED_ACQUISITION"
        )
        if self.verdict != derived_verdict:
            raise ValueError("admission verdict does not follow from gate statuses")
        if (
            self.verdict in {"PASS_PILOT", "KILL_CONSTRUCT"}
            and len(self.eligible_incident_ids) < 30
        ):
            raise ValueError("admission verdict lacks the minimum eligible incident count")
        if not set(self.eligible_incident_ids).issubset(self.candidate_incident_ids):
            raise ValueError("eligible incidents are absent from the candidate registry")
        if len(self.candidate_incident_ids) != len(set(self.candidate_incident_ids)):
            raise ValueError("admission report candidate incidents are not unique")
        if len(self.eligible_incident_ids) != len(set(self.eligible_incident_ids)):
            raise ValueError("admission report eligible incidents are not unique")
        if self.authorized_next_action != _ACTIONS[self.verdict]:
            raise ValueError("admission action does not follow from the verdict")
        expected = (
            "GPU or learned-model training",
            "diagnosis, recovery, safety, transfer, product, or economic-value claim",
            "live robot, flight, spacecraft, or destructive authority",
        )
        if self.forbidden_next_actions != expected:
            raise ValueError("admission forbidden-action contract is not exact")
        return self


T = TypeVar("T", bound=BaseModel)

_MIN_PHYSICAL_CAPTURE_BYTES = 512
_MIN_MODEL_VISIBLE_BYTES = 512
_FINGERPRINT_SAMPLE_BYTES = 512 * 1024
_FINGERPRINT_CHUNK_BYTES = 64
_NEAR_DUPLICATE_JACCARD = 0.90
_LEAKAGE_SCAN_CHUNK_BYTES = 64 * 1024
_MAX_BOUND_MODEL_BYTES = 16 * 1024 * 1024
_MAX_LEAKAGE_ARTIFACT_BYTES = 256 * 1024 * 1024
_MAX_LEAKAGE_INPUT_BYTES = 512 * 1024 * 1024
_MIN_JSON_IDENTITY_TOKEN_CHARS = 4
_MIN_OPAQUE_IDENTITY_TOKEN_BYTES = 8
_TIME_VARYING_SENSOR_MODALITIES = {
    Modality.TELEMETRY,
    Modality.VIDEO,
    Modality.AUDIO,
    Modality.NDE,
}
_ACTION_OR_EVENT_MODALITIES = {
    Modality.COMMAND_LOG,
    Modality.EVENT_LOG,
}


_STABLE_ARTIFACT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _artifact_metadata_matches(first: os.stat_result, *others: os.stat_result) -> bool:
    return all(
        getattr(first, field) == getattr(other, field)
        for other in others
        for field in _STABLE_ARTIFACT_FIELDS
    )


def _artifact_directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise AcquisitionAuditError("artifact consumption requires directory no-follow support")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _artifact_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise AcquisitionAuditError("artifact consumption requires file no-follow support")
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)


@contextmanager
def _open_bound_artifact(root: Path, binding: ArtifactBinding) -> Iterator[BinaryIO]:
    """Open one artifact through a stable no-follow descriptor chain."""

    pure = PurePosixPath(binding.path)
    if (
        pure.is_absolute()
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
        or pure.as_posix() != binding.path
    ):
        raise AcquisitionAuditError(f"unsafe artifact path: {binding.path}")

    directory_descriptors: list[tuple[int, os.stat_result, int | None, str | None]] = []
    file_descriptor: int | None = None
    handle: BinaryIO | None = None
    try:
        root_path = root.resolve(strict=True)
        root_lexical = root_path.lstat()
        root_descriptor = os.open(root_path, _artifact_directory_flags())
        root_opened = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_lexical.st_mode)
            or not stat.S_ISDIR(root_opened.st_mode)
            or not _artifact_metadata_matches(root_lexical, root_opened)
        ):
            os.close(root_descriptor)
            raise AcquisitionAuditError(f"unsafe artifact root: {binding.path}")
        directory_descriptors.append((root_descriptor, root_opened, None, None))

        for part in pure.parts[:-1]:
            parent_descriptor = directory_descriptors[-1][0]
            lexical = os.stat(part, dir_fd=parent_descriptor, follow_symlinks=False)
            child_descriptor = os.open(
                part,
                _artifact_directory_flags(),
                dir_fd=parent_descriptor,
            )
            opened = os.fstat(child_descriptor)
            if (
                not stat.S_ISDIR(lexical.st_mode)
                or not stat.S_ISDIR(opened.st_mode)
                or not _artifact_metadata_matches(lexical, opened)
            ):
                os.close(child_descriptor)
                raise AcquisitionAuditError(f"unsafe artifact path: {binding.path}")
            directory_descriptors.append((child_descriptor, opened, parent_descriptor, part))

        parent_descriptor = directory_descriptors[-1][0]
        filename = pure.parts[-1]
        lexical = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(lexical.st_mode)
            or lexical.st_nlink != 1
            or lexical.st_size != binding.bytes
        ):
            raise AcquisitionAuditError(f"artifact binding mismatch: {binding.path}")
        file_descriptor = os.open(
            filename,
            _artifact_file_flags(),
            dir_fd=parent_descriptor,
        )
        opened = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not _artifact_metadata_matches(lexical, opened)
        ):
            raise AcquisitionAuditError(f"artifact changed before open: {binding.path}")
        handle = os.fdopen(file_descriptor, "rb", closefd=False)
        try:
            yield handle
        finally:
            after = os.fstat(file_descriptor)
            current = os.stat(filename, dir_fd=parent_descriptor, follow_symlinks=False)
            if (
                not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
                or not _artifact_metadata_matches(opened, after, current)
            ):
                raise AcquisitionAuditError(f"artifact changed while consumed: {binding.path}")
            for descriptor, initial, parent, name in reversed(directory_descriptors):
                settled = os.fstat(descriptor)
                if parent is None:
                    current_directory = root_path.lstat()
                else:
                    assert name is not None
                    current_directory = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if not stat.S_ISDIR(current_directory.st_mode) or not _artifact_metadata_matches(
                    initial, settled, current_directory
                ):
                    raise AcquisitionAuditError(
                        f"artifact path changed while consumed: {binding.path}"
                    )
    except AcquisitionAuditError:
        raise
    except OSError as error:
        raise AcquisitionAuditError(f"artifact is unavailable or unsafe: {binding.path}") from error
    finally:
        if handle is not None:
            handle.close()
        if file_descriptor is not None:
            with suppress(OSError):
                os.close(file_descriptor)
        for descriptor, *_ in reversed(directory_descriptors):
            with suppress(OSError):
                os.close(descriptor)


def _assert_artifact_digest(binding: ArtifactBinding, digest: str, size: int) -> None:
    if size != binding.bytes or digest != binding.sha256:
        raise AcquisitionAuditError(f"artifact binding mismatch: {binding.path}")


def _read_bound_artifact(
    handle: BinaryIO,
    binding: ArtifactBinding,
    *,
    maximum_bytes: int,
) -> bytes:
    if binding.bytes > maximum_bytes:
        raise AcquisitionAuditError(f"artifact exceeds its consumption bound: {binding.path}")
    handle.seek(0)
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    size = 0
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
        chunks.append(chunk)
        size += len(chunk)
        if size > binding.bytes:
            raise AcquisitionAuditError(f"artifact binding mismatch: {binding.path}")
    _assert_artifact_digest(binding, digest.hexdigest(), size)
    return b"".join(chunks)


def _verify_bound_artifact(handle: BinaryIO, binding: ArtifactBinding) -> None:
    handle.seek(0)
    digest = hashlib.sha256()
    size = 0
    while chunk := handle.read(1024 * 1024):
        digest.update(chunk)
        size += len(chunk)
        if size > binding.bytes:
            raise AcquisitionAuditError(f"artifact binding mismatch: {binding.path}")
    _assert_artifact_digest(binding, digest.hexdigest(), size)


def _verify_artifact(root: Path, binding: ArtifactBinding) -> None:
    with _open_bound_artifact(root, binding) as handle:
        _verify_bound_artifact(handle, binding)


def _normalized_leakage_tokens(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value.casefold()
                for value in values
                if len(value.casefold()) >= _MIN_JSON_IDENTITY_TOKEN_CHARS
            }
        )
    )


def _json_without_duplicate_keys(data: bytes, path: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AcquisitionAuditError(f"duplicate JSON key in model input: {path}")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcquisitionAuditError(f"invalid UTF-8 JSON model input: {path}") from error


def _scan_json_leakage(
    value: Any,
    *,
    identity_tokens: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    forbidden: set[str] = set()
    matched: set[str] = set()

    def visit(node: Any, path: str) -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                child_path = f"{path}.{key}" if path else key
                normalized_key = key.casefold()
                if normalized_key in _FORBIDDEN_MODEL_VISIBLE_FIELDS:
                    forbidden.add(child_path)
                lexical = set(re.findall(r"[0-9a-z][0-9a-z._:/-]*", normalized_key))
                matched.update(token for token in identity_tokens if token in lexical)
                visit(child, child_path)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                visit(child, f"{path}[{index}]")
        elif isinstance(node, str):
            lexical = set(re.findall(r"[0-9a-z][0-9a-z._:/-]*", node.casefold()))
            matched.update(token for token in identity_tokens if token in lexical)

    visit(value, "$")
    return tuple(sorted(forbidden)), tuple(sorted(matched))


def _scan_opaque_identity_tokens(
    handle: BinaryIO,
    binding: ArtifactBinding,
    identity_tokens: tuple[str, ...],
) -> tuple[str, ...]:
    token_bytes = tuple(
        token.encode("utf-8")
        for token in identity_tokens
        if len(token.encode("utf-8")) >= _MIN_OPAQUE_IDENTITY_TOKEN_BYTES
    )
    if not token_bytes:
        _verify_bound_artifact(handle, binding)
        return ()
    overlap_bytes = max(len(token) for token in token_bytes) - 1
    matched: set[bytes] = set()
    overlap = b""
    digest = hashlib.sha256()
    size = 0
    handle.seek(0)
    while chunk := handle.read(_LEAKAGE_SCAN_CHUNK_BYTES):
        digest.update(chunk)
        size += len(chunk)
        if size > binding.bytes:
            raise AcquisitionAuditError(f"artifact binding mismatch: {binding.path}")
        window = (overlap + chunk).lower()
        matched.update(token for token in token_bytes if token in window)
        overlap = window[-overlap_bytes:] if overlap_bytes else b""
    _assert_artifact_digest(binding, digest.hexdigest(), size)
    return tuple(sorted(token.decode("utf-8") for token in matched))


def build_model_visible_leakage_scan(
    root: Path,
    *,
    incident_id: Identifier,
    artifacts: tuple[ArtifactBinding, ...],
    identity_values: tuple[str, ...],
) -> ModelVisibleLeakageScanReport:
    """Recompute a deterministic, bounded scan over the actual model-visible bytes."""
    if sum(binding.bytes for binding in artifacts) > _MAX_LEAKAGE_INPUT_BYTES:
        raise AcquisitionAuditError("model-visible leakage scan exceeds the input byte ceiling")
    identity_tokens = _normalized_leakage_tokens(identity_values)
    scans: list[LeakageArtifactScan] = []
    for binding in artifacts:
        if binding.bytes > _MAX_LEAKAGE_ARTIFACT_BYTES:
            raise AcquisitionAuditError(
                f"model-visible leakage scan exceeds artifact byte ceiling: {binding.path}"
            )
        with _open_bound_artifact(root, binding) as handle:
            if binding.media_type == "application/json":
                forbidden_paths, matched_tokens = _scan_json_leakage(
                    _json_without_duplicate_keys(
                        _read_bound_artifact(
                            handle,
                            binding,
                            maximum_bytes=_MAX_LEAKAGE_ARTIFACT_BYTES,
                        ),
                        binding.path,
                    ),
                    identity_tokens=identity_tokens,
                )
                scan_mode: Literal["utf8_json", "opaque_stream"] = "utf8_json"
            else:
                forbidden_paths = ()
                matched_tokens = _scan_opaque_identity_tokens(handle, binding, identity_tokens)
                scan_mode = "opaque_stream"
        scans.append(
            LeakageArtifactScan(
                artifact_sha256=binding.sha256,
                artifact_bytes=binding.bytes,
                media_type=binding.media_type,
                scan_mode=scan_mode,
                forbidden_field_paths=forbidden_paths,
                matched_identity_token_sha256=tuple(
                    sorted(sha256_bytes(token.encode("utf-8")) for token in matched_tokens)
                ),
            )
        )
    return ModelVisibleLeakageScanReport(
        incident_id=incident_id,
        input_artifacts_sha256=sha256_value(
            tuple(binding.model_dump(mode="json") for binding in artifacts)
        ),
        forbidden_field_set_sha256=sha256_value(_FORBIDDEN_MODEL_VISIBLE_FIELDS),
        identity_token_set_sha256=sha256_value(identity_tokens),
        artifact_scans=tuple(scans),
        leakage_detected=any(
            scan.forbidden_field_paths or scan.matched_identity_token_sha256 for scan in scans
        ),
    )


def _bounded_artifact_sample(root: Path, binding: ArtifactBinding) -> bytes:
    with _open_bound_artifact(root, binding) as handle:
        if binding.bytes <= _FINGERPRINT_SAMPLE_BYTES:
            return _read_bound_artifact(
                handle,
                binding,
                maximum_bytes=_FINGERPRINT_SAMPLE_BYTES,
            )
        _verify_bound_artifact(handle, binding)
        chunk_size = _FINGERPRINT_SAMPLE_BYTES // 16
        offsets = [round(index * (binding.bytes - chunk_size) / 15) for index in range(16)]
        samples: list[bytes] = []
        for offset in offsets:
            handle.seek(offset)
            sample = handle.read(chunk_size)
            if len(sample) != chunk_size:
                raise AcquisitionAuditError(f"artifact changed while sampled: {binding.path}")
            samples.append(sample)
        return b"".join(samples)


def _ordered_chunk_hashes(
    root: Path,
    binding: ArtifactBinding,
    chunk_bytes: int,
) -> tuple[str, ...]:
    if chunk_bytes <= 0 or chunk_bytes > 1024 * 1024:
        raise AcquisitionAuditError("evidence chunk size is outside the audit bound")
    with _open_bound_artifact(root, binding) as handle:
        hashes: list[str] = []
        digest = hashlib.sha256()
        size = 0
        handle.seek(0)
        while chunk := handle.read(chunk_bytes):
            digest.update(chunk)
            size += len(chunk)
            if size > binding.bytes:
                raise AcquisitionAuditError(f"artifact binding mismatch: {binding.path}")
            hashes.append(sha256_bytes(chunk))
        _assert_artifact_digest(binding, digest.hexdigest(), size)
        return tuple(hashes)


def _identity_stripped_shingles(data: bytes, identity_values: tuple[str, ...]) -> frozenset[str]:
    normalized = data
    for value in sorted(set(identity_values), key=len, reverse=True):
        encoded = value.encode("utf-8")
        if encoded:
            normalized = normalized.replace(encoded, b"<IDENTITY>")
    if not normalized:
        return frozenset({sha256_bytes(b"")})
    if len(normalized) <= _FINGERPRINT_CHUNK_BYTES:
        return frozenset({sha256_bytes(normalized)})
    step = _FINGERPRINT_CHUNK_BYTES // 2
    return frozenset(
        sha256_bytes(normalized[offset : offset + _FINGERPRINT_CHUNK_BYTES])
        for offset in range(0, len(normalized) - _FINGERPRINT_CHUNK_BYTES + 1, step)
    )


def _near_duplicate_pairs(
    fingerprints: list[tuple[str, frozenset[str]]],
) -> tuple[tuple[str, str], ...]:
    duplicates: list[tuple[str, str]] = []
    for index, (left_id, left) in enumerate(fingerprints):
        for right_id, right in fingerprints[index + 1 :]:
            union = left | right
            similarity = len(left & right) / len(union) if union else 1.0
            if similarity >= _NEAR_DUPLICATE_JACCARD:
                duplicates.append((left_id, right_id))
    return tuple(duplicates)


def _load_bound_model(root: Path, binding: ArtifactBinding, model: type[T]) -> T:
    try:
        with _open_bound_artifact(root, binding) as handle:
            return model.model_validate_json(
                _read_bound_artifact(
                    handle,
                    binding,
                    maximum_bytes=_MAX_BOUND_MODEL_BYTES,
                )
            )
    except AcquisitionAuditError:
        raise
    except (ValueError, json.JSONDecodeError) as error:
        raise AcquisitionAuditError(f"invalid {model.__name__}: {binding.path}") from error


def _role_map(dossier: IncidentDossier) -> dict[RoleKind, RoleAssignment]:
    return {item.role: item for item in dossier.roles}


def _review_map(dossier: IncidentDossier) -> dict[ReviewPurpose, BoundReview]:
    return {item.purpose: item for item in dossier.reviews}


def _attestation_body(attestation: SignedAttestation) -> dict[str, Any]:
    return attestation.model_dump(mode="json", exclude={"attestation_hash", "signature"})


def _verify_attestation(
    attestation: SignedAttestation,
    *,
    expected_kind: AttestationSubjectKind,
    expected_subject_sha256: str,
    expected_actor: TrustedActor,
    no_later_than: datetime | None = None,
) -> None:
    if (
        attestation.signer_id != expected_actor.actor_id
        or attestation.signer_public_key != expected_actor.public_key
        or attestation.subject_kind != expected_kind
        or attestation.subject_sha256 != expected_subject_sha256
        or (no_later_than is not None and attestation.issued_at > no_later_than)
        or sha256_value(_attestation_body(attestation)) != attestation.attestation_hash
    ):
        raise AcquisitionAuditError("signed attestation identity or subject differs")
    try:
        VerifyKey(bytes.fromhex(expected_actor.public_key)).verify(
            bytes.fromhex(attestation.attestation_hash),
            bytes.fromhex(attestation.signature),
        )
    except (BadSignatureError, ValueError) as error:
        raise AcquisitionAuditError("signed attestation signature is invalid") from error


def _verify_anchor_attestation(
    attestation: SignedAttestation,
    *,
    expected_kind: AttestationSubjectKind,
    expected_subject_sha256: str,
    expected_public_key: str,
) -> None:
    if (
        attestation.signer_public_key != expected_public_key
        or attestation.subject_kind != expected_kind
        or attestation.subject_sha256 != expected_subject_sha256
        or sha256_value(_attestation_body(attestation)) != attestation.attestation_hash
    ):
        raise AcquisitionAuditError("anchor attestation identity or subject differs")
    try:
        VerifyKey(bytes.fromhex(expected_public_key)).verify(
            bytes.fromhex(attestation.attestation_hash),
            bytes.fromhex(attestation.signature),
        )
    except (BadSignatureError, ValueError) as error:
        raise AcquisitionAuditError("anchor attestation signature is invalid") from error


def _verify_trust_registry(
    root: Path,
    registry: ActorTrustRegistry,
    contract: AcquisitionContract,
    *,
    no_later_than: datetime,
) -> dict[str, TrustedActor]:
    if registry.issued_at > no_later_than:
        raise AcquisitionAuditError("trust registry postdates governed acquisition activity")
    if registry.signer_public_key != contract.trust_anchor_public_key:
        raise AcquisitionAuditError("trust registry is not signed by the contract anchor")
    body = registry.model_dump(mode="json", exclude={"registry_hash", "signature"})
    if sha256_value(body) != registry.registry_hash:
        raise AcquisitionAuditError("trust registry hash differs")
    try:
        VerifyKey(bytes.fromhex(contract.trust_anchor_public_key)).verify(
            bytes.fromhex(registry.registry_hash),
            bytes.fromhex(registry.signature),
        )
    except (BadSignatureError, ValueError) as error:
        raise AcquisitionAuditError("trust registry signature is invalid") from error
    actors = {actor.actor_id: actor for actor in registry.actors}
    for actor in registry.actors:
        _verify_artifact(root, actor.mandate)
    return actors


def _rights_subject(source: SourceManifest) -> dict[str, Any]:
    return {
        "source_id": source.source_id,
        "source_authority": source.source_authority,
        "source_version": source.source_version,
        "evidence_track": source.evidence_track,
        "terms_artifact": source.terms_artifact,
        "permissions": source.permissions,
        "restricted_fields": source.restricted_fields,
        "deletion_obligations": source.deletion_obligations,
        "limitations": source.limitations,
        "resources": [
            {
                "resource_id": resource.resource_id,
                "uri": resource.uri,
                "version": resource.version,
                "sha256": resource.sha256,
                "bytes": resource.bytes,
                "media_type": resource.media_type,
            }
            for resource in source.resources
        ],
    }


def _unsigned_subject(value: BaseModel, *, exclude: set[str]) -> dict[str, Any]:
    return value.model_dump(mode="json", exclude=exclude)


def _assert_review(
    review: BoundReview,
    *,
    subject: BaseModel,
    producer_role: RoleKind,
    reviewer_role: RoleKind,
    roles: dict[RoleKind, RoleAssignment],
    actors: dict[str, TrustedActor],
) -> None:
    if (
        review.subject_sha256 != sha256_value(subject)
        or review.producer_role != producer_role
        or review.reviewer_role != reviewer_role
        or review.attestation.issued_at != review.reviewed_at
    ):
        raise AcquisitionAuditError(f"{review.purpose.value} review is not content-bound")
    producer = roles[producer_role]
    reviewer = roles[reviewer_role]
    if (
        producer.actor_id == reviewer.actor_id
        or producer.independence_group_id == reviewer.independence_group_id
    ):
        raise AcquisitionAuditError(f"{review.purpose.value} review is not independent")
    review_subject = _unsigned_subject(review, exclude={"attestation"})
    _verify_attestation(
        review.attestation,
        expected_kind=AttestationSubjectKind.REVIEW,
        expected_subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.REVIEW,
            review_subject,
        ),
        expected_actor=actors[reviewer.actor_id],
        no_later_than=review.reviewed_at,
    )


def _verify_source(
    root: Path,
    source: SourceManifest,
    contract: AcquisitionContract,
    actors: dict[str, TrustedActor],
) -> list[str]:
    rights_failures: list[str] = []
    _verify_artifact(root, source.terms_artifact)
    decisions = {item.kind: item for item in source.permissions}
    for permission in source.permissions:
        _verify_artifact(root, permission.basis)
    reviewer = actors.get(source.rights_reviewer_id)
    steward = actors.get(source.source_steward_id)
    if (
        reviewer is None
        or steward is None
        or RoleKind.RIGHTS_REVIEWER not in reviewer.authorized_roles
        or RoleKind.SOURCE_STEWARD not in steward.authorized_roles
        or reviewer.independence_group_id != source.rights_reviewer_independence_group
        or steward.independence_group_id != source.source_steward_independence_group
        or source.rights_attestation.issued_at != source.approved_at
    ):
        raise AcquisitionAuditError("source roles are absent from the trust registry")
    _verify_attestation(
        source.rights_attestation,
        expected_kind=AttestationSubjectKind.SOURCE_RIGHTS,
        expected_subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.SOURCE_RIGHTS,
            _rights_subject(source),
        ),
        expected_actor=reviewer,
        no_later_than=source.approved_at,
    )
    for required in contract.required_permissions:
        if decisions[required].decision != PermissionDecision.ALLOWED:
            rights_failures.append(f"{source.source_id}:{required.value}")
    if rights_failures:
        return rights_failures
    for resource in source.resources:
        if resource.staged_at < source.approved_at:
            raise AcquisitionAuditError(
                f"source resource was staged before rights approval: {resource.resource_id}"
            )
        _verify_artifact(root, resource.staged_artifact)
        if (
            resource.staged_artifact.sha256 != resource.sha256
            or resource.staged_artifact.bytes != resource.bytes
            or resource.staged_artifact.media_type != resource.media_type
        ):
            raise AcquisitionAuditError(f"source resource is not bound: {resource.resource_id}")
    return rights_failures


def _verify_resource_usage(usage: ResourceUsage, ceiling: ResourceCeiling) -> list[str]:
    checks = {
        "cpu_seconds": usage.cpu_seconds <= ceiling.max_cpu_seconds,
        "wall_seconds": usage.wall_seconds <= ceiling.max_wall_seconds,
        "peak_memory_bytes": usage.peak_memory_bytes <= ceiling.max_peak_memory_bytes,
        "downloaded_bytes": usage.downloaded_bytes <= ceiling.max_downloaded_bytes,
        "peak_staged_bytes": usage.peak_staged_bytes <= ceiling.max_peak_staged_bytes,
        "derived_bytes": usage.derived_bytes <= ceiling.max_derived_bytes,
        "gpu_seconds": usage.gpu_seconds <= ceiling.max_gpu_seconds,
        "cloud_jobs": usage.cloud_jobs <= ceiling.max_cloud_jobs,
        "paid_calls": usage.paid_calls <= ceiling.max_paid_calls,
        "cost_usd": Decimal(usage.cost_usd) <= Decimal(ceiling.max_cost_usd),
    }
    return [name for name, passed in checks.items() if not passed]


def _verify_artifact_ref(root: Path, uri: str, expected_sha256: str, expected_bytes: int) -> None:
    binding = ArtifactBinding(
        path=uri,
        sha256=expected_sha256,
        bytes=expected_bytes,
        media_type="application/octet-stream",
    )
    _verify_artifact(root, binding)


def _verify_dossier(
    root: Path,
    dossier: IncidentDossier,
    source: SourceManifest,
    contract: AcquisitionContract,
    actors: dict[str, TrustedActor],
) -> None:
    if (
        dossier.source_id != source.source_id
        or dossier.source_manifest_sha256 != sha256_value(source)
        or dossier.evidence_track != EvidenceTrack.PHYSICAL_ADMISSION
        or source.evidence_track != EvidenceTrack.PHYSICAL_ADMISSION
    ):
        raise AcquisitionAuditError("dossier source or evidence track is not bound")
    if source.approved_at > dossier.timeline.source_acquired_at:
        raise AcquisitionAuditError("source was acquired before its rights approval")
    if (
        dossier.group.physicality != Physicality.PHYSICAL
        or not dossier.group.claim_bearing
        or dossier.group.incident_id != dossier.group.root_incident_group_id
    ):
        raise AcquisitionAuditError("counted dossier is not one claim-bearing physical root event")

    for assignment in dossier.roles:
        _verify_artifact(root, assignment.conflict_disclosure)
        actor = actors.get(assignment.actor_id)
        if (
            actor is None
            or assignment.role not in actor.authorized_roles
            or assignment.independence_group_id != actor.independence_group_id
            or assignment.approval_public_key != actor.public_key
        ):
            raise AcquisitionAuditError(
                f"role assignment is not trust-registry bound: {assignment.role.value}"
            )
    for review in dossier.reviews:
        for review_evidence in review.evidence:
            _verify_artifact(root, review_evidence)

    provenance = _load_bound_model(
        root,
        dossier.physical_provenance,
        PhysicalProvenanceRecord,
    )
    plane = _load_bound_model(root, dossier.plane_separation_receipt, PlaneSeparationReceipt)
    evidence = _load_bound_model(root, dossier.evidence_bundle, EvidenceBundle)
    evidence_sequence = _load_bound_model(
        root,
        dossier.evidence_sequence,
        EvidenceSequenceReceipt,
    )
    projection = _load_bound_model(
        root,
        dossier.model_visible_projection,
        ModelVisibleProjection,
    )
    truth = _load_bound_model(root, dossier.truth_record, TruthRecord)
    truth_custody = _load_bound_model(root, dossier.truth_custody, TruthCustodyReceipt)
    hypotheses = _load_bound_model(root, dossier.hypothesis_set, HypothesisSet)
    candidate = _load_bound_model(root, dossier.discriminating_test, DiscriminatingTest)
    selected = _load_bound_model(root, dossier.selected_test, SelectedTest)
    envelope = _load_bound_model(root, dossier.safety_envelope, SafetyEnvelope)
    test_approval = _load_bound_model(root, dossier.test_approval, ApprovalReceipt)
    observation = _load_bound_model(root, dossier.test_observation, TestObservation)
    diagnostic_execution = _load_bound_model(
        root,
        dossier.diagnostic_execution,
        DiagnosticExecution,
    )
    diagnostic_action_contract = _load_bound_model(
        root,
        diagnostic_execution.action_contract,
        DiagnosticActionContract,
    )
    recovery_plan = _load_bound_model(root, dossier.recovery_plan, RecoveryPlan)
    recovery_approval = _load_bound_model(root, dossier.recovery_approval, ApprovalReceipt)
    recovery_execution = _load_bound_model(root, dossier.recovery_execution, RecoveryExecution)
    settled = _load_bound_model(root, dossier.settled_outcome, SettledOutcomeRecord)
    verification = _load_bound_model(root, dossier.verification_result, VerificationResult)
    incident_resources = _load_bound_model(
        root,
        dossier.incident_resource_plane,
        IncidentResourcePlane,
    )

    incident_id = dossier.group.incident_id
    provenance_subject = _unsigned_subject(provenance, exclude={"attestation"})
    source_steward = actors[source.source_steward_id]
    if (
        not provenance.independently_initiated
        or not provenance.baseline_restored_before
        or provenance.incident_id != incident_id
        or provenance.root_incident_group_id != dossier.group.root_incident_group_id
        or provenance.acquisition_session_id != dossier.group.acquisition_session_id
        or provenance.independence_group_id != dossier.group.independence_group_id
        or provenance.acquisition_lineage_id != dossier.group.acquisition_lineage_id
        or provenance.source_id != source.source_id
        or provenance.source_resource_id not in {item.resource_id for item in source.resources}
        or provenance.system_family != dossier.group.system_family
        or provenance.hardware_id != dossier.group.hardware_id
        or provenance.configuration_id != dossier.group.configuration_id
        or provenance.environment_id != dossier.group.environment_id
        or provenance.site_id != dossier.group.site_id
        or provenance.acquired_at != dossier.timeline.source_acquired_at
        or provenance.attestation.issued_at != provenance.acquired_at
    ):
        raise AcquisitionAuditError("physical provenance is incomplete or not dossier-bound")
    _verify_attestation(
        provenance.attestation,
        expected_kind=AttestationSubjectKind.PHYSICAL_PROVENANCE,
        expected_subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.PHYSICAL_PROVENANCE,
            provenance_subject,
        ),
        expected_actor=source_steward,
        no_later_than=provenance.acquired_at,
    )
    for binding in (
        provenance.initiation_evidence,
        provenance.baseline_evidence,
        provenance.physical_capture,
    ):
        _verify_artifact(root, binding)
    if plane.source_id != source.source_id or plane.source_manifest_sha256 != sha256_value(source):
        raise AcquisitionAuditError("plane-separation receipt is not source-bound")
    _verify_artifact(root, plane.parser_coverage)
    evidence_incidents = _load_bound_model(
        root,
        plane.evidence_manifest,
        PlaneIncidentManifest,
    )
    truth_incidents = _load_bound_model(
        root,
        plane.truth_manifest,
        PlaneIncidentManifest,
    )
    evidence_incident_hash = sha256_value(sorted(evidence_incidents.incident_ids))
    truth_incident_hash = sha256_value(sorted(truth_incidents.incident_ids))
    if (
        evidence_incidents.plane != "model_visible"
        or truth_incidents.plane != "truth_only"
        or incident_id not in evidence_incidents.incident_ids
        or incident_id not in truth_incidents.incident_ids
        or plane.evidence_incident_ids_sha256 != evidence_incident_hash
        or plane.truth_incident_ids_sha256 != truth_incident_hash
        or evidence_incident_hash != truth_incident_hash
    ):
        raise AcquisitionAuditError("evidence and truth incident joins differ")
    forbidden_assignments = {
        assignment.field_name
        for assignment in plane.assignments
        if assignment.plane == EvidencePlane.MODEL_VISIBLE
        and assignment.field_name.lower() in _FORBIDDEN_MODEL_VISIBLE_FIELDS
    }
    if forbidden_assignments:
        raise AcquisitionAuditError(
            f"forbidden fields are model-visible: {sorted(forbidden_assignments)}"
        )
    if any(
        item != incident_id
        for item in (
            evidence.incident_id,
            truth.incident_id,
            hypotheses.incident_id,
            selected.incident_id,
            observation.incident_id,
            recovery_plan.incident_id,
            recovery_execution.incident_id,
            settled.incident_id,
        )
    ):
        raise AcquisitionAuditError("dossier artifacts do not name one incident")
    if (
        truth.hardware_family != dossier.group.system_family
        or truth.hardware_id != dossier.group.hardware_id
        or truth.fault_family != dossier.group.fault_family
        or evidence.system_family != dossier.group.system_family
        or evidence.system_id != dossier.group.hardware_id
        or evidence.mission_id != dossier.group.mission_id
        or evidence.truth_commitment != sha256_value(truth)
        or evidence.context
    ):
        raise AcquisitionAuditError("evidence, truth, and group identity are inconsistent")
    roles = _role_map(dossier)
    reviews = _review_map(dossier)
    custody_subject = _unsigned_subject(truth_custody, exclude={"attestation"})
    if (
        truth_custody.incident_id != incident_id
        or truth_custody.truth_record_sha256 != sha256_value(truth)
        or truth_custody.custodian_id != roles[RoleKind.MECHANISM_REVIEWER].actor_id
        or truth_custody.committed_at != dossier.timeline.truth_committed_at
        or truth_custody.unsealed_at != dossier.timeline.truth_unsealed_at
        or truth_custody.unauthorized_access_detected
        or truth_custody.attestation.issued_at != truth_custody.unsealed_at
    ):
        raise AcquisitionAuditError("truth custody is incomplete or chronology differs")
    _verify_artifact(root, truth_custody.access_log)
    _verify_attestation(
        truth_custody.attestation,
        expected_kind=AttestationSubjectKind.TRUTH_CUSTODY,
        expected_subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.TRUTH_CUSTODY,
            custody_subject,
        ),
        expected_actor=actors[roles[RoleKind.MECHANISM_REVIEWER].actor_id],
        no_later_than=truth_custody.unsealed_at,
    )
    projected_hashes = {item.sha256 for item in projection.model_input_artifacts}
    evidence_hashes = {item.artifact.sha256 for item in evidence.evidence}
    projection_subject = _unsigned_subject(projection, exclude={"attestation"})
    supplied_leakage_scan = _load_bound_model(
        root,
        projection.leakage_scan,
        ModelVisibleLeakageScanReport,
    )
    identity_values = (
        incident_id,
        dossier.group.root_incident_group_id,
        dossier.group.acquisition_session_id,
        dossier.group.independence_group_id,
        dossier.group.acquisition_lineage_id,
        dossier.group.system_family,
        dossier.group.hardware_id,
        dossier.group.fault_family,
        dossier.group.configuration_id,
        dossier.group.environment_id,
        dossier.group.mission_id,
        dossier.group.site_id,
        source.source_id,
        source.source_authority,
        source.source_version,
        *(resource.resource_id for resource in source.resources),
        truth.commitment_nonce,
        truth.hardware_family,
        truth.hardware_id,
        truth.fault_family,
        *truth.mechanism_ids,
        truth.cause_authority,
    )
    recomputed_leakage_scan = build_model_visible_leakage_scan(
        root,
        incident_id=incident_id,
        artifacts=projection.model_input_artifacts,
        identity_values=identity_values,
    )
    if (
        projection.incident_id != incident_id
        or projection.source_manifest_sha256 != sha256_value(source)
        or projection.plane_separation_sha256 != sha256_value(plane)
        or projection.evidence_bundle_sha256 != sha256_value(evidence)
        or projected_hashes != evidence_hashes
        or projection.leakage_detected
        or supplied_leakage_scan != recomputed_leakage_scan
        or supplied_leakage_scan.leakage_detected != projection.leakage_detected
        or projection.projected_at < dossier.timeline.source_acquired_at
        or projection.projected_at > dossier.timeline.evidence_cutoff_at
        or projection.curator_id != roles[RoleKind.EVIDENCE_CURATOR].actor_id
        or projection.attestation.issued_at != projection.projected_at
    ):
        raise AcquisitionAuditError("model-visible projection is incomplete or leaks metadata")
    for binding in (
        *projection.model_input_artifacts,
        projection.projection_implementation,
        projection.leakage_scan,
    ):
        _verify_artifact(root, binding)
    _verify_attestation(
        projection.attestation,
        expected_kind=AttestationSubjectKind.MODEL_VISIBLE_PROJECTION,
        expected_subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.MODEL_VISIBLE_PROJECTION,
            projection_subject,
        ),
        expected_actor=actors[roles[RoleKind.EVIDENCE_CURATOR].actor_id],
        no_later_than=projection.projected_at,
    )
    sequence_by_id = {stream.evidence_id: stream for stream in evidence_sequence.streams}
    evidence_by_id = {item.evidence_id: item for item in evidence.evidence}
    sequence_subject = _unsigned_subject(evidence_sequence, exclude={"attestation"})
    if (
        evidence_sequence.incident_id != incident_id
        or evidence_sequence.source_steward_id != source.source_steward_id
        or set(sequence_by_id) != set(evidence_by_id)
        or evidence_sequence.produced_at < dossier.timeline.source_acquired_at
        or evidence_sequence.produced_at > dossier.timeline.evidence_cutoff_at
        or evidence_sequence.attestation.issued_at != evidence_sequence.produced_at
    ):
        raise AcquisitionAuditError("evidence-sequence: sequence receipt is not source-bound")
    if tuple(sequence_by_id) != tuple(evidence_by_id):
        raise AcquisitionAuditError(
            "shuffled-modality: evidence order differs from its source sequence receipt"
        )
    for evidence_id, stream in sequence_by_id.items():
        item = evidence_by_id[evidence_id]
        artifact_binding = ArtifactBinding(
            path=item.artifact.uri,
            sha256=item.artifact.sha256,
            bytes=item.artifact.bytes,
            media_type=item.artifact.media_type,
        )
        observed_chunk_hashes = _ordered_chunk_hashes(
            root,
            artifact_binding,
            stream.chunk_bytes,
        )
        if (
            not stream.source_order_monotonic
            or stream.artifact_sha256 != item.artifact.sha256
            or stream.artifact_bytes != item.artifact.bytes
            or stream.ordered_chunk_sha256 != observed_chunk_hashes
        ):
            raise AcquisitionAuditError(
                "shuffled-modality: evidence order differs from its source sequence receipt"
            )
    _verify_attestation(
        evidence_sequence.attestation,
        expected_kind=AttestationSubjectKind.EVIDENCE_SEQUENCE,
        expected_subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.EVIDENCE_SEQUENCE,
            sequence_subject,
        ),
        expected_actor=source_steward,
        no_later_than=evidence_sequence.produced_at,
    )
    post_cutoff_or_truth_hashes = {
        dossier.truth_record.sha256,
        dossier.truth_custody.sha256,
        truth_custody.access_log.sha256,
        observation.observation_artifact.sha256,
        diagnostic_execution.command.sha256,
        diagnostic_execution.acknowledgement.sha256,
        diagnostic_execution.realized_action.sha256,
        diagnostic_execution.constraint_margins.sha256,
        diagnostic_execution.abort_log.sha256,
        recovery_execution.commanded_action.sha256,
        recovery_execution.realized_action.sha256,
        settled.settled_predicate.sha256,
        settled.predicate_evaluation.sha256,
        settled.recurrence_evidence.sha256,
        *(item.sha256 for item in settled.outcome_artifacts),
        *(item.sha256 for item in verification.outcome_artifacts),
    }
    if projected_hashes & post_cutoff_or_truth_hashes:
        raise AcquisitionAuditError(
            "model-visible-content-collision: model-visible content collides with truth-only "
            "or post-cutoff evidence"
        )

    known_hypotheses = [item for item in hypotheses.hypotheses if not item.unknown]
    unknown_hypotheses = [item for item in hypotheses.hypotheses if item.unknown]
    if (
        len(known_hypotheses) < 2
        or len(unknown_hypotheses) != 1
        or unknown_hypotheses[0].prior <= 0
        or set(truth.competing_hypothesis_ids)
        != {item.hypothesis_id for item in hypotheses.hypotheses}
        or candidate.test_id not in truth.safe_discriminating_test_ids
    ):
        raise AcquisitionAuditError("fewer than two known mechanism hypotheses")

    safety_actor = roles[RoleKind.SAFETY_REVIEWER]
    safety_key = safety_actor.approval_public_key
    test_subject = authorization_subject_hash(
        ApprovalSubjectKind.TEST_EXECUTION,
        {
            "candidate": candidate.model_dump(mode="json", exclude={"approval_receipt_hash"}),
            "safety_envelope": envelope.model_dump(mode="json", exclude={"approval_receipt_hash"}),
            "diagnostic_action_contract": diagnostic_action_contract.model_dump(mode="json"),
        },
    )
    try:
        verified_test_approval = verify_approval(
            test_approval,
            expected_signer_public_key=safety_key,
            expected_subject_kind=ApprovalSubjectKind.TEST_EXECUTION,
            expected_subject_sha256=test_subject,
            expected_authority=ExecutionAuthority.TESTBED,
            required_risk=candidate.risk,
            required_cost_usd=diagnostic_execution.direct_cost_usd,
            at=observation.started_at,
        )
    except ApprovalVerificationError as error:
        raise AcquisitionAuditError("forged-approval: diagnostic approval is invalid") from error
    if not (
        verified_test_approval.issuer_id == safety_actor.actor_id
        and test_approval.issuer_id == safety_actor.actor_id
        and candidate.approval_receipt_hash
        == envelope.approval_receipt_hash
        == observation.approval_receipt_hash
        == test_approval.receipt_hash
    ):
        raise AcquisitionAuditError("forged-approval: diagnostic approval hashes differ")
    try:
        recomputed_selection = select_discriminating_test(
            hypotheses,
            (candidate,),
            envelope,
            planner_id=roles[RoleKind.TEST_SELECTOR].actor_id,
            approval_receipt=test_approval,
            expected_approval_signer=roles[RoleKind.SAFETY_REVIEWER].approval_public_key,
            approval_time=observation.started_at,
            approval_subject_extension={
                "diagnostic_action_contract": diagnostic_action_contract.model_dump(mode="json")
            },
        )
    except (NoEligibleTestError, NonDiscriminatingTestError, ValueError) as error:
        raise AcquisitionAuditError(
            "selected test lacks a reproducible safe positive-information-gain selection"
        ) from error
    if selected != recomputed_selection:
        raise AcquisitionAuditError("selected test fields differ from deterministic recomputation")
    if (
        selected.test_id != candidate.test_id
        or selected.candidate_sha256 != sha256_value(candidate)
        or selected.safety_envelope_sha256 != sha256_value(envelope)
        or candidate.authority != ExecutionAuthority.TESTBED
        or envelope.authority != ExecutionAuthority.TESTBED
        or observation.authority != ExecutionAuthority.TESTBED
        or candidate.test_id not in envelope.allowed_test_ids
        or not candidate.approved
        or candidate.risk > envelope.max_risk
        or not set(candidate.preconditions).issubset(envelope.satisfied_preconditions)
        or observation.test_id != candidate.test_id
        or observation.outcome_id not in {item.outcome_id for item in candidate.outcome_model}
        or observation.candidate_sha256 != sha256_value(candidate)
        or observation.safety_envelope_sha256 != sha256_value(envelope)
    ):
        raise AcquisitionAuditError("diagnostic test execution is not cross-bound")
    diagnostic_subject = _unsigned_subject(diagnostic_execution, exclude={"attestation"})
    for binding in (
        diagnostic_action_contract.parameter_bounds,
        diagnostic_action_contract.abort_specification,
    ):
        _verify_artifact(root, binding)
    diagnostic_duration = (
        diagnostic_execution.finished_at - diagnostic_execution.started_at
    ).total_seconds()
    diagnostic_action_hashes = {
        diagnostic_execution.command.sha256,
        diagnostic_execution.acknowledgement.sha256,
        diagnostic_execution.realized_action.sha256,
    }
    if len(diagnostic_action_hashes) != 3:
        raise AcquisitionAuditError(
            "diagnostic-realization: diagnostic command, acknowledgement, and realization "
            "are not distinct evidence"
        )
    if (
        diagnostic_action_contract.incident_id != incident_id
        or diagnostic_action_contract.test_id != candidate.test_id
        or diagnostic_action_contract.command_sha256 != diagnostic_execution.command.sha256
        or diagnostic_action_contract.expected_realized_action_sha256
        != diagnostic_execution.realized_action.sha256
        or diagnostic_action_contract.committed_at > dossier.timeline.safe_test_reviewed_at
        or candidate.duration_seconds > diagnostic_action_contract.max_duration_seconds
        or candidate.risk > diagnostic_action_contract.max_risk
        or Decimal(diagnostic_execution.direct_cost_usd)
        > Decimal(diagnostic_action_contract.max_cost_usd)
        or diagnostic_duration > diagnostic_action_contract.max_duration_seconds
    ):
        raise AcquisitionAuditError(
            "diagnostic-action-conformance: execution differs from its safety-approved action "
            "contract"
        )
    if (
        diagnostic_execution.incident_id != incident_id
        or diagnostic_execution.test_id != candidate.test_id
        or diagnostic_execution.executor_id != roles[RoleKind.TEST_EXECUTOR].actor_id
        or diagnostic_execution.candidate_sha256 != sha256_value(candidate)
        or diagnostic_execution.safety_envelope_sha256 != sha256_value(envelope)
        or diagnostic_execution.observation_sha256 != sha256_value(observation)
        or diagnostic_execution.authority != ExecutionAuthority.TESTBED
        or diagnostic_execution.started_at != observation.started_at
        or diagnostic_execution.finished_at != observation.finished_at
        or diagnostic_execution.approval_receipt_hash != test_approval.receipt_hash
        or diagnostic_execution.attestation.issued_at != diagnostic_execution.finished_at
    ):
        raise AcquisitionAuditError("diagnostic execution is not observation-bound")
    _verify_attestation(
        diagnostic_execution.attestation,
        expected_kind=AttestationSubjectKind.DIAGNOSTIC_EXECUTION,
        expected_subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.DIAGNOSTIC_EXECUTION,
            diagnostic_subject,
        ),
        expected_actor=actors[roles[RoleKind.TEST_EXECUTOR].actor_id],
        no_later_than=diagnostic_execution.finished_at,
    )
    for binding in (
        diagnostic_execution.command,
        diagnostic_execution.acknowledgement,
        diagnostic_execution.realized_action,
        diagnostic_execution.constraint_margins,
        diagnostic_execution.abort_log,
    ):
        _verify_artifact(root, binding)

    _assert_review(
        reviews[ReviewPurpose.MECHANISM],
        subject=truth,
        producer_role=RoleKind.TRUTH_PRODUCER,
        reviewer_role=RoleKind.MECHANISM_REVIEWER,
        roles=roles,
        actors=actors,
    )
    _assert_review(
        reviews[ReviewPurpose.AMBIGUITY],
        subject=hypotheses,
        producer_role=RoleKind.HYPOTHESIS_PROPOSER,
        reviewer_role=RoleKind.MECHANISM_REVIEWER,
        roles=roles,
        actors=actors,
    )
    _assert_review(
        reviews[ReviewPurpose.SAFE_TEST],
        subject=candidate,
        producer_role=RoleKind.TEST_PROPOSER,
        reviewer_role=RoleKind.SAFETY_REVIEWER,
        roles=roles,
        actors=actors,
    )
    _assert_review(
        reviews[ReviewPurpose.RECOVERY],
        subject=recovery_plan,
        producer_role=RoleKind.RECOVERY_PROPOSER,
        reviewer_role=RoleKind.SAFETY_REVIEWER,
        roles=roles,
        actors=actors,
    )
    _assert_review(
        reviews[ReviewPurpose.SETTLED_OUTCOME],
        subject=settled,
        producer_role=RoleKind.RECOVERY_EXECUTOR,
        reviewer_role=RoleKind.OUTCOME_VERIFIER,
        roles=roles,
        actors=actors,
    )
    if (
        roles[RoleKind.SOURCE_STEWARD].actor_id != source.source_steward_id
        or roles[RoleKind.RIGHTS_REVIEWER].actor_id != source.rights_reviewer_id
        or hypotheses.proposer_id != roles[RoleKind.HYPOTHESIS_PROPOSER].actor_id
        or truth.cause_authority != roles[RoleKind.MECHANISM_REVIEWER].actor_id
        or selected.planner_id != roles[RoleKind.TEST_SELECTOR].actor_id
        or observation.executor_id != roles[RoleKind.TEST_EXECUTOR].actor_id
        or recovery_plan.proposer_id != roles[RoleKind.RECOVERY_PROPOSER].actor_id
        or recovery_execution.executor_id != roles[RoleKind.RECOVERY_EXECUTOR].actor_id
        or settled.outcome_authority_id != roles[RoleKind.OUTCOME_VERIFIER].actor_id
        or settled.outcome_authority_independence_group
        != roles[RoleKind.OUTCOME_VERIFIER].independence_group_id
        or verification.verifier_id != roles[RoleKind.OUTCOME_VERIFIER].actor_id
        or verification.proposer_id != recovery_plan.proposer_id
    ):
        raise AcquisitionAuditError("artifact actors do not match assigned roles")

    forbidden_group_pairs = (
        (RoleKind.EVIDENCE_CURATOR, RoleKind.TRUTH_PRODUCER),
        (RoleKind.EVIDENCE_CURATOR, RoleKind.MECHANISM_REVIEWER),
        (RoleKind.EVIDENCE_CURATOR, RoleKind.OUTCOME_VERIFIER),
        (RoleKind.TRUTH_PRODUCER, RoleKind.MECHANISM_REVIEWER),
        (RoleKind.HYPOTHESIS_PROPOSER, RoleKind.TRUTH_PRODUCER),
        (RoleKind.HYPOTHESIS_PROPOSER, RoleKind.MECHANISM_REVIEWER),
        (RoleKind.TEST_PROPOSER, RoleKind.TRUTH_PRODUCER),
        (RoleKind.TEST_PROPOSER, RoleKind.MECHANISM_REVIEWER),
        (RoleKind.TEST_PROPOSER, RoleKind.SAFETY_REVIEWER),
        (RoleKind.TEST_SELECTOR, RoleKind.TRUTH_PRODUCER),
        (RoleKind.TEST_SELECTOR, RoleKind.MECHANISM_REVIEWER),
        (RoleKind.TEST_SELECTOR, RoleKind.SAFETY_REVIEWER),
        (RoleKind.TEST_EXECUTOR, RoleKind.SAFETY_REVIEWER),
        (RoleKind.HYPOTHESIS_PROPOSER, RoleKind.OUTCOME_VERIFIER),
        (RoleKind.TEST_SELECTOR, RoleKind.OUTCOME_VERIFIER),
        (RoleKind.TEST_EXECUTOR, RoleKind.OUTCOME_VERIFIER),
        (RoleKind.RECOVERY_PROPOSER, RoleKind.OUTCOME_VERIFIER),
        (RoleKind.RECOVERY_EXECUTOR, RoleKind.OUTCOME_VERIFIER),
        (RoleKind.STATISTICIAN, RoleKind.TRUTH_PRODUCER),
        (RoleKind.STATISTICIAN, RoleKind.MECHANISM_REVIEWER),
    )
    if any(
        roles[left].actor_id == roles[right].actor_id
        or roles[left].independence_group_id == roles[right].independence_group_id
        for left, right in forbidden_group_pairs
    ):
        raise AcquisitionAuditError("forbidden role independence overlap")

    recovery_subject = authorization_subject_hash(
        ApprovalSubjectKind.RECOVERY_EXECUTION,
        {
            "recovery_plan": recovery_plan.model_dump(
                mode="json", exclude={"approval_receipt_hash"}
            ),
            "settled_predicate_sha256": settled.settled_predicate.sha256,
        },
    )
    try:
        verified_recovery_approval = verify_approval(
            recovery_approval,
            expected_signer_public_key=safety_key,
            expected_subject_kind=ApprovalSubjectKind.RECOVERY_EXECUTION,
            expected_subject_sha256=recovery_subject,
            expected_authority=ExecutionAuthority.TESTBED,
            required_cost_usd=recovery_execution.cost_usd,
            at=recovery_execution.started_at,
        )
    except ApprovalVerificationError as error:
        raise AcquisitionAuditError("recovery approval is invalid") from error
    if not (
        verified_recovery_approval.issuer_id == safety_actor.actor_id
        and recovery_approval.issuer_id == safety_actor.actor_id
        and recovery_plan.approval_receipt_hash
        == recovery_execution.approval_receipt_hash
        == recovery_approval.receipt_hash
    ):
        raise AcquisitionAuditError("recovery approval hashes differ")

    if (
        recovery_plan.authority != ExecutionAuthority.TESTBED
        or recovery_plan.hypothesis_id not in {item.hypothesis_id for item in hypotheses.hypotheses}
        or recovery_execution.recovery_id != recovery_plan.recovery_id
        or recovery_execution.plan_sha256 != sha256_value(recovery_plan)
        or recovery_execution.authority != ExecutionAuthority.TESTBED
        or settled.recovery_id != recovery_plan.recovery_id
        or settled.selected_test_sha256 != sha256_value(selected)
        or settled.test_observation_sha256 != sha256_value(observation)
        or settled.diagnostic_execution_sha256 != sha256_value(diagnostic_execution)
        or settled.recovery_execution_sha256 != sha256_value(recovery_execution)
        or verification.recovery_id != recovery_plan.recovery_id
        or verification.action_valid != settled.action_valid
        or verification.target_valid != settled.target_valid
        or verification.settled_success != settled.settled_success
        or verification.abstained
        or not settled.recurrence_checked
        or (verification.settled_success and not settled.constraints_satisfied)
        or {item.sha256 for item in verification.outcome_artifacts}
        != {item.sha256 for item in settled.outcome_artifacts}
        or settled.attestation.issued_at != dossier.timeline.outcome_verified_at
        or recovery_execution.attestation.issued_at != recovery_execution.finished_at
        or recovery_execution.commanded_action.sha256 == recovery_execution.realized_action.sha256
    ):
        raise AcquisitionAuditError("recovery and settled outcome are not cross-bound")

    recovery_execution_subject = _unsigned_subject(
        recovery_execution,
        exclude={"attestation"},
    )
    _verify_attestation(
        recovery_execution.attestation,
        expected_kind=AttestationSubjectKind.RECOVERY_EXECUTION,
        expected_subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.RECOVERY_EXECUTION,
            recovery_execution_subject,
        ),
        expected_actor=actors[roles[RoleKind.RECOVERY_EXECUTOR].actor_id],
        no_later_than=recovery_execution.finished_at,
    )

    settled_subject = _unsigned_subject(settled, exclude={"attestation"})
    _verify_attestation(
        settled.attestation,
        expected_kind=AttestationSubjectKind.SETTLED_OUTCOME,
        expected_subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.SETTLED_OUTCOME,
            settled_subject,
        ),
        expected_actor=actors[roles[RoleKind.OUTCOME_VERIFIER].actor_id],
        no_later_than=dossier.timeline.outcome_verified_at,
    )

    for binding in (
        recovery_execution.commanded_action,
        recovery_execution.realized_action,
        settled.settled_predicate,
        settled.predicate_evaluation,
        settled.recurrence_evidence,
        *settled.outcome_artifacts,
    ):
        _verify_artifact(root, binding)
    for evidence_item in evidence.evidence:
        _verify_artifact_ref(
            root,
            evidence_item.artifact.uri,
            evidence_item.artifact.sha256,
            evidence_item.artifact.bytes,
        )
    _verify_artifact_ref(
        root,
        observation.observation_artifact.uri,
        observation.observation_artifact.sha256,
        observation.observation_artifact.bytes,
    )
    for outcome_artifact in (*truth.settled_outcome_refs, *verification.outcome_artifacts):
        _verify_artifact_ref(
            root, outcome_artifact.uri, outcome_artifact.sha256, outcome_artifact.bytes
        )

    modalities = {item.modality for item in evidence.evidence}
    modality_hashes = {item.artifact.sha256 for item in evidence.evidence}
    if (
        len(modalities) < contract.minimum_operational_modalities
        or len(modality_hashes) < contract.minimum_operational_modalities
    ):
        raise AcquisitionAuditError(
            "one-modality: insufficient distinct operational modality types or content streams"
        )
    if not (
        modalities & _TIME_VARYING_SENSOR_MODALITIES and modalities & _ACTION_OR_EVENT_MODALITIES
    ):
        raise AcquisitionAuditError(
            "stationary-image-proxy: evidence lacks both a time-varying sensor stream and an "
            "action or event stream"
        )
    _verify_artifact(root, incident_resources.measurement_artifact)
    if (
        incident_resources.incident_id != incident_id
        or incident_resources.diagnostic_test_seconds
        != (diagnostic_execution.finished_at - diagnostic_execution.started_at).total_seconds()
        or incident_resources.recovery_seconds
        != (recovery_execution.finished_at - recovery_execution.started_at).total_seconds()
        or incident_resources.diagnostic_action_cost_usd != diagnostic_execution.direct_cost_usd
        or incident_resources.recovery_action_cost_usd != recovery_execution.cost_usd
    ):
        raise AcquisitionAuditError("incident cost and resource planes are not execution-bound")
    clock_by_id = {item.clock_domain: item for item in dossier.clocks}
    calibration_by_id: dict[str, ClockMappingEvidence] = {}
    binding_by_id = {item.evidence_id: item for item in dossier.evidence_times}
    if set(binding_by_id) != {item.evidence_id for item in evidence.evidence}:
        raise AcquisitionAuditError("evidence time bindings do not cover evidence exactly")
    for clock in dossier.clocks:
        calibration = _load_bound_model(
            root,
            clock.mapping_artifact,
            ClockMappingEvidence,
        )
        predicted_errors = [
            abs(
                round(pair.source_value * clock.scale_to_reference)
                + clock.offset_ns
                - pair.reference_ns
            )
            for pair in calibration.calibration_pairs
        ]
        observed_missing_fraction = 1.0 - (
            calibration.observed_samples / calibration.expected_samples
        )
        if (
            calibration.clock_domain != clock.clock_domain
            or calibration.reference_clock_domain != clock.reference_clock_domain
            or max(predicted_errors) != clock.max_alignment_error_ns
            or abs(observed_missing_fraction - clock.missing_fraction) > 1e-12
            or clock.max_alignment_error_ns > contract.max_clock_alignment_error_ns
            or clock.missing_fraction > contract.max_clock_missing_fraction
        ):
            raise AcquisitionAuditError("clock alignment or missingness exceeds the contract")
        calibration_by_id[clock.clock_domain] = calibration
    for evidence_item in evidence.evidence:
        if evidence_item.artifact.clock_domain is None:
            raise AcquisitionAuditError("evidence artifact lacks a clock domain")
        time_binding = binding_by_id[evidence_item.evidence_id]
        evidence_clock = clock_by_id.get(time_binding.clock_domain)
        try:
            observed_start = float(evidence_item.observed_start or "")
            observed_end = float(evidence_item.observed_end or "")
        except ValueError as error:
            raise AcquisitionAuditError("evidence lacks numeric source-clock bounds") from error
        if (
            time_binding.clock_domain != evidence_item.artifact.clock_domain
            or evidence_clock is None
            or time_binding.clock_domain not in calibration_by_id
            or time_binding.normalized_start_ns
            != round(observed_start * evidence_clock.scale_to_reference) + evidence_clock.offset_ns
            or time_binding.normalized_end_ns
            != round(observed_end * evidence_clock.scale_to_reference) + evidence_clock.offset_ns
            or time_binding.normalized_end_ns > dossier.timeline.model_visible_cutoff_ns
        ):
            raise AcquisitionAuditError("evidence time binding crosses the model-visible cutoff")

    timeline = dossier.timeline
    if (
        observation.started_at != timeline.test_started_at
        or observation.finished_at != timeline.test_finished_at
        or recovery_execution.started_at != timeline.recovery_started_at
        or recovery_execution.finished_at != timeline.recovery_finished_at
        or settled.window_started_at != timeline.settled_window_started_at
        or settled.window_finished_at != timeline.settled_window_finished_at
        or reviews[ReviewPurpose.MECHANISM].reviewed_at > timeline.truth_committed_at
        or reviews[ReviewPurpose.AMBIGUITY].reviewed_at < timeline.hypothesis_committed_at
        or reviews[ReviewPurpose.AMBIGUITY].reviewed_at
        > reviews[ReviewPurpose.SAFE_TEST].reviewed_at
        or reviews[ReviewPurpose.SAFE_TEST].reviewed_at != timeline.safe_test_reviewed_at
        or reviews[ReviewPurpose.SAFE_TEST].reviewed_at >= observation.started_at
        or reviews[ReviewPurpose.RECOVERY].reviewed_at >= recovery_execution.started_at
        or reviews[ReviewPurpose.RECOVERY].reviewed_at < timeline.recovery_plan_committed_at
        or reviews[ReviewPurpose.SETTLED_OUTCOME].reviewed_at < settled.window_finished_at
    ):
        raise AcquisitionAuditError("review and execution times do not match the frozen timeline")


def _gate(
    gate_id: str,
    passed: bool,
    observed: Any,
    requirement: str,
    detail: str,
    *,
    invalid: bool = False,
) -> AcquisitionGateResult:
    return AcquisitionGateResult(
        gate_id=gate_id,
        status="pass" if passed else "invalid" if invalid else "blocked",
        observed=observed,
        requirement=requirement,
        detail=detail,
    )


def audit_acquisition(
    contract: AcquisitionContract,
    input_root: Path,
) -> AcquisitionAdmissionReport:
    """Audit one immutable input tree without executing data acquisition or physical actions."""

    source_root = input_root / "sources"
    dossier_root = input_root / "dossiers"
    usage_path = input_root / "resource_usage.json"
    trust_path = input_root / "trust_registry.json"
    control_path = input_root / "control_suite_receipt.json"
    candidate_registry_path = input_root / "candidate_registry.json"
    shortcut_path = input_root / "shortcut_baseline.json"
    comparator_path = input_root / "intervention_comparators.json"
    protocol_reviews_path = input_root / "protocol_reviews.json"
    split_locks_path = input_root / "split_locks.json"
    required_files = (
        usage_path,
        trust_path,
        control_path,
        candidate_registry_path,
        shortcut_path,
        comparator_path,
        protocol_reviews_path,
        split_locks_path,
    )
    if (
        not source_root.is_dir()
        or not dossier_root.is_dir()
        or any(not path.is_file() for path in required_files)
    ):
        raise AcquisitionAuditError(
            "input root lacks a required acquisition, trust, control, review, or split surface"
        )
    try:
        sources = [
            SourceManifest.model_validate(read_json(path))
            for path in sorted(source_root.glob("*.json"))
        ]
        dossiers = [
            IncidentDossier.model_validate(read_json(path))
            for path in sorted(dossier_root.glob("*.json"))
        ]
        usage = ResourceUsage.model_validate(read_json(usage_path))
        trust_registry = ActorTrustRegistry.model_validate(read_json(trust_path))
        control_suite = AdmissionControlSuiteReceipt.model_validate(read_json(control_path))
        candidate_registry = AcquisitionCandidateRegistry.model_validate(
            read_json(candidate_registry_path)
        )
        shortcut_report = ShortcutBaselineReport.model_validate(read_json(shortcut_path))
        comparator_registry = InterventionComparatorRegistry.model_validate(
            read_json(comparator_path)
        )
        protocol_reviews = ProtocolReviewRegistry.model_validate(read_json(protocol_reviews_path))
        split_locks = AcquisitionSplitLocks.model_validate(read_json(split_locks_path))
    except (OSError, ValueError) as error:
        raise AcquisitionAuditError("acquisition input manifests are invalid") from error
    if not sources:
        raise AcquisitionAuditError("at least one source manifest is required")
    source_by_id = {item.source_id: item for item in sources}
    if len(source_by_id) != len(sources):
        raise AcquisitionAuditError("source IDs must be unique")
    dossier_ids = [item.dossier_id for item in dossiers]
    if len(dossier_ids) != len(set(dossier_ids)):
        raise AcquisitionAuditError("dossier IDs must be unique")

    integrity_failures: list[str] = []
    rights_failures: list[str] = []
    try:
        if control_suite.authority_profile != contract.authority_profile:
            raise AcquisitionAuditError("control suite authority profile differs from the contract")
        registry_dependent_times = (
            *(source.approved_at for source in sources),
            candidate_registry.produced_at,
            shortcut_report.evaluated_at,
            comparator_registry.committed_at,
            *(review.reviewed_at for review in protocol_reviews.reviews),
            usage.measured_at,
            *(dossier.timeline.source_acquired_at for dossier in dossiers),
        )
        actors = _verify_trust_registry(
            input_root,
            trust_registry,
            contract,
            no_later_than=min(registry_dependent_times),
        )
        control_subject = _unsigned_subject(control_suite, exclude={"attestation"})
        if (
            sha256_value(control_suite) != contract.control_suite_sha256
            or control_suite.validator_git_blob != contract.validator_git_blob
            or control_suite.validator_source_sha256 != contract.validator_source_sha256
            or control_suite.dependency_lock_sha256 != contract.dependency_lock_sha256
        ):
            raise AcquisitionAuditError("control suite differs from the acquisition contract")
        _verify_artifact(input_root, control_suite.execution_manifest)
        for control in control_suite.controls:
            _verify_artifact(input_root, control.evidence)
        _verify_anchor_attestation(
            control_suite.attestation,
            expected_kind=AttestationSubjectKind.CONTROL_SUITE,
            expected_subject_sha256=attestation_subject_hash(
                AttestationSubjectKind.CONTROL_SUITE,
                control_subject,
            ),
            expected_public_key=contract.trust_anchor_public_key,
        )
        registrar = actors[candidate_registry.registrar_id]
        if RoleKind.STATISTICIAN not in registrar.authorized_roles:
            raise AcquisitionAuditError("candidate registrar is not the statistician")
        candidate_subject = _unsigned_subject(candidate_registry, exclude={"attestation"})
        _verify_attestation(
            candidate_registry.attestation,
            expected_kind=AttestationSubjectKind.CANDIDATE_REGISTRY,
            expected_subject_sha256=attestation_subject_hash(
                AttestationSubjectKind.CANDIDATE_REGISTRY,
                candidate_subject,
            ),
            expected_actor=registrar,
            no_later_than=candidate_registry.produced_at,
        )
        if candidate_registry.attestation.issued_at != candidate_registry.produced_at:
            raise AcquisitionAuditError("candidate registry attestation time differs")
        for candidate_root in candidate_registry.candidates:
            if (
                candidate_root.physicality != Physicality.PHYSICAL
                or candidate_root.source_id not in source_by_id
            ):
                raise AcquisitionAuditError("candidate registry contains a nonphysical root")
            _verify_artifact(input_root, candidate_root.discovery_evidence)
    except (AcquisitionAuditError, KeyError) as error:
        raise AcquisitionAuditError("acquisition trust or control authority is invalid") from error
    candidate_by_incident = {
        candidate.incident_id: candidate for candidate in candidate_registry.candidates
    }
    for dossier in dossiers:
        registered_candidate = candidate_by_incident.get(dossier.group.incident_id)
        if (
            registered_candidate is None
            or registered_candidate.root_incident_group_id != dossier.group.root_incident_group_id
            or registered_candidate.source_id != dossier.source_id
        ):
            integrity_failures.append(
                f"{dossier.dossier_id}: dossier is absent from the physical candidate registry"
            )
    for source in sources:
        try:
            rights_failures.extend(_verify_source(input_root, source, contract, actors))
        except AcquisitionAuditError as error:
            integrity_failures.append(str(error))
    eligible: list[IncidentDossier] = []
    for dossier in dossiers:
        dossier_source = source_by_id.get(dossier.source_id)
        if dossier_source is None:
            integrity_failures.append(f"unknown dossier source: {dossier.source_id}")
            continue
        try:
            _verify_dossier(input_root, dossier, dossier_source, contract, actors)
        except (AcquisitionAuditError, ValueError) as error:
            integrity_failures.append(f"{dossier.dossier_id}: {error}")
        else:
            eligible.append(dossier)

    root_ids = [item.group.root_incident_group_id for item in eligible]
    if len(root_ids) != len(set(root_ids)):
        integrity_failures.append("duplicate physical root incident groups")
    independence_groups = [item.group.independence_group_id for item in eligible]
    if len(independence_groups) != len(set(independence_groups)):
        integrity_failures.append("physical roots reuse an independence group")
    session_groups: dict[str, set[str]] = defaultdict(set)
    for item in eligible:
        session_groups[item.group.acquisition_session_id].add(item.group.independence_group_id)
    if any(len(groups) != 1 for groups in session_groups.values()):
        integrity_failures.append("one acquisition session claims multiple independence groups")
    lineage_ids = [item.group.acquisition_lineage_id for item in eligible]
    if len(lineage_ids) != len(set(lineage_ids)):
        integrity_failures.append("physical roots reuse an acquisition lineage")
    hardware_families: dict[str, set[tuple[str, SystemDomain]]] = defaultdict(set)
    for item in eligible:
        hardware_families[item.group.hardware_id].add(
            (item.group.system_family, item.group.system_domain)
        )
    if any(len(assignments) != 1 for assignments in hardware_families.values()):
        integrity_failures.append("one hardware identity maps to multiple families or domains")
    capture_hashes: list[str] = []
    capture_fingerprints: list[tuple[str, frozenset[str]]] = []
    model_fingerprints: list[tuple[str, frozenset[str]]] = []
    for item in eligible:
        try:
            provenance = _load_bound_model(
                input_root,
                item.physical_provenance,
                PhysicalProvenanceRecord,
            )
            projection = _load_bound_model(
                input_root,
                item.model_visible_projection,
                ModelVisibleProjection,
            )
            _verify_artifact(input_root, provenance.physical_capture)
            for binding in projection.model_input_artifacts:
                _verify_artifact(input_root, binding)
            if provenance.physical_capture.bytes < _MIN_PHYSICAL_CAPTURE_BYTES:
                raise AcquisitionAuditError("physical capture is too small for uniqueness audit")
            if sum(binding.bytes for binding in projection.model_input_artifacts) < (
                _MIN_MODEL_VISIBLE_BYTES
            ):
                raise AcquisitionAuditError(
                    "model-visible evidence is too small for uniqueness audit"
                )
        except AcquisitionAuditError as error:
            integrity_failures.append(f"{item.dossier_id}: {error}")
        else:
            capture_hashes.append(provenance.physical_capture.sha256)
            identity_values = (
                item.group.incident_id,
                item.group.root_incident_group_id,
                item.group.acquisition_session_id,
                item.group.independence_group_id,
                item.group.acquisition_lineage_id,
                item.group.hardware_id,
                item.group.configuration_id,
                item.group.environment_id,
                item.group.mission_id,
                item.group.site_id,
            )
            capture_fingerprints.append(
                (
                    item.group.incident_id,
                    _identity_stripped_shingles(
                        _bounded_artifact_sample(input_root, provenance.physical_capture),
                        identity_values,
                    ),
                )
            )
            model_sample = b"\x00MODEL-STREAM\x00".join(
                _bounded_artifact_sample(input_root, binding)
                for binding in projection.model_input_artifacts
            )
            model_fingerprints.append(
                (
                    item.group.incident_id,
                    _identity_stripped_shingles(model_sample, identity_values),
                )
            )
    if len(capture_hashes) != len(set(capture_hashes)):
        integrity_failures.append("physical roots reuse identical full-capture bytes")
    capture_duplicates = _near_duplicate_pairs(capture_fingerprints)
    if capture_duplicates:
        integrity_failures.append(
            "near-duplicate-physical-capture: physical roots reuse near-duplicate capture "
            f"content: {capture_duplicates[:3]}"
        )
    model_duplicates = _near_duplicate_pairs(model_fingerprints)
    if model_duplicates:
        integrity_failures.append(
            "near-duplicate-model-visible: physical roots reuse near-duplicate model-visible "
            f"content: {model_duplicates[:3]}"
        )

    split_units = [
        SplitUnit(
            incident_id=item.group.incident_id,
            hardware_family=item.group.system_family,
            hardware_id=item.group.hardware_id,
            mission_id=item.group.mission_id,
            fault_family=item.group.fault_family,
            evidence_hash=item.evidence_bundle.sha256,
            truth_hash=item.truth_record.sha256,
        )
        for item in eligible
    ]
    expected_split_dimensions = {
        "hardware_family": ("hardware_family",),
        "hardware_identity": ("hardware_id",),
        "fault_family": ("fault_family",),
    }
    split_results: dict[str, dict[str, Any]] = {}
    for axis, expected_dimensions in expected_split_dimensions.items():
        binding = getattr(split_locks, axis)
        try:
            lock = _load_bound_model(input_root, binding, SplitLock)
            validate_split_lock(lock, split_units)
            if lock.holdout_dimensions != expected_dimensions:
                raise AcquisitionAuditError(f"{axis} split lock uses the wrong holdout axis")
        except (AcquisitionAuditError, ValueError) as error:
            integrity_failures.append(f"{axis} split lock: {error}")
        else:
            split_results[axis] = {
                "sha256": binding.sha256,
                "split_counts": lock.split_counts,
                "holdout_dimensions": lock.holdout_dimensions,
            }

    shortcut_kill = False
    try:
        statistician = actors[shortcut_report.statistician_id]
        if RoleKind.STATISTICIAN not in statistician.authorized_roles:
            raise AcquisitionAuditError("shortcut report signer is not the statistician")
        shortcut_subject = _unsigned_subject(shortcut_report, exclude={"attestation"})
        expected_incident_hash = sha256_value(sorted(item.group.incident_id for item in eligible))
        if shortcut_report.incident_ids_sha256 != expected_incident_hash:
            raise AcquisitionAuditError("shortcut report does not cover the eligible corpus")
        _verify_attestation(
            shortcut_report.attestation,
            expected_kind=AttestationSubjectKind.SHORTCUT_BASELINE,
            expected_subject_sha256=attestation_subject_hash(
                AttestationSubjectKind.SHORTCUT_BASELINE,
                shortcut_subject,
            ),
            expected_actor=statistician,
            no_later_than=shortcut_report.evaluated_at,
        )
        if shortcut_report.attestation.issued_at != shortcut_report.evaluated_at:
            raise AcquisitionAuditError("shortcut report attestation time differs")
        for result in shortcut_report.results:
            _verify_artifact(input_root, result.implementation)
            _verify_artifact(input_root, result.evaluation)
        shortcut_kill = any(
            result.resolves_mechanism_without_action for result in shortcut_report.results
        )
    except (AcquisitionAuditError, KeyError) as error:
        integrity_failures.append(f"shortcut baseline: {error}")

    try:
        comparator_statistician = actors[comparator_registry.statistician_id]
        if RoleKind.STATISTICIAN not in comparator_statistician.authorized_roles:
            raise AcquisitionAuditError("comparator registry signer is not the statistician")
        comparator_subject = _unsigned_subject(comparator_registry, exclude={"attestation"})
        expected_incident_hash = sha256_value(sorted(item.group.incident_id for item in eligible))
        if comparator_registry.incident_ids_sha256 != expected_incident_hash:
            raise AcquisitionAuditError("comparator registry does not cover the eligible corpus")
        _verify_attestation(
            comparator_registry.attestation,
            expected_kind=AttestationSubjectKind.COMPARATOR_REGISTRY,
            expected_subject_sha256=attestation_subject_hash(
                AttestationSubjectKind.COMPARATOR_REGISTRY,
                comparator_subject,
            ),
            expected_actor=comparator_statistician,
            no_later_than=comparator_registry.committed_at,
        )
        if comparator_registry.attestation.issued_at != comparator_registry.committed_at:
            raise AcquisitionAuditError("comparator registry attestation time differs")
        for comparator in comparator_registry.comparators:
            _verify_artifact(input_root, comparator.implementation)
            _verify_artifact(input_root, comparator.evaluation_plan)
    except (AcquisitionAuditError, KeyError) as error:
        integrity_failures.append(f"intervention comparators: {error}")

    try:
        protocol_review_actors = [actors[review.reviewer_id] for review in protocol_reviews.reviews]
        first_test_started_at = min(
            (dossier.timeline.test_started_at for dossier in dossiers),
            default=None,
        )
        if (
            len({actor.actor_id for actor in protocol_review_actors}) != 2
            or len({actor.independence_group_id for actor in protocol_review_actors}) != 2
        ):
            raise AcquisitionAuditError("protocol reviewers are not independent")
        for review, actor in zip(
            protocol_reviews.reviews,
            protocol_review_actors,
            strict=True,
        ):
            _verify_artifact(input_root, review.review_artifact)
            subject = _unsigned_subject(review, exclude={"attestation"})
            _verify_attestation(
                review.attestation,
                expected_kind=AttestationSubjectKind.PROTOCOL_REVIEW,
                expected_subject_sha256=attestation_subject_hash(
                    AttestationSubjectKind.PROTOCOL_REVIEW,
                    subject,
                ),
                expected_actor=actor,
                no_later_than=review.reviewed_at,
            )
            if review.attestation.issued_at != review.reviewed_at:
                raise AcquisitionAuditError("protocol-review attestation time differs")
            if first_test_started_at is not None and review.reviewed_at >= first_test_started_at:
                raise AcquisitionAuditError(
                    "protocol review does not precede physical test execution"
                )
    except (AcquisitionAuditError, KeyError) as error:
        integrity_failures.append(f"protocol reviews: {error}")

    try:
        resource_measurer = actors[usage.measurer_id]
        if RoleKind.STATISTICIAN not in resource_measurer.authorized_roles:
            raise AcquisitionAuditError("resource measurer is not independently authorized")
        _verify_artifact(input_root, usage.measurement_artifact)
        usage_subject = _unsigned_subject(usage, exclude={"attestation"})
        _verify_attestation(
            usage.attestation,
            expected_kind=AttestationSubjectKind.RESOURCE_USAGE,
            expected_subject_sha256=attestation_subject_hash(
                AttestationSubjectKind.RESOURCE_USAGE,
                usage_subject,
            ),
            expected_actor=resource_measurer,
            no_later_than=usage.measured_at,
        )
        if usage.attestation.issued_at != usage.measured_at:
            raise AcquisitionAuditError("resource measurement attestation time differs")
    except (AcquisitionAuditError, KeyError) as error:
        integrity_failures.append(f"resource measurement: {error}")
    resource_failures = _verify_resource_usage(usage, contract.resource_ceiling)
    if resource_failures:
        integrity_failures.append("resource ceiling exceeded: " + ", ".join(resource_failures))

    family_counts = Counter(item.group.system_family for item in eligible)
    identity_counts = Counter(item.group.hardware_id for item in eligible)
    fault_counts = Counter(item.group.fault_family for item in eligible)
    identities_by_family: dict[str, set[str]] = defaultdict(set)
    faults_by_family: dict[str, set[str]] = defaultdict(set)
    identities_by_fault: dict[str, set[str]] = defaultdict(set)
    families_by_fault: dict[str, set[str]] = defaultdict(set)
    for item in eligible:
        group = item.group
        identities_by_family[group.system_family].add(group.hardware_id)
        faults_by_family[group.system_family].add(group.fault_family)
        identities_by_fault[group.fault_family].add(group.hardware_id)
        families_by_fault[group.fault_family].add(group.system_family)
    total = len(eligible)
    maximum_share = (
        max([*family_counts.values(), *fault_counts.values()], default=0) / total if total else 1.0
    )
    domains = {item.group.system_domain for item in eligible}

    coverage_checks = {
        "complete_count": total >= contract.minimum_complete_physical_incidents,
        "system_families": len(family_counts) >= contract.minimum_system_families,
        "hardware_identities": len(identity_counts) >= contract.minimum_hardware_identities,
        "fault_families": len(fault_counts) >= contract.minimum_fault_families,
        "incidents_per_family": bool(family_counts)
        and min(family_counts.values()) >= contract.minimum_incidents_per_system_family,
        "incidents_per_fault": bool(fault_counts)
        and min(fault_counts.values()) >= contract.minimum_incidents_per_fault_family,
        "incidents_per_identity": bool(identity_counts)
        and min(identity_counts.values()) >= contract.minimum_incidents_per_hardware_identity,
        "identities_per_family": bool(identities_by_family)
        and min(map(len, identities_by_family.values()))
        >= contract.minimum_identities_per_system_family,
        "maximum_share": maximum_share <= contract.maximum_family_share,
        "faults_per_family": bool(faults_by_family)
        and min(map(len, faults_by_family.values())) >= contract.minimum_faults_per_system_family,
        "identities_per_fault": bool(identities_by_fault)
        and min(map(len, identities_by_fault.values())) >= 2,
        "families_per_fault": bool(families_by_fault)
        and min(map(len, families_by_fault.values())) >= contract.minimum_system_families_per_fault,
        "required_domains": set(contract.required_domains).issubset(domains),
        "per_axis_split_feasible": len(split_results) == 3,
    }
    coverage_passed = all(coverage_checks.values())
    integrity_passed = not integrity_failures
    rights_passed = not rights_failures
    resources_passed = not resource_failures

    gates = (
        _gate(
            "artifact-integrity",
            integrity_passed,
            {"failures": integrity_failures},
            (
                "Every artifact, join, commitment, chronology, role, approval, and execution "
                "cross-binding verifies."
            ),
            "Integrity is evaluated on the same dossiers used for coverage.",
            invalid=True,
        ),
        _gate(
            "source-rights",
            rights_passed,
            {"failures": rights_failures},
            "Every required permission is explicitly allowed by an independent rights review.",
            "Unknown, prohibited, or not-applicable required permissions block staging.",
        ),
        _gate(
            "resource-ceiling",
            resources_passed,
            {"failures": resource_failures},
            "Measured audit resource use remains inside the preregistered ceiling.",
            "Missing usage is invalid and a ceiling breach stops the audit.",
            invalid=True,
        ),
        _gate(
            "conjunctive-coverage",
            coverage_passed,
            {
                "checks": coverage_checks,
                "candidate_physical_roots": len(candidate_registry.candidates),
                "complete_incidents": total,
                "system_families": dict(family_counts),
                "hardware_identities": dict(identity_counts),
                "fault_families": dict(fault_counts),
                "maximum_share": maximum_share,
                "domains": sorted(item.value for item in domains),
            },
            "At least 30 complete physical dossiers meet every balance and transfer floor.",
            "Rows, windows, branches, and separate per-gate counts cannot raise this count.",
        ),
        _gate(
            "shortcut-baseline",
            not shortcut_kill,
            {
                "resolving_rules": [
                    result.rule_id
                    for result in shortcut_report.results
                    if result.resolves_mechanism_without_action
                ]
            },
            (
                "No frozen shortcut or cheapest deterministic rule resolves the mechanism "
                "without action."
            ),
            (
                "A resolving shortcut kills the proposed multimodal construct before "
                "learned-model work."
            ),
        ),
    )
    verdict: Literal[
        "PASS_PILOT",
        "BLOCKED_ACQUISITION",
        "BLOCKED_RIGHTS",
        "KILL_CONSTRUCT",
        "INVALID",
    ] = (
        "INVALID"
        if not integrity_passed or not resources_passed
        else "BLOCKED_RIGHTS"
        if not rights_passed
        else "KILL_CONSTRUCT"
        if coverage_passed and shortcut_kill
        else "PASS_PILOT"
        if coverage_passed
        else "BLOCKED_ACQUISITION"
    )
    corpus_sha256 = sha256_value(
        [
            item.model_dump(mode="json")
            for item in sorted(eligible, key=lambda value: value.dossier_id)
        ]
    )
    return AcquisitionAdmissionReport(
        authority_profile=contract.authority_profile,
        iteration_id=contract.iteration_id,
        contract_sha256=sha256_value(contract),
        validator_git_blob=contract.validator_git_blob,
        validator_source_sha256=contract.validator_source_sha256,
        trust_registry_sha256=sha256_value(trust_registry),
        control_suite_sha256=sha256_value(control_suite),
        candidate_registry_sha256=sha256_value(candidate_registry),
        comparator_registry_sha256=sha256_value(comparator_registry),
        split_locks_sha256=sha256_value(split_locks),
        corpus_sha256=corpus_sha256,
        resource_usage_sha256=sha256_value(usage),
        candidate_incident_ids=tuple(sorted(candidate_by_incident)),
        eligible_incident_ids=tuple(sorted(item.group.incident_id for item in eligible)),
        gates=gates,
        verdict=verdict,
        authorized_next_action=_ACTIONS[verdict],
        forbidden_next_actions=(
            "GPU or learned-model training",
            "diagnosis, recovery, safety, transfer, product, or economic-value claim",
            "live robot, flight, spacecraft, or destructive authority",
        ),
    )


def load_acquisition_contract(path: Path) -> AcquisitionContract:
    try:
        return AcquisitionContract.model_validate(read_json(path))
    except (OSError, ValueError) as error:
        raise AcquisitionAuditError(f"invalid acquisition contract: {path}") from error


def _read_binding_file(path: Path, label: str) -> bytes:
    maximum_bytes = 16 * 1024 * 1024
    if not hasattr(os, "O_NOFOLLOW"):
        raise AcquisitionAuditError(f"{label} requires file no-follow support")
    try:
        lexical = path.lstat()
        if (
            not stat.S_ISREG(lexical.st_mode)
            or lexical.st_nlink != 1
            or lexical.st_size > maximum_bytes
        ):
            raise AcquisitionAuditError(f"{label} must be a bounded regular file")
        descriptor = os.open(
            path,
            os.O_RDONLY
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
    except AcquisitionAuditError:
        raise
    except OSError as error:
        raise AcquisitionAuditError(f"{label} is unavailable") from error
    try:
        before = os.fstat(descriptor)
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(maximum_bytes + 1)
        after = os.fstat(descriptor)
        current = path.lstat()
    except OSError as error:
        raise AcquisitionAuditError(f"{label} changed while being read") from error
    finally:
        os.close(descriptor)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
        "st_uid",
        "st_gid",
    )
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or any(getattr(lexical, field) != getattr(before, field) for field in stable_fields)
        or any(getattr(before, field) != getattr(after, field) for field in stable_fields)
        or any(getattr(after, field) != getattr(current, field) for field in stable_fields)
        or len(data) != before.st_size
        or len(data) > maximum_bytes
    ):
        raise AcquisitionAuditError(f"{label} changed while being read")
    return data


_MAX_ACQUISITION_SOURCE_FILES = 64
_MAX_ACQUISITION_SOURCE_DESCENDANTS = 128
_MAX_ACQUISITION_SOURCE_TOTAL_BYTES = 32 * 1024 * 1024
_MAX_GIT_SOURCE_CENSUS_BYTES = 1024 * 1024
_GIT_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_SOURCE_PATH = re.compile(r"src/fieldtrue/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+")
_STABLE_SOURCE_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _isolated_launcher_flags_present() -> bool:
    flags = sys.flags
    return (
        flags.isolated == 1
        and flags.no_site == 1
        and flags.ignore_environment == 1
        and flags.safe_path is True
        and flags.dont_write_bytecode == 1
    )


def _code_objects(root: CodeType) -> dict[tuple[str, int], CodeType]:
    discovered: dict[tuple[str, int], CodeType] = {}
    pending = [root]
    while pending:
        code = pending.pop()
        identity = (code.co_qualname, code.co_firstlineno)
        if identity in discovered:
            raise AcquisitionAuditError("validator source contains ambiguous code identities")
        discovered[identity] = code
        pending.extend(value for value in code.co_consts if isinstance(value, CodeType))
    return discovered


def _executing_validator_matches_source(repo_root: Path, validator_bytes: bytes) -> bool:
    expected_path = repo_root / "src" / "fieldtrue" / "acquisition.py"
    try:
        executing_path = Path(__file__).resolve(strict=True)
        canonical_path = expected_path.resolve(strict=True)
        specification_origin = None if __spec__ is None else __spec__.origin
        if specification_origin is None:
            return False
        if executing_path != canonical_path or Path(specification_origin).resolve(strict=True) != (
            canonical_path
        ):
            return False
        compiled = compile(
            validator_bytes,
            str(canonical_path),
            "exec",
            dont_inherit=True,
            optimize=sys.flags.optimize,
        )
    except (OSError, SyntaxError, ValueError):
        return False
    expected_codes = _code_objects(compiled)
    critical_functions = (
        _isolated_launcher_flags_present,
        _code_objects,
        _executing_validator_matches_source,
        _read_binding_file,
        _git_source_census,
        _git_source_contents,
        _source_file_mode,
        _working_source_census,
        _acquisition_source_closure,
        _clean_repository_status,
        verify_preregistration_binding,
    )
    for function in critical_functions:
        code = function.__code__
        expected = expected_codes.get((code.co_qualname, code.co_firstlineno))
        if function.__module__ != __name__ or expected is None or code != expected:
            return False
    return True


def _git_source_census(
    git: str,
    repo_root: Path,
    environment: dict[str, str],
    commit: str,
) -> tuple[tuple[str, str, str], ...]:
    result = subprocess.run(  # noqa: S603 - fixed trusted Git and validated commit identity
        [git, "ls-tree", "-r", "-z", "--full-tree", commit, "--", "src/fieldtrue"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        env=environment,
        timeout=10,
    )
    if result.returncode != 0:
        raise AcquisitionAuditError("Git source census failed")
    if len(result.stdout) > _MAX_GIT_SOURCE_CENSUS_BYTES:
        raise AcquisitionAuditError("Git source census exceeds its byte ceiling")
    if not result.stdout or not result.stdout.endswith(b"\0"):
        raise AcquisitionAuditError("Git source census is empty or malformed")
    entries: list[tuple[str, str, str]] = []
    for raw_entry in result.stdout[:-1].split(b"\0"):
        try:
            raw_header, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, blob = raw_header.decode("ascii").split(" ")
            path = raw_path.decode("ascii")
        except (UnicodeDecodeError, ValueError) as error:
            raise AcquisitionAuditError("Git source census is malformed") from error
        if (
            mode not in {"100644", "100755"}
            or object_type != "blob"
            or _GIT_OBJECT_ID.fullmatch(blob) is None
            or _SOURCE_PATH.fullmatch(path) is None
            or PurePosixPath(path).as_posix() != path
        ):
            raise AcquisitionAuditError(f"Git source census contains an invalid entry: {path}")
        entries.append((path, mode, blob))
        if len(entries) > _MAX_ACQUISITION_SOURCE_FILES:
            raise AcquisitionAuditError("acquisition source census exceeds its file ceiling")
    ordered = tuple(sorted(entries))
    if len({path for path, _, _ in ordered}) != len(ordered):
        raise AcquisitionAuditError("Git source census contains duplicate paths")
    return ordered


def _git_source_contents(
    git: str,
    repo_root: Path,
    environment: dict[str, str],
    census: tuple[tuple[str, str, str], ...],
) -> dict[str, bytes]:
    requested = tuple(blob for _, _, blob in census)
    request = "".join(f"{blob}\n" for blob in requested).encode("ascii")
    size_result = subprocess.run(  # noqa: S603 - fixed trusted Git and validated object IDs
        [git, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        env=environment,
        input=request,
        timeout=10,
    )
    if size_result.returncode != 0:
        raise AcquisitionAuditError("Git source sizes failed to resolve")
    size_lines = size_result.stdout.splitlines()
    if len(size_lines) != len(requested):
        raise AcquisitionAuditError("Git source size census is incomplete")
    sizes: list[int] = []
    for expected_blob, raw_line in zip(requested, size_lines, strict=True):
        try:
            blob, object_type, raw_size = raw_line.decode("ascii").split(" ")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as error:
            raise AcquisitionAuditError("Git source size census is malformed") from error
        if blob != expected_blob or object_type != "blob" or size < 0 or size > 16 * 1024 * 1024:
            raise AcquisitionAuditError("Git source size census contains an invalid blob")
        sizes.append(size)
    if sum(sizes) > _MAX_ACQUISITION_SOURCE_TOTAL_BYTES:
        raise AcquisitionAuditError("acquisition source census exceeds its total byte ceiling")

    content_result = subprocess.run(  # noqa: S603 - fixed trusted Git and validated object IDs
        [git, "cat-file", "--batch"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        env=environment,
        input=request,
        timeout=10,
    )
    if content_result.returncode != 0:
        raise AcquisitionAuditError("Git source contents failed to resolve")
    output = memoryview(content_result.stdout)
    offset = 0
    contents: dict[str, bytes] = {}
    for expected_blob, expected_size in zip(requested, sizes, strict=True):
        newline = content_result.stdout.find(b"\n", offset)
        if newline < 0:
            raise AcquisitionAuditError("Git source content census is truncated")
        try:
            raw_header = content_result.stdout[offset:newline].decode("ascii")
            blob, object_type, raw_size = raw_header.split(" ")
            size = int(raw_size)
        except (UnicodeDecodeError, ValueError) as error:
            raise AcquisitionAuditError("Git source content census is malformed") from error
        start = newline + 1
        end = start + size
        if (
            blob != expected_blob
            or object_type != "blob"
            or size != expected_size
            or end >= len(output)
            or output[end] != 0x0A
        ):
            raise AcquisitionAuditError("Git source content census is incoherent")
        contents[blob] = bytes(output[start:end])
        offset = end + 1
    if offset != len(output):
        raise AcquisitionAuditError("Git source content census has trailing output")
    return contents


def _source_file_mode(
    metadata: os.stat_result,
    *,
    private_read_only: bool = False,
) -> str:
    permissions = stat.S_IMODE(metadata.st_mode)
    if permissions == (0o400 if private_read_only else 0o644):
        return "100644"
    if permissions == (0o500 if private_read_only else 0o755):
        return "100755"
    raise AcquisitionAuditError("acquisition source file has noncanonical permissions")


def _working_source_census(
    repo_root: Path,
    *,
    private_read_only: bool = False,
) -> tuple[tuple[tuple[str, str, bytes], ...], tuple[str, ...]]:
    root_path = repo_root / "src" / "fieldtrue"
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise AcquisitionAuditError(
            "acquisition source census requires no-follow directory support"
        )
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = (
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    )
    directories: list[tuple[int, os.stat_result, int | None, str | None, str]] = []
    files: list[tuple[int, os.stat_result, int, str, str, bytes]] = []
    descendants = 0
    total_bytes = 0
    try:
        try:
            root_lexical = root_path.lstat()
            if not stat.S_ISDIR(root_lexical.st_mode):
                raise AcquisitionAuditError("acquisition source root must be a regular directory")
            root_descriptor = os.open(root_path, directory_flags)
            try:
                root_metadata = os.fstat(root_descriptor)
            except OSError:
                os.close(root_descriptor)
                raise
        except AcquisitionAuditError:
            raise
        except OSError as error:
            raise AcquisitionAuditError("acquisition source root is unavailable") from error
        if not stat.S_ISDIR(root_metadata.st_mode):
            os.close(root_descriptor)
            raise AcquisitionAuditError("acquisition source root must be a regular directory")
        if any(
            getattr(root_lexical, field) != getattr(root_metadata, field)
            for field in _STABLE_SOURCE_FIELDS
        ):
            os.close(root_descriptor)
            raise AcquisitionAuditError("acquisition source root changed during census")
        directories.append((root_descriptor, root_metadata, None, None, "src/fieldtrue"))

        cursor = 0
        while cursor < len(directories):
            descriptor, _, _, _, relative_directory = directories[cursor]
            cursor += 1
            try:
                with os.scandir(descriptor) as entries:
                    names = sorted(entry.name for entry in entries)
            except OSError as error:
                raise AcquisitionAuditError(
                    "acquisition source directory cannot be read"
                ) from error
            if len(names) != len(set(names)):
                raise AcquisitionAuditError("acquisition source directory contains duplicate names")
            for name in names:
                descendants += 1
                if descendants > _MAX_ACQUISITION_SOURCE_DESCENDANTS:
                    raise AcquisitionAuditError(
                        "acquisition source census exceeds its descendant ceiling"
                    )
                relative = f"{relative_directory}/{name}"
                if _SOURCE_PATH.fullmatch(relative) is None:
                    raise AcquisitionAuditError(
                        f"acquisition source census contains an invalid path: {relative}"
                    )
                try:
                    lexical = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except OSError as error:
                    raise AcquisitionAuditError(
                        f"acquisition source changed during census: {relative}"
                    ) from error
                if stat.S_ISDIR(lexical.st_mode):
                    child: int | None = None
                    try:
                        child = os.open(name, directory_flags, dir_fd=descriptor)
                        opened = os.fstat(child)
                    except OSError as error:
                        if child is not None:
                            with suppress(OSError):
                                os.close(child)
                        raise AcquisitionAuditError(
                            f"acquisition source directory is unsafe: {relative}"
                        ) from error
                    if any(
                        getattr(lexical, field) != getattr(opened, field)
                        for field in _STABLE_SOURCE_FIELDS
                    ):
                        os.close(child)
                        raise AcquisitionAuditError(
                            f"acquisition source directory changed during census: {relative}"
                        )
                    directories.append((child, opened, descriptor, name, relative))
                    continue
                if not stat.S_ISREG(lexical.st_mode) or lexical.st_nlink != 1:
                    raise AcquisitionAuditError(
                        f"acquisition source descendant is not a regular file: {relative}"
                    )
                child = None
                try:
                    child = os.open(name, file_flags, dir_fd=descriptor)
                    opened = os.fstat(child)
                    with os.fdopen(child, "rb", closefd=False) as handle:
                        content = handle.read(16 * 1024 * 1024 + 1)
                    after = os.fstat(child)
                    current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except OSError as error:
                    if child is not None:
                        with suppress(OSError):
                            os.close(child)
                    raise AcquisitionAuditError(
                        f"acquisition source file changed during census: {relative}"
                    ) from error
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or len(content) != opened.st_size
                    or len(content) > 16 * 1024 * 1024
                    or any(
                        getattr(lexical, field) != getattr(opened, field)
                        or getattr(opened, field) != getattr(after, field)
                        or getattr(after, field) != getattr(current, field)
                        for field in _STABLE_SOURCE_FIELDS
                    )
                ):
                    os.close(child)
                    raise AcquisitionAuditError(
                        f"acquisition source file changed during census: {relative}"
                    )
                total_bytes += len(content)
                if total_bytes > _MAX_ACQUISITION_SOURCE_TOTAL_BYTES:
                    os.close(child)
                    raise AcquisitionAuditError(
                        "acquisition source census exceeds its total byte ceiling"
                    )
                files.append((child, opened, descriptor, name, relative, content))
                if len(files) > _MAX_ACQUISITION_SOURCE_FILES:
                    raise AcquisitionAuditError(
                        "acquisition source census exceeds its file ceiling"
                    )

        for descriptor, opened, parent, directory_name, relative in directories:
            after = os.fstat(descriptor)
            if any(
                getattr(opened, field) != getattr(after, field) for field in _STABLE_SOURCE_FIELDS
            ):
                raise AcquisitionAuditError(
                    f"acquisition source directory changed during census: {relative}"
                )
            if parent is not None and directory_name is not None:
                current = os.stat(directory_name, dir_fd=parent, follow_symlinks=False)
                if any(
                    getattr(after, field) != getattr(current, field)
                    for field in _STABLE_SOURCE_FIELDS
                ):
                    raise AcquisitionAuditError(
                        f"acquisition source directory changed during census: {relative}"
                    )
        root_current = root_path.lstat()
        if any(
            getattr(root_metadata, field) != getattr(root_current, field)
            for field in _STABLE_SOURCE_FIELDS
        ):
            raise AcquisitionAuditError("acquisition source root changed during census")
        for descriptor, opened, parent, name, relative, _ in files:
            after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if any(
                getattr(opened, field) != getattr(after, field)
                or getattr(after, field) != getattr(current, field)
                for field in _STABLE_SOURCE_FIELDS
            ):
                raise AcquisitionAuditError(
                    f"acquisition source file changed during census: {relative}"
                )
        source_files = tuple(
            sorted(
                (
                    relative,
                    _source_file_mode(opened, private_read_only=private_read_only),
                    content,
                )
                for _, opened, _, _, relative, content in files
            )
        )
        source_directories = tuple(sorted(relative for *_, relative in directories))
        return source_files, source_directories
    except AcquisitionAuditError:
        raise
    except OSError as error:
        raise AcquisitionAuditError("acquisition source census failed") from error
    finally:
        for descriptor, *_ in reversed(files):
            with suppress(OSError):
                os.close(descriptor)
        for descriptor, *_ in reversed(directories):
            with suppress(OSError):
                os.close(descriptor)


def _acquisition_source_closure(
    git: str,
    repo_root: Path,
    environment: dict[str, str],
    *,
    authority_commit: str,
    repository_head: str,
    expected_validator_blob: str,
    expected_validator_sha256: str,
    working_source_root: Path | None = None,
    working_source_private_read_only: bool = False,
) -> AcquisitionSourceClosure:
    authority_census = _git_source_census(
        git,
        repo_root,
        environment,
        authority_commit,
    )
    head_census = _git_source_census(
        git,
        repo_root,
        environment,
        repository_head,
    )
    if head_census != authority_census:
        raise AcquisitionAuditError(
            "acquisition source tree differs from control execution authority"
        )
    authority_contents = _git_source_contents(
        git,
        repo_root,
        environment,
        authority_census,
    )
    working_files, working_directories = _working_source_census(
        working_source_root or repo_root,
        private_read_only=working_source_private_read_only,
    )
    expected_directories = {"src/fieldtrue"}
    expected_working: list[tuple[str, str, bytes]] = []
    sources: list[tuple[str, str, str, str, int]] = []
    for path, mode, authority_blob in authority_census:
        parent = PurePosixPath(path).parent
        while parent.as_posix().startswith("src/fieldtrue"):
            expected_directories.add(parent.as_posix())
            if parent.as_posix() == "src/fieldtrue":
                break
            parent = parent.parent
        authority_bytes = authority_contents[authority_blob]
        expected_working.append((path, mode, authority_bytes))
        sources.append(
            (
                path,
                mode,
                authority_blob,
                sha256_bytes(authority_bytes),
                len(authority_bytes),
            )
        )
    if working_files != tuple(expected_working) or working_directories != tuple(
        sorted(expected_directories)
    ):
        raise AcquisitionAuditError(
            "working acquisition source census differs from control execution authority"
        )

    root_sources = [item for item in sources if item[0] == "src/fieldtrue/acquisition.py"]
    if len(root_sources) != 1 or (
        root_sources[0][2] != expected_validator_blob
        or root_sources[0][3] != expected_validator_sha256
    ):
        raise AcquisitionAuditError("validator source closure differs from the sealed contract")
    source_tuple = tuple(sources)
    return AcquisitionSourceClosure(
        authority_commit=authority_commit,
        repository_head=repository_head,
        sources=source_tuple,
        closure_sha256=sha256_value(
            [
                {
                    "path": path,
                    "mode": mode,
                    "git_blob": blob,
                    "sha256": digest,
                    "bytes": size,
                }
                for path, mode, blob, digest, size in source_tuple
            ]
        ),
    )


def _clean_repository_status(
    git: str,
    repo_root: Path,
    environment: dict[str, str],
) -> bytes:
    status_result = subprocess.run(  # noqa: S603 - fixed trusted Git status query
        [git, "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        env=environment,
        timeout=10,
    )
    return status_result.stdout


def verify_preregistration_binding(
    repo_root: Path,
    contract: AcquisitionContract,
    execution_commit: str | None = None,
) -> AcquisitionSourceClosure:
    """Verify preregistration and exact on-disk package sources against Git authority.

    This self-observation is a necessary gate, not executable or runtime attestation.
    """

    canonical_contract_path = repo_root / "protocol" / "acquisition" / "iter001_contract.json"
    try:
        canonical_contract_bytes = _read_binding_file(
            canonical_contract_path,
            "canonical acquisition contract",
        )
        canonical_contract = AcquisitionContract.model_validate_json(canonical_contract_bytes)
    except (AcquisitionAuditError, ValueError) as error:
        raise AcquisitionAuditError("canonical acquisition contract is invalid") from error
    if contract != canonical_contract:
        raise AcquisitionAuditError("selected acquisition contract is not the canonical contract")
    if contract.control_authority_status != "sealed":
        raise AcquisitionAuditError("canonical control authority is not sealed")
    if not _isolated_launcher_flags_present():
        raise AcquisitionAuditError(
            "sealed acquisition binding requires isolated launcher process flags"
        )
    current_path = repo_root.joinpath(*PurePosixPath(contract.preregistration_path).parts)
    preregistration_bytes = _read_binding_file(current_path, "current preregistration")
    if sha256_bytes(preregistration_bytes) != contract.preregistration_sha256:
        raise AcquisitionAuditError("current preregistration bytes do not match the contract")
    try:
        git = trusted_repository_git(repo_root)
    except GitTrustError as error:
        raise AcquisitionAuditError("Git preregistration trust failed") from error
    environment = git_environment()
    try:
        head_before = subprocess.run(  # noqa: S603 - fixed trusted Git identity query
            [git, "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=environment,
            text=True,
            timeout=10,
        ).stdout.strip()
        if _GIT_OBJECT_ID.fullmatch(head_before) is None:
            raise AcquisitionAuditError("canonical acquisition HEAD is invalid")
        if _clean_repository_status(git, repo_root, environment):
            raise AcquisitionAuditError("production acquisition requires a clean repository")
        authority_commit = execution_commit or head_before
        if _GIT_OBJECT_ID.fullmatch(authority_commit) is None:
            raise AcquisitionAuditError("control execution commit is invalid")
        authority_check = subprocess.run(  # noqa: S603 - fixed trusted Git and object ID
            [git, "cat-file", "-e", f"{authority_commit}^{{commit}}"],
            cwd=repo_root,
            check=False,
            env=environment,
            timeout=10,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        authority_ancestry = subprocess.run(  # noqa: S603 - fixed trusted Git ancestry query
            [git, "merge-base", "--is-ancestor", authority_commit, head_before],
            cwd=repo_root,
            check=False,
            env=environment,
            timeout=10,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if authority_check.returncode != 0 or authority_ancestry.returncode != 0:
            raise AcquisitionAuditError("control execution commit is not trusted HEAD ancestry")
        commit_check = subprocess.run(  # noqa: S603 - fixed arguments and typed Git object ID
            [git, "cat-file", "-e", f"{contract.preregistration_commit}^{{commit}}"],
            cwd=repo_root,
            check=False,
            env=environment,
            timeout=10,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if commit_check.returncode != 0:
            raise AcquisitionAuditError("preregistration commit does not resolve")
        preregistration_ancestry = subprocess.run(  # noqa: S603 - validated Git object IDs
            [
                git,
                "merge-base",
                "--is-ancestor",
                contract.preregistration_commit,
                authority_commit,
            ],
            cwd=repo_root,
            check=False,
            env=environment,
            timeout=10,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if preregistration_ancestry.returncode != 0:
            raise AcquisitionAuditError("preregistration commit is not control execution ancestry")
        committed = subprocess.run(  # noqa: S603 - fixed arguments and validated contract fields
            [
                git,
                "show",
                f"{contract.preregistration_commit}:{contract.preregistration_path}",
            ],
            cwd=repo_root,
            check=False,
            capture_output=True,
            env=environment,
            timeout=10,
        )
        if committed.returncode != 0:
            raise AcquisitionAuditError("preregistration path is absent from its frozen commit")
        if sha256_bytes(committed.stdout) != contract.preregistration_sha256:
            raise AcquisitionAuditError("committed preregistration bytes do not match the contract")
        validator_path = "src/fieldtrue/acquisition.py"
        validator_bytes = _read_binding_file(
            repo_root / validator_path,
            "validator source",
        )
        lock_bytes = _read_binding_file(repo_root / "uv.lock", "dependency lock")
        validator_blob = subprocess.run(  # noqa: S603 - fixed path and validated Git object ID
            [git, "cat-file", "blob", contract.validator_git_blob],
            cwd=repo_root,
            check=False,
            capture_output=True,
            env=environment,
            timeout=10,
        )
        if (
            validator_blob.returncode != 0
            or sha256_bytes(validator_blob.stdout) != contract.validator_source_sha256
            or sha256_bytes(validator_bytes) != contract.validator_source_sha256
        ):
            raise AcquisitionAuditError("validator source differs from its control-suite authority")
        if not _executing_validator_matches_source(repo_root, validator_bytes):
            raise AcquisitionAuditError(
                "executing validator does not match the canonical source snapshot"
            )
        if sha256_bytes(lock_bytes) != contract.dependency_lock_sha256:
            raise AcquisitionAuditError("dependency lock differs from the control-suite authority")
        source_closure_before = _acquisition_source_closure(
            git,
            repo_root,
            environment,
            authority_commit=authority_commit,
            repository_head=head_before,
            expected_validator_blob=contract.validator_git_blob,
            expected_validator_sha256=contract.validator_source_sha256,
        )
        head_contract = subprocess.run(  # noqa: S603 - fixed Git operation and path
            [git, "show", f"{head_before}:protocol/acquisition/iter001_contract.json"],
            cwd=repo_root,
            check=False,
            capture_output=True,
            env=environment,
            timeout=10,
        )
        head_after = subprocess.run(  # noqa: S603 - fixed trusted Git identity query
            [git, "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=environment,
            text=True,
            timeout=10,
        ).stdout.strip()
        status_after = _clean_repository_status(git, repo_root, environment)
        source_closure_after = _acquisition_source_closure(
            git,
            repo_root,
            environment,
            authority_commit=authority_commit,
            repository_head=head_after,
            expected_validator_blob=contract.validator_git_blob,
            expected_validator_sha256=contract.validator_source_sha256,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AcquisitionAuditError("Git preregistration verification failed to run") from error
    if head_contract.returncode != 0 or head_contract.stdout != canonical_contract_bytes:
        raise AcquisitionAuditError("canonical acquisition contract is not committed at HEAD")
    try:
        if trusted_repository_git(repo_root) != git:
            raise AcquisitionAuditError("Git preregistration trust changed")
        final_status = _clean_repository_status(git, repo_root, environment)
        head_final = subprocess.run(  # noqa: S603 - fixed trusted Git identity query
            [git, "rev-parse", "--verify", "HEAD^{commit}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=environment,
            text=True,
            timeout=10,
        ).stdout.strip()
        source_closure_final = _acquisition_source_closure(
            git,
            repo_root,
            environment,
            authority_commit=authority_commit,
            repository_head=head_final,
            expected_validator_blob=contract.validator_git_blob,
            expected_validator_sha256=contract.validator_source_sha256,
        )
    except GitTrustError as error:
        raise AcquisitionAuditError("Git preregistration trust changed") from error
    except (OSError, subprocess.SubprocessError) as error:
        raise AcquisitionAuditError("Git preregistration verification failed to run") from error
    if (
        head_after != head_before
        or head_final != head_before
        or status_after
        or final_status
        or source_closure_after != source_closure_before
        or source_closure_final != source_closure_before
        or _read_binding_file(current_path, "current preregistration") != preregistration_bytes
        or _read_binding_file(repo_root / validator_path, "validator source") != validator_bytes
        or _read_binding_file(repo_root / "uv.lock", "dependency lock") != lock_bytes
        or _read_binding_file(canonical_contract_path, "canonical acquisition contract")
        != canonical_contract_bytes
    ):
        raise AcquisitionAuditError("preregistration binding inputs changed during verification")
    return source_closure_before


def render_admission_result(report: AcquisitionAdmissionReport) -> bytes:
    gate_lines = "\n".join(f"- {gate.gate_id}: {gate.status.upper()}" for gate in report.gates)
    scope_statement = (
        "This canonical PASS_PILOT result records construct-complete pilot admission only."
        if report.verdict == "PASS_PILOT" and report.authority_profile == "canonical"
        else (
            "This test-fixture result is local validator evidence and is not publication evidence."
            if report.authority_profile == "test_fixture"
            else "This result does not establish construct-complete pilot admission."
        )
    )
    text = (
        "# Iteration 001 Acquisition Admission Result\n\n"
        f"Verdict: `{report.verdict}`\n\n"
        f"Authority profile: `{report.authority_profile}`\n\n"
        f"Complete eligible physical incidents: {len(report.eligible_incident_ids)}\n\n"
        "## Gates\n\n"
        f"{gate_lines}\n\n"
        "## Authorized next action\n\n"
        f"{report.authorized_next_action}\n\n"
        "## Boundaries\n\n"
        f"{scope_statement} It is not evidence of model performance, diagnosis benefit, recovery "
        "success, safety, transfer, product readiness, or economic value.\n"
    )
    return text.encode("ascii")


def write_admission_output(output_root: Path, report: AcquisitionAdmissionReport) -> None:
    """Publish one atomic report directory; never merge into an existing proof root."""

    if output_root.exists():
        raise AcquisitionAuditError("admission output root must not already exist")
    output_root.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_root.name}.", dir=output_root.parent))
    try:
        report_path = temporary / "admission_report.json"
        result_path = temporary / "RESULT.md"
        atomic_write(report_path, canonical_json_pretty(report))
        atomic_write(result_path, render_admission_result(report))
        manifest = {
            "schema_version": "fieldtrue.acquisition-output-manifest.v1",
            "authority_profile": report.authority_profile,
            "report_sha256": sha256_file(report_path),
            "result_sha256": sha256_file(result_path),
            "contract_sha256": report.contract_sha256,
            "validator_git_blob": report.validator_git_blob,
            "validator_source_sha256": report.validator_source_sha256,
            "trust_registry_sha256": report.trust_registry_sha256,
            "control_suite_sha256": report.control_suite_sha256,
            "candidate_registry_sha256": report.candidate_registry_sha256,
            "comparator_registry_sha256": report.comparator_registry_sha256,
            "split_locks_sha256": report.split_locks_sha256,
            "corpus_sha256": report.corpus_sha256,
            "resource_usage_sha256": report.resource_usage_sha256,
        }
        atomic_write(temporary / "manifest.json", canonical_json_pretty(manifest))
        temporary.rename(output_root)
        directory_fd = os.open(output_root.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
