"""Export and verify committed JSON Schema contracts."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from fieldtrue.acquisition import (
    AcquisitionAdmissionReport,
    AcquisitionCandidateRegistry,
    AcquisitionContract,
    AcquisitionGateResult,
    AcquisitionSplitLocks,
    ActorTrustRegistry,
    AdmissionControlResult,
    AdmissionControlSuiteReceipt,
    ArtifactBinding,
    BoundReview,
    CandidateIncidentRoot,
    ClockCalibrationPair,
    ClockMap,
    ClockMappingEvidence,
    DiagnosticActionContract,
    DiagnosticExecution,
    EvidenceSequenceReceipt,
    EvidenceStreamSequence,
    EvidenceTimeBinding,
    FieldPlaneAssignment,
    IncidentDossier,
    IncidentGroupRecord,
    IncidentResourcePlane,
    IncidentTimeline,
    InterventionComparator,
    InterventionComparatorRegistry,
    LeakageArtifactScan,
    ModelVisibleLeakageScanReport,
    ModelVisibleProjection,
    PermissionDisposition,
    PhysicalProvenanceRecord,
    PlaneIncidentManifest,
    PlaneSeparationReceipt,
    ProtocolReviewRecord,
    ProtocolReviewRegistry,
    RecoveryExecution,
    ResourceCeiling,
    ResourceUsage,
    RoleAssignment,
    SettledOutcomeRecord,
    ShortcutBaselineReport,
    ShortcutRuleResult,
    SignedAttestation,
    SourceManifest,
    SourceResource,
    TrustedActor,
    TruthCustodyReceipt,
)
from fieldtrue.adapters.adapt import (
    AdaptCoverageReport,
    AdaptDatasetLock,
    AdaptIngestionReceipt,
)
from fieldtrue.approvals import ApprovalReceipt
from fieldtrue.canonical import atomic_write, canonical_json_pretty
from fieldtrue.census import (
    CandidateScreening,
    CensusReport,
    ChronologyAssessment,
    RoleInheritanceAssessment,
    SourceFactLocator,
)
from fieldtrue.census import (
    GateResult as CensusGateResult,
)
from fieldtrue.control_authority import (
    ControlExecutionEvidence,
    ControlExecutionManifest,
    ControlManifestEntry,
    GitBoundSource,
)
from fieldtrue.control_observation import (
    ControlObservation,
    FixtureFile,
    FixtureSnapshot,
    PytestLifecycle,
    PytestPhase,
)
from fieldtrue.control_protocol import ControlProducerRequest, ControlProducerResponse
from fieldtrue.domain import (
    AssuranceCertificate,
    ClaimRecord,
    DiscriminatingTest,
    EngineeringValidationReceipt,
    EvidenceBundle,
    HypothesisSet,
    JobSpec,
    MonitorSpecification,
    ReadinessReport,
    RecoveryPlan,
    SafetyEnvelope,
    TestObservation,
    TruthRecord,
    VerificationResult,
)
from fieldtrue.memory import ResearchMemoryRecord
from fieldtrue.receipts import LedgerEvent, LedgerHead, PublicationSignerAnchor, SignerAnchor
from fieldtrue.runtime import RuntimeIdentity
from fieldtrue.shortcut_contracts import (
    OwnerAmendmentApprovalReceipt,
    ShortcutAttestation,
)
from fieldtrue.shortcut_v2_crossfit import (
    CategoricalFittedState,
    CategoricalHoldoutInput,
    CategoricalPredictionManifest,
    CategoricalTrainingExample,
    CrossfitCensus,
    CrossfitFold,
    CrossfitFoldRegistry,
    CrossfitJobIdentity,
    FittedStateRootItem,
    IncidentLocalHypothesisMap,
    PredictionRootItem,
    TreeFittedState,
    TreePredictionManifest,
)
from fieldtrue.shortcut_v2_release import (
    RegistryRecomputationAuthoritySubject,
    RuleAxisFoldAuthoritySubject,
    ShortcutReleaseContext,
    TargetEnvelope,
    X25519RecipientIdentity,
)
from fieldtrue.shortcut_v2_tree import (
    DepthTwoExactGiniTree,
    FeatureVector,
    TreePrediction,
)
from fieldtrue.splits import SplitLock
from fieldtrue.terminal_authority import (
    AcquisitionInputEntry,
    AcquisitionInputManifest,
    AdmissionInvalidityRecord,
    AdmissionTerminalRecord,
    AdmissionVerifierCertificate,
)

_SCHEMAS: dict[str, type[BaseModel]] = {
    "acquisition_admission_report.schema.json": AcquisitionAdmissionReport,
    "acquisition_candidate_registry.schema.json": AcquisitionCandidateRegistry,
    "acquisition_contract.schema.json": AcquisitionContract,
    "acquisition_gate_result.schema.json": AcquisitionGateResult,
    "acquisition_split_locks.schema.json": AcquisitionSplitLocks,
    "actor_trust_registry.schema.json": ActorTrustRegistry,
    "admission_control_result.schema.json": AdmissionControlResult,
    "admission_control_suite_receipt.schema.json": AdmissionControlSuiteReceipt,
    "adapt_coverage.schema.json": AdaptCoverageReport,
    "adapt_dataset_lock.schema.json": AdaptDatasetLock,
    "adapt_ingestion_receipt.schema.json": AdaptIngestionReceipt,
    "approval_receipt.schema.json": ApprovalReceipt,
    "artifact_binding.schema.json": ArtifactBinding,
    "assurance_certificate.schema.json": AssuranceCertificate,
    "bound_review.schema.json": BoundReview,
    "candidate_incident_root.schema.json": CandidateIncidentRoot,
    "claim_record.schema.json": ClaimRecord,
    "clock_calibration_pair.schema.json": ClockCalibrationPair,
    "clock_map.schema.json": ClockMap,
    "clock_mapping_evidence.schema.json": ClockMappingEvidence,
    "control_execution_evidence.schema.json": ControlExecutionEvidence,
    "control_execution_manifest.schema.json": ControlExecutionManifest,
    "control_fixture_file.schema.json": FixtureFile,
    "control_fixture_snapshot.schema.json": FixtureSnapshot,
    "control_git_bound_source.schema.json": GitBoundSource,
    "control_manifest_entry.schema.json": ControlManifestEntry,
    "control_observation.schema.json": ControlObservation,
    "control_producer_request.schema.json": ControlProducerRequest,
    "control_producer_response.schema.json": ControlProducerResponse,
    "control_pytest_lifecycle.schema.json": PytestLifecycle,
    "control_pytest_phase.schema.json": PytestPhase,
    "discriminating_test.schema.json": DiscriminatingTest,
    "diagnostic_action_contract.schema.json": DiagnosticActionContract,
    "diagnostic_execution.schema.json": DiagnosticExecution,
    "engineering_validation_receipt.schema.json": EngineeringValidationReceipt,
    "evidence_bundle.schema.json": EvidenceBundle,
    "evidence_sequence_receipt.schema.json": EvidenceSequenceReceipt,
    "evidence_stream_sequence.schema.json": EvidenceStreamSequence,
    "evidence_time_binding.schema.json": EvidenceTimeBinding,
    "field_plane_assignment.schema.json": FieldPlaneAssignment,
    "hypothesis_set.schema.json": HypothesisSet,
    "incident_dossier.schema.json": IncidentDossier,
    "incident_group_record.schema.json": IncidentGroupRecord,
    "incident_resource_plane.schema.json": IncidentResourcePlane,
    "incident_timeline.schema.json": IncidentTimeline,
    "intervention_comparator.schema.json": InterventionComparator,
    "intervention_comparator_registry.schema.json": InterventionComparatorRegistry,
    "leakage_artifact_scan.schema.json": LeakageArtifactScan,
    "job_spec.schema.json": JobSpec,
    "ledger_event.schema.json": LedgerEvent,
    "ledger_head.schema.json": LedgerHead,
    "monitor_specification.schema.json": MonitorSpecification,
    "model_visible_projection.schema.json": ModelVisibleProjection,
    "model_visible_leakage_scan_report.schema.json": ModelVisibleLeakageScanReport,
    "plane_incident_manifest.schema.json": PlaneIncidentManifest,
    "plane_separation_receipt.schema.json": PlaneSeparationReceipt,
    "permission_disposition.schema.json": PermissionDisposition,
    "physical_provenance.schema.json": PhysicalProvenanceRecord,
    "protocol_review_record.schema.json": ProtocolReviewRecord,
    "protocol_review_registry.schema.json": ProtocolReviewRegistry,
    "publication_signer_anchor.schema.json": PublicationSignerAnchor,
    "readiness_report.schema.json": ReadinessReport,
    "recovery_plan.schema.json": RecoveryPlan,
    "recovery_execution.schema.json": RecoveryExecution,
    "research_memory.schema.json": ResearchMemoryRecord,
    "resource_ceiling.schema.json": ResourceCeiling,
    "resource_usage.schema.json": ResourceUsage,
    "role_assignment.schema.json": RoleAssignment,
    "runtime_identity.schema.json": RuntimeIdentity,
    "safety_envelope.schema.json": SafetyEnvelope,
    "settled_outcome.schema.json": SettledOutcomeRecord,
    "shortcut_rule_result.schema.json": ShortcutRuleResult,
    "shortcut_baseline_report.schema.json": ShortcutBaselineReport,
    "census_candidate_screening.schema.json": CandidateScreening,
    "census_chronology_assessment.schema.json": ChronologyAssessment,
    "census_gate_result.schema.json": CensusGateResult,
    "census_report.schema.json": CensusReport,
    "census_role_inheritance.schema.json": RoleInheritanceAssessment,
    "census_source_fact_locator.schema.json": SourceFactLocator,
    "shortcut_owner_approval_receipt.schema.json": OwnerAmendmentApprovalReceipt,
    "shortcut_attestation.schema.json": ShortcutAttestation,
    "shortcut_v2_categorical_fitted_state.schema.json": CategoricalFittedState,
    "shortcut_v2_categorical_holdout_input.schema.json": CategoricalHoldoutInput,
    "shortcut_v2_categorical_prediction_manifest.schema.json": CategoricalPredictionManifest,
    "shortcut_v2_categorical_training_example.schema.json": CategoricalTrainingExample,
    "shortcut_v2_crossfit_census.schema.json": CrossfitCensus,
    "shortcut_v2_crossfit_fold.schema.json": CrossfitFold,
    "shortcut_v2_crossfit_fold_registry.schema.json": CrossfitFoldRegistry,
    "shortcut_v2_crossfit_job_identity.schema.json": CrossfitJobIdentity,
    "shortcut_v2_exact_gini_tree.schema.json": DepthTwoExactGiniTree,
    "shortcut_v2_feature_vector.schema.json": FeatureVector,
    "shortcut_v2_fitted_state_root_item.schema.json": FittedStateRootItem,
    "shortcut_v2_local_hypothesis_map.schema.json": IncidentLocalHypothesisMap,
    "shortcut_v2_prediction_root_item.schema.json": PredictionRootItem,
    "shortcut_v2_registry_recomputation_subject.schema.json": (
        RegistryRecomputationAuthoritySubject
    ),
    "shortcut_v2_release_context.schema.json": ShortcutReleaseContext,
    "shortcut_v2_rule_axis_fold_subject.schema.json": RuleAxisFoldAuthoritySubject,
    "shortcut_v2_target_envelope.schema.json": TargetEnvelope,
    "shortcut_v2_tree_fitted_state.schema.json": TreeFittedState,
    "shortcut_v2_tree_prediction.schema.json": TreePrediction,
    "shortcut_v2_tree_prediction_manifest.schema.json": TreePredictionManifest,
    "shortcut_v2_x25519_recipient_identity.schema.json": X25519RecipientIdentity,
    "signed_attestation.schema.json": SignedAttestation,
    "signer_anchor.schema.json": SignerAnchor,
    "split_lock.schema.json": SplitLock,
    "source_manifest.schema.json": SourceManifest,
    "source_resource.schema.json": SourceResource,
    "test_observation.schema.json": TestObservation,
    "truth_record.schema.json": TruthRecord,
    "truth_custody_receipt.schema.json": TruthCustodyReceipt,
    "trusted_actor.schema.json": TrustedActor,
    "verification_result.schema.json": VerificationResult,
    "acquisition_input_entry.schema.json": AcquisitionInputEntry,
    "acquisition_input_manifest.schema.json": AcquisitionInputManifest,
    "admission_invalidity_record.schema.json": AdmissionInvalidityRecord,
    "admission_terminal_record.schema.json": AdmissionTerminalRecord,
    "admission_verifier_certificate.schema.json": AdmissionVerifierCertificate,
}


def schema_documents() -> dict[str, bytes]:
    return {
        filename: canonical_json_pretty(model.model_json_schema(mode="validation"))
        for filename, model in _SCHEMAS.items()
    }


def export_schemas(repo_root: Path) -> list[Path]:
    schema_root = repo_root / "protocol" / "schemas"
    schema_root.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for filename, content in schema_documents().items():
        path = schema_root / filename
        atomic_write(path, content)
        paths.append(path)
    return paths


def verify_schemas(repo_root: Path) -> list[str]:
    errors: list[str] = []
    schema_root = repo_root / "protocol" / "schemas"
    expected = schema_documents()
    for filename, content in expected.items():
        path = schema_root / filename
        if not path.is_file():
            errors.append(f"missing schema: {path.relative_to(repo_root)}")
        elif path.read_bytes() != content:
            errors.append(f"stale schema: {path.relative_to(repo_root)}")
    unexpected = {path.name for path in schema_root.glob("*.json") if path.name not in expected}
    errors.extend(f"unexpected schema: protocol/schemas/{name}" for name in sorted(unexpected))
    return errors
