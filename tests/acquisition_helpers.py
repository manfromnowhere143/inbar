from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

from nacl.signing import SigningKey
from pydantic import BaseModel

from fieldtrue.acquisition import (
    _CONTROL_REQUIREMENTS,
    _FORBIDDEN_MODEL_VISIBLE_FIELDS,
    _REQUIRED_CONTROL_IDS,
    _REQUIRED_SHORTCUT_RULE_IDS,
    AcquisitionCandidateRegistry,
    AcquisitionContract,
    AcquisitionSplitLocks,
    ActorTrustRegistry,
    AdmissionControlResult,
    AdmissionControlSuiteReceipt,
    ArtifactBinding,
    AttestationSubjectKind,
    BoundReview,
    CandidateIncidentRoot,
    ClockCalibrationPair,
    ClockMap,
    ClockMappingEvidence,
    DiagnosticActionContract,
    DiagnosticExecution,
    EvidencePlane,
    EvidenceSequenceReceipt,
    EvidenceStreamSequence,
    EvidenceTimeBinding,
    EvidenceTrack,
    FieldPlaneAssignment,
    IncidentDossier,
    IncidentGroupRecord,
    IncidentResourcePlane,
    IncidentTimeline,
    InterventionComparator,
    InterventionComparatorRegistry,
    ModelVisibleProjection,
    PermissionDecision,
    PermissionDisposition,
    PermissionKind,
    Physicality,
    PhysicalProvenanceRecord,
    PlaneIncidentManifest,
    PlaneSeparationReceipt,
    ProtocolReviewRecord,
    ProtocolReviewRegistry,
    RecoveryExecution,
    ResourceCeiling,
    ResourceUsage,
    ReviewPurpose,
    RoleAssignment,
    RoleKind,
    SettledOutcomeRecord,
    ShortcutBaselineReport,
    ShortcutRuleResult,
    SourceManifest,
    SourceResource,
    SystemDomain,
    TrustedActor,
    TruthCustodyReceipt,
    attestation_subject_hash,
    build_model_visible_leakage_scan,
    issue_actor_trust_registry,
    issue_attestation,
)
from fieldtrue.approvals import ApprovalSubjectKind, authorization_subject_hash, issue_approval
from fieldtrue.canonical import sha256_file, sha256_value, write_json
from fieldtrue.domain import (
    ArtifactRef,
    CausalHypothesis,
    DiscriminatingTest,
    EvidenceBundle,
    EvidenceItem,
    ExecutionAuthority,
    HypothesisSet,
    Modality,
    RecoveryPlan,
    SafetyEnvelope,
    SelectedTest,
    TestObservation,
    TestOutcomeModel,
    TruthRecord,
    VerificationResult,
)
from fieldtrue.planning import expected_information_gain_bits, select_discriminating_test
from fieldtrue.splits import SplitUnit, freeze_group_split

BASE = datetime(2026, 7, 15, tzinfo=UTC)
ANCHOR_KEY = SigningKey(hashlib.sha256(b"fieldtrue-test-trust-anchor").digest())
ACTOR_KEYS = {
    role: SigningKey(hashlib.sha256(f"fieldtrue-test-actor:{role.value}".encode()).digest())
    for role in RoleKind
}
SAFETY_KEY = ACTOR_KEYS[RoleKind.SAFETY_REVIEWER]

VALIDATOR_GIT_BLOB = "3" * 40
VALIDATOR_SOURCE_SHA256 = "4" * 64
DEPENDENCY_LOCK_SHA256 = "5" * 64
FIXTURE_BUILDER_GIT_BLOB = "6" * 40
FIXTURE_BUILDER_SHA256 = "7" * 64
CONTROL_TEST_GIT_BLOB = "8" * 40
CONTROL_TEST_SHA256 = "9" * 64
GENERATOR_GIT_BLOB = "a" * 40
GENERATOR_SHA256 = "b" * 64
DEPENDENCY_LOCK_GIT_BLOB = "c" * 40
EXECUTION_COMMIT = "d" * 40
EXECUTION_TREE = "e" * 40

M = TypeVar("M", bound=BaseModel)


def _deterministic_bytes(label: str, size: int = 2048) -> bytes:
    blocks: list[bytes] = []
    counter = 0
    while sum(len(block) for block in blocks) < size:
        blocks.append(hashlib.sha256(f"{label}:{counter}".encode()).digest())
        counter += 1
    return b"".join(blocks)[:size]


def _write_bytes(
    root: Path,
    relative: str,
    content: bytes,
    media_type: str = "application/octet-stream",
) -> ArtifactBinding:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return ArtifactBinding(
        path=relative,
        sha256=sha256_file(path),
        bytes=path.stat().st_size,
        media_type=media_type,
    )


def _write_model(root: Path, relative: str, value: object) -> ArtifactBinding:
    path = root / relative
    write_json(path, value)
    return ArtifactBinding(
        path=relative,
        sha256=sha256_file(path),
        bytes=path.stat().st_size,
        media_type="application/json",
    )


def _artifact_ref(
    binding: ArtifactBinding,
    identifier: str,
    *,
    clock_domain: str = "reference-clock",
) -> ArtifactRef:
    return ArtifactRef(
        artifact_id=identifier,
        uri=binding.path,
        sha256=binding.sha256,
        bytes=binding.bytes,
        media_type=binding.media_type,
        source_authority="fixture-testbed",
        clock_domain=clock_domain,
        license_ref="internal-fixture",
    )


def _signed_model(
    model: type[M],
    body: dict[str, Any],
    *,
    subject_kind: AttestationSubjectKind,
    signing_key: SigningKey,
    signer_id: str,
    attestation_id: str,
    issued_at: datetime,
) -> M:
    placeholder = issue_attestation(
        signing_key,
        attestation_id=f"{attestation_id}-placeholder",
        signer_id=signer_id,
        subject_kind=subject_kind,
        subject_sha256="0" * 64,
        issued_at=issued_at,
    )
    preliminary = model.model_validate({**body, "attestation": placeholder})
    subject = preliminary.model_dump(mode="json", exclude={"attestation"})
    attestation = issue_attestation(
        signing_key,
        attestation_id=attestation_id,
        signer_id=signer_id,
        subject_kind=subject_kind,
        subject_sha256=attestation_subject_hash(subject_kind, subject),
        issued_at=issued_at,
    )
    return model.model_validate({**body, "attestation": attestation})


def _actor_id(role: RoleKind) -> str:
    return f"actor-{role.value}"


def _actor_group(role: RoleKind) -> str:
    return f"group-{role.value}"


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


def _roles(
    actors: tuple[TrustedActor, ...],
    disclosures: dict[RoleKind, ArtifactBinding],
) -> tuple[RoleAssignment, ...]:
    actor_by_role = {actor.authorized_roles[0]: actor for actor in actors}
    return tuple(
        RoleAssignment(
            role=role,
            actor_id=actor_by_role[role].actor_id,
            independence_group_id=actor_by_role[role].independence_group_id,
            conflict_disclosure=disclosures[role],
            approval_public_key=actor_by_role[role].public_key,
        )
        for role in RoleKind
    )


def _review(
    *,
    incident_id: str,
    purpose: ReviewPurpose,
    subject: BaseModel,
    producer_role: RoleKind,
    reviewer_role: RoleKind,
    reviewed_at: datetime,
    evidence: ArtifactBinding,
) -> BoundReview:
    return _signed_model(
        BoundReview,
        {
            "review_id": f"{incident_id}-{purpose.value}-review",
            "purpose": purpose,
            "subject_sha256": sha256_value(subject),
            "producer_role": producer_role,
            "reviewer_role": reviewer_role,
            "reviewed_at": reviewed_at,
            "evidence": (evidence,),
        },
        subject_kind=AttestationSubjectKind.REVIEW,
        signing_key=ACTOR_KEYS[reviewer_role],
        signer_id=_actor_id(reviewer_role),
        attestation_id=f"{incident_id}-{purpose.value}-review-attestation",
        issued_at=reviewed_at,
    )


def _build_control_suite(root: Path | None = None) -> AdmissionControlSuiteReceipt:
    controls: list[AdmissionControlResult] = []
    for control_id in _REQUIRED_CONTROL_IDS:
        node_id, verdict, gate_id, failure_code = _CONTROL_REQUIREMENTS[control_id]
        fixture_sha256 = sha256_value({"frozen_control": control_id})
        report_sha256 = sha256_value(
            {
                "control_id": control_id,
                "verdict": verdict,
                "gate_id": gate_id,
                "failure_code": failure_code,
            }
        )
        evidence_payload = {
            "control_id": control_id,
            "fixture_sha256": fixture_sha256,
            "report_sha256": report_sha256,
            "observed_verdict": verdict,
            "observed_gate_id": gate_id,
            "observed_failure_code": failure_code,
            "fixture_only": True,
        }
        evidence = (
            _write_model(root, f"control-evidence/{control_id}.json", evidence_payload)
            if root is not None
            else ArtifactBinding(
                path=f"control-evidence/{control_id}.json",
                sha256=sha256_value(evidence_payload),
                bytes=0,
                media_type="application/json",
            )
        )
        controls.append(
            AdmissionControlResult(
                control_id=control_id,
                fixture_sha256=fixture_sha256,
                report_sha256=report_sha256,
                evidence=evidence,
                pytest_node_id=node_id,
                expected_verdict=verdict,
                observed_verdict=verdict,
                expected_gate_id=gate_id,
                observed_gate_id=gate_id,
                expected_failure_code=failure_code,
                observed_failure_code=failure_code,
                passed=True,
            )
        )
    manifest_payload = {
        "execution_commit": EXECUTION_COMMIT,
        "execution_tree": EXECUTION_TREE,
        "controls": [
            {
                "control_id": control.control_id,
                "evidence_sha256": control.evidence.sha256,
            }
            for control in controls
        ],
        "fixture_only": True,
    }
    execution_manifest = (
        _write_model(root, "control-evidence/execution-manifest.json", manifest_payload)
        if root is not None
        else ArtifactBinding(
            path="control-evidence/execution-manifest.json",
            sha256=sha256_value(manifest_payload),
            bytes=0,
            media_type="application/json",
        )
    )
    return _signed_model(
        AdmissionControlSuiteReceipt,
        {
            "suite_id": "iter001-admission-controls-v1",
            "validator_git_blob": VALIDATOR_GIT_BLOB,
            "validator_source_sha256": VALIDATOR_SOURCE_SHA256,
            "fixture_builder_git_blob": FIXTURE_BUILDER_GIT_BLOB,
            "fixture_builder_sha256": FIXTURE_BUILDER_SHA256,
            "control_test_git_blob": CONTROL_TEST_GIT_BLOB,
            "control_test_sha256": CONTROL_TEST_SHA256,
            "generator_git_blob": GENERATOR_GIT_BLOB,
            "generator_sha256": GENERATOR_SHA256,
            "dependency_lock_git_blob": DEPENDENCY_LOCK_GIT_BLOB,
            "dependency_lock_sha256": DEPENDENCY_LOCK_SHA256,
            "execution_commit": EXECUTION_COMMIT,
            "execution_tree": EXECUTION_TREE,
            "execution_manifest": execution_manifest,
            "executed_at": BASE + timedelta(hours=3),
            "controls": tuple(controls),
        },
        subject_kind=AttestationSubjectKind.CONTROL_SUITE,
        signing_key=ANCHOR_KEY,
        signer_id="fixture-trust-anchor",
        attestation_id="iter001-control-suite-attestation",
        issued_at=BASE + timedelta(hours=3),
    )


def acquisition_contract(
    *,
    control_suite: AdmissionControlSuiteReceipt | None = None,
) -> AcquisitionContract:
    suite = control_suite or _build_control_suite()
    return AcquisitionContract(
        authority_profile="test_fixture",
        control_authority_status="test_fixture",
        iteration_id="iter001_physical_causal_evidence_acquisition",
        preregistration_path=(
            "experiments/iter001_physical_causal_evidence_acquisition/HYPOTHESIS.md"
        ),
        preregistration_commit="1" * 40,
        preregistration_sha256="2" * 64,
        required_permissions=(
            PermissionKind.ACQUIRE,
            PermissionKind.PROCESS,
            PermissionKind.RETAIN_RAW,
            PermissionKind.RETAIN_DERIVED,
            PermissionKind.PUBLISH_METADATA,
            PermissionKind.INDEPENDENT_REVIEW,
            PermissionKind.COMMERCIAL_RESEARCH,
        ),
        minimum_complete_physical_incidents=30,
        minimum_system_families=3,
        minimum_hardware_identities=6,
        minimum_identities_per_system_family=2,
        minimum_fault_families=3,
        minimum_incidents_per_system_family=6,
        minimum_incidents_per_fault_family=6,
        minimum_incidents_per_hardware_identity=3,
        maximum_family_share=0.5,
        minimum_faults_per_system_family=2,
        minimum_system_families_per_fault=2,
        required_domains=(SystemDomain.AEROSPACE, SystemDomain.ROBOTICS),
        minimum_operational_modalities=2,
        max_clock_alignment_error_ns=100_000_000,
        max_clock_missing_fraction=0.05,
        trust_anchor_public_key=ANCHOR_KEY.verify_key.encode().hex(),
        validator_git_blob=VALIDATOR_GIT_BLOB,
        validator_source_sha256=VALIDATOR_SOURCE_SHA256,
        dependency_lock_sha256=DEPENDENCY_LOCK_SHA256,
        control_suite_sha256=sha256_value(suite),
        resource_ceiling=ResourceCeiling(
            max_cpu_seconds=14_400,
            max_wall_seconds=7_200,
            max_peak_memory_bytes=16 * 1024**3,
            max_downloaded_bytes=1024**3,
            max_peak_staged_bytes=2 * 1024**3,
            max_derived_bytes=2 * 1024**3,
            max_gpu_seconds=0,
            max_cloud_jobs=0,
            max_paid_calls=0,
            max_cost_usd="0",
        ),
    )


def build_acquisition_tree(
    root: Path,
    *,
    count: int = 30,
    blocked_permission: PermissionKind | None = None,
    zero_information_test: bool = False,
) -> AcquisitionContract:
    terms = _write_bytes(root, "common/terms.txt", b"internal fixture terms\n", "text/plain")
    source_bytes = _write_bytes(root, "common/source.bin", b"physical source fixture\n")
    parser_coverage = _write_model(root, "common/parser-coverage.json", {"complete": True})
    projection_implementation = _write_bytes(
        root,
        "common/projection-implementation.txt",
        b"select only enumerated operational streams\n",
        "text/plain",
    )
    review_evidence = _write_bytes(
        root,
        "common/review-evidence.txt",
        b"independent fixture review completed\n",
        "text/plain",
    )

    mandates: dict[RoleKind, ArtifactBinding] = {}
    disclosures: dict[RoleKind, ArtifactBinding] = {}
    actors: list[TrustedActor] = []
    for role in RoleKind:
        mandates[role] = _write_bytes(
            root,
            f"authority/{role.value}/mandate.txt",
            f"fixture mandate for {role.value}\n".encode(),
            "text/plain",
        )
        disclosures[role] = _write_bytes(
            root,
            f"authority/{role.value}/conflicts.txt",
            f"no fixture conflict for {role.value}\n".encode(),
            "text/plain",
        )
        actors.append(
            TrustedActor(
                actor_id=_actor_id(role),
                independence_group_id=_actor_group(role),
                public_key=ACTOR_KEYS[role].verify_key.encode().hex(),
                authorized_roles=(role,),
                mandate=mandates[role],
            )
        )
    actor_tuple = tuple(actors)
    trust_registry: ActorTrustRegistry = issue_actor_trust_registry(
        ANCHOR_KEY,
        registry_id="iter001-fixture-trust-registry",
        issued_at=BASE,
        actors=actor_tuple,
    )
    write_json(root / "trust_registry.json", trust_registry)
    roles = _roles(actor_tuple, disclosures)

    permissions = tuple(
        PermissionDisposition(
            kind=kind,
            decision=(
                PermissionDecision.UNKNOWN
                if kind == blocked_permission
                else PermissionDecision.ALLOWED
            ),
            scope="internal test fixture",
            basis=terms,
        )
        for kind in PermissionKind
    )
    source_resource = SourceResource(
        resource_id="physical-source-bytes",
        uri="testbed://fixture-testbed/physical-source-bytes",
        version="v1",
        sha256=source_bytes.sha256,
        bytes=source_bytes.bytes,
        media_type=source_bytes.media_type,
        staged_at=BASE + timedelta(minutes=2),
        staged_artifact=source_bytes,
    )
    placeholder = issue_attestation(
        ACTOR_KEYS[RoleKind.RIGHTS_REVIEWER],
        attestation_id="physical-source-rights-placeholder",
        signer_id=_actor_id(RoleKind.RIGHTS_REVIEWER),
        subject_kind=AttestationSubjectKind.SOURCE_RIGHTS,
        subject_sha256="0" * 64,
        issued_at=BASE + timedelta(minutes=1),
    )
    source = SourceManifest(
        source_id="physical-source",
        source_authority="fixture-testbed",
        source_version="v1",
        landing_page="testbed://fixture-testbed/physical-source",
        evidence_track=EvidenceTrack.PHYSICAL_ADMISSION,
        approved_at=BASE + timedelta(minutes=1),
        source_steward_id=_actor_id(RoleKind.SOURCE_STEWARD),
        source_steward_independence_group=_actor_group(RoleKind.SOURCE_STEWARD),
        rights_reviewer_id=_actor_id(RoleKind.RIGHTS_REVIEWER),
        rights_reviewer_independence_group=_actor_group(RoleKind.RIGHTS_REVIEWER),
        terms_artifact=terms,
        permissions=permissions,
        rights_attestation=placeholder,
        resources=(source_resource,),
    )
    rights_attestation = issue_attestation(
        ACTOR_KEYS[RoleKind.RIGHTS_REVIEWER],
        attestation_id="physical-source-rights",
        signer_id=_actor_id(RoleKind.RIGHTS_REVIEWER),
        subject_kind=AttestationSubjectKind.SOURCE_RIGHTS,
        subject_sha256=attestation_subject_hash(
            AttestationSubjectKind.SOURCE_RIGHTS,
            _rights_subject(source),
        ),
        issued_at=source.approved_at,
    )
    source = source.model_copy(update={"rights_attestation": rights_attestation})
    write_json(root / "sources" / "physical-source.json", source)

    incident_ids = [f"incident-{index:03d}" for index in range(count)]
    candidate_incident_ids = [f"incident-{index:03d}" for index in range(max(30, count))]
    candidate_roots: list[CandidateIncidentRoot] = []
    for candidate_id in candidate_incident_ids:
        discovery_evidence = _write_model(
            root,
            f"candidate-discovery/{candidate_id}.json",
            {
                "incident_id": candidate_id,
                "physical_root_observed": True,
                "fixture_only": True,
            },
        )
        candidate_roots.append(
            CandidateIncidentRoot(
                incident_id=candidate_id,
                root_incident_group_id=candidate_id,
                source_id=source.source_id,
                physicality=Physicality.PHYSICAL,
                discovered_at=BASE + timedelta(minutes=4),
                discovery_evidence=discovery_evidence,
            )
        )
    candidate_registry = _signed_model(
        AcquisitionCandidateRegistry,
        {
            "registry_id": "iter001-fixture-candidate-registry",
            "produced_at": BASE + timedelta(minutes=5),
            "registrar_id": _actor_id(RoleKind.STATISTICIAN),
            "candidates": tuple(candidate_roots),
        },
        subject_kind=AttestationSubjectKind.CANDIDATE_REGISTRY,
        signing_key=ACTOR_KEYS[RoleKind.STATISTICIAN],
        signer_id=_actor_id(RoleKind.STATISTICIAN),
        attestation_id="iter001-fixture-candidate-registry-attestation",
        issued_at=BASE + timedelta(minutes=5),
    )
    write_json(root / "candidate_registry.json", candidate_registry)
    incident_hash = sha256_value(sorted(incident_ids))
    evidence_manifest = _write_model(
        root,
        "common/evidence-manifest.json",
        PlaneIncidentManifest(plane="model_visible", incident_ids=tuple(incident_ids)),
    )
    truth_manifest = _write_model(
        root,
        "common/truth-manifest.json",
        PlaneIncidentManifest(plane="truth_only", incident_ids=tuple(incident_ids)),
    )
    plane = PlaneSeparationReceipt(
        source_id=source.source_id,
        source_manifest_sha256=sha256_value(source),
        source_fields=("telemetry", "commands", "fault_label"),
        assignments=(
            FieldPlaneAssignment(
                field_name="telemetry",
                plane=EvidencePlane.MODEL_VISIBLE,
                rationale="operational evidence",
            ),
            FieldPlaneAssignment(
                field_name="commands",
                plane=EvidencePlane.MODEL_VISIBLE,
                rationale="operational evidence",
            ),
            FieldPlaneAssignment(
                field_name="fault_label",
                plane=EvidencePlane.TRUTH_ONLY,
                rationale="sealed mechanism truth",
            ),
        ),
        parser_coverage=parser_coverage,
        evidence_manifest=evidence_manifest,
        truth_manifest=truth_manifest,
        evidence_incident_ids_sha256=incident_hash,
        truth_incident_ids_sha256=incident_hash,
        produced_at=BASE + timedelta(minutes=3),
    )
    plane_binding = _write_model(root, "common/plane-separation.json", plane)
    clock_artifact = _write_model(
        root,
        "common/clock-map.json",
        ClockMappingEvidence(
            clock_domain="reference-clock",
            reference_clock_domain="reference-clock",
            calibration_pairs=(
                ClockCalibrationPair(source_value=0, reference_ns=0),
                ClockCalibrationPair(source_value=900_000_000, reference_ns=900_000_000),
            ),
            expected_samples=100,
            observed_samples=100,
            method="fixture identity calibration",
        ),
    )

    split_units: list[SplitUnit] = []
    for index, incident_id in enumerate(incident_ids):
        prefix = f"artifacts/{incident_id}"
        telemetry = _write_bytes(
            root,
            f"{prefix}/telemetry.json",
            (
                '{"samples_hex":"'
                f'{_deterministic_bytes(f"telemetry:{incident_id}", 1024).hex()}"}}\n'
            ).encode(),
            "application/json",
        )
        commands = _write_bytes(
            root,
            f"{prefix}/commands.json",
            b'{"relay_command":"open"}\n',
            "application/json",
        )
        physical_capture = _write_bytes(
            root,
            f"{prefix}/physical-capture.bin",
            _deterministic_bytes(f"physical-capture:{incident_id}", 2048),
        )
        initiation = _write_bytes(
            root,
            f"{prefix}/initiation.json",
            f'{{"incident":"{incident_id}","initiated":true}}\n'.encode(),
            "application/json",
        )
        baseline = _write_bytes(
            root,
            f"{prefix}/baseline.json",
            f'{{"incident":"{incident_id}","restored":true}}\n'.encode(),
            "application/json",
        )
        test_observation_bytes = _write_bytes(
            root,
            f"{prefix}/test-observation.json",
            f'{{"incident":"{incident_id}","voltage":24.1}}\n'.encode(),
            "application/json",
        )
        diagnostic_command = _write_bytes(
            root,
            f"{prefix}/diagnostic-command.json",
            f'{{"incident":"{incident_id}","command":"pulse"}}\n'.encode(),
            "application/json",
        )
        diagnostic_ack = _write_bytes(
            root,
            f"{prefix}/diagnostic-ack.json",
            f'{{"incident":"{incident_id}","ack":"accepted"}}\n'.encode(),
            "application/json",
        )
        diagnostic_realized = _write_bytes(
            root,
            f"{prefix}/diagnostic-realized.json",
            f'{{"incident":"{incident_id}","realized":"pulse"}}\n'.encode(),
            "application/json",
        )
        constraint_margins = _write_bytes(
            root,
            f"{prefix}/diagnostic-constraints.json",
            f'{{"incident":"{incident_id}","risk_margin":0.01}}\n'.encode(),
            "application/json",
        )
        abort_log = _write_bytes(
            root,
            f"{prefix}/diagnostic-abort-log.json",
            f'{{"incident":"{incident_id}","aborted":false}}\n'.encode(),
            "application/json",
        )
        diagnostic_parameter_bounds = _write_model(
            root,
            f"{prefix}/diagnostic-parameter-bounds.json",
            {"pulse_seconds": {"minimum": 0.5, "maximum": 1.0}},
        )
        diagnostic_abort_specification = _write_model(
            root,
            f"{prefix}/diagnostic-abort-specification.json",
            {"abort_on_voltage_below": 23.0, "maximum_latency_ms": 10},
        )
        recovery_commanded = _write_bytes(
            root,
            f"{prefix}/recovery-command.json",
            f'{{"incident":"{incident_id}","relay":"close"}}\n'.encode(),
            "application/json",
        )
        recovery_realized = _write_bytes(
            root,
            f"{prefix}/recovery-realized.json",
            f'{{"incident":"{incident_id}","relay":"closed"}}\n'.encode(),
            "application/json",
        )
        settled_bytes = _write_bytes(
            root,
            f"{prefix}/settled.json",
            b'{"stable":true}\n',
            "application/json",
        )
        predicate = _write_model(
            root,
            f"{prefix}/settled-predicate.json",
            {"voltage_min": 23.5, "dwell_seconds": 600},
        )
        predicate_evaluation = _write_model(
            root,
            f"{prefix}/predicate-evaluation.json",
            {"incident_id": incident_id, "passed": True},
        )
        recurrence_evidence = _write_model(
            root,
            f"{prefix}/recurrence-evidence.json",
            {"incident_id": incident_id, "recurrence": False},
        )
        resource_measurement = _write_model(
            root,
            f"{prefix}/resource-measurement.json",
            {"incident_id": incident_id, "source": "fixture counters"},
        )

        family_index = index % 3
        family = f"system-family-{family_index}"
        sequence_in_family = index // 3
        hardware_id = f"{family}-hardware-{sequence_in_family % 2}"
        fault_family = f"fault-family-{sequence_in_family % 3}"
        domain = (
            SystemDomain.AEROSPACE
            if family_index == 0
            else SystemDomain.ROBOTICS
            if family_index == 1
            else SystemDomain.INDUSTRIAL
        )
        group = IncidentGroupRecord(
            incident_id=incident_id,
            root_incident_group_id=incident_id,
            acquisition_session_id=f"session-{index:03d}",
            independence_group_id=f"incident-group-{index:03d}",
            physicality=Physicality.PHYSICAL,
            system_domain=domain,
            system_family=family,
            hardware_id=hardware_id,
            fault_family=fault_family,
            configuration_id=f"configuration-{family_index}-{sequence_in_family % 2}",
            environment_id=f"environment-{family_index}",
            acquisition_lineage_id=f"lineage-{index:03d}",
            mission_id=f"mission-{family_index}",
            site_id=f"site-{family_index}",
            claim_bearing=True,
        )
        timeline = IncidentTimeline(
            source_acquired_at=BASE + timedelta(minutes=10),
            truth_committed_at=BASE + timedelta(minutes=20),
            evidence_cutoff_at=BASE + timedelta(minutes=30),
            model_visible_cutoff_ns=1_000_000_000,
            hypothesis_committed_at=BASE + timedelta(minutes=40),
            safe_test_reviewed_at=BASE + timedelta(minutes=50),
            test_started_at=BASE + timedelta(minutes=60),
            test_finished_at=BASE + timedelta(minutes=61),
            recovery_plan_committed_at=BASE + timedelta(minutes=70),
            recovery_started_at=BASE + timedelta(minutes=80),
            recovery_finished_at=BASE + timedelta(minutes=81),
            settled_window_started_at=BASE + timedelta(minutes=82),
            settled_window_finished_at=BASE + timedelta(minutes=92),
            outcome_verified_at=BASE + timedelta(minutes=93),
            truth_unsealed_at=BASE + timedelta(minutes=95),
        )
        provenance = _signed_model(
            PhysicalProvenanceRecord,
            {
                "provenance_id": f"{incident_id}-provenance",
                "incident_id": incident_id,
                "root_incident_group_id": group.root_incident_group_id,
                "acquisition_session_id": group.acquisition_session_id,
                "independence_group_id": group.independence_group_id,
                "acquisition_lineage_id": group.acquisition_lineage_id,
                "source_id": source.source_id,
                "source_resource_id": source_resource.resource_id,
                "system_family": family,
                "hardware_id": hardware_id,
                "configuration_id": group.configuration_id,
                "environment_id": group.environment_id,
                "site_id": group.site_id,
                "acquired_at": timeline.source_acquired_at,
                "independently_initiated": True,
                "baseline_restored_before": True,
                "initiation_evidence": initiation,
                "baseline_evidence": baseline,
                "physical_capture": physical_capture,
            },
            subject_kind=AttestationSubjectKind.PHYSICAL_PROVENANCE,
            signing_key=ACTOR_KEYS[RoleKind.SOURCE_STEWARD],
            signer_id=_actor_id(RoleKind.SOURCE_STEWARD),
            attestation_id=f"{incident_id}-provenance-attestation",
            issued_at=timeline.source_acquired_at,
        )

        hypothesis_ids = (
            f"{incident_id}-relay-open",
            f"{incident_id}-sensor-bias",
            f"{incident_id}-unknown",
        )
        test_id = f"{incident_id}-diagnostic-test"
        recovery_id = f"{incident_id}-recovery"
        outcome_ref = _artifact_ref(settled_bytes, f"{incident_id}-settled-artifact")
        truth = TruthRecord(
            incident_id=incident_id,
            commitment_nonce=hashlib.sha256(f"nonce-{incident_id}".encode()).hexdigest(),
            hardware_family=family,
            hardware_id=hardware_id,
            fault_family=fault_family,
            mechanism_ids=(f"mechanism-{fault_family}",),
            cause_authority=_actor_id(RoleKind.MECHANISM_REVIEWER),
            verification_method="controlled physical injection and calibrated measurement",
            injection_method="human-approved testbed injection",
            injection_times=((BASE + timedelta(minutes=15)).isoformat(),),
            competing_hypothesis_ids=hypothesis_ids,
            safe_discriminating_test_ids=(test_id,),
            settled_outcome_refs=(outcome_ref,),
        )
        truth_access_log = _write_model(
            root,
            f"{prefix}/truth-access-log.json",
            {
                "incident_id": incident_id,
                "accesses": ["commit", "authorized-unseal"],
                "unauthorized_access": False,
            },
        )
        truth_custody = _signed_model(
            TruthCustodyReceipt,
            {
                "custody_id": f"{incident_id}-truth-custody",
                "incident_id": incident_id,
                "truth_record_sha256": sha256_value(truth),
                "custodian_id": _actor_id(RoleKind.MECHANISM_REVIEWER),
                "committed_at": timeline.truth_committed_at,
                "unsealed_at": timeline.truth_unsealed_at,
                "access_log": truth_access_log,
                "unauthorized_access_detected": False,
            },
            subject_kind=AttestationSubjectKind.TRUTH_CUSTODY,
            signing_key=ACTOR_KEYS[RoleKind.MECHANISM_REVIEWER],
            signer_id=_actor_id(RoleKind.MECHANISM_REVIEWER),
            attestation_id=f"{incident_id}-truth-custody-attestation",
            issued_at=timeline.truth_unsealed_at,
        )
        evidence = EvidenceBundle(
            incident_id=incident_id,
            system_family=family,
            system_id=hardware_id,
            mission_id=group.mission_id,
            evidence=(
                EvidenceItem(
                    evidence_id=f"{incident_id}-telemetry",
                    modality=Modality.TELEMETRY,
                    artifact=_artifact_ref(telemetry, f"{incident_id}-telemetry-artifact"),
                    observed_start="0",
                    observed_end="900000000",
                    description="clocked voltage telemetry",
                ),
                EvidenceItem(
                    evidence_id=f"{incident_id}-commands",
                    modality=Modality.COMMAND_LOG,
                    artifact=_artifact_ref(commands, f"{incident_id}-commands-artifact"),
                    observed_start="0",
                    observed_end="900000000",
                    description="clocked command history",
                ),
            ),
            truth_commitment=sha256_value(truth),
        )
        sequence_streams = tuple(
            EvidenceStreamSequence(
                evidence_id=evidence_item.evidence_id,
                artifact_sha256=evidence_item.artifact.sha256,
                artifact_bytes=evidence_item.artifact.bytes,
                chunk_bytes=64,
                ordered_chunk_sha256=tuple(
                    hashlib.sha256(content[offset : offset + 64]).hexdigest()
                    for offset in range(0, len(content), 64)
                ),
                source_order_monotonic=True,
            )
            for evidence_item, content in (
                (evidence.evidence[0], (root / telemetry.path).read_bytes()),
                (evidence.evidence[1], (root / commands.path).read_bytes()),
            )
        )
        evidence_sequence = _signed_model(
            EvidenceSequenceReceipt,
            {
                "receipt_id": f"{incident_id}-evidence-sequence",
                "incident_id": incident_id,
                "produced_at": BASE + timedelta(minutes=12),
                "source_steward_id": _actor_id(RoleKind.SOURCE_STEWARD),
                "streams": sequence_streams,
            },
            subject_kind=AttestationSubjectKind.EVIDENCE_SEQUENCE,
            signing_key=ACTOR_KEYS[RoleKind.SOURCE_STEWARD],
            signer_id=_actor_id(RoleKind.SOURCE_STEWARD),
            attestation_id=f"{incident_id}-evidence-sequence-attestation",
            issued_at=BASE + timedelta(minutes=12),
        )
        evidence_sequence_binding = _write_model(
            root,
            f"{prefix}/evidence-sequence.json",
            evidence_sequence,
        )
        leakage_scan = _write_model(
            root,
            f"{prefix}/projection-leakage-scan.json",
            build_model_visible_leakage_scan(
                root,
                incident_id=incident_id,
                artifacts=(telemetry, commands),
                identity_values=(
                    incident_id,
                    group.root_incident_group_id,
                    group.acquisition_session_id,
                    group.independence_group_id,
                    group.acquisition_lineage_id,
                    group.system_family,
                    group.hardware_id,
                    group.fault_family,
                    group.configuration_id,
                    group.environment_id,
                    group.mission_id,
                    group.site_id,
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
                ),
            ),
        )
        projection = _signed_model(
            ModelVisibleProjection,
            {
                "projection_id": f"{incident_id}-model-visible-projection",
                "incident_id": incident_id,
                "source_manifest_sha256": sha256_value(source),
                "plane_separation_sha256": sha256_value(plane),
                "evidence_bundle_sha256": sha256_value(evidence),
                "model_input_artifacts": (telemetry, commands),
                "excluded_fields": _FORBIDDEN_MODEL_VISIBLE_FIELDS,
                "projection_implementation": projection_implementation,
                "leakage_scan": leakage_scan,
                "leakage_detected": False,
                "projected_at": BASE + timedelta(minutes=29),
                "curator_id": _actor_id(RoleKind.EVIDENCE_CURATOR),
            },
            subject_kind=AttestationSubjectKind.MODEL_VISIBLE_PROJECTION,
            signing_key=ACTOR_KEYS[RoleKind.EVIDENCE_CURATOR],
            signer_id=_actor_id(RoleKind.EVIDENCE_CURATOR),
            attestation_id=f"{incident_id}-projection-attestation",
            issued_at=BASE + timedelta(minutes=29),
        )
        hypotheses = HypothesisSet(
            incident_id=incident_id,
            proposer_id=_actor_id(RoleKind.HYPOTHESIS_PROPOSER),
            hypotheses=(
                CausalHypothesis(
                    hypothesis_id=hypothesis_ids[0],
                    description="relay failed open",
                    prior=0.45,
                ),
                CausalHypothesis(
                    hypothesis_id=hypothesis_ids[1],
                    description="sensor bias",
                    prior=0.45,
                ),
                CausalHypothesis(
                    hypothesis_id=hypothesis_ids[2],
                    description="mechanism outside the catalog",
                    prior=0.10,
                    unknown=True,
                ),
            ),
        )
        positive = (
            dict.fromkeys(hypothesis_ids, 0.5)
            if zero_information_test
            else {
                hypothesis_ids[0]: 0.9,
                hypothesis_ids[1]: 0.1,
                hypothesis_ids[2]: 0.5,
            }
        )
        negative = (
            dict(positive)
            if zero_information_test
            else {
                hypothesis_ids[0]: 0.1,
                hypothesis_ids[1]: 0.9,
                hypothesis_ids[2]: 0.5,
            }
        )
        candidate_base = DiscriminatingTest(
            test_id=test_id,
            description="briefly energize an isolated diagnostic path",
            authority=ExecutionAuthority.TESTBED,
            approved=True,
            cost_units=1.0,
            duration_seconds=60.0,
            risk=0.01,
            preconditions=("isolated",),
            outcome_model=(
                TestOutcomeModel(
                    outcome_id=f"{incident_id}-signal-high",
                    probability_by_hypothesis=positive,
                ),
                TestOutcomeModel(
                    outcome_id=f"{incident_id}-signal-low",
                    probability_by_hypothesis=negative,
                ),
            ),
            approval_receipt_hash="0" * 64,
        )
        envelope_base = SafetyEnvelope(
            envelope_id=f"{incident_id}-envelope",
            authority=ExecutionAuthority.TESTBED,
            allowed_test_ids=(test_id,),
            max_risk=0.02,
            satisfied_preconditions=("isolated",),
            approval_receipt_hash="0" * 64,
        )
        diagnostic_action_contract = DiagnosticActionContract(
            action_contract_id=f"{incident_id}-diagnostic-action-contract",
            incident_id=incident_id,
            test_id=test_id,
            command_sha256=diagnostic_command.sha256,
            expected_realized_action_sha256=diagnostic_realized.sha256,
            parameter_bounds=diagnostic_parameter_bounds,
            abort_specification=diagnostic_abort_specification,
            max_duration_seconds=60.0,
            max_risk=0.02,
            max_cost_usd="10",
            committed_at=BASE + timedelta(minutes=45),
        )
        diagnostic_action_contract_binding = _write_model(
            root,
            f"{prefix}/diagnostic-action-contract.json",
            diagnostic_action_contract,
        )
        test_subject = authorization_subject_hash(
            ApprovalSubjectKind.TEST_EXECUTION,
            {
                "candidate": candidate_base.model_dump(
                    mode="json", exclude={"approval_receipt_hash"}
                ),
                "safety_envelope": envelope_base.model_dump(
                    mode="json", exclude={"approval_receipt_hash"}
                ),
                "diagnostic_action_contract": diagnostic_action_contract.model_dump(mode="json"),
            },
        )
        test_approval = issue_approval(
            SAFETY_KEY,
            approval_id=f"{incident_id}-test-approval",
            issuer_id=_actor_id(RoleKind.SAFETY_REVIEWER),
            subject_kind=ApprovalSubjectKind.TEST_EXECUTION,
            subject_sha256=test_subject,
            authority=ExecutionAuthority.TESTBED,
            scope="isolated fixture diagnostic test",
            max_risk=0.02,
            max_cost_usd="10",
            not_before=BASE,
            expires_at=BASE + timedelta(days=1),
            nonce=hashlib.sha256(f"test-approval-{incident_id}".encode()).hexdigest(),
        )
        candidate = candidate_base.model_copy(
            update={"approval_receipt_hash": test_approval.receipt_hash}
        )
        envelope = envelope_base.model_copy(
            update={"approval_receipt_hash": test_approval.receipt_hash}
        )
        if zero_information_test:
            gain = expected_information_gain_bits(
                {item.hypothesis_id: item.prior for item in hypotheses.hypotheses},
                candidate,
            )
            selected = SelectedTest(
                incident_id=incident_id,
                test_id=test_id,
                expected_information_gain_bits=gain,
                denominator=61.01,
                utility=0,
                posterior_before={item.hypothesis_id: item.prior for item in hypotheses.hypotheses},
                planner_id=_actor_id(RoleKind.TEST_SELECTOR),
                candidate_sha256=sha256_value(candidate),
                safety_envelope_sha256=sha256_value(envelope),
            )
        else:
            selected = select_discriminating_test(
                hypotheses,
                (candidate,),
                envelope,
                planner_id=_actor_id(RoleKind.TEST_SELECTOR),
                approval_receipt=test_approval,
                expected_approval_signer=SAFETY_KEY.verify_key.encode().hex(),
                approval_time=timeline.test_started_at,
                approval_subject_extension={
                    "diagnostic_action_contract": diagnostic_action_contract.model_dump(mode="json")
                },
            )
        observation = TestObservation(
            incident_id=incident_id,
            test_id=test_id,
            outcome_id=f"{incident_id}-signal-high",
            authority=ExecutionAuthority.TESTBED,
            executor_id=_actor_id(RoleKind.TEST_EXECUTOR),
            started_at=timeline.test_started_at,
            finished_at=timeline.test_finished_at,
            observation_artifact=_artifact_ref(
                test_observation_bytes,
                f"{incident_id}-test-observation-artifact",
            ),
            safety_envelope_id=envelope.envelope_id,
            candidate_sha256=sha256_value(candidate),
            safety_envelope_sha256=sha256_value(envelope),
            approval_receipt_hash=test_approval.receipt_hash,
        )
        diagnostic_execution = _signed_model(
            DiagnosticExecution,
            {
                "execution_id": f"{incident_id}-diagnostic-execution",
                "incident_id": incident_id,
                "test_id": test_id,
                "executor_id": _actor_id(RoleKind.TEST_EXECUTOR),
                "candidate_sha256": sha256_value(candidate),
                "safety_envelope_sha256": sha256_value(envelope),
                "observation_sha256": sha256_value(observation),
                "authority": ExecutionAuthority.TESTBED,
                "started_at": timeline.test_started_at,
                "commanded_at": timeline.test_started_at + timedelta(seconds=10),
                "acknowledged_at": timeline.test_started_at + timedelta(seconds=20),
                "realized_at": timeline.test_started_at + timedelta(seconds=30),
                "finished_at": timeline.test_finished_at,
                "approval_receipt_hash": test_approval.receipt_hash,
                "action_contract": diagnostic_action_contract_binding,
                "command": diagnostic_command,
                "acknowledgement": diagnostic_ack,
                "realized_action": diagnostic_realized,
                "constraint_margins": constraint_margins,
                "abort_log": abort_log,
                "direct_cost_usd": "1",
            },
            subject_kind=AttestationSubjectKind.DIAGNOSTIC_EXECUTION,
            signing_key=ACTOR_KEYS[RoleKind.TEST_EXECUTOR],
            signer_id=_actor_id(RoleKind.TEST_EXECUTOR),
            attestation_id=f"{incident_id}-diagnostic-attestation",
            issued_at=timeline.test_finished_at,
        )
        recovery_base = RecoveryPlan(
            recovery_id=recovery_id,
            incident_id=incident_id,
            hypothesis_id=hypothesis_ids[0],
            proposer_id=_actor_id(RoleKind.RECOVERY_PROPOSER),
            action="close the isolated relay",
            target="restore the nominal power path",
            expected_settled_state={"voltage_min": 23.5},
            authority=ExecutionAuthority.TESTBED,
            approval_receipt_hash="0" * 64,
        )
        recovery_subject = authorization_subject_hash(
            ApprovalSubjectKind.RECOVERY_EXECUTION,
            {
                "recovery_plan": recovery_base.model_dump(
                    mode="json", exclude={"approval_receipt_hash"}
                ),
                "settled_predicate_sha256": predicate.sha256,
            },
        )
        recovery_approval = issue_approval(
            SAFETY_KEY,
            approval_id=f"{incident_id}-recovery-approval",
            issuer_id=_actor_id(RoleKind.SAFETY_REVIEWER),
            subject_kind=ApprovalSubjectKind.RECOVERY_EXECUTION,
            subject_sha256=recovery_subject,
            authority=ExecutionAuthority.TESTBED,
            scope="isolated fixture recovery",
            max_risk=0.02,
            max_cost_usd="10",
            not_before=BASE,
            expires_at=BASE + timedelta(days=1),
            nonce=hashlib.sha256(f"recovery-approval-{incident_id}".encode()).hexdigest(),
        )
        recovery_plan = recovery_base.model_copy(
            update={"approval_receipt_hash": recovery_approval.receipt_hash}
        )
        recovery_execution = _signed_model(
            RecoveryExecution,
            {
                "execution_id": f"{incident_id}-recovery-execution",
                "recovery_id": recovery_id,
                "incident_id": incident_id,
                "executor_id": _actor_id(RoleKind.RECOVERY_EXECUTOR),
                "plan_sha256": sha256_value(recovery_plan),
                "authority": ExecutionAuthority.TESTBED,
                "started_at": timeline.recovery_started_at,
                "finished_at": timeline.recovery_finished_at,
                "approval_receipt_hash": recovery_approval.receipt_hash,
                "commanded_action": recovery_commanded,
                "realized_action": recovery_realized,
                "cost_usd": "1",
            },
            subject_kind=AttestationSubjectKind.RECOVERY_EXECUTION,
            signing_key=ACTOR_KEYS[RoleKind.RECOVERY_EXECUTOR],
            signer_id=_actor_id(RoleKind.RECOVERY_EXECUTOR),
            attestation_id=f"{incident_id}-recovery-execution-attestation",
            issued_at=timeline.recovery_finished_at,
        )
        settled = _signed_model(
            SettledOutcomeRecord,
            {
                "outcome_id": f"{incident_id}-outcome",
                "incident_id": incident_id,
                "recovery_id": recovery_id,
                "recovery_execution_sha256": sha256_value(recovery_execution),
                "outcome_authority_id": _actor_id(RoleKind.OUTCOME_VERIFIER),
                "outcome_authority_independence_group": _actor_group(RoleKind.OUTCOME_VERIFIER),
                "settled_predicate": predicate,
                "predicate_evaluation": predicate_evaluation,
                "recurrence_evidence": recurrence_evidence,
                "window_started_at": timeline.settled_window_started_at,
                "window_finished_at": timeline.settled_window_finished_at,
                "recurrence_checked": True,
                "constraints_satisfied": True,
                "action_valid": True,
                "target_valid": True,
                "settled_success": True,
                "outcome_artifacts": (settled_bytes,),
            },
            subject_kind=AttestationSubjectKind.SETTLED_OUTCOME,
            signing_key=ACTOR_KEYS[RoleKind.OUTCOME_VERIFIER],
            signer_id=_actor_id(RoleKind.OUTCOME_VERIFIER),
            attestation_id=f"{incident_id}-outcome-attestation",
            issued_at=timeline.outcome_verified_at,
        )
        verification = VerificationResult(
            verification_id=f"{incident_id}-verification",
            recovery_id=recovery_id,
            verifier_id=_actor_id(RoleKind.OUTCOME_VERIFIER),
            proposer_id=_actor_id(RoleKind.RECOVERY_PROPOSER),
            action_valid=True,
            target_valid=True,
            settled_success=True,
            abstained=False,
            outcome_artifacts=(outcome_ref,),
            scope="fixture settled window only",
        )
        incident_resources = IncidentResourcePlane(
            incident_id=incident_id,
            engineering_seconds=120.0,
            diagnostic_test_seconds=60.0,
            recovery_seconds=60.0,
            downtime_seconds=5_520.0,
            compute_seconds=1.0,
            diagnostic_action_cost_usd="1",
            recovery_action_cost_usd="1",
            realized_risk=0.01,
            measurement_artifact=resource_measurement,
        )
        reviews = (
            _review(
                incident_id=incident_id,
                purpose=ReviewPurpose.MECHANISM,
                subject=truth,
                producer_role=RoleKind.TRUTH_PRODUCER,
                reviewer_role=RoleKind.MECHANISM_REVIEWER,
                reviewed_at=timeline.truth_committed_at,
                evidence=review_evidence,
            ),
            _review(
                incident_id=incident_id,
                purpose=ReviewPurpose.AMBIGUITY,
                subject=hypotheses,
                producer_role=RoleKind.HYPOTHESIS_PROPOSER,
                reviewer_role=RoleKind.MECHANISM_REVIEWER,
                reviewed_at=BASE + timedelta(minutes=45),
                evidence=review_evidence,
            ),
            _review(
                incident_id=incident_id,
                purpose=ReviewPurpose.SAFE_TEST,
                subject=candidate,
                producer_role=RoleKind.TEST_PROPOSER,
                reviewer_role=RoleKind.SAFETY_REVIEWER,
                reviewed_at=timeline.safe_test_reviewed_at,
                evidence=review_evidence,
            ),
            _review(
                incident_id=incident_id,
                purpose=ReviewPurpose.RECOVERY,
                subject=recovery_plan,
                producer_role=RoleKind.RECOVERY_PROPOSER,
                reviewer_role=RoleKind.SAFETY_REVIEWER,
                reviewed_at=BASE + timedelta(minutes=75),
                evidence=review_evidence,
            ),
            _review(
                incident_id=incident_id,
                purpose=ReviewPurpose.SETTLED_OUTCOME,
                subject=settled,
                producer_role=RoleKind.RECOVERY_EXECUTOR,
                reviewer_role=RoleKind.OUTCOME_VERIFIER,
                reviewed_at=BASE + timedelta(minutes=94),
                evidence=review_evidence,
            ),
        )
        bindings = {
            "physical_provenance": _write_model(
                root, f"{prefix}/physical-provenance.json", provenance
            ),
            "model_visible_projection": _write_model(
                root, f"{prefix}/model-visible-projection.json", projection
            ),
            "evidence_bundle": _write_model(root, f"{prefix}/evidence-bundle.json", evidence),
            "evidence_sequence": evidence_sequence_binding,
            "truth_record": _write_model(root, f"{prefix}/truth-record.json", truth),
            "truth_custody": _write_model(root, f"{prefix}/truth-custody.json", truth_custody),
            "hypothesis_set": _write_model(root, f"{prefix}/hypothesis-set.json", hypotheses),
            "discriminating_test": _write_model(
                root, f"{prefix}/discriminating-test.json", candidate
            ),
            "selected_test": _write_model(root, f"{prefix}/selected-test.json", selected),
            "safety_envelope": _write_model(root, f"{prefix}/safety-envelope.json", envelope),
            "test_approval": _write_model(root, f"{prefix}/test-approval.json", test_approval),
            "test_observation": _write_model(
                root, f"{prefix}/test-observation-record.json", observation
            ),
            "diagnostic_execution": _write_model(
                root, f"{prefix}/diagnostic-execution.json", diagnostic_execution
            ),
            "recovery_plan": _write_model(root, f"{prefix}/recovery-plan.json", recovery_plan),
            "recovery_approval": _write_model(
                root, f"{prefix}/recovery-approval.json", recovery_approval
            ),
            "recovery_execution": _write_model(
                root, f"{prefix}/recovery-execution.json", recovery_execution
            ),
            "settled_outcome": _write_model(root, f"{prefix}/settled-outcome.json", settled),
            "verification_result": _write_model(
                root, f"{prefix}/verification-result.json", verification
            ),
            "incident_resource_plane": _write_model(
                root, f"{prefix}/incident-resource-plane.json", incident_resources
            ),
        }
        dossier = IncidentDossier(
            dossier_id=f"{incident_id}-dossier",
            source_id=source.source_id,
            source_manifest_sha256=sha256_value(source),
            evidence_track=EvidenceTrack.PHYSICAL_ADMISSION,
            group=group,
            roles=roles,
            reviews=reviews,
            clocks=(
                ClockMap(
                    clock_domain="reference-clock",
                    unit="nanosecond",
                    origin="monotonic testbed start",
                    reference_clock_domain="reference-clock",
                    scale_to_reference=1.0,
                    offset_ns=0,
                    max_alignment_error_ns=0,
                    missing_fraction=0.0,
                    mapping_artifact=clock_artifact,
                ),
            ),
            evidence_times=(
                EvidenceTimeBinding(
                    evidence_id=f"{incident_id}-telemetry",
                    clock_domain="reference-clock",
                    normalized_start_ns=0,
                    normalized_end_ns=900_000_000,
                ),
                EvidenceTimeBinding(
                    evidence_id=f"{incident_id}-commands",
                    clock_domain="reference-clock",
                    normalized_start_ns=0,
                    normalized_end_ns=900_000_000,
                ),
            ),
            timeline=timeline,
            plane_separation_receipt=plane_binding,
            **bindings,
        )
        write_json(root / "dossiers" / f"{incident_id}.json", dossier)
        split_units.append(
            SplitUnit(
                incident_id=incident_id,
                hardware_family=family,
                hardware_id=hardware_id,
                mission_id=group.mission_id,
                fault_family=fault_family,
                evidence_hash=bindings["evidence_bundle"].sha256,
                truth_hash=bindings["truth_record"].sha256,
            )
        )

    split_bindings: dict[str, ArtifactBinding] = {}
    for axis, dimensions in (
        ("hardware_family", ("hardware_family",)),
        ("hardware_identity", ("hardware_id",)),
        ("fault_family", ("fault_family",)),
    ):
        lock = freeze_group_split(
            split_units,
            seed=f"iter001-fixture-{axis}",
            holdout_dimensions=dimensions,
        )
        split_bindings[axis] = _write_model(root, f"splits/{axis}.json", lock)
    split_locks = AcquisitionSplitLocks.model_validate(split_bindings)
    write_json(root / "split_locks.json", split_locks)

    shortcut_results: list[ShortcutRuleResult] = []
    for rule_id in _REQUIRED_SHORTCUT_RULE_IDS:
        implementation = _write_bytes(
            root,
            f"shortcuts/{rule_id}/implementation.txt",
            f"deterministic fixture implementation for {rule_id}\n".encode(),
            "text/plain",
        )
        evaluation = _write_model(
            root,
            f"shortcuts/{rule_id}/evaluation.json",
            {"rule_id": rule_id, "resolves_mechanism_without_action": False},
        )
        shortcut_results.append(
            ShortcutRuleResult(
                rule_id=rule_id,
                implementation=implementation,
                evaluation=evaluation,
                truth_access=False,
                resolves_mechanism_without_action=False,
            )
        )
    shortcut_report = _signed_model(
        ShortcutBaselineReport,
        {
            "report_id": "iter001-fixture-shortcut-baseline",
            "incident_ids_sha256": incident_hash,
            "evaluated_at": BASE + timedelta(hours=2),
            "results": tuple(shortcut_results),
            "statistician_id": _actor_id(RoleKind.STATISTICIAN),
        },
        subject_kind=AttestationSubjectKind.SHORTCUT_BASELINE,
        signing_key=ACTOR_KEYS[RoleKind.STATISTICIAN],
        signer_id=_actor_id(RoleKind.STATISTICIAN),
        attestation_id="iter001-shortcut-baseline-attestation",
        issued_at=BASE + timedelta(hours=2),
    )
    write_json(root / "shortcut_baseline.json", shortcut_report)

    comparators: list[InterventionComparator] = []
    for kind in ("no_op", "random_safe", "cheapest_safe", "wrong_safe"):
        implementation = _write_bytes(
            root,
            f"comparators/{kind}/implementation.txt",
            f"deterministic fixture comparator for {kind}\n".encode(),
            "text/plain",
        )
        evaluation_plan = _write_model(
            root,
            f"comparators/{kind}/evaluation-plan.json",
            {"kind": kind, "eligible_incident_ids_sha256": incident_hash},
        )
        comparators.append(
            InterventionComparator(
                kind=kind,
                implementation=implementation,
                evaluation_plan=evaluation_plan,
                included=True,
            )
        )
    comparator_registry = _signed_model(
        InterventionComparatorRegistry,
        {
            "registry_id": "iter001-fixture-intervention-comparators",
            "incident_ids_sha256": incident_hash,
            "committed_at": BASE + timedelta(hours=2),
            "statistician_id": _actor_id(RoleKind.STATISTICIAN),
            "comparators": tuple(comparators),
        },
        subject_kind=AttestationSubjectKind.COMPARATOR_REGISTRY,
        signing_key=ACTOR_KEYS[RoleKind.STATISTICIAN],
        signer_id=_actor_id(RoleKind.STATISTICIAN),
        attestation_id="iter001-comparator-registry-attestation",
        issued_at=BASE + timedelta(hours=2),
    )
    write_json(root / "intervention_comparators.json", comparator_registry)

    protocol_records: list[ProtocolReviewRecord] = []
    for domain, role in (
        ("aerospace", RoleKind.MECHANISM_REVIEWER),
        ("robotics", RoleKind.SAFETY_REVIEWER),
    ):
        artifact = _write_bytes(
            root,
            f"protocol-reviews/{domain}.txt",
            f"{domain} physical protocol approved for fixture execution\n".encode(),
            "text/plain",
        )
        reviewed_at = BASE + timedelta(minutes=5)
        protocol_records.append(
            _signed_model(
                ProtocolReviewRecord,
                {
                    "domain": domain,
                    "reviewer_id": _actor_id(role),
                    "review_artifact": artifact,
                    "reviewed_at": reviewed_at,
                    "approved_for_physical_execution": True,
                },
                subject_kind=AttestationSubjectKind.PROTOCOL_REVIEW,
                signing_key=ACTOR_KEYS[role],
                signer_id=_actor_id(role),
                attestation_id=f"iter001-{domain}-protocol-attestation",
                issued_at=reviewed_at,
            )
        )
    write_json(
        root / "protocol_reviews.json",
        ProtocolReviewRegistry(reviews=tuple(protocol_records)),
    )

    control_suite = _build_control_suite(root)
    write_json(root / "control_suite_receipt.json", control_suite)
    usage_measurement = _write_model(
        root,
        "common/audit-resource-measurement.json",
        {"method": "test fixture counters", "complete": True},
    )
    usage = _signed_model(
        ResourceUsage,
        {
            "cpu_seconds": 1,
            "wall_seconds": 1,
            "peak_memory_bytes": 1024,
            "downloaded_bytes": 0,
            "peak_staged_bytes": source_bytes.bytes,
            "derived_bytes": 0,
            "gpu_seconds": 0,
            "cloud_jobs": 0,
            "paid_calls": 0,
            "cost_usd": "0",
            "measured_at": BASE + timedelta(hours=2),
            "measurement_method": "test fixture counters",
            "measurement_artifact": usage_measurement,
            "measurer_id": _actor_id(RoleKind.STATISTICIAN),
        },
        subject_kind=AttestationSubjectKind.RESOURCE_USAGE,
        signing_key=ACTOR_KEYS[RoleKind.STATISTICIAN],
        signer_id=_actor_id(RoleKind.STATISTICIAN),
        attestation_id="iter001-resource-usage-attestation",
        issued_at=BASE + timedelta(hours=2),
    )
    write_json(root / "resource_usage.json", usage)
    return acquisition_contract(control_suite=control_suite)
