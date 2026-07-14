"""Corpus qualification gates frozen by iteration 000."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from fieldtrue.adapters.adapt import (
    AdaptCoverageReport,
    AdaptDatasetLock,
    AdaptIngestionReceipt,
    AdaptIngestionResult,
    load_jsonl_models,
)
from fieldtrue.canonical import (
    atomic_write,
    canonical_json,
    canonical_json_pretty,
    read_json,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import (
    EvidenceBundle,
    GateResult,
    GateStatus,
    ReadinessReport,
    ReviewKind,
    TruthRecord,
)
from fieldtrue.splits import SplitUnit, leakage_component_count

_TRUTH_MARKERS = (
    "experimentcontrol",
    "faultinject",
    "antagonistcommand",
    "faulttype",
    "faultmode",
    "faultlocation",
    "faultinjection",
)


def _gate(
    gate_id: str,
    passed: bool,
    observed: Any,
    requirement: str,
    detail: str,
    *,
    invalid_on_failure: bool = False,
    evidence_refs: tuple[str, ...] = (),
) -> GateResult:
    status = (
        GateStatus.PASS
        if passed
        else GateStatus.INVALID
        if invalid_on_failure
        else GateStatus.BLOCKED
    )
    return GateResult(
        gate_id=gate_id,
        status=status,
        observed=observed,
        requirement=requirement,
        evidence_refs=evidence_refs,
        detail=detail,
    )


_GATE_REQUIREMENTS = {
    "source-integrity": "Every resource matches its frozen SHA-256 and byte count.",
    "parser-integrity": (
        "Every discovered experiment is parsed exactly once with an exact evidence/truth join."
    ),
    "truth-separation": (
        "Fault metadata and injection-internal rows are absent from model-visible evidence."
    ),
    "minimum-count": "At least 30 incidents have independently identified mechanisms.",
    "ambiguity": ("At least 30 incidents carry two or more pre-outcome plausible hypotheses."),
    "discriminating-action": (
        "At least 30 incidents have an independently reviewed safe discriminating test."
    ),
    "transfer-support": (
        "At least two hardware families, two hardware identities, and two fault families permit "
        "grouped transfer."
    ),
    "evidence-usefulness": (
        "At least 30 incidents have two operational channels with explicit clock domains."
    ),
}


def invalid_readiness_report(
    *,
    dataset_id: str,
    failed_gate_id: str,
    error_type: str,
    error_message: str,
    passed_gate_ids: tuple[str, ...] = (),
) -> ReadinessReport:
    """Produce the full-weight preregistered INVALID result after early integrity failure."""

    if failed_gate_id not in {"source-integrity", "parser-integrity", "truth-separation"}:
        raise ValueError(f"{failed_gate_id} is not an invalidating integrity gate")
    unknown_passes = set(passed_gate_ids) - set(_GATE_REQUIREMENTS)
    if unknown_passes or failed_gate_id in passed_gate_ids:
        raise ValueError("invalid readiness gate disposition")
    gates = tuple(
        GateResult(
            gate_id=gate_id,
            status=(
                GateStatus.INVALID
                if gate_id == failed_gate_id
                else GateStatus.PASS
                if gate_id in passed_gate_ids
                else GateStatus.NOT_RUN
            ),
            observed=(
                {"error_type": error_type, "message": error_message}
                if gate_id == failed_gate_id
                else {"verified_before_failure": True}
                if gate_id in passed_gate_ids
                else {"reason": f"not run after {failed_gate_id} invalidated the iteration"}
            ),
            requirement=requirement,
            evidence_refs=("proof/invalidity.json",),
            detail=(
                "The integrity failure invalidates this iteration."
                if gate_id == failed_gate_id
                else "This gate completed before the invalidating failure."
                if gate_id in passed_gate_ids
                else "The preregistered stop rule forbids further scientific adjudication."
            ),
        )
        for gate_id, requirement in _GATE_REQUIREMENTS.items()
    )
    return ReadinessReport(
        dataset_id=dataset_id,
        gates=gates,
        verdict="INVALID",
        authorized_next_action=(
            "Repair the source or ingestion integrity failure and rerun only under an explicit "
            "amendment."
        ),
        forbidden_next_actions=(
            "GPU or learned-model training",
            "active-diagnosis performance claim",
            "recovery or safety claim",
            "cross-hardware transfer claim",
            "product or economic-value claim",
        ),
    )


def _source_integrity(
    lock: AdaptDatasetLock,
    result: AdaptIngestionResult,
) -> tuple[bool, dict[str, Any]]:
    expected = {resource.id: resource for resource in lock.resources}
    actual = {receipt.resource_id: receipt for receipt in result.receipt.resource_receipts}
    failures: list[str] = []
    if result.receipt.dataset_lock_content_sha256 != sha256_value(lock):
        failures.append("dataset-lock-content")
    if len(actual) != len(result.receipt.resource_receipts) or set(actual) != set(expected):
        failures.append("resource-set")
    for resource_id, resource in expected.items():
        receipt = actual.get(resource_id)
        if receipt is None:
            continue
        if (
            not receipt.verified
            or receipt.filename != resource.filename
            or receipt.sha256 != resource.sha256
            or receipt.bytes != resource.bytes
        ):
            failures.append(f"receipt:{resource_id}")
            continue
        path = result.raw_root / resource.filename
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != resource.bytes
            or sha256_file(path) != resource.sha256
        ):
            failures.append(f"raw-bytes:{resource_id}")
    return not failures, {
        "locked_resources": len(expected),
        "receipt_resources": len(result.receipt.resource_receipts),
        "failures": failures,
    }


def _review_covers(record: TruthRecord, kind: ReviewKind, subjects: tuple[str, ...]) -> bool:
    covered = {
        subject
        for review in record.review_attestations
        if review.kind == kind
        for subject in review.subject_ids
    }
    return bool(subjects) and set(subjects).issubset(covered)


def _artifact_integrity(
    output_root: Path,
    evidence: list[EvidenceBundle],
    source_hashes: set[str],
) -> tuple[bool, list[str], set[str]]:
    evidence_root = (output_root / "evidence").resolve()
    failures: list[str] = []
    observed_hashes: set[str] = set()
    for bundle in evidence:
        if bundle.context:
            failures.append(f"truth-derived-context:{bundle.incident_id}")
        for item in bundle.evidence:
            pure = PurePosixPath(item.artifact.uri)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or not pure.parts
                or pure.parts[0] != "evidence"
            ):
                failures.append(f"unsafe-uri:{item.evidence_id}")
                continue
            path = output_root.joinpath(*pure.parts)
            try:
                resolved = path.resolve(strict=True)
            except (FileNotFoundError, OSError):
                failures.append(f"missing-artifact:{item.evidence_id}")
                continue
            if path.is_symlink() or not resolved.is_relative_to(evidence_root):
                failures.append(f"escaped-artifact:{item.evidence_id}")
                continue
            actual_hash = sha256_file(resolved)
            if (
                actual_hash != item.artifact.sha256
                or resolved.stat().st_size != item.artifact.bytes
            ):
                failures.append(f"artifact-bytes:{item.evidence_id}")
            if set(item.artifact.lineage_sha256) != source_hashes:
                failures.append(f"artifact-lineage:{item.evidence_id}")
            observed_hashes.add(actual_hash)
    return not failures, failures, observed_hashes


def _ingestion_integrity(
    lock: AdaptDatasetLock,
    result: AdaptIngestionResult,
    evidence: list[EvidenceBundle],
    truth: list[TruthRecord],
) -> dict[str, Any]:
    output_root = result.evidence_manifest_path.parent.parent
    failures: list[str] = []
    if result.evidence_manifest_path != output_root / "manifests" / "evidence.jsonl":
        failures.append("evidence-manifest-location")
    if result.truth_manifest_path != output_root / "truth" / "truth.jsonl":
        failures.append("truth-manifest-location")
    try:
        receipt_on_disk = AdaptIngestionReceipt.model_validate(read_json(result.receipt_path))
        coverage_on_disk = AdaptCoverageReport.model_validate(read_json(result.coverage_path))
    except (OSError, ValueError) as error:
        failures.append(f"producer-artifact-parse:{type(error).__name__}")
        receipt_on_disk = None
        coverage_on_disk = None
    if receipt_on_disk != result.receipt:
        failures.append("receipt-object")
    if coverage_on_disk != result.coverage:
        failures.append("coverage-object")
    expected_hashes = {
        result.evidence_manifest_path: result.receipt.evidence_manifest_sha256,
        result.truth_manifest_path: result.receipt.truth_manifest_sha256,
        result.coverage_path: result.receipt.coverage_report_sha256,
    }
    for path, expected_hash in expected_hashes.items():
        if not path.is_file() or sha256_file(path) != expected_hash:
            failures.append(f"producer-artifact-hash:{path.name}")
    evidence_ids = [record.incident_id for record in evidence]
    truth_ids = [record.incident_id for record in truth]
    if len(evidence_ids) != len(set(evidence_ids)):
        failures.append("duplicate-evidence-incident")
    if len(truth_ids) != len(set(truth_ids)):
        failures.append("duplicate-truth-incident")
    evidence_by_id = {record.incident_id: record for record in evidence}
    truth_by_id = {record.incident_id: record for record in truth}
    if set(evidence_by_id) != set(truth_by_id) or len(evidence) != len(truth):
        failures.append("evidence-truth-join")
    commitment_failures = [
        incident_id
        for incident_id, record in truth_by_id.items()
        if incident_id not in evidence_by_id
        or evidence_by_id[incident_id].truth_commitment != sha256_value(record)
    ]
    failures.extend(f"truth-commitment:{incident_id}" for incident_id in commitment_failures)
    source_hashes = {resource.sha256 for resource in lock.resources}
    artifacts_passed, artifact_failures, observed_hashes = _artifact_integrity(
        output_root, evidence, source_hashes
    )
    failures.extend(artifact_failures)
    if observed_hashes != set(result.receipt.derived_artifact_hashes):
        failures.append("derived-artifact-set")
    evidence_text = (
        result.evidence_manifest_path.read_text(encoding="utf-8").casefold()
        if result.evidence_manifest_path.is_file()
        else ""
    )
    marker_failures = [marker for marker in _TRUTH_MARKERS if marker in evidence_text]
    failures.extend(f"truth-marker:{marker}" for marker in marker_failures)
    return {
        "passed": not failures and artifacts_passed,
        "failures": failures,
        "exact_join": not any(
            item in failures
            for item in (
                "duplicate-evidence-incident",
                "duplicate-truth-incident",
                "evidence-truth-join",
            )
        ),
        "commitments_passed": not commitment_failures,
        "markers": marker_failures,
    }


def _adjudicate_readiness(
    *,
    dataset_id: str,
    source_integrity: bool,
    source_observed: dict[str, Any],
    parser_integrity: bool,
    parser_observed: dict[str, Any],
    truth_separation: bool,
    truth_observed: dict[str, Any],
    evidence: list[EvidenceBundle],
    truth: list[TruthRecord],
) -> ReadinessReport:
    evidence_by_id = {record.incident_id: record for record in evidence}
    truth_by_id = {record.incident_id: record for record in truth}
    verified_causes = sum(
        _review_covers(record, ReviewKind.CAUSE, record.mechanism_ids) for record in truth
    )
    ambiguous = sum(
        len(record.competing_hypothesis_ids) >= 2
        and _review_covers(record, ReviewKind.AMBIGUITY, record.competing_hypothesis_ids)
        for record in truth
    )
    safe_tests = sum(
        _review_covers(record, ReviewKind.SAFE_TEST, record.safe_discriminating_test_ids)
        for record in truth
    )
    hardware_families = sorted({record.hardware_family for record in truth})
    hardware_identities = sorted({record.hardware_id for record in truth})
    fault_families = sorted({record.fault_family for record in truth})
    useful_evidence = sum(
        len({item.modality for item in bundle.evidence}) >= 2
        and all(item.artifact.clock_domain for item in bundle.evidence)
        for bundle in evidence
    )
    split_units = [
        SplitUnit(
            incident_id=incident_id,
            hardware_family=truth_by_id[incident_id].hardware_family,
            hardware_id=truth_by_id[incident_id].hardware_id,
            mission_id=evidence_by_id[incident_id].mission_id,
            fault_family=truth_by_id[incident_id].fault_family,
            evidence_hash=sha256_value(evidence_by_id[incident_id]),
            truth_hash=sha256_value(truth_by_id[incident_id]),
        )
        for incident_id in sorted(set(evidence_by_id) & set(truth_by_id))
    ]
    try:
        transfer_components = leakage_component_count(split_units)
    except ValueError:
        transfer_components = 0
    gates = (
        _gate(
            "source-integrity",
            source_integrity,
            source_observed,
            "Every resource matches its frozen SHA-256 and byte count.",
            "The source lock must fail closed on changed bytes.",
            invalid_on_failure=True,
            evidence_refs=("protocol/datasets/nasa_adapt_v1.json", "proof/ingestion_receipt.json"),
        ),
        _gate(
            "parser-integrity",
            parser_integrity,
            parser_observed,
            "Every discovered experiment is parsed exactly once with an exact evidence/truth join.",
            "Silent file, row, or join loss invalidates the run.",
            invalid_on_failure=True,
            evidence_refs=("proof/coverage.json",),
        ),
        _gate(
            "truth-separation",
            truth_separation,
            truth_observed,
            "Fault metadata and injection-internal rows are absent from model-visible evidence.",
            "Truth is represented only by a commitment in the evidence plane.",
            invalid_on_failure=True,
            evidence_refs=("proof/coverage.json", "proof/ingestion_receipt.json"),
        ),
        _gate(
            "minimum-count",
            verified_causes >= 30,
            verified_causes,
            "At least 30 incidents have independently identified mechanisms.",
            "Counts incidents, not telemetry windows.",
            evidence_refs=("proof/readiness_report.json",),
        ),
        _gate(
            "ambiguity",
            ambiguous >= 30,
            ambiguous,
            "At least 30 incidents carry two or more pre-outcome plausible hypotheses.",
            "A fault label alone does not demonstrate diagnostic ambiguity.",
            evidence_refs=("proof/readiness_report.json",),
        ),
        _gate(
            "discriminating-action",
            safe_tests >= 30,
            safe_tests,
            "At least 30 incidents have an independently reviewed safe discriminating test.",
            "Static telemetry cannot imply unobserved counterfactual test outcomes.",
            evidence_refs=("proof/readiness_report.json",),
        ),
        _gate(
            "transfer-support",
            len(hardware_families) >= 2
            and len(hardware_identities) >= 2
            and len(fault_families) >= 2
            and transfer_components >= 3,
            {
                "hardware_families": hardware_families,
                "hardware_identities": hardware_identities,
                "fault_families": fault_families,
                "leakage_components": transfer_components,
            },
            "At least two hardware families, two hardware identities, and two fault families "
            "permit grouped transfer.",
            "One physical testbed cannot establish cross-hardware transfer.",
            evidence_refs=("proof/readiness_report.json",),
        ),
        _gate(
            "evidence-usefulness",
            useful_evidence == len(evidence) and useful_evidence >= 30,
            {"useful_incidents": useful_evidence, "total_incidents": len(evidence)},
            "At least 30 incidents have two operational channels with explicit clock domains.",
            "Channel count does not itself establish a multimodal benefit.",
            evidence_refs=("proof/readiness_report.json",),
        ),
    )
    verdict: Literal["PASS", "BLOCKED_EVIDENCE", "INVALID"]
    if any(gate.status == GateStatus.INVALID for gate in gates):
        verdict = "INVALID"
        authorized = "Repair ingestion or source integrity and rerun under an explicit amendment."
    elif all(gate.status == GateStatus.PASS for gate in gates):
        verdict = "PASS"
        authorized = "Freeze grouped splits and execute the cheap deterministic baseline ladder."
    else:
        verdict = "BLOCKED_EVIDENCE"
        authorized = (
            "Acquire additional independently verified physical incidents and reviewed safe test "
            "actions; ADAPT remains parser and evidence-plane validation only."
        )
    return ReadinessReport(
        dataset_id=dataset_id,
        gates=gates,
        verdict=verdict,
        authorized_next_action=authorized,
        forbidden_next_actions=(
            "GPU or learned-model training",
            "active-diagnosis performance claim",
            "recovery or safety claim",
            "cross-hardware transfer claim",
            "product or economic-value claim",
        ),
    )


def audit_adapt_readiness(
    lock: AdaptDatasetLock,
    result: AdaptIngestionResult,
) -> ReadinessReport:
    evidence = load_jsonl_models(result.evidence_manifest_path, EvidenceBundle)
    truth = load_jsonl_models(result.truth_manifest_path, TruthRecord)
    evidence_by_id = {record.incident_id: record for record in evidence}
    truth_by_id = {record.incident_id: record for record in truth}
    exact_join = (
        set(evidence_by_id) == set(truth_by_id)
        and len(evidence_by_id) == len(evidence)
        and len(truth_by_id) == len(truth)
        and len(evidence) == len(truth)
    )
    source_integrity, source_observed = _source_integrity(lock, result)
    ingestion_integrity = _ingestion_integrity(lock, result, evidence, truth)
    parser_integrity = (
        ingestion_integrity["passed"]
        and result.coverage.exact_file_coverage
        and result.coverage.parsed_files == result.coverage.expected_files
        and result.receipt.evidence_bundle_count == result.coverage.expected_files
        and result.receipt.truth_record_count == result.coverage.expected_files
        and exact_join
    )
    truth_separation = (
        result.receipt.truth_separation_passed
        and ingestion_integrity["passed"]
        and ingestion_integrity["commitments_passed"]
        and not ingestion_integrity["markers"]
        and not result.coverage.leakage_markers_found
    )
    return _adjudicate_readiness(
        dataset_id=result.receipt.dataset_id,
        source_integrity=source_integrity,
        source_observed=source_observed,
        parser_integrity=parser_integrity,
        parser_observed={
            "expected": result.coverage.expected_files,
            "parsed": result.coverage.parsed_files,
            "exact_join": exact_join,
            "integrity_failures": ingestion_integrity["failures"],
        },
        truth_separation=truth_separation,
        truth_observed={"leakage_markers": list(result.coverage.leakage_markers_found)},
        evidence=evidence,
        truth=truth,
    )


def audit_adapt_proof_readiness(
    lock: AdaptDatasetLock,
    receipt: AdaptIngestionReceipt,
    coverage: AdaptCoverageReport,
    coverage_path: Path,
    evidence_manifest_path: Path,
    truth_manifest_path: Path,
) -> ReadinessReport:
    """Recompute the frozen readiness gates using only durable proof artifacts.

    Raw NASA bytes are intentionally not redistributed. Source integrity is therefore
    recomputed from the signed, exact resource receipts and the proof-local lock; the parser
    and scientific gates are recomputed from the separately sealed evidence and truth planes.
    """

    evidence = load_jsonl_models(evidence_manifest_path, EvidenceBundle)
    truth = load_jsonl_models(truth_manifest_path, TruthRecord)
    evidence_bytes = b"".join(canonical_json(record) + b"\n" for record in evidence)
    truth_bytes = b"".join(canonical_json(record) + b"\n" for record in truth)

    expected_resources = {resource.id: resource for resource in lock.resources}
    actual_resources = {item.resource_id: item for item in receipt.resource_receipts}
    source_failures: list[str] = []
    if receipt.dataset_lock_content_sha256 != sha256_value(lock):
        source_failures.append("dataset-lock-content")
    if receipt.dataset_id != lock.dataset_id:
        source_failures.append("dataset-id")
    if len(actual_resources) != len(receipt.resource_receipts) or set(actual_resources) != set(
        expected_resources
    ):
        source_failures.append("resource-set")
    for resource_id, resource in expected_resources.items():
        actual = actual_resources.get(resource_id)
        if actual is None:
            continue
        if (
            not actual.verified
            or actual.filename != resource.filename
            or actual.sha256 != resource.sha256
            or actual.bytes != resource.bytes
        ):
            source_failures.append(f"receipt:{resource_id}")

    evidence_ids = [record.incident_id for record in evidence]
    truth_ids = [record.incident_id for record in truth]
    evidence_by_id = {record.incident_id: record for record in evidence}
    truth_by_id = {record.incident_id: record for record in truth}
    exact_join = (
        set(evidence_by_id) == set(truth_by_id)
        and len(evidence_by_id) == len(evidence)
        and len(truth_by_id) == len(truth)
        and len(evidence) == len(truth)
    )
    integrity_failures: list[str] = []
    if evidence_manifest_path.read_bytes() != evidence_bytes:
        integrity_failures.append("noncanonical-evidence-manifest")
    if truth_manifest_path.read_bytes() != truth_bytes:
        integrity_failures.append("noncanonical-truth-manifest")
    if sha256_file(evidence_manifest_path) != receipt.evidence_manifest_sha256:
        integrity_failures.append("evidence-manifest-hash")
    if sha256_file(truth_manifest_path) != receipt.truth_manifest_sha256:
        integrity_failures.append("truth-manifest-hash")
    if coverage_path.read_bytes() != canonical_json_pretty(coverage):
        integrity_failures.append("noncanonical-coverage-report")
    if coverage.expected_files != lock.expected_experiment_files:
        integrity_failures.append("coverage-lock-count")
    if (
        coverage.discovered_files != lock.expected_experiment_files
        or coverage.parsed_files != lock.expected_experiment_files
        or not coverage.exact_file_coverage
        or len(coverage.files) != lock.expected_experiment_files
    ):
        integrity_failures.append("coverage-exactness")
    coverage_names = [item.filename for item in coverage.files]
    coverage_incidents = [item.experiment_id for item in coverage.files]
    if len(coverage_names) != len(set(coverage_names)):
        integrity_failures.append("duplicate-coverage-file")
    if len(coverage_incidents) != len(set(coverage_incidents)):
        integrity_failures.append("duplicate-coverage-incident")
    if set(coverage_incidents) != set(evidence_ids):
        integrity_failures.append("coverage-evidence-join")
    if receipt.coverage_report_sha256 != sha256_file(coverage_path):
        integrity_failures.append("coverage-report-hash")
    if (
        receipt.experiment_count != coverage.parsed_files
        or receipt.evidence_bundle_count != len(evidence)
        or receipt.truth_record_count != len(truth)
    ):
        integrity_failures.append("receipt-counts")
    if len(evidence_ids) != len(set(evidence_ids)):
        integrity_failures.append("duplicate-evidence-incident")
    if len(truth_ids) != len(set(truth_ids)):
        integrity_failures.append("duplicate-truth-incident")
    if not exact_join:
        integrity_failures.append("evidence-truth-join")

    commitment_failures = [
        incident_id
        for incident_id, truth_record in truth_by_id.items()
        if incident_id not in evidence_by_id
        or evidence_by_id[incident_id].truth_commitment != sha256_value(truth_record)
    ]
    integrity_failures.extend(
        f"truth-commitment:{incident_id}" for incident_id in commitment_failures
    )

    source_hashes = {resource.sha256 for resource in lock.resources}
    artifact_ids: list[str] = []
    evidence_item_ids: list[str] = []
    artifact_uris: list[str] = []
    artifact_hashes: list[str] = []
    for bundle in evidence:
        if bundle.context:
            integrity_failures.append(f"truth-derived-context:{bundle.incident_id}")
        for item in bundle.evidence:
            pure = PurePosixPath(item.artifact.uri)
            if (
                pure.is_absolute()
                or ".." in pure.parts
                or not pure.parts
                or pure.parts[0] != "evidence"
            ):
                integrity_failures.append(f"unsafe-uri:{item.evidence_id}")
            if set(item.artifact.lineage_sha256) != source_hashes:
                integrity_failures.append(f"artifact-lineage:{item.evidence_id}")
            artifact_ids.append(item.artifact.artifact_id)
            evidence_item_ids.append(item.evidence_id)
            artifact_uris.append(item.artifact.uri)
            artifact_hashes.append(item.artifact.sha256)
    for label, values in (
        ("artifact-id", artifact_ids),
        ("evidence-id", evidence_item_ids),
        ("artifact-uri", artifact_uris),
    ):
        if len(values) != len(set(values)):
            integrity_failures.append(f"duplicate-{label}")
    if tuple(sorted(artifact_hashes)) != receipt.derived_artifact_hashes:
        integrity_failures.append("derived-artifact-set")

    evidence_text = evidence_manifest_path.read_text(encoding="utf-8").casefold()
    marker_failures = [marker for marker in _TRUTH_MARKERS if marker in evidence_text]
    integrity_failures.extend(f"truth-marker:{marker}" for marker in marker_failures)
    parser_integrity = not integrity_failures
    truth_separation = (
        receipt.truth_separation_passed
        and parser_integrity
        and not commitment_failures
        and not marker_failures
        and not coverage.leakage_markers_found
    )
    return _adjudicate_readiness(
        dataset_id=receipt.dataset_id,
        source_integrity=not source_failures,
        source_observed={
            "locked_resources": len(expected_resources),
            "receipt_resources": len(receipt.resource_receipts),
            "failures": source_failures,
        },
        parser_integrity=parser_integrity,
        parser_observed={
            "expected": coverage.expected_files,
            "parsed": coverage.parsed_files,
            "exact_join": exact_join,
            "integrity_failures": integrity_failures,
        },
        truth_separation=truth_separation,
        truth_observed={"leakage_markers": list(coverage.leakage_markers_found)},
        evidence=evidence,
        truth=truth,
    )


def render_readiness_result(report: ReadinessReport) -> str:
    rows = [
        "| Gate | Status | Observed | Requirement |",
        "|---|---|---|---|",
    ]
    for gate in report.gates:
        observed = json.dumps(gate.observed, ensure_ascii=True, sort_keys=True)
        rows.append(
            f"| `{gate.gate_id}` | **{gate.status.value.upper()}** | "
            f"`{observed}` | {gate.requirement} |"
        )
    return "\n".join(
        (
            "# Iteration 000 Result",
            "",
            f"**Verdict: `{report.verdict}`**",
            "",
            "This is a corpus and construct-readiness result, not a diagnosis benchmark.",
            "",
            *rows,
            "",
            "## Authorized next action",
            "",
            report.authorized_next_action,
            "",
            "## Forbidden conclusions",
            "",
            *(f"- {item}" for item in report.forbidden_next_actions),
            "",
            "NASA does not endorse this project. No model, recovery, safety, transfer, product, "
            "state-of-the-art, or economic claim is authorized by this iteration.",
            "",
        )
    )


def write_readiness_artifacts(
    report: ReadinessReport,
    report_path: Path,
    result_path: Path,
) -> None:
    atomic_write(report_path, canonical_json_pretty(report))
    atomic_write(result_path, render_readiness_result(report).encode())
