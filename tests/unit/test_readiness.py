from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from fieldtrue.adapters.adapt import (
    AdaptCoverageReport,
    AdaptDatasetLock,
    AdaptIngestionResult,
    ingest_adapt_dataset,
    load_jsonl_models,
)
from fieldtrue.canonical import (
    canonical_json,
    canonical_json_pretty,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import (
    EvidenceBundle,
    GateStatus,
    ReviewAttestation,
    ReviewKind,
    TruthRecord,
)
from fieldtrue.readiness import (
    audit_adapt_readiness,
    render_readiness_result,
    write_readiness_artifacts,
)
from tests.helpers import HASH_A, create_adapt_source


def _ingested(tmp_path: Path):
    raw_root = tmp_path / "raw"
    lock, receipts = create_adapt_source(raw_root)
    result = ingest_adapt_dataset(lock, raw_root, tmp_path / "derived", receipts)
    return lock, result


def _seal_fixture(
    result: AdaptIngestionResult,
    evidence: list[EvidenceBundle],
    truth: list[TruthRecord],
) -> AdaptIngestionResult:
    truth_by_id = {record.incident_id: record for record in truth}
    committed_evidence = [
        record.model_copy(
            update={"truth_commitment": sha256_value(truth_by_id[record.incident_id])}
        )
        for record in evidence
    ]
    result.evidence_manifest_path.write_bytes(
        b"".join(canonical_json(record) + b"\n" for record in committed_evidence)
    )
    result.truth_manifest_path.write_bytes(
        b"".join(canonical_json(record) + b"\n" for record in truth)
    )
    receipt = result.receipt.model_copy(
        update={
            "evidence_manifest_sha256": sha256_file(result.evidence_manifest_path),
            "truth_manifest_sha256": sha256_file(result.truth_manifest_path),
        }
    )
    result.receipt_path.write_bytes(canonical_json_pretty(receipt))
    return result.__class__(
        receipt=receipt,
        coverage=result.coverage,
        evidence_manifest_path=result.evidence_manifest_path,
        truth_manifest_path=result.truth_manifest_path,
        receipt_path=result.receipt_path,
        coverage_path=result.coverage_path,
        raw_root=result.raw_root,
    )


def _qualified_fixture(
    tmp_path: Path,
) -> tuple[AdaptDatasetLock, AdaptIngestionResult, list[EvidenceBundle], list[TruthRecord]]:
    raw_root = tmp_path / "raw"
    lock, receipts = create_adapt_source(raw_root, count=30)
    result = ingest_adapt_dataset(lock, raw_root, tmp_path / "derived", receipts)
    evidence = load_jsonl_models(result.evidence_manifest_path, EvidenceBundle)
    original_truth = load_jsonl_models(result.truth_manifest_path, TruthRecord)
    qualified_truth: list[TruthRecord] = []
    reviewed_at = datetime(2026, 1, 1, tzinfo=UTC)
    for index, (bundle, record) in enumerate(zip(evidence, original_truth, strict=True)):
        hypotheses = (f"{record.incident_id}-hypothesis-a", f"{record.incident_id}-hypothesis-b")
        safe_tests = (f"{record.incident_id}-safe-test",)
        review_artifact = bundle.evidence[0].artifact
        reviews = (
            ReviewAttestation(
                attestation_id=f"{record.incident_id}-cause-review",
                kind=ReviewKind.CAUSE,
                producer_id="fixture-producer",
                reviewer_id="fixture-independent-reviewer",
                subject_ids=record.mechanism_ids,
                method="fixture control review",
                scope="cause control",
                evidence_refs=(review_artifact,),
                reviewed_at=reviewed_at,
            ),
            ReviewAttestation(
                attestation_id=f"{record.incident_id}-ambiguity-review",
                kind=ReviewKind.AMBIGUITY,
                producer_id="fixture-producer",
                reviewer_id="fixture-independent-reviewer",
                subject_ids=hypotheses,
                method="fixture control review",
                scope="ambiguity control",
                evidence_refs=(review_artifact,),
                reviewed_at=reviewed_at,
            ),
            ReviewAttestation(
                attestation_id=f"{record.incident_id}-safe-test-review",
                kind=ReviewKind.SAFE_TEST,
                producer_id="fixture-producer",
                reviewer_id="fixture-independent-reviewer",
                subject_ids=safe_tests,
                method="fixture control review",
                scope="safe-test control",
                evidence_refs=(review_artifact,),
                reviewed_at=reviewed_at,
            ),
        )
        group = index % 3
        qualified_truth.append(
            record.model_copy(
                update={
                    "hardware_family": f"fixture-family-{group}",
                    "hardware_id": f"fixture-hardware-{group}",
                    "fault_family": f"fixture-fault-{group}",
                    "competing_hypothesis_ids": hypotheses,
                    "safe_discriminating_test_ids": safe_tests,
                    "review_attestations": reviews,
                }
            )
        )
    sealed = _seal_fixture(result, evidence, qualified_truth)
    committed_evidence = load_jsonl_models(sealed.evidence_manifest_path, EvidenceBundle)
    return lock, sealed, committed_evidence, qualified_truth


def test_public_fixture_is_validly_ingested_but_scientifically_blocked(tmp_path: Path) -> None:
    lock, result = _ingested(tmp_path)
    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert report.verdict == "BLOCKED_EVIDENCE"
    assert statuses["source-integrity"] == GateStatus.PASS
    assert statuses["parser-integrity"] == GateStatus.PASS
    assert statuses["truth-separation"] == GateStatus.PASS
    assert statuses["minimum-count"] == GateStatus.BLOCKED
    assert statuses["ambiguity"] == GateStatus.BLOCKED
    assert statuses["discriminating-action"] == GateStatus.BLOCKED
    assert "GPU" in report.forbidden_next_actions[0]


def test_scientific_readiness_gates_reject_one_factor_negative_controls(
    tmp_path: Path,
) -> None:
    lock, result, evidence, truth = _qualified_fixture(tmp_path)
    positive = audit_adapt_readiness(lock, result)
    assert positive.verdict == "PASS"
    assert all(gate.status == GateStatus.PASS for gate in positive.gates)

    controls: dict[str, tuple[list[EvidenceBundle], list[TruthRecord]]] = {}
    for gate_id, review_kind in (
        ("minimum-count", ReviewKind.CAUSE),
        ("ambiguity", ReviewKind.AMBIGUITY),
        ("discriminating-action", ReviewKind.SAFE_TEST),
    ):
        weakened = list(truth)
        weakened[0] = weakened[0].model_copy(
            update={
                "review_attestations": tuple(
                    review
                    for review in weakened[0].review_attestations
                    if review.kind != review_kind
                )
            }
        )
        controls[gate_id] = (evidence, weakened)

    collapsed_transfer = [
        record.model_copy(
            update={
                "hardware_family": "one-family",
                "hardware_id": "one-hardware",
                "fault_family": "one-fault",
            }
        )
        for record in truth
    ]
    controls["transfer-support"] = (evidence, collapsed_transfer)

    weakened_evidence = list(evidence)
    first_items = list(weakened_evidence[0].evidence)
    first_items[0] = first_items[0].model_copy(
        update={"artifact": first_items[0].artifact.model_copy(update={"clock_domain": None})}
    )
    weakened_evidence[0] = weakened_evidence[0].model_copy(update={"evidence": tuple(first_items)})
    controls["evidence-usefulness"] = (weakened_evidence, truth)

    for expected_failure, (control_evidence, control_truth) in controls.items():
        controlled_result = _seal_fixture(result, control_evidence, control_truth)
        report = audit_adapt_readiness(lock, controlled_result)
        statuses = {gate.gate_id: gate.status for gate in report.gates}
        assert report.verdict == "BLOCKED_EVIDENCE"
        assert statuses[expected_failure] == GateStatus.BLOCKED
        assert all(
            status == GateStatus.PASS
            for gate_id, status in statuses.items()
            if gate_id != expected_failure
        )


def _with_coverage(
    result: AdaptIngestionResult,
    coverage: AdaptCoverageReport,
) -> AdaptIngestionResult:
    result.coverage_path.write_bytes(canonical_json_pretty(coverage))
    receipt = result.receipt.model_copy(
        update={"coverage_report_sha256": sha256_file(result.coverage_path)}
    )
    result.receipt_path.write_bytes(canonical_json_pretty(receipt))
    return result.__class__(
        receipt=receipt,
        coverage=coverage,
        evidence_manifest_path=result.evidence_manifest_path,
        truth_manifest_path=result.truth_manifest_path,
        receipt_path=result.receipt_path,
        coverage_path=result.coverage_path,
        raw_root=result.raw_root,
    )


def _without_review(truth: list[TruthRecord], kind: ReviewKind) -> list[TruthRecord]:
    weakened = list(truth)
    weakened[0] = weakened[0].model_copy(
        update={
            "review_attestations": tuple(
                review for review in weakened[0].review_attestations if review.kind != kind
            )
        }
    )
    return weakened


def test_source_integrity_positive_control(tmp_path: Path) -> None:
    lock, result = _ingested(tmp_path)
    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["source-integrity"] == GateStatus.PASS


def test_source_integrity_negative_control(tmp_path: Path) -> None:
    lock, result = _ingested(tmp_path)
    forged_resource = result.receipt.resource_receipts[0].model_copy(update={"sha256": HASH_A})
    forged = result.__class__(
        receipt=result.receipt.model_copy(update={"resource_receipts": (forged_resource,)}),
        coverage=result.coverage,
        evidence_manifest_path=result.evidence_manifest_path,
        truth_manifest_path=result.truth_manifest_path,
        receipt_path=result.receipt_path,
        coverage_path=result.coverage_path,
        raw_root=result.raw_root,
    )
    report = audit_adapt_readiness(lock, forged)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["source-integrity"] == GateStatus.INVALID


def test_parser_integrity_positive_control(tmp_path: Path) -> None:
    lock, result = _ingested(tmp_path)
    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["parser-integrity"] == GateStatus.PASS


def test_parser_integrity_negative_control(tmp_path: Path) -> None:
    lock, result = _ingested(tmp_path)
    controlled = _with_coverage(
        result,
        result.coverage.model_copy(update={"exact_file_coverage": False}),
    )
    report = audit_adapt_readiness(lock, controlled)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["parser-integrity"] == GateStatus.INVALID
    assert statuses["truth-separation"] == GateStatus.PASS


def test_truth_separation_positive_control(tmp_path: Path) -> None:
    lock, result = _ingested(tmp_path)
    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["truth-separation"] == GateStatus.PASS


def test_truth_separation_negative_control(tmp_path: Path) -> None:
    lock, result = _ingested(tmp_path)
    controlled = _with_coverage(
        result,
        result.coverage.model_copy(update={"leakage_markers_found": ("FaultInject",)}),
    )
    report = audit_adapt_readiness(lock, controlled)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["truth-separation"] == GateStatus.INVALID
    assert statuses["parser-integrity"] == GateStatus.PASS


def test_minimum_count_positive_control(tmp_path: Path) -> None:
    lock, result, _, _ = _qualified_fixture(tmp_path)
    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["minimum-count"] == GateStatus.PASS


def test_minimum_count_negative_control(tmp_path: Path) -> None:
    lock, result, evidence, truth = _qualified_fixture(tmp_path)
    controlled = _seal_fixture(result, evidence, _without_review(truth, ReviewKind.CAUSE))
    report = audit_adapt_readiness(lock, controlled)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["minimum-count"] == GateStatus.BLOCKED


def test_ambiguity_positive_control(tmp_path: Path) -> None:
    lock, result, _, _ = _qualified_fixture(tmp_path)
    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["ambiguity"] == GateStatus.PASS


def test_ambiguity_negative_control(tmp_path: Path) -> None:
    lock, result, evidence, truth = _qualified_fixture(tmp_path)
    controlled = _seal_fixture(result, evidence, _without_review(truth, ReviewKind.AMBIGUITY))
    report = audit_adapt_readiness(lock, controlled)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["ambiguity"] == GateStatus.BLOCKED


def test_discriminating_action_positive_control(tmp_path: Path) -> None:
    lock, result, _, _ = _qualified_fixture(tmp_path)
    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["discriminating-action"] == GateStatus.PASS


def test_discriminating_action_negative_control(tmp_path: Path) -> None:
    lock, result, evidence, truth = _qualified_fixture(tmp_path)
    controlled = _seal_fixture(result, evidence, _without_review(truth, ReviewKind.SAFE_TEST))
    report = audit_adapt_readiness(lock, controlled)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["discriminating-action"] == GateStatus.BLOCKED


def test_transfer_support_positive_control(tmp_path: Path) -> None:
    lock, result, _, _ = _qualified_fixture(tmp_path)
    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["transfer-support"] == GateStatus.PASS


def test_transfer_support_negative_control(tmp_path: Path) -> None:
    lock, result, evidence, truth = _qualified_fixture(tmp_path)
    one_family = [record.model_copy(update={"hardware_family": "one-family"}) for record in truth]
    controlled = _seal_fixture(result, evidence, one_family)
    report = audit_adapt_readiness(lock, controlled)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["transfer-support"] == GateStatus.BLOCKED
    assert len(statuses) == 8


def test_evidence_usefulness_positive_control(tmp_path: Path) -> None:
    lock, result, _, _ = _qualified_fixture(tmp_path)
    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["evidence-usefulness"] == GateStatus.PASS


def test_evidence_usefulness_negative_control(tmp_path: Path) -> None:
    lock, result, evidence, truth = _qualified_fixture(tmp_path)
    weakened = list(evidence)
    items = list(weakened[0].evidence)
    items[0] = items[0].model_copy(
        update={"artifact": items[0].artifact.model_copy(update={"clock_domain": None})}
    )
    weakened[0] = weakened[0].model_copy(update={"evidence": tuple(items)})
    controlled = _seal_fixture(result, weakened, truth)
    report = audit_adapt_readiness(lock, controlled)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert statuses["evidence-usefulness"] == GateStatus.BLOCKED


def test_readiness_recomputes_manifest_commitments_and_uri_containment(tmp_path: Path) -> None:
    lock, result = _ingested(tmp_path)
    record = json.loads(result.evidence_manifest_path.read_text())
    record["truth_commitment"] = HASH_A
    record["evidence"][0]["artifact"]["uri"] = "truth/truth.jsonl"
    result.evidence_manifest_path.write_bytes(canonical_json(record) + b"\n")

    report = audit_adapt_readiness(lock, result)
    statuses = {gate.gate_id: gate.status for gate in report.gates}
    assert report.verdict == "INVALID"
    assert statuses["parser-integrity"] == GateStatus.INVALID
    assert statuses["truth-separation"] == GateStatus.INVALID


def test_readiness_rejects_fabricated_receipt_and_post_ingestion_raw_change(
    tmp_path: Path,
) -> None:
    lock, result = _ingested(tmp_path)
    forged_resource = result.receipt.resource_receipts[0].model_copy(update={"sha256": HASH_A})
    forged_result = result.__class__(
        receipt=result.receipt.model_copy(update={"resource_receipts": (forged_resource,)}),
        coverage=result.coverage,
        evidence_manifest_path=result.evidence_manifest_path,
        truth_manifest_path=result.truth_manifest_path,
        receipt_path=result.receipt_path,
        coverage_path=result.coverage_path,
        raw_root=result.raw_root,
    )
    forged_report = audit_adapt_readiness(lock, forged_result)
    assert forged_report.gates[0].status == GateStatus.INVALID

    (result.raw_root / "dataset_text.zip").write_bytes(b"changed")
    changed_report = audit_adapt_readiness(lock, result)
    assert changed_report.gates[0].status == GateStatus.INVALID


def test_result_renderer_and_writer_share_one_typed_report(tmp_path: Path) -> None:
    lock, result = _ingested(tmp_path)
    report = audit_adapt_readiness(lock, result)
    rendered = render_readiness_result(report)
    assert "BLOCKED_EVIDENCE" in rendered
    assert "not a diagnosis benchmark" in rendered
    report_path = tmp_path / "proof" / "report.json"
    result_path = tmp_path / "RESULT.md"
    write_readiness_artifacts(report, report_path, result_path)
    assert json.loads(report_path.read_text())["verdict"] == report.verdict
    assert result_path.read_text() == rendered
