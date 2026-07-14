from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from fieldtrue.adapters.adapt import (
    AdaptCoverageReport,
    AdaptDatasetLock,
    AdaptIngestionReceipt,
    ingest_adapt_dataset,
)
from fieldtrue.canonical import canonical_json, canonical_json_pretty, sha256_file
from fieldtrue.domain import EvidenceBundle, GateStatus, TruthRecord
from fieldtrue.readiness import audit_adapt_proof_readiness
from tests.helpers import HASH_A, create_adapt_source


@dataclass
class _Material:
    lock: AdaptDatasetLock
    receipt: AdaptIngestionReceipt
    coverage: AdaptCoverageReport
    coverage_path: Path
    evidence_path: Path
    truth_path: Path


def _material(root: Path) -> _Material:
    raw = root / "raw"
    lock, receipts = create_adapt_source(raw)
    result = ingest_adapt_dataset(lock, raw, root / "derived", receipts)
    return _Material(
        lock=lock,
        receipt=result.receipt,
        coverage=result.coverage,
        coverage_path=result.coverage_path,
        evidence_path=result.evidence_manifest_path,
        truth_path=result.truth_manifest_path,
    )


def _write_models(path: Path, records: list[EvidenceBundle] | list[TruthRecord]) -> None:
    path.write_bytes(b"".join(canonical_json(record) + b"\n" for record in records))


def _gate_status(material: _Material, gate_id: str) -> GateStatus:
    report = audit_adapt_proof_readiness(
        material.lock,
        material.receipt,
        material.coverage,
        material.coverage_path,
        material.evidence_path,
        material.truth_path,
    )
    return next(gate.status for gate in report.gates if gate.gate_id == gate_id)


@pytest.mark.parametrize(
    "case",
    [
        "lock-content",
        "dataset-id",
        "resource-missing",
        "resource-mismatch",
    ],
)
def test_proof_source_controls_fail_closed(tmp_path: Path, case: str) -> None:
    material = _material(tmp_path)
    if case == "lock-content":
        material.receipt = material.receipt.model_copy(
            update={"dataset_lock_content_sha256": HASH_A}
        )
    elif case == "dataset-id":
        material.receipt = material.receipt.model_copy(update={"dataset_id": "other-dataset"})
    elif case == "resource-missing":
        material.receipt = material.receipt.model_copy(update={"resource_receipts": ()})
    else:
        resource = material.receipt.resource_receipts[0].model_copy(update={"verified": False})
        material.receipt = material.receipt.model_copy(update={"resource_receipts": (resource,)})

    assert _gate_status(material, "source-integrity") == GateStatus.INVALID


@pytest.mark.parametrize(
    "case",
    [
        "evidence-encoding",
        "truth-encoding",
        "coverage-encoding",
        "coverage-exactness",
        "coverage-duplicates",
        "coverage-join",
        "receipt-counts",
        "duplicate-evidence",
        "duplicate-truth",
        "truth-commitment",
        "artifact-contract",
        "derived-artifact-set",
        "truth-marker",
    ],
)
def test_proof_parser_controls_fail_closed(tmp_path: Path, case: str) -> None:
    material = _material(tmp_path)
    if case == "evidence-encoding":
        material.evidence_path.write_bytes(material.evidence_path.read_bytes().rstrip() + b" \n")
    elif case == "truth-encoding":
        material.truth_path.write_bytes(material.truth_path.read_bytes().rstrip() + b" \n")
    elif case == "coverage-encoding":
        material.coverage_path.write_bytes(material.coverage_path.read_bytes().rstrip() + b" \n")
    elif case == "coverage-exactness":
        material.coverage = material.coverage.model_copy(
            update={
                "expected_files": 0,
                "discovered_files": 0,
                "parsed_files": 0,
                "exact_file_coverage": False,
                "files": (),
            }
        )
        material.coverage_path.write_bytes(canonical_json_pretty(material.coverage))
    elif case == "coverage-duplicates":
        first = material.coverage.files[0]
        material.coverage = material.coverage.model_copy(update={"files": (first, first)})
        material.coverage_path.write_bytes(canonical_json_pretty(material.coverage))
    elif case == "coverage-join":
        changed = material.coverage.files[0].model_copy(update={"experiment_id": "other-incident"})
        material.coverage = material.coverage.model_copy(update={"files": (changed,)})
        material.coverage_path.write_bytes(canonical_json_pretty(material.coverage))
    elif case == "receipt-counts":
        material.receipt = material.receipt.model_copy(
            update={"experiment_count": 2, "evidence_bundle_count": 2, "truth_record_count": 2}
        )
    elif case == "duplicate-evidence":
        evidence = [
            EvidenceBundle.model_validate_json(material.evidence_path.read_text(encoding="utf-8"))
        ]
        _write_models(material.evidence_path, [evidence[0], evidence[0]])
    elif case == "duplicate-truth":
        truth = [TruthRecord.model_validate_json(material.truth_path.read_text(encoding="utf-8"))]
        _write_models(material.truth_path, [truth[0], truth[0]])
    elif case == "truth-commitment":
        evidence = EvidenceBundle.model_validate_json(
            material.evidence_path.read_text(encoding="utf-8")
        ).model_copy(update={"truth_commitment": HASH_A})
        _write_models(material.evidence_path, [evidence])
    elif case == "artifact-contract":
        evidence = EvidenceBundle.model_validate_json(
            material.evidence_path.read_text(encoding="utf-8")
        )
        first, second = evidence.evidence
        first = first.model_copy(
            update={
                "artifact": first.artifact.model_copy(
                    update={"uri": "../truth.jsonl", "lineage_sha256": ()}
                )
            }
        )
        second = second.model_copy(
            update={
                "artifact": second.artifact.model_copy(
                    update={
                        "artifact_id": first.artifact.artifact_id,
                        "uri": first.artifact.uri,
                    }
                )
            }
        )
        evidence = evidence.model_copy(
            update={"context": {"hidden": True}, "evidence": (first, second)}
        )
        _write_models(material.evidence_path, [evidence])
    elif case == "derived-artifact-set":
        material.receipt = material.receipt.model_copy(update={"derived_artifact_hashes": ()})
    else:
        evidence = EvidenceBundle.model_validate_json(
            material.evidence_path.read_text(encoding="utf-8")
        )
        first, *remaining = evidence.evidence
        first = first.model_copy(update={"description": "FaultInject control marker"})
        evidence = evidence.model_copy(update={"evidence": (first, *remaining)})
        _write_models(material.evidence_path, [evidence])

    assert _gate_status(material, "parser-integrity") == GateStatus.INVALID


@pytest.mark.parametrize("case", ["receipt", "coverage"])
def test_proof_truth_separation_controls_fail_closed(tmp_path: Path, case: str) -> None:
    material = _material(tmp_path)
    if case == "receipt":
        material.receipt = material.receipt.model_copy(update={"truth_separation_passed": False})
    else:
        material.coverage = material.coverage.model_copy(
            update={"leakage_markers_found": ("FaultInject",)}
        )
        material.coverage_path.write_bytes(canonical_json_pretty(material.coverage))
        material.receipt = material.receipt.model_copy(
            update={"coverage_report_sha256": sha256_file(material.coverage_path)}
        )

    assert _gate_status(material, "truth-separation") == GateStatus.INVALID
