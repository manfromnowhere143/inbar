"""Export and verify committed JSON Schema contracts."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from fieldtrue.adapters.adapt import (
    AdaptCoverageReport,
    AdaptDatasetLock,
    AdaptIngestionReceipt,
)
from fieldtrue.approvals import ApprovalReceipt
from fieldtrue.canonical import atomic_write, canonical_json_pretty
from fieldtrue.domain import (
    AssuranceCertificate,
    ClaimRecord,
    DiscriminatingTest,
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
from fieldtrue.receipts import LedgerEvent, LedgerHead, SignerAnchor
from fieldtrue.runtime import RuntimeIdentity
from fieldtrue.splits import SplitLock

_SCHEMAS: dict[str, type[BaseModel]] = {
    "adapt_coverage.schema.json": AdaptCoverageReport,
    "adapt_dataset_lock.schema.json": AdaptDatasetLock,
    "adapt_ingestion_receipt.schema.json": AdaptIngestionReceipt,
    "approval_receipt.schema.json": ApprovalReceipt,
    "assurance_certificate.schema.json": AssuranceCertificate,
    "claim_record.schema.json": ClaimRecord,
    "discriminating_test.schema.json": DiscriminatingTest,
    "evidence_bundle.schema.json": EvidenceBundle,
    "hypothesis_set.schema.json": HypothesisSet,
    "job_spec.schema.json": JobSpec,
    "ledger_event.schema.json": LedgerEvent,
    "ledger_head.schema.json": LedgerHead,
    "monitor_specification.schema.json": MonitorSpecification,
    "readiness_report.schema.json": ReadinessReport,
    "recovery_plan.schema.json": RecoveryPlan,
    "research_memory.schema.json": ResearchMemoryRecord,
    "runtime_identity.schema.json": RuntimeIdentity,
    "safety_envelope.schema.json": SafetyEnvelope,
    "signer_anchor.schema.json": SignerAnchor,
    "split_lock.schema.json": SplitLock,
    "test_observation.schema.json": TestObservation,
    "truth_record.schema.json": TruthRecord,
    "verification_result.schema.json": VerificationResult,
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
