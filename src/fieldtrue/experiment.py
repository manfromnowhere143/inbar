"""Pre-registered experiment runners."""

from __future__ import annotations

import fcntl
import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from fieldtrue.adapters.adapt import (
    fetch_adapt_dataset,
    ingest_adapt_dataset,
    load_adapt_lock,
)
from fieldtrue.canonical import (
    atomic_write,
    canonical_json_pretty,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import Ed25519PublicKey, ReadinessReport
from fieldtrue.readiness import (
    audit_adapt_readiness,
    invalid_readiness_report,
    write_readiness_artifacts,
)
from fieldtrue.receipts import (
    SignedLedger,
    load_or_create_signing_key,
    load_signer_anchor,
    verify_ledger,
)
from fieldtrue.runtime import RuntimeIdentity, collect_runtime_identity
from fieldtrue.verification import (
    ProofBundleVerificationError,
    verify_iter000_proof_bundle,
)


class ExperimentAlreadyExecutedError(RuntimeError):
    pass


class ExperimentPreflightError(RuntimeError):
    pass


class ExperimentFinalizationError(RuntimeError):
    """A terminally sealed run failed independent proof verification."""


@contextmanager
def _exclusive_run_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ExperimentPreflightError("iteration 000 is already running") from error
        yield
    finally:
        os.close(descriptor)


def _protocol_bundle(repo_root: Path) -> dict[str, object]:
    fixed_paths = (
        "PREREGISTRATION.md",
        "claims/registry.jsonl",
        "experiments/iter000_nasa_adapt_corpus_readiness/HYPOTHESIS.md",
        "mission/contract.json",
        "mission/loop.json",
        "mission/name.json",
        "protocol/baselines/v1.json",
        "protocol/datasets/nasa_adapt_v1.json",
        "protocol/trust/iter000_signer_anchor.json",
        "src/fieldtrue/adapters/adapt.py",
        "src/fieldtrue/experiment.py",
        "src/fieldtrue/readiness.py",
        "uv.lock",
    )
    schema_paths = tuple(
        path.relative_to(repo_root).as_posix()
        for path in sorted((repo_root / "protocol" / "schemas").glob("*.json"))
    )
    hashes = {
        relative: sha256_file(repo_root / relative) for relative in (*fixed_paths, *schema_paths)
    }
    return {
        "schema_version": "fieldtrue.protocol-bundle.v1",
        "files": hashes,
        "bundle_sha256": sha256_value(hashes),
    }


def _write_invalidity(
    path: Path,
    *,
    dataset_id: str,
    dataset_lock_hash: str,
    stage: str,
    error: ValueError,
) -> None:
    atomic_write(
        path,
        canonical_json_pretty(
            {
                "schema_version": "fieldtrue.iter000-invalidity.v1",
                "dataset_id": dataset_id,
                "dataset_lock_hash": dataset_lock_hash,
                "stage": stage,
                "verdict": "INVALID",
                "error_type": type(error).__name__,
                "message": str(error)[:500],
            }
        ),
    )


def _iteration_learning(report: ReadinessReport) -> dict[str, object]:
    if report.verdict == "INVALID":
        lessons = [
            "An integrity failure invalidates scientific adjudication rather than weakening it.",
            "No scientific-readiness inference is permitted after an invalidating stop condition.",
            "Invalid results receive the same proof and publication path as other verdicts.",
        ]
    else:
        lessons = [
            "Public data usefulness and scientific sufficiency are separate gates.",
            "Fault-injection metadata must be physically separated from model evidence.",
            "Static fault runs do not supply counterfactual safe-test outcomes.",
        ]
    return {
        "schema_version": "fieldtrue.iteration-learning.v1",
        "iteration_id": "iter000_nasa_adapt_corpus_readiness",
        "verdict": report.verdict,
        "grounded_lessons": lessons,
        "engine_extraction_candidates": [
            "content-addressed source acquisition",
            "typed evidence/truth separation",
            "proof-first result rendering",
        ],
        "engine_construction_authorized": False,
    }


def _finalize_iter000(
    *,
    report: ReadinessReport,
    proof_root: Path,
    dataset_lock_path: Path,
    evidence_artifacts: dict[str, Path],
    ledger: SignedLedger,
    run_id: str,
    runtime: RuntimeIdentity,
    expected_signer_public_key: Ed25519PublicKey,
    signer_anchor_path: Path,
) -> ReadinessReport:
    proof_dataset_lock = proof_root / "dataset_lock.json"
    atomic_write(proof_dataset_lock, dataset_lock_path.read_bytes())
    proof_report = proof_root / "readiness_report.json"
    proof_result = proof_root / "RESULT.md"
    write_readiness_artifacts(report, proof_report, proof_result)

    learning_bytes = canonical_json_pretty(_iteration_learning(report))
    proof_learning = proof_root / "LEARNING.json"
    atomic_write(proof_learning, learning_bytes)
    ledger.append(
        run_id=run_id,
        event_type="readiness-adjudicated",
        payload={
            "verdict": report.verdict,
            "readiness_report_hash": sha256_file(proof_report),
            "result_hash": sha256_file(proof_result),
            "learning_hash": sha256_file(proof_learning),
            "gate_statuses": {gate.gate_id: gate.status.value for gate in report.gates},
        },
        runtime=runtime,
    )

    artifact_paths = {
        "dataset_lock.json": proof_dataset_lock,
        **evidence_artifacts,
        "readiness_report.json": proof_report,
        "RESULT.md": proof_result,
        "LEARNING.json": proof_learning,
    }
    artifact_hashes = {name: sha256_file(path) for name, path in sorted(artifact_paths.items())}
    artifact_bundle_body: dict[str, object] = {
        "schema_version": "fieldtrue.artifact-bundle.v1",
        "run_id": run_id,
        "artifacts": artifact_hashes,
    }
    artifact_bundle = {
        **artifact_bundle_body,
        "bundle_sha256": sha256_value(artifact_bundle_body),
    }
    artifact_bundle_path = proof_root / "artifact_bundle.json"
    atomic_write(artifact_bundle_path, canonical_json_pretty(artifact_bundle))

    ledger_checkpoint = verify_ledger(
        proof_root / "execution_ledger.jsonl",
        proof_root / "execution_ledger.head.json",
        expected_signer_public_key=expected_signer_public_key,
    )
    manifest_body = {
        "schema_version": "fieldtrue.run-manifest.v1",
        "run_id": run_id,
        "runtime": runtime,
        "artifacts": {
            **artifact_hashes,
            "artifact_bundle.json": sha256_file(artifact_bundle_path),
        },
        "ledger_checkpoint": ledger_checkpoint,
        "verdict": report.verdict,
    }
    manifest = {
        **manifest_body,
        "manifest_content_hash": sha256_value(manifest_body),
    }
    manifest_path = proof_root / "run_manifest.json"
    atomic_write(manifest_path, canonical_json_pretty(manifest))
    ledger.append(
        run_id=run_id,
        event_type="run-completed",
        payload={
            "verdict": report.verdict,
            "authorized_next_action": report.authorized_next_action,
            "gpu_hours": 0,
            "cloud_jobs": 0,
            "paid_calls": 0,
            "artifact_bundle_hash": sha256_file(artifact_bundle_path),
            "run_manifest_hash": sha256_file(manifest_path),
        },
        runtime=runtime,
    )
    try:
        verification = verify_iter000_proof_bundle(
            proof_root,
            signer_anchor_path=signer_anchor_path,
        )
    except ProofBundleVerificationError as error:
        raise ExperimentFinalizationError(
            "sealed iter000 proof bundle failed independent verification"
        ) from error
    if verification.verdict != report.verdict:
        raise ExperimentFinalizationError(
            "sealed iter000 proof verdict differs from the producer verdict"
        )
    return report


def run_iter000(repo_root: Path, *, command: tuple[str, ...]) -> ReadinessReport:
    with _exclusive_run_lock(repo_root / ".local" / "locks" / "iter000.lock"):
        return _run_iter000_locked(repo_root, command=command)


def _run_iter000_locked(repo_root: Path, *, command: tuple[str, ...]) -> ReadinessReport:
    from fieldtrue.mission import validate_mission

    experiment_root = repo_root / "experiments" / "iter000_nasa_adapt_corpus_readiness"
    proof_root = experiment_root / "proof"
    if (proof_root / "RESULT.md").exists() or (proof_root / "execution_ledger.jsonl").exists():
        raise ExperimentAlreadyExecutedError(
            "iteration 000 already has execution evidence; amendment required for another run"
        )
    mission_validation = validate_mission(repo_root)
    if not mission_validation.passed:
        failures = [check.check_id for check in mission_validation.checks if not check.passed]
        raise ExperimentPreflightError(f"mission preflight failed: {', '.join(failures)}")
    runtime = collect_runtime_identity(repo_root, command=command, require_clean=True)
    run_id = f"iter000-{runtime.git_commit[:12]}"
    key = load_or_create_signing_key(repo_root / ".local" / "keys" / "iter000.ed25519")
    anchor = load_signer_anchor(repo_root / "protocol" / "trust" / "iter000_signer_anchor.json")
    signer_anchor_path = repo_root / "protocol" / "trust" / "iter000_signer_anchor.json"
    if key.verify_key.encode().hex() != anchor.signer_public_key:
        raise ExperimentPreflightError("local execution key does not match the pinned signer")
    ledger = SignedLedger(
        proof_root / "execution_ledger.jsonl",
        proof_root / "execution_ledger.head.json",
        key,
    )
    ledger.append(
        run_id=run_id,
        event_type="run-started",
        payload={
            "hypothesis": "experiments/iter000_nasa_adapt_corpus_readiness/HYPOTHESIS.md",
            "protocol_bundle": _protocol_bundle(repo_root),
            "gpu_authorized": False,
            "cloud_authorized": False,
            "live_action_authorized": False,
        },
        runtime=runtime,
    )
    try:
        lock_path = repo_root / "protocol" / "datasets" / "nasa_adapt_v1.json"
        lock = load_adapt_lock(lock_path)
        raw_root = repo_root / "data" / "raw" / lock.dataset_id
        derived_root = repo_root / "data" / "derived" / lock.dataset_id
        try:
            resource_receipts = fetch_adapt_dataset(lock, raw_root)
        except ValueError as error:
            proof_root.mkdir(parents=True, exist_ok=True)
            invalidity_path = proof_root / "invalidity.json"
            _write_invalidity(
                invalidity_path,
                dataset_id=lock.dataset_id,
                dataset_lock_hash=sha256_file(lock_path),
                stage="source-integrity",
                error=error,
            )
            ledger.append(
                run_id=run_id,
                event_type="source-invalid",
                payload={
                    "invalidity_hash": sha256_file(invalidity_path),
                    "error_type": type(error).__name__,
                },
                runtime=runtime,
            )
            report = invalid_readiness_report(
                dataset_id=lock.dataset_id,
                failed_gate_id="source-integrity",
                error_type=type(error).__name__,
                error_message=str(error)[:500],
            )
            return _finalize_iter000(
                report=report,
                proof_root=proof_root,
                dataset_lock_path=lock_path,
                evidence_artifacts={"invalidity.json": invalidity_path},
                ledger=ledger,
                run_id=run_id,
                runtime=runtime,
                expected_signer_public_key=anchor.signer_public_key,
                signer_anchor_path=signer_anchor_path,
            )
        ledger.append(
            run_id=run_id,
            event_type="sources-verified",
            payload={
                "dataset_id": lock.dataset_id,
                "dataset_lock_hash": sha256_file(lock_path),
                "resources": [receipt.model_dump(mode="json") for receipt in resource_receipts],
                "network_source_only": True,
                "cost_usd": "0",
            },
            runtime=runtime,
        )
        try:
            ingestion = ingest_adapt_dataset(lock, raw_root, derived_root, resource_receipts)
        except ValueError as error:
            proof_root.mkdir(parents=True, exist_ok=True)
            invalidity_path = proof_root / "invalidity.json"
            _write_invalidity(
                invalidity_path,
                dataset_id=lock.dataset_id,
                dataset_lock_hash=sha256_file(lock_path),
                stage="parser-integrity",
                error=error,
            )
            ledger.append(
                run_id=run_id,
                event_type="ingestion-invalid",
                payload={
                    "invalidity_hash": sha256_file(invalidity_path),
                    "error_type": type(error).__name__,
                },
                runtime=runtime,
            )
            report = invalid_readiness_report(
                dataset_id=lock.dataset_id,
                failed_gate_id="parser-integrity",
                error_type=type(error).__name__,
                error_message=str(error)[:500],
                passed_gate_ids=("source-integrity",),
            )
            return _finalize_iter000(
                report=report,
                proof_root=proof_root,
                dataset_lock_path=lock_path,
                evidence_artifacts={"invalidity.json": invalidity_path},
                ledger=ledger,
                run_id=run_id,
                runtime=runtime,
                expected_signer_public_key=anchor.signer_public_key,
                signer_anchor_path=signer_anchor_path,
            )
        proof_root.mkdir(parents=True, exist_ok=True)
        atomic_write(proof_root / "ingestion_receipt.json", ingestion.receipt_path.read_bytes())
        atomic_write(proof_root / "coverage.json", ingestion.coverage_path.read_bytes())
        atomic_write(
            proof_root / "model_evidence_manifest.jsonl",
            ingestion.evidence_manifest_path.read_bytes(),
        )
        atomic_write(
            proof_root / "truth_manifest.jsonl",
            ingestion.truth_manifest_path.read_bytes(),
            mode=0o600,
        )
        ledger.append(
            run_id=run_id,
            event_type="dataset-ingested",
            payload={
                "ingestion_receipt_hash": sha256_file(proof_root / "ingestion_receipt.json"),
                "coverage_hash": sha256_file(proof_root / "coverage.json"),
                "model_evidence_manifest_hash": sha256_file(
                    proof_root / "model_evidence_manifest.jsonl"
                ),
                "evidence_manifest_hash": ingestion.receipt.evidence_manifest_sha256,
                "truth_manifest_hash": ingestion.receipt.truth_manifest_sha256,
                "truth_separation_passed": ingestion.receipt.truth_separation_passed,
            },
            runtime=runtime,
        )
        report = audit_adapt_readiness(lock, ingestion)
        return _finalize_iter000(
            report=report,
            proof_root=proof_root,
            dataset_lock_path=lock_path,
            evidence_artifacts={
                "coverage.json": proof_root / "coverage.json",
                "ingestion_receipt.json": proof_root / "ingestion_receipt.json",
                "model_evidence_manifest.jsonl": (proof_root / "model_evidence_manifest.jsonl"),
                "truth_manifest.jsonl": proof_root / "truth_manifest.jsonl",
            },
            ledger=ledger,
            run_id=run_id,
            runtime=runtime,
            expected_signer_public_key=anchor.signer_public_key,
            signer_anchor_path=signer_anchor_path,
        )
    except ExperimentFinalizationError:
        raise
    except Exception as error:
        ledger.append(
            run_id=run_id,
            event_type="run-failed",
            payload={"error_type": type(error).__name__, "message": str(error)[:500]},
            runtime=runtime,
        )
        raise
