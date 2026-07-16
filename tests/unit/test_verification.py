from __future__ import annotations

import json
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any, Literal

import pytest
from nacl.signing import SigningKey

import fieldtrue.verification as verification_module
from fieldtrue.adapters.adapt import ingest_adapt_dataset
from fieldtrue.canonical import (
    canonical_json,
    canonical_json_pretty,
    sha256_bytes,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import GateResult, GateStatus, ReadinessReport
from fieldtrue.readiness import (
    audit_adapt_readiness,
    invalid_readiness_report,
    render_readiness_result,
)
from fieldtrue.receipts import SignedLedger, load_signer_anchor, verify_ledger, write_signer_anchor
from fieldtrue.verification import (
    ProofBundleVerificationError,
    render_iter000_result_from_proof,
    verify_iter000_proof_bundle,
)
from tests.helpers import create_adapt_source, legacy_runtime_identity, runtime_identity

_ITERATION_ID = "iter000_nasa_adapt_corpus_readiness"
_GATE_IDS = (
    "source-integrity",
    "parser-integrity",
    "truth-separation",
    "minimum-count",
    "ambiguity",
    "discriminating-action",
    "transfer-support",
    "evidence-usefulness",
)
FixtureFlow = Literal["normal", "source-invalid", "ingestion-invalid"]


def _normal_report(*, passed: bool = False) -> ReadinessReport:
    gates = tuple(
        GateResult(
            gate_id=gate_id,
            status=(GateStatus.PASS if passed or gate_id in _GATE_IDS[:3] else GateStatus.BLOCKED),
            observed=1,
            requirement=f"Frozen requirement for {gate_id}.",
            detail="Fixture readiness gate.",
        )
        for gate_id in _GATE_IDS
    )
    return ReadinessReport(
        dataset_id="adapt-fixture",
        gates=gates,
        verdict="PASS" if passed else "BLOCKED_EVIDENCE",
        authorized_next_action=(
            "Execute deterministic baselines." if passed else "Collect evidence."
        ),
        forbidden_next_actions=("GPU or learned-model training",),
    )


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_pretty(value))


def _iteration_learning(report: ReadinessReport) -> dict[str, object]:
    return {
        "schema_version": "fieldtrue.iteration-learning.v1",
        "iteration_id": _ITERATION_ID,
        "verdict": report.verdict,
        "grounded_lessons": ["Evidence sufficiency is independently gated."],
        "engine_extraction_candidates": ["proof-first result rendering"],
        "engine_construction_authorized": False,
    }


def _fixture_bundle(
    tmp_path: Path,
    *,
    flow: FixtureFlow = "normal",
    corrupt_bundle_self_hash: bool = False,
    protocol_overrides: dict[str, object] | None = None,
    source_overrides: dict[str, object] | None = None,
    receipt_overrides: dict[str, object] | None = None,
    ingested_overrides: dict[str, object] | None = None,
    result_override: str | None = None,
    learning_overrides: dict[str, object] | None = None,
    adjudicated_overrides: dict[str, object] | None = None,
    bundle_overrides: dict[str, object] | None = None,
    bundled_artifact_overrides: dict[str, object] | None = None,
    manifest_overrides: dict[str, object] | None = None,
    terminal_overrides: dict[str, object] | None = None,
    report_override: ReadinessReport | None = None,
    noncanonical_dataset_lock: bool = False,
) -> tuple[Path, Path, SigningKey]:
    experiment = tmp_path / "experiments" / _ITERATION_ID
    proof = experiment / "proof"
    proof.mkdir(parents=True)
    key = SigningKey.generate()
    anchor_path = tmp_path / "protocol" / "trust" / "iter000_signer_anchor.json"
    write_signer_anchor(
        anchor_path,
        key,
        anchor_id="iter000-execution-ledger",
        ledger_scope=_ITERATION_ID,
    )
    repository = Path(__file__).resolve().parents[2]
    (proof / "AMENDMENT_001.md").write_bytes(
        (repository / "experiments" / _ITERATION_ID / "AMENDMENT_001.md").read_bytes()
    )
    (proof / "amendment_001.json").write_bytes(
        (repository / "protocol" / "amendments" / "iter000_001.json").read_bytes()
    )
    raw_root = tmp_path / "source"
    lock, resource_receipts = create_adapt_source(raw_root)
    dataset_lock_data = canonical_json_pretty(lock)
    if noncanonical_dataset_lock:
        dataset_lock_data += b"\n"
    (proof / "dataset_lock.json").write_bytes(dataset_lock_data)
    dataset_lock_hash = sha256_file(proof / "dataset_lock.json")

    runtime = runtime_identity()
    run_id = "iter000-fixture"
    ledger = SignedLedger(
        proof / "execution_ledger.jsonl",
        proof / "execution_ledger.head.json",
        key,
    )
    protocol_files = {
        f"experiments/{_ITERATION_ID}/HYPOTHESIS.md": "c" * 64,
        f"experiments/{_ITERATION_ID}/AMENDMENT_001.md": sha256_file(proof / "AMENDMENT_001.md"),
        "protocol/trust/iter000_signer_anchor.json": sha256_file(anchor_path),
        "protocol/datasets/nasa_adapt_v1.json": dataset_lock_hash,
    }
    amendment = json.loads((proof / "amendment_001.json").read_text())
    amendment["amendment_document"]["sha256"] = protocol_files[
        f"experiments/{_ITERATION_ID}/AMENDMENT_001.md"
    ]
    amendment["frozen_inputs"]["hypothesis"]["sha256"] = protocol_files[
        f"experiments/{_ITERATION_ID}/HYPOTHESIS.md"
    ]
    amendment["frozen_inputs"]["dataset_lock"]["sha256"] = dataset_lock_hash
    amendment["trigger_attempt"]["artifacts"]["signer_anchor"]["sha256"] = sha256_file(anchor_path)
    _write_json(proof / "amendment_001.json", amendment)
    protocol_files["protocol/amendments/iter000_001.json"] = sha256_file(
        proof / "amendment_001.json"
    )
    if protocol_overrides:
        protocol_files.update(protocol_overrides)
    ledger.append(
        run_id=run_id,
        event_type="run-started",
        payload={
            "hypothesis": f"experiments/{_ITERATION_ID}/HYPOTHESIS.md",
            "protocol_bundle": {
                "schema_version": "fieldtrue.protocol-bundle.v1",
                "files": protocol_files,
                "bundle_sha256": sha256_value(protocol_files),
            },
            "gpu_authorized": False,
            "cloud_authorized": False,
            "live_action_authorized": False,
        },
        runtime=runtime,
    )

    sources_payload = {
        "dataset_id": "adapt-fixture",
        "dataset_lock_hash": dataset_lock_hash,
        "resources": [item.model_dump(mode="json") for item in resource_receipts],
        "network_source_only": True,
        "cost_usd": "0",
    }
    if source_overrides:
        sources_payload.update(source_overrides)
    evidence_paths: dict[str, Path]
    if flow == "source-invalid":
        invalidity = {
            "schema_version": "fieldtrue.iter000-invalidity.v1",
            "dataset_id": "adapt-fixture",
            "dataset_lock_hash": dataset_lock_hash,
            "stage": "source-integrity",
            "verdict": "INVALID",
            "error_type": "ValueError",
            "message": "integrity mismatch",
        }
        _write_json(proof / "invalidity.json", invalidity)
        ledger.append(
            run_id=run_id,
            event_type="source-invalid",
            payload={
                "invalidity_hash": sha256_file(proof / "invalidity.json"),
                "error_type": "ValueError",
            },
            runtime=runtime,
        )
        report = invalid_readiness_report(
            dataset_id="adapt-fixture",
            failed_gate_id="source-integrity",
            error_type="ValueError",
            error_message="integrity mismatch",
        )
        evidence_paths = {"invalidity.json": proof / "invalidity.json"}
    elif flow == "ingestion-invalid":
        ledger.append(
            run_id=run_id,
            event_type="sources-verified",
            payload=sources_payload,
            runtime=runtime,
        )
        invalidity = {
            "schema_version": "fieldtrue.iter000-invalidity.v1",
            "dataset_id": "adapt-fixture",
            "dataset_lock_hash": dataset_lock_hash,
            "stage": "parser-integrity",
            "verdict": "INVALID",
            "error_type": "ValueError",
            "message": "unknown row types",
        }
        _write_json(proof / "invalidity.json", invalidity)
        ledger.append(
            run_id=run_id,
            event_type="ingestion-invalid",
            payload={
                "invalidity_hash": sha256_file(proof / "invalidity.json"),
                "error_type": "ValueError",
            },
            runtime=runtime,
        )
        report = invalid_readiness_report(
            dataset_id="adapt-fixture",
            failed_gate_id="parser-integrity",
            error_type="ValueError",
            error_message="unknown row types",
            passed_gate_ids=("source-integrity",),
        )
        evidence_paths = {"invalidity.json": proof / "invalidity.json"}
    else:
        ledger.append(
            run_id=run_id,
            event_type="sources-verified",
            payload=sources_payload,
            runtime=runtime,
        )
        ingestion = ingest_adapt_dataset(
            lock,
            raw_root,
            tmp_path / "derived",
            resource_receipts,
        )
        receipt = ingestion.receipt.model_copy(update=receipt_overrides or {})
        (proof / "model_evidence_manifest.jsonl").write_bytes(
            ingestion.evidence_manifest_path.read_bytes()
        )
        (proof / "truth_manifest.jsonl").write_bytes(ingestion.truth_manifest_path.read_bytes())
        (proof / "coverage.json").write_bytes(ingestion.coverage_path.read_bytes())
        _write_json(proof / "ingestion_receipt.json", receipt)
        ingested_payload = {
            "ingestion_receipt_hash": sha256_file(proof / "ingestion_receipt.json"),
            "coverage_hash": sha256_file(proof / "coverage.json"),
            "model_evidence_manifest_hash": sha256_file(proof / "model_evidence_manifest.jsonl"),
            "evidence_manifest_hash": receipt.evidence_manifest_sha256,
            "truth_manifest_hash": receipt.truth_manifest_sha256,
            "truth_separation_passed": receipt.truth_separation_passed,
        }
        if ingested_overrides:
            ingested_payload.update(ingested_overrides)
        ledger.append(
            run_id=run_id,
            event_type="dataset-ingested",
            payload=ingested_payload,
            runtime=runtime,
        )
        report = report_override or audit_adapt_readiness(lock, ingestion)
        evidence_paths = {
            "coverage.json": proof / "coverage.json",
            "ingestion_receipt.json": proof / "ingestion_receipt.json",
            "model_evidence_manifest.jsonl": proof / "model_evidence_manifest.jsonl",
            "truth_manifest.jsonl": proof / "truth_manifest.jsonl",
        }

    _write_json(proof / "readiness_report.json", report)
    (proof / "RESULT.md").write_text(result_override or render_readiness_result(report))
    learning = _iteration_learning(report)
    if learning_overrides:
        learning.update(learning_overrides)
    _write_json(proof / "LEARNING.json", learning)
    adjudicated_payload = {
        "verdict": report.verdict,
        "readiness_report_hash": sha256_file(proof / "readiness_report.json"),
        "result_hash": sha256_file(proof / "RESULT.md"),
        "learning_hash": sha256_file(proof / "LEARNING.json"),
        "gate_statuses": {gate.gate_id: gate.status.value for gate in report.gates},
    }
    if adjudicated_overrides:
        adjudicated_payload.update(adjudicated_overrides)
    ledger.append(
        run_id=run_id,
        event_type="readiness-adjudicated",
        payload=adjudicated_payload,
        runtime=runtime,
    )

    artifact_paths = {
        "AMENDMENT_001.md": proof / "AMENDMENT_001.md",
        "amendment_001.json": proof / "amendment_001.json",
        "dataset_lock.json": proof / "dataset_lock.json",
        **evidence_paths,
        "readiness_report.json": proof / "readiness_report.json",
        "RESULT.md": proof / "RESULT.md",
        "LEARNING.json": proof / "LEARNING.json",
    }
    artifact_hashes = {name: sha256_file(path) for name, path in sorted(artifact_paths.items())}
    bundled_artifacts: dict[str, object] = dict(artifact_hashes)
    if bundled_artifact_overrides:
        bundled_artifacts.update(bundled_artifact_overrides)
    artifact_bundle_body: dict[str, object] = {
        "schema_version": "fieldtrue.artifact-bundle.v1",
        "run_id": run_id,
        "artifacts": bundled_artifacts,
    }
    if bundle_overrides:
        artifact_bundle_body.update(bundle_overrides)
    artifact_bundle = {
        **artifact_bundle_body,
        "bundle_sha256": (
            "0" * 64 if corrupt_bundle_self_hash else sha256_value(artifact_bundle_body)
        ),
    }
    _write_json(proof / "artifact_bundle.json", artifact_bundle)

    checkpoint = verify_ledger(
        proof / "execution_ledger.jsonl",
        proof / "execution_ledger.head.json",
        expected_signer_public_key=key.verify_key.encode().hex(),
    )
    manifest_body = {
        "schema_version": "fieldtrue.run-manifest.v1",
        "run_id": run_id,
        "runtime": runtime,
        "artifacts": {
            **artifact_hashes,
            "artifact_bundle.json": sha256_file(proof / "artifact_bundle.json"),
        },
        "ledger_checkpoint": checkpoint,
        "verdict": report.verdict,
    }
    if manifest_overrides:
        manifest_body.update(manifest_overrides)
    _write_json(
        proof / "run_manifest.json",
        {**manifest_body, "manifest_content_hash": sha256_value(manifest_body)},
    )
    terminal_payload = {
        "verdict": report.verdict,
        "authorized_next_action": report.authorized_next_action,
        "gpu_hours": 0,
        "cloud_jobs": 0,
        "paid_calls": 0,
        "artifact_bundle_hash": sha256_file(proof / "artifact_bundle.json"),
        "run_manifest_hash": sha256_file(proof / "run_manifest.json"),
    }
    if terminal_overrides:
        terminal_payload.update(terminal_overrides)
    ledger.append(
        run_id=run_id,
        event_type="run-completed",
        payload=terminal_payload,
        runtime=runtime,
    )
    return proof, anchor_path, key


def test_normal_bundle_verifies_from_proof_only(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path)
    assert not (proof.parent / "RESULT.md").exists()
    assert not (proof.parent / "LEARNING.json").exists()
    shutil.rmtree(tmp_path / "derived")
    shutil.rmtree(tmp_path / "source")

    verification = verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)
    assert verification.run_id == "iter000-fixture"
    assert verification.flow == "normal"
    assert verification.verdict == "BLOCKED_EVIDENCE"
    assert verification.ledger_checkpoint.event_count == 4
    assert verification.ledger_verification.event_count == 5
    assert render_iter000_result_from_proof(proof) == (proof / "RESULT.md").read_text()
    assert (proof / "truth_manifest.jsonl").is_file()


def test_dataset_lock_correction_is_exact_and_strict_verifier_stays_strict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path, noncanonical_dataset_lock=True)
    raw_data = (proof / "dataset_lock.json").read_bytes()
    value = json.loads(raw_data)
    correction = {
        "canonical_pretty_sha256": sha256_bytes(canonical_json_pretty(value)),
        "path": "dataset_lock.json",
        "protocol_path": "protocol/datasets/nasa_adapt_v1.json",
        "raw_sha256": sha256_bytes(raw_data),
        "semantic_canonical_sha256": sha256_bytes(canonical_json(value)),
    }

    with pytest.raises(ProofBundleVerificationError, match="canonical pretty JSON"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)

    monkeypatch.setattr(verification_module, "_DATASET_LOCK_CORRECTION", correction)
    verification = verification_module._verify_iter000_proof_bundle(
        proof,
        signer_anchor_path=anchor,
        dataset_lock_correction=correction,
    )
    assert verification.verdict == "BLOCKED_EVIDENCE"

    (proof / "dataset_lock.json").write_bytes(raw_data + b"\n")
    with pytest.raises(ProofBundleVerificationError, match="artifact hash mismatch"):
        verification_module._verify_iter000_proof_bundle(
            proof,
            signer_anchor_path=anchor,
            dataset_lock_correction=correction,
        )


def test_frozen_dataset_lock_exercises_the_authorized_serialization_defect() -> None:
    repository = Path(__file__).resolve().parents[2]
    data = (repository / "protocol" / "datasets" / "nasa_adapt_v1.json").read_bytes()
    value = verification_module._json_object(data, "frozen dataset lock")
    verification_module._model(
        verification_module.AdaptDatasetLock,
        value,
        "frozen dataset lock",
    )

    assert sha256_bytes(data) == verification_module._DATASET_LOCK_CORRECTION["raw_sha256"]
    assert data != canonical_json_pretty(value)
    assert (
        sha256_bytes(canonical_json_pretty(value))
        == verification_module._DATASET_LOCK_CORRECTION["canonical_pretty_sha256"]
    )
    assert (
        sha256_bytes(canonical_json(value))
        == verification_module._DATASET_LOCK_CORRECTION["semantic_canonical_sha256"]
    )


def test_verification_amendments_bind_the_original_verifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    amendment, _, _ = verification_module._load_verification_amendments(repository)

    assert (
        amendment["trigger"]["execution_commit"]["git_commit"]
        == verification_module._ATTEMPT_001_EXECUTION_COMMIT
    )
    assert amendment["trigger"]["original_verifier"] == {
        "path": "src/fieldtrue/verification.py",
        "sha256": verification_module._ORIGINAL_VERIFIER_SHA256,
    }

    monkeypatch.setattr(verification_module, "_ORIGINAL_VERIFIER_SHA256", "0" * 64)
    with pytest.raises(ProofBundleVerificationError, match="original verifier binding"):
        verification_module._load_verification_amendments(repository)


def test_verification_surface_ignores_inherited_git_redirection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = Path(__file__).resolve().parents[2]
    fake_git = tmp_path / "git"
    fake_git.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.setenv("GIT_DIR", "/does/not/exist")
    monkeypatch.setenv("GIT_WORK_TREE", "/does/not/exist")
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", "/does/not/exist")
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", "/does/not/exist")

    valid, detail = verification_module.validate_iter000_verification_correction_surface(repository)

    assert valid
    assert "proof-bound" in detail


def test_verification_signer_must_differ_from_execution_signer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = SigningKey.generate()
    execution_anchor_path = tmp_path / verification_module._ANCHOR_PROTOCOL_PATH
    write_signer_anchor(
        execution_anchor_path,
        key,
        anchor_id="iter000-execution-ledger",
        ledger_scope=_ITERATION_ID,
    )
    monkeypatch.setattr(
        verification_module,
        "load_or_create_signing_key",
        lambda _path: key,
    )

    with pytest.raises(ProofBundleVerificationError, match="must differ"):
        verification_module.initialize_iter000_verification_signer(tmp_path)
    assert not (tmp_path / verification_module._VERIFICATION_SIGNER_ANCHOR_PATH).exists()


def test_verification_authority_binds_external_signer_code_tests_and_protocol(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commit = "d" * 40
    tree = "e" * 40
    head = "f" * 40
    source_path = "src/fieldtrue/sample.py"
    test_path = "tests/test_sample.py"
    protocol_paths = {
        verification_module._VERIFICATION_AMENDMENT_DOCUMENT_PATH,
        verification_module._VERIFICATION_AMENDMENT_PATH,
        verification_module._VERIFICATION_AMENDMENT_CORRECTION_DOCUMENT_PATH,
        verification_module._VERIFICATION_AMENDMENT_CORRECTION_PATH,
        verification_module._AUTHORITY_PROTOCOL_PATH,
        verification_module._AUTHORITY_RECEIPT_PATH,
        verification_module._ANCHOR_PROTOCOL_PATH,
        verification_module._DATASET_PROTOCOL_PATH,
        verification_module._HYPOTHESIS_PATH,
    }
    for relative in {source_path, test_path, *protocol_paths, "pyproject.toml", "uv.lock"}:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"fixture:{relative}\n")
    execution_key = SigningKey.generate()
    execution_anchor_path = tmp_path / verification_module._ANCHOR_PROTOCOL_PATH
    execution_anchor_path.unlink()
    write_signer_anchor(
        execution_anchor_path,
        execution_key,
        anchor_id="iter000-execution-ledger",
        ledger_scope=_ITERATION_ID,
    )
    correction_key = SigningKey.generate()
    anchor_path = tmp_path / verification_module._VERIFICATION_SIGNER_ANCHOR_PATH
    write_signer_anchor(
        anchor_path,
        correction_key,
        anchor_id=verification_module._VERIFICATION_ANCHOR_ID,
        ledger_scope=verification_module._VERIFICATION_LEDGER_SCOPE,
    )
    anchor = load_signer_anchor(anchor_path)
    proof_binding = {
        "artifact_count": 1,
        "content_map_sha256": "1" * 64,
        "file_sha256": {"synthetic": "2" * 64},
        "git_commit": "3" * 40,
        "git_subtree": "4" * 40,
        "path": "proof",
    }
    amendment = {"proof_binding": proof_binding, "trigger": {"fixture": True}}
    authority = {
        "schema_version": "fieldtrue.iter000-verification-authority.v1",
        "authority_id": "iter000_verification_001",
        "iteration_id": _ITERATION_ID,
        "authorized_command": list(verification_module._CORRECTED_VERIFICATION_COMMAND),
        "amendments": [
            {
                "path": verification_module._VERIFICATION_AMENDMENT_PATH,
                "sha256": verification_module._VERIFICATION_AMENDMENT_SHA256,
            },
            {
                "path": verification_module._VERIFICATION_AMENDMENT_CORRECTION_PATH,
                "sha256": verification_module._VERIFICATION_AMENDMENT_CORRECTION_SHA256,
            },
        ],
        "proof_binding": proof_binding,
        "trigger": amendment["trigger"],
        "correction": verification_module._DATASET_LOCK_CORRECTION,
        "implementation": {
            "git_commit": commit,
            "git_tree": tree,
            "protocol_hashes": {
                relative: sha256_file(tmp_path / relative) for relative in protocol_paths
            },
            "pyproject_sha256": sha256_file(tmp_path / "pyproject.toml"),
            "source_hashes": {source_path: sha256_file(tmp_path / source_path)},
            "test_hashes": {test_path: sha256_file(tmp_path / test_path)},
            "uv_lock_sha256": sha256_file(tmp_path / "uv.lock"),
        },
        "signer_anchor": {
            "path": verification_module._VERIFICATION_SIGNER_ANCHOR_PATH,
            "sha256": sha256_file(anchor_path),
            "signer_public_key": anchor.signer_public_key,
        },
        "consumption": {
            "consumption_timing": "before_outcome_artifact_interpretation",
            "failure_mode": "fail_closed",
            "maximum_consumptions": 1,
            "proof_deletion_restores_authority": False,
            "receipt_path": verification_module._VERIFICATION_RECEIPT_PATH,
            "receipt_presence_consumes_authority": True,
        },
        "resource_constraints": {
            "cloud_jobs": 0,
            "gpu_hours": 0,
            "network_access": False,
            "paid_calls": 0,
        },
        "trust_model": {
            "blocks": [
                "ordinary_receipt_deletion",
                "concurrent_local_replay",
                "proof_local_authority_substitution",
            ],
            "does_not_block": [
                "same_local_owner_deletes_receipt",
                "same_local_owner_rolls_back_repository",
                "same_local_owner_controls_local_git",
                "verification_key_compromise",
            ],
            "external_timestamp": False,
            "signature": "git_pinned_separate_local_ed25519",
        },
    }
    authority_path = tmp_path / verification_module._VERIFICATION_AUTHORITY_PATH
    _write_json(authority_path, authority)
    implementation_paths = {
        source_path,
        test_path,
        *protocol_paths,
        "pyproject.toml",
        "uv.lock",
    }
    committed_blobs = {
        relative: (tmp_path / relative).read_bytes() for relative in implementation_paths
    }
    expected_selection_changes = "\n".join(
        (
            verification_module._VERIFICATION_AUTHORITY_PATH,
            verification_module._VERIFICATION_SIGNER_ANCHOR_PATH,
        )
    )
    git_state = {"selection_changes": expected_selection_changes}
    proof_state = {"hashes": proof_binding["file_sha256"]}

    def git_text(_repo: Path, *arguments: str) -> str:
        if arguments == ("rev-parse", f"{commit}^{{tree}}"):
            return tree
        if arguments == ("rev-parse", "HEAD"):
            return head
        if arguments[:2] == ("merge-base", "--is-ancestor"):
            return ""
        if arguments[:2] == ("diff", "--name-only"):
            return git_state["selection_changes"]
        raise AssertionError(arguments)

    monkeypatch.setattr(verification_module, "_git_text", git_text)

    def git_blob(repo: Path, selected_commit: str, relative: str) -> bytes:
        if selected_commit == commit:
            return committed_blobs[relative]
        return (repo / relative).read_bytes()

    monkeypatch.setattr(verification_module, "_git_blob", git_blob)
    monkeypatch.setattr(
        verification_module,
        "_git_file_set",
        lambda _repo, _commit, prefix: {source_path} if prefix == "src/fieldtrue" else {test_path},
    )
    monkeypatch.setattr(
        verification_module,
        "_proof_file_hashes",
        lambda _proof: proof_state["hashes"],
    )

    loaded, loaded_data, loaded_anchor, _ = verification_module._load_verification_authority(
        tmp_path,
        authority_path,
        amendment=amendment,
    )
    assert loaded == authority
    assert loaded_data == authority_path.read_bytes()
    assert loaded_anchor == anchor

    original_source = (tmp_path / source_path).read_bytes()
    original_pyproject = (tmp_path / "pyproject.toml").read_bytes()
    (tmp_path / source_path).write_text("future iteration source\n")
    (tmp_path / "pyproject.toml").write_text("future iteration dependencies\n")
    git_state["selection_changes"] = expected_selection_changes + "\nREADME.md"
    verification_module._load_verification_authority(
        tmp_path,
        authority_path,
        amendment=amendment,
        strict_selection_head=False,
    )
    with pytest.raises(ProofBundleVerificationError, match="working hash differs"):
        verification_module._load_verification_authority(
            tmp_path,
            authority_path,
            amendment=amendment,
        )
    (tmp_path / source_path).write_bytes(original_source)
    (tmp_path / "pyproject.toml").write_bytes(original_pyproject)
    git_state["selection_changes"] = expected_selection_changes

    protected_protocol = tmp_path / verification_module._HYPOTHESIS_PATH
    original_protocol = protected_protocol.read_bytes()
    protected_protocol.write_text("tampered historical protocol\n")
    with pytest.raises(ProofBundleVerificationError, match="working hash differs"):
        verification_module._load_verification_authority(
            tmp_path,
            authority_path,
            amendment=amendment,
            strict_selection_head=False,
        )
    protected_protocol.write_bytes(original_protocol)

    def assert_authority_rejected(
        candidate: dict[str, Any],
        match: str,
        *,
        selection_changes: str = expected_selection_changes,
        observed_proof_hashes: dict[str, str] | None = None,
    ) -> None:
        git_state["selection_changes"] = selection_changes
        proof_state["hashes"] = observed_proof_hashes or proof_binding["file_sha256"]
        _write_json(authority_path, candidate)
        with pytest.raises(ProofBundleVerificationError, match=match):
            verification_module._load_verification_authority(
                tmp_path,
                authority_path,
                amendment=amendment,
            )

    execution_anchor_data = execution_anchor_path.read_bytes()
    execution_anchor_path.write_bytes(anchor_path.read_bytes())
    assert_authority_rejected(deepcopy(authority), "separately selected signer")
    execution_anchor_path.write_bytes(execution_anchor_data)

    candidate = deepcopy(authority)
    candidate["authority_id"] = "rebound_authority"
    assert_authority_rejected(candidate, "identity or frozen bindings")

    candidate = deepcopy(authority)
    candidate["consumption"]["maximum_consumptions"] = 2
    assert_authority_rejected(candidate, "one fail-closed consumption")

    candidate = deepcopy(authority)
    candidate["resource_constraints"]["network_access"] = True
    assert_authority_rejected(candidate, "unapproved resources")

    candidate = deepcopy(authority)
    candidate["trust_model"]["external_timestamp"] = True
    assert_authority_rejected(candidate, "misstates its local trust boundary")

    candidate = deepcopy(authority)
    candidate["signer_anchor"]["signer_public_key"] = "0" * 64
    assert_authority_rejected(candidate, "separately selected signer")

    candidate = deepcopy(authority)
    candidate["implementation"]["git_commit"] = "--help"
    assert_authority_rejected(candidate, "lowercase 40-character Git object ID")

    candidate = deepcopy(authority)
    candidate["implementation"]["git_tree"] = "0" * 40
    assert_authority_rejected(candidate, "tree differs")

    candidate = deepcopy(authority)
    candidate["implementation"]["source_hashes"] = {}
    assert_authority_rejected(candidate, "complete implementation source tree")

    candidate = deepcopy(authority)
    candidate["implementation"]["test_hashes"] = {}
    assert_authority_rejected(candidate, "complete test tree")

    candidate = deepcopy(authority)
    candidate["implementation"]["pyproject_sha256"] = "0" * 64
    assert_authority_rejected(candidate, "implementation differs for pyproject")

    candidate = deepcopy(authority)
    candidate["implementation"]["protocol_hashes"].pop(verification_module._HYPOTHESIS_PATH)
    assert_authority_rejected(candidate, "exact correction protocol surface")

    assert_authority_rejected(
        deepcopy(authority),
        "tracked files changed",
        selection_changes=expected_selection_changes + "\nREADME.md",
    )
    assert_authority_rejected(
        deepcopy(authority),
        "proof binding no longer matches",
        observed_proof_hashes={"synthetic": "0" * 64},
    )

    with pytest.raises(ProofBundleVerificationError, match="fixed repository path"):
        verification_module._load_verification_authority(
            tmp_path,
            tmp_path / "proof" / "attempt_authority.json",
            amendment=amendment,
        )


def test_corrected_verification_consumes_before_reading_and_replay_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof, execution_anchor, _ = _fixture_bundle(tmp_path / "fixture")
    base_verification = verify_iter000_proof_bundle(
        proof,
        signer_anchor_path=execution_anchor,
    )
    correction_key = SigningKey.generate()
    correction_anchor_path = tmp_path / "correction-anchor.json"
    write_signer_anchor(
        correction_anchor_path,
        correction_key,
        anchor_id="iter000-verification-correction-001",
        ledger_scope=f"{_ITERATION_ID}/attempt_001/correction_001",
    )
    correction_anchor = load_signer_anchor(correction_anchor_path)
    correction_anchor_data = correction_anchor_path.read_bytes()
    proof_hashes = {"synthetic": "a" * 64}
    execution_authority_sha256 = "d" * 64
    authority_consumption_sha256 = "e" * 64
    base_verification = base_verification.model_copy(
        update={
            "authority_specification_sha256": execution_authority_sha256,
            "authority_consumption_sha256": authority_consumption_sha256,
        }
    )
    amendment = {
        "proof_binding": {
            "content_map_sha256": sha256_value(proof_hashes),
            "file_sha256": proof_hashes,
        }
    }
    authority = {
        "authority_id": "iter000_verification_001",
        "amendments": [
            {"path": "amendment-001", "sha256": "b" * 64},
            {"path": "amendment-002", "sha256": "c" * 64},
        ],
        "trigger": {
            "execution_authority": {"sha256": execution_authority_sha256},
            "authority_consumption": {"sha256": authority_consumption_sha256},
        },
    }
    authority_data = canonical_json_pretty(authority)
    receipt_relative = "verification/receipt.json"
    command = verification_module._CORRECTED_VERIFICATION_COMMAND
    runtime = runtime_identity().model_copy(
        update={
            "command": command,
            "repository_dirty": False,
            "dirty_state_hash": sha256_bytes(b""),
        }
    )
    calls = 0

    def corrected_core(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        consumed = json.loads((tmp_path / receipt_relative).read_text())
        assert (
            consumed["schema_version"] == "fieldtrue.iter000-verification-authority-consumption.v1"
        )
        verification_module._verify_consumption_record(
            consumed,
            authority=authority,
            authority_data=authority_data,
            amendment=amendment,
            anchor=correction_anchor,
        )
        valid, detail = verification_module.validate_iter000_verification_correction_surface(
            tmp_path
        )
        assert valid is False
        assert "consumed without a completed receipt" in detail
        return base_verification

    monkeypatch.setattr(
        verification_module,
        "_load_verification_amendments",
        lambda _repo: (amendment, b"amendment-001", b"amendment-002"),
    )
    monkeypatch.setattr(
        verification_module,
        "_load_verification_authority",
        lambda *_args, **_kwargs: (
            authority,
            authority_data,
            correction_anchor,
            correction_anchor_data,
        ),
    )
    monkeypatch.setattr(verification_module, "collect_runtime_identity", lambda *_a, **_k: runtime)
    monkeypatch.setattr(
        verification_module,
        "_git_text",
        lambda _repo, *arguments: (
            runtime.git_commit if arguments == ("rev-parse", "HEAD") else runtime.git_tree
        ),
    )
    monkeypatch.setattr(
        verification_module,
        "load_or_create_signing_key",
        lambda _path: correction_key,
    )
    monkeypatch.setattr(verification_module, "_proof_file_hashes", lambda _path: proof_hashes)
    monkeypatch.setattr(verification_module, "_verify_iter000_proof_bundle", corrected_core)
    monkeypatch.setattr(verification_module, "_VERIFICATION_RECEIPT_PATH", receipt_relative)

    valid, detail = verification_module.validate_iter000_verification_correction_surface(tmp_path)
    assert valid is True
    assert "unconsumed" in detail

    mismatched_runtime = runtime.model_copy(update={"git_tree": "3" * 40})
    monkeypatch.setattr(
        verification_module,
        "collect_runtime_identity",
        lambda *_a, **_k: mismatched_runtime,
    )
    with pytest.raises(ProofBundleVerificationError, match="selected HEAD"):
        verification_module.verify_iter000_proof_bundle_correction_001(
            tmp_path,
            command=command,
        )
    assert not (tmp_path / receipt_relative).exists()
    monkeypatch.setattr(
        verification_module,
        "collect_runtime_identity",
        lambda *_a, **_k: runtime,
    )

    receipt = verification_module.verify_iter000_proof_bundle_correction_001(
        tmp_path,
        command=command,
    )
    assert calls == 1
    assert receipt.correction_applied == verification_module._DATASET_LOCK_CORRECTION
    assert receipt.resource_usage["network_access"] is False
    receipt_value, receipt_data = verification_module._read_json_object(
        tmp_path / receipt_relative,
        "corrected verification receipt",
    )
    loaded_receipt = verification_module._verify_final_correction_receipt(
        receipt_value,
        receipt_data,
        authority=authority,
        authority_data=authority_data,
        amendment=amendment,
        anchor=correction_anchor,
    )
    assert loaded_receipt.model_dump(mode="json") == receipt.model_dump(mode="json")
    valid, detail = verification_module.validate_iter000_verification_correction_surface(tmp_path)
    assert valid is True
    assert "signed, complete, and proof-bound" in detail

    rebound_receipt = deepcopy(receipt_value)
    rebound_receipt["resource_usage"]["network_access"] = True
    with pytest.raises(ProofBundleVerificationError, match="frozen authority"):
        verification_module._verify_final_correction_receipt(
            rebound_receipt,
            canonical_json_pretty(rebound_receipt),
            authority=authority,
            authority_data=authority_data,
            amendment=amendment,
            anchor=correction_anchor,
        )

    invalid_hash_receipt = deepcopy(receipt_value)
    invalid_hash_receipt["receipt_hash"] = "0" * 64
    with pytest.raises(ProofBundleVerificationError, match="content hash differs"):
        verification_module._verify_final_correction_receipt(
            invalid_hash_receipt,
            canonical_json_pretty(invalid_hash_receipt),
            authority=authority,
            authority_data=authority_data,
            amendment=amendment,
            anchor=correction_anchor,
        )

    invalid_receipt = deepcopy(receipt_value)
    invalid_receipt["signature"] = "00" * 64
    with pytest.raises(ProofBundleVerificationError, match="signature is invalid"):
        verification_module._verify_final_correction_receipt(
            invalid_receipt,
            canonical_json_pretty(invalid_receipt),
            authority=authority,
            authority_data=authority_data,
            amendment=amendment,
            anchor=correction_anchor,
        )
    with pytest.raises(ProofBundleVerificationError, match="already consumed"):
        verification_module.verify_iter000_proof_bundle_correction_001(
            tmp_path,
            command=command,
        )
    assert calls == 1

    (tmp_path / receipt_relative).chmod(0o644)
    _write_json(tmp_path / receipt_relative, {"schema_version": "unsupported"})
    valid, detail = verification_module.validate_iter000_verification_correction_surface(tmp_path)
    assert valid is False
    assert "unsupported schema" in detail

    failed_receipt_relative = "verification/failed-receipt.json"
    monkeypatch.setattr(
        verification_module,
        "_VERIFICATION_RECEIPT_PATH",
        failed_receipt_relative,
    )
    failed_calls = 0

    def failing_core(*_args: object, **_kwargs: object) -> object:
        nonlocal failed_calls
        failed_calls += 1
        assert (tmp_path / failed_receipt_relative).is_file()
        raise ProofBundleVerificationError("synthetic corrected verifier failure")

    monkeypatch.setattr(verification_module, "_verify_iter000_proof_bundle", failing_core)
    with pytest.raises(ProofBundleVerificationError, match="synthetic corrected verifier failure"):
        verification_module.verify_iter000_proof_bundle_correction_001(
            tmp_path,
            command=command,
        )
    failed_value, failed_data = verification_module._read_json_object(
        tmp_path / failed_receipt_relative,
        "failed verification consumption receipt",
    )
    assert canonical_json_pretty(failed_value) == failed_data
    verification_module._verify_consumption_record(
        failed_value,
        authority=authority,
        authority_data=authority_data,
        amendment=amendment,
        anchor=correction_anchor,
    )
    with pytest.raises(ProofBundleVerificationError, match="already consumed"):
        verification_module.verify_iter000_proof_bundle_correction_001(
            tmp_path,
            command=command,
        )
    assert failed_calls == 1


def test_amended_runtime_must_match_the_external_authority() -> None:
    runtime = runtime_identity().model_copy(
        update={
            "repository_dirty": False,
            "dirty_state_hash": sha256_bytes(b""),
            "lockfile_hash": "b" * 64,
            "command": ("fieldtrue", "experiment", "iter000-amendment-001"),
        }
    )
    authority = {"authorized_command": ["fieldtrue", "experiment", "iter000-amendment-001"]}
    protocol_hashes = {"uv.lock": "b" * 64}
    run_id = f"iter000-attempt_001-{runtime.git_commit[:12]}"

    verification_module._verify_authorized_runtime(
        run_id=run_id,
        runtime=runtime,
        authority=authority,
        protocol_hashes=protocol_hashes,
    )

    invalid_cases = (
        ("iter000-fixture", runtime),
        (run_id, runtime.model_copy(update={"repository_dirty": True})),
        (run_id, runtime.model_copy(update={"dirty_state_hash": "a" * 64})),
        (run_id, runtime.model_copy(update={"lockfile_hash": "a" * 64})),
        (run_id, runtime.model_copy(update={"command": ("fieldtrue", "experiment", "iter000")})),
    )
    for candidate_run_id, candidate_runtime in invalid_cases:
        with pytest.raises(ProofBundleVerificationError):
            verification_module._verify_authorized_runtime(
                run_id=candidate_run_id,
                runtime=candidate_runtime,
                authority=authority,
                protocol_hashes=protocol_hashes,
            )

    legacy = legacy_runtime_identity().model_copy(
        update={
            "repository_dirty": False,
            "dirty_state_hash": sha256_bytes(b""),
            "lockfile_hash": "b" * 64,
            "command": ("fieldtrue", "experiment", "iter000-amendment-001"),
        }
    )
    with pytest.raises(ProofBundleVerificationError, match="requires observed-v1"):
        verification_module._verify_authorized_runtime(
            run_id=f"iter000-attempt_001-{legacy.git_commit[:12]}",
            runtime=legacy,
            authority=authority,
            protocol_hashes=protocol_hashes,
        )


def test_verification_authority_consumption_refuses_legacy_runtime() -> None:
    legacy = legacy_runtime_identity()
    promoted = legacy.model_copy(update={"provenance_state": "observed-v1"})
    for candidate in (legacy, promoted):
        with pytest.raises(ProofBundleVerificationError, match="requires observed-v1"):
            verification_module._consumption_record(
                authority={},
                authority_data=b"authority",
                amendment={},
                runtime=candidate,
                signer_public_key="0" * 64,
                signing_key=SigningKey.generate(),
            )


def test_external_attempt_authority_rejects_rebound_contracts(tmp_path: Path) -> None:
    repository = Path(__file__).resolve().parents[2]
    source = repository / "protocol" / "attempt_authorities" / "iter000_001.json"
    anchor_path = repository / "protocol" / "trust" / "iter000_signer_anchor.json"
    anchor = load_signer_anchor(anchor_path)
    anchor_data = anchor_path.read_bytes()
    original = json.loads(source.read_text())
    candidate_path = tmp_path / "authority.json"

    candidate_path.write_bytes(source.read_bytes())
    _, authority_data, protocol_hashes = verification_module._trusted_attempt_authority(
        candidate_path,
        anchor=anchor,
        anchor_data=anchor_data,
    )
    assert authority_data == source.read_bytes()
    assert protocol_hashes[verification_module._ANCHOR_PROTOCOL_PATH] == sha256_bytes(anchor_data)

    mutations = (
        (("authority_id",), "iter000_002", "wrong identity or command"),
        (("amendment", "binding"), "mutable", "wrong amendment binding"),
        (("signer_anchor", "signer_public_key"), "a" * 64, "selected signer"),
        (("consumption", "maximum_consumptions"), 2, "one fail-closed consumption"),
        (("runtime_constraints", "tls", "trust_store_version"), "other", "TLS runtime"),
        (("trust_model", "external_timestamp"), True, "local trust boundary"),
    )
    for keys, replacement, message in mutations:
        candidate = deepcopy(original)
        target = candidate
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = replacement
        _write_json(candidate_path, candidate)
        with pytest.raises(ProofBundleVerificationError, match=message):
            verification_module._trusted_attempt_authority(
                candidate_path,
                anchor=anchor,
                anchor_data=anchor_data,
            )

    candidate = deepcopy(original)
    candidate["protocol_hashes"].pop("src/fieldtrue/splits.py")
    _write_json(candidate_path, candidate)
    with pytest.raises(ProofBundleVerificationError, match="omits a mandatory protocol file"):
        verification_module._trusted_attempt_authority(
            candidate_path,
            anchor=anchor,
            anchor_data=anchor_data,
        )

    candidate = deepcopy(original)
    candidate["protocol_hashes"][verification_module._ANCHOR_PROTOCOL_PATH] = "0" * 64
    _write_json(candidate_path, candidate)
    with pytest.raises(ProofBundleVerificationError, match="signer-anchor hash differs"):
        verification_module._trusted_attempt_authority(
            candidate_path,
            anchor=anchor,
            anchor_data=anchor_data,
        )


def test_authority_consumption_rejects_resigned_semantic_tampering(tmp_path: Path) -> None:
    proof = tmp_path / "proof"
    proof.mkdir()
    key = SigningKey.generate()
    anchor_path = tmp_path / "anchor.json"
    write_signer_anchor(
        anchor_path,
        key,
        anchor_id="iter000-execution-ledger",
        ledger_scope=_ITERATION_ID,
    )
    anchor = load_signer_anchor(anchor_path)
    anchor_data = anchor_path.read_bytes()
    authority_data = canonical_json_pretty({"authority_id": "iter000_001"})
    authority = {"runtime_constraints": {"tls": verification_module._ATTEMPT_001_TLS_CONSTRAINTS}}
    protocol_hashes = {verification_module._AMENDMENT_CONTRACT_PATH: "a" * 64}
    runtime = runtime_identity().model_copy(
        update={"command": ("fieldtrue", "experiment", "iter000-amendment-001")}
    )
    run_id = f"iter000-attempt_001-{runtime.git_commit[:12]}"
    body = {
        "schema_version": "fieldtrue.attempt-authority-consumption.v1",
        "authority_id": "iter000_001",
        "iteration_id": _ITERATION_ID,
        "attempt_id": "attempt_001",
        "run_id": run_id,
        "consumed_at": "2026-07-14T12:00:00+00:00",
        "authority_specification": {
            "path": verification_module._AUTHORITY_PROTOCOL_PATH,
            "sha256": sha256_bytes(authority_data),
        },
        "amendment": {
            "amendment_id": "iter000_001",
            "path": verification_module._AMENDMENT_CONTRACT_PATH,
            "sha256": protocol_hashes[verification_module._AMENDMENT_CONTRACT_PATH],
        },
        "signer_anchor": {
            "path": verification_module._ANCHOR_PROTOCOL_PATH,
            "sha256": sha256_bytes(anchor_data),
        },
        "runtime": runtime.model_dump(mode="json"),
        "tls_runtime": verification_module._ATTEMPT_001_TLS_CONSTRAINTS,
        "signer_public_key": anchor.signer_public_key,
        "trust_level": "local_ed25519_no_external_timestamp",
        "same_local_owner_can_delete_or_rollback_local_state": True,
    }
    receipt_hash = sha256_value(body)
    original = {
        **body,
        "receipt_hash": receipt_hash,
        "signature": key.sign(bytes.fromhex(receipt_hash)).signature.hex(),
    }
    receipt_path = proof / verification_module._AUTHORITY_CONSUMPTION_ARTIFACT
    _write_json(receipt_path, original)
    assert verification_module._verify_authority_consumption(
        proof,
        authority=authority,
        authority_data=authority_data,
        protocol_hashes=protocol_hashes,
        anchor=anchor,
        anchor_data=anchor_data,
        run_id=run_id,
        runtime=runtime,
        signed_receipt_hash=receipt_hash,
    ) == sha256_file(receipt_path)

    semantic_mutations = (
        (("consumed_at",), 7, "RFC 3339 string"),
        (("consumed_at",), "not-a-time", "time is invalid"),
        (("consumed_at",), "2026-07-14T12:00:00", "timezone-aware"),
        (("run_id",), "iter000-attempt_001-other", "identity is inconsistent"),
        (("authority_specification", "sha256"), "0" * 64, "trusted authority"),
        (("amendment", "sha256"), "0" * 64, "bind Amendment 001"),
        (("signer_anchor", "sha256"), "0" * 64, "selected signer anchor"),
        (("tls_runtime", "trust_store_version"), "other", "TLS runtime differs"),
        (
            ("runtime",),
            runtime.model_copy(update={"command": ("other",)}).model_dump(mode="json"),
            "runtime differs",
        ),
    )
    for keys, replacement, message in semantic_mutations:
        candidate = deepcopy(original)
        target = candidate
        for field in keys[:-1]:
            target = target[field]
        target[keys[-1]] = replacement
        candidate_body = dict(candidate)
        candidate_body.pop("receipt_hash")
        candidate_body.pop("signature")
        candidate_hash = sha256_value(candidate_body)
        candidate["receipt_hash"] = candidate_hash
        candidate["signature"] = key.sign(bytes.fromhex(candidate_hash)).signature.hex()
        _write_json(receipt_path, candidate)
        with pytest.raises(ProofBundleVerificationError, match=message):
            verification_module._verify_authority_consumption(
                proof,
                authority=authority,
                authority_data=authority_data,
                protocol_hashes=protocol_hashes,
                anchor=anchor,
                anchor_data=anchor_data,
                run_id=run_id,
                runtime=runtime,
                signed_receipt_hash=candidate_hash,
            )

    malformed_signature_cases = (
        ({**original, "signature": 7}, "signature must be hexadecimal"),
        ({**original, "receipt_hash": "0" * 64}, "receipt hash mismatch"),
        ({**original, "signature": "not-hex"}, "signature is invalid"),
    )
    for candidate, message in malformed_signature_cases:
        _write_json(receipt_path, candidate)
        with pytest.raises(ProofBundleVerificationError, match=message):
            verification_module._verify_authority_consumption(
                proof,
                authority=authority,
                authority_data=authority_data,
                protocol_hashes=protocol_hashes,
                anchor=anchor,
                anchor_data=anchor_data,
                run_id=run_id,
                runtime=runtime,
                signed_receipt_hash=str(candidate["receipt_hash"]),
            )


def test_signed_scientifically_impossible_pass_is_rejected(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(
        tmp_path,
        report_override=_normal_report(passed=True),
    )

    with pytest.raises(ProofBundleVerificationError, match="proof-local recomputation"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)


@pytest.mark.parametrize("flow", ["source-invalid", "ingestion-invalid"])
def test_invalid_bundles_receive_full_verification(
    tmp_path: Path,
    flow: FixtureFlow,
) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path, flow=flow)
    verification = verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)
    assert verification.flow == flow
    assert verification.verdict == "INVALID"
    assert verification.result_reproducible is True
    assert "invalidity.json" in verification.artifact_hashes


def test_exact_proof_local_result_tampering_is_rejected(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path)
    with (proof / "RESULT.md").open("a") as handle:
        handle.write("unsigned suffix\n")
    with pytest.raises(ProofBundleVerificationError, match=r"artifact hash.*RESULT"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)


def test_manifest_and_artifact_bundle_self_hashes_are_checked(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path)
    manifest_path = proof / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["manifest_content_hash"] = "0" * 64
    _write_json(manifest_path, manifest)
    with pytest.raises(ProofBundleVerificationError, match="manifest content hash"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)

    proof, anchor, _ = _fixture_bundle(tmp_path / "bundle-case", corrupt_bundle_self_hash=True)
    with pytest.raises(ProofBundleVerificationError, match="artifact bundle content hash"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)


def test_verifier_rejects_cross_layer_commitment_rebinding(tmp_path: Path) -> None:
    def rejected(case: str, message: str, **fixture_options: Any) -> None:
        proof, anchor, _ = _fixture_bundle(tmp_path / case, **fixture_options)
        with pytest.raises(ProofBundleVerificationError, match=message):
            verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)

    rejected(
        "bundle-schema",
        "unsupported artifact bundle schema",
        bundle_overrides={"schema_version": "unsupported"},
    )
    rejected(
        "bundle-run",
        "artifact bundle run_id differs",
        bundle_overrides={"run_id": "other-run"},
    )
    rejected(
        "bundle-artifact",
        "artifact bundle hash mismatch",
        bundled_artifact_overrides={"RESULT.md": "0" * 64},
    )
    rejected(
        "terminal-bundle",
        "signed terminal event does not commit",
        terminal_overrides={"artifact_bundle_hash": "0" * 64},
    )

    report = _normal_report()
    reordered = report.model_copy(
        update={"gates": (report.gates[1], report.gates[0], *report.gates[2:])}
    )
    rejected(
        "gate-sequence",
        "frozen iter000 gate sequence",
        report_override=reordered,
    )
    rejected(
        "derived-verdict",
        "verdict does not follow",
        report_override=ReadinessReport.model_validate(
            {**report.model_dump(mode="json"), "verdict": "PASS"}
        ),
    )
    rejected(
        "result-render",
        "RESULT.md is not reproducible",
        result_override="counterfeit result\n",
    )
    rejected(
        "learning",
        "iteration learning is inconsistent",
        learning_overrides={"engine_construction_authorized": True},
    )
    rejected(
        "dataset-binding",
        "dataset lock differs",
        protocol_overrides={verification_module._DATASET_PROTOCOL_PATH: "0" * 64},
    )
    rejected(
        "amendment-document-binding",
        "Amendment 001 document differs",
        protocol_overrides={verification_module._AMENDMENT_DOCUMENT_PATH: "0" * 64},
    )
    rejected(
        "amendment-contract-binding",
        "Amendment 001 contract differs",
        protocol_overrides={verification_module._AMENDMENT_CONTRACT_PATH: "0" * 64},
    )
    rejected(
        "source-dataset",
        "dataset identity differs",
        source_overrides={"dataset_id": "other-dataset"},
    )
    rejected(
        "source-resources",
        "source ledger resources differ",
        source_overrides={"resources": []},
    )
    rejected(
        "receipt-coverage",
        "does not commit to proof/coverage",
        receipt_overrides={"coverage_report_sha256": "0" * 64},
    )
    rejected(
        "receipt-evidence",
        "does not commit to the model evidence manifest",
        receipt_overrides={"evidence_manifest_sha256": "0" * 64},
    )
    rejected(
        "receipt-truth",
        "does not commit to the proof-local truth manifest",
        receipt_overrides={"truth_manifest_sha256": "0" * 64},
    )
    rejected(
        "ingestion-event",
        "signed ingestion event differs",
        ingested_overrides={"coverage_hash": "0" * 64},
    )
    rejected(
        "adjudication-event",
        "signed readiness adjudication differs",
        adjudicated_overrides={"verdict": "PASS"},
    )
    rejected(
        "terminal-verdict",
        "signed terminal verdict differs",
        terminal_overrides={"verdict": "PASS"},
    )
    rejected(
        "manifest-verdict",
        "run manifest verdict differs",
        manifest_overrides={"verdict": "PASS"},
    )


def test_unsigned_full_verdict_rewrite_fails_signed_manifest_commitment(
    tmp_path: Path,
) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path)
    report = _normal_report(passed=True)
    _write_json(proof / "readiness_report.json", report)
    (proof / "RESULT.md").write_text(render_readiness_result(report))
    _write_json(proof / "LEARNING.json", _iteration_learning(report))

    bundle_path = proof / "artifact_bundle.json"
    bundle = json.loads(bundle_path.read_text())
    for name in ("readiness_report.json", "RESULT.md", "LEARNING.json"):
        bundle["artifacts"][name] = sha256_file(proof / name)
    bundle_body = dict(bundle)
    bundle_body.pop("bundle_sha256")
    bundle["bundle_sha256"] = sha256_value(bundle_body)
    _write_json(bundle_path, bundle)

    manifest_path = proof / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["verdict"] = "PASS"
    for name in (
        "readiness_report.json",
        "RESULT.md",
        "LEARNING.json",
        "artifact_bundle.json",
    ):
        manifest["artifacts"][name] = sha256_file(proof / name)
    manifest_body = dict(manifest)
    manifest_body.pop("manifest_content_hash")
    manifest["manifest_content_hash"] = sha256_value(manifest_body)
    _write_json(manifest_path, manifest)

    with pytest.raises(ProofBundleVerificationError, match="signed terminal event"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)


def test_wholesale_attacker_ledger_replacement_fails_pinned_anchor(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path)
    original_events = [
        json.loads(line) for line in (proof / "execution_ledger.jsonl").read_text().splitlines()
    ]
    (proof / "execution_ledger.jsonl").unlink()
    (proof / "execution_ledger.head.json").unlink()
    attacker = SignedLedger(
        proof / "execution_ledger.jsonl",
        proof / "execution_ledger.head.json",
        SigningKey.generate(),
    )
    for event in original_events:
        attacker.append(
            run_id=event["run_id"],
            event_type=event["event_type"],
            payload=event["payload"],
            runtime=runtime_identity(),
        )

    with pytest.raises(ProofBundleVerificationError, match="pinned ledger verification"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xff", "not valid UTF-8 JSON"),
        (b"{", "not valid UTF-8 JSON"),
        (b"[]", "must contain one JSON object"),
        (b'{"key":1,"key":2}', "duplicate JSON object key"),
    ],
)
def test_verifier_json_parser_fails_closed(
    data: bytes,
    message: str,
) -> None:
    with pytest.raises(ProofBundleVerificationError, match=message):
        verification_module._json_object(data, "fixture")


def test_verifier_structural_guards_reject_malformed_values(tmp_path: Path) -> None:
    with pytest.raises(ProofBundleVerificationError, match="must be a JSON object"):
        verification_module._object([], "fixture")
    with pytest.raises(ProofBundleVerificationError, match="keys differ"):
        verification_module._exact_keys({"a": 1}, frozenset({"b"}), "fixture")
    with pytest.raises(ProofBundleVerificationError, match="lowercase SHA-256"):
        verification_module._hash("A" * 64, "fixture")
    with pytest.raises(ProofBundleVerificationError, match="canonical pretty JSON"):
        verification_module._canonical({"a": 1}, b'{"a":1}', "fixture")
    with pytest.raises(ProofBundleVerificationError, match="typed schema"):
        verification_module._model(ReadinessReport, {}, "fixture")

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ProofBundleVerificationError, match="regular, non-symlink file"):
        verification_module._read_regular_file(directory, "fixture")
    target = tmp_path / "target.json"
    target.write_text("{}\n")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(ProofBundleVerificationError, match="regular, non-symlink file"):
        verification_module._read_regular_file(link, "fixture")


def test_verifier_lifecycle_and_verdict_derivation_are_closed_world() -> None:
    with pytest.raises(ProofBundleVerificationError, match="complete allowed"):
        verification_module._flow([])
    with pytest.raises(ProofBundleVerificationError, match="not UTF-8"):
        verification_module._parse_events(b"\xff")
    with pytest.raises(ProofBundleVerificationError, match="blank line"):
        verification_module._parse_events(b"\n")

    assert verification_module._expected_verdict(_normal_report(passed=True)) == "PASS"
    assert verification_module._expected_verdict(_normal_report()) == "BLOCKED_EVIDENCE"
    invalid = invalid_readiness_report(
        dataset_id="adapt-fixture",
        failed_gate_id="source-integrity",
        error_type="ValueError",
        error_message="integrity mismatch",
    )
    assert verification_module._expected_verdict(invalid) == "INVALID"


def test_result_renderer_rejects_missing_or_noncanonical_proof(tmp_path: Path) -> None:
    with pytest.raises(ProofBundleVerificationError, match="proof root"):
        render_iter000_result_from_proof(tmp_path / "missing")

    proof = tmp_path / "proof"
    proof.mkdir()
    report = _normal_report()
    (proof / "readiness_report.json").write_text(json.dumps(report.model_dump(mode="json")))
    with pytest.raises(ProofBundleVerificationError, match="canonical pretty JSON"):
        render_iter000_result_from_proof(proof)


def test_signed_protocol_guards_reject_scope_and_authority_changes(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path)
    events = verification_module._parse_events((proof / "execution_ledger.jsonl").read_bytes())
    started = events[0]
    anchor_data = anchor.read_bytes()

    def changed_started(payload: dict[str, object]) -> object:
        return started.model_copy(update={"payload": payload})

    payload = deepcopy(started.payload)
    payload["hypothesis"] = "experiments/other/HYPOTHESIS.md"
    with pytest.raises(ProofBundleVerificationError, match="frozen iter000 hypothesis"):
        verification_module._verify_started(changed_started(payload), anchor_data)

    payload = deepcopy(started.payload)
    payload["gpu_authorized"] = True
    with pytest.raises(ProofBundleVerificationError, match="forbids GPU"):
        verification_module._verify_started(changed_started(payload), anchor_data)

    payload = deepcopy(started.payload)
    payload["protocol_bundle"]["schema_version"] = "unsupported"  # type: ignore[index]
    with pytest.raises(ProofBundleVerificationError, match="unsupported signed protocol"):
        verification_module._verify_started(changed_started(payload), anchor_data)

    payload = deepcopy(started.payload)
    payload["protocol_bundle"]["bundle_sha256"] = "0" * 64  # type: ignore[index]
    with pytest.raises(ProofBundleVerificationError, match="content hash mismatch"):
        verification_module._verify_started(changed_started(payload), anchor_data)

    for omitted_path, message in (
        (verification_module._HYPOTHESIS_PATH, "omits the frozen hypothesis"),
        (verification_module._DATASET_PROTOCOL_PATH, "omits the frozen dataset lock"),
    ):
        payload = deepcopy(started.payload)
        bundle = payload["protocol_bundle"]
        files = bundle["files"]  # type: ignore[index]
        files.pop(omitted_path)  # type: ignore[union-attr]
        bundle["bundle_sha256"] = sha256_value(files)  # type: ignore[index]
        with pytest.raises(ProofBundleVerificationError, match=message):
            verification_module._verify_started(changed_started(payload), anchor_data)

    payload = deepcopy(started.payload)
    bundle = payload["protocol_bundle"]
    files = bundle["files"]  # type: ignore[index]
    files[verification_module._ANCHOR_PROTOCOL_PATH] = "0" * 64  # type: ignore[index]
    bundle["bundle_sha256"] = sha256_value(files)  # type: ignore[index]
    with pytest.raises(ProofBundleVerificationError, match="selected signer anchor"):
        verification_module._verify_started(changed_started(payload), anchor_data)


def test_signed_source_guards_reject_unfrozen_or_paid_inputs(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path)
    events = verification_module._parse_events((proof / "execution_ledger.jsonl").read_bytes())
    protocol_files, _ = verification_module._verify_started(events[0], anchor.read_bytes())
    source = events[1]

    payload = deepcopy(source.payload)
    payload["dataset_lock_hash"] = "0" * 64
    with pytest.raises(ProofBundleVerificationError, match="frozen dataset lock"):
        verification_module._verify_sources(
            source.model_copy(update={"payload": payload}), protocol_files
        )

    payload = deepcopy(source.payload)
    payload["cost_usd"] = "1"
    with pytest.raises(ProofBundleVerificationError, match="no-cost source protocol"):
        verification_module._verify_sources(
            source.model_copy(update={"payload": payload}), protocol_files
        )

    payload = deepcopy(source.payload)
    payload["resources"] = {}
    with pytest.raises(ProofBundleVerificationError, match="resources must be a list"):
        verification_module._verify_sources(
            source.model_copy(update={"payload": payload}), protocol_files
        )


def test_invalidity_adjudicator_rejects_semantic_rewrites(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path, flow="source-invalid")
    events_list = verification_module._parse_events((proof / "execution_ledger.jsonl").read_bytes())
    events = {event.event_type: event for event in events_list}
    protocol_files, _ = verification_module._verify_started(
        events["run-started"], anchor.read_bytes()
    )
    report = ReadinessReport.model_validate_json((proof / "readiness_report.json").read_bytes())
    invalidity_path = proof / "invalidity.json"
    original = json.loads(invalidity_path.read_text())

    def adjudicate(
        value: dict[str, object],
        *,
        candidate_report: ReadinessReport = report,
        align_event: bool = True,
        sources: dict[str, object] | None = None,
    ) -> None:
        _write_json(invalidity_path, value)
        candidate_events = dict(events)
        if align_event:
            candidate_events["source-invalid"] = events["source-invalid"].model_copy(
                update={
                    "payload": {
                        "invalidity_hash": sha256_file(invalidity_path),
                        "error_type": value["error_type"],
                    }
                }
            )
        verification_module._verify_invalidity(
            proof_root=proof,
            flow="source-invalid",
            events=candidate_events,
            actual_hashes={"invalidity.json": sha256_file(invalidity_path)},
            report=candidate_report,
            protocol_files=protocol_files,
            sources=sources,
        )

    value = {**original, "stage": "parser-integrity"}
    with pytest.raises(ProofBundleVerificationError, match="inconsistent"):
        adjudicate(value)

    value = {**original, "dataset_lock_hash": "0" * 64}
    with pytest.raises(ProofBundleVerificationError, match="frozen dataset lock"):
        adjudicate(value)

    value = {**original, "error_type": ""}
    with pytest.raises(ProofBundleVerificationError, match="non-empty string"):
        adjudicate(value)

    value = {**original, "message": 1}
    with pytest.raises(ProofBundleVerificationError, match="message must be a string"):
        adjudicate(value)

    with pytest.raises(ProofBundleVerificationError, match="signed invalidity event"):
        adjudicate({**original, "message": "rewritten"}, align_event=False)

    with pytest.raises(ProofBundleVerificationError, match="different inputs"):
        adjudicate(
            original,
            sources={
                "dataset_id": "other",
                "dataset_lock_hash": original["dataset_lock_hash"],
            },
        )

    with pytest.raises(ProofBundleVerificationError, match="early-stop rule"):
        adjudicate(original, candidate_report=_normal_report())

    changed_gate = report.gates[0].model_copy(
        update={"observed": {"error_type": "ValueError", "message": "different"}}
    )
    changed_report = report.model_copy(update={"gates": (changed_gate, *report.gates[1:])})
    with pytest.raises(ProofBundleVerificationError, match="gate observation"):
        adjudicate(original, candidate_report=changed_report)


def test_terminal_resource_and_manifest_commitments_are_enforced(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(
        tmp_path / "manifest-hash",
        terminal_overrides={"run_manifest_hash": "0" * 64},
    )
    with pytest.raises(ProofBundleVerificationError, match=r"run_manifest\.json"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)

    proof, anchor, _ = _fixture_bundle(
        tmp_path / "resource-use",
        terminal_overrides={"gpu_hours": 1},
    )
    with pytest.raises(ProofBundleVerificationError, match="zero accelerator"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)

    changed_runtime = runtime_identity().model_copy(update={"command": ("other",)})
    proof, anchor, _ = _fixture_bundle(
        tmp_path / "runtime",
        manifest_overrides={"runtime": changed_runtime},
    )
    with pytest.raises(ProofBundleVerificationError, match="runtime differs"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)

    proof, anchor, _ = _fixture_bundle(
        tmp_path / "manifest-schema",
        manifest_overrides={"schema_version": "unsupported"},
    )
    with pytest.raises(ProofBundleVerificationError, match="unsupported run manifest"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)

    proof, anchor, _ = _fixture_bundle(
        tmp_path / "run-id",
        manifest_overrides={"run_id": 7},
    )
    with pytest.raises(ProofBundleVerificationError, match="run_id must be a string"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)

    proof, anchor, _ = _fixture_bundle(
        tmp_path / "checkpoint",
        manifest_overrides={
            "ledger_checkpoint": {
                "event_count": 4,
                "head_hash": "0" * 64,
                "signer_public_key": "a" * 64,
                "trust_level": "git_pinned_ed25519_no_external_timestamp",
            }
        },
    )
    with pytest.raises(ProofBundleVerificationError, match="preterminal ledger"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)


def test_verifier_rejects_noncanonical_ledger_and_wrong_anchor_scope(tmp_path: Path) -> None:
    proof, anchor, _ = _fixture_bundle(tmp_path / "ledger")
    first_event = json.loads((proof / "execution_ledger.jsonl").read_text().splitlines()[0])
    noncanonical = (json.dumps(first_event) + "\n").encode()
    with pytest.raises(ProofBundleVerificationError, match="not canonical JSONL"):
        verification_module._parse_events(noncanonical)

    proof, anchor, _ = _fixture_bundle(tmp_path / "anchor")
    anchor_value = json.loads(anchor.read_text())
    anchor_value["ledger_scope"] = "other-iteration"
    _write_json(anchor, anchor_value)
    with pytest.raises(ProofBundleVerificationError, match="does not authorize"):
        verify_iter000_proof_bundle(proof, signer_anchor_path=anchor)

    link = tmp_path / "proof-link"
    link.symlink_to(proof, target_is_directory=True)
    with pytest.raises(ProofBundleVerificationError, match="proof root"):
        verify_iter000_proof_bundle(link, signer_anchor_path=anchor)
