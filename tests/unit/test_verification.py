from __future__ import annotations

import json
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Literal

import pytest
from nacl.signing import SigningKey

import fieldtrue.verification as verification_module
from fieldtrue.adapters.adapt import ingest_adapt_dataset
from fieldtrue.canonical import (
    canonical_json_pretty,
    sha256_file,
    sha256_value,
)
from fieldtrue.domain import GateResult, GateStatus, ReadinessReport
from fieldtrue.readiness import (
    audit_adapt_readiness,
    invalid_readiness_report,
    render_readiness_result,
)
from fieldtrue.receipts import SignedLedger, verify_ledger, write_signer_anchor
from fieldtrue.verification import (
    ProofBundleVerificationError,
    render_iter000_result_from_proof,
    verify_iter000_proof_bundle,
)
from tests.helpers import create_adapt_source, runtime_identity

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
    manifest_overrides: dict[str, object] | None = None,
    terminal_overrides: dict[str, object] | None = None,
    report_override: ReadinessReport | None = None,
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
    raw_root = tmp_path / "source"
    lock, resource_receipts = create_adapt_source(raw_root)
    _write_json(proof / "dataset_lock.json", lock)
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
        "protocol/trust/iter000_signer_anchor.json": sha256_file(anchor_path),
        "protocol/datasets/nasa_adapt_v1.json": dataset_lock_hash,
    }
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
        receipt = ingestion.receipt
        (proof / "model_evidence_manifest.jsonl").write_bytes(
            ingestion.evidence_manifest_path.read_bytes()
        )
        (proof / "truth_manifest.jsonl").write_bytes(ingestion.truth_manifest_path.read_bytes())
        (proof / "coverage.json").write_bytes(ingestion.coverage_path.read_bytes())
        (proof / "ingestion_receipt.json").write_bytes(ingestion.receipt_path.read_bytes())
        ledger.append(
            run_id=run_id,
            event_type="dataset-ingested",
            payload={
                "ingestion_receipt_hash": sha256_file(proof / "ingestion_receipt.json"),
                "coverage_hash": sha256_file(proof / "coverage.json"),
                "model_evidence_manifest_hash": sha256_file(
                    proof / "model_evidence_manifest.jsonl"
                ),
                "evidence_manifest_hash": receipt.evidence_manifest_sha256,
                "truth_manifest_hash": receipt.truth_manifest_sha256,
                "truth_separation_passed": receipt.truth_separation_passed,
            },
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
    (proof / "RESULT.md").write_text(render_readiness_result(report))
    _write_json(proof / "LEARNING.json", _iteration_learning(report))
    ledger.append(
        run_id=run_id,
        event_type="readiness-adjudicated",
        payload={
            "verdict": report.verdict,
            "readiness_report_hash": sha256_file(proof / "readiness_report.json"),
            "result_hash": sha256_file(proof / "RESULT.md"),
            "learning_hash": sha256_file(proof / "LEARNING.json"),
            "gate_statuses": {gate.gate_id: gate.status.value for gate in report.gates},
        },
        runtime=runtime,
    )

    artifact_paths = {
        "dataset_lock.json": proof / "dataset_lock.json",
        **evidence_paths,
        "readiness_report.json": proof / "readiness_report.json",
        "RESULT.md": proof / "RESULT.md",
        "LEARNING.json": proof / "LEARNING.json",
    }
    artifact_hashes = {name: sha256_file(path) for name, path in sorted(artifact_paths.items())}
    artifact_bundle_body = {
        "schema_version": "fieldtrue.artifact-bundle.v1",
        "run_id": run_id,
        "artifacts": artifact_hashes,
    }
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
    protocol_files = verification_module._verify_started(events[0], anchor.read_bytes())
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
    protocol_files = verification_module._verify_started(events["run-started"], anchor.read_bytes())
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
