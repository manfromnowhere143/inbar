from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import fieldtrue.experiment as experiment_module
from fieldtrue.canonical import canonical_json_pretty, sha256_file, sha256_value
from fieldtrue.experiment import (
    ExperimentAlreadyExecutedError,
    ExperimentPreflightError,
    _exclusive_run_lock,
    _protocol_bundle,
    run_iter000,
)
from fieldtrue.mission import MissionValidation, ValidationCheck
from fieldtrue.receipts import (
    load_or_create_signing_key,
    load_signer_anchor,
    verify_ledger,
    write_signer_anchor,
)
from fieldtrue.verification import verify_iter000_proof_bundle
from tests.helpers import create_adapt_source

_GIT = shutil.which("git")
if _GIT is None:
    raise RuntimeError("git executable is required for integration tests")


def _git(repo: Path, *arguments: str) -> None:
    subprocess.run(  # noqa: S603 - executable is resolved once from the test environment
        [_GIT, *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def _experiment_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "mission"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    (repo / ".gitignore").write_text(".local/\ndata/\n")
    (repo / "uv.lock").write_text("lock-version = 1\n")
    hypothesis = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "HYPOTHESIS.md"
    hypothesis.parent.mkdir(parents=True)
    hypothesis.write_text("fixture preregistration\n")
    raw_root = repo / "data" / "raw" / "adapt-fixture"
    lock, _ = create_adapt_source(raw_root)
    lock_path = repo / "protocol" / "datasets" / "nasa_adapt_v1.json"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_bytes(canonical_json_pretty(lock))
    key = load_or_create_signing_key(repo / ".local" / "keys" / "iter000.ed25519")
    write_signer_anchor(
        repo / "protocol" / "trust" / "iter000_signer_anchor.json",
        key,
        anchor_id="iter000-execution-ledger",
        ledger_scope="iter000_nasa_adapt_corpus_readiness",
    )
    _git(repo, "add", ".")
    _git(
        repo,
        "-c",
        "user.name=Mission Test",
        "-c",
        "user.email=mission@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    return repo


def _pass_validation(_repo: Path) -> MissionValidation:
    return MissionValidation(passed=True, checks=())


def _fixture_protocol_bundle(repo: Path) -> dict[str, object]:
    paths = (
        "experiments/iter000_nasa_adapt_corpus_readiness/HYPOTHESIS.md",
        "protocol/datasets/nasa_adapt_v1.json",
        "protocol/trust/iter000_signer_anchor.json",
    )
    hashes = {path: sha256_file(repo / path) for path in paths}
    return {
        "schema_version": "fieldtrue.protocol-bundle.v1",
        "files": hashes,
        "bundle_sha256": sha256_value(hashes),
    }


def _ledger_event_types(proof_root: Path) -> list[str]:
    lines = (proof_root / "execution_ledger.jsonl").read_text().splitlines()
    return [json.loads(line)["event_type"] for line in lines]


def test_iter000_runs_once_and_produces_a_pinned_verifiable_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)
    monkeypatch.setattr(
        experiment_module,
        "_protocol_bundle",
        _fixture_protocol_bundle,
    )
    report = run_iter000(repo, command=("fieldtrue", "experiment", "iter000"))
    assert report.verdict == "BLOCKED_EVIDENCE"
    experiment_root = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness"
    proof = experiment_root / "proof"
    assert not (experiment_root / "RESULT.md").exists()
    assert not (experiment_root / "LEARNING.json").exists()
    assert (proof / "RESULT.md").is_file()
    assert (proof / "LEARNING.json").is_file()
    assert (proof / "artifact_bundle.json").is_file()
    assert (proof / "dataset_lock.json").is_file()
    assert (proof / "model_evidence_manifest.jsonl").is_file()
    assert (proof / "truth_manifest.jsonl").is_file()
    manifest = json.loads((proof / "run_manifest.json").read_text())
    assert manifest["verdict"] == report.verdict
    anchor = load_signer_anchor(repo / "protocol" / "trust" / "iter000_signer_anchor.json")
    verification = verify_ledger(
        proof / "execution_ledger.jsonl",
        proof / "execution_ledger.head.json",
        expected_signer_public_key=anchor.signer_public_key,
    )
    assert verification.event_count == 5
    proof_verification = verify_iter000_proof_bundle(
        proof,
        signer_anchor_path=(repo / "protocol" / "trust" / "iter000_signer_anchor.json"),
    )
    assert proof_verification.verdict == report.verdict
    with pytest.raises(ExperimentAlreadyExecutedError):
        run_iter000(repo, command=("fieldtrue", "experiment", "iter000"))


def test_iter000_records_infrastructure_failure_without_false_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)
    monkeypatch.setattr(
        experiment_module,
        "_protocol_bundle",
        _fixture_protocol_bundle,
    )
    monkeypatch.setattr(
        experiment_module,
        "fetch_adapt_dataset",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("fixture failure")),
    )
    with pytest.raises(RuntimeError, match="fixture failure"):
        run_iter000(repo, command=("fieldtrue", "experiment", "iter000"))
    proof = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof"
    assert _ledger_event_types(proof) == ["run-started", "run-failed"]


def test_source_integrity_failure_produces_full_weight_invalid_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)
    monkeypatch.setattr(
        experiment_module,
        "_protocol_bundle",
        _fixture_protocol_bundle,
    )
    monkeypatch.setattr(
        experiment_module,
        "fetch_adapt_dataset",
        lambda *_args: (_ for _ in ()).throw(ValueError("integrity mismatch")),
    )

    report = run_iter000(repo, command=("fieldtrue", "experiment", "iter000"))
    proof = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof"
    assert report.verdict == "INVALID"
    assert report.gates[0].status.value == "invalid"
    assert {gate.status.value for gate in report.gates[1:]} == {"not_run"}
    assert _ledger_event_types(proof) == [
        "run-started",
        "source-invalid",
        "readiness-adjudicated",
        "run-completed",
    ]
    assert (proof / "invalidity.json").is_file()
    assert (proof / "RESULT.md").is_file()
    assert not (proof.parent / "RESULT.md").exists()
    proof_verification = verify_iter000_proof_bundle(
        proof,
        signer_anchor_path=(repo / "protocol" / "trust" / "iter000_signer_anchor.json"),
    )
    assert proof_verification.verdict == report.verdict


def test_parser_failure_preserves_source_pass_and_produces_invalid_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)
    monkeypatch.setattr(
        experiment_module,
        "_protocol_bundle",
        _fixture_protocol_bundle,
    )
    monkeypatch.setattr(
        experiment_module,
        "ingest_adapt_dataset",
        lambda *_args: (_ for _ in ()).throw(ValueError("unknown row types")),
    )

    report = run_iter000(repo, command=("fieldtrue", "experiment", "iter000"))
    proof = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof"
    assert report.verdict == "INVALID"
    assert report.gates[0].status.value == "pass"
    assert report.gates[1].status.value == "invalid"
    assert {gate.status.value for gate in report.gates[2:]} == {"not_run"}
    assert _ledger_event_types(proof) == [
        "run-started",
        "sources-verified",
        "ingestion-invalid",
        "readiness-adjudicated",
        "run-completed",
    ]
    proof_verification = verify_iter000_proof_bundle(
        proof,
        signer_anchor_path=(repo / "protocol" / "trust" / "iter000_signer_anchor.json"),
    )
    assert proof_verification.verdict == report.verdict


def test_iter000_preflight_and_run_lock_fail_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    failed = MissionValidation(
        passed=False,
        checks=(ValidationCheck(check_id="schemas", passed=False, detail="missing"),),
    )
    monkeypatch.setattr("fieldtrue.mission.validate_mission", lambda _repo: failed)
    with pytest.raises(ExperimentPreflightError, match="schemas"):
        run_iter000(repo, command=("run",))
    assert not (
        repo
        / "experiments"
        / "iter000_nasa_adapt_corpus_readiness"
        / "proof"
        / "execution_ledger.jsonl"
    ).exists()

    lock_path = tmp_path / "exclusive.lock"
    with (
        _exclusive_run_lock(lock_path),
        pytest.raises(ExperimentPreflightError, match="already running"),
        _exclusive_run_lock(lock_path),
    ):
        pass


def test_protocol_bundle_hashes_frozen_inputs() -> None:
    repo = Path(__file__).resolve().parents[2]
    bundle = _protocol_bundle(repo)
    assert bundle["schema_version"] == "fieldtrue.protocol-bundle.v1"
    assert len(str(bundle["bundle_sha256"])) == 64
    assert "PREREGISTRATION.md" in bundle["files"]
