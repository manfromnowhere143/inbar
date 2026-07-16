from __future__ import annotations

import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

import fieldtrue.experiment as experiment_module
import fieldtrue.runtime as runtime_module
from fieldtrue.canonical import canonical_json_pretty, sha256_file, sha256_value
from fieldtrue.experiment import (
    ExperimentAlreadyExecutedError,
    ExperimentPreflightError,
    _exclusive_run_lock,
    _load_attempt_001_authority_specification,
    _protocol_bundle,
    _run_iter000_locked,
    _verify_attempt_authority_consumption,
    _write_attempt_001_authority_consumption,
    run_iter000,
    run_iter000_amendment_001,
)
from fieldtrue.mission import MissionValidation, ValidationCheck
from fieldtrue.receipts import (
    load_or_create_signing_key,
    load_signer_anchor,
    verify_ledger,
    write_signer_anchor,
)
from fieldtrue.verification import ProofBundleVerificationError, verify_iter000_proof_bundle
from tests.helpers import create_adapt_source, legacy_runtime_identity, runtime_identity

_GIT = shutil.which("git")
if _GIT is None:
    raise RuntimeError("git executable is required for integration tests")

_OBSERVED_PROVENANCE = runtime_module._ObservedExecutionProvenance(
    python_interpreter_provenance_sha256="1" * 64,
    startup_provenance_sha256="2" * 64,
    environment_provenance_sha256="3" * 64,
    fieldtrue_source_sha256="4" * 64,
    loaded_module_closure_sha256="5" * 64,
    dependency_closure_sha256="6" * 64,
)


@pytest.fixture(autouse=True)
def _stub_execution_provenance(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runtime_module,
        "_observe_execution_provenance",
        lambda *_args, **_kwargs: _OBSERVED_PROVENANCE,
    )


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
    repo.mkdir(parents=True)
    _git(repo, "init", "-b", "main")
    (repo / ".gitignore").write_text(".local/\ndata/\n")
    (repo / "uv.lock").write_text("lock-version = 1\n")
    source_repo = Path(__file__).resolve().parents[2]
    source_authority = json.loads(
        (source_repo / "protocol" / "attempt_authorities" / "iter000_001.json").read_text()
    )
    fixture_overrides = {
        "experiments/iter000_nasa_adapt_corpus_readiness/HYPOTHESIS.md",
        "protocol/amendments/iter000_001.json",
        "protocol/datasets/nasa_adapt_v1.json",
        "protocol/trust/iter000_signer_anchor.json",
    }
    for relative_path in source_authority["protocol_hashes"]:
        if relative_path in fixture_overrides:
            continue
        target = repo / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((source_repo / relative_path).read_bytes())
    hypothesis = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "HYPOTHESIS.md"
    hypothesis.write_text("fixture preregistration\n")
    (hypothesis.parent / "AMENDMENT_001.md").write_bytes(
        (
            source_repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "AMENDMENT_001.md"
        ).read_bytes()
    )
    raw_root = repo / "data" / "raw" / "adapt-fixture"
    lock, _ = create_adapt_source(raw_root)
    lock_path = repo / "protocol" / "datasets" / "nasa_adapt_v1.json"
    lock_path.parent.mkdir(parents=True)
    lock_path.write_bytes(canonical_json_pretty(lock))
    amendment_path = repo / "protocol" / "amendments" / "iter000_001.json"
    amendment_path.parent.mkdir(parents=True)
    amendment_path.write_bytes(
        (source_repo / "protocol" / "amendments" / "iter000_001.json").read_bytes()
    )
    key = load_or_create_signing_key(repo / ".local" / "keys" / "iter000.ed25519")
    anchor_path = repo / "protocol" / "trust" / "iter000_signer_anchor.json"
    write_signer_anchor(
        anchor_path,
        key,
        anchor_id="iter000-execution-ledger",
        ledger_scope="iter000_nasa_adapt_corpus_readiness",
    )
    amendment = json.loads(amendment_path.read_text())
    amendment["amendment_document"]["sha256"] = sha256_file(hypothesis.parent / "AMENDMENT_001.md")
    amendment["frozen_inputs"]["hypothesis"]["sha256"] = sha256_file(hypothesis)
    amendment["frozen_inputs"]["dataset_lock"]["sha256"] = sha256_file(lock_path)
    amendment["trigger_attempt"]["artifacts"]["signer_anchor"]["sha256"] = sha256_file(anchor_path)
    amendment_path.write_bytes(canonical_json_pretty(amendment))
    authority_path = repo / "protocol" / "attempt_authorities" / "iter000_001.json"
    authority_path.parent.mkdir(parents=True)
    authority = source_authority
    authority["signer_anchor"]["signer_public_key"] = key.verify_key.encode().hex()
    authority["protocol_hashes"] = {
        relative_path: sha256_file(repo / relative_path)
        for relative_path in authority["protocol_hashes"]
    }
    authority_path.write_bytes(canonical_json_pretty(authority))
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
    authority_path = "protocol/attempt_authorities/iter000_001.json"
    authority = json.loads((repo / authority_path).read_text())
    paths = (
        *authority["protocol_hashes"],
        authority_path,
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
    proof = experiment_root / "proof" / "attempt_000"
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


def test_amendment_001_uses_a_distinct_single_attempt_proof_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)

    report = run_iter000_amendment_001(
        repo,
        command=("fieldtrue", "experiment", "iter000-amendment-001"),
    )
    proof = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof" / "attempt_001"
    receipt_path = (
        repo
        / "experiments"
        / "iter000_nasa_adapt_corpus_readiness"
        / "authority"
        / "attempt_001_consumption.json"
    )
    assert report.verdict == "BLOCKED_EVIDENCE"
    assert (proof / "AMENDMENT_001.md").is_file()
    assert (proof / "amendment_001.json").is_file()
    assert (proof / "attempt_authority.json").is_file()
    assert (proof / "attempt_authority_consumption.json").read_bytes() == receipt_path.read_bytes()
    anchor = load_signer_anchor(repo / "protocol" / "trust" / "iter000_signer_anchor.json")
    receipt = _verify_attempt_authority_consumption(
        receipt_path,
        expected_signer_public_key=anchor.signer_public_key,
    )
    assert receipt["attempt_id"] == "attempt_001"
    assert receipt["authority_specification"]["sha256"] == sha256_file(
        repo / "protocol" / "attempt_authorities" / "iter000_001.json"
    )
    started = json.loads((proof / "execution_ledger.jsonl").read_text().splitlines()[0])
    assert (
        started["payload"]["attempt_authority_consumption_receipt_hash"] == receipt["receipt_hash"]
    )
    with pytest.raises(
        ProofBundleVerificationError,
        match="requires a trusted authority specification",
    ):
        verify_iter000_proof_bundle(
            proof,
            signer_anchor_path=repo / "protocol" / "trust" / "iter000_signer_anchor.json",
        )
    assert (
        verify_iter000_proof_bundle(
            proof,
            signer_anchor_path=repo / "protocol" / "trust" / "iter000_signer_anchor.json",
            authority_specification_path=(
                repo / "protocol" / "attempt_authorities" / "iter000_001.json"
            ),
        ).verdict
        == report.verdict
    )
    shutil.rmtree(proof)
    with pytest.raises(ExperimentAlreadyExecutedError, match="authority is already consumed"):
        run_iter000_amendment_001(
            repo,
            command=("fieldtrue", "experiment", "iter000-amendment-001"),
        )


def test_amendment_001_rejects_a_preexisting_output_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)
    output_root = (
        repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof" / "attempt_001"
    )
    output_root.mkdir(parents=True)

    with pytest.raises(ExperimentAlreadyExecutedError, match="output root already exists"):
        run_iter000_amendment_001(
            repo,
            command=("fieldtrue", "experiment", "iter000-amendment-001"),
        )


def test_amendment_001_rejects_an_unregistered_command_before_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)

    with pytest.raises(ExperimentPreflightError, match="command is not authorized"):
        run_iter000_amendment_001(repo, command=("fieldtrue", "experiment", "iter000"))
    assert not (
        repo
        / "experiments"
        / "iter000_nasa_adapt_corpus_readiness"
        / "authority"
        / "attempt_001_consumption.json"
    ).exists()


def test_amendment_001_rejects_protocol_drift_before_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)
    (repo / "mission" / "contract.json").write_text("{}\n")

    with pytest.raises(ExperimentPreflightError, match="protocol hash mismatch"):
        run_iter000_amendment_001(
            repo,
            command=("fieldtrue", "experiment", "iter000-amendment-001"),
        )
    assert not (
        repo
        / "experiments"
        / "iter000_nasa_adapt_corpus_readiness"
        / "authority"
        / "attempt_001_consumption.json"
    ).exists()


@pytest.mark.parametrize("existing_kind", ["file", "directory", "symlink"])
def test_amendment_001_rejects_any_preexisting_authority_receipt_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing_kind: str,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)
    receipt_path = (
        repo
        / "experiments"
        / "iter000_nasa_adapt_corpus_readiness"
        / "authority"
        / "attempt_001_consumption.json"
    )
    receipt_path.parent.mkdir(parents=True)
    if existing_kind == "file":
        receipt_path.write_text("consumed\n")
    elif existing_kind == "directory":
        receipt_path.mkdir()
    else:
        receipt_path.symlink_to(repo / "missing-receipt-target")

    with pytest.raises(ExperimentAlreadyExecutedError, match="authority is already consumed"):
        run_iter000_amendment_001(
            repo,
            command=("fieldtrue", "experiment", "iter000-amendment-001"),
        )


def test_amendment_001_consumption_is_fail_closed_after_execution_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    monkeypatch.setattr("fieldtrue.mission.validate_mission", _pass_validation)
    monkeypatch.setattr(experiment_module, "_protocol_bundle", _fixture_protocol_bundle)
    monkeypatch.setattr(
        experiment_module,
        "fetch_adapt_dataset",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("fixture failure")),
    )

    with pytest.raises(RuntimeError, match="fixture failure"):
        run_iter000_amendment_001(
            repo,
            command=("fieldtrue", "experiment", "iter000-amendment-001"),
        )
    receipt_path = (
        repo
        / "experiments"
        / "iter000_nasa_adapt_corpus_readiness"
        / "authority"
        / "attempt_001_consumption.json"
    )
    proof = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof" / "attempt_001"
    assert receipt_path.is_file()
    assert _ledger_event_types(proof) == ["run-started", "run-failed"]
    shutil.rmtree(proof)
    with pytest.raises(ExperimentAlreadyExecutedError, match="authority is already consumed"):
        run_iter000_amendment_001(
            repo,
            command=("fieldtrue", "experiment", "iter000-amendment-001"),
        )


def test_attempt_authority_loader_rejects_malformed_or_unbound_surfaces(tmp_path: Path) -> None:
    repo = _experiment_repo(tmp_path)
    authority_path, loaded = _load_attempt_001_authority_specification(repo)
    original = authority_path.read_bytes()
    assert loaded["attempt_id"] == "attempt_001"

    malformed_documents = (
        (b"{", "specification is invalid"),
        (canonical_json_pretty([]), "must be an object"),
    )
    for data, message in malformed_documents:
        authority_path.write_bytes(data)
        with pytest.raises(ExperimentPreflightError, match=message):
            _load_attempt_001_authority_specification(repo)

    mutations = (
        (("protocol_hashes",), [], "bindings are invalid"),
        (("authority_id",), "iter000_002", "executable contract"),
        (("signer_anchor", "signer_public_key"), "short", "signer key is malformed"),
    )
    authority = json.loads(original)
    for keys, replacement, message in mutations:
        candidate = deepcopy(authority)
        target = candidate
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = replacement
        authority_path.write_bytes(canonical_json_pretty(candidate))
        with pytest.raises(ExperimentPreflightError, match=message):
            _load_attempt_001_authority_specification(repo)

    candidate = deepcopy(authority)
    candidate["protocol_hashes"].pop("src/fieldtrue/splits.py")
    authority_path.write_bytes(canonical_json_pretty(candidate))
    with pytest.raises(ExperimentPreflightError, match="hash surface is incomplete"):
        _load_attempt_001_authority_specification(repo)

    authority_path.write_bytes(original)
    bound_path = repo / "mission" / "name.json"
    bound_bytes = bound_path.read_bytes()
    bound_path.unlink()
    with pytest.raises(ExperimentPreflightError, match="protocol file is unavailable"):
        _load_attempt_001_authority_specification(repo)
    bound_path.write_bytes(bound_bytes + b"\n")
    with pytest.raises(ExperimentPreflightError, match="protocol hash mismatch"):
        _load_attempt_001_authority_specification(repo)
    bound_path.write_bytes(bound_bytes)

    authority_path.unlink()
    authority_path.symlink_to(repo / "missing-authority.json")
    with pytest.raises(ExperimentPreflightError, match="committed regular file"):
        _load_attempt_001_authority_specification(repo)


def test_attempt_authority_consumption_refuses_legacy_runtime(tmp_path: Path) -> None:
    with pytest.raises(ExperimentPreflightError, match="requires observed-v1"):
        _write_attempt_001_authority_consumption(
            tmp_path,
            run_id="iter000-attempt_001-legacy",
            runtime=legacy_runtime_identity(),
            signing_key=load_or_create_signing_key(tmp_path / "key"),
            signer_public_key="0" * 64,
            authority_specification_path=tmp_path / "authority.json",
            authority_specification={},
        )


def test_attempt_authority_receipt_verifier_rejects_counterfeits(tmp_path: Path) -> None:
    repo = _experiment_repo(tmp_path)
    authority_path, authority = _load_attempt_001_authority_specification(repo)
    key = load_or_create_signing_key(repo / ".local" / "keys" / "iter000.ed25519")
    anchor = load_signer_anchor(repo / "protocol" / "trust" / "iter000_signer_anchor.json")
    runtime = runtime_identity().model_copy(
        update={"command": ("fieldtrue", "experiment", "iter000-amendment-001")}
    )
    receipt_path, receipt_hash = _write_attempt_001_authority_consumption(
        repo,
        run_id=f"iter000-attempt_001-{runtime.git_commit[:12]}",
        runtime=runtime,
        signing_key=key,
        signer_public_key=anchor.signer_public_key,
        authority_specification_path=authority_path,
        authority_specification=authority,
    )
    original = json.loads(receipt_path.read_text())
    assert (
        _verify_attempt_authority_consumption(
            receipt_path,
            expected_signer_public_key=anchor.signer_public_key,
        )["receipt_hash"]
        == receipt_hash
    )
    receipt_path.chmod(0o600)

    receipt_path.write_text("{")
    with pytest.raises(ExperimentPreflightError, match="receipt is invalid"):
        _verify_attempt_authority_consumption(
            receipt_path,
            expected_signer_public_key=anchor.signer_public_key,
        )
    receipt_path.write_bytes(canonical_json_pretty([]))
    with pytest.raises(ExperimentPreflightError, match="must be an object"):
        _verify_attempt_authority_consumption(
            receipt_path,
            expected_signer_public_key=anchor.signer_public_key,
        )

    counterfeits = (
        ({**original, "receipt_hash": "0" * 64}, "receipt hash mismatch"),
        ({**original, "signature": None}, "signature is missing"),
        ({**original, "signature": "not-hex"}, "signature mismatch"),
    )
    for candidate, message in counterfeits:
        receipt_path.write_bytes(canonical_json_pretty(candidate))
        with pytest.raises(ExperimentPreflightError, match=message):
            _verify_attempt_authority_consumption(
                receipt_path,
                expected_signer_public_key=anchor.signer_public_key,
            )

    candidate = deepcopy(original)
    candidate["signer_public_key"] = "a" * 64
    body = experiment_module._authority_receipt_body(candidate)
    candidate_hash = sha256_value(body)
    candidate["receipt_hash"] = candidate_hash
    candidate["signature"] = key.sign(bytes.fromhex(candidate_hash)).signature.hex()
    receipt_path.write_bytes(canonical_json_pretty(candidate))
    with pytest.raises(ExperimentPreflightError, match="receipt signer mismatch"):
        _verify_attempt_authority_consumption(
            receipt_path,
            expected_signer_public_key=anchor.signer_public_key,
        )

    receipt_path.unlink()
    receipt_path.symlink_to(repo / "missing-receipt.json")
    with pytest.raises(ExperimentPreflightError, match="regular file"):
        _verify_attempt_authority_consumption(
            receipt_path,
            expected_signer_public_key=anchor.signer_public_key,
        )


def test_attempt_authority_consumption_loses_races_and_self_verifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    race_repo = _experiment_repo(tmp_path / "race")
    authority_path, authority = _load_attempt_001_authority_specification(race_repo)
    key = load_or_create_signing_key(race_repo / ".local" / "keys" / "iter000.ed25519")
    anchor = load_signer_anchor(race_repo / "protocol" / "trust" / "iter000_signer_anchor.json")
    runtime = runtime_identity()
    receipt_path = (
        race_repo
        / "experiments"
        / "iter000_nasa_adapt_corpus_readiness"
        / "authority"
        / "attempt_001_consumption.json"
    )
    real_open = experiment_module.os.open

    def lose_exclusive_create(
        path: Any,
        flags: int,
        *arguments: Any,
        **keywords: Any,
    ) -> int:
        if (
            flags & experiment_module.os.O_EXCL
            and path == receipt_path.name
            and keywords.get("dir_fd") is not None
        ):
            raise FileExistsError
        return real_open(path, flags, *arguments, **keywords)

    monkeypatch.setattr(experiment_module.os, "open", lose_exclusive_create)
    with pytest.raises(ExperimentAlreadyExecutedError, match="already consumed"):
        _write_attempt_001_authority_consumption(
            race_repo,
            run_id="iter000-attempt_001-race",
            runtime=runtime,
            signing_key=key,
            signer_public_key=anchor.signer_public_key,
            authority_specification_path=authority_path,
            authority_specification=authority,
        )

    monkeypatch.setattr(experiment_module.os, "open", real_open)
    verify_repo = _experiment_repo(tmp_path / "self-check")
    verify_authority, verify_specification = _load_attempt_001_authority_specification(verify_repo)
    verify_key = load_or_create_signing_key(verify_repo / ".local" / "keys" / "iter000.ed25519")
    verify_anchor = load_signer_anchor(
        verify_repo / "protocol" / "trust" / "iter000_signer_anchor.json"
    )
    monkeypatch.setattr(
        experiment_module,
        "_verify_attempt_authority_consumption",
        lambda *_args, **_kwargs: {"receipt_hash": "0" * 64},
    )
    with pytest.raises(ExperimentPreflightError, match="self-verification failed"):
        _write_attempt_001_authority_consumption(
            verify_repo,
            run_id="iter000-attempt_001-self-check",
            runtime=runtime,
            signing_key=verify_key,
            signer_public_key=verify_anchor.signer_public_key,
            authority_specification_path=verify_authority,
            authority_specification=verify_specification,
        )


def test_attempt_authority_consumption_rejects_a_linked_parent_directory(
    tmp_path: Path,
) -> None:
    repo = _experiment_repo(tmp_path)
    authority_path, authority = _load_attempt_001_authority_specification(repo)
    key = load_or_create_signing_key(repo / ".local" / "keys" / "iter000.ed25519")
    anchor = load_signer_anchor(repo / "protocol" / "trust" / "iter000_signer_anchor.json")
    redirected_directory = repo / "redirected-authority"
    redirected_directory.mkdir()
    authority_directory = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "authority"
    authority_directory.symlink_to(redirected_directory, target_is_directory=True)

    with pytest.raises(ExperimentPreflightError, match="directory must not be linked"):
        _write_attempt_001_authority_consumption(
            repo,
            run_id="iter000-attempt_001-linked-parent",
            runtime=runtime_identity(),
            signing_key=key,
            signer_public_key=anchor.signer_public_key,
            authority_specification_path=authority_path,
            authority_specification=authority,
        )
    assert not (redirected_directory / "attempt_001_consumption.json").exists()


def test_locked_runner_rejects_unknown_attempt_and_failed_mission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _experiment_repo(tmp_path)
    with pytest.raises(ExperimentPreflightError, match="attempt ID is not authorized"):
        _run_iter000_locked(repo, command=("fieldtrue", "experiment"), attempt_id="attempt_002")

    failed = MissionValidation(
        passed=False,
        checks=(ValidationCheck(check_id="scientific-surface", passed=False, detail="failed"),),
    )
    monkeypatch.setattr("fieldtrue.mission.validate_mission", lambda _repo: failed)
    with pytest.raises(ExperimentPreflightError, match="scientific-surface"):
        _run_iter000_locked(
            repo,
            command=("fieldtrue", "experiment", "iter000"),
            attempt_id="attempt_000",
        )


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
    proof = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof" / "attempt_000"
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
    proof = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof" / "attempt_000"
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
    proof = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof" / "attempt_000"
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
        / "attempt_000"
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
    authority_path = "protocol/attempt_authorities/iter000_001.json"
    authority = json.loads((repo / authority_path).read_text())
    assert bundle["schema_version"] == "fieldtrue.protocol-bundle.v1"
    assert len(str(bundle["bundle_sha256"])) == 64
    assert set(bundle["files"]) == {*authority["protocol_hashes"], authority_path}
