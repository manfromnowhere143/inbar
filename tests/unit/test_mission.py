from __future__ import annotations

import io
import json
import shutil
import ssl
import stat
import subprocess
import tomllib
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

import fieldtrue.mission as mission_module
import fieldtrue.verification as verification_module
from fieldtrue.canonical import canonical_json, canonical_json_pretty, sha256_bytes, sha256_value
from fieldtrue.domain import ClaimRecord
from fieldtrue.memory import (
    AccessClass,
    EpistemicPhase,
    LabelAccess,
    MemoryActor,
    MemoryEventType,
    MemoryEvidenceRef,
    MemoryStatus,
    append_memory,
)
from fieldtrue.mission import (
    _adapt_tls_source_is_verified,
    _certifi_dependency_is_locked,
    _claim_registry_valid,
    _claims,
    _control_node_is_substantive,
    _expected_credibility_gate_control_registry,
    _first_commit_files,
    _gate_control_runner_is_unchanged,
    _gate_control_set_hash,
    _gate_controls_valid,
    _json,
    _materialize_gate_control_snapshot,
    _prepare_gate_control_runner,
    _pytest_node_exists,
    _root_preregistration_bytes,
    _verified_tls_runtime_active,
    _verify_credibility_gate_control_registry,
    _verify_gate_control_registry,
    _verify_iteration_amendment_001,
    _verify_memory_git_anchors,
    _verify_publication_transition,
    validate_mission,
)
from fieldtrue.receipts import (
    LedgerVerificationError,
    write_publication_signer_anchor,
    write_signer_anchor,
)


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _git(repo: Path, *arguments: str) -> str:
    git = shutil.which("git")
    assert git is not None
    return subprocess.run(  # noqa: S603 - tests supply fixed Git arguments
        [git, *arguments],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _fixture_git_repo(tmp_path: Path) -> tuple[Path, str, str, bytes]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Inbar Test")
    _git(repo, "config", "user.email", "inbar@example.invalid")
    evidence = b"historically anchored evidence\n"
    evidence_path = repo / "evidence" / "source.txt"
    evidence_path.parent.mkdir()
    evidence_path.write_bytes(evidence)
    _git(repo, "add", "evidence/source.txt")
    _git(repo, "commit", "--quiet", "-m", "anchor fixture evidence")
    commit = _git(repo, "rev-parse", "HEAD")
    blob = _git(repo, "rev-parse", "HEAD:evidence/source.txt")
    return repo, commit, blob, evidence


def _write_memory(
    repo: Path,
    *,
    source_commit: str,
    evidence: tuple[MemoryEvidenceRef, ...] = (),
) -> Path:
    memory_path = repo / "memory" / "research_engine_extraction.jsonl"
    append_memory(
        memory_path,
        event_id="git-anchor-fixture",
        stage="fixture",
        epistemic_phase=EpistemicPhase.PROSPECTIVE,
        actor=MemoryActor(kind="agent", actor_id="mission-test"),
        event_type=MemoryEventType.SOURCE,
        status=MemoryStatus.RECORDED,
        summary="Exercise repository-level Git anchoring",
        payload={"source": "fixture"},
        source_commit=source_commit,
        evidence=evidence,
    )
    return memory_path


def _committed_amendment_repo(tmp_path: Path) -> Path:
    source = _repo()
    repo = tmp_path / "amendment-repo"
    _git(source, "clone", "--quiet", "--no-hardlinks", source.as_posix(), repo.as_posix())
    _git(repo, "config", "user.name", "Amendment Test")
    _git(repo, "config", "user.email", "amendment@example.invalid")
    _git(
        repo,
        "checkout",
        "--quiet",
        "--detach",
        mission_module._ITER000_ATTEMPT_001_EXECUTION_COMMIT,
    )
    return repo


def _historical_attempt_repo(tmp_path: Path) -> Path:
    source = _repo()
    repo = tmp_path / "historical-attempt-repo"
    _git(source, "clone", "--quiet", "--no-hardlinks", source.as_posix(), repo.as_posix())
    _git(repo, "config", "user.name", "Historical Test")
    _git(repo, "config", "user.email", "historical@example.invalid")
    return repo


def _claim_contract_repo(
    tmp_path: Path,
) -> tuple[Path, dict[str, str], dict[str, str], str]:
    repo = tmp_path / "claim-contract-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Claim Contract Test")
    _git(repo, "config", "user.email", "claims@example.invalid")
    evidence_path = repo / "evidence" / "source.json"
    evidence_path.parent.mkdir()
    evidence_path.write_bytes(b'{"verdict":"blocked"}\n')
    common = {
        "wording": "Fixture claim.",
        "scope": "Fixture scope.",
        "evidence_refs": ("evidence/source.json",),
        "permitted_wording": "fixture",
        "forbidden_wording": "wider claim",
        "next_falsifier": "Fixture falsifier.",
    }
    claims = (
        ClaimRecord(
            claim_id="scope.integrated-loop.v1",
            status="corrected",
            **common,
        ),
        ClaimRecord(
            claim_id="scope.integrated-loop.v2",
            status="untested",
            supersedes_claim_id="scope.integrated-loop.v1",
            **common,
        ),
    )
    registry = repo / "claims" / "registry.jsonl"
    registry.parent.mkdir()
    registry.write_bytes(
        b"\n".join(
            canonical_json(claim.model_dump(mode="json", exclude_none=True)) for claim in claims
        )
        + b"\n"
    )
    _git(repo, "add", "claims/registry.jsonl", "evidence/source.json")
    _git(repo, "commit", "--quiet", "-m", "freeze claim contracts")
    digests = {
        claim.claim_id: sha256_value(claim.model_dump(mode="json", exclude_none=True))
        for claim in claims
    }
    evidence_digests = {"evidence/source.json": sha256_bytes(evidence_path.read_bytes())}
    return repo, digests, evidence_digests, sha256_bytes(registry.read_bytes())


def _install_claim_contract(
    monkeypatch: pytest.MonkeyPatch,
    claim_digests: dict[str, str],
    evidence_digests: dict[str, str],
    registry_digest: str,
) -> None:
    monkeypatch.setattr(mission_module, "_REQUIRED_BOOTSTRAP_CLAIM_DIGESTS", claim_digests)
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_EVIDENCE_DIGESTS",
        evidence_digests,
    )
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_REGISTRY_SHA256",
        registry_digest,
    )
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_CLAIM_STATUSES",
        {
            "scope.integrated-loop.v1": mission_module.ClaimStatus.CORRECTED,
            "scope.integrated-loop.v2": mission_module.ClaimStatus.UNTESTED,
        },
    )


def _credibility_control_repo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    repo = tmp_path / "credibility-control-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Credibility Control Test")
    _git(repo, "config", "user.email", "credibility@example.invalid")
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_CLAIM_DIGESTS",
        {claim.claim_id: "0" * 64 for claim in _claims(_repo() / "claims" / "registry.jsonl")},
    )
    registry = _expected_credibility_gate_control_registry()
    nodes_by_path: dict[str, set[str]] = {}
    for control in registry["controls"]:
        for role in ("positive_control", "negative_control", "placebo_control"):
            relative, function_name = control[role].split("::")
            nodes_by_path.setdefault(relative, set()).add(function_name)
    for relative, function_names in nodes_by_path.items():
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n\n".join(
                f"def {function_name}():\n    assert True"
                for function_name in sorted(function_names)
            )
            + "\n",
            encoding="utf-8",
        )
    registry_path = repo / mission_module._CREDIBILITY_GATE_CONTROL_PATH
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_bytes(canonical_json_pretty(registry))
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", "freeze credibility controls")
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_EVIDENCE_DIGESTS",
        {relative: sha256_bytes((repo / relative).read_bytes()) for relative in nodes_by_path},
    )
    return repo


def test_mission_check_assembly_reports_invariants_individually(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo()
    # Dedicated tests and the frozen mission-validation command execute these expensive
    # verifiers. This test isolates check assembly, identifiers, and aggregate status.
    monkeypatch.setattr(
        mission_module,
        "_verify_gate_control_registry",
        lambda *_args: (True, "Historical gate controls verified."),
    )
    monkeypatch.setattr(
        mission_module,
        "_verify_credibility_gate_control_registry",
        lambda *_args: (True, "Current credibility controls verified."),
    )
    monkeypatch.setattr(
        mission_module,
        "_verify_iteration_amendment_001",
        lambda *_args: (True, "Historical amendment verified."),
    )
    monkeypatch.setattr(
        verification_module,
        "validate_iter000_verification_correction_surface",
        lambda *_args: (True, "Historical correction verified."),
    )
    monkeypatch.setattr(
        mission_module,
        "_claim_registry_valid",
        lambda *_args: (True, "Claim registry verified."),
    )
    monkeypatch.setattr(
        mission_module,
        "_verify_memory_git_anchors",
        lambda *_args: (True, "Memory Git anchors verified."),
    )

    validation = validate_mission(repo)
    checks = {check.check_id: check for check in validation.checks}
    assert tuple(checks) == (
        "owner-boundary",
        "active-identity",
        "execution-authority",
        "mission-stage",
        "research-engine-deferred",
        "publication-gates",
        "publication-transition-evidence",
        "gate-falsification",
        "gate-control-registry",
        "preregistration-first",
        "hypothesis-status",
        "iter001-acquisition-contract",
        "dataset-lock",
        "iteration-amendment-001",
        "verification-correction-001",
        "claim-registry",
        "research-memory",
        "research-memory-git-anchors",
        "signer-anchor",
        "schemas",
        "lockfile",
        "provider-independence",
    )
    assert checks["owner-boundary"].passed
    assert checks["active-identity"].passed
    assert checks["execution-authority"].passed
    assert checks["preregistration-first"].passed
    assert checks["hypothesis-status"].passed
    assert checks["dataset-lock"].passed
    assert checks["claim-registry"].passed
    assert checks["gate-falsification"].passed
    assert checks["gate-control-registry"].passed
    assert checks["iteration-amendment-001"].passed
    assert checks["verification-correction-001"].passed
    assert checks["research-memory-git-anchors"].passed
    assert checks["signer-anchor"].passed
    assert checks["provider-independence"].passed
    assert validation.passed == all(check.passed for check in validation.checks)


def test_historical_attempt_validation_is_outcome_blind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    protected = {
        "LEARNING.json",
        "RESULT.md",
        "artifact_bundle.json",
        "coverage.json",
        "ingestion_receipt.json",
        "model_evidence_manifest.jsonl",
        "readiness_report.json",
        "run_manifest.json",
        "truth_manifest.jsonl",
    }
    original_read_bytes = Path.read_bytes

    def guarded_read_bytes(path: Path) -> bytes:
        if path.name in protected and "proof/attempt_001" in path.as_posix():
            raise AssertionError(f"outcome artifact was read: {path.name}")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", guarded_read_bytes)
    monkeypatch.setattr(mission_module, "_verified_tls_runtime_active", lambda: False)
    monkeypatch.setattr(mission_module, "_certifi_dependency_is_locked", lambda _repo: False)

    passed, detail = _verify_iteration_amendment_001(_repo())

    assert passed
    assert "Historical attempt 001 execution" in detail


def test_historical_attempt_rejects_proof_mutation_and_git_replacement(tmp_path: Path) -> None:
    repo = _historical_attempt_repo(tmp_path)
    result = (
        repo
        / "experiments"
        / "iter000_nasa_adapt_corpus_readiness"
        / "proof"
        / "attempt_001"
        / "RESULT.md"
    )
    original = result.read_bytes()
    result.write_bytes(original + b"tamper\n")
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "proof or consumed authority has uncommitted changes" in detail
    result.write_bytes(original)

    _git(
        repo,
        "replace",
        mission_module._ITER000_ATTEMPT_001_EXECUTION_COMMIT,
        mission_module._ITER000_PROOF_COMMIT,
    )
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "replacement objects" in detail


def test_amendment_001_authorizes_only_the_committed_predata_failure(
    tmp_path: Path,
) -> None:
    repo = _committed_amendment_repo(tmp_path)
    assert _git(repo, "rev-parse", "HEAD") == (mission_module._ITER000_ATTEMPT_001_EXECUTION_COMMIT)
    for relative, (
        _,
        authorized_hash,
    ) in mission_module._ITER000_ATTEMPT_001_AUTHORIZED_SOURCE_HASHES.items():
        assert sha256_bytes((repo / relative).read_bytes()) == authorized_hash

    passed, detail = _verify_iteration_amendment_001(repo)

    assert passed
    assert "one isolated certifi-backed retry" in detail


def test_historical_correction_separates_current_source_from_committed_trust_inputs(
    tmp_path: Path,
) -> None:
    repo = _historical_attempt_repo(tmp_path)
    for relative in (
        "src/fieldtrue/adapters/adapt.py",
        "src/fieldtrue/experiment.py",
        "src/fieldtrue/verification.py",
    ):
        path = repo / relative
        path.write_bytes(path.read_bytes() + b"\n# future iteration implementation\n")

    passed, detail = _verify_iteration_amendment_001(repo)

    assert passed
    assert "exact Git objects" in detail

    correction_path = repo / mission_module._ITER000_VERIFICATION_CONTRACT_PATH
    correction_bytes = correction_path.read_bytes()
    correction_path.write_bytes(correction_bytes + b"\n")
    _git(repo, "add", correction_path.relative_to(repo).as_posix())
    _git(repo, "commit", "--quiet", "-m", "replace current correction trust input")
    correction_path.write_bytes(correction_bytes)
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "correction trust input is not committed at HEAD" in detail


def test_historical_correction_requires_retained_exact_correction_authority(
    tmp_path: Path,
) -> None:
    repo = _historical_attempt_repo(tmp_path)
    correction_path = repo / mission_module._ITER000_VERIFICATION_CORRECTION_PATH
    original = correction_path.read_bytes()

    correction_path.write_bytes(original + b"\n")
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "correction trust input differs" in detail

    correction_path.unlink()
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "correction trust input is missing" in detail


def test_amendment_001_contract_fields_are_exact(tmp_path: Path) -> None:
    repo = _committed_amendment_repo(tmp_path)
    contract_path = repo / "protocol" / "amendments" / "iter000_001.json"
    original = contract_path.read_bytes()
    mutations = (
        (("retry_authorization", "maximum_additional_attempts"), 2),
        (("retry_authorization", "tls", "bypass_forbidden"), False),
        (("retry_authorization", "tls", "trust_store"), "system"),
        (("trigger_attempt", "expected_event_types"), ["run-started", "run-completed"]),
        (("trigger_attempt", "triggering_git_commit"), "0" * 40),
        (("trigger_attempt", "failure", "error_type"), "RuntimeError"),
        (("trigger_attempt", "scientific_effect", "accepted_data"), True),
        (("frozen_inputs", "dataset_lock", "sha256"), "0" * 64),
    )
    for keys, value in mutations:
        contract = json.loads(original)
        target = contract
        for key in keys[:-1]:
            target = target[key]
        target[keys[-1]] = value
        contract_path.write_bytes(canonical_json_pretty(contract))

        passed, detail = _verify_iteration_amendment_001(repo)

        assert not passed
        assert "exact authorized recovery contract" in detail
    contract_path.write_bytes(original)


def test_amendment_001_rejects_changed_inputs_results_and_retry_count(tmp_path: Path) -> None:
    repo = _committed_amendment_repo(tmp_path)
    dataset = repo / "protocol" / "datasets" / "nasa_adapt_v1.json"
    hypothesis = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "HYPOTHESIS.md"
    ledger = (
        repo
        / "experiments"
        / "iter000_nasa_adapt_corpus_readiness"
        / "proof"
        / "attempt_000"
        / "execution_ledger.jsonl"
    )
    for path in (dataset, hypothesis, ledger):
        original = path.read_bytes()
        path.write_bytes(original + b"tamper\n")
        passed, _ = _verify_iteration_amendment_001(repo)
        assert not passed
        path.write_bytes(original)

    result = ledger.parent / "RESULT.md"
    result.write_text("no scientific result is authorized\n")
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "only its signed failure ledger and head" in detail
    result.unlink()

    attempt_002 = ledger.parents[1] / "attempt_002"
    attempt_002.mkdir()
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "at most one isolated additional attempt" in detail
    attempt_002.rmdir()

    attempt_001 = ledger.parents[1] / "attempt_001"
    attempt_001.symlink_to(ledger.parent, target_is_directory=True)
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "at most one isolated additional attempt" in detail


def test_amendment_001_requires_committed_verified_tls_without_bypass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _committed_amendment_repo(tmp_path)
    cli_path = repo / "src" / "fieldtrue" / "cli.py"
    cli_path.write_bytes(cli_path.read_bytes() + b"\n")
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "protocol hash mismatch" in detail
    _git(repo, "checkout", "--quiet", "HEAD", "--", "src/fieldtrue/cli.py")

    unsafe = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unsafe.check_hostname = False
    unsafe.verify_mode = ssl.CERT_NONE
    monkeypatch.setattr(
        mission_module.adapt_adapter,
        "_verified_tls_context",
        lambda: unsafe,
    )
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "TLS runtime" in detail


def test_amendment_001_source_contract_rejects_tls_bypass(tmp_path: Path) -> None:
    repo = _committed_amendment_repo(tmp_path)
    adapt_path = repo / "src" / "fieldtrue" / "adapters" / "adapt.py"
    adapt_path.write_bytes(adapt_path.read_bytes() + b'\nPYTHONHTTPSVERIFY = "0"\n')
    _git(repo, "add", "src/fieldtrue/adapters/adapt.py")
    _git(repo, "commit", "--quiet", "-m", "inject forbidden TLS bypass")

    passed, detail = _verify_iteration_amendment_001(repo)

    assert not passed
    assert "protocol hash mismatch" in detail


def test_amendment_tls_helpers_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing.py"
    assert not _adapt_tls_source_is_verified(missing)

    incomplete = tmp_path / "incomplete.py"
    incomplete.write_text("def unrelated():\n    return None\n")
    assert not _adapt_tls_source_is_verified(incomplete)

    bypass = tmp_path / "bypass.py"
    bypass.write_text(
        "def _verified_tls_context():\n"
        "    return ssl.create_default_context(cafile=certifi.where())\n"
        "def _download_resource():\n"
        "    return urllib.request.urlopen(\n"
        "        'https://example.invalid', context=_verified_tls_context(), verify=False\n"
        "    )\n"
    )
    assert not _adapt_tls_source_is_verified(bypass)
    assert not _certifi_dependency_is_locked(tmp_path)

    trusted_bundle = Path(mission_module.certifi.where()).read_bytes()
    substituted_bundle = tmp_path / "substituted-certifi.pem"
    substituted_bundle.write_bytes(trusted_bundle + b"\n")
    monkeypatch.setattr(mission_module.certifi, "where", lambda: str(substituted_bundle))
    assert not _verified_tls_runtime_active()

    monkeypatch.setattr(mission_module.certifi, "where", lambda: str(tmp_path / "missing.pem"))
    assert not _verified_tls_runtime_active()


def test_amendment_001_rejects_noncanonical_or_missing_trust_inputs(tmp_path: Path) -> None:
    repo = _committed_amendment_repo(tmp_path)
    contract_path = repo / "protocol" / "amendments" / "iter000_001.json"
    contract_bytes = contract_path.read_bytes()
    contract_path.write_text(json.dumps(json.loads(contract_bytes)))
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "canonical JSON" in detail
    contract_path.write_bytes(contract_bytes)

    document = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "AMENDMENT_001.md"
    document_backup = document.with_suffix(".backup")
    document.rename(document_backup)
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "regular files" in detail
    document_backup.rename(document)

    attempt = repo / "experiments" / "iter000_nasa_adapt_corpus_readiness" / "proof" / "attempt_000"
    attempt_backup = attempt.with_name("attempt_000_backup")
    attempt.rename(attempt_backup)
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "regular files" in detail
    attempt.symlink_to(attempt_backup, target_is_directory=True)
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "must not be symbolic links" in detail


@pytest.mark.parametrize(
    "relative",
    [
        "src/fieldtrue/readiness.py",
        "protocol/schemas/readiness_report.schema.json",
        "protocol/baselines/v1.json",
    ],
)
def test_amendment_001_rejects_self_consistent_trigger_surface_changes(
    tmp_path: Path,
    relative: str,
) -> None:
    repo = _committed_amendment_repo(tmp_path)
    target = repo / relative
    target.write_bytes(target.read_bytes() + b"\n")
    authority_path = repo / "protocol" / "attempt_authorities" / "iter000_001.json"
    authority = json.loads(authority_path.read_text())
    authority["protocol_hashes"][relative] = sha256_bytes(target.read_bytes())
    authority_path.write_bytes(canonical_json_pretty(authority))
    _git(repo, "add", relative, authority_path.relative_to(repo).as_posix())
    _git(repo, "commit", "--quiet", "-m", "mutate frozen scientific surface")

    passed, detail = _verify_iteration_amendment_001(repo)

    assert not passed
    assert "trigger-commit" in detail or "unauthorized source" in detail


def test_amendment_001_rejects_a_rogue_source_file(tmp_path: Path) -> None:
    repo = _committed_amendment_repo(tmp_path)
    rogue = repo / "src" / "fieldtrue" / "rogue.py"
    rogue.write_text("raise RuntimeError('unregistered producer')\n")
    _git(repo, "add", rogue.relative_to(repo).as_posix())
    _git(repo, "commit", "--quiet", "-m", "inject unregistered producer")

    passed, detail = _verify_iteration_amendment_001(repo)

    assert not passed
    assert "added, removed, or linked" in detail


def test_amendment_001_rejects_a_rebound_authorized_source(tmp_path: Path) -> None:
    repo = _committed_amendment_repo(tmp_path)
    relative = "src/fieldtrue/adapters/adapt.py"
    target = repo / relative
    target.write_bytes(target.read_bytes() + b"\n")
    authority_path = repo / "protocol" / "attempt_authorities" / "iter000_001.json"
    authority = json.loads(authority_path.read_text())
    authority["protocol_hashes"][relative] = sha256_bytes(target.read_bytes())
    authority_path.write_bytes(canonical_json_pretty(authority))
    _git(repo, "add", relative, authority_path.relative_to(repo).as_posix())
    _git(repo, "commit", "--quiet", "-m", "rebind authorized producer")

    passed, detail = _verify_iteration_amendment_001(repo)

    assert not passed
    assert "authorized source binding differs" in detail


def test_amendment_001_rejects_a_rebound_gate_control_contract(tmp_path: Path) -> None:
    repo = _committed_amendment_repo(tmp_path)
    relative = "protocol/gate_controls/v1.json"
    target = repo / relative
    registry = json.loads(target.read_text())
    registry["controls"][0]["failure_class"] = "blocked"
    target.write_bytes(canonical_json_pretty(registry))
    authority_path = repo / "protocol" / "attempt_authorities" / "iter000_001.json"
    authority = json.loads(authority_path.read_text())
    authority["protocol_hashes"][relative] = sha256_bytes(target.read_bytes())
    authority_path.write_bytes(canonical_json_pretty(authority))
    _git(repo, "add", relative, authority_path.relative_to(repo).as_posix())
    _git(repo, "commit", "--quiet", "-m", "rebind scientific gate controls")

    passed, detail = _verify_iteration_amendment_001(repo)

    assert not passed
    assert "scientific gate-control contract" in detail


def test_amendment_001_rejects_weakened_or_placeholder_authority(tmp_path: Path) -> None:
    repo = _committed_amendment_repo(tmp_path)
    authority_path = repo / "protocol" / "attempt_authorities" / "iter000_001.json"
    original = authority_path.read_bytes()

    authority = json.loads(original)
    authority["consumption"]["proof_deletion_restores_authority"] = True
    authority_path.write_bytes(canonical_json_pretty(authority))
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "single-use receipt policy" in detail

    authority = json.loads(original)
    authority["protocol_hashes"].pop("src/fieldtrue/splits.py")
    authority_path.write_bytes(canonical_json_pretty(authority))
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "exact protocol surface" in detail

    authority = json.loads(original)
    authority["protocol_hashes"]["src/fieldtrue/readiness.py"] = "0" * 64
    authority_path.write_bytes(canonical_json_pretty(authority))
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "invalid hash binding" in detail

    bound_path = repo / "mission" / "name.json"
    changed_bytes = bound_path.read_bytes() + b"\n"
    bound_path.write_bytes(changed_bytes)
    authority = json.loads(original)
    authority["protocol_hashes"]["mission/name.json"] = sha256_bytes(changed_bytes)
    authority_path.write_bytes(canonical_json_pretty(authority))
    git = shutil.which("git")
    assert git is not None
    head = _git(repo, "rev-parse", "HEAD")
    passed, detail = mission_module._verify_attempt_001_scientific_surface(
        repo,
        git=git,
        head=head,
    )
    assert not passed
    assert "not committed at HEAD" in detail


def test_attempt_001_surface_fails_closed_on_missing_or_linked_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _committed_amendment_repo(tmp_path)
    git = shutil.which("git")
    assert git is not None
    head = _git(repo, "rev-parse", "HEAD")
    authority_path = repo / mission_module._ITER000_ATTEMPT_001_AUTHORITY_PATH
    original_authority = authority_path.read_bytes()

    authority_path.write_text("{")
    passed, detail = mission_module._verify_attempt_001_scientific_surface(repo, git=git, head=head)
    assert not passed
    assert "authority is unreadable" in detail

    authority_path.write_text(json.dumps(json.loads(original_authority)))
    passed, detail = mission_module._verify_attempt_001_scientific_surface(repo, git=git, head=head)
    assert not passed
    assert "canonical JSON" in detail

    authority_path.unlink()
    authority_backup = authority_path.with_suffix(".backup")
    authority_backup.write_bytes(original_authority)
    authority_path.symlink_to(authority_backup)
    passed, detail = mission_module._verify_attempt_001_scientific_surface(repo, git=git, head=head)
    assert not passed
    assert "regular file" in detail
    authority_path.unlink()
    authority_path.write_bytes(original_authority)

    bound_path = repo / "mission" / "name.json"
    bound_backup = bound_path.with_suffix(".backup")
    bound_path.rename(bound_backup)
    bound_path.symlink_to(bound_backup)
    passed, detail = mission_module._verify_attempt_001_scientific_surface(repo, git=git, head=head)
    assert not passed
    assert "protocol input is not a regular file" in detail
    bound_path.unlink()
    bound_backup.rename(bound_path)

    receipt_path = repo / mission_module._ITER000_ATTEMPT_001_RECEIPT_PATH
    receipt_path.mkdir(parents=True)
    passed, detail = mission_module._verify_attempt_001_scientific_surface(repo, git=git, head=head)
    assert not passed
    assert "consumption path is not a regular file" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module,
            "load_signer_anchor",
            lambda _path: (_ for _ in ()).throw(LedgerVerificationError("invalid anchor")),
        )
        passed, detail = mission_module._verify_attempt_001_scientific_surface(
            repo, git=git, head=head
        )
    assert not passed
    assert "signer anchor is invalid" in detail

    receipt_path.rmdir()
    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module,
            "load_signer_anchor",
            lambda _path: SimpleNamespace(signer_public_key="a" * 64),
        )
        passed, detail = mission_module._verify_attempt_001_scientific_surface(
            repo, git=git, head=head
        )
    assert not passed
    assert "signer key differs" in detail


def test_attempt_001_surface_rejects_missing_git_objects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _committed_amendment_repo(tmp_path)
    git = shutil.which("git")
    assert git is not None
    head = _git(repo, "rev-parse", "HEAD")

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_git_tree_paths", lambda *_args: None)
        passed, detail = mission_module._verify_attempt_001_scientific_surface(
            repo, git=git, head=head
        )
    assert not passed
    assert "triggering schema surface" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_working_source_paths", lambda _repo: None)
        passed, detail = mission_module._verify_attempt_001_scientific_surface(
            repo, git=git, head=head
        )
    assert not passed
    assert "complete source surface" in detail

    original_blob = mission_module._git_blob_at_path

    def missing_source(root: Path, executable: str, commit: str, relative: str) -> bytes | None:
        if (
            commit == mission_module._ITER000_TRIGGER_COMMIT
            and relative == "src/fieldtrue/approvals.py"
        ):
            return None
        return original_blob(root, executable, commit, relative)

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_git_blob_at_path", missing_source)
        passed, detail = mission_module._verify_attempt_001_scientific_surface(
            repo, git=git, head=head
        )
    assert not passed
    assert "triggering source is unavailable" in detail

    def malformed_gate(root: Path, executable: str, commit: str, relative: str) -> bytes | None:
        if (
            commit == mission_module._ITER000_TRIGGER_COMMIT
            and relative == mission_module._ITER000_GATE_CONTROL_PATH
        ):
            return b"[]"
        return original_blob(root, executable, commit, relative)

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_git_blob_at_path", malformed_gate)
        passed, detail = mission_module._verify_attempt_001_scientific_surface(
            repo, git=git, head=head
        )
    assert not passed
    assert "triggering gate-control registry is unavailable" in detail


def test_amendment_001_fails_closed_when_external_verifiers_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _committed_amendment_repo(tmp_path)
    document = repo / mission_module._AMENDMENT_001_DOCUMENT_PATH
    original_document = document.read_bytes()
    document.write_bytes(original_document + b"tamper\n")
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "document bytes" in detail
    document.write_bytes(original_document)

    amendment = repo / mission_module._AMENDMENT_001_PATH
    original_amendment = amendment.read_bytes()
    amendment.write_text("{")
    passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "Amendment 001 is unreadable" in detail
    amendment.write_bytes(original_amendment)

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module,
            "verify_ledger",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                LedgerVerificationError("verification unavailable")
            ),
        )
        passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "ledger does not verify" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_TRUSTED_GIT_PATH", tmp_path / "missing-git")
        passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "Git trust failed" in detail

    def fail_subprocess(*_args: object, **_kwargs: object) -> object:
        raise subprocess.CalledProcessError(1, "git")

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module.subprocess, "run", fail_subprocess)
        passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "Git trust failed" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_git_commit_resolves", lambda *_args: False)
        passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "not an ancestor" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_root_preregistration_bytes", lambda *_args: b"other")
        passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "root-preregistered hypothesis" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_certifi_dependency_is_locked", lambda _repo: False)
        passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "locked direct certifi dependency" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_adapt_tls_source_is_verified", lambda _path: False)
        passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "TLS source contract" in detail


def test_gate_falsification_policy_rejects_paper_only_controls() -> None:
    loop = _json(_repo() / "mission" / "loop.json")
    assert _gate_controls_valid(loop)

    policy = loop["gate_falsification_policy"]
    assert isinstance(policy, dict)
    requirements = policy["requirements"]
    assert isinstance(requirements, list)
    weakened = {
        **loop,
        "gate_falsification_policy": {
            **policy,
            "requirements": [
                requirement
                for requirement in requirements
                if requirement != "executable_sensitivity_test"
            ],
        },
    }

    assert not _gate_controls_valid(weakened)


def test_gate_control_registry_resolves_executable_pytest_nodes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo()
    registry = repo / "protocol" / "gate_controls" / "v1.json"
    registry_value = _json(registry)
    seal = registry_value["execution_seal"]
    assert isinstance(seal, dict)
    sealed_paths = seal["sealed_paths"]
    controls = registry_value["controls"]
    assert isinstance(sealed_paths, list)
    assert isinstance(controls, list)
    assert (
        _gate_control_set_hash(
            repo,
            iteration_id=registry_value["iteration_id"],
            controls=controls,
            sealed_paths=tuple(sealed_paths),
        )
        != seal["control_set_sha256"]
    )
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTEST_PLUGINS", "hostile_plugin")
    monkeypatch.setenv("PYTHONPATH", "/does/not/exist")
    passed, detail = _verify_gate_control_registry(repo, registry)
    assert passed
    assert "Executed and verified 16 distinct controls" in detail

    broken = _json(registry)
    controls = broken["controls"]
    assert isinstance(controls, list)
    controls[0]["negative_control"] = "tests/unit/test_readiness.py::test_missing_control"
    broken_path = tmp_path / "broken.json"
    broken_path.write_text(json.dumps(broken))

    passed, detail = _verify_gate_control_registry(repo, broken_path)
    assert not passed
    assert "source-integrity: negative_control" in detail


def test_gate_control_runner_is_bound_to_the_historical_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo()
    poisoned_uv_cache = tmp_path / "poisoned-uv-cache"
    poisoned_pytest = poisoned_uv_cache / "archive-v0" / "poison" / "_pytest"
    poisoned_pytest.mkdir(parents=True)
    poisoned_pytest.joinpath("__init__.py").write_text(
        "raise RuntimeError('mutable uv cache executed')\n", encoding="utf-8"
    )
    poisoned_python = tmp_path / "poisoned-python"
    poisoned_json = poisoned_python / "cpython-3.12.13-macos-aarch64-none" / "lib" / "python3.12"
    poisoned_json.mkdir(parents=True)
    poisoned_json.joinpath("json.py").write_text(
        "raise RuntimeError('mutable managed Python executed')\n", encoding="utf-8"
    )
    monkeypatch.setenv("UV_CACHE_DIR", str(poisoned_uv_cache))
    monkeypatch.setenv("UV_PYTHON_INSTALL_DIR", str(poisoned_python))
    monkeypatch.setenv("UV_PYTHON_DOWNLOADS_JSON_URL", "file:///tmp/hostile-python.json")
    monkeypatch.setenv("UV_PYTHON_INSTALL_MIRROR", "file:///tmp/hostile-mirror")
    monkeypatch.setenv("UV_ASTRAL_MIRROR_URL", "https://example.invalid")
    # Proxy reachability is an acquisition condition, not evidence of runner-integrity drift.
    monkeypatch.setenv("DYLD_INSERT_LIBRARIES", str(tmp_path / "hostile.dylib"))
    monkeypatch.setenv("LD_PRELOAD", str(tmp_path / "hostile.so"))
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    assert _materialize_gate_control_snapshot(
        repo,
        git=mission_module._trusted_git(repo),
        destination=snapshot,
    )
    runner = _prepare_gate_control_runner(snapshot)
    assert runner is not None
    assert (
        b"mutable uv cache executed"
        not in (runner.site_packages / "_pytest" / "__init__.py").read_bytes()
    )
    assert not runner.interpreter_root.is_relative_to(poisoned_python)
    assert (
        b"mutable managed Python executed"
        not in (
            runner.interpreter_root / "lib" / "python3.12" / "json" / "__init__.py"
        ).read_bytes()
    )
    lock_path = snapshot / "uv.lock"
    lock_bytes = lock_path.read_bytes()
    assert runner.lock_sha256 == sha256_bytes(lock_bytes)

    source = snapshot / "src" / "fieldtrue" / "readiness.py"
    source.write_bytes(source.read_bytes() + b"\n")
    assert not _gate_control_runner_is_unchanged(snapshot, runner)
    with pytest.raises(OSError, match="changed before child execution"):
        mission_module._run_gate_control_nodes(snapshot, [], runner)

    lock_path.unlink()
    assert _prepare_gate_control_runner(snapshot) is None

    mutated_snapshot = tmp_path / "mutated-snapshot"
    mutated_snapshot.mkdir()
    assert _materialize_gate_control_snapshot(
        repo,
        git=mission_module._trusted_git(repo),
        destination=mutated_snapshot,
    )
    mutated_lock = mutated_snapshot / "uv.lock"
    mutated_lock.write_bytes(
        mutated_lock.read_bytes().replace(b'version = "9.1.1"', b'version = "9.1.0"')
    )
    assert _prepare_gate_control_runner(mutated_snapshot) is None

    fake_uv = tmp_path / "uv"
    fake_uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_uv.chmod(0o755)
    monkeypatch.setattr(mission_module.shutil, "which", lambda _name: str(fake_uv))
    passed, detail = _verify_gate_control_registry(
        repo,
        repo / "protocol" / "gate_controls" / "v1.json",
    )
    assert not passed
    assert "runner does not match" in detail


class _ArtifactResponse:
    def __init__(self, url: str, payload: bytes) -> None:
        self._url = url
        self._payload = payload

    def __enter__(self) -> _ArtifactResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self, maximum_bytes: int) -> bytes:
        assert maximum_bytes == len(self._payload) + 1
        return self._payload


def test_authenticated_artifact_cache_is_advisory_and_repaired_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"locked artifact bytes"
    digest = sha256_bytes(payload)
    url = f"https://files.pythonhosted.org/packages/frozen/{digest}/fixture.whl"
    cache_root = tmp_path / "cache"
    namespace = "frozen-lock"
    cache_directory = cache_root / namespace
    cache_directory.mkdir(parents=True)
    cache_path = cache_directory / f"{digest}-fixture.whl"
    cache_path.write_bytes(b"x" * len(payload))
    downloads = 0

    def urlopen(*_args: object, **_kwargs: object) -> _ArtifactResponse:
        nonlocal downloads
        downloads += 1
        return _ArtifactResponse(url, payload)

    monkeypatch.setattr(mission_module.urllib.request, "urlopen", urlopen)
    assert (
        mission_module._authenticated_artifact_bytes(
            url=url,
            expected_sha256=digest,
            expected_size=len(payload),
            cache_root=cache_root,
            cache_namespace=namespace,
        )
        == payload
    )
    assert downloads == 1
    assert cache_path.read_bytes() == payload

    external = tmp_path / "external"
    external.write_bytes(b"do not replace")
    cache_path.unlink()
    cache_path.symlink_to(external)
    assert (
        mission_module._authenticated_artifact_bytes(
            url=url,
            expected_sha256=digest,
            expected_size=len(payload),
            cache_root=cache_root,
            cache_namespace=namespace,
        )
        == payload
    )
    assert downloads == 2
    assert external.read_bytes() == b"do not replace"
    assert not cache_path.is_symlink()
    assert cache_path.read_bytes() == payload

    cache_path.unlink()
    hardlink_source = tmp_path / "hardlink-source"
    hardlink_source.write_bytes(payload)
    cache_path.hardlink_to(hardlink_source)
    assert (
        mission_module._authenticated_artifact_bytes(
            url=url,
            expected_sha256=digest,
            expected_size=len(payload),
            cache_root=cache_root,
            cache_namespace=namespace,
        )
        == payload
    )
    assert downloads == 3
    assert cache_path.stat().st_nlink == 1
    assert hardlink_source.read_bytes() == payload


def test_gate_control_wheels_are_a_minimal_locked_cpython_312_closure() -> None:
    lock = tomllib.loads((_repo() / "uv.lock").read_text(encoding="utf-8"))
    packages = mission_module._locked_gate_control_packages(lock)
    wheels = mission_module._locked_gate_control_wheels(lock)

    assert packages is not None
    assert set(packages) == {
        "annotated-types",
        "certifi",
        "iniconfig",
        "networkx",
        "packaging",
        "pluggy",
        "pydantic",
        "pydantic-core",
        "pygments",
        "pytest",
        "typing-extensions",
        "typing-inspection",
    }
    assert wheels is not None
    assert {wheel.distribution for wheel in wheels} == set(packages)
    pydantic_core = next(wheel for wheel in wheels if wheel.distribution == "pydantic-core")
    assert "-cp312-cp312-" in pydantic_core.filename


@pytest.mark.parametrize(
    ("system", "machine", "platform_tag", "wheel_platform"),
    [
        ("Darwin", "arm64", "macosx_11_0_arm64", "macosx_11_0_arm64"),
        (
            "Linux",
            "x86_64",
            "manylinux_2_17_x86_64",
            "manylinux_2_17_x86_64",
        ),
    ],
)
def test_gate_control_wheel_selection_targets_supported_cpython_312_platforms(
    monkeypatch: pytest.MonkeyPatch,
    system: str,
    machine: str,
    platform_tag: str,
    wheel_platform: str,
) -> None:
    monkeypatch.setattr(mission_module.platform, "system", lambda: system)
    monkeypatch.setattr(mission_module.platform, "machine", lambda: machine)
    monkeypatch.setattr(mission_module, "platform_tags", lambda: iter((platform_tag,)))
    lock = tomllib.loads((_repo() / "uv.lock").read_text(encoding="utf-8"))

    wheels = mission_module._locked_gate_control_wheels(lock)

    assert wheels is not None
    pydantic_core = next(wheel for wheel in wheels if wheel.distribution == "pydantic-core")
    assert "-cp312-cp312-" in pydantic_core.filename
    assert wheel_platform in pydantic_core.filename


def _malformed_wheel(case: str) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if case == "traversal":
            archive.writestr("../escape.py", "pass\n")
        elif case == "symlink":
            member = zipfile.ZipInfo("package/link.py")
            member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, "target.py")
        elif case == "case-collision":
            archive.writestr("package/Module.py", "pass\n")
            archive.writestr("package/module.py", "pass\n")
        else:
            archive.writestr("fixture.data/scripts/fixture", "pass\n")
    return output.getvalue()


@pytest.mark.parametrize(
    "case",
    ["traversal", "symlink", "case-collision", "unsupported-data-scheme"],
)
def test_authenticated_wheel_extraction_rejects_unsafe_members(
    tmp_path: Path,
    case: str,
) -> None:
    data = _malformed_wheel(case)
    wheel = mission_module._LockedWheel(
        distribution="fixture",
        version="1.0",
        url="https://files.pythonhosted.org/packages/frozen/fixture.whl",
        sha256=sha256_bytes(data),
        size=len(data),
        filename="fixture-1.0-py3-none-any.whl",
    )

    assert not mission_module._extract_authenticated_wheels(
        ((wheel, data),), tmp_path / "site-packages"
    )
    assert not (tmp_path / "escape.py").exists()


def test_gate_control_registry_maps_historical_git_timeout_to_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(*_args: object, **_kwargs: object) -> bool:
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)

    monkeypatch.setattr(mission_module, "_git_commit_resolves", timeout)
    passed, detail = _verify_gate_control_registry(
        _repo(),
        _repo() / "protocol" / "gate_controls" / "v1.json",
    )

    assert not passed
    assert "TimeoutExpired" in detail


def test_gate_control_registry_reports_runner_acquisition_without_lock_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(_snapshot_root: Path) -> None:
        raise mission_module.runner_trust.RunnerAcquisitionError("fixture timeout")

    monkeypatch.setattr(mission_module, "_prepare_gate_control_runner", unavailable)
    passed, detail = _verify_gate_control_registry(
        _repo(),
        _repo() / "protocol" / "gate_controls" / "v1.json",
    )

    assert not passed
    assert detail == (
        "Gate control runner acquisition could not be completed; runner trust was not established."
    )
    assert "does not match the frozen historical lock" not in detail


def _write_registry_case(tmp_path: Path, name: str, value: object) -> Path:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(value))
    return path


def test_gate_control_registry_fails_closed_on_structure_and_seal_tampering(
    tmp_path: Path,
) -> None:
    repo = _repo()
    registry_path = repo / "protocol" / "gate_controls" / "v1.json"

    unreadable = tmp_path / "unreadable.json"
    unreadable.write_text("{")
    passed, detail = _verify_gate_control_registry(repo, unreadable)
    assert not passed
    assert "unreadable" in detail

    malformed = _json(registry_path)
    malformed["unexpected"] = True
    passed, detail = _verify_gate_control_registry(
        repo, _write_registry_case(tmp_path, "malformed", malformed)
    )
    assert not passed
    assert "identity or structure" in detail

    invalid_record = _json(registry_path)
    invalid_record["controls"][0] = []
    passed, detail = _verify_gate_control_registry(
        repo, _write_registry_case(tmp_path, "invalid-record", invalid_record)
    )
    assert not passed
    assert "invalid control record" in detail

    duplicate = _json(registry_path)
    duplicate["controls"].append(dict(duplicate["controls"][0]))
    passed, detail = _verify_gate_control_registry(
        repo, _write_registry_case(tmp_path, "duplicate", duplicate)
    )
    assert not passed
    assert "duplicates" in detail

    incomplete = _json(registry_path)
    incomplete["controls"].pop()
    passed, detail = _verify_gate_control_registry(
        repo, _write_registry_case(tmp_path, "incomplete", incomplete)
    )
    assert not passed
    assert "exact iteration-000 gate set" in detail

    wrong_class = _json(registry_path)
    wrong_class["controls"][0]["failure_class"] = "blocked"
    passed, detail = _verify_gate_control_registry(
        repo, _write_registry_case(tmp_path, "wrong-class", wrong_class)
    )
    assert not passed
    assert "failure class" in detail

    malformed_seal = _json(registry_path)
    malformed_seal["execution_seal"]["runner"] = "paper-only"
    passed, detail = _verify_gate_control_registry(
        repo, _write_registry_case(tmp_path, "malformed-seal", malformed_seal)
    )
    assert not passed
    assert "execution seal" in detail

    stale_seal = _json(registry_path)
    stale_seal["execution_seal"]["control_set_sha256"] = "0" * 64
    passed, detail = _verify_gate_control_registry(
        repo, _write_registry_case(tmp_path, "stale-seal", stale_seal)
    )
    assert not passed
    assert "source seal" in detail

    assert (
        _gate_control_set_hash(
            repo,
            iteration_id="iter000_nasa_adapt_corpus_readiness",
            controls=[],
            sealed_paths=("missing-control-source.py",),
        )
        is None
    )


def test_gate_control_registry_requires_a_reproduced_passing_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _repo()
    registry = repo / "protocol" / "gate_controls" / "v1.json"
    runner = SimpleNamespace()
    # This case classifies child execution failures. Dedicated tests construct, execute, and
    # mutation-check the authenticated historical runner.
    monkeypatch.setattr(
        mission_module,
        "_prepare_gate_control_runner",
        lambda _snapshot_root: runner,
    )
    monkeypatch.setattr(
        mission_module,
        "_gate_control_runner_is_unchanged",
        lambda _snapshot_root, candidate: candidate is runner,
    )

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="pytest", timeout=120)

    monkeypatch.setattr(mission_module, "_run_gate_control_nodes", timeout)
    passed, detail = _verify_gate_control_registry(repo, registry)
    assert not passed
    assert "TimeoutExpired" in detail

    monkeypatch.setattr(
        mission_module,
        "_run_gate_control_nodes",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="failed control",
            stderr="",
        ),
    )
    passed, detail = _verify_gate_control_registry(repo, registry)
    assert not passed
    assert "failed control" in detail

    monkeypatch.setattr(
        mission_module,
        "_run_gate_control_nodes",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="16 collected",
            stderr="",
        ),
    )
    passed, detail = _verify_gate_control_registry(repo, registry)
    assert not passed
    assert "sealed passing result" in detail


def test_gate_control_nodes_must_be_gate_specific_and_substantive(tmp_path: Path) -> None:
    control_path = tmp_path / "tests" / "test_controls.py"
    control_path.parent.mkdir()
    control_path.write_text("def test_source_integrity_positive_control():\n    pass\n")

    assert not _control_node_is_substantive(
        tmp_path,
        "tests/test_controls.py::test_source_integrity_positive_control",
        gate_id="source-integrity",
        role="positive",
        expected_status="pass",
    )


def test_publication_transition_stays_blocked_without_signed_evidence() -> None:
    loop = _json(_repo() / "mission" / "loop.json")
    requirements = set(loop["transition_requirements"]["published"])

    passed, detail = _verify_publication_transition(_repo(), loop, requirements)
    assert passed
    assert "explicitly blocked" in detail

    published = {**loop, "current_stage": "published"}
    passed, detail = _verify_publication_transition(_repo(), published, requirements)
    assert not passed
    assert "requires an authorized publication receipt" in detail


@pytest.mark.parametrize(
    "mutation",
    [
        {"publication_transition": None},
        {"stages": "not-a-stage-list"},
        {
            "publication_transition": {
                "status": "blocked",
                "receipt_path": None,
                "signer_anchor_path": None,
                "block_reason": "",
            }
        },
        {
            "publication_transition": {
                "status": "pending",
                "receipt_path": None,
                "signer_anchor_path": None,
                "block_reason": None,
            }
        },
        {
            "publication_transition": {
                "status": "authorized",
                "receipt_path": "../receipt.json",
                "signer_anchor_path": "../anchor.json",
                "block_reason": None,
            }
        },
    ],
)
def test_publication_transition_rejects_malformed_or_unsafe_state(
    mutation: dict[str, object],
) -> None:
    loop = {**_json(_repo() / "mission" / "loop.json"), **mutation}
    requirements = set(loop.get("transition_requirements", {}).get("published", []))
    passed, _ = _verify_publication_transition(_repo(), loop, requirements)
    assert not passed


def test_publication_transition_accepts_only_signed_git_anchored_gate_evidence(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "publication-repo"
    repo.mkdir()
    _git(repo, "init", "--quiet")
    _git(repo, "config", "user.name", "Publication Test")
    _git(repo, "config", "user.email", "publication@example.invalid")
    loop = _json(_repo() / "mission" / "loop.json")
    contract = _json(_repo() / "mission" / "contract.json")
    requirements = list(loop["transition_requirements"]["published"])
    evidence: dict[str, dict[str, str]] = {}
    for index, requirement in enumerate(requirements):
        relative = f"publication/evidence/{index:02d}-{requirement}.json"
        path = repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        content = canonical_json_pretty({"requirement": requirement, "status": "satisfied"})
        path.write_bytes(content)
        evidence[requirement] = {
            "path": relative,
            "git_commit": "pending",
            "sha256": sha256_bytes(content),
        }
    _git(repo, "add", "publication/evidence")
    _git(repo, "commit", "--quiet", "-m", "anchor publication evidence")
    evidence_commit = _git(repo, "rev-parse", "HEAD")
    for item in evidence.values():
        item["git_commit"] = evidence_commit

    key = SigningKey.generate()
    anchor_relative = "protocol/trust/publication_signer_anchor.json"
    write_publication_signer_anchor(
        repo / anchor_relative,
        key,
        anchor_id="publication-transition",
        ledger_scope="publication-gates",
    )
    receipt_body = {
        "schema_version": "fieldtrue.publication-gate-receipt.v1",
        "mission_id": contract["mission_id"],
        "target_stage": "published",
        "requirements": requirements,
        "evidence": evidence,
        "signer_public_key": key.verify_key.encode().hex(),
    }
    receipt_hash = sha256_value(receipt_body)
    receipt = {
        **receipt_body,
        "receipt_hash": receipt_hash,
        "signature": key.sign(bytes.fromhex(receipt_hash)).signature.hex(),
    }
    receipt_relative = "publication/publication_gate_receipt.json"
    (repo / receipt_relative).write_bytes(canonical_json_pretty(receipt))
    authorized_loop = {
        **loop,
        "current_stage": "published",
        "publication_transition": {
            "status": "authorized",
            "receipt_path": receipt_relative,
            "signer_anchor_path": anchor_relative,
            "block_reason": None,
        },
    }
    loop_path = repo / "mission" / "loop.json"
    loop_path.parent.mkdir(parents=True)
    loop_path.write_bytes(canonical_json_pretty(authorized_loop))
    contract_path = repo / "mission" / "contract.json"
    contract_path.write_bytes(canonical_json_pretty(contract))
    _git(
        repo,
        "add",
        anchor_relative,
        receipt_relative,
        "mission/contract.json",
        "mission/loop.json",
    )
    _git(repo, "commit", "--quiet", "-m", "authorize publication transition")

    passed, detail = _verify_publication_transition(repo, authorized_loop, set(requirements))
    assert passed
    assert "signed" in detail

    anchor_path = repo / anchor_relative
    inbar_anchor_bytes = anchor_path.read_bytes()
    anchor_path.unlink()
    write_signer_anchor(
        anchor_path,
        key,
        anchor_id="publication-transition",
        ledger_scope="publication-gates",
    )
    passed, detail = _verify_publication_transition(repo, authorized_loop, set(requirements))
    assert not passed
    assert "unreadable" in detail
    anchor_path.write_bytes(inbar_anchor_bytes)

    contract_bytes = contract_path.read_bytes()
    contract_path.write_bytes(b" " + contract_bytes)
    passed, detail = _verify_publication_transition(repo, authorized_loop, set(requirements))
    assert not passed
    assert "canonical JSON" in detail
    contract_path.write_bytes(contract_bytes)

    outside_contract = repo.parent / "outside-contract.json"
    outside_contract.write_bytes(contract_bytes)
    contract_path.unlink()
    contract_path.symlink_to(outside_contract)
    passed, detail = _verify_publication_transition(repo, authorized_loop, set(requirements))
    assert not passed
    assert "unreadable" in detail
    contract_path.unlink()
    contract_path.write_bytes(contract_bytes)

    mismatched_loop = {**authorized_loop, "mission_id": "fieldtrue"}
    loop_path.write_bytes(canonical_json_pretty(mismatched_loop))
    passed, detail = _verify_publication_transition(repo, mismatched_loop, set(requirements))
    assert not passed
    assert "exact required gate set" in detail
    loop_path.write_bytes(canonical_json_pretty(authorized_loop))

    tampered = json.loads((repo / receipt_relative).read_text())
    tampered["target_stage"] = "learned"
    (repo / receipt_relative).write_bytes(canonical_json_pretty(tampered))
    passed, detail = _verify_publication_transition(repo, authorized_loop, set(requirements))
    assert not passed
    assert "target_stage" not in detail or "exact required gate set" in detail


@pytest.mark.parametrize(
    "node_id",
    [
        None,
        "tests/unit/test_readiness.py",
        "tests/unit/test_readiness.py::helper",
        "../tests/unit/test_readiness.py::test_control",
        "docs/control.md::test_control",
    ],
)
def test_pytest_control_node_rejects_unsafe_or_non_test_references(
    node_id: object,
) -> None:
    assert not _pytest_node_exists(_repo(), node_id)


def test_pytest_control_node_rejects_unreadable_or_invalid_modules(tmp_path: Path) -> None:
    missing = "tests/missing.py::test_control"
    assert not _pytest_node_exists(tmp_path, missing)

    invalid_path = tmp_path / "tests" / "invalid.py"
    invalid_path.parent.mkdir()
    invalid_path.write_text("def broken(:\n")
    assert not _pytest_node_exists(tmp_path, "tests/invalid.py::test_control")


def test_current_credibility_registry_binds_exact_claims_and_control_nodes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _credibility_control_repo(tmp_path, monkeypatch)

    passed, detail = _verify_credibility_gate_control_registry(repo)

    assert passed
    assert detail == (
        "Current credibility registry binds 4 gates, "
        f"{len(mission_module._REQUIRED_BOOTSTRAP_CLAIM_DIGESTS)} claims, "
        "and 12 control roles to committed tests."
    )


@pytest.mark.parametrize("wrapped_by_git_trust", [False, True])
def test_current_credibility_registry_reports_timeout_without_trust_verdict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    wrapped_by_git_trust: bool,
) -> None:
    repo = _credibility_control_repo(tmp_path, monkeypatch)

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="git", timeout=10)

    if not wrapped_by_git_trust:
        monkeypatch.setattr(mission_module, "_trusted_git", lambda _repo: "git")
    monkeypatch.setattr(mission_module.subprocess, "run", timeout)
    passed, detail = _verify_credibility_gate_control_registry(repo)

    assert not passed
    assert detail == (
        "Current credibility-control registry verification timed out; "
        "credibility trust was not established."
    )


def test_current_credibility_registry_rejects_dirty_or_noncanonical_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _credibility_control_repo(tmp_path, monkeypatch)
    registry = repo / mission_module._CREDIBILITY_GATE_CONTROL_PATH
    original = registry.read_bytes()
    registry.write_bytes(original + b" ")

    passed, detail = _verify_credibility_gate_control_registry(repo)

    assert not passed
    assert detail == "Current credibility-control registry is not committed at HEAD."

    registry.write_bytes(b" " + original)
    _git(repo, "add", mission_module._CREDIBILITY_GATE_CONTROL_PATH)
    _git(repo, "commit", "--quiet", "-m", "make registry noncanonical")
    passed, detail = _verify_credibility_gate_control_registry(repo)
    assert not passed
    assert detail == "Current credibility-control registry differs from its exact contract."


def test_current_credibility_registry_rejects_uncommitted_or_substituted_test(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _credibility_control_repo(tmp_path, monkeypatch)
    relative = "tests/unit/test_mission.py"
    test_module = repo / relative
    original = test_module.read_bytes()
    test_module.write_bytes(original + b"\n")

    passed, detail = _verify_credibility_gate_control_registry(repo)

    assert not passed
    assert detail == f"Current credibility-control tests are not committed at HEAD: {relative}."

    test_module.write_bytes(original.replace(b"assert True", b"assert 1 == 1", 1))
    _git(repo, "add", relative)
    _git(repo, "commit", "--quiet", "-m", "substitute credibility test")
    passed, detail = _verify_credibility_gate_control_registry(repo)
    assert not passed
    assert detail == f"Current credibility-control tests differ from reviewed evidence: {relative}."


def test_current_credibility_registry_rejects_unresolved_control_node(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _credibility_control_repo(tmp_path, monkeypatch)
    relative = "tests/unit/test_handoff.py"
    test_module = repo / relative
    target = b"def test_checkpoint_v2_rejects_current_artifact_drift():\n    assert True\n"
    assert target in test_module.read_bytes()
    test_module.write_bytes(test_module.read_bytes().replace(target, b"", 1))
    _git(repo, "add", relative)
    _git(repo, "commit", "--quiet", "-m", "remove credibility control node")
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_EVIDENCE_DIGESTS",
        {
            **mission_module._REQUIRED_BOOTSTRAP_EVIDENCE_DIGESTS,
            relative: sha256_bytes(test_module.read_bytes()),
        },
    )

    passed, detail = _verify_credibility_gate_control_registry(repo)

    assert not passed
    assert detail == "Current credibility controls do not resolve three distinct tests."


def test_current_credibility_registry_rejects_decorated_control_node(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _credibility_control_repo(tmp_path, monkeypatch)
    relative = "tests/unit/test_mission.py"
    test_module = repo / relative
    target = b"def test_current_credibility_registry_binds_exact_claims_and_control_nodes():\n"
    assert target in test_module.read_bytes()
    test_module.write_bytes(
        test_module.read_bytes().replace(target, b"@staticmethod\n" + target, 1)
    )
    _git(repo, "add", relative)
    _git(repo, "commit", "--quiet", "-m", "decorate credibility control node")
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_EVIDENCE_DIGESTS",
        {
            **mission_module._REQUIRED_BOOTSTRAP_EVIDENCE_DIGESTS,
            relative: sha256_bytes(test_module.read_bytes()),
        },
    )

    passed, detail = _verify_credibility_gate_control_registry(repo)

    assert not passed
    assert detail == "Current credibility controls do not resolve three distinct tests."


def test_root_commit_contains_only_the_frozen_hypothesis() -> None:
    repo = _repo()
    relative = "experiments/iter000_nasa_adapt_corpus_readiness/HYPOTHESIS.md"
    assert _first_commit_files(repo) == [relative]
    assert _root_preregistration_bytes(repo, relative) == (repo / relative).read_bytes()


def test_json_and_claim_loaders_fail_with_precise_context(tmp_path: Path) -> None:
    not_object = tmp_path / "array.json"
    not_object.write_text("[]\n")
    with pytest.raises(ValueError, match="JSON object"):
        _json(not_object)

    invalid_claims = tmp_path / "claims.jsonl"
    invalid_claims.write_text("{}\n")
    with pytest.raises(ValueError, match="line 1"):
        _claims(invalid_claims)

    valid_claims = _claims(_repo() / "claims" / "registry.jsonl")
    assert valid_claims


def test_claim_registry_binds_exact_contracts_registry_and_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, digests, evidence_digests, registry_digest = _claim_contract_repo(tmp_path)
    _install_claim_contract(monkeypatch, digests, evidence_digests, registry_digest)

    passed, detail = _claim_registry_valid(repo)

    assert passed
    assert detail == (
        "Claim registry binds 2 exact claim contracts and 1 evidence file to Git HEAD."
    )

    registry = repo / "claims" / "registry.jsonl"
    registry.write_bytes(registry.read_bytes().replace(b"Fixture claim", b"Changed claim", 1))
    passed, detail = _claim_registry_valid(repo)
    assert not passed
    assert detail == "Claim registry is not committed at HEAD."


def test_claim_registry_rejects_committed_semantic_substitution_and_extra_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, digests, evidence_digests, registry_digest = _claim_contract_repo(tmp_path)
    _install_claim_contract(monkeypatch, digests, evidence_digests, registry_digest)
    registry = repo / "claims" / "registry.jsonl"
    lines = registry.read_text(encoding="utf-8").splitlines()
    substituted = json.loads(lines[0])
    substituted["wording"] = "Arbitrary supported claim."
    lines[0] = canonical_json(substituted).decode("utf-8")
    registry.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _git(repo, "add", "claims/registry.jsonl")
    _git(repo, "commit", "--quiet", "-m", "substitute claim semantics")
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_REGISTRY_SHA256",
        sha256_bytes(registry.read_bytes()),
    )

    passed, detail = _claim_registry_valid(repo)

    assert not passed
    assert "differ from reviewed contracts" in detail

    extra = {
        **substituted,
        "claim_id": "claim.unreviewed.v1",
        "status": "blocked",
    }
    with registry.open("a", encoding="utf-8") as handle:
        handle.write(canonical_json(extra).decode("utf-8") + "\n")
    _git(repo, "add", "claims/registry.jsonl")
    _git(repo, "commit", "--quiet", "-m", "append unreviewed claim")
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_REGISTRY_SHA256",
        sha256_bytes(registry.read_bytes()),
    )
    passed, detail = _claim_registry_valid(repo)
    assert not passed
    assert detail == "Claim registry IDs differ from the reviewed bootstrap claim set."


def test_claim_registry_rejects_dirty_evidence_and_head_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, digests, evidence_digests, registry_digest = _claim_contract_repo(tmp_path)
    _install_claim_contract(monkeypatch, digests, evidence_digests, registry_digest)
    evidence = repo / "evidence" / "source.json"
    original = evidence.read_bytes()
    evidence.write_bytes(b'{"verdict":"substituted"}\n')

    passed, detail = _claim_registry_valid(repo)

    assert not passed
    assert detail == "Claim evidence is not committed at HEAD: evidence/source.json."
    evidence.write_bytes(original)

    original_run = mission_module.subprocess.run
    head_reads = 0

    def changing_head(*args: object, **kwargs: object) -> object:
        nonlocal head_reads
        result = original_run(*args, **kwargs)
        command = args[0]
        if isinstance(command, list) and command[1:4] == [
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ]:
            head_reads += 1
            if head_reads == 2:
                return SimpleNamespace(stdout="0" * 40 + "\n", returncode=0)
        return result

    monkeypatch.setattr(mission_module.subprocess, "run", changing_head)
    passed, detail = _claim_registry_valid(repo)
    assert not passed
    assert detail == "Claim registry Git HEAD changed during verification."


def test_claim_registry_rejects_committed_evidence_content_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, digests, evidence_digests, registry_digest = _claim_contract_repo(tmp_path)
    _install_claim_contract(monkeypatch, digests, evidence_digests, registry_digest)
    evidence = repo / "evidence" / "source.json"
    evidence.write_bytes(b'{"verdict":"opposite"}\n')
    _git(repo, "add", "evidence/source.json")
    _git(repo, "commit", "--quiet", "-m", "substitute committed evidence")

    passed, detail = _claim_registry_valid(repo)

    assert not passed
    assert detail == "Claim evidence differs from reviewed content: evidence/source.json."


def test_claim_registry_preserves_bootstrap_status_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, digests, evidence_digests, registry_digest = _claim_contract_repo(tmp_path)
    _install_claim_contract(monkeypatch, digests, evidence_digests, registry_digest)
    registry = repo / "claims" / "registry.jsonl"
    lines = registry.read_text(encoding="utf-8").splitlines()
    promoted = ClaimRecord.model_validate_json(lines[1]).model_copy(
        update={"status": mission_module.ClaimStatus.SUPPORTED}
    )
    lines[1] = canonical_json(promoted.model_dump(mode="json", exclude_none=True)).decode("utf-8")
    registry.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _git(repo, "add", "claims/registry.jsonl")
    _git(repo, "commit", "--quiet", "-m", "promote bootstrap claim")
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_CLAIM_DIGESTS",
        {**digests, promoted.claim_id: sha256_value(promoted.model_dump(mode="json"))},
    )
    monkeypatch.setattr(
        mission_module,
        "_REQUIRED_BOOTSTRAP_REGISTRY_SHA256",
        sha256_bytes(registry.read_bytes()),
    )

    passed, detail = _claim_registry_valid(repo)

    assert not passed
    assert detail == (
        "Claim statuses violate the bootstrap result boundary: scope.integrated-loop.v2"
    )


def test_claim_registry_rejects_incomplete_correction_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, digests, evidence_digests, _registry_digest = _claim_contract_repo(tmp_path)
    registry = repo / "claims" / "registry.jsonl"
    lines = registry.read_text(encoding="utf-8").splitlines()
    successor = ClaimRecord.model_validate_json(lines[1]).model_copy(
        update={"supersedes_claim_id": None}
    )
    lines[1] = canonical_json(successor.model_dump(mode="json", exclude_none=True)).decode("utf-8")
    registry.write_text("\n".join(lines) + "\n", encoding="utf-8")
    _git(repo, "add", "claims/registry.jsonl")
    _git(repo, "commit", "--quiet", "-m", "remove correction lineage")
    _install_claim_contract(
        monkeypatch,
        {
            **digests,
            successor.claim_id: sha256_value(successor.model_dump(mode="json", exclude_none=True)),
        },
        evidence_digests,
        sha256_bytes(registry.read_bytes()),
    )

    passed, detail = _claim_registry_valid(repo)

    assert not passed
    assert detail == "Claim correction lineage is invalid."


def test_research_memory_git_anchors_use_historical_blob_bytes(tmp_path: Path) -> None:
    repo, commit, _, evidence_bytes = _fixture_git_repo(tmp_path)
    evidence = MemoryEvidenceRef(
        role="source",
        uri="evidence/source.txt",
        sha256=sha256_bytes(evidence_bytes),
        git_commit=commit,
        media_type="text/plain",
        access=AccessClass.INTERNAL,
        label_access=LabelAccess.NONE,
    )
    evidence_without_hash = evidence.model_copy(update={"role": "derived", "sha256": None})
    memory_path = _write_memory(
        repo,
        source_commit=commit,
        evidence=(evidence, evidence_without_hash),
    )
    (repo / "evidence" / "source.txt").write_bytes(b"uncommitted replacement\n")

    passed, detail = _verify_memory_git_anchors(repo, memory_path)

    assert passed
    assert detail == "Research memory Git anchors verify (1 event)."


def test_research_memory_git_anchors_reject_unreachable_commits(tmp_path: Path) -> None:
    repo, _, _, _ = _fixture_git_repo(tmp_path)
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    orphan = _git(repo, "commit-tree", tree, "-m", "unreachable evidence")
    memory_path = _write_memory(repo, source_commit=orphan)

    passed, detail = _verify_memory_git_anchors(repo, memory_path)

    assert not passed
    assert "reachable from HEAD" in detail


@pytest.mark.parametrize(
    ("failure", "expected_detail"),
    [
        ("source-not-commit", "source_commit is not a Git commit"),
        ("evidence-not-commit", "git_commit is not a Git commit"),
        ("missing-path", "path is not a historical Git blob"),
        ("hash-mismatch", "sha256 does not match the historical Git blob"),
    ],
)
def test_research_memory_git_anchor_failures_are_reported(
    tmp_path: Path,
    failure: str,
    expected_detail: str,
) -> None:
    repo, commit, blob, evidence_bytes = _fixture_git_repo(tmp_path)
    source_commit = blob if failure == "source-not-commit" else commit
    evidence_commit = blob if failure == "evidence-not-commit" else commit
    evidence_uri = "evidence/missing.txt" if failure == "missing-path" else "evidence/source.txt"
    evidence_hash = "0" * 64 if failure == "hash-mismatch" else sha256_bytes(evidence_bytes)
    evidence = MemoryEvidenceRef(
        role="source",
        uri=evidence_uri,
        sha256=evidence_hash,
        git_commit=evidence_commit,
        media_type="text/plain",
        access=AccessClass.INTERNAL,
        label_access=LabelAccess.NONE,
    )
    memory_path = _write_memory(repo, source_commit=source_commit, evidence=(evidence,))

    passed, detail = _verify_memory_git_anchors(repo, memory_path)

    assert not passed
    assert expected_detail in detail


@pytest.mark.parametrize(
    ("wrapper", "dependency", "arguments", "expected"),
    [
        (
            "_authenticated_artifact_bytes",
            "authenticated_artifact_bytes",
            {
                "url": "https://example.invalid/artifact.whl",
                "expected_sha256": "0" * 64,
                "expected_size": 1,
                "cache_root": Path("cache"),
                "cache_namespace": "fixture",
            },
            None,
        ),
        (
            "_locked_gate_control_packages",
            "resolve_locked_packages",
            {"lock": {}},
            None,
        ),
        (
            "_locked_gate_control_wheels",
            "resolve_locked_wheels",
            {"lock": {}},
            None,
        ),
        (
            "_extract_authenticated_wheels",
            "extract_authenticated_wheels",
            {"artifacts": (), "site_packages": Path("site-packages")},
            False,
        ),
        (
            "_prepare_gate_control_runner",
            "prepare_authenticated_runner",
            {"snapshot_root": Path("snapshot")},
            None,
        ),
    ],
)
def test_gate_control_trust_adapters_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    wrapper: str,
    dependency: str,
    arguments: dict[str, object],
    expected: object,
) -> None:
    def reject(*_args: object, **_kwargs: object) -> None:
        raise mission_module.runner_trust.RunnerTrustError("fixture rejection")

    monkeypatch.setattr(mission_module.runner_trust, dependency, reject)
    monkeypatch.setattr(mission_module, "platform_tags", lambda: ())

    assert getattr(mission_module, wrapper)(**arguments) is expected


@pytest.mark.parametrize(
    ("wrapper", "dependency", "arguments"),
    [
        (
            "_authenticated_artifact_bytes",
            "authenticated_artifact_bytes",
            {
                "url": "https://example.invalid/artifact.whl",
                "expected_sha256": "0" * 64,
                "expected_size": 1,
                "cache_root": Path("cache"),
                "cache_namespace": "fixture",
            },
        ),
        (
            "_prepare_gate_control_runner",
            "prepare_authenticated_runner",
            {"snapshot_root": Path("snapshot")},
        ),
    ],
)
def test_gate_control_acquisition_adapters_preserve_typed_failure(
    monkeypatch: pytest.MonkeyPatch,
    wrapper: str,
    dependency: str,
    arguments: dict[str, object],
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise mission_module.runner_trust.RunnerAcquisitionError("fixture acquisition")

    monkeypatch.setattr(mission_module.runner_trust, dependency, unavailable)

    with pytest.raises(
        mission_module.runner_trust.RunnerAcquisitionError,
        match="fixture acquisition",
    ):
        getattr(mission_module, wrapper)(**arguments)


def test_gate_control_snapshot_and_source_seal_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        _gate_control_set_hash(
            tmp_path,
            iteration_id="iter000_nasa_adapt_corpus_readiness",
            controls=[],
            sealed_paths=("missing.py",),
        )
        is None
    )

    monkeypatch.setattr(mission_module, "_git_tree_paths", lambda *_args: None)
    assert not _materialize_gate_control_snapshot(tmp_path, git="git", destination=tmp_path / "a")

    monkeypatch.setattr(mission_module, "_git_tree_paths", lambda *_args: [])
    monkeypatch.setattr(mission_module, "_git_blob_at_path", lambda *_args: None)
    assert not _materialize_gate_control_snapshot(tmp_path, git="git", destination=tmp_path / "b")


def test_gate_control_runner_preflight_rejects_missing_or_preexisting_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = SimpleNamespace(
        snapshot_root=tmp_path / "missing-snapshot",
        scratch_root=tmp_path / "scratch",
        python_path=tmp_path / "python",
        site_packages=tmp_path / "site-packages",
    )
    assert not _gate_control_runner_is_unchanged(tmp_path / "missing", runner)

    monkeypatch.setattr(mission_module, "_gate_control_runner_is_unchanged", lambda *_args: False)
    with pytest.raises(OSError, match="changed before child execution"):
        mission_module._run_gate_control_nodes(tmp_path, [], runner)

    monkeypatch.setattr(mission_module, "_gate_control_runner_is_unchanged", lambda *_args: True)
    monkeypatch.setattr(mission_module.runner_trust, "ensure_private_directory", lambda _path: True)
    runner.scratch_root.mkdir()
    (tmp_path / mission_module._GATE_CONTROL_REPORT).write_text("occupied", encoding="utf-8")
    with pytest.raises(OSError, match="report path already exists"):
        mission_module._run_gate_control_nodes(tmp_path, [], runner)


@pytest.mark.parametrize(
    "report",
    [
        None,
        b"not xml",
        b'<testsuite><testcase name="wrong"/></testsuite>',
        b'<testsuite><testcase name="test_expected"><failure/></testcase></testsuite>',
    ],
)
def test_gate_control_report_rejects_missing_malformed_or_nonpassing_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    report: bytes | None,
) -> None:
    monkeypatch.setattr(
        mission_module.runner_trust,
        "stable_regular_bytes",
        lambda *_args, **_kwargs: report,
    )

    assert not mission_module._gate_control_report_is_exact(
        tmp_path,
        ["tests/unit/test_gate.py::test_expected"],
    )


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "LF-terminated framing"),
        (b"\xff\n", "valid UTF-8"),
        (b"{}\n\n", "blank records"),
        (b'{"claim_id":"a","claim_id":"b"}\n', "line 1"),
    ],
)
def test_claim_parser_rejects_ambiguous_or_noncanonical_framing(
    data: bytes,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        mission_module._claims_bytes(data)


def test_git_guards_reject_malformed_identifiers_and_paths_without_spawning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_spawn(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("invalid Git inputs must be rejected before process creation")

    monkeypatch.setattr(mission_module.subprocess, "run", unexpected_spawn)
    invalid = "not-an-object-id"
    valid = "1" * 40

    assert not mission_module._git_commit_resolves(tmp_path, "git", invalid)
    assert mission_module._git_blob_at_path(tmp_path, "git", invalid, "file.txt") is None
    assert mission_module._git_blob_at_path(tmp_path, "git", valid, "../file.txt") is None
    assert not mission_module._git_is_ancestor(tmp_path, "git", invalid, valid)
    assert mission_module._git_object_type(tmp_path, "git", invalid) is None
    assert mission_module._git_tree_id(tmp_path, "git", invalid) is None
    assert mission_module._git_path_object_id(tmp_path, "git", valid, "../tree") is None
    assert mission_module._safe_relative_path(None) is None

    monkeypatch.setattr(mission_module, "_trusted_git", lambda _repo: "git")
    monkeypatch.setattr(
        mission_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="invalid\n"),
    )
    with pytest.raises(ValueError, match="invalid root commit"):
        mission_module._root_commit(tmp_path)


@pytest.mark.parametrize(
    "tree_entry",
    [
        b"\xff blob " + b"1" * 40 + b"\tfile.txt\0",
        b"100644 blob " + b"1" * 40 + b"\t\xff\0",
        b"100644 blob " + b"1" * 40 + b" file.txt\0",
        b"040000 tree " + b"1" * 40 + b"\tfile.txt\0",
        b"100644 blob short\tfile.txt\0",
    ],
)
def test_git_blob_reader_rejects_malformed_tree_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tree_entry: bytes,
) -> None:
    monkeypatch.setattr(
        mission_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=tree_entry),
    )

    assert mission_module._git_blob_at_path(tmp_path, "git", "1" * 40, "file.txt") is None


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (1, b""),
        (0, b"\xff\0"),
        (0, b"outside/file.py\0"),
        (0, b"src/fieldtrue/../escape.py\0"),
    ],
)
def test_git_tree_census_rejects_failed_or_unsafe_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    stdout: bytes,
) -> None:
    monkeypatch.setattr(
        mission_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=returncode, stdout=stdout),
    )

    assert (
        mission_module._git_tree_paths(
            tmp_path,
            "git",
            "1" * 40,
            "src/fieldtrue",
        )
        is None
    )


def test_working_source_census_rejects_links_cache_payloads_and_special_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing_repo = tmp_path / "missing"
    missing_repo.mkdir()
    assert mission_module._working_source_paths(missing_repo) is None

    linked_repo = tmp_path / "linked"
    linked_repo.mkdir()
    linked_target = tmp_path / "linked-target"
    linked_target.mkdir()
    (linked_repo / "src").mkdir()
    (linked_repo / "src" / "fieldtrue").symlink_to(linked_target, target_is_directory=True)
    assert mission_module._working_source_paths(linked_repo) is None

    candidate_repo = tmp_path / "candidate"
    source_root = candidate_repo / "src" / "fieldtrue"
    source_root.mkdir(parents=True)
    external = tmp_path / "external.py"
    external.write_text("VALUE = 1\n", encoding="utf-8")
    (source_root / "linked.py").symlink_to(external)
    assert mission_module._working_source_paths(candidate_repo) is None

    cache_repo = tmp_path / "cache"
    cache_root = cache_repo / "src" / "fieldtrue" / "__pycache__"
    cache_root.mkdir(parents=True)
    (cache_root / "payload.txt").write_text("not bytecode\n", encoding="utf-8")
    assert mission_module._working_source_paths(cache_repo) is None

    valid_repo = tmp_path / "valid"
    valid_root = valid_repo / "src" / "fieldtrue"
    (valid_root / "__pycache__").mkdir(parents=True)
    (valid_root / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (valid_root / "__pycache__" / "module.pyc").write_bytes(b"fixture")
    assert mission_module._working_source_paths(valid_repo) == {"src/fieldtrue/module.py"}

    special_repo = tmp_path / "special"
    special_root = special_repo / "src" / "fieldtrue"
    special_root.mkdir(parents=True)
    mission_module.os.mkfifo(special_root / "source.pipe")
    assert mission_module._working_source_paths(special_repo) is None

    unreadable_repo = tmp_path / "unreadable"
    unreadable_root = unreadable_repo / "src" / "fieldtrue"
    unreadable_root.mkdir(parents=True)
    original_rglob = Path.rglob

    def unreadable_rglob(path: Path, pattern: str) -> object:
        if path == unreadable_root:
            raise OSError("fixture traversal failure")
        return original_rglob(path, pattern)

    monkeypatch.setattr(Path, "rglob", unreadable_rglob)
    assert mission_module._working_source_paths(unreadable_repo) is None


def test_regular_repository_reader_rejects_unsafe_nonregular_oversize_and_racing_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="path is unsafe"):
        mission_module._read_repo_regular_file(tmp_path, "../outside")

    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(ValueError, match="must be regular"):
        mission_module._read_repo_regular_file(tmp_path, "directory")

    oversized = tmp_path / "oversized.bin"
    with oversized.open("wb") as handle:
        handle.truncate(mission_module._MAX_PUBLICATION_TRUST_INPUT_BYTES + 1)
    with pytest.raises(ValueError, match="size limit"):
        mission_module._read_repo_regular_file(tmp_path, "oversized.bin")

    stable = tmp_path / "stable.bin"
    stable.write_bytes(b"stable")
    original_fstat = mission_module.os.fstat
    calls = 0

    def changed_fstat(file_descriptor: int) -> object:
        nonlocal calls
        observed = original_fstat(file_descriptor)
        calls += 1
        if calls != 2:
            return observed
        return SimpleNamespace(
            st_mode=observed.st_mode,
            st_dev=observed.st_dev,
            st_ino=observed.st_ino,
            st_size=observed.st_size,
            st_mtime_ns=observed.st_mtime_ns + 1,
            st_ctime_ns=observed.st_ctime_ns,
        )

    monkeypatch.setattr(mission_module.os, "fstat", changed_fstat)
    with pytest.raises(ValueError, match="changed while being read"):
        mission_module._read_repo_regular_file(tmp_path, "stable.bin")


def test_memory_anchor_verifier_rejects_initial_and_final_git_identity_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    memory_path = tmp_path / "memory.jsonl"
    monkeypatch.setattr(mission_module, "load_memory_records", lambda _path: [])

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module,
            "_trusted_git",
            lambda _repo: (_ for _ in ()).throw(ValueError("untrusted")),
        )
        passed, detail = _verify_memory_git_anchors(tmp_path, memory_path)
        assert not passed
        assert "Git trust failed" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_trusted_git", lambda _repo: "git")
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("unavailable")),
        )
        passed, detail = _verify_memory_git_anchors(tmp_path, memory_path)
        assert not passed
        assert "HEAD cannot be captured" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_trusted_git", lambda _repo: "git")
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(stdout="invalid\n"),
        )
        passed, detail = _verify_memory_git_anchors(tmp_path, memory_path)
        assert not passed
        assert "invalid object identity" in detail

    trust_reads = 0

    def changing_trust(_repo: Path) -> str:
        nonlocal trust_reads
        trust_reads += 1
        if trust_reads == 2:
            raise ValueError("changed")
        return "git"

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_trusted_git", changing_trust)
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(stdout="1" * 40 + "\n"),
        )
        passed, detail = _verify_memory_git_anchors(tmp_path, memory_path)
        assert not passed
        assert "trust changed" in detail

    head_reads = iter(("1" * 40 + "\n", "2" * 40 + "\n"))
    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_trusted_git", lambda _repo: "git")
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(stdout=next(head_reads)),
        )
        passed, detail = _verify_memory_git_anchors(tmp_path, memory_path)
        assert not passed
        assert "HEAD changed" in detail


def test_memory_anchor_verifier_ignores_external_evidence_uris(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = SimpleNamespace(
        event_id="event-1",
        source_commit="1" * 40,
        evidence=(
            SimpleNamespace(
                uri="https://example.invalid/evidence",
                git_commit=None,
                sha256=None,
            ),
        ),
    )
    monkeypatch.setattr(mission_module, "load_memory_records", lambda _path: [record])
    monkeypatch.setattr(mission_module, "_trusted_git", lambda _repo: "git")
    monkeypatch.setattr(mission_module, "_git_commit_resolves", lambda *_args: True)
    monkeypatch.setattr(mission_module, "_git_is_ancestor", lambda *_args: True)
    monkeypatch.setattr(
        mission_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="1" * 40 + "\n"),
    )

    passed, detail = _verify_memory_git_anchors(tmp_path, tmp_path / "memory.jsonl")

    assert passed
    assert detail == "Research memory Git anchors verify (1 event)."


def test_iteration_history_reports_each_git_integrity_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clean_replacements = SimpleNamespace(returncode=0, stdout="")
    expected_trees = {
        mission_module._ITER000_ATTEMPT_001_EXECUTION_COMMIT: (
            mission_module._ITER000_ATTEMPT_001_EXECUTION_TREE
        ),
        mission_module._ITER000_PROOF_COMMIT: mission_module._ITER000_PROOF_COMMIT_TREE,
        mission_module._ITER000_VERIFICATION_CONTRACT_COMMIT: (
            mission_module._ITER000_VERIFICATION_CONTRACT_TREE
        ),
        mission_module._ITER000_VERIFICATION_CORRECTION_COMMIT: (
            mission_module._ITER000_VERIFICATION_CORRECTION_TREE
        ),
    }
    head = "f" * 40

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(returncode=1, stdout=""),
        )
        passed, detail = mission_module._verify_iter000_history(tmp_path, "git", head)
        assert not passed
        assert "replacement objects" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: clean_replacements,
        )
        scoped.setattr(mission_module, "_git_object_type", lambda *_args: None)
        passed, detail = mission_module._verify_iter000_history(tmp_path, "git", head)
        assert not passed
        assert "historical commit is unavailable" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: clean_replacements,
        )
        scoped.setattr(mission_module, "_git_object_type", lambda *_args: "commit")
        scoped.setattr(mission_module, "_git_tree_id", lambda *_args: None)
        passed, detail = mission_module._verify_iter000_history(tmp_path, "git", head)
        assert not passed
        assert "commit tree differs" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: clean_replacements,
        )
        scoped.setattr(mission_module, "_git_object_type", lambda *_args: "commit")
        scoped.setattr(
            mission_module,
            "_git_tree_id",
            lambda _repo, _git, commit: expected_trees.get(commit),
        )
        scoped.setattr(mission_module, "_git_is_ancestor", lambda *_args: False)
        passed, detail = mission_module._verify_iter000_history(tmp_path, "git", head)
        assert not passed
        assert "ancestry chain" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: clean_replacements,
        )
        scoped.setattr(mission_module, "_git_object_type", lambda *_args: "commit")
        scoped.setattr(
            mission_module,
            "_git_tree_id",
            lambda _repo, _git, commit: expected_trees.get(commit),
        )
        scoped.setattr(
            mission_module,
            "_git_is_ancestor",
            lambda _repo, _git, _ancestor, descendant: descendant != head,
        )
        passed, detail = mission_module._verify_iter000_history(tmp_path, "git", head)
        assert not passed
        assert "not an ancestor of HEAD" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: clean_replacements,
        )
        scoped.setattr(mission_module, "_git_object_type", lambda *_args: "commit")
        scoped.setattr(
            mission_module,
            "_git_tree_id",
            lambda _repo, _git, commit: expected_trees.get(commit),
        )
        scoped.setattr(mission_module, "_git_is_ancestor", lambda *_args: True)
        scoped.setattr(mission_module, "_git_path_object_id", lambda *_args: None)
        passed, detail = mission_module._verify_iter000_history(tmp_path, "git", head)
        assert not passed
        assert "execution source tree differs" in detail


def test_current_credibility_registry_rejects_invalid_head_coverage_and_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = _credibility_control_repo(tmp_path, monkeypatch)
    registry_path = repo / mission_module._CREDIBILITY_GATE_CONTROL_PATH
    document = json.loads(registry_path.read_bytes())

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_trusted_git", lambda _repo: "git")
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(stdout="invalid\n"),
        )
        passed, detail = _verify_credibility_gate_control_registry(repo)
        assert not passed
        assert "valid Git HEAD" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module,
            "_REQUIRED_BOOTSTRAP_CLAIM_DIGESTS",
            {**mission_module._REQUIRED_BOOTSTRAP_CLAIM_DIGESTS, "uncovered.claim": "0" * 64},
        )
        scoped.setattr(
            mission_module,
            "_expected_credibility_gate_control_registry",
            lambda: document,
        )
        passed, detail = _verify_credibility_gate_control_registry(repo)
        assert not passed
        assert "do not cover the exact bootstrap claims" in detail

    original_run = mission_module.subprocess.run
    head_reads = 0

    def changing_head(*args: object, **kwargs: object) -> object:
        nonlocal head_reads
        result = original_run(*args, **kwargs)
        command = args[0]
        if isinstance(command, list) and command[1:4] == [
            "rev-parse",
            "--verify",
            "HEAD^{commit}",
        ]:
            head_reads += 1
            if head_reads == 2:
                return SimpleNamespace(stdout="0" * 40 + "\n", returncode=0)
        return result

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module.subprocess, "run", changing_head)
        passed, detail = _verify_credibility_gate_control_registry(repo)
        assert not passed
        assert "Git HEAD changed" in detail

    original_read = mission_module._read_repo_regular_file
    registry_reads = 0

    def changing_registry(repo_root: Path, relative: str) -> bytes:
        nonlocal registry_reads
        value = original_read(repo_root, relative)
        if relative == mission_module._CREDIBILITY_GATE_CONTROL_PATH:
            registry_reads += 1
            if registry_reads == 2:
                return value + b" "
        return value

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_read_repo_regular_file", changing_registry)
        passed, detail = _verify_credibility_gate_control_registry(repo)
        assert not passed
        assert "registry changed" in detail

    target_test = document["controls"][0]["positive_control"].split("::", maxsplit=1)[0]
    test_reads = 0

    def changing_test(repo_root: Path, relative: str) -> bytes:
        nonlocal test_reads
        value = original_read(repo_root, relative)
        if relative == target_test:
            test_reads += 1
            if test_reads == 2:
                return value + b"\n"
        return value

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_read_repo_regular_file", changing_test)
        passed, detail = _verify_credibility_gate_control_registry(repo)
        assert not passed
        assert "test changed" in detail


def test_claim_registry_rejects_invalid_head_lineage_evidence_sets_and_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, digests, evidence_digests, registry_digest = _claim_contract_repo(tmp_path)
    _install_claim_contract(monkeypatch, digests, evidence_digests, registry_digest)
    registry_path = repo / "claims" / "registry.jsonl"
    claims = _claims(registry_path)

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_trusted_git", lambda _repo: "git")
        scoped.setattr(
            mission_module.subprocess,
            "run",
            lambda *_args, **_kwargs: SimpleNamespace(stdout="invalid\n"),
        )
        passed, detail = _claim_registry_valid(repo)
        assert not passed
        assert "valid Git HEAD" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_REQUIRED_BOOTSTRAP_REGISTRY_SHA256", "0" * 64)
        passed, detail = _claim_registry_valid(repo)
        assert not passed
        assert "registry bytes differ" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_claims_bytes", lambda _data: [claims[0], claims[0]])
        passed, detail = _claim_registry_valid(repo)
        assert not passed
        assert "nonempty, typed, and unique" in detail

    invalid_successor = claims[1].model_copy(update={"supersedes_claim_id": claims[1].claim_id})
    invalid_claims = [claims[0], invalid_successor]
    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_claims_bytes", lambda _data: invalid_claims)
        scoped.setattr(
            mission_module,
            "_REQUIRED_BOOTSTRAP_CLAIM_DIGESTS",
            {
                claim.claim_id: sha256_value(claim.model_dump(mode="json", exclude_none=True))
                for claim in invalid_claims
            },
        )
        passed, detail = _claim_registry_valid(repo)
        assert not passed
        assert "correction lineage is invalid" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module,
            "_REQUIRED_BOOTSTRAP_EVIDENCE_DIGESTS",
            {**evidence_digests, "evidence/unreviewed.json": "0" * 64},
        )
        passed, detail = _claim_registry_valid(repo)
        assert not passed
        assert "evidence paths differ" in detail

    original_read = mission_module._read_repo_regular_file
    registry_reads = 0

    def changing_registry(repo_root: Path, relative: str) -> bytes:
        nonlocal registry_reads
        value = original_read(repo_root, relative)
        if relative == "claims/registry.jsonl":
            registry_reads += 1
            if registry_reads == 2:
                return value + b" "
        return value

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_read_repo_regular_file", changing_registry)
        passed, detail = _claim_registry_valid(repo)
        assert not passed
        assert "registry changed" in detail

    evidence_reads = 0

    def changing_evidence(repo_root: Path, relative: str) -> bytes:
        nonlocal evidence_reads
        value = original_read(repo_root, relative)
        if relative == "evidence/source.json":
            evidence_reads += 1
            if evidence_reads == 2:
                return value + b" "
        return value

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module, "_read_repo_regular_file", changing_evidence)
        passed, detail = _claim_registry_valid(repo)
        assert not passed
        assert "evidence changed" in detail

    with monkeypatch.context() as scoped:
        scoped.setattr(
            mission_module,
            "_trusted_git",
            lambda _repo: (_ for _ in ()).throw(ValueError("untrusted")),
        )
        passed, detail = _claim_registry_valid(repo)
        assert not passed
        assert "cannot be reconstructed" in detail
