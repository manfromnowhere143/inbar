from __future__ import annotations

import json
import shutil
import ssl
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

import fieldtrue.mission as mission_module
from fieldtrue.canonical import canonical_json_pretty, sha256_bytes, sha256_value
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
    _claims,
    _control_node_is_substantive,
    _first_commit_files,
    _gate_control_set_hash,
    _gate_controls_valid,
    _json,
    _pytest_node_exists,
    _root_preregistration_bytes,
    _verified_tls_runtime_active,
    _verify_gate_control_registry,
    _verify_iteration_amendment_001,
    _verify_memory_git_anchors,
    _verify_publication_transition,
    validate_mission,
)
from fieldtrue.receipts import LedgerVerificationError, write_signer_anchor


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
    _git(repo, "config", "user.name", "Fieldtrue Test")
    _git(repo, "config", "user.email", "fieldtrue@example.invalid")
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
    changed_paths = (
        "experiments/iter000_nasa_adapt_corpus_readiness/AMENDMENT_001.md",
        "experiments/iter000_nasa_adapt_corpus_readiness/proof/attempt_000/execution_ledger.jsonl",
        "experiments/iter000_nasa_adapt_corpus_readiness/proof/attempt_000/execution_ledger.head.json",
        "protocol/amendments/iter000_001.json",
        "protocol/attempt_authorities/iter000_001.json",
        "pyproject.toml",
        "src/fieldtrue/adapters/adapt.py",
        "src/fieldtrue/cli.py",
        "src/fieldtrue/experiment.py",
        "src/fieldtrue/mission.py",
        "src/fieldtrue/verification.py",
        "uv.lock",
    )
    for relative in changed_paths:
        destination = repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, destination)
    authority_path = repo / "protocol" / "attempt_authorities" / "iter000_001.json"
    authority = json.loads(authority_path.read_text())
    schema_paths = {
        path.relative_to(repo).as_posix() for path in (repo / "protocol" / "schemas").glob("*.json")
    }
    protocol_paths = mission_module._ITER000_ATTEMPT_001_PROTOCOL_PATHS | schema_paths
    authority["protocol_hashes"] = {
        relative: sha256_bytes((repo / relative).read_bytes())
        for relative in sorted(protocol_paths)
    }
    authority_path.write_bytes(canonical_json_pretty(authority))
    _git(repo, "add", *changed_paths)
    if _git(repo, "status", "--porcelain"):
        _git(repo, "commit", "--quiet", "-m", "authorize amendment fixture")
    return repo


def test_real_mission_invariants_are_individually_reported() -> None:
    repo = _repo()
    validation = validate_mission(repo)
    checks = {check.check_id: check for check in validation.checks}
    assert checks["owner-boundary"].passed
    assert checks["execution-authority"].passed
    assert checks["preregistration-first"].passed
    assert checks["hypothesis-status"].passed
    assert checks["dataset-lock"].passed
    assert checks["claim-registry"].passed
    assert checks["gate-falsification"].passed
    assert checks["gate-control-registry"].passed
    assert "research-memory-git-anchors" in checks
    assert checks["signer-anchor"].passed
    assert checks["provider-independence"].passed
    assert validation.passed == all(check.passed for check in validation.checks)


def test_amendment_001_authorizes_only_the_committed_predata_failure(
    tmp_path: Path,
) -> None:
    repo = _committed_amendment_repo(tmp_path)

    passed, detail = _verify_iteration_amendment_001(repo)

    assert passed
    assert "one isolated certifi-backed retry" in detail


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
        scoped.setattr(mission_module.shutil, "which", lambda _name: None)
        passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "without Git" in detail

    def fail_subprocess(*_args: object, **_kwargs: object) -> object:
        raise subprocess.CalledProcessError(1, "git")

    with monkeypatch.context() as scoped:
        scoped.setattr(mission_module.subprocess, "run", fail_subprocess)
        passed, detail = _verify_iteration_amendment_001(repo)
    assert not passed
    assert "cannot resolve HEAD" in detail

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


def test_gate_control_registry_resolves_executable_pytest_nodes(tmp_path: Path) -> None:
    repo = _repo()
    registry = repo / "protocol" / "gate_controls" / "v1.json"
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

    def timeout(*_args: object, **_kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="pytest", timeout=120)

    monkeypatch.setattr(mission_module.subprocess, "run", timeout)
    passed, detail = _verify_gate_control_registry(repo, registry)
    assert not passed
    assert "TimeoutExpired" in detail

    monkeypatch.setattr(
        mission_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="failed control",
            stderr="",
        ),
    )
    passed, detail = _verify_gate_control_registry(repo, registry)
    assert not passed
    assert "failed control" in detail


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
    write_signer_anchor(
        repo / anchor_relative,
        key,
        anchor_id="publication-transition",
        ledger_scope="publication-gates",
    )
    receipt_body = {
        "schema_version": "fieldtrue.publication-gate-receipt.v1",
        "mission_id": "fieldtrue",
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
    _git(repo, "add", anchor_relative, receipt_relative, "mission/loop.json")
    _git(repo, "commit", "--quiet", "-m", "authorize publication transition")

    passed, detail = _verify_publication_transition(repo, authorized_loop, set(requirements))
    assert passed
    assert "signed" in detail

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
