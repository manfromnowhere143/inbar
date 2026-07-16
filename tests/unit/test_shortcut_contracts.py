from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey
from pydantic import ValidationError

import fieldtrue.shortcut_contracts as contracts
from fieldtrue.canonical import canonical_json_pretty, sha256_value
from fieldtrue.shortcut_contracts import (
    AMENDMENT_DOCUMENT_SHA256,
    APPROVED_PROPOSAL_COMMIT,
    MACHINE_PROPOSAL_SHA256,
    OWNER_APPROVAL_ARTIFACT_SHA256,
    OWNER_APPROVAL_PATH,
    OWNER_APPROVAL_RECEIPT_HASH,
    OWNER_PUBLIC_KEY,
    OwnerAmendmentApprovalReceipt,
    ShortcutContractError,
    ShortcutImplementationAuthorityVerification,
    issue_shortcut_attestation,
    load_shortcut_implementation_authority,
    shortcut_attestation_subject_hash,
    verify_shortcut_attestation,
)

NOW = datetime(2026, 7, 15, 16, 0, tzinfo=UTC)


def _repo() -> Path:
    return Path(__file__).resolve().parents[2]


def _receipt_value() -> dict[str, Any]:
    return json.loads((_repo() / OWNER_APPROVAL_PATH).read_bytes())


def _receipt() -> OwnerAmendmentApprovalReceipt:
    return OwnerAmendmentApprovalReceipt.model_validate(_receipt_value())


def test_committed_owner_approval_authorizes_implementation_only() -> None:
    authority = load_shortcut_implementation_authority(_repo(), verified_at=NOW)
    assert authority.proposal_git_commit == APPROVED_PROPOSAL_COMMIT
    assert authority.amendment_document_artifact_sha256 == AMENDMENT_DOCUMENT_SHA256
    assert authority.machine_proposal_artifact_sha256 == MACHINE_PROPOSAL_SHA256
    assert authority.authorized_action == "shortcut_v2_implementation_only"
    assert authority.owner_approval_receipt_artifact_sha256 == OWNER_APPROVAL_ARTIFACT_SHA256
    assert authority.owner_approval_receipt_hash == OWNER_APPROVAL_RECEIPT_HASH
    assert authority.denied_authorities == (
        "production_data_access",
        "target_creation",
        "truth_release",
        "resource_spend",
        "physical_action",
        "training",
        "scientific_result",
        "canonical_seal",
        "publication_transition",
    )
    assert authority.verified_at == NOW


def test_owner_approval_models_reject_naive_times_and_wrong_hashes() -> None:
    value = _receipt_value()
    value["issued_at"] = "2026-07-15T14:00:00"
    with pytest.raises(ValidationError, match="timezone-aware"):
        OwnerAmendmentApprovalReceipt.model_validate(value)

    value = _receipt_value()
    value["receipt_hash"] = "0" * 64
    with pytest.raises(ValidationError, match="receipt hash mismatch"):
        OwnerAmendmentApprovalReceipt.model_validate(value)

    authority = load_shortcut_implementation_authority(_repo(), verified_at=NOW)
    with pytest.raises(ValidationError, match="timezone-aware"):
        ShortcutImplementationAuthorityVerification.model_validate(
            {**authority.model_dump(mode="json"), "verified_at": "2026-07-15T14:00:00"}
        )


def test_verified_authority_rejects_scope_forgery() -> None:
    authority = load_shortcut_implementation_authority(_repo(), verified_at=NOW)
    for field, value in (
        ("proposal_git_commit", "0" * 40),
        ("owner_approval_receipt_artifact_sha256", "0" * 64),
        ("owner_approval_receipt_hash", "0" * 64),
        ("denied_authorities", ()),
    ):
        forged = {**authority.model_dump(mode="json"), field: value}
        with pytest.raises(ValidationError, match="approved implementation scope"):
            ShortcutImplementationAuthorityVerification.model_validate(forged)


def test_owner_approval_body_accepts_an_unvalidated_dictionary() -> None:
    value = _receipt_value()
    body = contracts.owner_approval_body(value)
    assert "receipt_hash" not in body
    assert "signature" not in body
    assert sha256_value(body) == value["receipt_hash"]


def test_authority_loader_rejects_naive_verification_time() -> None:
    with pytest.raises(ShortcutContractError, match="verification time"):
        load_shortcut_implementation_authority(
            _repo(),
            verified_at=datetime(2026, 7, 15, 14, 0),  # noqa: DTZ001
        )

    with pytest.raises(ShortcutContractError, match="predates owner approval"):
        load_shortcut_implementation_authority(
            _repo(),
            verified_at=datetime(2026, 7, 15, 15, 0, tzinfo=UTC),
        )


def test_authority_loader_rejects_uncommitted_receipt_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = contracts._git_blob

    def substitute(root: Path, commit: str, relative: str, label: str) -> bytes:
        if relative == OWNER_APPROVAL_PATH:
            return b"substituted"
        return original(root, commit, relative, label)

    monkeypatch.setattr(contracts, "_git_blob", substitute)
    with pytest.raises(ShortcutContractError, match="not committed"):
        load_shortcut_implementation_authority(_repo(), verified_at=NOW)


def test_authority_loader_rejects_typed_receipt_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    malformed = _receipt_value()
    malformed["owner_actor_id"] = None
    monkeypatch.setattr(
        contracts,
        "_read_regular_file",
        lambda _path, _label: canonical_json_pretty(malformed),
    )
    with pytest.raises(ShortcutContractError, match="typed contract"):
        load_shortcut_implementation_authority(_repo(), verified_at=NOW)


def test_shortcut_attestation_is_domain_separated_and_scope_bound() -> None:
    key = SigningKey.generate()
    subject = {"schema_version": "inbar.test.v1", "value": "evidence"}
    attestation = issue_shortcut_attestation(
        key,
        signer_id="shortcut-reviewer",
        kind="freeze_receipt",
        subject=subject,
    )
    assert attestation.subject_sha256 == shortcut_attestation_subject_hash(
        "freeze_receipt", subject
    )
    verify_shortcut_attestation(
        attestation,
        expected_kind="freeze_receipt",
        expected_subject=subject,
        expected_signer_id="shortcut-reviewer",
        expected_public_key=key.verify_key.encode().hex(),
    )


def test_shortcut_attestation_exposes_no_unsigned_identity_or_chronology_metadata() -> None:
    key = SigningKey.generate()
    attestation = issue_shortcut_attestation(
        key,
        signer_id="shortcut-reviewer",
        kind="freeze_receipt",
        subject={"value": "evidence"},
    )
    assert "attestation_id" not in type(attestation).model_fields
    assert "issued_at" not in type(attestation).model_fields


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"expected_kind": "target_receipt"}, "scope or signer"),
        ({"expected_subject": {"value": "changed"}}, "scope or signer"),
        ({"expected_signer_id": "substitute"}, "scope or signer"),
        ({"expected_public_key": OWNER_PUBLIC_KEY}, "scope or signer"),
    ],
)
def test_shortcut_attestation_rejects_scope_signer_and_time_substitution(
    change: dict[str, object],
    message: str,
) -> None:
    key = SigningKey.generate()
    subject = {"value": "evidence"}
    attestation = issue_shortcut_attestation(
        key,
        signer_id="shortcut-reviewer",
        kind="freeze_receipt",
        subject=subject,
    )
    arguments: dict[str, object] = {
        "expected_kind": "freeze_receipt",
        "expected_subject": subject,
        "expected_signer_id": "shortcut-reviewer",
        "expected_public_key": key.verify_key.encode().hex(),
    }
    arguments.update(change)
    with pytest.raises(ShortcutContractError, match=message):
        verify_shortcut_attestation(attestation, **arguments)  # type: ignore[arg-type]


def test_shortcut_attestation_rejects_signature_substitution() -> None:
    key = SigningKey.generate()
    subject = {"value": "evidence"}
    attestation = issue_shortcut_attestation(
        key,
        signer_id="shortcut-reviewer",
        kind="freeze_receipt",
        subject=subject,
    )
    forged = attestation.model_copy(update={"signature": "0" * 128})
    with pytest.raises(ShortcutContractError, match="signature"):
        verify_shortcut_attestation(
            forged,
            expected_kind="freeze_receipt",
            expected_subject=subject,
            expected_signer_id="shortcut-reviewer",
            expected_public_key=key.verify_key.encode().hex(),
        )


def test_shortcut_attestation_rejects_validator_bypassed_schema_version() -> None:
    key = SigningKey.generate()
    subject = {"value": "evidence"}
    attestation = issue_shortcut_attestation(
        key,
        signer_id="shortcut-reviewer",
        kind="freeze_receipt",
        subject=subject,
    )
    forged = attestation.model_copy(
        update={"schema_version": "inbar.iter001.shortcut-attestation.v2"}
    )

    with pytest.raises(ShortcutContractError, match="typed contract"):
        verify_shortcut_attestation(
            forged,
            expected_kind="freeze_receipt",
            expected_subject=subject,
            expected_signer_id="shortcut-reviewer",
            expected_public_key=key.verify_key.encode().hex(),
        )


def test_owner_scope_and_signature_substitutions_fail_closed() -> None:
    receipt = _receipt()
    with pytest.raises(ShortcutContractError, match="approved implementation scope"):
        contracts._verify_owner_receipt_scope_and_signature(
            receipt.model_copy(update={"owner_actor_id": "substitute"})
        )
    with pytest.raises(ShortcutContractError, match="signature mismatch"):
        contracts._verify_owner_receipt_scope_and_signature(
            receipt.model_copy(update={"signature": "0" * 128})
        )


@pytest.mark.parametrize(
    ("substituted_label", "message"),
    [
        ("amendment document", "amendment document hash"),
        ("machine proposal", "machine proposal hash"),
        ("owner anchor", "owner anchor hash"),
    ],
)
def test_proposal_verification_rejects_substituted_git_bytes(
    monkeypatch: pytest.MonkeyPatch,
    substituted_label: str,
    message: str,
) -> None:
    original = contracts._git_blob

    def substitute(root: Path, commit: str, relative: str, label: str) -> bytes:
        if label == substituted_label:
            return b"substituted"
        return original(root, commit, relative, label)

    monkeypatch.setattr(contracts, "_git_blob", substitute)
    with pytest.raises(ShortcutContractError, match=message):
        contracts._verify_proposal_and_owner_anchor(_repo(), _receipt())


def test_proposal_verification_rejects_broken_cross_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = contracts._canonical_json_object

    def substitute(data: bytes, label: str, *, require_pretty: bool = True) -> dict[str, Any]:
        value = original(data, label, require_pretty=require_pretty)
        if label == "machine proposal":
            value["amendment_document"] = {}
        return value

    monkeypatch.setattr(contracts, "_canonical_json_object", substitute)
    with pytest.raises(ShortcutContractError, match="does not bind"):
        contracts._verify_proposal_and_owner_anchor(_repo(), _receipt())

    def substitute_anchor(
        data: bytes, label: str, *, require_pretty: bool = True
    ) -> dict[str, Any]:
        value = original(data, label, require_pretty=require_pretty)
        if label == "owner anchor":
            value["trust_anchor_public_key"] = "0" * 64
        return value

    monkeypatch.setattr(contracts, "_canonical_json_object", substitute_anchor)
    with pytest.raises(ShortcutContractError, match="approved public key"):
        contracts._verify_proposal_and_owner_anchor(_repo(), _receipt())


def test_regular_file_reader_rejects_missing_symlink_size_and_read_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ShortcutContractError, match="unavailable"):
        contracts._read_regular_file(tmp_path / "missing", "receipt")

    target = tmp_path / "target"
    target.write_bytes(b"{}")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(ShortcutContractError, match="regular file"):
        contracts._read_regular_file(link, "receipt")
    with pytest.raises(ShortcutContractError, match="regular file"):
        contracts._read_regular_file(tmp_path, "receipt")

    oversized = tmp_path / "oversized"
    oversized.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ShortcutContractError, match="byte limit"):
        contracts._read_regular_file(oversized, "receipt")

    readable = tmp_path / "readable"
    readable.write_bytes(b"{}")
    original = Path.read_bytes

    def fail_read(path: Path) -> bytes:
        if path == readable:
            raise OSError("unavailable")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", fail_read)
    with pytest.raises(ShortcutContractError, match="cannot be read"):
        contracts._read_regular_file(readable, "receipt")


def test_regular_file_reader_rejects_changed_length(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "receipt"
    path.write_bytes(b"{}")
    monkeypatch.setattr(Path, "read_bytes", lambda _path: b"changed")
    with pytest.raises(ShortcutContractError, match="changed while being read"):
        contracts._read_regular_file(path, "receipt")


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xff", "valid UTF-8 JSON"),
        (b"[]", "JSON object"),
        (b'{"value":1}', "canonical pretty JSON"),
        (b'{"value":1,"value":2}', "duplicate object keys"),
    ],
)
def test_canonical_json_object_rejects_ambiguous_inputs(data: bytes, message: str) -> None:
    with pytest.raises(ShortcutContractError, match=message):
        contracts._canonical_json_object(data, "authority")


def test_git_blob_rejects_missing_git_failed_reads_and_oversize(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    trusted_git = contracts._TRUSTED_GIT_PATH
    monkeypatch.setattr(contracts, "_TRUSTED_GIT_PATH", tmp_path / "missing-git")
    with pytest.raises(ShortcutContractError, match="system Git is unavailable"):
        contracts._git_blob(_repo(), "HEAD", OWNER_APPROVAL_PATH, "receipt")

    monkeypatch.setattr(contracts, "_TRUSTED_GIT_PATH", trusted_git)

    def fail_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.CalledProcessError(1, ["git"])

    monkeypatch.setattr(contracts.subprocess, "run", fail_run)
    with pytest.raises(ShortcutContractError, match="unavailable"):
        contracts._git_blob(_repo(), "HEAD", OWNER_APPROVAL_PATH, "receipt")

    monkeypatch.setattr(
        contracts.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            ["git"], 0, stdout=b"x" * (2 * 1024 * 1024 + 1), stderr=b""
        ),
    )
    with pytest.raises(ShortcutContractError, match="byte limit"):
        contracts._git_blob(_repo(), "HEAD", OWNER_APPROVAL_PATH, "receipt")


def test_git_history_requires_exact_worktree_root_and_approved_ancestry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contracts._verify_git_history(_repo())
    original = contracts.subprocess.run

    with monkeypatch.context() as scoped:
        scoped.setattr(
            contracts,
            "verify_repository_trust",
            lambda *_args: (_ for _ in ()).throw(
                contracts.GitTrustError("repository or object directory is redirected")
            ),
        )
        with pytest.raises(ShortcutContractError, match="authority Git trust failed"):
            contracts._verify_git_history(_repo())

    def reject_ancestry(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        command = args[0]
        if isinstance(command, list) and "merge-base" in command:
            return subprocess.CompletedProcess(command, 1, stdout="", stderr="")
        return original(*args, **kwargs)  # type: ignore[return-value]

    with monkeypatch.context() as scoped:
        scoped.setattr(contracts.subprocess, "run", reject_ancestry)
        with pytest.raises(ShortcutContractError, match="not an ancestor"):
            contracts._verify_git_history(_repo())


def test_git_authority_ignores_inherited_repository_redirection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_DIR", "/does/not/exist")
    monkeypatch.setenv("GIT_WORK_TREE", "/does/not/exist")
    authority = load_shortcut_implementation_authority(_repo(), verified_at=NOW)
    assert authority.authorized_action == "shortcut_v2_implementation_only"


def test_git_authority_ignores_path_executable_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_git = tmp_path / "git"
    fake_git.write_text("#!/bin/sh\nexit 99\n")
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    authority = load_shortcut_implementation_authority(_repo(), verified_at=NOW)

    assert authority.authorized_action == "shortcut_v2_implementation_only"


def test_git_authority_rejects_unsafe_system_git_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsafe_git = tmp_path / "git"
    unsafe_git.write_text("#!/bin/sh\nexit 0\n")
    unsafe_git.chmod(0o777)
    monkeypatch.setattr(contracts, "_TRUSTED_GIT_PATH", unsafe_git)

    with pytest.raises(ShortcutContractError, match="unsafe ownership or mode"):
        contracts._trusted_git_executable()


def test_git_authority_maps_shared_history_trust_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        contracts,
        "verify_repository_trust",
        lambda *_args: (_ for _ in ()).throw(contracts.GitTrustError("graft state is forbidden")),
    )
    with pytest.raises(ShortcutContractError, match="graft state is forbidden"):
        contracts._verify_git_history(_repo())


def test_git_authority_rejects_head_change_during_verification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    head = subprocess.run(
        ["/usr/bin/git", "rev-parse", "HEAD"],
        cwd=_repo(),
        check=True,
        capture_output=True,
        env=contracts._git_environment(),
        text=True,
        timeout=10,
    ).stdout.strip()
    observed = iter((head, "f" * len(head)))
    monkeypatch.setattr(contracts, "_verify_git_history", lambda _repo_root: next(observed))

    with pytest.raises(ShortcutContractError, match="HEAD changed"):
        load_shortcut_implementation_authority(_repo(), verified_at=NOW)


def test_git_authority_rejects_a_real_alternate_object_database(tmp_path: Path) -> None:
    clone = tmp_path / "authority-clone"
    subprocess.run(  # noqa: S603 - fixed Git path and test-controlled repository paths
        ["/usr/bin/git", "clone", "--quiet", "--no-local", str(_repo()), str(clone)],
        check=True,
        env={**contracts._git_environment(), "GIT_ALLOW_PROTOCOL": "file"},
        timeout=30,
    )
    alternates = clone / ".git" / "objects" / "info" / "alternates"
    alternates.parent.mkdir(parents=True, exist_ok=True)
    alternates.write_text(f"{_repo() / '.git' / 'objects'}\n", encoding="utf-8")

    with pytest.raises(ShortcutContractError, match="alternate-object state is forbidden"):
        load_shortcut_implementation_authority(clone, verified_at=NOW)
