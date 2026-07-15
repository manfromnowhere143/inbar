from __future__ import annotations

import os
import socket
import tempfile
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from nacl.signing import SigningKey

import fieldtrue.terminal_authority as authority
from fieldtrue.acquisition import ArtifactBinding, AttestationSubjectKind, attestation_subject_hash
from fieldtrue.canonical import sha256_bytes, sha256_value
from fieldtrue.terminal_authority import (
    AcquisitionInputEntry,
    AcquisitionInputManifest,
    AdmissionInvalidityRecord,
    AdmissionTerminalRecord,
    AdmissionVerifierCertificate,
    InputSnapshotLimits,
    TerminalAuthorityError,
    ensure_disjoint_roots,
    input_manifest_root,
    issue_admission_terminal_record,
    issue_admission_verifier_certificate,
    snapshot_acquisition_input,
    verify_admission_terminal_signature,
    verify_admission_verifier_certificate,
    verify_bound_artifact,
    verify_input_manifest_replay,
)

HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64
HASH_D = "d" * 64
GIT_A = "a" * 40
GIT_B = "b" * 40
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=UTC)


def _entry(path: str, content: bytes, *, mode: int = 0o644) -> AcquisitionInputEntry:
    return AcquisitionInputEntry(
        path=path,
        sha256=sha256_bytes(content),
        bytes=len(content),
        mode=mode,
    )


def _manifest(*entries: AcquisitionInputEntry) -> AcquisitionInputManifest:
    exact = tuple(entries)
    return AcquisitionInputManifest(
        entries=exact,
        total_bytes=sum(entry.bytes for entry in exact),
        root_sha256=input_manifest_root(exact),
    )


def _certificate(
    root_key: SigningKey,
    verifier_key: SigningKey,
    **overrides: Any,
) -> AdmissionVerifierCertificate:
    values: dict[str, Any] = {
        "certificate_id": "iter001-terminal-verifier-v1",
        "verifier_id": "terminal-verifier",
        "verifier_public_key": verifier_key.verify_key.encode().hex(),
        "validator_git_blob": GIT_A,
        "validator_source_sha256": HASH_A,
        "control_suite_sha256": HASH_B,
        "dependency_lock_sha256": HASH_C,
        "not_before": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(days=1),
        "issued_at": NOW - timedelta(minutes=2),
        "root_signer_id": "governance-root",
    }
    values.update(overrides)
    return issue_admission_verifier_certificate(root_key, **values)


def _binding(path: str, *, digest: str, size: int = 1) -> ArtifactBinding:
    return ArtifactBinding(
        path=path,
        sha256=digest,
        bytes=size,
        media_type="application/json",
    )


def _terminal_record(
    verifier_key: SigningKey,
    certificate: AdmissionVerifierCertificate,
    **overrides: Any,
) -> AdmissionTerminalRecord:
    values: dict[str, Any] = {
        "terminal_id": "iter001-terminal-blocked-001",
        "execution_commit": GIT_A,
        "execution_tree": GIT_B,
        "contract_sha256": HASH_D,
        "verifier_certificate_sha256": sha256_value(certificate),
        "control_suite_sha256": certificate.control_suite_sha256,
        "validator_git_blob": certificate.validator_git_blob,
        "validator_source_sha256": certificate.validator_source_sha256,
        "dependency_lock_sha256": certificate.dependency_lock_sha256,
        "input_manifest": _binding("input-manifest.json", digest=HASH_A),
        "payload_kind": "admission_report",
        "payload": _binding("admission-report.json", digest=HASH_B),
        "rendered_result": _binding("result.txt", digest=HASH_C),
        "produced_at": NOW,
        "verifier_id": certificate.verifier_id,
    }
    values.update(overrides)
    return issue_admission_terminal_record(verifier_key, **values)


@pytest.mark.parametrize(
    "path",
    [
        "/absolute.json",
        "../escape.json",
        "nested/../escape.json",
        "./prefixed.json",
        "nested//alias.json",
        "e\u0301vidence.json",
    ],
)
def test_input_entry_rejects_noncanonical_paths(path: str) -> None:
    with pytest.raises(ValueError, match="normalized NFC relative POSIX"):
        _entry(path, b"evidence")


def test_manifest_derives_exact_total_order_and_root() -> None:
    entries = (
        _entry("A.json", b"first", mode=0o600),
        _entry("nested/evidence.bin", b"second"),
        _entry("\u05e2\u05e0\u05d1\u05e8.json", b"third"),
    )

    manifest = _manifest(*entries)

    assert manifest.total_bytes == sum(entry.bytes for entry in entries)
    assert manifest.root_sha256 == sha256_value(
        {
            "domain": "fieldtrue.acquisition-input-manifest-root.v1",
            "root_algorithm": "sha256-canonical-path-content-v1",
            "entries": [entry.model_dump(mode="json") for entry in entries],
        }
    )


def test_manifest_rejects_order_duplicate_case_total_and_root_mutations() -> None:
    first = _entry("A.json", b"first")
    second = _entry("b.json", b"second")

    with pytest.raises(ValueError, match="UTF-8 byte order"):
        _manifest(second, first)
    with pytest.raises(ValueError, match="UTF-8 byte order"):
        _manifest(first, first)

    case_alias = _entry("a.json", b"alias")
    case_entries = (first, case_alias)
    with pytest.raises(ValueError, match="case-fold path collision"):
        AcquisitionInputManifest(
            entries=case_entries,
            total_bytes=sum(entry.bytes for entry in case_entries),
            root_sha256=input_manifest_root(case_entries),
        )

    component_aliases = (
        _entry("Dossier/first.json", b"first"),
        _entry("dossier/second.json", b"second"),
    )
    with pytest.raises(ValueError, match="case-fold path collision"):
        AcquisitionInputManifest(
            entries=component_aliases,
            total_bytes=sum(entry.bytes for entry in component_aliases),
            root_sha256=input_manifest_root(component_aliases),
        )

    valid = _manifest(first, second)
    with pytest.raises(ValueError, match="total bytes"):
        AcquisitionInputManifest.model_validate(
            {**valid.model_dump(mode="json"), "total_bytes": valid.total_bytes + 1}
        )
    with pytest.raises(ValueError, match="root digest"):
        AcquisitionInputManifest.model_validate(
            {**valid.model_dump(mode="json"), "root_sha256": HASH_D}
        )


def test_manifest_root_binds_path_content_size_and_mode() -> None:
    baseline = _manifest(_entry("evidence.bin", b"bound", mode=0o640))
    alternatives = (
        _manifest(_entry("renamed.bin", b"bound", mode=0o640)),
        _manifest(_entry("evidence.bin", b"other", mode=0o640)),
        _manifest(_entry("evidence.bin", b"bound", mode=0o600)),
    )

    assert all(candidate.root_sha256 != baseline.root_sha256 for candidate in alternatives)


@pytest.mark.parametrize(
    "values",
    [
        {"max_files": 0},
        {"max_file_bytes": 0},
        {"max_total_bytes": 0},
        {"read_chunk_bytes": 0},
        {"max_file_bytes": 2, "max_total_bytes": 1},
    ],
)
def test_snapshot_limits_must_be_positive_and_coherent(values: dict[str, int]) -> None:
    with pytest.raises(ValueError, match=r"positive|per-file"):
        InputSnapshotLimits(**values)


def test_invalidity_record_requires_an_aware_timestamp_and_stable_code() -> None:
    record = AdmissionInvalidityRecord(
        contract_sha256=HASH_A,
        input_manifest_sha256=HASH_B,
        failure_stage="input_snapshot",
        failure_code="invalid-input-mutation",
        diagnostic_sha256=HASH_C,
        occurred_at=NOW,
    )
    assert record.failure_stage == "input_snapshot"
    assert record.failure_code == "invalid-input-mutation"

    with pytest.raises(ValueError, match="timezone-aware"):
        AdmissionInvalidityRecord.model_validate(
            {**record.model_dump(mode="json"), "occurred_at": "2026-07-15T12:00:00"}
        )
    with pytest.raises(ValueError, match="Input should be"):
        AdmissionInvalidityRecord.model_validate(
            {**record.model_dump(mode="json"), "failure_stage": "arbitrary_exception"}
        )


def test_certificate_is_derived_and_root_signed() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()

    certificate = _certificate(root_key, verifier_key)
    certificate_body = certificate.model_dump(mode="json", exclude={"root_attestation"})

    assert certificate.root_attestation.subject_kind == (
        AttestationSubjectKind.ADMISSION_VERIFIER_CERTIFICATE
    )
    assert certificate.root_attestation.subject_sha256 == attestation_subject_hash(
        AttestationSubjectKind.ADMISSION_VERIFIER_CERTIFICATE,
        certificate_body,
    )
    verify_admission_verifier_certificate(
        certificate,
        expected_root_public_key=root_key.verify_key.encode().hex(),
        at=NOW,
    )


def test_certificate_and_terminal_accept_equivalent_non_utc_aware_times() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()
    local_zone = timezone(timedelta(hours=5, minutes=30))
    local_now = NOW.astimezone(local_zone)
    certificate = _certificate(
        root_key,
        verifier_key,
        not_before=local_now - timedelta(minutes=1),
        expires_at=local_now + timedelta(days=1),
        issued_at=local_now - timedelta(minutes=2),
    )
    record = _terminal_record(verifier_key, certificate, produced_at=local_now)

    verify_admission_terminal_signature(
        record,
        certificate,
        expected_root_public_key=root_key.verify_key.encode().hex(),
    )


def test_certificate_rejects_invalid_time_contracts() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()

    with pytest.raises(ValueError, match=r"naive datetimes|timezone-aware"):
        _certificate(root_key, verifier_key, not_before=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError, match="expiry must follow"):
        _certificate(
            root_key,
            verifier_key,
            not_before=NOW,
            expires_at=NOW,
        )

    certificate = _certificate(root_key, verifier_key)
    with pytest.raises(TerminalAuthorityError, match="verification time must be timezone-aware"):
        verify_admission_verifier_certificate(
            certificate,
            expected_root_public_key=root_key.verify_key.encode().hex(),
            at=NOW.replace(tzinfo=None),
        )
    invalid_times = (
        certificate.not_before - timedelta(microseconds=1),
        certificate.expires_at + timedelta(microseconds=1),
    )
    for when in invalid_times:
        with pytest.raises(TerminalAuthorityError, match="validity window"):
            verify_admission_verifier_certificate(
                certificate,
                expected_root_public_key=root_key.verify_key.encode().hex(),
                at=when,
            )


def test_certificate_verification_rejects_wrong_root_body_and_signature() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()
    certificate = _certificate(root_key, verifier_key)

    with pytest.raises(TerminalAuthorityError, match="root key differs"):
        verify_admission_verifier_certificate(
            certificate,
            expected_root_public_key=SigningKey.generate().verify_key.encode().hex(),
            at=NOW,
        )

    changed_body = certificate.model_copy(update={"control_suite_sha256": HASH_D})
    with pytest.raises(TerminalAuthorityError, match="root attestation differs"):
        verify_admission_verifier_certificate(
            changed_body,
            expected_root_public_key=root_key.verify_key.encode().hex(),
            at=NOW,
        )

    changed_attestation = certificate.root_attestation.model_copy(update={"signature": "f" * 128})
    changed_signature = certificate.model_copy(update={"root_attestation": changed_attestation})
    with pytest.raises(TerminalAuthorityError, match="root signature is invalid"):
        verify_admission_verifier_certificate(
            changed_signature,
            expected_root_public_key=root_key.verify_key.encode().hex(),
            at=NOW,
        )


def test_certificate_model_rejects_an_attestation_for_another_body() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()
    certificate = _certificate(root_key, verifier_key)
    changed = certificate.model_dump(mode="json")
    changed["validator_source_sha256"] = HASH_D

    with pytest.raises(ValueError, match="does not bind"):
        AdmissionVerifierCertificate.model_validate(changed)


def test_terminal_record_is_derived_signed_and_verifiable() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()
    certificate = _certificate(root_key, verifier_key)

    record = _terminal_record(verifier_key, certificate)

    assert record.attestation_hash == sha256_value(
        record.model_dump(mode="json", exclude={"attestation_hash", "signature"})
    )
    verify_admission_terminal_signature(
        record,
        certificate,
        expected_root_public_key=root_key.verify_key.encode().hex(),
    )


def test_terminal_record_rejects_naive_time_duplicate_paths_and_wrong_signing_key() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()
    certificate = _certificate(root_key, verifier_key)

    with pytest.raises(ValueError, match=r"naive datetimes|timezone-aware"):
        _terminal_record(
            verifier_key,
            certificate,
            produced_at=NOW.replace(tzinfo=None),
        )
    with pytest.raises(ValueError, match="distinct files"):
        _terminal_record(
            verifier_key,
            certificate,
            payload=_binding("input-manifest.json", digest=HASH_B),
        )
    with pytest.raises(TerminalAuthorityError, match="signing key"):
        _terminal_record(
            SigningKey.generate(),
            certificate,
            verifier_public_key=certificate.verifier_public_key,
        )


def test_terminal_verification_rejects_certificate_and_certified_field_substitution() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()
    certificate = _certificate(root_key, verifier_key)

    wrong_certificate_hash = _terminal_record(
        verifier_key,
        certificate,
        verifier_certificate_sha256=HASH_D,
    )
    with pytest.raises(TerminalAuthorityError, match="different verifier certificate"):
        verify_admission_terminal_signature(
            wrong_certificate_hash,
            certificate,
            expected_root_public_key=root_key.verify_key.encode().hex(),
        )

    changed_control = _terminal_record(
        verifier_key,
        certificate,
        control_suite_sha256=HASH_D,
    )
    with pytest.raises(TerminalAuthorityError, match="certified authority"):
        verify_admission_terminal_signature(
            changed_control,
            certificate,
            expected_root_public_key=root_key.verify_key.encode().hex(),
        )


def test_terminal_verification_rejects_signature_and_body_tampering() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()
    certificate = _certificate(root_key, verifier_key)
    record = _terminal_record(verifier_key, certificate)

    changed_signature = record.model_copy(update={"signature": "f" * 128})
    with pytest.raises(TerminalAuthorityError, match="terminal signature is invalid"):
        verify_admission_terminal_signature(
            changed_signature,
            certificate,
            expected_root_public_key=root_key.verify_key.encode().hex(),
        )

    changed_body = record.model_copy(update={"contract_sha256": HASH_A})
    with pytest.raises(TerminalAuthorityError, match="attestation hash"):
        verify_admission_terminal_signature(
            changed_body,
            certificate,
            expected_root_public_key=root_key.verify_key.encode().hex(),
        )


def test_terminal_model_rejects_stale_attestation_hash() -> None:
    root_key = SigningKey.generate()
    verifier_key = SigningKey.generate()
    certificate = _certificate(root_key, verifier_key)
    record = _terminal_record(verifier_key, certificate)
    changed = record.model_dump(mode="json")
    changed["contract_sha256"] = HASH_A

    with pytest.raises(ValueError, match="attestation hash is not derived"):
        AdmissionTerminalRecord.model_validate(changed)


def test_snapshot_is_complete_deterministic_and_utf8_sorted(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "z.bin").write_bytes(b"last")
    (root / "a").mkdir()
    (root / "a" / "nested.bin").write_bytes(b"nested")
    unicode_name = "\u05e2\u05e0\u05d1\u05e8.bin"
    (root / unicode_name).write_bytes(b"unicode")
    (root / "z.bin").chmod(0o600)

    first = snapshot_acquisition_input(root)
    second = snapshot_acquisition_input(root)

    expected_paths = sorted(
        ("z.bin", "a/nested.bin", unicode_name),
        key=lambda path: path.encode("utf-8"),
    )
    assert [entry.path for entry in first.entries] == expected_paths
    assert first == second
    assert first.total_bytes == len(b"lastnestedunicode")
    assert first.root_sha256 == input_manifest_root(first.entries)
    by_path = {entry.path: entry for entry in first.entries}
    assert by_path["z.bin"].sha256 == sha256_bytes(b"last")
    assert by_path["z.bin"].mode == 0o600


def test_snapshot_root_changes_for_content_mode_extra_and_missing_files(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    evidence = root / "evidence.bin"
    evidence.write_bytes(b"baseline")
    baseline = snapshot_acquisition_input(root)

    evidence.write_bytes(b"mutation")
    changed_content = snapshot_acquisition_input(root)
    evidence.chmod(0o600)
    changed_mode = snapshot_acquisition_input(root)
    extra = root / "extra.bin"
    extra.write_bytes(b"extra")
    added = snapshot_acquisition_input(root)
    evidence.unlink()
    missing = snapshot_acquisition_input(root)

    roots = {
        baseline.root_sha256,
        changed_content.root_sha256,
        changed_mode.root_sha256,
        added.root_sha256,
        missing.root_sha256,
    }
    assert len(roots) == 5
    assert [entry.path for entry in added.entries] == ["evidence.bin", "extra.bin"]
    assert [entry.path for entry in missing.entries] == ["extra.bin"]


def test_snapshot_rejects_empty_missing_file_and_symlink_roots(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(TerminalAuthorityError, match="no regular files"):
        snapshot_acquisition_input(empty)
    with pytest.raises(TerminalAuthorityError, match="does not exist"):
        snapshot_acquisition_input(tmp_path / "missing")

    plain_file = tmp_path / "plain.bin"
    plain_file.write_bytes(b"not-a-root")
    with pytest.raises(TerminalAuthorityError, match="must be a directory"):
        snapshot_acquisition_input(plain_file)

    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(empty, target_is_directory=True)
    with pytest.raises(TerminalAuthorityError, match="symbolic link"):
        snapshot_acquisition_input(linked_root)


def test_snapshot_rejects_symlink_escape_and_special_files(tmp_path: Path) -> None:
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    symlink_root = tmp_path / "symlink-input"
    symlink_root.mkdir()
    (symlink_root / "escape.bin").symlink_to(outside)
    with pytest.raises(TerminalAuthorityError, match="symbolic link"):
        snapshot_acquisition_input(symlink_root)

    fifo_root = tmp_path / "fifo-input"
    fifo_root.mkdir()
    os.mkfifo(fifo_root / "stream")
    with pytest.raises(TerminalAuthorityError, match="special file"):
        snapshot_acquisition_input(fifo_root)

    socket_parent = Path("/private/tmp")
    if not socket_parent.is_dir():
        socket_parent = Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(prefix="inbar-", dir=socket_parent) as temporary:
        socket_root = Path(temporary)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(socket_root / "listener.sock"))
            with pytest.raises(TerminalAuthorityError, match="special file"):
                snapshot_acquisition_input(socket_root)
        finally:
            listener.close()


def test_snapshot_rejects_hard_link_aliases(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    original = root / "original.bin"
    original.write_bytes(b"same inode")
    os.link(original, root / "alias.bin")

    with pytest.raises(TerminalAuthorityError, match="hard-link aliases"):
        snapshot_acquisition_input(root)


def test_snapshot_rejects_casefold_collisions_before_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "A.json").write_bytes(b"first")
    monkeypatch.setattr(authority, "_path_inventory", lambda _root: ("A.json", "a.json"))

    with pytest.raises(TerminalAuthorityError, match="case-fold path collision"):
        snapshot_acquisition_input(root)


def test_snapshot_rejects_non_utf8_filesystem_names_as_authority_errors(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    raw_path = os.fsencode(root) + b"/invalid-\xff.bin"
    try:
        descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        pytest.skip("filesystem rejects non-UTF-8 names before snapshotting")
    try:
        os.write(descriptor, b"evidence")
    finally:
        os.close(descriptor)

    with pytest.raises(TerminalAuthorityError, match=r"UTF-8|normalized"):
        snapshot_acquisition_input(root)


def test_snapshot_rejects_file_count_file_bytes_and_total_bytes(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "one.bin").write_bytes(b"one")
    (root / "two.bin").write_bytes(b"two")

    with pytest.raises(TerminalAuthorityError, match="file-count limit"):
        snapshot_acquisition_input(root, limits=InputSnapshotLimits(max_files=1))
    with pytest.raises(TerminalAuthorityError, match="per-file byte limit"):
        snapshot_acquisition_input(
            root,
            limits=InputSnapshotLimits(max_file_bytes=2, max_total_bytes=4),
        )
    with pytest.raises(TerminalAuthorityError, match="total-byte limit"):
        snapshot_acquisition_input(
            root,
            limits=InputSnapshotLimits(max_file_bytes=3, max_total_bytes=5),
        )


def test_snapshot_detects_content_mutation_while_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "input"
    root.mkdir()
    evidence = root / "evidence.bin"
    evidence.write_bytes(b"abcdefgh")
    original_read = os.read
    mutated = False

    def mutating_read(descriptor: int, count: int) -> bytes:
        nonlocal mutated
        chunk = original_read(descriptor, count)
        if chunk and not mutated:
            mutated = True
            evidence.write_bytes(b"changed-and-longer")
        return chunk

    monkeypatch.setattr(authority.os, "read", mutating_read)

    with pytest.raises(TerminalAuthorityError, match="changed while it was being hashed"):
        snapshot_acquisition_input(root, limits=InputSnapshotLimits(read_chunk_bytes=2))


def test_snapshot_detects_inventory_mutation_during_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "input"
    root.mkdir()
    (root / "first.bin").write_bytes(b"first")
    original_hash = authority._hash_stable_file
    mutated = False

    def mutating_hash(
        root_descriptor: int,
        relative: str,
        *,
        limits: InputSnapshotLimits,
    ) -> AcquisitionInputEntry:
        nonlocal mutated
        entry = original_hash(root_descriptor, relative, limits=limits)
        if not mutated:
            mutated = True
            (root / "late.bin").write_bytes(b"late")
        return entry

    monkeypatch.setattr(authority, "_hash_stable_file", mutating_hash)

    with pytest.raises(TerminalAuthorityError, match="inventory changed during snapshot"):
        snapshot_acquisition_input(root)


def test_snapshot_rejects_intermediate_directory_symlink_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "input"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (nested / "evidence.bin").write_bytes(b"local---")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evidence.bin").write_bytes(b"external")
    saved = tmp_path / "saved-nested"
    original_hash = authority._hash_stable_file
    raced = False

    def escaping_hash(
        root_descriptor: int,
        relative: str,
        *,
        limits: InputSnapshotLimits,
    ) -> AcquisitionInputEntry:
        nonlocal raced
        if raced:
            return original_hash(root_descriptor, relative, limits=limits)
        raced = True
        nested.rename(saved)
        nested.symlink_to(outside, target_is_directory=True)
        try:
            return original_hash(root_descriptor, relative, limits=limits)
        finally:
            nested.unlink()
            saved.rename(nested)

    monkeypatch.setattr(authority, "_hash_stable_file", escaping_hash)

    with pytest.raises(TerminalAuthorityError, match=r"symbolic link|escape|identity"):
        snapshot_acquisition_input(root)


def test_bound_artifact_verification_requires_exact_stable_regular_bytes(tmp_path: Path) -> None:
    root = tmp_path / "output"
    root.mkdir()
    artifact = root / "payload.json"
    artifact.write_bytes(b"bound payload")
    binding = ArtifactBinding(
        path="payload.json",
        sha256=sha256_bytes(b"bound payload"),
        bytes=len(b"bound payload"),
        media_type="application/json",
    )

    assert verify_bound_artifact(root, binding) == artifact

    artifact.write_bytes(b"changed payload")
    with pytest.raises(TerminalAuthorityError, match="bytes differ"):
        verify_bound_artifact(root, binding)
    artifact.unlink()
    with pytest.raises(TerminalAuthorityError, match="missing"):
        verify_bound_artifact(root, binding)

    directory = root / "payload.json"
    directory.mkdir()
    with pytest.raises(TerminalAuthorityError, match="regular file"):
        verify_bound_artifact(root, binding)


def test_bound_artifact_rejects_final_symlink_and_hard_link(tmp_path: Path) -> None:
    root = tmp_path / "output"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"outside")
    binding = ArtifactBinding(
        path="payload.json",
        sha256=sha256_bytes(b"outside"),
        bytes=len(b"outside"),
        media_type="application/json",
    )

    (root / "payload.json").symlink_to(outside)
    with pytest.raises(TerminalAuthorityError, match="symbolic link"):
        verify_bound_artifact(root, binding)
    (root / "payload.json").unlink()

    os.link(outside, root / "payload.json")
    with pytest.raises(TerminalAuthorityError, match="hard-link aliases"):
        verify_bound_artifact(root, binding)


def test_bound_artifact_rejects_intermediate_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "output"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload.json").write_bytes(b"outside")
    (root / "nested").symlink_to(outside, target_is_directory=True)
    binding = ArtifactBinding(
        path="nested/payload.json",
        sha256=sha256_bytes(b"outside"),
        bytes=len(b"outside"),
        media_type="application/json",
    )

    with pytest.raises(TerminalAuthorityError, match=r"symbolic link|outside"):
        verify_bound_artifact(root, binding)


def test_bound_artifact_detects_mutation_during_verification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "output"
    root.mkdir()
    artifact = root / "payload.json"
    artifact.write_bytes(b"baseline")
    binding = ArtifactBinding(
        path="payload.json",
        sha256=sha256_bytes(b"baseline"),
        bytes=len(b"baseline"),
        media_type="application/json",
    )
    original_hash = authority._hash_descriptor
    mutated = False

    def mutating_hash(
        descriptor: int,
        *,
        max_bytes: int,
        chunk_bytes: int,
    ) -> tuple[str, int]:
        nonlocal mutated
        result = original_hash(descriptor, max_bytes=max_bytes, chunk_bytes=chunk_bytes)
        if not mutated:
            mutated = True
            artifact.write_bytes(b"changed!")
        return result

    monkeypatch.setattr(authority, "_hash_descriptor", mutating_hash)

    with pytest.raises(TerminalAuthorityError, match="changed while it was being verified"):
        verify_bound_artifact(root, binding)


def test_input_manifest_replay_rejects_any_later_input_change(tmp_path: Path) -> None:
    root = tmp_path / "input"
    root.mkdir()
    evidence = root / "evidence.bin"
    evidence.write_bytes(b"baseline")
    expected = snapshot_acquisition_input(root)

    verify_input_manifest_replay(expected, root)

    evidence.write_bytes(b"changed")
    with pytest.raises(TerminalAuthorityError, match="snapshot differs"):
        verify_input_manifest_replay(expected, root)


def test_roots_must_be_resolved_and_disjoint(tmp_path: Path) -> None:
    input_root = tmp_path / "input"
    input_root.mkdir()
    (input_root / "evidence.bin").write_bytes(b"evidence")
    sibling = tmp_path / "output"

    resolved_input, resolved_output = ensure_disjoint_roots(input_root, sibling)
    assert resolved_input == input_root.resolve()
    assert resolved_output == sibling.resolve()

    with pytest.raises(TerminalAuthorityError, match="output root must not be inside"):
        snapshot_acquisition_input(input_root, output_root=input_root / "terminal-output")
    with pytest.raises(TerminalAuthorityError, match="input root must not be inside"):
        ensure_disjoint_roots(input_root, tmp_path)
