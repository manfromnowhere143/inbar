"""Terminal admission authority primitives.

This module defines the dormant contracts for complete input capture and terminal
signatures. It does not authorize production signing or change canonical authority.
"""

from __future__ import annotations

import hashlib
import os
import stat
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import Field, field_validator, model_validator

from fieldtrue.acquisition import (
    ArtifactBinding,
    AttestationSubjectKind,
    SignedAttestation,
    attestation_subject_hash,
    issue_attestation,
)
from fieldtrue.canonical import sha256_value
from fieldtrue.domain import (
    Ed25519PublicKey,
    FrozenModel,
    GitObjectId,
    HexSignature,
    Identifier,
    Sha256,
)

ITERATION_ID: Literal["iter001_physical_causal_evidence_acquisition"] = (
    "iter001_physical_causal_evidence_acquisition"
)
INPUT_ROOT_ALGORITHM: Literal["sha256-canonical-path-content-v1"] = (
    "sha256-canonical-path-content-v1"
)


class TerminalAuthorityError(RuntimeError):
    """Terminal authority or complete-input evidence is invalid."""


@dataclass(frozen=True, slots=True)
class InputSnapshotLimits:
    """Hard resource limits applied before and during complete input capture."""

    max_files: int = 100_000
    max_file_bytes: int = 16 * 1024**3
    max_total_bytes: int = 128 * 1024**3
    read_chunk_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if (
            min(
                self.max_files,
                self.max_file_bytes,
                self.max_total_bytes,
                self.read_chunk_bytes,
            )
            <= 0
        ):
            raise ValueError("input snapshot limits must be positive")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("per-file limit cannot exceed total-byte limit")


class AdmissionVerifierCertificate(FrozenModel):
    schema_version: Literal["fieldtrue.admission-verifier-certificate.v1"] = (
        "fieldtrue.admission-verifier-certificate.v1"
    )
    certificate_id: Identifier
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"] = ITERATION_ID
    verifier_id: Identifier
    verifier_public_key: Ed25519PublicKey
    validator_git_blob: GitObjectId
    validator_source_sha256: Sha256
    control_suite_sha256: Sha256
    dependency_lock_sha256: Sha256
    not_before: datetime
    expires_at: datetime
    root_attestation: SignedAttestation

    @model_validator(mode="after")
    def certificate_is_well_formed(self) -> Self:
        if self.not_before.tzinfo is None or self.not_before.utcoffset() is None:
            raise ValueError("certificate not-before timestamp must be timezone-aware")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("certificate expiry timestamp must be timezone-aware")
        if self.expires_at <= self.not_before:
            raise ValueError("certificate expiry must follow its not-before timestamp")
        expected_subject = attestation_subject_hash(
            AttestationSubjectKind.ADMISSION_VERIFIER_CERTIFICATE,
            _certificate_body(self),
        )
        if (
            self.root_attestation.subject_kind
            != AttestationSubjectKind.ADMISSION_VERIFIER_CERTIFICATE
            or self.root_attestation.subject_sha256 != expected_subject
        ):
            raise ValueError("root attestation does not bind the verifier certificate")
        return self


class AcquisitionInputEntry(FrozenModel):
    path: str = Field(min_length=1)
    sha256: Sha256
    bytes: int = Field(ge=0)
    mode: int = Field(ge=0, le=0o7777)

    @field_validator("path")
    @classmethod
    def path_is_canonical(cls, value: str) -> str:
        pure = PurePosixPath(value)
        if (
            pure.is_absolute()
            or not pure.parts
            or "." in pure.parts
            or ".." in pure.parts
            or pure.as_posix() != value
            or unicodedata.normalize("NFC", value) != value
        ):
            raise ValueError("input path must be normalized NFC relative POSIX")
        return value


class AcquisitionInputManifest(FrozenModel):
    schema_version: Literal["fieldtrue.acquisition-input-manifest.v1"] = (
        "fieldtrue.acquisition-input-manifest.v1"
    )
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"] = ITERATION_ID
    root_algorithm: Literal["sha256-canonical-path-content-v1"] = INPUT_ROOT_ALGORITHM
    entries: tuple[AcquisitionInputEntry, ...] = Field(min_length=1)
    total_bytes: int = Field(ge=0)
    root_sha256: Sha256

    @model_validator(mode="after")
    def manifest_is_exactly_derived(self) -> Self:
        paths = [entry.path for entry in self.entries]
        expected_order = sorted(paths, key=lambda path: path.encode("utf-8"))
        if paths != expected_order or len(paths) != len(set(paths)):
            raise ValueError("input entries must have unique canonical UTF-8 byte order")
        if _has_casefold_component_collision(paths):
            raise ValueError("input entries contain a case-fold path collision")
        if self.total_bytes != sum(entry.bytes for entry in self.entries):
            raise ValueError("input total bytes are not derived from entries")
        if self.root_sha256 != input_manifest_root(self.entries):
            raise ValueError("input root digest is not derived from entries")
        return self


InvalidityStage = Literal[
    "authority",
    "input_snapshot",
    "control_verification",
    "artifact_loading",
    "admission_audit",
    "output_staging",
]


class AdmissionInvalidityRecord(FrozenModel):
    schema_version: Literal["fieldtrue.admission-invalidity-record.v1"] = (
        "fieldtrue.admission-invalidity-record.v1"
    )
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"] = ITERATION_ID
    contract_sha256: Sha256
    input_manifest_sha256: Sha256
    failure_stage: InvalidityStage
    failure_code: Identifier
    diagnostic_sha256: Sha256
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def occurrence_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("invalidity timestamp must be timezone-aware")
        return value


class AdmissionTerminalRecord(FrozenModel):
    schema_version: Literal["fieldtrue.admission-terminal-record.v1"] = (
        "fieldtrue.admission-terminal-record.v1"
    )
    terminal_id: Identifier
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"] = ITERATION_ID
    execution_commit: GitObjectId
    execution_tree: GitObjectId
    contract_sha256: Sha256
    verifier_certificate_sha256: Sha256
    control_suite_sha256: Sha256
    validator_git_blob: GitObjectId
    validator_source_sha256: Sha256
    dependency_lock_sha256: Sha256
    input_manifest: ArtifactBinding
    payload_kind: Literal["admission_report", "invalidity_record"]
    payload: ArtifactBinding
    rendered_result: ArtifactBinding
    produced_at: datetime
    verifier_id: Identifier
    verifier_public_key: Ed25519PublicKey
    attestation_hash: Sha256
    signature: HexSignature

    @model_validator(mode="after")
    def terminal_record_is_well_formed(self) -> Self:
        if self.produced_at.tzinfo is None or self.produced_at.utcoffset() is None:
            raise ValueError("terminal timestamp must be timezone-aware")
        paths = (self.input_manifest.path, self.payload.path, self.rendered_result.path)
        if len(paths) != len(set(paths)):
            raise ValueError("terminal output bindings must name distinct files")
        if sha256_value(_terminal_body(self)) != self.attestation_hash:
            raise ValueError("terminal attestation hash is not derived from its body")
        return self


def _certificate_body(value: AdmissionVerifierCertificate | dict[str, Any]) -> dict[str, Any]:
    body = (
        value.model_dump(mode="python")
        if isinstance(value, AdmissionVerifierCertificate)
        else dict(value)
    )
    body.pop("root_attestation", None)
    return body


def _terminal_body(value: AdmissionTerminalRecord | dict[str, Any]) -> dict[str, Any]:
    body = (
        value.model_dump(mode="python")
        if isinstance(value, AdmissionTerminalRecord)
        else dict(value)
    )
    body.pop("attestation_hash", None)
    body.pop("signature", None)
    return body


def input_manifest_root(entries: tuple[AcquisitionInputEntry, ...]) -> str:
    """Derive the domain-separated root of an exact canonical entry tuple."""

    return sha256_value(
        {
            "domain": "fieldtrue.acquisition-input-manifest-root.v1",
            "root_algorithm": INPUT_ROOT_ALGORITHM,
            "entries": [entry.model_dump(mode="json") for entry in entries],
        }
    )


_STABLE_STAT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)


def _utf8_key(value: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise TerminalAuthorityError("input path is not valid UTF-8") from error


def _canonical_parts(parts: tuple[str, ...]) -> str:
    value = PurePosixPath(*parts).as_posix()
    try:
        AcquisitionInputEntry.path_is_canonical(value)
    except ValueError as error:
        raise TerminalAuthorityError("input path is not normalized NFC UTF-8") from error
    _utf8_key(value)
    return value


def _has_casefold_component_collision(paths: list[str] | tuple[str, ...]) -> bool:
    seen: dict[tuple[str, ...], tuple[str, ...]] = {}
    for path in paths:
        parts = PurePosixPath(path).parts
        for length in range(1, len(parts) + 1):
            prefix = parts[:length]
            folded = tuple(part.casefold() for part in prefix)
            previous = seen.setdefault(folded, prefix)
            if previous != prefix:
                return True
    return False


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise TerminalAuthorityError("root path component cannot be inspected") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise TerminalAuthorityError("root path must not traverse a symbolic link")


def _directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise TerminalAuthorityError("terminal snapshots require directory no-follow support")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise TerminalAuthorityError("terminal snapshots require file no-follow support")
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _same_stat(left: os.stat_result, right: os.stat_result) -> bool:
    return all(getattr(left, name) == getattr(right, name) for name in _STABLE_STAT_FIELDS)


def _path_inventory(root_descriptor: int) -> tuple[str, ...]:
    values: list[str] = []

    def visit(directory_descriptor: int, prefix: tuple[str, ...]) -> None:
        try:
            with os.scandir(directory_descriptor) as iterator:
                children = list(iterator)
        except OSError as error:
            raise TerminalAuthorityError("input directory cannot be enumerated") from error
        children.sort(key=lambda child: _utf8_key(child.name))
        for child in children:
            relative = _canonical_parts((*prefix, child.name))
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise TerminalAuthorityError("input path cannot be inspected") from error
            if stat.S_ISLNK(metadata.st_mode):
                raise TerminalAuthorityError("input contains a symbolic link")
            if stat.S_ISREG(metadata.st_mode):
                values.append(relative)
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                raise TerminalAuthorityError("input contains a special file")
            try:
                nested_descriptor = os.open(
                    child.name,
                    _directory_flags(),
                    dir_fd=directory_descriptor,
                )
            except OSError as error:
                raise TerminalAuthorityError(
                    "input directory changed or became a symbolic link"
                ) from error
            try:
                if not _same_stat(metadata, os.fstat(nested_descriptor)):
                    raise TerminalAuthorityError("input directory identity changed")
                visit(nested_descriptor, (*prefix, child.name))
            finally:
                os.close(nested_descriptor)

    visit(root_descriptor, ())
    values.sort(key=_utf8_key)
    return tuple(values)


def _open_file_beneath(root_descriptor: int, relative: str) -> tuple[int, int, str]:
    parts = PurePosixPath(relative).parts
    if not parts:
        raise TerminalAuthorityError("input file path is empty")
    parent_descriptor = os.dup(root_descriptor)
    try:
        for part in parts[:-1]:
            try:
                nested_descriptor = os.open(
                    part,
                    _directory_flags(),
                    dir_fd=parent_descriptor,
                )
            except OSError as error:
                raise TerminalAuthorityError(
                    "input path escaped or traversed a symbolic link"
                ) from error
            os.close(parent_descriptor)
            parent_descriptor = nested_descriptor
        try:
            file_descriptor = os.open(parts[-1], _file_flags(), dir_fd=parent_descriptor)
        except OSError as error:
            raise TerminalAuthorityError(
                "input file is missing, escaped, or became a symbolic link"
            ) from error
        return file_descriptor, parent_descriptor, parts[-1]
    except Exception:
        os.close(parent_descriptor)
        raise


def _hash_descriptor(
    descriptor: int,
    *,
    max_bytes: int,
    chunk_bytes: int,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    consumed = 0
    while chunk := os.read(descriptor, min(chunk_bytes, max_bytes - consumed + 1)):
        consumed += len(chunk)
        if consumed > max_bytes:
            raise TerminalAuthorityError("input file exceeds the per-file byte limit")
        digest.update(chunk)
    return digest.hexdigest(), consumed


def _hash_stable_file(
    root_descriptor: int,
    relative: str,
    *,
    limits: InputSnapshotLimits,
) -> AcquisitionInputEntry:
    try:
        descriptor, parent_descriptor, name = _open_file_beneath(root_descriptor, relative)
    except TerminalAuthorityError:
        raise
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TerminalAuthorityError("input path stopped being a regular file")
        if before.st_nlink != 1:
            raise TerminalAuthorityError("input regular files must not have hard-link aliases")
        if before.st_size > limits.max_file_bytes:
            raise TerminalAuthorityError("input file exceeds the per-file byte limit")
        digest, consumed = _hash_descriptor(
            descriptor,
            max_bytes=limits.max_file_bytes,
            chunk_bytes=limits.read_chunk_bytes,
        )
        after = os.fstat(descriptor)
        try:
            try:
                current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            except OSError as error:
                raise TerminalAuthorityError(
                    "bound artifact changed while it was being verified"
                ) from error
        except OSError as error:
            raise TerminalAuthorityError("input file disappeared after hashing") from error
    finally:
        os.close(descriptor)
        os.close(parent_descriptor)
    if not _same_stat(before, after):
        raise TerminalAuthorityError("input file changed while it was being hashed")
    if not _same_stat(after, current):
        raise TerminalAuthorityError("input file identity changed after hashing")
    if consumed != after.st_size:
        raise TerminalAuthorityError("input file size changed while it was being hashed")
    return AcquisitionInputEntry(
        path=relative,
        sha256=digest,
        bytes=after.st_size,
        mode=stat.S_IMODE(after.st_mode),
    )


def ensure_disjoint_roots(input_root: Path, output_root: Path) -> tuple[Path, Path]:
    """Resolve roots and reject either root being nested below the other."""

    _reject_symlink_components(input_root)
    _reject_symlink_components(output_root)
    resolved_input = input_root.resolve(strict=True)
    resolved_output = output_root.resolve(strict=False)
    if resolved_output == resolved_input or resolved_output.is_relative_to(resolved_input):
        raise TerminalAuthorityError("output root must not be inside the input root")
    if resolved_input.is_relative_to(resolved_output):
        raise TerminalAuthorityError("input root must not be inside the output root")
    return resolved_input, resolved_output


def snapshot_acquisition_input(
    root: Path,
    *,
    output_root: Path | None = None,
    limits: InputSnapshotLimits | None = None,
) -> AcquisitionInputManifest:
    """Capture every stable regular file below one non-link input root."""

    limits = limits or InputSnapshotLimits()
    _reject_symlink_components(root)
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise TerminalAuthorityError("input root does not exist") from error
    if not resolved.is_dir():
        raise TerminalAuthorityError("input root must be a directory")
    if output_root is not None:
        ensure_disjoint_roots(resolved, output_root)

    try:
        root_descriptor = os.open(resolved, _directory_flags())
    except OSError as error:
        raise TerminalAuthorityError(
            "input root cannot be opened without following links"
        ) from error
    try:
        root_identity = os.fstat(root_descriptor)
        initial_paths = _path_inventory(root_descriptor)
        if not initial_paths:
            raise TerminalAuthorityError("input root contains no regular files")
        if len(initial_paths) > limits.max_files:
            raise TerminalAuthorityError("input root exceeds the file-count limit")
        if _has_casefold_component_collision(initial_paths):
            raise TerminalAuthorityError("input contains a case-fold path collision")

        entries: list[AcquisitionInputEntry] = []
        total_bytes = 0
        for relative in initial_paths:
            entry = _hash_stable_file(root_descriptor, relative, limits=limits)
            total_bytes += entry.bytes
            if total_bytes > limits.max_total_bytes:
                raise TerminalAuthorityError("input root exceeds the total-byte limit")
            entries.append(entry)
        if _path_inventory(root_descriptor) != initial_paths:
            raise TerminalAuthorityError("input path inventory changed during snapshot")
        if not _same_stat(root_identity, resolved.stat(follow_symlinks=False)):
            raise TerminalAuthorityError("input root identity changed during snapshot")
    finally:
        os.close(root_descriptor)

    exact_entries = tuple(entries)
    return AcquisitionInputManifest(
        entries=exact_entries,
        total_bytes=total_bytes,
        root_sha256=input_manifest_root(exact_entries),
    )


def verify_bound_artifact(root: Path, binding: ArtifactBinding) -> Path:
    """Verify one bound regular file without following links or changing it."""

    _reject_symlink_components(root)
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise TerminalAuthorityError("artifact root does not exist") from error
    try:
        root_descriptor = os.open(resolved_root, _directory_flags())
    except OSError as error:
        raise TerminalAuthorityError("artifact root cannot be opened") from error
    try:
        root_identity = os.fstat(root_descriptor)
        descriptor, parent_descriptor, name = _open_file_beneath(root_descriptor, binding.path)
        try:
            metadata_before = os.fstat(descriptor)
            if not stat.S_ISREG(metadata_before.st_mode):
                raise TerminalAuthorityError("bound artifact must be a regular file")
            if metadata_before.st_nlink != 1:
                raise TerminalAuthorityError("bound artifact must not have hard-link aliases")
            if metadata_before.st_size != binding.bytes:
                raise TerminalAuthorityError("bound artifact bytes differ")
            digest, consumed = _hash_descriptor(
                descriptor,
                max_bytes=binding.bytes,
                chunk_bytes=1024 * 1024,
            )
            metadata_after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
        finally:
            os.close(descriptor)
            os.close(parent_descriptor)
        if not _same_stat(metadata_before, metadata_after) or not _same_stat(
            metadata_after, current
        ):
            raise TerminalAuthorityError("bound artifact changed while it was being verified")
        if not _same_stat(root_identity, resolved_root.stat(follow_symlinks=False)):
            raise TerminalAuthorityError("artifact root identity changed during verification")
    finally:
        os.close(root_descriptor)
    if consumed != binding.bytes or digest != binding.sha256:
        raise TerminalAuthorityError("bound artifact bytes differ")
    path = resolved_root / PurePosixPath(binding.path)
    if not path.is_relative_to(resolved_root):
        raise TerminalAuthorityError("bound artifact is outside its root")
    return path


def verify_input_manifest_replay(
    expected: AcquisitionInputManifest,
    root: Path,
    *,
    output_root: Path | None = None,
    limits: InputSnapshotLimits | None = None,
) -> None:
    """Rebuild one complete input manifest and require exact typed equality."""

    observed = snapshot_acquisition_input(root, output_root=output_root, limits=limits)
    if observed != expected:
        raise TerminalAuthorityError("complete input snapshot differs from the terminal manifest")


def issue_admission_verifier_certificate(
    root_signing_key: SigningKey,
    *,
    certificate_id: Identifier,
    verifier_id: Identifier,
    verifier_public_key: Ed25519PublicKey,
    validator_git_blob: GitObjectId,
    validator_source_sha256: Sha256,
    control_suite_sha256: Sha256,
    dependency_lock_sha256: Sha256,
    not_before: datetime,
    expires_at: datetime,
    issued_at: datetime,
    root_signer_id: Identifier,
) -> AdmissionVerifierCertificate:
    body: dict[str, Any] = {
        "schema_version": "fieldtrue.admission-verifier-certificate.v1",
        "certificate_id": certificate_id,
        "iteration_id": ITERATION_ID,
        "verifier_id": verifier_id,
        "verifier_public_key": verifier_public_key,
        "validator_git_blob": validator_git_blob,
        "validator_source_sha256": validator_source_sha256,
        "control_suite_sha256": control_suite_sha256,
        "dependency_lock_sha256": dependency_lock_sha256,
        "not_before": not_before,
        "expires_at": expires_at,
    }
    subject_sha256 = attestation_subject_hash(
        AttestationSubjectKind.ADMISSION_VERIFIER_CERTIFICATE,
        body,
    )
    attestation = issue_attestation(
        root_signing_key,
        attestation_id=f"{certificate_id}:root",
        signer_id=root_signer_id,
        subject_kind=AttestationSubjectKind.ADMISSION_VERIFIER_CERTIFICATE,
        subject_sha256=subject_sha256,
        issued_at=issued_at,
    )
    return AdmissionVerifierCertificate.model_validate({**body, "root_attestation": attestation})


def verify_admission_verifier_certificate(
    certificate: AdmissionVerifierCertificate,
    *,
    expected_root_public_key: Ed25519PublicKey,
    at: datetime,
) -> None:
    """Verify certificate binding, root signature, and validity without a private key."""

    if at.tzinfo is None or at.utcoffset() is None:
        raise TerminalAuthorityError("certificate verification time must be timezone-aware")
    if not certificate.not_before <= at <= certificate.expires_at:
        raise TerminalAuthorityError("verifier certificate is outside its validity window")
    attestation = certificate.root_attestation
    if attestation.signer_public_key != expected_root_public_key:
        raise TerminalAuthorityError("verifier certificate root key differs")
    expected_subject = attestation_subject_hash(
        AttestationSubjectKind.ADMISSION_VERIFIER_CERTIFICATE,
        _certificate_body(certificate),
    )
    attestation_body = attestation.model_dump(
        mode="python", exclude={"attestation_hash", "signature"}
    )
    if (
        attestation.subject_sha256 != expected_subject
        or sha256_value(attestation_body) != attestation.attestation_hash
    ):
        raise TerminalAuthorityError("verifier certificate root attestation differs")
    try:
        VerifyKey(bytes.fromhex(expected_root_public_key)).verify(
            bytes.fromhex(attestation.attestation_hash),
            bytes.fromhex(attestation.signature),
        )
    except (BadSignatureError, ValueError) as error:
        raise TerminalAuthorityError("verifier certificate root signature is invalid") from error


def issue_admission_terminal_record(
    signing_key: SigningKey,
    **body: Any,
) -> AdmissionTerminalRecord:
    """Sign a complete terminal body with an explicitly supplied verifier key."""

    supplied = dict(body)
    if {"attestation_hash", "signature"} & supplied.keys():
        raise TerminalAuthorityError("terminal signature fields are derived")
    supplied.setdefault("schema_version", "fieldtrue.admission-terminal-record.v1")
    supplied.setdefault("iteration_id", ITERATION_ID)
    public_key = signing_key.verify_key.encode().hex()
    if supplied.get("verifier_public_key", public_key) != public_key:
        raise TerminalAuthorityError("terminal verifier key differs from the signing key")
    supplied["verifier_public_key"] = public_key
    attestation_hash = sha256_value(supplied)
    signature = signing_key.sign(bytes.fromhex(attestation_hash)).signature.hex()
    return AdmissionTerminalRecord.model_validate(
        {**supplied, "attestation_hash": attestation_hash, "signature": signature}
    )


def verify_admission_terminal_signature(
    record: AdmissionTerminalRecord,
    certificate: AdmissionVerifierCertificate,
    *,
    expected_root_public_key: Ed25519PublicKey,
) -> None:
    """Verify certificate and terminal signature without loading signing material."""

    verify_admission_verifier_certificate(
        certificate,
        expected_root_public_key=expected_root_public_key,
        at=record.produced_at,
    )
    if sha256_value(certificate) != record.verifier_certificate_sha256:
        raise TerminalAuthorityError("terminal record binds a different verifier certificate")
    expected = (
        (record.verifier_id, certificate.verifier_id),
        (record.verifier_public_key, certificate.verifier_public_key),
        (record.validator_git_blob, certificate.validator_git_blob),
        (record.validator_source_sha256, certificate.validator_source_sha256),
        (record.control_suite_sha256, certificate.control_suite_sha256),
        (record.dependency_lock_sha256, certificate.dependency_lock_sha256),
    )
    if any(observed != certified for observed, certified in expected):
        raise TerminalAuthorityError("terminal record differs from certified authority")
    if sha256_value(_terminal_body(record)) != record.attestation_hash:
        raise TerminalAuthorityError("terminal attestation hash differs from its body")
    try:
        VerifyKey(bytes.fromhex(record.verifier_public_key)).verify(
            bytes.fromhex(record.attestation_hash),
            bytes.fromhex(record.signature),
        )
    except (BadSignatureError, ValueError) as error:
        raise TerminalAuthorityError("terminal signature is invalid") from error
