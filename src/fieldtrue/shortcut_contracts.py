"""Committed authority and signature contracts for Shortcut Authority V2.

These primitives authorize implementation only. They do not authorize data access,
truth release, resource spend, physical action, a scientific verdict, or publication.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, Self

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import Field, ValidationError, field_validator, model_validator

from fieldtrue.canonical import canonical_json_pretty, sha256_value
from fieldtrue.domain import (
    Ed25519PublicKey,
    FrozenModel,
    GitObjectId,
    HexSignature,
    Identifier,
    Sha256,
)

ITERATION_ID: Final = "iter001_physical_causal_evidence_acquisition"
APPROVED_PROPOSAL_COMMIT: Final = "551a4ffb8bad5f12312af4a074a467af6bc0ebc2"
AMENDMENT_DOCUMENT_PATH: Final = (
    "experiments/iter001_physical_causal_evidence_acquisition/AMENDMENT_001.md"
)
AMENDMENT_DOCUMENT_SHA256: Final = (
    "9278eb33ef5a837c0ae043112f2fb041df4faa39cf34d26787a47f2326bf360c"
)
MACHINE_PROPOSAL_PATH: Final = "protocol/amendments/iter001_001.json"
MACHINE_PROPOSAL_SHA256: Final = "9c13ef9562f1842f238770fc3d2e3741a77b5db291b4a8cf6b3a66f2e218a76a"
OWNER_APPROVAL_PATH: Final = "protocol/approvals/iter001_001_owner_approval.json"
OWNER_APPROVAL_ARTIFACT_SHA256: Final = (
    "904bc22b103a1b8835bde86971aa2fbf122eaf3b679de5e2923e794faec45a16"
)
OWNER_APPROVAL_RECEIPT_HASH: Final = (
    "482575c10bb58da6b867ee60587cefa290512fa6f09529a324cea3002fd616c3"
)
OWNER_ANCHOR_COMMIT: Final = "2955c1bcca190430cd5c88c57187126bb7531d7a"
OWNER_ANCHOR_PATH: Final = "protocol/acquisition/iter001_contract.json"
OWNER_ANCHOR_SHA256: Final = "c5cf91b620ae3f34cc9ecebf936c4f48014f04cfa21e3fdc1cf0713f440b1804"
OWNER_PUBLIC_KEY: Final = "b0f514d7b91caa7c43ea58ffae42ebeea48164d24948723a8c805f780df38962"
OWNER_ACTOR_ID: Final = "daniel-wahnich"
OWNER_SIGNING_KEY_ID: Final = "iter001-governance"
OWNER_TRUST_BASIS: Final = "git-pinned-iter001-governance-ed25519-no-external-timestamp"
IMPLEMENTATION_DECISION: Final = "approve_shortcut_v2_implementation_only"
APPROVAL_GENESIS: Final = "0" * 64
_TRUSTED_GIT_PATH: Final = Path("/usr/bin/git")

_MAX_AUTHORITY_FILE_BYTES = 2 * 1024 * 1024
_DENIED_AUTHORITIES = (
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


class ShortcutContractError(ValueError):
    """A V2 authority, committed input, or signature is invalid."""


class OwnerAmendmentApprovalReceipt(FrozenModel):
    schema_version: Literal["inbar.owner-amendment-approval-receipt.v1"]
    approval_id: Identifier
    owner_actor_id: Identifier
    owner_signing_key_id: Identifier
    owner_signer_anchor_artifact_sha256: Sha256
    owner_key_trust_basis: str = Field(min_length=1)
    owner_ed25519_public_key: Ed25519PublicKey
    proposal_git_commit: GitObjectId
    amendment_document_artifact_sha256: Sha256
    machine_proposal_artifact_sha256: Sha256
    decision: Literal["approve_shortcut_v2_implementation_only"]
    previous_approval_receipt_sha256: Sha256
    nonce: Sha256
    issued_at: datetime
    receipt_hash: Sha256
    signature: HexSignature

    @field_validator("issued_at")
    @classmethod
    def issued_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("owner approval timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def receipt_hash_is_derived(self) -> Self:
        if sha256_value(owner_approval_body(self)) != self.receipt_hash:
            raise ValueError("owner approval receipt hash mismatch")
        return self


class ShortcutImplementationAuthorityVerification(FrozenModel):
    """Non-portable report returned by a fresh repository verification.

    This model is not authorization evidence and must never be accepted as a gate input.
    A consumer crossing a trust boundary must call
    :func:`load_shortcut_implementation_authority` against its own repository.
    """

    schema_version: Literal["inbar.verified-shortcut-implementation-authority.v1"] = (
        "inbar.verified-shortcut-implementation-authority.v1"
    )
    proposal_git_commit: GitObjectId
    amendment_document_artifact_sha256: Sha256
    machine_proposal_artifact_sha256: Sha256
    owner_approval_receipt_artifact_sha256: Sha256
    owner_approval_receipt_hash: Sha256
    authorized_action: Literal["shortcut_v2_implementation_only"]
    denied_authorities: tuple[str, ...]
    verified_at: datetime

    @field_validator("verified_at")
    @classmethod
    def verification_time_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authority verification timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def authority_is_exactly_implementation_only(self) -> Self:
        expected = {
            "proposal_git_commit": APPROVED_PROPOSAL_COMMIT,
            "amendment_document_artifact_sha256": AMENDMENT_DOCUMENT_SHA256,
            "machine_proposal_artifact_sha256": MACHINE_PROPOSAL_SHA256,
            "owner_approval_receipt_artifact_sha256": OWNER_APPROVAL_ARTIFACT_SHA256,
            "owner_approval_receipt_hash": OWNER_APPROVAL_RECEIPT_HASH,
            "authorized_action": "shortcut_v2_implementation_only",
            "denied_authorities": _DENIED_AUTHORITIES,
        }
        if any(getattr(self, field) != value for field, value in expected.items()):
            raise ValueError("verified authority differs from the approved implementation scope")
        return self


class ShortcutAttestation(FrozenModel):
    schema_version: Literal["inbar.iter001.shortcut-attestation.v1"]
    signer_id: Identifier
    kind: Identifier
    subject_sha256: Sha256
    signer_public_key: Ed25519PublicKey
    signature: HexSignature


def owner_approval_body(
    receipt: OwnerAmendmentApprovalReceipt | dict[str, Any],
) -> dict[str, Any]:
    body = (
        receipt.model_dump(mode="json")
        if isinstance(receipt, OwnerAmendmentApprovalReceipt)
        else dict(receipt)
    )
    body.pop("receipt_hash", None)
    body.pop("signature", None)
    return body


def shortcut_attestation_subject_hash(kind: str, subject: Any) -> str:
    return sha256_value(
        {
            "domain": "inbar.iter001.shortcut-attestation-subject.v1",
            "kind": kind,
            "subject": subject,
        }
    )


def issue_shortcut_attestation(
    signing_key: SigningKey,
    *,
    signer_id: Identifier,
    kind: Identifier,
    subject: Any,
) -> ShortcutAttestation:
    subject_hash = shortcut_attestation_subject_hash(kind, subject)
    signature = signing_key.sign(bytes.fromhex(subject_hash)).signature.hex()
    return ShortcutAttestation(
        schema_version="inbar.iter001.shortcut-attestation.v1",
        signer_id=signer_id,
        kind=kind,
        subject_sha256=subject_hash,
        signer_public_key=signing_key.verify_key.encode().hex(),
        signature=signature,
    )


def verify_shortcut_attestation(
    attestation: ShortcutAttestation,
    *,
    expected_kind: str,
    expected_subject: Any,
    expected_signer_id: str,
    expected_public_key: str,
) -> None:
    try:
        validated_attestation = ShortcutAttestation.model_validate(
            attestation.model_dump(mode="python"),
            strict=True,
        )
    except ValidationError as error:
        raise ShortcutContractError("shortcut attestation violates its typed contract") from error
    expected_subject_hash = shortcut_attestation_subject_hash(expected_kind, expected_subject)
    if (
        validated_attestation.kind != expected_kind
        or validated_attestation.subject_sha256 != expected_subject_hash
        or validated_attestation.signer_id != expected_signer_id
        or validated_attestation.signer_public_key != expected_public_key
    ):
        raise ShortcutContractError("shortcut attestation scope or signer mismatch")
    try:
        VerifyKey(bytes.fromhex(expected_public_key)).verify(
            bytes.fromhex(expected_subject_hash),
            bytes.fromhex(validated_attestation.signature),
        )
    except (BadSignatureError, ValueError) as error:
        raise ShortcutContractError("shortcut attestation signature mismatch") from error


def load_shortcut_implementation_authority(
    repo_root: Path,
    *,
    verified_at: datetime | None = None,
) -> ShortcutImplementationAuthorityVerification:
    root = repo_root.resolve(strict=True)
    _verify_git_history(root)
    receipt_path = root / OWNER_APPROVAL_PATH
    raw_receipt = _read_regular_file(receipt_path, "owner approval receipt")
    _canonical_json_object(raw_receipt, "owner approval receipt")
    try:
        receipt = OwnerAmendmentApprovalReceipt.model_validate_json(raw_receipt, strict=True)
    except ValueError as error:
        raise ShortcutContractError("owner approval receipt violates its typed contract") from error
    head_receipt = _git_blob(root, "HEAD", OWNER_APPROVAL_PATH, "owner approval receipt")
    if head_receipt != raw_receipt:
        raise ShortcutContractError("owner approval receipt is not committed at HEAD")
    _verify_proposal_and_owner_anchor(root, receipt)
    _verify_owner_receipt_scope_and_signature(receipt)

    checked_at = verified_at or datetime.now(UTC)
    if checked_at.tzinfo is None or checked_at.utcoffset() is None:
        raise ShortcutContractError("authority verification time must be timezone-aware")
    if checked_at < receipt.issued_at:
        raise ShortcutContractError("authority verification predates owner approval")
    return ShortcutImplementationAuthorityVerification(
        proposal_git_commit=receipt.proposal_git_commit,
        amendment_document_artifact_sha256=receipt.amendment_document_artifact_sha256,
        machine_proposal_artifact_sha256=receipt.machine_proposal_artifact_sha256,
        owner_approval_receipt_artifact_sha256=hashlib.sha256(raw_receipt).hexdigest(),
        owner_approval_receipt_hash=receipt.receipt_hash,
        authorized_action="shortcut_v2_implementation_only",
        denied_authorities=_DENIED_AUTHORITIES,
        verified_at=checked_at,
    )


def _verify_owner_receipt_scope_and_signature(receipt: OwnerAmendmentApprovalReceipt) -> None:
    expected = {
        "owner_actor_id": OWNER_ACTOR_ID,
        "owner_signing_key_id": OWNER_SIGNING_KEY_ID,
        "owner_signer_anchor_artifact_sha256": OWNER_ANCHOR_SHA256,
        "owner_key_trust_basis": OWNER_TRUST_BASIS,
        "owner_ed25519_public_key": OWNER_PUBLIC_KEY,
        "proposal_git_commit": APPROVED_PROPOSAL_COMMIT,
        "amendment_document_artifact_sha256": AMENDMENT_DOCUMENT_SHA256,
        "machine_proposal_artifact_sha256": MACHINE_PROPOSAL_SHA256,
        "decision": IMPLEMENTATION_DECISION,
        "previous_approval_receipt_sha256": APPROVAL_GENESIS,
    }
    observed = receipt.model_dump(mode="json")
    if any(observed[field] != value for field, value in expected.items()):
        raise ShortcutContractError("owner approval differs from the approved implementation scope")
    try:
        VerifyKey(bytes.fromhex(OWNER_PUBLIC_KEY)).verify(
            bytes.fromhex(receipt.receipt_hash), bytes.fromhex(receipt.signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise ShortcutContractError("owner approval signature mismatch") from error


def _verify_proposal_and_owner_anchor(
    repo_root: Path,
    receipt: OwnerAmendmentApprovalReceipt,
) -> None:
    amendment = _git_blob(
        repo_root,
        APPROVED_PROPOSAL_COMMIT,
        AMENDMENT_DOCUMENT_PATH,
        "amendment document",
    )
    machine = _git_blob(
        repo_root,
        APPROVED_PROPOSAL_COMMIT,
        MACHINE_PROPOSAL_PATH,
        "machine proposal",
    )
    anchor = _git_blob(repo_root, OWNER_ANCHOR_COMMIT, OWNER_ANCHOR_PATH, "owner anchor")
    if hashlib.sha256(amendment).hexdigest() != AMENDMENT_DOCUMENT_SHA256:
        raise ShortcutContractError("committed amendment document hash mismatch")
    if hashlib.sha256(machine).hexdigest() != MACHINE_PROPOSAL_SHA256:
        raise ShortcutContractError("committed machine proposal hash mismatch")
    if hashlib.sha256(anchor).hexdigest() != OWNER_ANCHOR_SHA256:
        raise ShortcutContractError("committed owner anchor hash mismatch")
    machine_value = _canonical_json_object(machine, "machine proposal")
    anchor_value = _canonical_json_object(anchor, "owner anchor", require_pretty=False)
    if machine_value.get("amendment_document") != {
        "artifact_sha256": receipt.amendment_document_artifact_sha256,
        "path": AMENDMENT_DOCUMENT_PATH,
    }:
        raise ShortcutContractError("machine proposal does not bind the amendment document")
    if anchor_value.get("trust_anchor_public_key") != OWNER_PUBLIC_KEY:
        raise ShortcutContractError("owner anchor does not bind the approved public key")


def _read_regular_file(path: Path, label: str) -> bytes:
    try:
        file_stat = path.lstat()
    except OSError as error:
        raise ShortcutContractError(f"{label} is unavailable") from error
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISREG(file_stat.st_mode):
        raise ShortcutContractError(f"{label} must be a regular file")
    if file_stat.st_size > _MAX_AUTHORITY_FILE_BYTES:
        raise ShortcutContractError(f"{label} exceeds its byte limit")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ShortcutContractError(f"{label} cannot be read") from error
    if len(data) != file_stat.st_size:
        raise ShortcutContractError(f"{label} changed while being read")
    return data


def _canonical_json_object(
    data: bytes,
    label: str,
    *,
    require_pretty: bool = True,
) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ShortcutContractError(f"{label} contains duplicate object keys")
            value[key] = item
        return value

    try:
        parsed = json.loads(data, object_pairs_hook=object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ShortcutContractError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(parsed, dict):
        raise ShortcutContractError(f"{label} must be a JSON object")
    if require_pretty and canonical_json_pretty(parsed) != data:
        raise ShortcutContractError(f"{label} is not canonical pretty JSON")
    return parsed


def _git_blob(repo_root: Path, commit: str, relative: str, label: str) -> bytes:
    git = _trusted_git_executable()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed Git object read
            [git, "show", f"{commit}:{relative}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=_git_environment(),
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ShortcutContractError(f"committed {label} is unavailable") from error
    if len(completed.stdout) > _MAX_AUTHORITY_FILE_BYTES:
        raise ShortcutContractError(f"committed {label} exceeds its byte limit")
    return completed.stdout


def _verify_git_history(repo_root: Path) -> None:
    git = _trusted_git_executable()
    environment = _git_environment()
    try:
        top_level = subprocess.run(  # noqa: S603 - fixed Git repository query
            [git, "rev-parse", "--show-toplevel"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=environment,
            timeout=10,
            text=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise ShortcutContractError("authority root is not a readable Git worktree") from error
    try:
        observed_root = Path(top_level).resolve(strict=True)
    except OSError as error:
        raise ShortcutContractError("Git reported an unavailable worktree root") from error
    if observed_root != repo_root:
        raise ShortcutContractError("authority root is not the Git worktree top level")

    try:
        grafts_path = subprocess.run(  # noqa: S603 - fixed Git repository query
            [git, "rev-parse", "--git-path", "info/grafts"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            env=environment,
            timeout=10,
            text=True,
        ).stdout.strip()
        grafts = Path(grafts_path)
        if not grafts.is_absolute():
            grafts = repo_root / grafts
        grafts_stat = grafts.lstat()
    except FileNotFoundError:
        pass
    except (OSError, subprocess.SubprocessError) as error:
        raise ShortcutContractError("Git graft state cannot be verified") from error
    else:
        if grafts_stat.st_size > 0 or stat.S_ISLNK(grafts_stat.st_mode):
            raise ShortcutContractError(
                "legacy Git grafts are forbidden for authority verification"
            )

    for ancestor in (OWNER_ANCHOR_COMMIT, APPROVED_PROPOSAL_COMMIT):
        try:
            completed = subprocess.run(  # noqa: S603 - fixed Git ancestry query
                [git, "merge-base", "--is-ancestor", ancestor, "HEAD"],
                cwd=repo_root,
                check=False,
                capture_output=True,
                env=environment,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ShortcutContractError("approved Git ancestry cannot be verified") from error
        if completed.returncode != 0:
            raise ShortcutContractError("approved Git history is not an ancestor of HEAD")


def _trusted_git_executable() -> str:
    try:
        git_stat = _TRUSTED_GIT_PATH.lstat()
    except OSError as error:
        raise ShortcutContractError("trusted system Git is unavailable") from error
    if (
        stat.S_ISLNK(git_stat.st_mode)
        or not stat.S_ISREG(git_stat.st_mode)
        or git_stat.st_uid != 0
        or git_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ShortcutContractError("trusted system Git has unsafe ownership or mode")
    return str(_TRUSTED_GIT_PATH)


def _git_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return environment
