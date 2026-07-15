"""Recipient-scoped target envelopes for Shortcut Authority V2.

This module implements cryptographic envelope construction and validation only. It
does not create keys, publish ciphertext, release truth, or authorize an execution.
"""

from __future__ import annotations

import json
import struct
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Annotated, Any, Final, Literal, Protocol, TypeAlias, TypeVar, cast

from nacl.bindings import crypto_box_SEALBYTES, sodium_core
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from fieldtrue.canonical import canonical_json, sha256_bytes, sha256_value
from fieldtrue.domain import Identifier, Sha256
from fieldtrue.shortcut_contracts import (
    AMENDMENT_DOCUMENT_SHA256,
    APPROVED_PROPOSAL_COMMIT,
    MACHINE_PROPOSAL_SHA256,
    OWNER_APPROVAL_RECEIPT_HASH,
)
from fieldtrue.shortcut_v2_crossfit import RuleId
from fieldtrue.shortcut_v2_hashing import incident_id_list_sha256

ITERATION_ID: Final = "iter001_physical_causal_evidence_acquisition"
RELEASE_CONTEXT_SCHEMA: Final = "inbar.iter001.shortcut-release-context.v1"
RELEASE_CONTEXT_DOMAIN: Final = "inbar.iter001.recipient-scoped-truth-release.v1"
TARGET_ENVELOPE_SCHEMA: Final = "inbar.iter001.target-envelope.v1"
PADDING_UNIT_BYTES: Final = 16_384
FRAME_HEADER_BYTES: Final = 8
_SODIUM: Any = sodium_core
_SODIUM_FFI: Any = _SODIUM.ffi
_SODIUM_LIB: Any = _SODIUM.lib
_IDENTIFIER_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"

X25519PublicKeyHex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
SaltHex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
ShortcutAxis: TypeAlias = Literal["hardware_family", "hardware_identity", "fault_family"]
RecipientStage: TypeAlias = Literal["train_prediction", "holdout_evaluation"]


class ShortcutReleaseError(ValueError):
    """An envelope, recipient, context, or cryptographic operation is invalid."""


class ShortcutReleaseModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _strict_revalidate(value: _ModelT, model_type: type[_ModelT], *, label: str) -> _ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="python"), strict=True)
    except ValidationError as error:
        raise ShortcutReleaseError(f"{label} failed strict revalidation") from error


class ShortcutArtifactBinding(ShortcutReleaseModel):
    path: str = Field(min_length=1)
    sha256: Sha256
    bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def path_is_relative_and_normalized(cls, value: str) -> str:
        pure = PurePosixPath(value)
        if (
            pure.is_absolute()
            or not pure.parts
            or "." in pure.parts
            or ".." in pure.parts
            or pure.as_posix() != value
        ):
            raise ValueError("release artifact path must be normalized and relative")
        return value


class X25519RecipientIdentity(ShortcutReleaseModel):
    """Public identity for one isolated recipient job.

    Private keys are deliberately absent. Callers must supply private key objects
    explicitly to the open operation.
    """

    schema_version: Literal["inbar.iter001.x25519-recipient-identity.v1"]
    recipient_actor_id: Identifier
    isolated_execution_context_id: Identifier
    recipient_encryption_key_id: Identifier
    recipient_encryption_key_epoch: int = Field(ge=0)
    recipient_x25519_public_key: X25519PublicKeyHex
    recipient_x25519_public_key_sha256: Sha256

    @model_validator(mode="after")
    def public_key_hash_is_derived(self) -> X25519RecipientIdentity:
        key_bytes = bytes.fromhex(self.recipient_x25519_public_key)
        if key_bytes == bytes(32):
            raise ValueError("recipient X25519 public key cannot be all zeroes")
        if sha256_bytes(key_bytes) != self.recipient_x25519_public_key_sha256:
            raise ValueError("recipient X25519 public-key hash mismatch")
        return self


class RuleAxisFoldAuthoritySubject(ShortcutReleaseModel):
    kind: Literal["rule_axis_fold"]
    rule_id: RuleId
    axis: ShortcutAxis
    holdout_group: str = Field(min_length=1)
    recipient_stage: RecipientStage
    scope: str = Field(min_length=1)
    incident_count: int = Field(ge=1)
    incident_ids_sha256: Sha256


class RegistryRecomputationAuthoritySubject(ShortcutReleaseModel):
    kind: Literal["registry_recomputation"]
    rule_registry_sha256: Sha256
    scope: Literal["complete_registry"]
    incident_count: int = Field(ge=1)
    incident_ids_sha256: Sha256


AuthoritySubject: TypeAlias = Annotated[
    RuleAxisFoldAuthoritySubject | RegistryRecomputationAuthoritySubject,
    Field(discriminator="kind"),
]


class ShortcutReleaseContext(ShortcutReleaseModel):
    schema_version: Literal["inbar.iter001.shortcut-release-context.v1"]
    domain: Literal["inbar.iter001.recipient-scoped-truth-release.v1"]
    iteration_id: Literal["iter001_physical_causal_evidence_acquisition"]
    acquisition_session_id: Identifier
    proposal_git_commit: Literal["551a4ffb8bad5f12312af4a074a467af6bc0ebc2"]
    amendment_document_artifact_sha256: Literal[
        "9278eb33ef5a837c0ae043112f2fb041df4faa39cf34d26787a47f2326bf360c"
    ]
    machine_proposal_artifact_sha256: Literal[
        "9c13ef9562f1842f238770fc3d2e3741a77b5db291b4a8cf6b3a66f2e218a76a"
    ]
    owner_approval_receipt_sha256: Literal[
        "482575c10bb58da6b867ee60587cefa290512fa6f09529a324cea3002fd616c3"
    ]
    canonical_acquisition_contract_binding: ShortcutArtifactBinding
    trust_registry_sha256: Sha256
    freeze_receipt_artifact_sha256: Sha256
    target_manifest_hiding_commitment_sha256: Sha256
    release_plan_sha256: Sha256
    release_id: Identifier
    phase_ordinal: int = Field(ge=0)
    previous_phase_completion_sha256: Sha256
    prerequisite_artifacts: dict[Identifier, Sha256] = Field(
        min_length=1,
        json_schema_extra={
            "additionalProperties": False,
            "propertyNames": {"pattern": _IDENTIFIER_PATTERN},
        },
    )
    recipient_actor_id: Identifier
    isolated_execution_context_id: Identifier
    recipient_encryption_key_id: Identifier
    recipient_encryption_key_epoch: int = Field(ge=0)
    recipient_x25519_public_key_sha256: Sha256
    key_preflight_receipt_artifact_sha256: Sha256
    authority_subject: AuthoritySubject

    @model_validator(mode="after")
    def approved_implementation_authority_is_fixed(self) -> ShortcutReleaseContext:
        expected = {
            "proposal_git_commit": APPROVED_PROPOSAL_COMMIT,
            "amendment_document_artifact_sha256": AMENDMENT_DOCUMENT_SHA256,
            "machine_proposal_artifact_sha256": MACHINE_PROPOSAL_SHA256,
            "owner_approval_receipt_sha256": OWNER_APPROVAL_RECEIPT_HASH,
        }
        if any(getattr(self, field) != value for field, value in expected.items()):
            raise ValueError("release context differs from the approved implementation authority")
        return self


class TargetSubsetEntry(BaseModel):
    """Interim target record boundary with exact incident membership.

    The complete mechanism-target record remains a later admission gate. Extra
    JSON fields preserve the approved target body while this primitive proves
    only nonempty target content and exact incident-set binding.
    """

    model_config = ConfigDict(extra="allow", frozen=True, strict=True)

    __pydantic_extra__: dict[str, JsonValue]
    incident_id: Identifier

    @model_validator(mode="after")
    def target_content_is_nonempty(self) -> TargetSubsetEntry:
        if not self.__pydantic_extra__:
            raise ValueError("target subset entry must contain target content")
        return self


class TargetEnvelope(ShortcutReleaseModel):
    schema_version: Literal["inbar.iter001.target-envelope.v1"]
    release_context: ShortcutReleaseContext
    target_subset: tuple[TargetSubsetEntry, ...] = Field(min_length=1)
    salt_hex: SaltHex

    @model_validator(mode="after")
    def target_count_matches_release_subject(self) -> TargetEnvelope:
        if len(self.target_subset) != self.release_context.authority_subject.incident_count:
            raise ValueError("target subset count differs from the release context")
        incident_ids = tuple(item.incident_id for item in self.target_subset)
        expected_root = incident_id_list_sha256(incident_ids)
        if expected_root != self.release_context.authority_subject.incident_ids_sha256:
            raise ValueError("target subset incident root differs from the release context")
        return self


@dataclass(frozen=True)
class SealedTargetEnvelope:
    ciphertext: bytes
    envelope_commitment_sha256: Sha256


class SaltClaimStore(Protocol):
    """Port for a global atomic, durable, never-rollback salt claim."""

    def claim_once(
        self,
        *,
        salt_hex: SaltHex,
        envelope_commitment_sha256: Sha256,
    ) -> None: ...


def release_padding_length(incident_count: int) -> int:
    if (
        not isinstance(incident_count, int)
        or isinstance(incident_count, bool)
        or incident_count < 1
    ):
        raise ShortcutReleaseError("release incident count must be a positive integer")
    padding_length = PADDING_UNIT_BYTES * (incident_count + 1)
    if padding_length > sys.maxsize:
        raise ShortcutReleaseError("release padding length exceeds the platform size limit")
    return padding_length


def envelope_commitment(envelope: TargetEnvelope) -> str:
    """Hash the exact canonical envelope payload."""

    validated = _strict_revalidate(envelope, TargetEnvelope, label="target envelope")
    return sha256_value(validated)


def frame_target_envelope(envelope: TargetEnvelope) -> bytes:
    validated = _strict_revalidate(envelope, TargetEnvelope, label="target envelope")
    payload = canonical_json(validated)
    return struct.pack(">Q", len(payload)) + payload


def _sodium_pad_exact(data: bytes, padding_length: int) -> bytes:
    """Call libsodium with both blocksize and maximum buffer length set to P."""

    if len(data) >= padding_length:
        raise ShortcutReleaseError("framed envelope length must be strictly less than P")
    try:
        buffer = _SODIUM_FFI.new("unsigned char[]", padding_length)
    except (MemoryError, OverflowError) as error:
        raise ShortcutReleaseError("release padding buffer cannot be allocated") from error
    _SODIUM_FFI.memmove(buffer, data, len(data))
    padded_length = _SODIUM_FFI.new("size_t *")
    result = _SODIUM_LIB.sodium_pad(
        padded_length,
        buffer,
        len(data),
        padding_length,
        padding_length,
    )
    if result != 0 or padded_length[0] != padding_length:
        raise ShortcutReleaseError("libsodium did not produce the exact padded length")
    return bytes(_SODIUM_FFI.buffer(buffer, padding_length))


def _sodium_unpad_exact(data: bytes, padding_length: int) -> bytes:
    if len(data) != padding_length:
        raise ShortcutReleaseError("decrypted envelope length differs from P")
    buffer = _SODIUM_FFI.new("unsigned char[]", data)
    unpadded_length = _SODIUM_FFI.new("size_t *")
    result = _SODIUM_LIB.sodium_unpad(
        unpadded_length,
        buffer,
        len(data),
        padding_length,
    )
    if result != 0:
        raise ShortcutReleaseError("target envelope padding is invalid")
    return bytes(_SODIUM_FFI.buffer(buffer, unpadded_length[0]))


def _recipient_matches_context(
    recipient: X25519RecipientIdentity,
    context: ShortcutReleaseContext,
) -> bool:
    return (
        recipient.recipient_actor_id == context.recipient_actor_id
        and recipient.isolated_execution_context_id == context.isolated_execution_context_id
        and recipient.recipient_encryption_key_id == context.recipient_encryption_key_id
        and recipient.recipient_encryption_key_epoch == context.recipient_encryption_key_epoch
    )


def seal_target_envelope(
    envelope: TargetEnvelope,
    recipient: X25519RecipientIdentity,
    *,
    salt_claim_store: SaltClaimStore,
) -> SealedTargetEnvelope:
    """Seal one already-authorized payload to an explicitly supplied recipient."""

    validated_envelope = _strict_revalidate(envelope, TargetEnvelope, label="target envelope")
    validated_recipient = _strict_revalidate(
        recipient,
        X25519RecipientIdentity,
        label="recipient identity",
    )
    context = validated_envelope.release_context
    if not _recipient_matches_context(validated_recipient, context):
        raise ShortcutReleaseError("recipient identity differs from the release context")
    public_key_bytes = bytes.fromhex(validated_recipient.recipient_x25519_public_key)
    if sha256_bytes(public_key_bytes) != context.recipient_x25519_public_key_sha256:
        raise ShortcutReleaseError("recipient public-key bytes differ from the release context")
    commitment = envelope_commitment(validated_envelope)
    if salt_claim_store is None:
        raise ShortcutReleaseError("an atomic durable salt claim store is required")
    try:
        salt_claim_store.claim_once(
            salt_hex=validated_envelope.salt_hex,
            envelope_commitment_sha256=commitment,
        )
    except ShortcutReleaseError:
        raise
    except Exception as error:
        raise ShortcutReleaseError("target envelope salt claim failed") from error
    padding_length = release_padding_length(context.authority_subject.incident_count)
    framed = frame_target_envelope(validated_envelope)
    padded = _sodium_pad_exact(framed, padding_length)
    try:
        ciphertext = SealedBox(PublicKey(public_key_bytes)).encrypt(padded)
    except (CryptoError, TypeError, ValueError) as error:
        raise ShortcutReleaseError("target envelope encryption failed") from error
    if len(ciphertext) != padding_length + crypto_box_SEALBYTES:
        raise ShortcutReleaseError("sealed-box ciphertext length differs from P plus overhead")
    return SealedTargetEnvelope(
        ciphertext=ciphertext,
        envelope_commitment_sha256=commitment,
    )


def expected_ciphertext_length(context: ShortcutReleaseContext) -> int:
    validated = _strict_revalidate(context, ShortcutReleaseContext, label="release context")
    return release_padding_length(validated.authority_subject.incident_count) + crypto_box_SEALBYTES


def _json_object_without_duplicates(data: bytes) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ShortcutReleaseError("target envelope contains duplicate JSON keys")
            value[key] = item
        return value

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except ShortcutReleaseError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ShortcutReleaseError("target envelope is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ShortcutReleaseError("target envelope JSON must be an object")
    return cast(dict[str, Any], value)


def _unframe_target_envelope(data: bytes) -> tuple[TargetEnvelope, bytes]:
    if len(data) < FRAME_HEADER_BYTES:
        raise ShortcutReleaseError("target envelope frame is truncated")
    declared_length = struct.unpack(">Q", data[:FRAME_HEADER_BYTES])[0]
    payload = data[FRAME_HEADER_BYTES:]
    if declared_length != len(payload):
        raise ShortcutReleaseError("target envelope frame length or trailing bytes are invalid")
    value = _json_object_without_duplicates(payload)
    try:
        canonical_payload = canonical_json(value)
    except (TypeError, ValueError) as error:
        raise ShortcutReleaseError("target envelope JSON cannot be canonicalized") from error
    if canonical_payload != payload:
        raise ShortcutReleaseError("target envelope JSON is not compact canonical JSON")
    try:
        envelope = TargetEnvelope.model_validate_json(payload, strict=True)
    except ValueError as error:
        raise ShortcutReleaseError("target envelope violates its typed contract") from error
    if canonical_json(envelope) != payload:  # pragma: no cover - future normalization defense
        raise ShortcutReleaseError("target envelope omits or normalizes typed payload fields")
    return envelope, payload


def open_target_envelope(
    ciphertext: bytes,
    recipient_private_key: PrivateKey,
    *,
    expected_release_context: ShortcutReleaseContext,
    expected_envelope_commitment_sha256: Sha256,
) -> TargetEnvelope:
    """Open and fully validate one envelope with an explicit private key."""

    validated_context = _strict_revalidate(
        expected_release_context,
        ShortcutReleaseContext,
        label="expected release context",
    )
    public_key_bytes = recipient_private_key.public_key.encode()
    expected_key_hash = validated_context.recipient_x25519_public_key_sha256
    if sha256_bytes(public_key_bytes) != expected_key_hash:
        raise ShortcutReleaseError("recipient private key differs from the release context")
    padding_length = release_padding_length(validated_context.authority_subject.incident_count)
    if len(ciphertext) != padding_length + crypto_box_SEALBYTES:
        raise ShortcutReleaseError("sealed-box ciphertext length differs from P plus overhead")
    try:
        padded = SealedBox(recipient_private_key).decrypt(ciphertext)
    except (CryptoError, TypeError, ValueError) as error:
        raise ShortcutReleaseError("target envelope decryption failed") from error
    unpadded = _sodium_unpad_exact(padded, padding_length)
    envelope, _ = _unframe_target_envelope(unpadded)
    if envelope.release_context != validated_context:
        raise ShortcutReleaseError("target envelope release context mismatch")
    if envelope_commitment(envelope) != expected_envelope_commitment_sha256:
        raise ShortcutReleaseError("target envelope commitment mismatch")
    return envelope
