"""Pinned, signed, scoped authorization receipts for boundary-crossing actions."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal, Self

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey
from pydantic import BaseModel, ConfigDict, Field, model_validator

from fieldtrue.canonical import sha256_value
from fieldtrue.domain import (
    Ed25519PublicKey,
    ExecutionAuthority,
    HexSignature,
    Identifier,
    Sha256,
)


class ApprovalVerificationError(ValueError):
    """An approval is invalid, expired, untrusted, or out of scope."""


class ApprovalSubjectKind(StrEnum):
    TEST_EXECUTION = "test_execution"
    RECOVERY_EXECUTION = "recovery_execution"
    REMOTE_JOB = "remote_job"


class ApprovalReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["fieldtrue.approval-receipt.v1"] = "fieldtrue.approval-receipt.v1"
    approval_id: Identifier
    issuer_id: Identifier
    subject_kind: ApprovalSubjectKind
    subject_sha256: Sha256
    authority: ExecutionAuthority
    scope: str = Field(min_length=1)
    max_risk: float = Field(ge=0.0, le=1.0)
    max_cost_usd: str = Field(pattern=r"^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$")
    not_before: datetime
    expires_at: datetime
    nonce: Sha256
    signer_public_key: Ed25519PublicKey
    receipt_hash: Sha256
    signature: HexSignature

    @model_validator(mode="after")
    def validity_window_is_well_formed(self) -> Self:
        for value in (self.not_before, self.expires_at):
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError("approval timestamps must be timezone-aware")
        if self.expires_at <= self.not_before:
            raise ValueError("approval expiry must follow its start")
        return self


class VerifiedApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    approval_id: Identifier
    subject_kind: ApprovalSubjectKind
    subject_sha256: Sha256
    authority: ExecutionAuthority
    scope: str
    max_risk: float
    max_cost_usd: str
    expires_at: datetime
    receipt_hash: Sha256
    issuer_id: Identifier
    signer_public_key: Ed25519PublicKey
    verified_at: datetime


def _receipt_body(receipt: ApprovalReceipt | dict[str, Any]) -> dict[str, Any]:
    body = (
        receipt.model_dump(mode="json") if isinstance(receipt, ApprovalReceipt) else dict(receipt)
    )
    body.pop("receipt_hash", None)
    body.pop("signature", None)
    return body


def authorization_subject_hash(kind: ApprovalSubjectKind, subject: Any) -> str:
    return sha256_value(
        {
            "domain": "fieldtrue.authorization-subject.v1",
            "kind": kind.value,
            "subject": subject,
        }
    )


def issue_approval(
    signing_key: SigningKey,
    *,
    approval_id: Identifier,
    issuer_id: Identifier,
    subject_kind: ApprovalSubjectKind,
    subject_sha256: Sha256,
    authority: ExecutionAuthority,
    scope: str,
    max_risk: float,
    max_cost_usd: str,
    not_before: datetime,
    expires_at: datetime,
    nonce: Sha256,
) -> ApprovalReceipt:
    body: dict[str, Any] = {
        "schema_version": "fieldtrue.approval-receipt.v1",
        "approval_id": approval_id,
        "issuer_id": issuer_id,
        "subject_kind": subject_kind,
        "subject_sha256": subject_sha256,
        "authority": authority,
        "scope": scope,
        "max_risk": max_risk,
        "max_cost_usd": max_cost_usd,
        "not_before": not_before,
        "expires_at": expires_at,
        "nonce": nonce,
        "signer_public_key": signing_key.verify_key.encode().hex(),
    }
    receipt_hash = sha256_value(_receipt_body(body))
    signature = signing_key.sign(bytes.fromhex(receipt_hash)).signature.hex()
    return ApprovalReceipt.model_validate(
        {**body, "receipt_hash": receipt_hash, "signature": signature}
    )


def verify_approval(
    receipt: ApprovalReceipt,
    *,
    expected_signer_public_key: Ed25519PublicKey,
    expected_subject_kind: ApprovalSubjectKind,
    expected_subject_sha256: Sha256,
    expected_authority: ExecutionAuthority,
    required_risk: float = 0.0,
    required_cost_usd: str = "0",
    at: datetime | None = None,
) -> VerifiedApproval:
    verified_at = at or datetime.now(UTC)
    if verified_at.tzinfo is None or verified_at.utcoffset() is None:
        raise ApprovalVerificationError("approval verification time must be timezone-aware")
    if receipt.signer_public_key != expected_signer_public_key:
        raise ApprovalVerificationError("approval signer does not match the pinned issuer")
    if sha256_value(_receipt_body(receipt)) != receipt.receipt_hash:
        raise ApprovalVerificationError("approval receipt hash mismatch")
    try:
        VerifyKey(bytes.fromhex(expected_signer_public_key)).verify(
            bytes.fromhex(receipt.receipt_hash), bytes.fromhex(receipt.signature)
        )
    except (BadSignatureError, ValueError) as error:
        raise ApprovalVerificationError("approval signature mismatch") from error
    if not receipt.not_before <= verified_at < receipt.expires_at:
        raise ApprovalVerificationError("approval is not currently valid")
    if (
        receipt.subject_kind != expected_subject_kind
        or receipt.subject_sha256 != expected_subject_sha256
        or receipt.authority != expected_authority
    ):
        raise ApprovalVerificationError("approval scope does not match the requested action")
    if required_risk > receipt.max_risk:
        raise ApprovalVerificationError("requested risk exceeds approval")
    if Decimal(required_cost_usd) > Decimal(receipt.max_cost_usd):
        raise ApprovalVerificationError("requested cost exceeds approval")
    return VerifiedApproval(
        approval_id=receipt.approval_id,
        subject_kind=receipt.subject_kind,
        subject_sha256=receipt.subject_sha256,
        authority=receipt.authority,
        scope=receipt.scope,
        max_risk=receipt.max_risk,
        max_cost_usd=receipt.max_cost_usd,
        expires_at=receipt.expires_at,
        receipt_hash=receipt.receipt_hash,
        issuer_id=receipt.issuer_id,
        signer_public_key=receipt.signer_public_key,
        verified_at=verified_at,
    )
