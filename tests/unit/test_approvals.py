from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from nacl.signing import SigningKey

from fieldtrue.approvals import (
    ApprovalSubjectKind,
    ApprovalVerificationError,
    authorization_subject_hash,
    issue_approval,
    verify_approval,
)
from fieldtrue.domain import ExecutionAuthority, SafetyEnvelope
from fieldtrue.planning import NoEligibleTestError, select_discriminating_test
from tests.helpers import APPROVAL_HASH, HASH_A, hypotheses, informative_test


def _testbed_approval(signing_key: SigningKey):
    candidate = informative_test(
        authority=ExecutionAuthority.TESTBED,
        approval_hash=APPROVAL_HASH,
    )
    envelope = SafetyEnvelope(
        envelope_id="testbed-envelope",
        authority=ExecutionAuthority.TESTBED,
        allowed_test_ids=(candidate.test_id,),
        max_risk=0.2,
        satisfied_preconditions=("load-isolated",),
        approval_receipt_hash=APPROVAL_HASH,
    )
    subject = authorization_subject_hash(
        ApprovalSubjectKind.TEST_EXECUTION,
        {
            "candidate": candidate.model_dump(mode="json", exclude={"approval_receipt_hash"}),
            "safety_envelope": envelope.model_dump(mode="json", exclude={"approval_receipt_hash"}),
        },
    )
    now = datetime(2026, 7, 14, tzinfo=UTC)
    receipt = issue_approval(
        signing_key,
        approval_id="approval-1",
        issuer_id="daniel",
        subject_kind=ApprovalSubjectKind.TEST_EXECUTION,
        subject_sha256=subject,
        authority=ExecutionAuthority.TESTBED,
        scope="isolated fixture only",
        max_risk=0.2,
        max_cost_usd="0",
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
        nonce=HASH_A,
    )
    candidate = candidate.model_copy(update={"approval_receipt_hash": receipt.receipt_hash})
    envelope = envelope.model_copy(update={"approval_receipt_hash": receipt.receipt_hash})
    return candidate, envelope, receipt, now


def test_signed_scoped_approval_is_required_for_testbed_selection() -> None:
    key = SigningKey.generate()
    candidate, envelope, receipt, now = _testbed_approval(key)
    selected = select_discriminating_test(
        hypotheses(),
        (candidate,),
        envelope,
        approval_receipt=receipt,
        expected_approval_signer=key.verify_key.encode().hex(),
        approval_time=now,
    )
    assert selected.test_id == candidate.test_id
    with pytest.raises(NoEligibleTestError):
        select_discriminating_test(hypotheses(), (candidate,), envelope)


def test_wrong_signer_expiry_and_scope_fail_closed() -> None:
    key = SigningKey.generate()
    candidate, envelope, receipt, now = _testbed_approval(key)
    with pytest.raises(ApprovalVerificationError, match="pinned issuer"):
        verify_approval(
            receipt,
            expected_signer_public_key=SigningKey.generate().verify_key.encode().hex(),
            expected_subject_kind=ApprovalSubjectKind.TEST_EXECUTION,
            expected_subject_sha256=receipt.subject_sha256,
            expected_authority=ExecutionAuthority.TESTBED,
            at=now,
        )
    with pytest.raises(ApprovalVerificationError, match="currently valid"):
        verify_approval(
            receipt,
            expected_signer_public_key=key.verify_key.encode().hex(),
            expected_subject_kind=ApprovalSubjectKind.TEST_EXECUTION,
            expected_subject_sha256=receipt.subject_sha256,
            expected_authority=ExecutionAuthority.TESTBED,
            at=receipt.expires_at,
        )
    with pytest.raises(NoEligibleTestError):
        select_discriminating_test(
            hypotheses(),
            (candidate,),
            envelope,
            approval_receipt=receipt,
            expected_approval_signer=key.verify_key.encode().hex(),
            approval_time=receipt.expires_at,
        )


def test_approval_enforces_risk_and_cost_caps() -> None:
    key = SigningKey.generate()
    _, _, receipt, now = _testbed_approval(key)
    with pytest.raises(ApprovalVerificationError, match="risk"):
        verify_approval(
            receipt,
            expected_signer_public_key=key.verify_key.encode().hex(),
            expected_subject_kind=receipt.subject_kind,
            expected_subject_sha256=receipt.subject_sha256,
            expected_authority=receipt.authority,
            required_risk=0.3,
            at=now,
        )
    with pytest.raises(ApprovalVerificationError, match="cost"):
        verify_approval(
            receipt,
            expected_signer_public_key=key.verify_key.encode().hex(),
            expected_subject_kind=receipt.subject_kind,
            expected_subject_sha256=receipt.subject_sha256,
            expected_authority=receipt.authority,
            required_cost_usd="1",
            at=now,
        )
