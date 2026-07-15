from __future__ import annotations

import json
import struct
from collections.abc import Callable
from pathlib import Path

import pytest
from nacl.public import PrivateKey, SealedBox
from pydantic import ValidationError

import fieldtrue.shortcut_v2_release as release
from fieldtrue.canonical import canonical_json, sha256_bytes
from fieldtrue.shortcut_contracts import (
    AMENDMENT_DOCUMENT_SHA256,
    APPROVED_PROPOSAL_COMMIT,
    MACHINE_PROPOSAL_SHA256,
    OWNER_APPROVAL_RECEIPT_HASH,
)
from fieldtrue.shortcut_v2_hashing import incident_id_list_sha256
from fieldtrue.shortcut_v2_release import (
    ITERATION_ID,
    RELEASE_CONTEXT_DOMAIN,
    RELEASE_CONTEXT_SCHEMA,
    TARGET_ENVELOPE_SCHEMA,
    RegistryRecomputationAuthoritySubject,
    RuleAxisFoldAuthoritySubject,
    ShortcutArtifactBinding,
    ShortcutReleaseContext,
    ShortcutReleaseError,
    TargetEnvelope,
    X25519RecipientIdentity,
    envelope_commitment,
    expected_ciphertext_length,
    open_target_envelope,
    release_padding_length,
    seal_target_envelope,
)

ZERO_HASH = "0" * 64
SALT = "1" * 64


class _SaltStore:
    def __init__(self) -> None:
        self.claims: dict[str, str] = {}

    def claim_once(self, *, salt_hex: str, envelope_commitment_sha256: str) -> None:
        if salt_hex in self.claims:
            raise ShortcutReleaseError("target envelope salt was already used")
        self.claims[salt_hex] = envelope_commitment_sha256


def _seal(
    envelope: TargetEnvelope,
    recipient: X25519RecipientIdentity,
    *,
    salt_store: _SaltStore | None = None,
) -> release.SealedTargetEnvelope:
    return seal_target_envelope(
        envelope,
        recipient,
        salt_claim_store=salt_store or _SaltStore(),
    )


def _recipient(
    private_key: PrivateKey,
    *,
    actor_id: str = "shortcut-worker-001",
    context_id: str = "ctx:rule:axis:fold:train_prediction",
) -> X25519RecipientIdentity:
    public_key = private_key.public_key.encode()
    return X25519RecipientIdentity(
        schema_version="inbar.iter001.x25519-recipient-identity.v1",
        recipient_actor_id=actor_id,
        isolated_execution_context_id=context_id,
        recipient_encryption_key_id=f"key:{context_id}",
        recipient_encryption_key_epoch=1,
        recipient_x25519_public_key=public_key.hex(),
        recipient_x25519_public_key_sha256=sha256_bytes(public_key),
    )


def _subject(*, incident_count: int = 2) -> RuleAxisFoldAuthoritySubject:
    incident_ids = tuple(f"incident-{index:03d}" for index in range(incident_count))
    return RuleAxisFoldAuthoritySubject(
        kind="rule_axis_fold",
        rule_id="cheapest-deterministic-evidence-only",
        axis="hardware_family",
        holdout_group="family-a",
        recipient_stage="train_prediction",
        scope="exact-fold-train-targets",
        incident_count=incident_count,
        incident_ids_sha256=incident_id_list_sha256(incident_ids),
    )


def test_rule_axis_fold_subject_rejects_unregistered_rule_id() -> None:
    payload = _subject().model_dump(mode="python")
    payload["rule_id"] = "unregistered-rule"

    with pytest.raises(ValidationError):
        RuleAxisFoldAuthoritySubject.model_validate(payload, strict=True)


def _context(
    recipient: X25519RecipientIdentity,
    *,
    subject: RuleAxisFoldAuthoritySubject | RegistryRecomputationAuthoritySubject | None = None,
    release_id: str = "release-001",
) -> ShortcutReleaseContext:
    return ShortcutReleaseContext(
        schema_version=RELEASE_CONTEXT_SCHEMA,
        domain=RELEASE_CONTEXT_DOMAIN,
        iteration_id=ITERATION_ID,
        acquisition_session_id="acquisition-session-001",
        proposal_git_commit=APPROVED_PROPOSAL_COMMIT,
        amendment_document_artifact_sha256=AMENDMENT_DOCUMENT_SHA256,
        machine_proposal_artifact_sha256=MACHINE_PROPOSAL_SHA256,
        owner_approval_receipt_sha256=OWNER_APPROVAL_RECEIPT_HASH,
        canonical_acquisition_contract_binding=ShortcutArtifactBinding(
            path="protocol/acquisition/iter001_contract.json",
            sha256="6" * 64,
            bytes=1024,
            media_type="application/json",
        ),
        trust_registry_sha256="7" * 64,
        freeze_receipt_artifact_sha256="8" * 64,
        target_manifest_hiding_commitment_sha256="9" * 64,
        release_plan_sha256="a" * 64,
        release_id=release_id,
        phase_ordinal=0,
        previous_phase_completion_sha256=ZERO_HASH,
        prerequisite_artifacts={"freeze": "b" * 64},
        recipient_actor_id=recipient.recipient_actor_id,
        isolated_execution_context_id=recipient.isolated_execution_context_id,
        recipient_encryption_key_id=recipient.recipient_encryption_key_id,
        recipient_encryption_key_epoch=recipient.recipient_encryption_key_epoch,
        recipient_x25519_public_key_sha256=recipient.recipient_x25519_public_key_sha256,
        key_preflight_receipt_artifact_sha256="c" * 64,
        authority_subject=subject or _subject(),
    )


def _envelope(
    context: ShortcutReleaseContext,
    *,
    salt: str = SALT,
    value: str = "target-a",
) -> TargetEnvelope:
    count = context.authority_subject.incident_count
    return TargetEnvelope(
        schema_version=TARGET_ENVELOPE_SCHEMA,
        release_context=context,
        target_subset=tuple(
            {"incident_id": f"incident-{index:03d}", "target_prediction_key": value}
            for index in range(count)
        ),
        salt_hex=salt,
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("proposal_git_commit", "f" * 40),
        ("amendment_document_artifact_sha256", "f" * 64),
        ("machine_proposal_artifact_sha256", "f" * 64),
        ("owner_approval_receipt_sha256", "f" * 64),
    ],
)
def test_release_context_rejects_approved_authority_substitution(
    field: str,
    replacement: str,
) -> None:
    recipient = _recipient(PrivateKey.generate())
    context = _context(recipient)
    forged_context = context.model_copy(update={field: replacement})
    forged_envelope = _envelope(context).model_copy(update={"release_context": forged_context})

    with pytest.raises(ShortcutReleaseError, match="strict revalidation"):
        _seal(forged_envelope, recipient)


def _encrypt_padded(padded: bytes, private_key: PrivateKey) -> bytes:
    return SealedBox(private_key.public_key).encrypt(padded)


def _encrypt_payload(
    payload: bytes,
    private_key: PrivateKey,
    context: ShortcutReleaseContext,
    *,
    declared_length: int | None = None,
    trailing: bytes = b"",
) -> bytes:
    frame = struct.pack(">Q", len(payload) if declared_length is None else declared_length)
    frame += payload + trailing
    padded = release._sodium_pad_exact(
        frame,
        release_padding_length(context.authority_subject.incident_count),
    )
    return _encrypt_padded(padded, private_key)


def _encrypt_unpadded(
    unpadded: bytes,
    private_key: PrivateKey,
    context: ShortcutReleaseContext,
) -> bytes:
    padded = release._sodium_pad_exact(
        unpadded,
        release_padding_length(context.authority_subject.incident_count),
    )
    return _encrypt_padded(padded, private_key)


def test_models_match_the_machine_release_policy_exactly() -> None:
    repo = Path(__file__).resolve().parents[2]
    proposal = json.loads((repo / "protocol/amendments/iter001_001.json").read_bytes())
    policy = proposal["release_policy"]

    assert list(ShortcutReleaseContext.model_fields) == policy["release_context_fields"]
    assert list(TargetEnvelope.model_fields) == policy["envelope"]["payload_fields"]
    assert (
        list(RuleAxisFoldAuthoritySubject.model_fields)
        == policy["release_context_subject_union"]["rule_axis_fold"]
    )
    assert (
        list(RegistryRecomputationAuthoritySubject.model_fields)
        == policy["release_context_subject_union"]["registry_recomputation"]
    )
    assert release.PADDING_UNIT_BYTES == 16_384
    assert release.crypto_box_SEALBYTES == 48


def test_recipient_scoped_envelope_round_trip_and_exact_lengths() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    envelope = _envelope(context)

    sealed = _seal(envelope, recipient)
    opened = open_target_envelope(
        sealed.ciphertext,
        private_key,
        expected_release_context=context,
        expected_envelope_commitment_sha256=sealed.envelope_commitment_sha256,
    )

    assert opened == envelope
    assert sealed.envelope_commitment_sha256 == envelope_commitment(envelope)
    assert len(sealed.ciphertext) == expected_ciphertext_length(context)
    assert release._sodium_unpad_exact(
        release._sodium_pad_exact(
            release.frame_target_envelope(envelope), release_padding_length(2)
        ),
        release_padding_length(2),
    ) == release.frame_target_envelope(envelope)


def test_registry_recomputation_subject_is_a_typed_release_context() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key, actor_id="final-evaluator", context_id="ctx:final")
    subject = RegistryRecomputationAuthoritySubject(
        kind="registry_recomputation",
        rule_registry_sha256="d" * 64,
        scope="complete_registry",
        incident_count=1,
        incident_ids_sha256=incident_id_list_sha256(("incident-000",)),
    )
    context = _context(recipient, subject=subject, release_id="final-release")

    sealed = _seal(_envelope(context), recipient)

    assert context.authority_subject.kind == "registry_recomputation"
    assert len(sealed.ciphertext) == expected_ciphertext_length(context)


def test_wrong_recipient_and_ciphertext_tampering_are_rejected() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    envelope = _envelope(context)
    sealed = _seal(envelope, recipient)

    wrong_key = PrivateKey.generate()
    wrong_recipient = _recipient(
        wrong_key,
        actor_id=recipient.recipient_actor_id,
        context_id=recipient.isolated_execution_context_id,
    )
    wrong_context = _context(wrong_recipient)
    with pytest.raises(ShortcutReleaseError, match="decryption failed"):
        open_target_envelope(
            sealed.ciphertext,
            wrong_key,
            expected_release_context=wrong_context,
            expected_envelope_commitment_sha256=sealed.envelope_commitment_sha256,
        )

    tampered = bytearray(sealed.ciphertext)
    tampered[len(tampered) // 2] ^= 1
    with pytest.raises(ShortcutReleaseError, match="decryption failed"):
        open_target_envelope(
            bytes(tampered),
            private_key,
            expected_release_context=context,
            expected_envelope_commitment_sha256=sealed.envelope_commitment_sha256,
        )


@pytest.mark.parametrize("salt", ["A" * 64, "1" * 63, "g" * 64, "11" * 64])
def test_malformed_salts_are_rejected(salt: str) -> None:
    private_key = PrivateKey.generate()
    with pytest.raises(ValidationError, match="salt_hex"):
        _envelope(_context(_recipient(private_key)), salt=salt)


def test_salt_reuse_is_rejected_by_mandatory_claim_store() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    envelope = _envelope(_context(recipient))

    store = _SaltStore()
    _seal(envelope, recipient, salt_store=store)
    with pytest.raises(ShortcutReleaseError, match="already used"):
        _seal(envelope, recipient, salt_store=store)


def test_salt_claim_is_required_fails_closed_and_is_burned_before_encryption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    envelope = _envelope(_context(recipient))

    with pytest.raises(ShortcutReleaseError, match="claim store is required"):
        seal_target_envelope(envelope, recipient, salt_claim_store=None)  # type: ignore[arg-type]

    encryption_calls = 0

    class EncryptionFailure:
        def __init__(self, _key: object) -> None:
            pass

        def encrypt(self, _plaintext: bytes) -> bytes:
            nonlocal encryption_calls
            encryption_calls += 1
            raise ValueError("injected encryption failure")

    store = _SaltStore()
    monkeypatch.setattr(release, "SealedBox", EncryptionFailure)
    with pytest.raises(ShortcutReleaseError, match="encryption failed"):
        _seal(envelope, recipient, salt_store=store)
    assert encryption_calls == 1

    with pytest.raises(ShortcutReleaseError, match="already used"):
        _seal(envelope, recipient, salt_store=store)
    assert encryption_calls == 1


def test_salt_claim_store_failure_prevents_encryption(monkeypatch: pytest.MonkeyPatch) -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    envelope = _envelope(_context(recipient))
    encryption_calls = 0

    class CountingSealedBox:
        def __init__(self, _key: object) -> None:
            nonlocal encryption_calls
            encryption_calls += 1

    class FailingStore:
        def claim_once(self, **_values: str) -> None:
            raise OSError("injected durable-store failure")

    monkeypatch.setattr(release, "SealedBox", CountingSealedBox)
    with pytest.raises(ShortcutReleaseError, match="salt claim failed"):
        seal_target_envelope(
            envelope,
            recipient,
            salt_claim_store=FailingStore(),
        )
    assert encryption_calls == 0


def test_ciphertext_length_is_target_independent_for_one_incident_count() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)

    store = _SaltStore()
    first = _seal(_envelope(context, value="short"), recipient, salt_store=store)
    second = _seal(
        _envelope(context, salt="2" * 64, value="a much longer target value"),
        recipient,
        salt_store=store,
    )

    assert len(first.ciphertext) == len(second.ciphertext) == expected_ciphertext_length(context)
    assert first.ciphertext != second.ciphertext


def test_prepad_length_equal_to_or_greater_than_p_is_rejected() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    subject = _subject(incident_count=1)
    context = _context(recipient, subject=subject)
    envelope = _envelope(context, value="x" * release_padding_length(1))

    with pytest.raises(ShortcutReleaseError, match="strictly less than P"):
        _seal(envelope, recipient)


def test_invalid_padding_is_rejected_after_valid_sealed_box_open() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    padded_length = release_padding_length(context.authority_subject.incident_count)
    ciphertext = _encrypt_padded(bytes(padded_length), private_key)

    with pytest.raises(ShortcutReleaseError, match="padding is invalid"):
        open_target_envelope(
            ciphertext,
            private_key,
            expected_release_context=context,
            expected_envelope_commitment_sha256=ZERO_HASH,
        )


@pytest.mark.parametrize(
    ("build_ciphertext", "message"),
    [
        (
            lambda payload, key, context: _encrypt_payload(
                payload, key, context, declared_length=len(payload) + 1
            ),
            "frame length",
        ),
        (
            lambda payload, key, context: _encrypt_payload(payload, key, context, trailing=b"x"),
            "trailing bytes",
        ),
        (
            lambda _payload, key, context: _encrypt_payload(b'{"broken":', key, context),
            "valid UTF-8 JSON",
        ),
        (
            lambda payload, key, context: _encrypt_payload(
                json.dumps(json.loads(payload), indent=2, sort_keys=True).encode(), key, context
            ),
            "compact canonical JSON",
        ),
        (
            lambda payload, key, context: _encrypt_payload(
                b'{"salt_hex":"' + SALT.encode() + b'",' + payload[1:], key, context
            ),
            "duplicate JSON keys",
        ),
    ],
)
def test_framing_json_and_trailing_byte_failures_are_rejected(
    build_ciphertext: Callable[[bytes, PrivateKey, ShortcutReleaseContext], bytes],
    message: str,
) -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    envelope = _envelope(context)
    payload = canonical_json(envelope)
    ciphertext = build_ciphertext(payload, private_key, context)

    with pytest.raises(ShortcutReleaseError, match=message):
        open_target_envelope(
            ciphertext,
            private_key,
            expected_release_context=context,
            expected_envelope_commitment_sha256=envelope_commitment(envelope),
        )


def test_release_context_and_commitment_substitution_are_rejected() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    envelope = _envelope(context)
    sealed = _seal(envelope, recipient)
    substituted_context = _context(recipient, release_id="release-002")

    with pytest.raises(ShortcutReleaseError, match="release context mismatch"):
        open_target_envelope(
            sealed.ciphertext,
            private_key,
            expected_release_context=substituted_context,
            expected_envelope_commitment_sha256=sealed.envelope_commitment_sha256,
        )
    with pytest.raises(ShortcutReleaseError, match="commitment mismatch"):
        open_target_envelope(
            sealed.ciphertext,
            private_key,
            expected_release_context=context,
            expected_envelope_commitment_sha256=ZERO_HASH,
        )


def test_canonical_json_cannot_omit_defaulted_typed_fields() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    envelope = _envelope(context)
    incomplete = envelope.model_dump(mode="json")
    incomplete.pop("schema_version")
    ciphertext = _encrypt_payload(canonical_json(incomplete), private_key, context)

    with pytest.raises(ShortcutReleaseError, match="typed contract"):
        open_target_envelope(
            ciphertext,
            private_key,
            expected_release_context=context,
            expected_envelope_commitment_sha256=envelope_commitment(envelope),
        )


def test_recipient_identity_and_ciphertext_length_substitution_are_rejected() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    envelope = _envelope(context)
    sealed = _seal(envelope, recipient)
    different_actor = recipient.model_copy(update={"recipient_actor_id": "substitute-worker"})

    with pytest.raises(ShortcutReleaseError, match="recipient identity"):
        _seal(envelope, different_actor)
    with pytest.raises(ShortcutReleaseError, match="ciphertext length"):
        open_target_envelope(
            sealed.ciphertext[:-1],
            private_key,
            expected_release_context=context,
            expected_envelope_commitment_sha256=sealed.envelope_commitment_sha256,
        )


def test_recipient_identity_hash_and_target_subset_count_are_derived() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    body = recipient.model_dump(mode="json")
    body["recipient_x25519_public_key_sha256"] = ZERO_HASH
    with pytest.raises(ValidationError, match="public-key hash mismatch"):
        X25519RecipientIdentity.model_validate(body)

    context = _context(recipient)
    with pytest.raises(ValidationError, match="target subset count"):
        TargetEnvelope(
            schema_version=TARGET_ENVELOPE_SCHEMA,
            release_context=context,
            target_subset=({"incident_id": "incident-000", "target_prediction_key": "target"},),
            salt_hex=SALT,
        )


def test_zero_x25519_key_and_invalid_release_paths_are_rejected() -> None:
    with pytest.raises(ValidationError, match="cannot be all zeroes"):
        X25519RecipientIdentity(
            schema_version="inbar.iter001.x25519-recipient-identity.v1",
            recipient_actor_id="worker",
            isolated_execution_context_id="context",
            recipient_encryption_key_id="key",
            recipient_encryption_key_epoch=0,
            recipient_x25519_public_key=ZERO_HASH,
            recipient_x25519_public_key_sha256=sha256_bytes(bytes(32)),
        )

    for path in ("/absolute", ".", "nested/../escape", "nested//artifact"):
        with pytest.raises(ValidationError, match="normalized and relative"):
            ShortcutArtifactBinding(
                path=path,
                sha256=ZERO_HASH,
                bytes=0,
                media_type="application/json",
            )


def test_subject_text_must_be_valid_utf8() -> None:
    with pytest.raises(ValidationError, match="valid string"):
        RuleAxisFoldAuthoritySubject(
            kind="rule_axis_fold",
            rule_id="rule",
            axis="hardware_family",
            holdout_group="\ud800",
            recipient_stage="train_prediction",
            scope="scope",
            incident_count=1,
            incident_ids_sha256=ZERO_HASH,
        )


def test_target_subset_entries_require_incident_and_target_content() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    one_context = _context(recipient, subject=_subject(incident_count=1))
    with pytest.raises(ValidationError, match="incident_id"):
        TargetEnvelope(
            schema_version=TARGET_ENVELOPE_SCHEMA,
            release_context=one_context,
            target_subset=({},),
            salt_hex=SALT,
        )

    with pytest.raises(ValidationError, match="target content"):
        TargetEnvelope(
            schema_version=TARGET_ENVELOPE_SCHEMA,
            release_context=one_context,
            target_subset=({"incident_id": "incident-000"},),
            salt_hex=SALT,
        )


def test_target_subset_binds_exact_canonical_incident_membership() -> None:
    recipient = _recipient(PrivateKey.generate())
    context = _context(recipient)
    correct = (
        {"incident_id": "incident-000", "target_prediction_key": "target-a"},
        {"incident_id": "incident-001", "target_prediction_key": "target-b"},
    )

    with pytest.raises(ValidationError, match="incident root"):
        TargetEnvelope(
            schema_version=TARGET_ENVELOPE_SCHEMA,
            release_context=context,
            target_subset=(correct[0], {**correct[1], "incident_id": "incident-999"}),
            salt_hex=SALT,
        )
    with pytest.raises(ValidationError, match="canonical UTF-8 order"):
        TargetEnvelope(
            schema_version=TARGET_ENVELOPE_SCHEMA,
            release_context=context,
            target_subset=tuple(reversed(correct)),
            salt_hex=SALT,
        )
    with pytest.raises(ValidationError, match="must be unique"):
        TargetEnvelope(
            schema_version=TARGET_ENVELOPE_SCHEMA,
            release_context=context,
            target_subset=(correct[0], {**correct[1], "incident_id": "incident-000"}),
            salt_hex=SALT,
        )


def test_sealer_revalidates_copied_envelope_before_salt_claim_or_encryption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipient = _recipient(PrivateKey.generate())
    envelope = _envelope(_context(recipient))
    first = envelope.target_subset[0].model_copy(update={"incident_id": "incident-999"})
    forged = envelope.model_copy(update={"target_subset": (first, *envelope.target_subset[1:])})
    store = _SaltStore()
    encryption_calls = 0

    class CountingSealedBox:
        def __init__(self, _key: object) -> None:
            nonlocal encryption_calls
            encryption_calls += 1

    monkeypatch.setattr(release, "SealedBox", CountingSealedBox)
    with pytest.raises(ShortcutReleaseError, match="strict revalidation"):
        _seal(forged, recipient, salt_store=store)
    assert store.claims == {}
    assert encryption_calls == 0


@pytest.mark.parametrize(
    ("model", "field_name", "bad_value"),
    [
        (X25519RecipientIdentity, "recipient_encryption_key_epoch", "1"),
        (RuleAxisFoldAuthoritySubject, "incident_count", "2"),
        (ShortcutArtifactBinding, "bytes", "1024"),
        (ShortcutReleaseContext, "phase_ordinal", "0"),
        (ShortcutReleaseContext, "recipient_encryption_key_epoch", False),
    ],
)
def test_protocol_models_reject_scalar_coercion(
    model: type[release.ShortcutReleaseModel],
    field_name: str,
    bad_value: object,
) -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    values_by_model: dict[type[release.ShortcutReleaseModel], dict[str, object]] = {
        X25519RecipientIdentity: recipient.model_dump(mode="python"),
        RuleAxisFoldAuthoritySubject: _subject().model_dump(mode="python"),
        ShortcutArtifactBinding: _context(
            recipient
        ).canonical_acquisition_contract_binding.model_dump(mode="python"),
        ShortcutReleaseContext: _context(recipient).model_dump(mode="python"),
    }
    candidate = values_by_model[model]
    candidate[field_name] = bad_value

    with pytest.raises(ValidationError):
        model.model_validate(candidate)


def test_target_envelope_rejects_scalar_salt_coercion() -> None:
    recipient = _recipient(PrivateKey.generate())
    envelope = _envelope(_context(recipient)).model_dump(mode="python")
    envelope["salt_hex"] = 1
    with pytest.raises(ValidationError):
        TargetEnvelope.model_validate(envelope)


def test_nonfinite_json_is_rejected_as_noncanonicalizable() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    ciphertext = _encrypt_payload(b'{"value":NaN}', private_key, context)

    with pytest.raises(ShortcutReleaseError, match="cannot be canonicalized"):
        open_target_envelope(
            ciphertext,
            private_key,
            expected_release_context=context,
            expected_envelope_commitment_sha256=ZERO_HASH,
        )


def test_truncated_frame_nonobject_json_and_typed_payload_fail_closed() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    cases = (
        (_encrypt_unpadded(b"short", private_key, context), "frame is truncated"),
        (_encrypt_payload(b"[]", private_key, context), "must be an object"),
        (_encrypt_payload(b"{}", private_key, context), "typed contract"),
        (_encrypt_payload(b"\xff", private_key, context), "valid UTF-8 JSON"),
    )

    for ciphertext, message in cases:
        with pytest.raises(ShortcutReleaseError, match=message):
            open_target_envelope(
                ciphertext,
                private_key,
                expected_release_context=context,
                expected_envelope_commitment_sha256=ZERO_HASH,
            )


def test_canonical_json_with_coerced_scalar_is_rejected_on_open() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    value = _envelope(context).model_dump(mode="json")
    value["release_context"]["phase_ordinal"] = "0"  # type: ignore[index]
    ciphertext = _encrypt_payload(canonical_json(value), private_key, context)

    with pytest.raises(ShortcutReleaseError, match="typed contract"):
        open_target_envelope(
            ciphertext,
            private_key,
            expected_release_context=context,
            expected_envelope_commitment_sha256=ZERO_HASH,
        )


def test_padding_capacity_allocation_and_libsodium_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(release.sys, "maxsize", release.PADDING_UNIT_BYTES)
    with pytest.raises(ShortcutReleaseError, match="platform size limit"):
        release_padding_length(1)
    monkeypatch.undo()

    class AllocationFailure:
        def new(self, *_args: object) -> object:
            raise MemoryError

    monkeypatch.setattr(release, "_SODIUM_FFI", AllocationFailure())
    with pytest.raises(ShortcutReleaseError, match="cannot be allocated"):
        release._sodium_pad_exact(b"payload", release.PADDING_UNIT_BYTES)
    monkeypatch.undo()

    class PadFailure:
        def sodium_pad(self, *_args: object) -> int:
            return -1

    monkeypatch.setattr(release, "_SODIUM_LIB", PadFailure())
    with pytest.raises(ShortcutReleaseError, match="exact padded length"):
        release._sodium_pad_exact(b"payload", release.PADDING_UNIT_BYTES)
    monkeypatch.undo()

    class WrongPadLength:
        def sodium_pad(
            self,
            padded_length: object,
            _buffer: object,
            _data_length: int,
            _blocksize: int,
            maximum_length: int,
        ) -> int:
            padded_length[0] = maximum_length - 1  # type: ignore[index]
            return 0

    monkeypatch.setattr(release, "_SODIUM_LIB", WrongPadLength())
    with pytest.raises(ShortcutReleaseError, match="exact padded length"):
        release._sodium_pad_exact(b"payload", release.PADDING_UNIT_BYTES)


def test_unpadding_and_encryption_adapter_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ShortcutReleaseError, match="decrypted envelope length"):
        release._sodium_unpad_exact(b"short", release.PADDING_UNIT_BYTES)

    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    envelope = _envelope(_context(recipient))
    malformed_recipient = recipient.model_copy(update={"recipient_x25519_public_key": "not-hex"})
    with pytest.raises(ShortcutReleaseError, match="strict revalidation"):
        _seal(envelope, malformed_recipient)

    class WrongCiphertextLength:
        def __init__(self, _key: object) -> None:
            pass

        def encrypt(self, _plaintext: bytes) -> bytes:
            return b"short"

    monkeypatch.setattr(release, "SealedBox", WrongCiphertextLength)
    with pytest.raises(ShortcutReleaseError, match="ciphertext length"):
        _seal(envelope, recipient)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("recipient_actor_id", "substitute-worker"),
        ("isolated_execution_context_id", "substitute-context"),
        ("recipient_encryption_key_id", "substitute-key"),
        ("recipient_encryption_key_epoch", 2),
        ("recipient_x25519_public_key_sha256", "f" * 64),
    ],
)
def test_every_recipient_identity_binding_is_checked(field: str, replacement: object) -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    envelope = _envelope(_context(recipient))
    substituted = recipient.model_copy(update={field: replacement})

    with pytest.raises(ShortcutReleaseError, match=r"recipient identity|strict revalidation"):
        _seal(envelope, substituted)


def test_valid_attacker_public_key_cannot_redirect_encryption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipient = _recipient(PrivateKey.generate())
    attacker_key = PrivateKey.generate().public_key.encode().hex()
    envelope = _envelope(_context(recipient))
    redirected = recipient.model_copy(update={"recipient_x25519_public_key": attacker_key})
    encryption_calls = 0

    class CountingSealedBox:
        def __init__(self, _key: object) -> None:
            nonlocal encryption_calls
            encryption_calls += 1

    monkeypatch.setattr(release, "SealedBox", CountingSealedBox)
    with pytest.raises(ShortcutReleaseError, match="strict revalidation"):
        _seal(envelope, redirected)
    assert encryption_calls == 0


def test_actual_recipient_key_bytes_must_match_context_hash() -> None:
    recipient = _recipient(PrivateKey.generate())
    context = _context(recipient).model_copy(
        update={"recipient_x25519_public_key_sha256": "f" * 64}
    )
    envelope = _envelope(context)

    with pytest.raises(ShortcutReleaseError, match="public-key bytes differ"):
        _seal(envelope, recipient)


def test_private_key_hash_is_checked_before_decryption() -> None:
    private_key = PrivateKey.generate()
    recipient = _recipient(private_key)
    context = _context(recipient)
    sealed = _seal(_envelope(context), recipient)

    with pytest.raises(ShortcutReleaseError, match="private key differs"):
        open_target_envelope(
            sealed.ciphertext,
            PrivateKey.generate(),
            expected_release_context=context,
            expected_envelope_commitment_sha256=sealed.envelope_commitment_sha256,
        )


@pytest.mark.parametrize("incident_count", [0, -1, True, 1.5])
def test_padding_length_rejects_nonpositive_and_noninteger_counts(
    incident_count: object,
) -> None:
    with pytest.raises(ShortcutReleaseError, match="positive integer"):
        release_padding_length(incident_count)  # type: ignore[arg-type]
