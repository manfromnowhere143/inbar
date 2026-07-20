"""Broken-subject controls for mechanism targets, their manifest, and the hiding commitment.

Every guard in `fieldtrue.shortcut_v2_target` is exercised here by a subject deliberately built to
make it fire. `scripts/ci/verify_guard_coverage.py` enforces that, so a guard added to that module
without a test here fails the build rather than shipping unfalsifiable.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from nacl.signing import SigningKey
from pydantic import BaseModel, ValidationError

from fieldtrue.canonical import canonical_json_pretty, sha256_bytes
from fieldtrue.shortcut_contracts import issue_shortcut_attestation
from fieldtrue.shortcut_v2_ontology import PinnedActorBinding
from fieldtrue.shortcut_v2_target import (
    ELIGIBLE_INCIDENT_IDS_DOMAIN,
    MECHANISM_TARGET_ROOT_DOMAIN,
    TARGET_ATTESTATION_KIND,
    TARGET_MANIFEST_COMMITMENT_DOMAIN,
    BoundMechanismTarget,
    MechanismMappingEvidence,
    MechanismTargetManifestEntry,
    ShortcutTargetError,
    SignedMechanismResolutionTarget,
    TargetManifestCommitmentReceipt,
    _require_sha256,
    _strict_revalidate,
    _utf8_key,
    eligible_incident_ids_sha256,
    mechanism_target_root_sha256,
    target_attestation_subject,
    target_manifest_hiding_commitment_sha256,
    verify_one_manifest_across_targets,
    verify_target_manifest_reveal,
)

REVIEWER_KEY = SigningKey(bytes([11]) * 32)
IMPOSTOR_KEY = SigningKey(bytes([12]) * 32)
CUSTODIAN_KEY = SigningKey(bytes([13]) * 32)

T0 = datetime(2026, 7, 20, 9, 0, tzinfo=UTC)
T1 = T0 + timedelta(minutes=1)

MANIFEST_SHA = "a" * 64
ONTOLOGY_SHA = "b" * 64
SALT = "c" * 64
OTHER_SHA = "d" * 64


def _public_key(signing_key: SigningKey) -> str:
    return signing_key.verify_key.encode().hex()


MECHANISM_REVIEWER = PinnedActorBinding(
    role="mechanism_reviewer",
    actor_id="mechanism-reviewer",
    independence_group_id="mechanism-group",
    ed25519_public_key=_public_key(REVIEWER_KEY),
)


def _evidence() -> MechanismMappingEvidence:
    return MechanismMappingEvidence(
        schema_version="inbar.iter001.mechanism-mapping-evidence.v1",
        uri="evidence/physical/teardown-alpha.json",
        media_type="application/json",
        artifact_sha256="e" * 64,
        bytes_length=2048,
    )


def _case_key(seed: str) -> str:
    return seed * 64


def _target(
    *,
    incident_id: str = "incident-alpha",
    case_key: str | None = None,
    prediction_key_manifest_artifact_sha256: str = MANIFEST_SHA,
    ontology_artifact_sha256: str = ONTOLOGY_SHA,
    mechanism_reviewer_id: str = "mechanism-reviewer",
    target_kind: str = "known",
    target_prediction_key: str = "f" * 64,
    signing_key: SigningKey = REVIEWER_KEY,
) -> SignedMechanismResolutionTarget:
    base = SignedMechanismResolutionTarget(
        schema_version="inbar.iter001.mechanism-resolution-target.v1",
        case_key=case_key or _case_key("1"),
        incident_id=incident_id,
        truth_record_artifact_sha256="2" * 64,
        hypothesis_set_artifact_sha256="3" * 64,
        ontology_artifact_sha256=ontology_artifact_sha256,
        prediction_key_manifest_artifact_sha256=prediction_key_manifest_artifact_sha256,
        mechanism_ids_sha256="4" * 64,
        target_hypothesis_id="alpha-known-a",
        target_prediction_key=target_prediction_key,
        target_kind=target_kind,  # type: ignore[arg-type]
        mapping_evidence=_evidence(),
        committed_at=T0,
        mechanism_reviewer_id=mechanism_reviewer_id,
        attestation=issue_shortcut_attestation(
            signing_key,
            signer_id=mechanism_reviewer_id,
            kind=TARGET_ATTESTATION_KIND,
            subject={"placeholder": TARGET_ATTESTATION_KIND},
        ),
    )
    attestation = issue_shortcut_attestation(
        signing_key,
        signer_id=mechanism_reviewer_id,
        kind=TARGET_ATTESTATION_KIND,
        subject=target_attestation_subject(base),
    )
    return base.model_copy(update={"attestation": attestation})


def _entry(case_key: str, artifact: str = "9" * 64) -> MechanismTargetManifestEntry:
    return MechanismTargetManifestEntry(case_key=case_key, target_artifact_sha256=artifact)


def _bound(**kwargs: Any) -> BoundMechanismTarget:
    target = _target(**kwargs)
    raw = canonical_json_pretty(target)
    return BoundMechanismTarget(
        target=target,
        raw_target_json=raw,
        target_artifact_sha256=sha256_bytes(raw),
    )


def _receipt(
    *,
    commitment: str,
    target_count: int = 1,
    eligible_root: str | None = None,
) -> TargetManifestCommitmentReceipt:
    base = TargetManifestCommitmentReceipt(
        schema_version="inbar.iter001.target-manifest-commitment-receipt.v1",
        target_manifest_hiding_commitment_sha256=commitment,
        target_count=target_count,
        eligible_incident_ids_sha256=eligible_root
        or eligible_incident_ids_sha256(["incident-alpha"]),
        committed_at=T1,
        custodian_id="custodian",
        attestation=issue_shortcut_attestation(
            CUSTODIAN_KEY,
            signer_id="custodian",
            kind="shortcut_target_manifest_commitment",
            subject={"placeholder": "commitment"},
        ),
    )
    return base


def _validated_copy(model: BaseModel, **updates: object) -> Any:
    payload = model.model_dump(mode="python")
    payload.update(updates)
    return type(model).model_validate(payload, strict=True)


def test_frozen_domains_are_exactly_the_amendment_001_values() -> None:
    """The three roots are frozen; a drifted domain silently breaks every conforming verifier."""
    assert MECHANISM_TARGET_ROOT_DOMAIN == "inbar.iter001.mechanism-target-root.v1"
    assert TARGET_MANIFEST_COMMITMENT_DOMAIN == "inbar.iter001.target-manifest-commitment.v1"
    assert ELIGIBLE_INCIDENT_IDS_DOMAIN == "inbar.iter001.eligible-incident-ids.v1"


def test_commitment_receipt_structurally_cannot_carry_the_salt_or_the_root() -> None:
    """The hiding property is a type property, not a check that a caller could skip."""
    fields = set(TargetManifestCommitmentReceipt.model_fields)
    assert "salt_hex" not in fields
    assert "target_manifest_sha256" not in fields
    with pytest.raises(ValidationError):
        TargetManifestCommitmentReceipt.model_validate(
            {
                "schema_version": "inbar.iter001.target-manifest-commitment-receipt.v1",
                "target_manifest_hiding_commitment_sha256": "1" * 64,
                "target_count": 1,
                "eligible_incident_ids_sha256": "2" * 64,
                "committed_at": T1,
                "custodian_id": "custodian",
                "attestation": _receipt(commitment="1" * 64).attestation.model_dump(mode="python"),
                "salt_hex": SALT,
            },
            strict=True,
        )


def test_happy_path_verifies_one_manifest_and_reveals_against_the_commitment() -> None:
    """A positive control, so the negative controls below are not vacuous."""
    entries = verify_one_manifest_across_targets(
        [_bound()],
        expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
        expected_ontology_artifact_sha256=ONTOLOGY_SHA,
        expected_reviewer=MECHANISM_REVIEWER,
        eligible_incident_ids=["incident-alpha"],
    )
    root = mechanism_target_root_sha256(entries)
    commitment = target_manifest_hiding_commitment_sha256(root, SALT)
    recomputed = verify_target_manifest_reveal(
        revealed_entries=entries,
        revealed_salt_hex=SALT,
        receipt=_receipt(commitment=commitment),
        eligible_incident_ids=["incident-alpha"],
    )
    assert recomputed == root


def test_strict_revalidation_guard_rejects_a_construct_bypassed_model() -> None:
    """:79 — reached only by a caller holding an unvalidated model."""
    broken = MechanismTargetManifestEntry.model_construct(
        case_key=17, target_artifact_sha256="9" * 64
    )
    with pytest.raises(ShortcutTargetError, match="failed strict revalidation"):
        _strict_revalidate(broken, MechanismTargetManifestEntry, label="target manifest entry")


def test_canonical_ordering_key_rejects_unencodable_text() -> None:
    """:86 — unreachable through the public surface; pydantic rejects surrogates first."""
    with pytest.raises(ShortcutTargetError, match="not valid UTF-8"):
        _utf8_key("\ud800")


def test_target_rejects_a_naive_commitment_time() -> None:
    """:91 — a naive timestamp cannot anchor the frozen chronology."""
    with pytest.raises(ValidationError, match="must be timezone-aware"):
        _validated_copy(_target(), committed_at=T0.replace(tzinfo=None))


def test_unknown_target_without_the_reserved_key_is_rejected() -> None:
    """:138"""
    with pytest.raises(ValidationError, match="reserved unknown prediction key"):
        _validated_copy(_target(), target_kind="unknown")


def test_known_target_naming_the_reserved_key_is_rejected() -> None:
    """:140"""
    with pytest.raises(ValidationError, match="cannot name the reserved unknown"):
        _validated_copy(_target(), target_prediction_key="unknown")


def test_empty_target_manifest_is_rejected() -> None:
    """:170 — an empty manifest would make every downstream count vacuous."""
    with pytest.raises(ShortcutTargetError, match="cannot be empty"):
        mechanism_target_root_sha256([])


def test_target_manifest_out_of_canonical_order_is_rejected() -> None:
    """:173"""
    with pytest.raises(ShortcutTargetError, match="canonical case-key order"):
        mechanism_target_root_sha256([_entry(_case_key("2")), _entry(_case_key("1"))])


def test_target_manifest_with_duplicate_case_keys_is_rejected() -> None:
    """:175"""
    with pytest.raises(ShortcutTargetError, match="duplicate case keys"):
        mechanism_target_root_sha256([_entry(_case_key("1")), _entry(_case_key("1"))])


def test_empty_eligible_incident_list_is_rejected() -> None:
    """:201"""
    with pytest.raises(ShortcutTargetError, match="cannot be empty"):
        eligible_incident_ids_sha256([])


def test_eligible_incidents_out_of_canonical_order_are_rejected() -> None:
    """:204"""
    with pytest.raises(ShortcutTargetError, match="canonical UTF-8 order"):
        eligible_incident_ids_sha256(["incident-beta", "incident-alpha"])


def test_duplicate_eligible_incidents_are_rejected() -> None:
    """:206"""
    with pytest.raises(ShortcutTargetError, match="must be unique"):
        eligible_incident_ids_sha256(["incident-alpha", "incident-alpha"])


@pytest.mark.parametrize(
    ("root", "salt"),
    [
        ("not-a-hash", SALT),
        ("A" * 64, SALT),
        ("1" * 64, "short"),
        ("1" * 64, "C" * 64),
    ],
)
def test_hiding_commitment_rejects_untyped_inputs(root: str, salt: str) -> None:
    """:219 — a malformed salt or root must not silently produce a well-formed commitment."""
    with pytest.raises(ShortcutTargetError, match="violates its typed contract"):
        target_manifest_hiding_commitment_sha256(root, salt)


def test_no_targets_is_rejected() -> None:
    """:290"""
    with pytest.raises(ShortcutTargetError, match="at least one mechanism target"):
        verify_one_manifest_across_targets(
            [],
            expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
            expected_ontology_artifact_sha256=ONTOLOGY_SHA,
            expected_reviewer=MECHANISM_REVIEWER,
            eligible_incident_ids=["incident-alpha"],
        )


def test_expected_signer_without_the_mechanism_reviewer_role_is_rejected() -> None:
    """:301 — only the mechanism reviewer may sign a target."""
    wrong_role = PinnedActorBinding(
        role="hypothesis_proposer",
        actor_id="mechanism-reviewer",
        independence_group_id="mechanism-group",
        ed25519_public_key=_public_key(REVIEWER_KEY),
    )
    with pytest.raises(ShortcutTargetError, match="mechanism_reviewer role"):
        verify_one_manifest_across_targets(
            [_bound()],
            expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
            expected_ontology_artifact_sha256=ONTOLOGY_SHA,
            expected_reviewer=wrong_role,
            eligible_incident_ids=["incident-alpha"],
        )


def test_duplicate_eligible_incident_list_is_rejected_by_the_verifier() -> None:
    """:307"""
    with pytest.raises(ShortcutTargetError, match="eligible-incident list contains duplicates"):
        verify_one_manifest_across_targets(
            [_bound()],
            expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
            expected_ontology_artifact_sha256=ONTOLOGY_SHA,
            expected_reviewer=MECHANISM_REVIEWER,
            eligible_incident_ids=["incident-alpha", "incident-alpha"],
        )


def test_target_naming_a_different_prediction_key_manifest_is_rejected() -> None:
    """:312 — this is the one-manifest enforcement CONTINUITY.md records as unimplemented."""
    with pytest.raises(ShortcutTargetError, match="different prediction-key manifest"):
        verify_one_manifest_across_targets(
            [_bound(prediction_key_manifest_artifact_sha256=OTHER_SHA)],
            expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
            expected_ontology_artifact_sha256=ONTOLOGY_SHA,
            expected_reviewer=MECHANISM_REVIEWER,
            eligible_incident_ids=["incident-alpha"],
        )


def test_target_naming_a_different_ontology_is_rejected() -> None:
    """:314"""
    with pytest.raises(ShortcutTargetError, match="different ontology artifact"):
        verify_one_manifest_across_targets(
            [_bound(ontology_artifact_sha256=OTHER_SHA)],
            expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
            expected_ontology_artifact_sha256=ONTOLOGY_SHA,
            expected_reviewer=MECHANISM_REVIEWER,
            eligible_incident_ids=["incident-alpha"],
        )


def test_target_reviewer_differing_from_the_caller_pin_is_rejected() -> None:
    """:316"""
    with pytest.raises(ShortcutTargetError, match="reviewer differs from the caller pin"):
        verify_one_manifest_across_targets(
            [_bound(mechanism_reviewer_id="substitute-reviewer")],
            expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
            expected_ontology_artifact_sha256=ONTOLOGY_SHA,
            expected_reviewer=MECHANISM_REVIEWER,
            eligible_incident_ids=["incident-alpha"],
        )


def test_target_signed_by_an_impostor_key_is_rejected() -> None:
    """:326 — a valid-looking signature from the wrong key must not pass."""
    with pytest.raises(ShortcutTargetError, match="attestation is invalid"):
        verify_one_manifest_across_targets(
            [_bound(signing_key=IMPOSTOR_KEY)],
            expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
            expected_ontology_artifact_sha256=ONTOLOGY_SHA,
            expected_reviewer=MECHANISM_REVIEWER,
            eligible_incident_ids=["incident-alpha"],
        )


def test_two_targets_for_one_incident_are_rejected() -> None:
    """:330 — exactly one target per eligible case is a frozen Amendment 001 requirement."""
    with pytest.raises(ShortcutTargetError, match="same incident"):
        verify_one_manifest_across_targets(
            [_bound(), _bound(case_key=_case_key("2"))],
            expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
            expected_ontology_artifact_sha256=ONTOLOGY_SHA,
            expected_reviewer=MECHANISM_REVIEWER,
            eligible_incident_ids=["incident-alpha"],
        )


def test_targets_not_covering_the_eligible_incidents_are_rejected() -> None:
    """:332 — a missing or extra target invalidates the audit rather than counting as wrong."""
    with pytest.raises(ShortcutTargetError, match="do not cover the eligible incidents"):
        verify_one_manifest_across_targets(
            [_bound()],
            expected_prediction_key_manifest_artifact_sha256=MANIFEST_SHA,
            expected_ontology_artifact_sha256=ONTOLOGY_SHA,
            expected_reviewer=MECHANISM_REVIEWER,
            eligible_incident_ids=["incident-alpha", "incident-beta"],
        )


def test_reveal_with_a_different_target_count_is_rejected() -> None:
    """:365"""
    entries = (_entry(_case_key("1")),)
    root = mechanism_target_root_sha256(entries)
    commitment = target_manifest_hiding_commitment_sha256(root, SALT)
    with pytest.raises(ShortcutTargetError, match="target count differs"):
        verify_target_manifest_reveal(
            revealed_entries=entries,
            revealed_salt_hex=SALT,
            receipt=_receipt(commitment=commitment, target_count=2),
            eligible_incident_ids=["incident-alpha"],
        )


def test_reveal_with_a_different_eligible_incident_root_is_rejected() -> None:
    """:369"""
    entries = (_entry(_case_key("1")),)
    root = mechanism_target_root_sha256(entries)
    commitment = target_manifest_hiding_commitment_sha256(root, SALT)
    with pytest.raises(ShortcutTargetError, match="eligible-incident root differs"):
        verify_target_manifest_reveal(
            revealed_entries=entries,
            revealed_salt_hex=SALT,
            receipt=_receipt(
                commitment=commitment,
                eligible_root=eligible_incident_ids_sha256(["incident-zulu"]),
            ),
            eligible_incident_ids=["incident-alpha"],
        )


def test_reveal_of_a_substituted_manifest_does_not_reproduce_the_commitment() -> None:
    """:375 — the whole point of the hiding commitment."""
    entries = (_entry(_case_key("1")),)
    root = mechanism_target_root_sha256(entries)
    commitment = target_manifest_hiding_commitment_sha256(root, SALT)
    substituted = (_entry(_case_key("1"), artifact="8" * 64),)
    with pytest.raises(ShortcutTargetError, match="does not reproduce the frozen commitment"):
        verify_target_manifest_reveal(
            revealed_entries=substituted,
            revealed_salt_hex=SALT,
            receipt=_receipt(commitment=commitment),
            eligible_incident_ids=["incident-alpha"],
        )


@pytest.mark.parametrize("value", ["short", "A" * 64, "g" * 64, 17])
def test_sha256_guard_rejects_malformed_hashes(value: object) -> None:
    """:381"""
    with pytest.raises(ShortcutTargetError, match="64 lowercase hexadecimal"):
        _require_sha256(value, label="expected hash")  # type: ignore[arg-type]


def test_bound_target_with_a_mismatched_raw_hash_is_rejected() -> None:
    """The declared artifact hash must be the hash of the bytes actually supplied."""
    target = _target()
    with pytest.raises(ValidationError, match="raw artifact hash mismatch"):
        BoundMechanismTarget(
            target=target,
            raw_target_json=canonical_json_pretty(target),
            target_artifact_sha256="7" * 64,
        )


def test_bound_target_whose_bytes_are_not_a_valid_target_is_rejected() -> None:
    """Raw bytes that do not materialize a target cannot bind one."""
    raw = b'{"schema_version": "inbar.iter001.mechanism-resolution-target.v1"}'
    with pytest.raises(ValidationError, match="violate the typed contract"):
        BoundMechanismTarget(
            target=_target(),
            raw_target_json=raw,
            target_artifact_sha256=sha256_bytes(raw),
        )


def test_bound_target_whose_bytes_describe_a_different_target_is_rejected() -> None:
    """A caller cannot bind one target while supplying another's bytes.

    This is the substitution the aggregate root exists to prevent: without it, the manifest could
    bind a hash whose preimage is a target nobody signed for that case.
    """
    other = _target(incident_id="incident-beta", case_key=_case_key("2"))
    raw = canonical_json_pretty(other)
    with pytest.raises(ValidationError, match="differ from the bound target"):
        BoundMechanismTarget(
            target=_target(),
            raw_target_json=raw,
            target_artifact_sha256=sha256_bytes(raw),
        )
