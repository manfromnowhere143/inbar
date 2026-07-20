"""Mechanism resolution targets, their aggregate manifest, and its hiding commitment.

Amendment 001 requires the mechanism reviewer to create exactly one truth-only signed target for
every eligible case, after the hypothesis set, ontology assignment, and ambiguity review are
committed and strictly before safe-test review. Those targets aggregate into one manifest whose
root stays custodian-only behind a salted commitment until final registry recomputation.

`CONTINUITY.md` records the gap this module closes: `inbar.iter001.prediction-key-root.v1` is a
mapping projection, not the complete artifact binding, and the target, freeze, and final
recomputation chain that carries the raw manifest hash through to reveal was not implemented. One
manifest must hold across every mechanism target, and the commitment must hide the root it binds.

Two properties are structural rather than checked, because a check can be bypassed and a type
cannot. The commitment receipt carries no salt and no manifest root: those fields do not exist on
the model, so no code path can leak them into a public receipt. And the target's declared kind is a
closed enum cross-validated against the reserved unknown key, so a target cannot claim to be a
known mechanism while naming the unknown key.

This module is implementation-only. It creates no target, admits no corpus, grants no authority,
and closes no gate. Every guard here is exercised by a deliberately broken subject in
`tests/unit/test_shortcut_v2_target.py`, enforced by `scripts/ci/verify_guard_coverage.py`.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Final, Literal, TypeAlias, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from fieldtrue.canonical import sha256_bytes, sha256_value
from fieldtrue.domain import Identifier, Sha256
from fieldtrue.shortcut_contracts import (
    ShortcutAttestation,
    ShortcutContractError,
    verify_shortcut_attestation,
)
from fieldtrue.shortcut_v2_ontology import UNKNOWN_PREDICTION_KEY, PinnedActorBinding
from fieldtrue.shortcut_v2_tree import PredictionKey

MECHANISM_TARGET_ROOT_DOMAIN: Final = "inbar.iter001.mechanism-target-root.v1"
TARGET_MANIFEST_COMMITMENT_DOMAIN: Final = "inbar.iter001.target-manifest-commitment.v1"
ELIGIBLE_INCIDENT_IDS_DOMAIN: Final = "inbar.iter001.eligible-incident-ids.v1"

TARGET_ATTESTATION_KIND: Final = "shortcut_mechanism_resolution_target"
COMMITMENT_ATTESTATION_KIND: Final = "shortcut_target_manifest_commitment"

SaltHex: TypeAlias = Annotated[StrictStr, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
NonEmptyUtf8: TypeAlias = Annotated[StrictStr, StringConstraints(min_length=1)]
TargetKind: TypeAlias = Literal["known", "unknown"]

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class ShortcutTargetError(ValueError):
    """A mechanism target, aggregate manifest, commitment, or reveal is invalid."""


class ShortcutTargetModel(BaseModel):
    """Strict immutable base for implementation-only mechanism-target contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _strict_revalidate(value: _ModelT, model_type: type[_ModelT], *, label: str) -> _ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="python"), strict=True)
    except ValidationError as error:
        raise ShortcutTargetError(f"{label} failed strict revalidation") from error


def _utf8_key(value: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ShortcutTargetError("canonical value is not valid UTF-8") from error


def _require_aware(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


class MechanismMappingEvidence(ShortcutTargetModel):
    """Content-addressed physical mapping evidence bound to one mechanism target."""

    schema_version: Literal["inbar.iter001.mechanism-mapping-evidence.v1"]
    uri: NonEmptyUtf8
    media_type: NonEmptyUtf8
    artifact_sha256: Sha256
    bytes_length: int = Field(ge=1)


class SignedMechanismResolutionTarget(ShortcutTargetModel):
    """One truth-only mechanism target signed by the mechanism reviewer.

    Every binding named in the frozen Amendment 001 target policy is required. The target plane is
    truth-only: this artifact and its hash never enter a model-visible tree before authorized
    release, which is a custody obligation on the caller that no type can enforce.
    """

    schema_version: Literal["inbar.iter001.mechanism-resolution-target.v1"]
    case_key: Sha256
    incident_id: Identifier
    truth_record_artifact_sha256: Sha256
    hypothesis_set_artifact_sha256: Sha256
    ontology_artifact_sha256: Sha256
    prediction_key_manifest_artifact_sha256: Sha256
    mechanism_ids_sha256: Sha256
    target_hypothesis_id: Identifier
    target_prediction_key: PredictionKey
    target_kind: TargetKind
    mapping_evidence: MechanismMappingEvidence
    committed_at: datetime
    mechanism_reviewer_id: Identifier
    attestation: ShortcutAttestation

    @field_validator("committed_at")
    @classmethod
    def target_time_is_aware(cls, value: datetime) -> datetime:
        return _require_aware(value, label="mechanism target commitment time")

    @model_validator(mode="after")
    def declared_kind_matches_the_reserved_key(self) -> SignedMechanismResolutionTarget:
        if self.target_kind == "unknown":
            if self.target_prediction_key != UNKNOWN_PREDICTION_KEY:
                raise ValueError("an unknown target requires the reserved unknown prediction key")
        elif self.target_prediction_key == UNKNOWN_PREDICTION_KEY:
            raise ValueError("a known target cannot name the reserved unknown prediction key")
        return self


def target_attestation_subject(target: SignedMechanismResolutionTarget) -> dict[str, object]:
    """Return the exact target body covered by its mechanism-reviewer attestation."""

    validated = _strict_revalidate(
        target,
        SignedMechanismResolutionTarget,
        label="mechanism resolution target",
    )
    return validated.model_dump(mode="json", exclude={"attestation"})


class BoundMechanismTarget(ShortcutTargetModel):
    """A signed target bound to the exact committed bytes it was serialized as.

    The aggregate root binds `target_artifact_sha256`, which is the hash of the target artifact
    itself and not of any artifact the target references. Binding the raw bytes in the type rather
    than trusting a caller-supplied hash is what makes the root reconstructible by an independent
    verifier holding only the committed files.
    """

    target: SignedMechanismResolutionTarget
    raw_target_json: bytes
    target_artifact_sha256: Sha256

    @model_validator(mode="after")
    def raw_bytes_bind_the_declared_artifact_hash(self) -> BoundMechanismTarget:
        if sha256_bytes(self.raw_target_json) != self.target_artifact_sha256:
            raise ValueError("mechanism target raw artifact hash mismatch")
        try:
            materialized = SignedMechanismResolutionTarget.model_validate_json(
                self.raw_target_json,
                strict=True,
            )
        except (ValidationError, ValueError) as error:
            raise ValueError("mechanism target bytes violate the typed contract") from error
        if materialized != self.target:
            raise ValueError("mechanism target bytes differ from the bound target")
        return self


class MechanismTargetManifestEntry(ShortcutTargetModel):
    """One case's contribution to the aggregate target manifest root."""

    case_key: Sha256
    target_artifact_sha256: Sha256


def mechanism_target_root_sha256(entries: Sequence[MechanismTargetManifestEntry]) -> str:
    """Compute the frozen aggregate target-manifest root over canonical case-ordered entries."""

    frozen = tuple(
        _strict_revalidate(item, MechanismTargetManifestEntry, label="target manifest entry")
        for item in entries
    )
    if not frozen:
        raise ShortcutTargetError("the aggregate target manifest cannot be empty")
    case_keys = tuple(item.case_key for item in frozen)
    if case_keys != tuple(sorted(case_keys, key=_utf8_key)):
        raise ShortcutTargetError("target manifest entries are not in canonical case-key order")
    if len(case_keys) != len(set(case_keys)):
        raise ShortcutTargetError("target manifest contains duplicate case keys")
    return sha256_value(
        {
            "domain": MECHANISM_TARGET_ROOT_DOMAIN,
            "items": [
                {
                    "case_key": item.case_key,
                    "target_artifact_sha256": item.target_artifact_sha256,
                }
                for item in frozen
            ],
        }
    )


def eligible_incident_ids_sha256(incident_ids: Sequence[str]) -> str:
    """Hash the canonical duplicate-free eligible-incident list under its own frozen domain.

    This is deliberately not `fieldtrue.shortcut_v2_hashing.incident_id_list_sha256`: that helper
    binds `inbar.iter001.shortcut-incident-id-list.v1`, and the eligible-incident root Amendment
    001 requires is a different frozen domain. Reusing the other helper would produce a
    well-formed root that no conforming verifier could reproduce.
    """

    frozen = tuple(incident_ids)
    if not frozen:
        raise ShortcutTargetError("the eligible-incident list cannot be empty")
    ordered = tuple(sorted(frozen, key=_utf8_key))
    if frozen != ordered:
        raise ShortcutTargetError("eligible incident IDs must be in canonical UTF-8 order")
    if len(frozen) != len(set(frozen)):
        raise ShortcutTargetError("eligible incident IDs must be unique")
    return sha256_value({"domain": ELIGIBLE_INCIDENT_IDS_DOMAIN, "items": list(frozen)})


def target_manifest_hiding_commitment_sha256(target_manifest_sha256: str, salt_hex: str) -> str:
    """Compute the public hiding commitment over the custodian-only manifest root and salt."""

    try:
        bound = _CommitmentInput(
            target_manifest_sha256=target_manifest_sha256,
            salt_hex=salt_hex,
        )
    except ValidationError as error:
        raise ShortcutTargetError("hiding-commitment input violates its typed contract") from error
    return sha256_value(
        {
            "domain": TARGET_MANIFEST_COMMITMENT_DOMAIN,
            "target_manifest_sha256": bound.target_manifest_sha256,
            "salt_hex": bound.salt_hex,
        }
    )


class _CommitmentInput(ShortcutTargetModel):
    target_manifest_sha256: Sha256
    salt_hex: SaltHex


class TargetManifestCommitmentReceipt(ShortcutTargetModel):
    """The public commitment receipt, which structurally cannot carry the salt or the root.

    Amendment 001 fixes these seven fields exactly. The salt and the target-manifest root remain
    custodian-only until final registry recomputation, so they are absent from this model rather
    than validated out of it: a field that does not exist cannot be populated by mistake.
    """

    schema_version: Literal["inbar.iter001.target-manifest-commitment-receipt.v1"]
    target_manifest_hiding_commitment_sha256: Sha256
    target_count: int = Field(ge=1)
    eligible_incident_ids_sha256: Sha256
    committed_at: datetime
    custodian_id: Identifier
    attestation: ShortcutAttestation

    @field_validator("committed_at")
    @classmethod
    def commitment_time_is_aware(cls, value: datetime) -> datetime:
        return _require_aware(value, label="target-manifest commitment time")


def commitment_attestation_subject(
    receipt: TargetManifestCommitmentReceipt,
) -> dict[str, object]:
    """Return the exact receipt body covered by its custodian attestation."""

    validated = _strict_revalidate(
        receipt,
        TargetManifestCommitmentReceipt,
        label="target-manifest commitment receipt",
    )
    return validated.model_dump(mode="json", exclude={"attestation"})


def verify_one_manifest_across_targets(
    targets: Sequence[BoundMechanismTarget],
    *,
    expected_prediction_key_manifest_artifact_sha256: str,
    expected_ontology_artifact_sha256: str,
    expected_reviewer: PinnedActorBinding,
    eligible_incident_ids: Sequence[str],
) -> tuple[MechanismTargetManifestEntry, ...]:
    """Enforce that one prediction-key manifest and one ontology hold across every target.

    This is the enforcement `CONTINUITY.md` records as unimplemented. A conforming implementation
    must bind one manifest across all targets; without it, two targets could each be internally
    valid while naming different manifests, and the aggregate root would attest to a mapping no
    single manifest ever contained.
    """

    bound = tuple(
        _strict_revalidate(item, BoundMechanismTarget, label="bound mechanism target")
        for item in targets
    )
    if not bound:
        raise ShortcutTargetError("at least one mechanism target is required")
    frozen = tuple(item.target for item in bound)

    expected_manifest = _require_sha256(
        expected_prediction_key_manifest_artifact_sha256,
        label="expected prediction-key manifest hash",
    )
    expected_ontology = _require_sha256(
        expected_ontology_artifact_sha256,
        label="expected ontology artifact hash",
    )
    if expected_reviewer.role != "mechanism_reviewer":
        raise ShortcutTargetError(
            "the expected target signer must hold the mechanism_reviewer role"
        )

    eligible = tuple(eligible_incident_ids)
    if len(eligible) != len(set(eligible)):
        raise ShortcutTargetError("the eligible-incident list contains duplicates")

    incidents: list[str] = []
    for target in frozen:
        if target.prediction_key_manifest_artifact_sha256 != expected_manifest:
            raise ShortcutTargetError("mechanism target names a different prediction-key manifest")
        if target.ontology_artifact_sha256 != expected_ontology:
            raise ShortcutTargetError("mechanism target names a different ontology artifact")
        if target.mechanism_reviewer_id != expected_reviewer.actor_id:
            raise ShortcutTargetError("mechanism target reviewer differs from the caller pin")
        try:
            verify_shortcut_attestation(
                target.attestation,
                expected_kind=TARGET_ATTESTATION_KIND,
                expected_subject=target_attestation_subject(target),
                expected_signer_id=expected_reviewer.actor_id,
                expected_public_key=expected_reviewer.ed25519_public_key,
            )
        except ShortcutContractError as error:
            raise ShortcutTargetError("mechanism target attestation is invalid") from error
        incidents.append(target.incident_id)

    if len(incidents) != len(set(incidents)):
        raise ShortcutTargetError("more than one mechanism target names the same incident")
    if set(incidents) != set(eligible):
        raise ShortcutTargetError("mechanism targets do not cover the eligible incidents exactly")

    entries = tuple(
        MechanismTargetManifestEntry(
            case_key=item.target.case_key,
            target_artifact_sha256=item.target_artifact_sha256,
        )
        for item in sorted(bound, key=lambda item: _utf8_key(item.target.case_key))
    )
    return entries


def verify_target_manifest_reveal(
    *,
    revealed_entries: Sequence[MechanismTargetManifestEntry],
    revealed_salt_hex: str,
    receipt: TargetManifestCommitmentReceipt,
    eligible_incident_ids: Sequence[str],
) -> str:
    """Recompute the root and commitment at reveal and check them against the frozen receipt.

    Returns the recomputed manifest root so a caller can bind it onward. A mismatch here means the
    custodian revealed a manifest other than the one committed, which invalidates the audit rather
    than counting as a wrong prediction.
    """

    validated_receipt = _strict_revalidate(
        receipt,
        TargetManifestCommitmentReceipt,
        label="target-manifest commitment receipt",
    )
    recomputed_root = mechanism_target_root_sha256(revealed_entries)
    if len(tuple(revealed_entries)) != validated_receipt.target_count:
        raise ShortcutTargetError("revealed target count differs from the committed receipt")
    if eligible_incident_ids_sha256(eligible_incident_ids) != (
        validated_receipt.eligible_incident_ids_sha256
    ):
        raise ShortcutTargetError("revealed eligible-incident root differs from the receipt")
    recomputed_commitment = target_manifest_hiding_commitment_sha256(
        recomputed_root,
        revealed_salt_hex,
    )
    if recomputed_commitment != validated_receipt.target_manifest_hiding_commitment_sha256:
        raise ShortcutTargetError("revealed manifest does not reproduce the frozen commitment")
    return recomputed_root


def _require_sha256(value: str, *, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _LOWER_HEX for c in value):
        raise ShortcutTargetError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


_LOWER_HEX = frozenset("0123456789abcdef")
