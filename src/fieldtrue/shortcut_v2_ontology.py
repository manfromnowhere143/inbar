"""Implementation-only mechanism ontology boundary for Shortcut Authority V2.

This module implements the structural portion of Amendment 001's shared prediction-key
contract.  It can prove exact content hashes, per-case hypothesis coverage, the reserved
``unknown`` mapping, caller-pinned signer and independence-group separation, chronology over
caller-bound inputs, and the frozen V1 prediction-key root.

It cannot decide whether differently worded definitions are semantically equivalent, detect
identity proxies inside technically valid prose, establish that a caller-pinned actor is
independent in the real world, verify the later target-manifest and freeze-receipt chain, or close
any scientific gate.  The V1 prediction-key root is intentionally a mapping projection; the raw
manifest artifact hash supplies the complete byte binding and is later carried by each mechanism
target.  A successful report therefore records the exact artifact hash but always leaves the
target and freeze chains unverified, with ``independent_attestation = False`` and
``authority_effect = "none"``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Annotated, Final, Literal, TypeAlias, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from fieldtrue.canonical import sha256_bytes, sha256_value
from fieldtrue.domain import (
    Ed25519PublicKey,
    HypothesisSet,
    Identifier,
    Sha256,
)
from fieldtrue.shortcut_contracts import (
    ShortcutAttestation,
    ShortcutContractError,
    verify_shortcut_attestation,
)
from fieldtrue.shortcut_v2_crossfit import (
    IncidentLocalHypothesisMap,
    LocalHypothesisAssignment,
)
from fieldtrue.shortcut_v2_tree import PredictionKey

MECHANISM_CLASS_DOMAIN: Final = "inbar.iter001.mechanism-class.v1"
SHORTCUT_CASE_KEY_DOMAIN: Final = "inbar.iter001.shortcut-case-key.v1"
PREDICTION_KEY_ROOT_DOMAIN: Final = "inbar.iter001.prediction-key-root.v1"
UNKNOWN_PREDICTION_KEY: Final = "unknown"

ONTOLOGY_ATTESTATION_KIND: Final = "shortcut_mechanism_ontology"
ASSIGNMENT_PROPOSAL_ATTESTATION_KIND: Final = "shortcut_prediction_key_assignment_proposal"
ASSIGNMENT_REVIEW_ATTESTATION_KIND: Final = "shortcut_prediction_key_assignment_review"

_MAXIMUM_JSON_ARTIFACT_BYTES: Final = 16 * 1024 * 1024
_LOWER_HEX = frozenset("0123456789abcdef")

NonEmptyUtf8: TypeAlias = Annotated[
    StrictStr,
    StringConstraints(min_length=1),
]
PinnedActorRole: TypeAlias = Literal[
    "ontology_reviewer",
    "hypothesis_proposer",
    "mechanism_reviewer",
    "shortcut_worker",
    "final_evaluator",
]


class ShortcutOntologyError(ValueError):
    """A Shortcut V2 ontology, mapping, signature, or bound input is invalid."""


class ShortcutOntologyModel(BaseModel):
    """Strict immutable base for implementation-only ontology contracts."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _strict_revalidate(value: _ModelT, model_type: type[_ModelT], *, label: str) -> _ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="python"), strict=True)
    except ValidationError as error:
        raise ShortcutOntologyError(f"{label} failed strict revalidation") from error


def _utf8(value: str, *, label: str) -> str:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must be valid UTF-8") from error
    return value


def _utf8_key(value: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ShortcutOntologyError("canonical value is not valid UTF-8") from error


def _require_sha256(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _LOWER_HEX for character in value)
    ):
        raise ShortcutOntologyError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def _require_aware(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value


class MechanismClassDefinition(ShortcutOntologyModel):
    """One exact known mechanism definition.

    The prediction key is not stored in this model.  It is recomputed from exactly the six
    Amendment 001 fields plus the flat domain member.  The reserved ``unknown`` value is not a
    known mechanism class.
    """

    schema_version: Literal["inbar.iter001.mechanism-class.v1"]
    canonical_name: NonEmptyUtf8
    causal_locus: NonEmptyUtf8
    failure_mode: NonEmptyUtf8
    temporal_signature: NonEmptyUtf8
    directionality: NonEmptyUtf8
    definition: NonEmptyUtf8

    @field_validator(
        "canonical_name",
        "causal_locus",
        "failure_mode",
        "temporal_signature",
        "directionality",
        "definition",
    )
    @classmethod
    def definition_text_is_exact_utf8(cls, value: str) -> str:
        return _utf8(value, label="mechanism-class text")

    @model_validator(mode="after")
    def known_class_does_not_claim_reserved_unknown(self) -> MechanismClassDefinition:
        if self.canonical_name == UNKNOWN_PREDICTION_KEY:
            raise ValueError("a known mechanism class cannot use the reserved unknown name")
        return self


def mechanism_class_prediction_key(definition: MechanismClassDefinition) -> str:
    """Derive the exact six-field, flat-domain shared prediction key."""

    validated = _strict_revalidate(
        definition,
        MechanismClassDefinition,
        label="mechanism class",
    )
    return sha256_value(
        {
            "domain": MECHANISM_CLASS_DOMAIN,
            "canonical_name": validated.canonical_name,
            "causal_locus": validated.causal_locus,
            "failure_mode": validated.failure_mode,
            "temporal_signature": validated.temporal_signature,
            "directionality": validated.directionality,
            "definition": validated.definition,
        }
    )


class SignedMechanismOntology(ShortcutOntologyModel):
    """Known mechanism definitions signed by the declared ontology reviewer."""

    schema_version: Literal["inbar.iter001.shortcut-mechanism-ontology.v1"]
    classes: tuple[MechanismClassDefinition, ...] = Field(min_length=1)
    committed_at: datetime
    ontology_reviewer_id: Identifier
    ontology_reviewer_independence_group_id: Identifier
    attestation: ShortcutAttestation

    @field_validator("committed_at")
    @classmethod
    def ontology_time_is_aware(cls, value: datetime) -> datetime:
        return _require_aware(value, label="ontology commitment time")

    @model_validator(mode="after")
    def classes_are_canonical_and_structurally_biconditional(
        self,
    ) -> SignedMechanismOntology:
        keys = tuple(mechanism_class_prediction_key(item) for item in self.classes)
        if keys != tuple(sorted(keys, key=_utf8_key)):
            raise ValueError("mechanism classes must be ordered by derived prediction key")
        if len(keys) != len(set(keys)):
            raise ValueError("mechanism ontology contains a duplicate exact definition")
        names = tuple(item.canonical_name for item in self.classes)
        if len(names) != len(set(names)):
            raise ValueError("one canonical mechanism name cannot map to multiple definitions")
        unnamed_definitions = tuple(
            (
                item.causal_locus,
                item.failure_mode,
                item.temporal_signature,
                item.directionality,
                item.definition,
            )
            for item in self.classes
        )
        if len(unnamed_definitions) != len(set(unnamed_definitions)):
            raise ValueError("mechanism classes cannot differ only by their canonical names")
        return self

    def classes_by_prediction_key(self) -> dict[str, MechanismClassDefinition]:
        return {mechanism_class_prediction_key(item): item for item in self.classes}


def ontology_attestation_subject(ontology: SignedMechanismOntology) -> dict[str, object]:
    """Return the exact ontology body covered by its Shortcut V2 attestation."""

    validated = _strict_revalidate(
        ontology,
        SignedMechanismOntology,
        label="signed mechanism ontology",
    )
    return validated.model_dump(mode="json", exclude={"attestation"})


class HypothesisPredictionKeyAssignment(ShortcutOntologyModel):
    """One incident-local hypothesis assigned to one shared prediction key."""

    hypothesis_id: Identifier
    prediction_key: PredictionKey
    unknown: StrictBool
    class_definition_sha256: Sha256 | None

    @model_validator(mode="after")
    def unknown_and_known_states_are_disjoint(self) -> HypothesisPredictionKeyAssignment:
        if self.unknown:
            if (
                self.prediction_key != UNKNOWN_PREDICTION_KEY
                or self.class_definition_sha256 is not None
            ):
                raise ValueError(
                    "the unknown hypothesis requires the reserved key and no class definition"
                )
        elif (
            self.prediction_key == UNKNOWN_PREDICTION_KEY
            or self.class_definition_sha256 is None
            or self.class_definition_sha256 != self.prediction_key
        ):
            raise ValueError("a known hypothesis requires its content-derived class definition key")
        return self


def shortcut_case_key(
    incident_id: str,
    hypothesis_set_artifact_sha256: str,
) -> str:
    """Derive the exact Amendment 001 case key."""

    try:
        validated = _CaseKeyInput(
            incident_id=incident_id,
            hypothesis_set_artifact_sha256=hypothesis_set_artifact_sha256,
        )
    except ValidationError as error:
        raise ShortcutOntologyError("case-key input violates its typed contract") from error
    return sha256_value(
        {
            "domain": SHORTCUT_CASE_KEY_DOMAIN,
            "incident_id": validated.incident_id,
            "hypothesis_set_artifact_sha256": validated.hypothesis_set_artifact_sha256,
        }
    )


class _CaseKeyInput(ShortcutOntologyModel):
    incident_id: Identifier
    hypothesis_set_artifact_sha256: Sha256


class SignedCasePredictionKeyManifest(ShortcutOntologyModel):
    """One signed, pre-target prediction-key assignment for an exact hypothesis set."""

    schema_version: Literal["inbar.iter001.prediction-key-assignment-manifest.v1"]
    case_key: Sha256
    incident_id: Identifier
    hypothesis_set_artifact_sha256: Sha256
    ontology_artifact_sha256: Sha256
    assignments: tuple[HypothesisPredictionKeyAssignment, ...] = Field(min_length=2)
    hypothesis_proposer_id: Identifier
    hypothesis_proposer_independence_group_id: Identifier
    ontology_reviewer_id: Identifier
    ontology_reviewer_independence_group_id: Identifier
    ambiguity_review_receipt_artifact_sha256: Sha256
    committed_at: datetime
    hypothesis_proposer_attestation: ShortcutAttestation
    ontology_reviewer_attestation: ShortcutAttestation

    @field_validator("committed_at")
    @classmethod
    def assignment_time_is_aware(cls, value: datetime) -> datetime:
        return _require_aware(value, label="prediction-key assignment commitment time")

    @model_validator(mode="after")
    def assignment_is_exact_canonical_and_locally_bijective(
        self,
    ) -> SignedCasePredictionKeyManifest:
        expected_case_key = shortcut_case_key(
            self.incident_id,
            self.hypothesis_set_artifact_sha256,
        )
        if self.case_key != expected_case_key:
            raise ValueError("case key does not match its incident and hypothesis-set artifact")
        hypothesis_ids = tuple(item.hypothesis_id for item in self.assignments)
        if hypothesis_ids != tuple(sorted(hypothesis_ids, key=_utf8_key)):
            raise ValueError("prediction-key assignments must be ordered by hypothesis ID")
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("prediction-key assignments contain duplicate hypotheses")
        prediction_keys = tuple(item.prediction_key for item in self.assignments)
        if len(prediction_keys) != len(set(prediction_keys)):
            raise ValueError("one local prediction key cannot map to multiple hypotheses")
        if sum(item.unknown for item in self.assignments) != 1:
            raise ValueError("every case requires exactly one explicit unknown assignment")
        if self.hypothesis_proposer_id == self.ontology_reviewer_id:
            raise ValueError("ontology reviewer and hypothesis proposer IDs must differ")
        if (
            self.hypothesis_proposer_independence_group_id
            == self.ontology_reviewer_independence_group_id
        ):
            raise ValueError(
                "ontology reviewer and hypothesis proposer independence groups must differ"
            )
        return self


def assignment_attestation_subject(
    manifest: SignedCasePredictionKeyManifest,
) -> dict[str, object]:
    """Return the exact per-case assignment body covered by both attestations."""

    validated = _strict_revalidate(
        manifest,
        SignedCasePredictionKeyManifest,
        label="signed case prediction-key manifest",
    )
    return validated.model_dump(
        mode="json",
        exclude={
            "hypothesis_proposer_attestation",
            "ontology_reviewer_attestation",
        },
    )


class PredictionKeyManifest(ShortcutOntologyModel):
    """Complete signed per-case assignments plus the exact frozen V1 semantic root."""

    schema_version: Literal["inbar.iter001.prediction-key-manifest.v1"]
    ontology_artifact_sha256: Sha256
    cases: tuple[SignedCasePredictionKeyManifest, ...] = Field(min_length=1)
    prediction_key_root_sha256: Sha256

    @model_validator(mode="after")
    def cases_are_canonical_complete_root_inputs(self) -> PredictionKeyManifest:
        case_keys = tuple(item.case_key for item in self.cases)
        if case_keys != tuple(sorted(case_keys, key=_utf8_key)):
            raise ValueError("prediction-key cases must be ordered by case key")
        if len(case_keys) != len(set(case_keys)):
            raise ValueError("prediction-key manifest contains duplicate case keys")
        incident_ids = tuple(item.incident_id for item in self.cases)
        if len(incident_ids) != len(set(incident_ids)):
            raise ValueError("prediction-key manifest contains duplicate incidents")
        if any(
            item.ontology_artifact_sha256 != self.ontology_artifact_sha256 for item in self.cases
        ):
            raise ValueError("case assignment names a different ontology artifact")
        expected_root = prediction_key_root_sha256(
            self.ontology_artifact_sha256,
            self.cases,
        )
        if self.prediction_key_root_sha256 != expected_root:
            raise ValueError("prediction-key root does not match the frozen V1 projection")
        return self


def prediction_key_root_sha256(
    ontology_artifact_sha256: str,
    cases: Sequence[SignedCasePredictionKeyManifest],
) -> str:
    """Compute the exact frozen V1 root, intentionally excluding assignment metadata."""

    validated_ontology_hash = _require_sha256(
        ontology_artifact_sha256,
        label="ontology artifact hash",
    )
    frozen = tuple(
        _strict_revalidate(
            item,
            SignedCasePredictionKeyManifest,
            label="prediction-key root case",
        )
        for item in cases
    )
    case_keys = tuple(item.case_key for item in frozen)
    if case_keys != tuple(sorted(case_keys, key=_utf8_key)):
        raise ShortcutOntologyError("prediction-key root cases are not in canonical order")
    if len(case_keys) != len(set(case_keys)):
        raise ShortcutOntologyError("prediction-key root contains duplicate cases")
    assignments = [
        {
            "case_key": case.case_key,
            "hypothesis_id": assignment.hypothesis_id,
            "prediction_key": assignment.prediction_key,
        }
        for case in frozen
        for assignment in case.assignments
    ]
    return sha256_value(
        {
            "domain": PREDICTION_KEY_ROOT_DOMAIN,
            "ontology_artifact_sha256": validated_ontology_hash,
            "assignments": assignments,
        }
    )


class PinnedActorBinding(ShortcutOntologyModel):
    """Caller-pinned actor identity used for structural signer/group separation only."""

    role: PinnedActorRole
    actor_id: Identifier
    independence_group_id: Identifier
    ed25519_public_key: Ed25519PublicKey


class BoundCaseVerificationInput(ShortcutOntologyModel):
    """Caller-bound hypothesis bytes and chronology for one assignment manifest.

    These values are verification inputs, not proof that the named actors, times, or artifacts
    came from an independent authority.
    """

    incident_id: Identifier
    raw_hypothesis_set_json: bytes = Field(
        min_length=2,
        max_length=_MAXIMUM_JSON_ARTIFACT_BYTES,
    )
    hypothesis_set_artifact_sha256: Sha256
    ambiguity_review_receipt_artifact_sha256: Sha256
    hypothesis_proposer: PinnedActorBinding
    hypothesis_set_committed_at: datetime
    ambiguity_review_committed_at: datetime
    reviewed_hypothesis_set_committed_at: datetime
    mechanism_target_committed_at: datetime | None
    safe_test_review_committed_at: datetime | None

    @field_validator(
        "hypothesis_set_committed_at",
        "ambiguity_review_committed_at",
        "reviewed_hypothesis_set_committed_at",
        "mechanism_target_committed_at",
        "safe_test_review_committed_at",
    )
    @classmethod
    def bound_times_are_aware(cls, value: datetime | None) -> datetime | None:
        if value is not None:
            _require_aware(value, label="bound case chronology time")
        return value

    @model_validator(mode="after")
    def bound_chronology_is_ordered(self) -> BoundCaseVerificationInput:
        if self.hypothesis_proposer.role != "hypothesis_proposer":
            raise ValueError("bound case proposer must carry the hypothesis_proposer role")
        if self.hypothesis_set_committed_at > self.ambiguity_review_committed_at:
            raise ValueError("ambiguity review cannot predate the hypothesis set")
        if self.ambiguity_review_committed_at > self.reviewed_hypothesis_set_committed_at:
            raise ValueError("reviewed hypothesis-set commitment cannot predate ambiguity review")
        if (
            self.mechanism_target_committed_at is not None
            and self.mechanism_target_committed_at <= self.reviewed_hypothesis_set_committed_at
        ):
            raise ValueError("mechanism target must strictly follow the reviewed hypothesis set")
        if self.safe_test_review_committed_at is not None:
            if self.mechanism_target_committed_at is None:
                raise ValueError("safe-test review requires a bound prior mechanism target")
            if self.safe_test_review_committed_at <= self.mechanism_target_committed_at:
                raise ValueError("safe-test review must strictly follow the mechanism target")
        return self


class ShortcutOntologyAssuranceReport(ShortcutOntologyModel):
    """Nonauthoritative report of implementation-only structural verification."""

    schema_version: Literal["inbar.iter001.shortcut-ontology-assurance-report.v1"]
    assurance_scope: Literal["same-operator-implementation-only-structural-verification"]
    ontology_artifact_sha256: Sha256
    prediction_key_manifest_artifact_sha256: Sha256
    caller_pinned_trust_registry_artifact_sha256: Sha256
    prediction_key_root_sha256: Sha256
    case_count: int = Field(gt=0)
    assignment_count: int = Field(gt=0)
    caller_pinned_actor_bindings_checked: int = Field(gt=0)
    exact_hypothesis_membership_verified: Literal[True]
    explicit_unknown_verified: Literal[True]
    structural_biconditional_verified: Literal[True]
    signatures_verified: Literal[True]
    declared_chronology_verified: Literal[True]
    external_chronology_verified: Literal[False]
    caller_pinned_group_separation_verified: Literal[True]
    semantic_equivalence_verified: Literal[False]
    identity_proxy_exclusion_verified: Literal[False]
    real_independence_verified: Literal[False]
    independent_attestation: Literal[False]
    manifest_artifact_hash_verified: Literal[True]
    prediction_key_root_is_mapping_projection: Literal[True]
    target_manifest_chain_verified: Literal[False]
    freeze_receipt_chain_verified: Literal[False]
    gate_closed: Literal[False]
    authority_effect: Literal["none"]


class ShortcutOntologyVerificationResult(ShortcutOntologyModel):
    """Verified report and its exact target-free execution projection."""

    assurance_report: ShortcutOntologyAssuranceReport
    local_hypothesis_maps: tuple[IncidentLocalHypothesisMap, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def projection_matches_report_cardinality(self) -> ShortcutOntologyVerificationResult:
        incident_ids = tuple(item.incident_id for item in self.local_hypothesis_maps)
        if len(incident_ids) != self.assurance_report.case_count:
            raise ValueError("verified local-map count differs from the assurance report")
        if len(incident_ids) != len(set(incident_ids)):
            raise ValueError("verified local maps contain duplicate incidents")
        assignment_count = sum(len(item.assignments) for item in self.local_hypothesis_maps)
        if assignment_count != self.assurance_report.assignment_count:
            raise ValueError("verified local-map assignments differ from the assurance report")
        return self


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ShortcutOntologyError(f"JSON artifact contains duplicate object key: {key}")
        value[key] = item
    return value


def _reject_json_constant(token: str) -> object:
    raise ShortcutOntologyError(f"JSON artifact contains non-finite constant: {token}")


def _parse_raw_json_model(
    raw_bytes: bytes,
    *,
    expected_artifact_sha256: str,
    model_type: type[_ModelT],
    label: str,
) -> _ModelT:
    if not isinstance(raw_bytes, bytes):
        raise ShortcutOntologyError(f"{label} bytes must be immutable")
    if len(raw_bytes) > _MAXIMUM_JSON_ARTIFACT_BYTES:
        raise ShortcutOntologyError(f"{label} exceeds its byte limit")
    expected_hash = _require_sha256(
        expected_artifact_sha256,
        label=f"{label} expected artifact hash",
    )
    if sha256_bytes(raw_bytes) != expected_hash:
        raise ShortcutOntologyError(f"{label} raw artifact hash mismatch")
    try:
        text = raw_bytes.decode("utf-8")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ShortcutOntologyError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(parsed, dict):
        raise ShortcutOntologyError(f"{label} must be a JSON object")
    try:
        validated = model_type.model_validate_json(raw_bytes, strict=True)
    except (ValidationError, ValueError) as error:
        raise ShortcutOntologyError(f"{label} violates its typed contract") from error
    if validated.model_dump(mode="json", exclude_none=False) != parsed:
        raise ShortcutOntologyError(
            f"{label} omits or differs from the fully materialized typed artifact"
        )
    return validated


def parse_signed_mechanism_ontology(
    raw_bytes: bytes,
    *,
    expected_artifact_sha256: str,
) -> SignedMechanismOntology:
    """Parse exact ontology bytes with duplicate-key and raw-hash checks."""

    return _parse_raw_json_model(
        raw_bytes,
        expected_artifact_sha256=expected_artifact_sha256,
        model_type=SignedMechanismOntology,
        label="signed mechanism ontology",
    )


def parse_prediction_key_manifest(
    raw_bytes: bytes,
    *,
    expected_artifact_sha256: str,
) -> PredictionKeyManifest:
    """Parse exact prediction-key bytes with duplicate-key and raw-hash checks."""

    return _parse_raw_json_model(
        raw_bytes,
        expected_artifact_sha256=expected_artifact_sha256,
        model_type=PredictionKeyManifest,
        label="prediction-key manifest",
    )


def _parse_hypothesis_set(
    raw_bytes: bytes,
    *,
    expected_artifact_sha256: str,
) -> HypothesisSet:
    return _parse_raw_json_model(
        raw_bytes,
        expected_artifact_sha256=expected_artifact_sha256,
        model_type=HypothesisSet,
        label="bound hypothesis set",
    )


def _canonical_actor_bindings(
    bindings: Sequence[PinnedActorBinding],
    *,
    label: str,
) -> tuple[PinnedActorBinding, ...]:
    frozen = tuple(_strict_revalidate(item, PinnedActorBinding, label=label) for item in bindings)
    identities: dict[tuple[str, str], tuple[str, str]] = {}
    for item in frozen:
        key = (item.role, item.actor_id)
        value = (item.independence_group_id, item.ed25519_public_key)
        previous = identities.setdefault(key, value)
        if previous != value:
            raise ShortcutOntologyError(
                f"{label} contains inconsistent pins for one role and actor"
            )
    return frozen


def _verify_reviewer_separation(
    reviewer: PinnedActorBinding,
    *,
    prohibited: Sequence[PinnedActorBinding],
) -> tuple[PinnedActorBinding, ...]:
    validated_reviewer = _strict_revalidate(
        reviewer,
        PinnedActorBinding,
        label="ontology reviewer pin",
    )
    if validated_reviewer.role != "ontology_reviewer":
        raise ShortcutOntologyError("ontology reviewer pin has the wrong role")
    frozen = _canonical_actor_bindings(
        prohibited,
        label="ontology reviewer prohibited actor pins",
    )
    required_roles = {
        "hypothesis_proposer",
        "mechanism_reviewer",
        "shortcut_worker",
        "final_evaluator",
    }
    observed_roles = {item.role for item in frozen}
    missing = required_roles - observed_roles
    if missing:
        raise ShortcutOntologyError(
            "ontology reviewer separation lacks caller-pinned roles: " + ", ".join(sorted(missing))
        )
    for item in frozen:
        if item.role == "ontology_reviewer":
            raise ShortcutOntologyError(
                "ontology reviewer cannot appear among its prohibited role bindings"
            )
        if item.actor_id == validated_reviewer.actor_id:
            raise ShortcutOntologyError(
                "ontology reviewer shares an actor identity with a prohibited role"
            )
        if item.independence_group_id == validated_reviewer.independence_group_id:
            raise ShortcutOntologyError(
                "ontology reviewer shares an independence group with a prohibited role"
            )
        if item.ed25519_public_key == validated_reviewer.ed25519_public_key:
            raise ShortcutOntologyError(
                "ontology reviewer shares a signing key with a prohibited role"
            )
    return frozen


def verify_signed_mechanism_ontology(
    ontology: SignedMechanismOntology,
    *,
    expected_reviewer: PinnedActorBinding,
    prohibited_actor_bindings: Sequence[PinnedActorBinding],
) -> None:
    """Verify ontology structure, signature, and caller-pinned role separation.

    Passing this function does not establish semantic equivalence review or real-world
    independence.  It only checks exact signed bytes represented by the model and the external
    pins supplied by the caller.
    """

    validated = _strict_revalidate(
        ontology,
        SignedMechanismOntology,
        label="signed mechanism ontology",
    )
    reviewer = _strict_revalidate(
        expected_reviewer,
        PinnedActorBinding,
        label="ontology reviewer pin",
    )
    _verify_reviewer_separation(
        reviewer,
        prohibited=prohibited_actor_bindings,
    )
    if (
        validated.ontology_reviewer_id != reviewer.actor_id
        or validated.ontology_reviewer_independence_group_id != reviewer.independence_group_id
    ):
        raise ShortcutOntologyError("ontology reviewer identity or group differs from caller pins")
    try:
        verify_shortcut_attestation(
            validated.attestation,
            expected_kind=ONTOLOGY_ATTESTATION_KIND,
            expected_subject=ontology_attestation_subject(validated),
            expected_signer_id=reviewer.actor_id,
            expected_public_key=reviewer.ed25519_public_key,
        )
    except ShortcutContractError as error:
        raise ShortcutOntologyError("mechanism ontology attestation is invalid") from error


def _verify_case_chronology(
    ontology: SignedMechanismOntology,
    case: SignedCasePredictionKeyManifest,
    bound: BoundCaseVerificationInput,
) -> None:
    if ontology.committed_at > case.committed_at:
        raise ShortcutOntologyError("case assignment predates its signed ontology")
    if case.committed_at < bound.hypothesis_set_committed_at:
        raise ShortcutOntologyError("case assignment predates its bound hypothesis set")
    if case.committed_at < bound.ambiguity_review_committed_at:
        raise ShortcutOntologyError("case assignment predates its bound ambiguity review")
    if case.committed_at > bound.reviewed_hypothesis_set_committed_at:
        raise ShortcutOntologyError(
            "case assignment missed the reviewed-hypothesis-set commitment deadline"
        )


def _verify_exact_hypothesis_membership(
    case: SignedCasePredictionKeyManifest,
    hypothesis_set: HypothesisSet,
    known_classes: Mapping[str, MechanismClassDefinition],
) -> None:
    try:
        validated_hypotheses = HypothesisSet.model_validate(
            hypothesis_set.model_dump(mode="python"),
            strict=True,
        )
    except ValidationError as error:
        raise ShortcutOntologyError("bound hypothesis set failed strict revalidation") from error
    if validated_hypotheses.incident_id != case.incident_id:
        raise ShortcutOntologyError("assignment incident differs from its hypothesis set")
    if validated_hypotheses.proposer_id != case.hypothesis_proposer_id:
        raise ShortcutOntologyError("assignment proposer differs from its hypothesis set")
    expected = {item.hypothesis_id: item.unknown for item in validated_hypotheses.hypotheses}
    observed = {item.hypothesis_id: item.unknown for item in case.assignments}
    if observed != expected:
        raise ShortcutOntologyError(
            "prediction-key assignments do not exactly cover hypothesis IDs and unknown states"
        )
    for assignment in case.assignments:
        if assignment.unknown:
            continue
        if assignment.prediction_key not in known_classes:
            raise ShortcutOntologyError(
                "known assignment names a key absent from the signed ontology"
            )
        # The class-definition hash is deliberately not re-compared here. `known_classes` is keyed
        # by `mechanism_class_prediction_key`, and `HypothesisPredictionKeyAssignment` already
        # requires `class_definition_sha256 == prediction_key` for every known assignment, so any
        # comparison at this point is equal by construction and can never fail. The invariant is
        # enforced at the model boundary and exercised there by a broken subject; a copy here would
        # be a guard that cannot fail, which is the defect `CONTINUITY.md` records.


def _verify_prediction_key_manifest(
    manifest: PredictionKeyManifest,
    ontology: SignedMechanismOntology,
    *,
    ontology_artifact_sha256: str,
    prediction_key_manifest_artifact_sha256: str,
    caller_pinned_trust_registry_artifact_sha256: str,
    expected_reviewer: PinnedActorBinding,
    bound_cases: Sequence[BoundCaseVerificationInput],
    prohibited_actor_bindings: Sequence[PinnedActorBinding],
) -> ShortcutOntologyAssuranceReport:
    """Verify parsed per-case mappings under caller-pinned implementation-only inputs."""

    validated_manifest = _strict_revalidate(
        manifest,
        PredictionKeyManifest,
        label="prediction-key manifest",
    )
    validated_ontology = _strict_revalidate(
        ontology,
        SignedMechanismOntology,
        label="signed mechanism ontology",
    )
    reviewer = _strict_revalidate(
        expected_reviewer,
        PinnedActorBinding,
        label="ontology reviewer pin",
    )
    validated_bound_cases = tuple(
        _strict_revalidate(item, BoundCaseVerificationInput, label="bound case input")
        for item in bound_cases
    )
    bound_incident_ids = tuple(item.incident_id for item in validated_bound_cases)
    if len(bound_incident_ids) != len(set(bound_incident_ids)):
        raise ShortcutOntologyError("bound verification inputs contain duplicate incidents")
    bound_by_incident = {item.incident_id: item for item in validated_bound_cases}
    manifest_incidents = tuple(item.incident_id for item in validated_manifest.cases)
    if set(manifest_incidents) != set(bound_by_incident):
        raise ShortcutOntologyError(
            "bound verification inputs do not exactly cover prediction-key cases"
        )

    validated_ontology_hash = _require_sha256(
        ontology_artifact_sha256,
        label="ontology artifact hash",
    )
    validated_manifest_hash = _require_sha256(
        prediction_key_manifest_artifact_sha256,
        label="prediction-key manifest artifact hash",
    )
    validated_trust_registry_hash = _require_sha256(
        caller_pinned_trust_registry_artifact_sha256,
        label="caller-pinned trust-registry artifact hash",
    )
    if validated_manifest.ontology_artifact_sha256 != validated_ontology_hash:
        raise ShortcutOntologyError("prediction-key manifest binds a different ontology artifact")

    proposer_pins = tuple(item.hypothesis_proposer for item in validated_bound_cases)
    prohibited = _canonical_actor_bindings(
        (*prohibited_actor_bindings, *proposer_pins),
        label="complete prohibited actor pins",
    )
    verify_signed_mechanism_ontology(
        validated_ontology,
        expected_reviewer=reviewer,
        prohibited_actor_bindings=prohibited,
    )
    known_classes = validated_ontology.classes_by_prediction_key()

    for case in validated_manifest.cases:
        bound = bound_by_incident[case.incident_id]
        proposer = bound.hypothesis_proposer
        if (
            case.hypothesis_set_artifact_sha256 != bound.hypothesis_set_artifact_sha256
            or case.ambiguity_review_receipt_artifact_sha256
            != bound.ambiguity_review_receipt_artifact_sha256
        ):
            raise ShortcutOntologyError("case assignment differs from caller-bound artifact hashes")
        if (
            case.hypothesis_proposer_id != proposer.actor_id
            or case.hypothesis_proposer_independence_group_id != proposer.independence_group_id
        ):
            raise ShortcutOntologyError("case assignment proposer differs from caller pins")
        if (
            case.ontology_reviewer_id != reviewer.actor_id
            or case.ontology_reviewer_independence_group_id != reviewer.independence_group_id
        ):
            raise ShortcutOntologyError("case assignment reviewer differs from caller pins")
        hypothesis_set = _parse_hypothesis_set(
            bound.raw_hypothesis_set_json,
            expected_artifact_sha256=bound.hypothesis_set_artifact_sha256,
        )
        _verify_exact_hypothesis_membership(case, hypothesis_set, known_classes)
        _verify_case_chronology(validated_ontology, case, bound)
        try:
            verify_shortcut_attestation(
                case.hypothesis_proposer_attestation,
                expected_kind=ASSIGNMENT_PROPOSAL_ATTESTATION_KIND,
                expected_subject=assignment_attestation_subject(case),
                expected_signer_id=proposer.actor_id,
                expected_public_key=proposer.ed25519_public_key,
            )
            verify_shortcut_attestation(
                case.ontology_reviewer_attestation,
                expected_kind=ASSIGNMENT_REVIEW_ATTESTATION_KIND,
                expected_subject=assignment_attestation_subject(case),
                expected_signer_id=reviewer.actor_id,
                expected_public_key=reviewer.ed25519_public_key,
            )
        except ShortcutContractError as error:
            raise ShortcutOntologyError(
                f"prediction-key assignment attestation pair is invalid for {case.incident_id}"
            ) from error

    return ShortcutOntologyAssuranceReport(
        schema_version="inbar.iter001.shortcut-ontology-assurance-report.v1",
        assurance_scope="same-operator-implementation-only-structural-verification",
        ontology_artifact_sha256=validated_ontology_hash,
        prediction_key_manifest_artifact_sha256=validated_manifest_hash,
        caller_pinned_trust_registry_artifact_sha256=validated_trust_registry_hash,
        prediction_key_root_sha256=validated_manifest.prediction_key_root_sha256,
        case_count=len(validated_manifest.cases),
        assignment_count=sum(len(item.assignments) for item in validated_manifest.cases),
        caller_pinned_actor_bindings_checked=1 + len(prohibited),
        exact_hypothesis_membership_verified=True,
        explicit_unknown_verified=True,
        structural_biconditional_verified=True,
        signatures_verified=True,
        declared_chronology_verified=True,
        external_chronology_verified=False,
        caller_pinned_group_separation_verified=True,
        semantic_equivalence_verified=False,
        identity_proxy_exclusion_verified=False,
        real_independence_verified=False,
        independent_attestation=False,
        manifest_artifact_hash_verified=True,
        prediction_key_root_is_mapping_projection=True,
        target_manifest_chain_verified=False,
        freeze_receipt_chain_verified=False,
        gate_closed=False,
        authority_effect="none",
    )


def verify_shortcut_v2_ontology_artifacts(
    *,
    ontology_artifact_bytes: bytes,
    ontology_artifact_sha256: str,
    prediction_key_manifest_artifact_bytes: bytes,
    prediction_key_manifest_artifact_sha256: str,
    caller_pinned_trust_registry_artifact_sha256: str,
    expected_reviewer: PinnedActorBinding,
    bound_cases: Sequence[BoundCaseVerificationInput],
    prohibited_actor_bindings: Sequence[PinnedActorBinding],
) -> ShortcutOntologyVerificationResult:
    """Parse and verify exact raw ontology and prediction-key artifacts.

    Duplicate object keys, raw-hash substitution, typed normalization, signature substitution,
    incomplete hypothesis coverage, unknown-key ambiguity, caller-pinned group overlap, and
    chronology violations all fail closed.
    """

    ontology = parse_signed_mechanism_ontology(
        ontology_artifact_bytes,
        expected_artifact_sha256=ontology_artifact_sha256,
    )
    manifest = parse_prediction_key_manifest(
        prediction_key_manifest_artifact_bytes,
        expected_artifact_sha256=prediction_key_manifest_artifact_sha256,
    )
    report = _verify_prediction_key_manifest(
        manifest,
        ontology,
        ontology_artifact_sha256=ontology_artifact_sha256,
        prediction_key_manifest_artifact_sha256=prediction_key_manifest_artifact_sha256,
        caller_pinned_trust_registry_artifact_sha256=(caller_pinned_trust_registry_artifact_sha256),
        expected_reviewer=expected_reviewer,
        bound_cases=bound_cases,
        prohibited_actor_bindings=prohibited_actor_bindings,
    )
    return ShortcutOntologyVerificationResult(
        assurance_report=report,
        local_hypothesis_maps=_project_local_hypothesis_maps(manifest),
    )


def _project_local_hypothesis_maps(
    manifest: PredictionKeyManifest,
) -> tuple[IncidentLocalHypothesisMap, ...]:
    """Project already-verified assignments into the target-free cross-fit map shape.

    The projection intentionally drops case, ontology, chronology, and signature bindings.
    It is private so the public verifier remains the only constructor path in this module.
    A known prediction key absent from one projected case remains an explicit
    ``key_unavailable`` abstention in the categorical and tree predictors.  The reserved
    ``unknown`` key is a real mapped hypothesis, not an abstention reason.
    """

    validated = _strict_revalidate(
        manifest,
        PredictionKeyManifest,
        label="prediction-key manifest projection",
    )
    return tuple(
        IncidentLocalHypothesisMap(
            incident_id=case.incident_id,
            assignments=tuple(
                LocalHypothesisAssignment(
                    prediction_key=assignment.prediction_key,
                    hypothesis_id=assignment.hypothesis_id,
                )
                for assignment in sorted(
                    case.assignments,
                    key=lambda item: _utf8_key(item.prediction_key),
                )
            ),
        )
        for case in validated.cases
    )
