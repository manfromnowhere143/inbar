from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from nacl.signing import SigningKey
from pydantic import BaseModel, ValidationError

from fieldtrue.canonical import canonical_json, canonical_json_pretty, sha256_bytes, sha256_value
from fieldtrue.domain import CausalHypothesis, HypothesisSet
from fieldtrue.shortcut_contracts import ShortcutAttestation, issue_shortcut_attestation
from fieldtrue.shortcut_v2_crossfit import (
    CategoricalHoldoutInput,
    CategoricalTrainingExample,
    CrossfitFold,
    CrossfitJobIdentity,
    IncidentLocalHypothesisMap,
    canonical_artifact_bytes,
    fit_categorical_train_mode,
    predict_categorical_holdout,
    selector_value,
)
from fieldtrue.shortcut_v2_hashing import incident_id_list_sha256
from fieldtrue.shortcut_v2_ontology import (
    ASSIGNMENT_PROPOSAL_ATTESTATION_KIND,
    ASSIGNMENT_REVIEW_ATTESTATION_KIND,
    MECHANISM_CLASS_DOMAIN,
    ONTOLOGY_ATTESTATION_KIND,
    PREDICTION_KEY_ROOT_DOMAIN,
    SHORTCUT_CASE_KEY_DOMAIN,
    BoundCaseVerificationInput,
    HypothesisPredictionKeyAssignment,
    MechanismClassDefinition,
    PinnedActorBinding,
    PredictionKeyManifest,
    ShortcutOntologyError,
    SignedCasePredictionKeyManifest,
    SignedMechanismOntology,
    assignment_attestation_subject,
    mechanism_class_prediction_key,
    ontology_attestation_subject,
    parse_prediction_key_manifest,
    parse_signed_mechanism_ontology,
    prediction_key_root_sha256,
    shortcut_case_key,
    verify_shortcut_v2_ontology_artifacts,
    verify_signed_mechanism_ontology,
)

ZERO_SHA = "0" * 64
TRUST_REGISTRY_SHA = "d" * 64
T0 = datetime(2026, 7, 15, 10, 0, tzinfo=UTC)
T1 = T0 + timedelta(minutes=1)
T2 = T0 + timedelta(minutes=2)
T3 = T0 + timedelta(minutes=3)
T4 = T0 + timedelta(minutes=4)
T5 = T0 + timedelta(minutes=5)

REVIEWER_KEY = SigningKey(bytes([1]) * 32)
PROPOSER_KEY = SigningKey(bytes([2]) * 32)
MECHANISM_KEY = SigningKey(bytes([3]) * 32)
WORKER_KEY = SigningKey(bytes([4]) * 32)
EVALUATOR_KEY = SigningKey(bytes([5]) * 32)
SUBSTITUTE_KEY = SigningKey(bytes([6]) * 32)


def _public_key(signing_key: SigningKey) -> str:
    return signing_key.verify_key.encode().hex()


REVIEWER = PinnedActorBinding(
    role="ontology_reviewer",
    actor_id="reviewer",
    independence_group_id="reviewer-group",
    ed25519_public_key=_public_key(REVIEWER_KEY),
)
PROPOSER = PinnedActorBinding(
    role="hypothesis_proposer",
    actor_id="proposer",
    independence_group_id="proposer-group",
    ed25519_public_key=_public_key(PROPOSER_KEY),
)
MECHANISM_REVIEWER = PinnedActorBinding(
    role="mechanism_reviewer",
    actor_id="mechanism-reviewer",
    independence_group_id="mechanism-group",
    ed25519_public_key=_public_key(MECHANISM_KEY),
)
SHORTCUT_WORKER = PinnedActorBinding(
    role="shortcut_worker",
    actor_id="shortcut-worker",
    independence_group_id="worker-group",
    ed25519_public_key=_public_key(WORKER_KEY),
)
FINAL_EVALUATOR = PinnedActorBinding(
    role="final_evaluator",
    actor_id="final-evaluator",
    independence_group_id="evaluator-group",
    ed25519_public_key=_public_key(EVALUATOR_KEY),
)
PROHIBITED = (MECHANISM_REVIEWER, SHORTCUT_WORKER, FINAL_EVALUATOR)


@dataclass(frozen=True)
class CaseFixture:
    hypothesis_set: HypothesisSet
    hypothesis_set_bytes: bytes
    hypothesis_set_sha256: str
    manifest: SignedCasePredictionKeyManifest
    bound: BoundCaseVerificationInput


@dataclass(frozen=True)
class OntologyFixture:
    definitions: dict[str, MechanismClassDefinition]
    keys: dict[str, str]
    ontology: SignedMechanismOntology
    ontology_bytes: bytes
    ontology_sha256: str
    cases_by_incident: dict[str, CaseFixture]
    manifest: PredictionKeyManifest
    manifest_bytes: bytes
    manifest_sha256: str


def _placeholder_attestation(
    *,
    signing_key: SigningKey,
    signer_id: str,
    kind: str,
) -> ShortcutAttestation:
    return issue_shortcut_attestation(
        signing_key,
        signer_id=signer_id,
        kind=kind,
        subject={"placeholder": kind},
    )


def _definition(
    canonical_name: str,
    *,
    causal_locus: str,
    failure_mode: str,
    temporal_signature: str,
    directionality: str,
    definition: str,
) -> MechanismClassDefinition:
    return MechanismClassDefinition(
        schema_version="inbar.iter001.mechanism-class.v1",
        canonical_name=canonical_name,
        causal_locus=causal_locus,
        failure_mode=failure_mode,
        temporal_signature=temporal_signature,
        directionality=directionality,
        definition=definition,
    )


def _definitions() -> dict[str, MechanismClassDefinition]:
    return {
        "a": _definition(
            "actuator-stiction",
            causal_locus="primary linear actuator",
            failure_mode="static friction prevents commanded displacement",
            temporal_signature="persistent command-position disagreement after onset",
            directionality="command changes precede absent displacement",
            definition="Mechanical stiction in the primary actuator prevents intended motion.",
        ),
        "b": _definition(
            "sensor-bias",
            causal_locus="position feedback transducer",
            failure_mode="additive bias shifts reported position",
            temporal_signature="persistent observation offset with preserved motion response",
            directionality="biased observation follows otherwise nominal displacement",
            definition="A stable sensor bias shifts feedback without preventing physical motion.",
        ),
        "c": _definition(
            "drive-current-limiting",
            causal_locus="actuator drive electronics",
            failure_mode="current limiting truncates delivered actuator torque",
            temporal_signature="current plateau precedes reduced acceleration",
            directionality="drive saturation precedes displacement deficit",
            definition="Electronic current limiting reduces available actuator torque.",
        ),
    }


def _signed_ontology(
    classes: tuple[MechanismClassDefinition, ...],
    *,
    committed_at: datetime = T0,
    signing_key: SigningKey = REVIEWER_KEY,
) -> SignedMechanismOntology:
    base = SignedMechanismOntology(
        schema_version="inbar.iter001.shortcut-mechanism-ontology.v1",
        classes=classes,
        committed_at=committed_at,
        ontology_reviewer_id=REVIEWER.actor_id,
        ontology_reviewer_independence_group_id=REVIEWER.independence_group_id,
        attestation=_placeholder_attestation(
            signing_key=signing_key,
            signer_id=REVIEWER.actor_id,
            kind=ONTOLOGY_ATTESTATION_KIND,
        ),
    )
    attestation = issue_shortcut_attestation(
        signing_key,
        signer_id=REVIEWER.actor_id,
        kind=ONTOLOGY_ATTESTATION_KIND,
        subject=ontology_attestation_subject(base),
    )
    return base.model_copy(update={"attestation": attestation})


def _resign_ontology(
    ontology: SignedMechanismOntology,
    *,
    signing_key: SigningKey = REVIEWER_KEY,
) -> SignedMechanismOntology:
    attestation = issue_shortcut_attestation(
        signing_key,
        signer_id=ontology.ontology_reviewer_id,
        kind=ONTOLOGY_ATTESTATION_KIND,
        subject=ontology_attestation_subject(ontology),
    )
    return ontology.model_copy(update={"attestation": attestation})


def _artifact(model: BaseModel) -> tuple[bytes, str]:
    artifact_bytes = canonical_json_pretty(model)
    return artifact_bytes, sha256_bytes(artifact_bytes)


def _hypothesis_set(
    incident_id: str,
    hypotheses: tuple[tuple[str, bool], ...],
) -> tuple[HypothesisSet, bytes, str]:
    prior = 1.0 / len(hypotheses)
    model = HypothesisSet(
        incident_id=incident_id,
        hypotheses=tuple(
            CausalHypothesis(
                hypothesis_id=hypothesis_id,
                description=f"Synthetic pre-truth hypothesis {hypothesis_id}",
                prior=prior,
                unknown=unknown,
            )
            for hypothesis_id, unknown in hypotheses
        ),
        proposer_id=PROPOSER.actor_id,
    )
    artifact_bytes, artifact_sha256 = _artifact(model)
    return model, artifact_bytes, artifact_sha256


def _signed_case(
    *,
    incident_id: str,
    hypothesis_set_sha256: str,
    ontology_sha256: str,
    assignments: tuple[HypothesisPredictionKeyAssignment, ...],
    ambiguity_review_sha256: str,
    committed_at: datetime = T3,
    proposer_key: SigningKey = PROPOSER_KEY,
    reviewer_key: SigningKey = REVIEWER_KEY,
) -> SignedCasePredictionKeyManifest:
    base = SignedCasePredictionKeyManifest(
        schema_version="inbar.iter001.prediction-key-assignment-manifest.v1",
        case_key=shortcut_case_key(incident_id, hypothesis_set_sha256),
        incident_id=incident_id,
        hypothesis_set_artifact_sha256=hypothesis_set_sha256,
        ontology_artifact_sha256=ontology_sha256,
        assignments=tuple(sorted(assignments, key=lambda item: item.hypothesis_id.encode("utf-8"))),
        hypothesis_proposer_id=PROPOSER.actor_id,
        hypothesis_proposer_independence_group_id=PROPOSER.independence_group_id,
        ontology_reviewer_id=REVIEWER.actor_id,
        ontology_reviewer_independence_group_id=REVIEWER.independence_group_id,
        ambiguity_review_receipt_artifact_sha256=ambiguity_review_sha256,
        committed_at=committed_at,
        hypothesis_proposer_attestation=_placeholder_attestation(
            signing_key=proposer_key,
            signer_id=PROPOSER.actor_id,
            kind=ASSIGNMENT_PROPOSAL_ATTESTATION_KIND,
        ),
        ontology_reviewer_attestation=_placeholder_attestation(
            signing_key=reviewer_key,
            signer_id=REVIEWER.actor_id,
            kind=ASSIGNMENT_REVIEW_ATTESTATION_KIND,
        ),
    )
    subject = assignment_attestation_subject(base)
    return base.model_copy(
        update={
            "hypothesis_proposer_attestation": issue_shortcut_attestation(
                proposer_key,
                signer_id=PROPOSER.actor_id,
                kind=ASSIGNMENT_PROPOSAL_ATTESTATION_KIND,
                subject=subject,
            ),
            "ontology_reviewer_attestation": issue_shortcut_attestation(
                reviewer_key,
                signer_id=REVIEWER.actor_id,
                kind=ASSIGNMENT_REVIEW_ATTESTATION_KIND,
                subject=subject,
            ),
        }
    )


def _resign_case(
    case: SignedCasePredictionKeyManifest,
    *,
    proposer_key: SigningKey = PROPOSER_KEY,
    reviewer_key: SigningKey = REVIEWER_KEY,
) -> SignedCasePredictionKeyManifest:
    subject = assignment_attestation_subject(case)
    return case.model_copy(
        update={
            "hypothesis_proposer_attestation": issue_shortcut_attestation(
                proposer_key,
                signer_id=case.hypothesis_proposer_id,
                kind=ASSIGNMENT_PROPOSAL_ATTESTATION_KIND,
                subject=subject,
            ),
            "ontology_reviewer_attestation": issue_shortcut_attestation(
                reviewer_key,
                signer_id=case.ontology_reviewer_id,
                kind=ASSIGNMENT_REVIEW_ATTESTATION_KIND,
                subject=subject,
            ),
        }
    )


def _bound_case(
    *,
    incident_id: str,
    hypothesis_set_bytes: bytes,
    hypothesis_set_sha256: str,
    ambiguity_review_sha256: str,
) -> BoundCaseVerificationInput:
    return BoundCaseVerificationInput(
        incident_id=incident_id,
        raw_hypothesis_set_json=hypothesis_set_bytes,
        hypothesis_set_artifact_sha256=hypothesis_set_sha256,
        ambiguity_review_receipt_artifact_sha256=ambiguity_review_sha256,
        hypothesis_proposer=PROPOSER,
        hypothesis_set_committed_at=T1,
        ambiguity_review_committed_at=T2,
        reviewed_hypothesis_set_committed_at=T3,
        mechanism_target_committed_at=T4,
        safe_test_review_committed_at=T5,
    )


def _prediction_manifest(
    ontology_sha256: str,
    cases: tuple[SignedCasePredictionKeyManifest, ...],
) -> PredictionKeyManifest:
    ordered = tuple(sorted(cases, key=lambda item: item.case_key.encode("utf-8")))
    return PredictionKeyManifest(
        schema_version="inbar.iter001.prediction-key-manifest.v1",
        ontology_artifact_sha256=ontology_sha256,
        cases=ordered,
        prediction_key_root_sha256=prediction_key_root_sha256(
            ontology_sha256,
            ordered,
        ),
    )


def _fixture() -> OntologyFixture:
    definitions = _definitions()
    keys = {
        name: mechanism_class_prediction_key(definition) for name, definition in definitions.items()
    }
    ontology = _signed_ontology(
        tuple(
            sorted(
                definitions.values(),
                key=lambda item: mechanism_class_prediction_key(item).encode("utf-8"),
            )
        )
    )
    ontology_bytes, ontology_sha256 = _artifact(ontology)

    alpha_hypotheses = (
        ("alpha-known-a", False),
        ("alpha-known-c", False),
        ("alpha-unknown", True),
    )
    alpha_set, alpha_bytes, alpha_sha256 = _hypothesis_set(
        "incident-alpha",
        alpha_hypotheses,
    )
    alpha_ambiguity = "a" * 64
    alpha_case = _signed_case(
        incident_id="incident-alpha",
        hypothesis_set_sha256=alpha_sha256,
        ontology_sha256=ontology_sha256,
        assignments=(
            HypothesisPredictionKeyAssignment(
                hypothesis_id="alpha-known-a",
                prediction_key=keys["a"],
                unknown=False,
                class_definition_sha256=keys["a"],
            ),
            HypothesisPredictionKeyAssignment(
                hypothesis_id="alpha-known-c",
                prediction_key=keys["c"],
                unknown=False,
                class_definition_sha256=keys["c"],
            ),
            HypothesisPredictionKeyAssignment(
                hypothesis_id="alpha-unknown",
                prediction_key="unknown",
                unknown=True,
                class_definition_sha256=None,
            ),
        ),
        ambiguity_review_sha256=alpha_ambiguity,
    )

    beta_hypotheses = (("beta-known-b", False), ("beta-unknown", True))
    beta_set, beta_bytes, beta_sha256 = _hypothesis_set(
        "incident-beta",
        beta_hypotheses,
    )
    beta_ambiguity = "b" * 64
    beta_case = _signed_case(
        incident_id="incident-beta",
        hypothesis_set_sha256=beta_sha256,
        ontology_sha256=ontology_sha256,
        assignments=(
            HypothesisPredictionKeyAssignment(
                hypothesis_id="beta-known-b",
                prediction_key=keys["b"],
                unknown=False,
                class_definition_sha256=keys["b"],
            ),
            HypothesisPredictionKeyAssignment(
                hypothesis_id="beta-unknown",
                prediction_key="unknown",
                unknown=True,
                class_definition_sha256=None,
            ),
        ),
        ambiguity_review_sha256=beta_ambiguity,
    )

    cases_by_incident = {
        "incident-alpha": CaseFixture(
            hypothesis_set=alpha_set,
            hypothesis_set_bytes=alpha_bytes,
            hypothesis_set_sha256=alpha_sha256,
            manifest=alpha_case,
            bound=_bound_case(
                incident_id="incident-alpha",
                hypothesis_set_bytes=alpha_bytes,
                hypothesis_set_sha256=alpha_sha256,
                ambiguity_review_sha256=alpha_ambiguity,
            ),
        ),
        "incident-beta": CaseFixture(
            hypothesis_set=beta_set,
            hypothesis_set_bytes=beta_bytes,
            hypothesis_set_sha256=beta_sha256,
            manifest=beta_case,
            bound=_bound_case(
                incident_id="incident-beta",
                hypothesis_set_bytes=beta_bytes,
                hypothesis_set_sha256=beta_sha256,
                ambiguity_review_sha256=beta_ambiguity,
            ),
        ),
    }
    manifest = _prediction_manifest(
        ontology_sha256,
        tuple(item.manifest for item in cases_by_incident.values()),
    )
    manifest_bytes, manifest_sha256 = _artifact(manifest)
    return OntologyFixture(
        definitions=definitions,
        keys=keys,
        ontology=ontology,
        ontology_bytes=ontology_bytes,
        ontology_sha256=ontology_sha256,
        cases_by_incident=cases_by_incident,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        manifest_sha256=manifest_sha256,
    )


def _verify(
    fixture: OntologyFixture,
    *,
    ontology: SignedMechanismOntology | None = None,
    manifest: PredictionKeyManifest | None = None,
    bound_cases: tuple[BoundCaseVerificationInput, ...] | None = None,
    expected_reviewer: PinnedActorBinding = REVIEWER,
    prohibited: tuple[PinnedActorBinding, ...] = PROHIBITED,
) -> Any:
    selected_ontology = ontology or fixture.ontology
    selected_manifest = manifest or fixture.manifest
    ontology_bytes, ontology_sha256 = _artifact(selected_ontology)
    manifest_bytes, manifest_sha256 = _artifact(selected_manifest)
    selected_bounds = bound_cases or tuple(
        item.bound for item in fixture.cases_by_incident.values()
    )
    return verify_shortcut_v2_ontology_artifacts(
        ontology_artifact_bytes=ontology_bytes,
        ontology_artifact_sha256=ontology_sha256,
        prediction_key_manifest_artifact_bytes=manifest_bytes,
        prediction_key_manifest_artifact_sha256=manifest_sha256,
        caller_pinned_trust_registry_artifact_sha256=TRUST_REGISTRY_SHA,
        expected_reviewer=expected_reviewer,
        bound_cases=selected_bounds,
        prohibited_actor_bindings=prohibited,
    )


def _validated_copy(model: BaseModel, **updates: object) -> Any:
    payload = model.model_dump(mode="python")
    payload.update(updates)
    return type(model).model_validate(payload, strict=True)


def test_golden_mechanism_class_case_and_prediction_root_hashes() -> None:
    definition = _definitions()["a"]
    assert mechanism_class_prediction_key(definition) == (
        "189cea5e9067bff34594eb607fe96bc2164caf48f7e15592c719f4ef770ea16c"
    )
    assert mechanism_class_prediction_key(definition) == sha256_value(
        {
            "domain": MECHANISM_CLASS_DOMAIN,
            "canonical_name": "actuator-stiction",
            "causal_locus": "primary linear actuator",
            "failure_mode": "static friction prevents commanded displacement",
            "temporal_signature": "persistent command-position disagreement after onset",
            "directionality": "command changes precede absent displacement",
            "definition": ("Mechanical stiction in the primary actuator prevents intended motion."),
        }
    )

    hypothesis_sha = "1" * 64
    case_key = shortcut_case_key("incident-alpha", hypothesis_sha)
    assert case_key == "2cb4f8a469489043e825b193e41ec1b5909228480475cca9c616353905e9a2a5"
    assert case_key == sha256_value(
        {
            "domain": SHORTCUT_CASE_KEY_DOMAIN,
            "incident_id": "incident-alpha",
            "hypothesis_set_artifact_sha256": hypothesis_sha,
        }
    )

    ontology_sha = "2" * 64
    case = _signed_case(
        incident_id="incident-alpha",
        hypothesis_set_sha256=hypothesis_sha,
        ontology_sha256=ontology_sha,
        assignments=(
            HypothesisPredictionKeyAssignment(
                hypothesis_id="hyp-known",
                prediction_key=mechanism_class_prediction_key(definition),
                unknown=False,
                class_definition_sha256=mechanism_class_prediction_key(definition),
            ),
            HypothesisPredictionKeyAssignment(
                hypothesis_id="hyp-unknown",
                prediction_key="unknown",
                unknown=True,
                class_definition_sha256=None,
            ),
        ),
        ambiguity_review_sha256="3" * 64,
    )
    root = prediction_key_root_sha256(ontology_sha, (case,))
    assert root == "be469bbc885c6a56e65d64870c645255f1fb3658426e1bfe8db984c19abeb682"
    assert root == sha256_value(
        {
            "domain": PREDICTION_KEY_ROOT_DOMAIN,
            "ontology_artifact_sha256": ontology_sha,
            "assignments": [
                {
                    "case_key": case_key,
                    "hypothesis_id": "hyp-known",
                    "prediction_key": mechanism_class_prediction_key(definition),
                },
                {
                    "case_key": case_key,
                    "hypothesis_id": "hyp-unknown",
                    "prediction_key": "unknown",
                },
            ],
        }
    )


def test_exact_raw_parsers_and_verifier_preserve_nonauthoritative_boundaries() -> None:
    fixture = _fixture()

    assert (
        parse_signed_mechanism_ontology(
            fixture.ontology_bytes,
            expected_artifact_sha256=fixture.ontology_sha256,
        )
        == fixture.ontology
    )
    assert (
        parse_prediction_key_manifest(
            fixture.manifest_bytes,
            expected_artifact_sha256=fixture.manifest_sha256,
        )
        == fixture.manifest
    )

    result = _verify(fixture)
    report = result.assurance_report
    assert report.ontology_artifact_sha256 == fixture.ontology_sha256
    assert report.prediction_key_manifest_artifact_sha256 == fixture.manifest_sha256
    assert report.prediction_key_root_sha256 == fixture.manifest.prediction_key_root_sha256
    assert report.case_count == 2
    assert report.assignment_count == 5
    assert report.exact_hypothesis_membership_verified is True
    assert report.explicit_unknown_verified is True
    assert report.structural_biconditional_verified is True
    assert report.signatures_verified is True
    assert report.declared_chronology_verified is True
    assert report.external_chronology_verified is False
    assert report.semantic_equivalence_verified is False
    assert report.identity_proxy_exclusion_verified is False
    assert report.real_independence_verified is False
    assert report.independent_attestation is False
    assert report.manifest_artifact_hash_verified is True
    assert report.prediction_key_root_is_mapping_projection is True
    assert report.target_manifest_chain_verified is False
    assert report.freeze_receipt_chain_verified is False
    assert report.gate_closed is False
    assert report.authority_effect == "none"

    maps = {item.incident_id: item.as_mapping() for item in result.local_hypothesis_maps}
    assert maps["incident-alpha"] == {
        fixture.keys["a"]: "alpha-known-a",
        fixture.keys["c"]: "alpha-known-c",
        "unknown": "alpha-unknown",
    }
    assert maps["incident-beta"] == {
        fixture.keys["b"]: "beta-known-b",
        "unknown": "beta-unknown",
    }


def test_verified_projection_produces_genuine_key_unavailable_abstention() -> None:
    fixture = _fixture()
    result = _verify(fixture)
    maps = {item.incident_id: item for item in result.local_hypothesis_maps}
    train_ids = ("incident-alpha",)
    holdout_ids = ("incident-beta",)
    fold = CrossfitFold(
        schema_version="inbar.iter001.crossfit-fold.v1",
        axis="hardware_identity",
        holdout_group="heldout-beta",
        train_incident_ids=train_ids,
        holdout_incident_ids=holdout_ids,
        train_incident_ids_sha256=incident_id_list_sha256(train_ids),
        holdout_incident_ids_sha256=incident_id_list_sha256(holdout_ids),
    )
    job = CrossfitJobIdentity(
        rule_id="source-identity",
        axis=fold.axis,
        holdout_group=fold.holdout_group,
        recipient_stage="train_prediction",
    )
    selector = selector_value("shared-selector")
    state = fit_categorical_train_mode(
        job,
        fold,
        (
            CategoricalTrainingExample(
                incident_id="incident-alpha",
                selector=selector,
                target_prediction_key=fixture.keys["a"],
            ),
        ),
    )
    prediction_manifest = predict_categorical_holdout(
        state,
        fold,
        (
            CategoricalHoldoutInput(
                incident_id="incident-beta",
                selector=selector,
            ),
        ),
        (maps["incident-beta"],),
        fitted_state_artifact_bytes=canonical_artifact_bytes(state),
    )
    prediction = prediction_manifest.predictions[0]
    assert prediction.proposed_prediction_key == fixture.keys["a"]
    assert prediction.selected_prediction_key is None
    assert prediction.selected_hypothesis_id is None
    assert prediction.abstention_reason == "key_unavailable"
    assert maps["incident-beta"].as_mapping()["unknown"] == "beta-unknown"


def test_low_level_predictor_still_accepts_an_omitted_caller_map() -> None:
    fixture = _fixture()
    result = _verify(fixture)
    maps = {item.incident_id: item for item in result.local_hypothesis_maps}
    train_ids = ("incident-beta",)
    holdout_ids = ("incident-alpha",)
    fold = CrossfitFold(
        schema_version="inbar.iter001.crossfit-fold.v1",
        axis="hardware_identity",
        holdout_group="heldout-alpha",
        train_incident_ids=train_ids,
        holdout_incident_ids=holdout_ids,
        train_incident_ids_sha256=incident_id_list_sha256(train_ids),
        holdout_incident_ids_sha256=incident_id_list_sha256(holdout_ids),
    )
    job = CrossfitJobIdentity(
        rule_id="source-identity",
        axis=fold.axis,
        holdout_group=fold.holdout_group,
        recipient_stage="train_prediction",
    )
    selector = selector_value("shared-selector")
    state = fit_categorical_train_mode(
        job,
        fold,
        (
            CategoricalTrainingExample(
                incident_id="incident-beta",
                selector=selector,
                target_prediction_key=fixture.keys["a"],
            ),
        ),
    )
    verified_alpha = maps["incident-alpha"]
    omitted_alpha = IncidentLocalHypothesisMap(
        incident_id=verified_alpha.incident_id,
        assignments=tuple(
            item for item in verified_alpha.assignments if item.prediction_key != fixture.keys["a"]
        ),
    )
    prediction_manifest = predict_categorical_holdout(
        state,
        fold,
        (CategoricalHoldoutInput(incident_id="incident-alpha", selector=selector),),
        (omitted_alpha,),
        fitted_state_artifact_bytes=canonical_artifact_bytes(state),
    )

    prediction = prediction_manifest.predictions[0]
    assert prediction.proposed_prediction_key == fixture.keys["a"]
    assert prediction.abstention_reason == "key_unavailable"
    assert prediction.selected_hypothesis_id is None
    assert result.assurance_report.gate_closed is False


@pytest.mark.parametrize("artifact_kind", ["ontology", "manifest"])
def test_raw_artifact_hash_substitution_fails_closed(artifact_kind: str) -> None:
    fixture = _fixture()
    parser: Any
    if artifact_kind == "ontology":
        parser = parse_signed_mechanism_ontology
        artifact_bytes = fixture.ontology_bytes
    else:
        parser = parse_prediction_key_manifest
        artifact_bytes = fixture.manifest_bytes

    with pytest.raises(ShortcutOntologyError, match="raw artifact hash mismatch"):
        parser(artifact_bytes, expected_artifact_sha256=ZERO_SHA)

    source, replacement = (
        (b"actuator-stiction", b"actuator-binding")
        if artifact_kind == "ontology"
        else (b"incident-alpha", b"incident-gamma")
    )
    substituted = artifact_bytes.replace(source, replacement, 1)
    assert substituted != artifact_bytes
    with pytest.raises(ShortcutOntologyError, match="raw artifact hash mismatch"):
        parser(
            substituted,
            expected_artifact_sha256=sha256_bytes(artifact_bytes),
        )


@pytest.mark.parametrize("artifact_kind", ["ontology", "manifest"])
def test_duplicate_keys_fail_and_raw_format_is_hash_bound(
    artifact_kind: str,
) -> None:
    fixture = _fixture()
    parser: Any
    model: BaseModel
    if artifact_kind == "ontology":
        parser = parse_signed_mechanism_ontology
        model = fixture.ontology
        schema_version = "inbar.iter001.shortcut-mechanism-ontology.v1"
    else:
        parser = parse_prediction_key_manifest
        model = fixture.manifest
        schema_version = "inbar.iter001.prediction-key-manifest.v1"

    artifact_bytes = canonical_json_pretty(model)
    duplicate = artifact_bytes.replace(
        b"{\n",
        f'{{\n  "schema_version": "{schema_version}",\n'.encode(),
        1,
    )
    with pytest.raises(ShortcutOntologyError, match="duplicate object key"):
        parser(duplicate, expected_artifact_sha256=sha256_bytes(duplicate))

    compact = canonical_json(model)
    assert parser(compact, expected_artifact_sha256=sha256_bytes(compact)) == model
    with pytest.raises(ShortcutOntologyError, match="raw artifact hash mismatch"):
        parser(compact, expected_artifact_sha256=sha256_bytes(artifact_bytes))


def test_structural_aliases_and_supplied_different_key_are_rejected() -> None:
    original = _definitions()["a"]
    alias = original.model_copy(update={"canonical_name": "actuator-stiction-alias"})
    ordered_aliases = tuple(
        sorted(
            (original, alias),
            key=lambda item: mechanism_class_prediction_key(item).encode("utf-8"),
        )
    )
    with pytest.raises(ValidationError, match="differ only by their canonical names"):
        _signed_ontology(ordered_aliases)

    changed = original.model_copy(
        update={"definition": "A materially different physical definition."}
    )
    ordered_same_name = tuple(
        sorted(
            (original, changed),
            key=lambda item: mechanism_class_prediction_key(item).encode("utf-8"),
        )
    )
    with pytest.raises(ValidationError, match="canonical mechanism name"):
        _signed_ontology(ordered_same_name)

    with pytest.raises(ValidationError, match="content-derived class definition key"):
        HypothesisPredictionKeyAssignment(
            hypothesis_id="known",
            prediction_key="e" * 64,
            unknown=False,
            class_definition_sha256=mechanism_class_prediction_key(original),
        )


def test_canonical_ordering_is_enforced_at_every_level() -> None:
    fixture = _fixture()
    with pytest.raises(ValidationError, match="ordered by derived prediction key"):
        _signed_ontology(tuple(reversed(fixture.ontology.classes)))

    alpha = fixture.cases_by_incident["incident-alpha"].manifest
    payload = alpha.model_dump(mode="python")
    payload["assignments"] = tuple(reversed(alpha.assignments))
    with pytest.raises(ValidationError, match="ordered by hypothesis ID"):
        SignedCasePredictionKeyManifest.model_validate(payload, strict=True)

    manifest_payload = fixture.manifest.model_dump(mode="python")
    manifest_payload["cases"] = tuple(reversed(fixture.manifest.cases))
    with pytest.raises(ValidationError, match="ordered by case key"):
        PredictionKeyManifest.model_validate(manifest_payload, strict=True)

    with pytest.raises(ShortcutOntologyError, match="not in canonical order"):
        prediction_key_root_sha256(
            fixture.ontology_sha256,
            tuple(reversed(fixture.manifest.cases)),
        )


@pytest.mark.parametrize("mutation", ["missing", "extra", "cross_case_swap"])
def test_missing_extra_and_swapped_assignments_fail_exact_membership(
    mutation: str,
) -> None:
    fixture = _fixture()
    alpha = fixture.cases_by_incident["incident-alpha"].manifest
    assignments = list(alpha.assignments)
    if mutation == "missing":
        assignments = [item for item in assignments if item.hypothesis_id != "alpha-known-c"]
    elif mutation == "extra":
        assignments.append(
            HypothesisPredictionKeyAssignment(
                hypothesis_id="unregistered-hypothesis",
                prediction_key="e" * 64,
                unknown=False,
                class_definition_sha256="e" * 64,
            )
        )
    else:
        assignments = [
            item.model_copy(update={"hypothesis_id": "beta-known-b"})
            if item.hypothesis_id == "alpha-known-a"
            else item
            for item in assignments
        ]
    changed_alpha = _signed_case(
        incident_id=alpha.incident_id,
        hypothesis_set_sha256=alpha.hypothesis_set_artifact_sha256,
        ontology_sha256=alpha.ontology_artifact_sha256,
        assignments=tuple(assignments),
        ambiguity_review_sha256=alpha.ambiguity_review_receipt_artifact_sha256,
    )
    beta = fixture.cases_by_incident["incident-beta"].manifest
    manifest = _prediction_manifest(fixture.ontology_sha256, (changed_alpha, beta))

    with pytest.raises(ShortcutOntologyError, match="do not exactly cover"):
        _verify(fixture, manifest=manifest)


def test_duplicate_assignment_and_case_are_rejected_structurally() -> None:
    fixture = _fixture()
    alpha = fixture.cases_by_incident["incident-alpha"].manifest
    duplicate_assignment_payload = alpha.model_dump(mode="python")
    duplicate_assignment_payload["assignments"] = (
        *alpha.assignments,
        alpha.assignments[0],
    )
    duplicate_assignment_payload["assignments"] = tuple(
        sorted(
            duplicate_assignment_payload["assignments"],
            key=lambda item: item.hypothesis_id.encode("utf-8"),
        )
    )
    with pytest.raises(ValidationError, match="duplicate hypotheses"):
        SignedCasePredictionKeyManifest.model_validate(
            duplicate_assignment_payload,
            strict=True,
        )

    duplicate_case_payload = fixture.manifest.model_dump(mode="python")
    duplicate_case_payload["cases"] = (
        fixture.manifest.cases[0],
        fixture.manifest.cases[0],
    )
    with pytest.raises(ValidationError, match="duplicate case keys"):
        PredictionKeyManifest.model_validate(duplicate_case_payload, strict=True)


def test_unknown_state_swapped_between_hypotheses_is_rejected() -> None:
    fixture = _fixture()
    alpha = fixture.cases_by_incident["incident-alpha"].manifest
    key_a = fixture.keys["a"]
    changed_assignments = tuple(
        (
            item.model_copy(
                update={
                    "prediction_key": "unknown",
                    "unknown": True,
                    "class_definition_sha256": None,
                }
            )
            if item.hypothesis_id == "alpha-known-a"
            else item.model_copy(
                update={
                    "prediction_key": key_a,
                    "unknown": False,
                    "class_definition_sha256": key_a,
                }
            )
            if item.hypothesis_id == "alpha-unknown"
            else item
        )
        for item in alpha.assignments
    )
    changed_alpha = _signed_case(
        incident_id=alpha.incident_id,
        hypothesis_set_sha256=alpha.hypothesis_set_artifact_sha256,
        ontology_sha256=alpha.ontology_artifact_sha256,
        assignments=changed_assignments,
        ambiguity_review_sha256=alpha.ambiguity_review_receipt_artifact_sha256,
    )
    beta = fixture.cases_by_incident["incident-beta"].manifest
    manifest = _prediction_manifest(fixture.ontology_sha256, (changed_alpha, beta))

    with pytest.raises(ShortcutOntologyError, match="unknown states"):
        _verify(fixture, manifest=manifest)


def test_known_assignment_key_absent_from_ontology_is_rejected() -> None:
    fixture = _fixture()
    alpha = fixture.cases_by_incident["incident-alpha"].manifest
    absent_key = "e" * 64
    assignments = tuple(
        item.model_copy(
            update={
                "prediction_key": absent_key,
                "class_definition_sha256": absent_key,
            }
        )
        if item.hypothesis_id == "alpha-known-a"
        else item
        for item in alpha.assignments
    )
    changed_alpha = _signed_case(
        incident_id=alpha.incident_id,
        hypothesis_set_sha256=alpha.hypothesis_set_artifact_sha256,
        ontology_sha256=alpha.ontology_artifact_sha256,
        assignments=assignments,
        ambiguity_review_sha256=alpha.ambiguity_review_receipt_artifact_sha256,
    )
    beta = fixture.cases_by_incident["incident-beta"].manifest
    manifest = _prediction_manifest(fixture.ontology_sha256, (changed_alpha, beta))

    with pytest.raises(ShortcutOntologyError, match="absent from the signed ontology"):
        _verify(fixture, manifest=manifest)


@pytest.mark.parametrize("substitution", ["proposer", "reviewer", "ontology"])
def test_proposer_reviewer_and_ontology_signature_substitution_fails(
    substitution: str,
) -> None:
    fixture = _fixture()
    if substitution == "ontology":
        ontology = _resign_ontology(fixture.ontology, signing_key=SUBSTITUTE_KEY)
        with pytest.raises(ShortcutOntologyError, match="ontology attestation is invalid"):
            verify_signed_mechanism_ontology(
                ontology,
                expected_reviewer=REVIEWER,
                prohibited_actor_bindings=(*PROHIBITED, PROPOSER),
            )
        return

    alpha = fixture.cases_by_incident["incident-alpha"].manifest
    changed_alpha = _resign_case(
        alpha,
        proposer_key=SUBSTITUTE_KEY if substitution == "proposer" else PROPOSER_KEY,
        reviewer_key=SUBSTITUTE_KEY if substitution == "reviewer" else REVIEWER_KEY,
    )
    beta = fixture.cases_by_incident["incident-beta"].manifest
    manifest = _prediction_manifest(fixture.ontology_sha256, (changed_alpha, beta))
    with pytest.raises(ShortcutOntologyError, match="attestation pair is invalid"):
        _verify(fixture, manifest=manifest)


@pytest.mark.parametrize("collision", ["actor", "group", "key"])
def test_caller_pinned_reviewer_role_collisions_fail(collision: str) -> None:
    fixture = _fixture()
    update: dict[str, str] = {}
    if collision == "actor":
        update["actor_id"] = REVIEWER.actor_id
    elif collision == "group":
        update["independence_group_id"] = REVIEWER.independence_group_id
    else:
        update["ed25519_public_key"] = REVIEWER.ed25519_public_key
    collided = _validated_copy(MECHANISM_REVIEWER, **update)
    prohibited = (collided, SHORTCUT_WORKER, FINAL_EVALUATOR)

    expected = {
        "actor": "shares an actor identity",
        "group": "shares an independence group",
        "key": "shares a signing key",
    }[collision]
    with pytest.raises(ShortcutOntologyError, match=expected):
        _verify(fixture, prohibited=prohibited)


@pytest.mark.parametrize(
    "missing_role",
    ["mechanism_reviewer", "shortcut_worker", "final_evaluator"],
)
def test_caller_pinned_independence_roster_must_be_complete(
    missing_role: str,
) -> None:
    fixture = _fixture()
    prohibited = tuple(item for item in PROHIBITED if item.role != missing_role)
    with pytest.raises(ShortcutOntologyError, match="lacks caller-pinned roles"):
        _verify(fixture, prohibited=prohibited)


def test_caller_pinned_reviewer_must_have_the_ontology_reviewer_role() -> None:
    fixture = _fixture()
    wrong_role = PinnedActorBinding(
        role="mechanism_reviewer",
        actor_id=REVIEWER.actor_id,
        independence_group_id=REVIEWER.independence_group_id,
        ed25519_public_key=REVIEWER.ed25519_public_key,
    )
    with pytest.raises(ShortcutOntologyError, match="wrong role"):
        _verify(fixture, expected_reviewer=wrong_role)


@pytest.mark.parametrize(
    ("chronology", "message"),
    [
        ("before_ontology", "predates its signed ontology"),
        ("before_hypothesis", "predates its bound hypothesis set"),
        ("before_ambiguity", "predates its bound ambiguity review"),
        ("after_reviewed_deadline", "missed the reviewed-hypothesis-set commitment deadline"),
    ],
)
def test_declared_assignment_chronology_fails_closed(
    chronology: str,
    message: str,
) -> None:
    fixture = _fixture()
    alpha_fixture = fixture.cases_by_incident["incident-alpha"]
    alpha = alpha_fixture.manifest
    bound = alpha_fixture.bound

    if chronology == "before_ontology":
        changed_alpha = _signed_case(
            incident_id=alpha.incident_id,
            hypothesis_set_sha256=alpha.hypothesis_set_artifact_sha256,
            ontology_sha256=alpha.ontology_artifact_sha256,
            assignments=alpha.assignments,
            ambiguity_review_sha256=alpha.ambiguity_review_receipt_artifact_sha256,
            committed_at=T0 - timedelta(seconds=1),
        )
        changed_bound = bound
    elif chronology == "before_hypothesis":
        changed_alpha = alpha
        changed_bound = _validated_copy(
            bound,
            hypothesis_set_committed_at=T4,
            ambiguity_review_committed_at=T4,
            reviewed_hypothesis_set_committed_at=T4,
            mechanism_target_committed_at=T5,
            safe_test_review_committed_at=T5 + timedelta(minutes=1),
        )
    elif chronology == "before_ambiguity":
        changed_alpha = alpha
        changed_bound = _validated_copy(
            bound,
            ambiguity_review_committed_at=T4,
            reviewed_hypothesis_set_committed_at=T4,
            mechanism_target_committed_at=T5,
            safe_test_review_committed_at=T5 + timedelta(minutes=1),
        )
    else:
        changed_alpha = alpha
        changed_bound = _validated_copy(
            bound,
            ambiguity_review_committed_at=T2,
            reviewed_hypothesis_set_committed_at=T2,
        )

    beta = fixture.cases_by_incident["incident-beta"].manifest
    manifest = _prediction_manifest(fixture.ontology_sha256, (changed_alpha, beta))
    bounds = (
        changed_bound,
        fixture.cases_by_incident["incident-beta"].bound,
    )
    with pytest.raises(ShortcutOntologyError, match=message):
        _verify(fixture, manifest=manifest, bound_cases=bounds)


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        (
            {
                "ambiguity_review_committed_at": T0,
            },
            "ambiguity review cannot predate",
        ),
        (
            {
                "reviewed_hypothesis_set_committed_at": T1,
            },
            "cannot predate ambiguity review",
        ),
        (
            {
                "mechanism_target_committed_at": T3,
            },
            "mechanism target must strictly follow",
        ),
        (
            {
                "mechanism_target_committed_at": None,
                "safe_test_review_committed_at": T5,
            },
            "safe-test review requires",
        ),
        (
            {
                "safe_test_review_committed_at": T4,
            },
            "safe-test review must strictly follow",
        ),
    ],
)
def test_declared_bound_chronology_contract_rejects_impossible_orders(
    updates: dict[str, object],
    message: str,
) -> None:
    fixture = _fixture()
    bound = fixture.cases_by_incident["incident-alpha"].bound
    payload = bound.model_dump(mode="python")
    payload.update(updates)
    with pytest.raises(ValidationError, match=message):
        BoundCaseVerificationInput.model_validate(payload, strict=True)


def test_reviewer_signed_known_key_swap_is_only_structurally_verifiable() -> None:
    fixture = _fixture()
    alpha = fixture.cases_by_incident["incident-alpha"].manifest
    assignments_by_id = {item.hypothesis_id: item for item in alpha.assignments}
    key_a = fixture.keys["a"]
    key_c = fixture.keys["c"]
    swapped = tuple(
        item.model_copy(
            update={
                "prediction_key": key_c,
                "class_definition_sha256": key_c,
            }
        )
        if item.hypothesis_id == "alpha-known-a"
        else item.model_copy(
            update={
                "prediction_key": key_a,
                "class_definition_sha256": key_a,
            }
        )
        if item.hypothesis_id == "alpha-known-c"
        else item
        for item in alpha.assignments
    )
    assert assignments_by_id["alpha-known-a"].prediction_key != key_c
    changed_alpha = _signed_case(
        incident_id=alpha.incident_id,
        hypothesis_set_sha256=alpha.hypothesis_set_artifact_sha256,
        ontology_sha256=alpha.ontology_artifact_sha256,
        assignments=swapped,
        ambiguity_review_sha256=alpha.ambiguity_review_receipt_artifact_sha256,
    )
    beta = fixture.cases_by_incident["incident-beta"].manifest
    manifest = _prediction_manifest(fixture.ontology_sha256, (changed_alpha, beta))

    result = _verify(fixture, manifest=manifest)
    assert result.assurance_report.structural_biconditional_verified is True
    assert result.assurance_report.semantic_equivalence_verified is False
    assert result.assurance_report.independent_attestation is False
    assert result.assurance_report.authority_effect == "none"


def test_v1_mapping_projection_requires_the_separate_raw_manifest_hash() -> None:
    fixture = _fixture()
    alpha_fixture = fixture.cases_by_incident["incident-alpha"]
    alpha = alpha_fixture.manifest
    changed_ambiguity_hash = "f" * 64
    changed_alpha = _signed_case(
        incident_id=alpha.incident_id,
        hypothesis_set_sha256=alpha.hypothesis_set_artifact_sha256,
        ontology_sha256=alpha.ontology_artifact_sha256,
        assignments=alpha.assignments,
        ambiguity_review_sha256=changed_ambiguity_hash,
        committed_at=T3,
    )
    beta = fixture.cases_by_incident["incident-beta"].manifest
    changed_manifest = _prediction_manifest(
        fixture.ontology_sha256,
        (changed_alpha, beta),
    )
    changed_manifest_bytes, changed_manifest_sha256 = _artifact(changed_manifest)
    changed_bound = _validated_copy(
        alpha_fixture.bound,
        ambiguity_review_receipt_artifact_sha256=changed_ambiguity_hash,
    )

    assert (
        changed_manifest.prediction_key_root_sha256 == fixture.manifest.prediction_key_root_sha256
    )
    assert changed_manifest_bytes != fixture.manifest_bytes
    assert changed_manifest_sha256 != fixture.manifest_sha256

    result = _verify(
        fixture,
        manifest=changed_manifest,
        bound_cases=(
            changed_bound,
            fixture.cases_by_incident["incident-beta"].bound,
        ),
    )
    report = result.assurance_report
    assert report.prediction_key_root_sha256 == fixture.manifest.prediction_key_root_sha256
    assert report.prediction_key_manifest_artifact_sha256 == changed_manifest_sha256
    assert report.manifest_artifact_hash_verified is True
    assert report.prediction_key_root_is_mapping_projection is True
    assert report.target_manifest_chain_verified is False
    assert report.freeze_receipt_chain_verified is False
    assert report.gate_closed is False
    assert report.authority_effect == "none"
