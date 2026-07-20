"""Controls for the terminal prediction boundary.

The first test here is the important one. It demonstrates on real code that a substituted caller
map produces a confident wrong answer rather than an abstention, which is the failure
`CONTINUITY.md` disclosed only in its benign half. The rest establish that the terminal entry
points cannot be driven that way, because they take no projection from a caller at all.
"""

from __future__ import annotations

import inspect

import pytest

from fieldtrue.canonical import canonical_json_pretty, sha256_bytes
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
from fieldtrue.shortcut_v2_ontology import ShortcutOntologyError
from fieldtrue.shortcut_v2_terminal import (
    predict_categorical_under_verified_projection,
    predict_tree_under_verified_projection,
)
from tests.unit.test_shortcut_v2_ontology import (
    PROHIBITED,
    REVIEWER,
    TRUST_REGISTRY_SHA,
    OntologyFixture,
    _fixture,
    _verify,
)


def _fold_holding_out_alpha() -> CrossfitFold:
    train_ids = ("incident-beta",)
    holdout_ids = ("incident-alpha",)
    return CrossfitFold(
        schema_version="inbar.iter001.crossfit-fold.v1",
        axis="hardware_identity",
        holdout_group="heldout-alpha",
        train_incident_ids=train_ids,
        holdout_incident_ids=holdout_ids,
        train_incident_ids_sha256=incident_id_list_sha256(train_ids),
        holdout_incident_ids_sha256=incident_id_list_sha256(holdout_ids),
    )


def _trained_state(fixture: OntologyFixture, fold: CrossfitFold):  # type: ignore[no-untyped-def]
    job = CrossfitJobIdentity(
        rule_id="source-identity",
        axis=fold.axis,
        holdout_group=fold.holdout_group,
        recipient_stage="train_prediction",
    )
    return fit_categorical_train_mode(
        job,
        fold,
        (
            CategoricalTrainingExample(
                incident_id="incident-beta",
                selector=selector_value("shared-selector"),
                target_prediction_key=fixture.keys["a"],
            ),
        ),
    )


def _terminal_kwargs(fixture: OntologyFixture) -> dict[str, object]:
    ontology_bytes = canonical_json_pretty(fixture.ontology)
    manifest_bytes = canonical_json_pretty(fixture.manifest)
    return {
        "ontology_artifact_bytes": ontology_bytes,
        "ontology_artifact_sha256": sha256_bytes(ontology_bytes),
        "prediction_key_manifest_artifact_bytes": manifest_bytes,
        "prediction_key_manifest_artifact_sha256": sha256_bytes(manifest_bytes),
        "caller_pinned_trust_registry_artifact_sha256": TRUST_REGISTRY_SHA,
        "expected_reviewer": REVIEWER,
        "bound_cases": tuple(item.bound for item in fixture.cases_by_incident.values()),
        "prohibited_actor_bindings": PROHIBITED,
    }


def test_substituted_caller_map_yields_a_confident_wrong_answer_on_the_primitive_path() -> None:
    """The dangerous half of the disclosure, demonstrated rather than asserted.

    `IncidentLocalHypothesisMap` validates ordering and bijectivity, never provenance. Swapping
    two hypothesis IDs between prediction keys keeps the map perfectly well formed, so the
    predictor accepts it and reports a confident selection that names the wrong hypothesis. It
    does not abstain, and nothing in the returned manifest records that anything is wrong.
    """
    fixture = _fixture()
    verified = {item.incident_id: item for item in _verify(fixture).local_hypothesis_maps}
    alpha = verified["incident-alpha"]

    swap = {"alpha-known-a": "alpha-known-c", "alpha-known-c": "alpha-known-a"}
    substituted = IncidentLocalHypothesisMap(
        incident_id=alpha.incident_id,
        assignments=tuple(
            item.model_copy(
                update={"hypothesis_id": swap.get(item.hypothesis_id, item.hypothesis_id)}
            )
            for item in alpha.assignments
        ),
    )

    fold = _fold_holding_out_alpha()
    state = _trained_state(fixture, fold)
    manifest = predict_categorical_holdout(
        state,
        fold,
        (
            CategoricalHoldoutInput(
                incident_id="incident-alpha", selector=selector_value("shared-selector")
            ),
        ),
        (substituted,),
        fitted_state_artifact_bytes=canonical_artifact_bytes(state),
    )

    prediction = manifest.predictions[0]
    assert prediction.proposed_prediction_key == fixture.keys["a"]
    assert prediction.abstention_reason is None, "a substituted map does not abstain"
    assert prediction.selected_hypothesis_id == "alpha-known-c"
    assert alpha.as_mapping()[fixture.keys["a"]] == "alpha-known-a"


@pytest.mark.parametrize(
    "entry_point",
    [predict_categorical_under_verified_projection, predict_tree_under_verified_projection],
)
def test_terminal_entry_points_accept_no_caller_projection(entry_point: object) -> None:
    """Structural control: substitution is impossible because the parameter does not exist."""
    parameters = inspect.signature(entry_point).parameters  # type: ignore[arg-type]
    assert "local_maps" not in parameters
    assert "local_hypothesis_maps" not in parameters


def test_terminal_path_predicts_under_the_projection_it_derives() -> None:
    """Positive control, so the negative controls are not vacuous."""
    fixture = _fixture()
    fold = _fold_holding_out_alpha()
    state = _trained_state(fixture, fold)
    manifest = predict_categorical_under_verified_projection(
        state,
        fold,
        (
            CategoricalHoldoutInput(
                incident_id="incident-alpha", selector=selector_value("shared-selector")
            ),
        ),
        fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        **_terminal_kwargs(fixture),  # type: ignore[arg-type]
    )
    prediction = manifest.predictions[0]
    assert prediction.proposed_prediction_key == fixture.keys["a"]
    assert prediction.selected_hypothesis_id == "alpha-known-a"
    assert prediction.abstention_reason is None


def test_terminal_path_still_fails_closed_on_a_substituted_ontology_artifact() -> None:
    """Deriving the projection does not weaken the artifact binding it derives from."""
    fixture = _fixture()
    fold = _fold_holding_out_alpha()
    state = _trained_state(fixture, fold)
    kwargs = _terminal_kwargs(fixture)
    kwargs["ontology_artifact_sha256"] = "0" * 64
    with pytest.raises(ShortcutOntologyError, match="raw artifact hash mismatch"):
        predict_categorical_under_verified_projection(
            state,
            fold,
            (
                CategoricalHoldoutInput(
                    incident_id="incident-alpha",
                    selector=selector_value("shared-selector"),
                ),
            ),
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
            **kwargs,  # type: ignore[arg-type]
        )
