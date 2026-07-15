from __future__ import annotations

import inspect
from typing import Any, cast

import pytest
from pydantic import JsonValue, ValidationError

from fieldtrue.canonical import canonical_json, sha256_value
from fieldtrue.shortcut_v2_crossfit import (
    AXIS_ORDER,
    CATEGORICAL_RULES,
    CROSSFIT_FOLD_ROOT_DOMAIN,
    ELIGIBLE_INCIDENT_IDS_DOMAIN,
    FITTED_STATE_ROOT_DOMAIN,
    PREDICTION_ROOT_DOMAIN,
    RULE_ORDER,
    TREE_RULE,
    CategoricalFittedState,
    CategoricalHoldoutInput,
    CategoricalMode,
    CategoricalPrediction,
    CategoricalPredictionManifest,
    CategoricalTrainingExample,
    CrossfitCensus,
    CrossfitFold,
    CrossfitFoldRegistry,
    CrossfitJobIdentity,
    EligibleIncident,
    FittedStateRootItem,
    IncidentLocalHypothesisMap,
    LocalHypothesisAssignment,
    PredictionRootItem,
    SelectorValue,
    ShortcutCrossfitError,
    TreeFittedState,
    TreePredictionManifest,
    build_crossfit_census,
    canonical_artifact_bytes,
    canonical_artifact_sha256,
    crossfit_fold_root_sha256,
    derive_crossfit_folds,
    fit_categorical_train_mode,
    fit_tree_train_fold,
    fitted_state_root_sha256,
    predict_categorical_holdout,
    predict_tree_holdout,
    prediction_root_sha256,
    selector_value,
    validate_categorical_fitted_state,
    validate_complete_rule_prediction_manifests,
    validate_crossfit_folds,
)
from fieldtrue.shortcut_v2_tree import (
    BooleanFeatureValue,
    FeatureEntry,
    FeatureVector,
)

KEY_ZERO = "0" * 64
KEY_ONE = "1" * 64
FEATURE = "a" * 64
ARTIFACT = "f" * 64


def _incidents() -> tuple[EligibleIncident, ...]:
    return tuple(
        EligibleIncident(
            incident_id=f"i{index}",
            hardware_family="family-a" if index < 4 else "family-b",
            hardware_identity=f"hardware-{index % 4}",
            fault_family=f"fault-{index % 2}",
        )
        for index in range(8)
    )


def _census() -> CrossfitCensus:
    return build_crossfit_census(tuple(reversed(_incidents())))


def _registry() -> CrossfitFoldRegistry:
    return derive_crossfit_folds(_census())


def _fold(
    registry: CrossfitFoldRegistry,
    axis: str = "hardware_family",
    group: str = "family-a",
) -> CrossfitFold:
    return next(
        item for item in registry.folds if item.axis == axis and item.holdout_group == group
    )


def _job(
    fold: CrossfitFold,
    *,
    rule_id: str = "source-identity",
    stage: str = "train_prediction",
) -> CrossfitJobIdentity:
    return CrossfitJobIdentity.model_validate(
        {
            "rule_id": rule_id,
            "axis": fold.axis,
            "holdout_group": fold.holdout_group,
            "recipient_stage": stage,
        }
    )


def _selector(text: str) -> SelectorValue:
    return selector_value(text)


def _categorical_examples(fold: CrossfitFold) -> tuple[CategoricalTrainingExample, ...]:
    selectors = (_selector("x"), _selector("x"), _selector("y"), _selector("y"))
    targets = (KEY_ZERO, KEY_ZERO, KEY_ZERO, KEY_ONE)
    return tuple(
        CategoricalTrainingExample(
            incident_id=incident_id,
            selector=selector,
            target_prediction_key=target,
        )
        for incident_id, selector, target in zip(
            fold.train_incident_ids,
            selectors,
            targets,
            strict=True,
        )
    )


def _local_map(
    incident_id: str,
    *assignments: tuple[str, str],
) -> IncidentLocalHypothesisMap:
    return IncidentLocalHypothesisMap(
        incident_id=incident_id,
        assignments=tuple(
            LocalHypothesisAssignment(prediction_key=key, hypothesis_id=hypothesis)
            for key, hypothesis in assignments
        ),
    )


def _row(incident_id: str, value: bool) -> FeatureVector:
    return FeatureVector(
        incident_id=incident_id,
        entries=(
            FeatureEntry(
                feature_key=FEATURE,
                value=BooleanFeatureValue(kind="boolean", value=value),
            ),
        ),
    )


def test_census_and_folds_are_exact_canonical_leave_one_group_out() -> None:
    census = _census()
    registry = derive_crossfit_folds(census)

    assert tuple(item.incident_id for item in census.incidents) == tuple(
        f"i{index}" for index in range(8)
    )
    assert census.eligible_incident_ids_sha256 == sha256_value(
        {
            "domain": ELIGIBLE_INCIDENT_IDS_DOMAIN,
            "items": [f"i{index}" for index in range(8)],
        }
    )
    assert tuple(dict.fromkeys(fold.axis for fold in registry.folds)) == AXIS_ORDER
    expected_groups = {
        "hardware_family": ("family-a", "family-b"),
        "hardware_identity": (
            "hardware-0",
            "hardware-1",
            "hardware-2",
            "hardware-3",
        ),
        "fault_family": ("fault-0", "fault-1"),
    }
    all_ids = {f"i{index}" for index in range(8)}
    for axis in AXIS_ORDER:
        axis_folds = tuple(fold for fold in registry.folds if fold.axis == axis)
        assert tuple(fold.holdout_group for fold in axis_folds) == expected_groups[axis]
        assert set().union(*(set(fold.holdout_incident_ids) for fold in axis_folds)) == all_ids
        for fold in axis_folds:
            expected_holdout = {
                item.incident_id
                for item in census.incidents
                if item.group_for(axis) == fold.holdout_group
            }
            assert set(fold.holdout_incident_ids) == expected_holdout
            assert set(fold.train_incident_ids) == all_ids - expected_holdout
    assert registry.crossfit_fold_root_sha256 == sha256_value(
        {
            "domain": CROSSFIT_FOLD_ROOT_DOMAIN,
            "items": [
                {
                    "axis": fold.axis,
                    "holdout_group": fold.holdout_group,
                    "train_incident_ids_sha256": fold.train_incident_ids_sha256,
                    "holdout_incident_ids_sha256": fold.holdout_incident_ids_sha256,
                }
                for fold in registry.folds
            ],
        }
    )
    validate_crossfit_folds(registry, census)


def test_census_rejects_empty_duplicate_noncanonical_non_utf8_and_bad_root() -> None:
    with pytest.raises(ShortcutCrossfitError, match="cannot be empty"):
        build_crossfit_census(())
    with pytest.raises(ShortcutCrossfitError, match="duplicate"):
        build_crossfit_census((_incidents()[0], _incidents()[0]))
    with pytest.raises(ValidationError, match="cannot be empty"):
        EligibleIncident(
            incident_id="bad",
            hardware_family="",
            hardware_identity="h",
            fault_family="f",
        )
    with pytest.raises(ValidationError, match="valid UTF-8"):
        EligibleIncident(
            incident_id="bad",
            hardware_family="\ud800",
            hardware_identity="h",
            fault_family="f",
        )

    census = _census()
    payload = census.model_dump(mode="python")
    payload["incidents"] = tuple(reversed(payload["incidents"]))
    with pytest.raises(ValidationError, match="canonical UTF-8"):
        CrossfitCensus.model_validate(payload)
    payload = census.model_dump(mode="python")
    payload["incidents"] = (
        payload["incidents"][0],
        *payload["incidents"],
    )
    with pytest.raises(ValidationError, match="duplicate"):
        CrossfitCensus.model_validate(payload)
    payload = census.model_dump(mode="python")
    payload["eligible_incident_ids_sha256"] = ARTIFACT
    with pytest.raises(ValidationError, match="root"):
        CrossfitCensus.model_validate(payload)


def test_fold_derivation_fails_when_any_axis_has_no_train_complement() -> None:
    incidents = tuple(
        EligibleIncident(
            incident_id=f"single-{index}",
            hardware_family="one-family",
            hardware_identity=f"hardware-{index}",
            fault_family=f"fault-{index}",
        )
        for index in range(2)
    )
    with pytest.raises(ShortcutCrossfitError, match="at least two groups"):
        derive_crossfit_folds(build_crossfit_census(incidents))


def test_fold_and_registry_reject_all_partition_defects() -> None:
    registry = _registry()
    fold = registry.folds[0]
    payload = fold.model_dump(mode="python")
    payload["holdout_group"] = ""
    with pytest.raises(ValidationError, match="cannot be empty"):
        CrossfitFold.model_validate(payload)
    payload = fold.model_dump(mode="python")
    payload["holdout_group"] = "\udfff"
    with pytest.raises(ValidationError, match="valid UTF-8"):
        CrossfitFold.model_validate(payload)
    payload = fold.model_dump(mode="python")
    payload["train_incident_ids"] = tuple(reversed(payload["train_incident_ids"]))
    with pytest.raises(ValidationError, match="canonical UTF-8"):
        CrossfitFold.model_validate(payload)
    payload = fold.model_dump(mode="python")
    payload["train_incident_ids"] = (
        payload["train_incident_ids"][0],
        *payload["train_incident_ids"],
    )
    with pytest.raises(ValidationError, match="duplicate"):
        CrossfitFold.model_validate(payload)
    payload = fold.model_dump(mode="python")
    payload["train_incident_ids"] = (
        *payload["train_incident_ids"],
        payload["holdout_incident_ids"][0],
    )
    payload["train_incident_ids"] = tuple(sorted(payload["train_incident_ids"]))
    payload["train_incident_ids_sha256"] = sha256_value(list(payload["train_incident_ids"]))
    with pytest.raises(ValidationError, match="overlap"):
        CrossfitFold.model_validate(payload)
    for root_field, message in (
        ("train_incident_ids_sha256", "train incident root"),
        ("holdout_incident_ids_sha256", "holdout incident root"),
    ):
        payload = fold.model_dump(mode="python")
        payload[root_field] = ARTIFACT
        with pytest.raises(ValidationError, match=message):
            CrossfitFold.model_validate(payload)

    payload = registry.model_dump(mode="python")
    payload["folds"] = payload["folds"][1:]
    payload["crossfit_fold_root_sha256"] = crossfit_fold_root_sha256(
        tuple(CrossfitFold.model_validate(item) for item in payload["folds"])
    )
    with pytest.raises(ValidationError, match="exact canonical"):
        CrossfitFoldRegistry.model_validate(payload)
    payload = registry.model_dump(mode="python")
    payload["crossfit_fold_root_sha256"] = ARTIFACT
    with pytest.raises(ValidationError, match="root"):
        CrossfitFoldRegistry.model_validate(payload)
    with pytest.raises(ShortcutCrossfitError, match="empty"):
        crossfit_fold_root_sha256(())
    with pytest.raises(ShortcutCrossfitError, match="canonical"):
        crossfit_fold_root_sha256(tuple(reversed(registry.folds)))
    with pytest.raises(ShortcutCrossfitError, match="duplicate"):
        crossfit_fold_root_sha256((registry.folds[0], registry.folds[0]))


def test_registry_validation_recomputes_against_the_supplied_census() -> None:
    registry = _registry()
    changed = list(_incidents())
    changed[0] = changed[0].model_copy(update={"hardware_identity": "hardware-z"})
    changed_census = build_crossfit_census(changed)
    with pytest.raises(ShortcutCrossfitError, match="differs"):
        validate_crossfit_folds(registry, changed_census)


def test_selector_encoding_is_typed_canonical_finite_and_utf8() -> None:
    assert selector_value({"b": [True, None], "a": 1}).canonical_json_text == (
        '{"a":1,"b":[true,null]}'
    )
    with pytest.raises(ValidationError, match="not canonical"):
        SelectorValue(canonical_json_text='{ "a": 1 }')
    with pytest.raises(ValidationError, match="finite canonical"):
        SelectorValue(canonical_json_text="NaN")
    with pytest.raises(ValidationError, match="finite canonical"):
        SelectorValue(canonical_json_text="not-json")
    with pytest.raises(ValidationError, match="valid UTF-8"):
        SelectorValue(canonical_json_text='"\\ud800"')
    with pytest.raises(ShortcutCrossfitError, match="cannot be canonicalized"):
        selector_value(float("inf"))
    with pytest.raises(ShortcutCrossfitError, match="cannot be canonicalized"):
        selector_value({"bad": "\ud800"})
    with pytest.raises(ShortcutCrossfitError, match="cannot be canonicalized"):
        selector_value(cast(JsonValue, {1: "bad-key"}))
    with pytest.raises(ShortcutCrossfitError, match="cannot be canonicalized"):
        selector_value(cast(JsonValue, ("not", "a", "json-array")))


def test_categorical_mode_fit_predicts_success_and_all_abstentions() -> None:
    fold = _fold(_registry())
    job = _job(fold)
    examples = _categorical_examples(fold)
    state = fit_categorical_train_mode(job, fold, tuple(reversed(examples)))

    assert state.train_incident_ids == fold.train_incident_ids
    assert tuple(mode.selector.canonical_json_text for mode in state.modes) == ('"x"', '"y"')
    assert state.modes[0].prediction_key == KEY_ZERO
    assert state.modes[0].abstention_reason is None
    assert state.modes[1].prediction_key is None
    assert state.modes[1].abstention_reason == "class_tie"
    validate_categorical_fitted_state(state, job, fold, examples)

    holdout_inputs = tuple(
        CategoricalHoldoutInput(incident_id=incident_id, selector=_selector(selector))
        for incident_id, selector in zip(
            fold.holdout_incident_ids,
            ("x", "x", "y", "z"),
            strict=True,
        )
    )
    local_maps = (
        _local_map(fold.holdout_incident_ids[0], (KEY_ZERO, "hypothesis-zero")),
        _local_map(fold.holdout_incident_ids[1]),
        _local_map(fold.holdout_incident_ids[2], (KEY_ZERO, "hypothesis-zero")),
        _local_map(fold.holdout_incident_ids[3], (KEY_ZERO, "hypothesis-zero")),
    )
    manifest = predict_categorical_holdout(
        state,
        fold,
        tuple(reversed(holdout_inputs)),
        tuple(reversed(local_maps)),
        fitted_state_artifact_bytes=canonical_artifact_bytes(state),
    )

    assert manifest.holdout_incident_ids == fold.holdout_incident_ids
    assert manifest.fitted_state_artifact_sha256 == canonical_artifact_sha256(
        state,
        canonical_artifact_bytes(state),
    )
    assert tuple(item.abstention_reason for item in manifest.predictions) == (
        None,
        "key_unavailable",
        "class_tie",
        "unseen_selector",
    )
    assert manifest.predictions[0].selected_hypothesis_id == "hypothesis-zero"
    assert manifest.predictions[1].proposed_prediction_key == KEY_ZERO
    with pytest.raises(ValidationError, match="frozen"):
        manifest.predictions[0].incident_id = "mutated"  # type: ignore[misc]


def test_categorical_fit_rejects_job_and_train_membership_defects() -> None:
    registry = _registry()
    fold = _fold(registry)
    examples = _categorical_examples(fold)
    other_fold = _fold(registry, group="family-b")
    with pytest.raises(ShortcutCrossfitError, match="does not match"):
        fit_categorical_train_mode(_job(other_fold), fold, examples)
    with pytest.raises(ShortcutCrossfitError, match="train_prediction"):
        fit_categorical_train_mode(_job(fold, stage="holdout_evaluation"), fold, examples)
    with pytest.raises(ShortcutCrossfitError, match="diagnostic"):
        fit_categorical_train_mode(_job(fold, rule_id=TREE_RULE), fold, examples)
    with pytest.raises(ShortcutCrossfitError, match="duplicate"):
        fit_categorical_train_mode(_job(fold), fold, (*examples[:-1], examples[0]))
    with pytest.raises(ShortcutCrossfitError, match="exactly"):
        fit_categorical_train_mode(_job(fold), fold, examples[:-1])
    leaked_holdout = examples[0].model_copy(update={"incident_id": fold.holdout_incident_ids[0]})
    with pytest.raises(ShortcutCrossfitError, match="exactly"):
        fit_categorical_train_mode(_job(fold), fold, (leaked_holdout, *examples[1:]))
    wrong_record_kind = tuple(
        CategoricalHoldoutInput(incident_id=item, selector=_selector("x"))
        for item in fold.train_incident_ids
    )
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        fit_categorical_train_mode(
            _job(fold),
            fold,
            cast(tuple[CategoricalTrainingExample, ...], wrong_record_kind),
        )


def test_categorical_state_and_manifest_models_reject_tampering() -> None:
    fold = _fold(_registry())
    job = _job(fold)
    examples = _categorical_examples(fold)
    state = fit_categorical_train_mode(job, fold, examples)

    with pytest.raises(ValidationError, match="unique train mode"):
        CategoricalMode(
            selector=_selector("x"),
            class_counts=state.modes[0].class_counts,
            prediction_key=KEY_ONE,
            abstention_reason=None,
        )
    with pytest.raises(ValidationError, match="canonically ordered"):
        CategoricalMode(
            selector=_selector("x"),
            class_counts=tuple(reversed(state.modes[1].class_counts)),
            prediction_key=None,
            abstention_reason="class_tie",
        )
    duplicate_counts = (state.modes[0].class_counts[0],) * 2
    with pytest.raises(ValidationError, match="duplicate keys"):
        CategoricalMode(
            selector=_selector("x"),
            class_counts=duplicate_counts,
            prediction_key=KEY_ZERO,
            abstention_reason=None,
        )

    for field, value, message in (
        ("job", _job(fold, stage="holdout_evaluation"), "train_prediction"),
        ("job", _job(fold, rule_id=TREE_RULE), "diagnostic"),
        ("train_incident_ids", tuple(reversed(state.train_incident_ids)), "canonical"),
        ("train_incident_ids_sha256", ARTIFACT, "root"),
        ("modes", tuple(reversed(state.modes)), "selector order"),
        ("modes", (state.modes[0], state.modes[0]), "duplicate selectors"),
    ):
        payload = state.model_dump(mode="python")
        payload[field] = value
        with pytest.raises(ValidationError, match=message):
            CategoricalFittedState.model_validate(payload)
    duplicate_train = state.model_dump(mode="python")
    duplicate_train["train_incident_ids"] = (
        state.train_incident_ids[0],
        *state.train_incident_ids,
    )
    with pytest.raises(ValidationError, match="duplicate"):
        CategoricalFittedState.model_validate(duplicate_train)

    changed = state.model_copy(update={"modes": (state.modes[0],)})
    with pytest.raises(ShortcutCrossfitError, match="differs"):
        validate_categorical_fitted_state(changed, job, fold, examples)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {
                "incident_id": "i0",
                "proposed_prediction_key": None,
                "selected_prediction_key": KEY_ZERO,
                "selected_hypothesis_id": None,
                "abstention_reason": "class_tie",
            },
            "selection",
        ),
        (
            {
                "incident_id": "i0",
                "proposed_prediction_key": KEY_ZERO,
                "selected_prediction_key": KEY_ZERO,
                "selected_hypothesis_id": "h0",
                "abstention_reason": "key_unavailable",
            },
            "selection",
        ),
        (
            {
                "incident_id": "i0",
                "proposed_prediction_key": KEY_ZERO,
                "selected_prediction_key": None,
                "selected_hypothesis_id": None,
                "abstention_reason": None,
            },
            "selection",
        ),
    ],
)
def test_categorical_prediction_state_is_fail_closed(
    payload: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        CategoricalPrediction.model_validate(payload)


def test_prediction_rejects_state_holdout_and_local_map_defects() -> None:
    registry = _registry()
    fold = _fold(registry)
    state = fit_categorical_train_mode(_job(fold), fold, _categorical_examples(fold))
    inputs = tuple(
        CategoricalHoldoutInput(incident_id=item, selector=_selector("x"))
        for item in fold.holdout_incident_ids
    )
    maps = tuple(_local_map(item) for item in fold.holdout_incident_ids)
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        predict_categorical_holdout(
            state.model_copy(update={"train_incident_ids": ("wrong",)}),
            fold,
            inputs,
            maps,
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )
    with pytest.raises(ShortcutCrossfitError, match="duplicate"):
        predict_categorical_holdout(
            state,
            fold,
            (*inputs[:-1], inputs[0]),
            maps,
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )
    with pytest.raises(ShortcutCrossfitError, match="exactly"):
        predict_categorical_holdout(
            state,
            fold,
            inputs[:-1],
            maps,
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )
    with pytest.raises(ShortcutCrossfitError, match="duplicate"):
        predict_categorical_holdout(
            state,
            fold,
            inputs,
            (*maps[:-1], maps[0]),
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )
    with pytest.raises(ShortcutCrossfitError, match="exactly"):
        predict_categorical_holdout(
            state,
            fold,
            inputs,
            maps[:-1],
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )
    wrong_record_kind = tuple(
        CategoricalTrainingExample(
            incident_id=item,
            selector=_selector("x"),
            target_prediction_key=KEY_ZERO,
        )
        for item in fold.holdout_incident_ids
    )
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        predict_categorical_holdout(
            state,
            fold,
            cast(tuple[CategoricalHoldoutInput, ...], wrong_record_kind),
            maps,
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )


def test_local_maps_are_canonical_unique_and_one_to_one() -> None:
    with pytest.raises(ValidationError, match="canonically ordered"):
        _local_map("i0", (KEY_ONE, "h1"), (KEY_ZERO, "h0"))
    with pytest.raises(ValidationError, match="duplicate prediction"):
        _local_map("i0", (KEY_ZERO, "h0"), (KEY_ZERO, "h1"))
    with pytest.raises(ValidationError, match="not one-to-one"):
        _local_map("i0", (KEY_ZERO, "same"), (KEY_ONE, "same"))


def test_manifest_models_reject_missing_duplicate_order_root_stage_and_rule() -> None:
    fold = _fold(_registry())
    state = fit_categorical_train_mode(_job(fold), fold, _categorical_examples(fold))
    inputs = tuple(
        CategoricalHoldoutInput(incident_id=item, selector=_selector("x"))
        for item in fold.holdout_incident_ids
    )
    manifest = predict_categorical_holdout(
        state,
        fold,
        inputs,
        tuple(_local_map(item) for item in fold.holdout_incident_ids),
        fitted_state_artifact_bytes=canonical_artifact_bytes(state),
    )
    mutations = (
        ("job", _job(fold, stage="holdout_evaluation"), "train_prediction"),
        ("job", _job(fold, rule_id=TREE_RULE), "diagnostic"),
        (
            "holdout_incident_ids",
            tuple(reversed(manifest.holdout_incident_ids)),
            "canonically ordered",
        ),
        (
            "holdout_incident_ids_sha256",
            ARTIFACT,
            "root",
        ),
        (
            "predictions",
            manifest.predictions[:-1],
            "exactly one prediction",
        ),
    )
    for field, value, message in mutations:
        payload = manifest.model_dump(mode="python")
        payload[field] = value
        with pytest.raises(ValidationError, match=message):
            CategoricalPredictionManifest.model_validate(payload)
    payload = manifest.model_dump(mode="python")
    payload["holdout_incident_ids"] = (
        manifest.holdout_incident_ids[0],
        *manifest.holdout_incident_ids,
    )
    with pytest.raises(ValidationError, match="duplicate"):
        CategoricalPredictionManifest.model_validate(payload)

    with pytest.raises(ShortcutCrossfitError, match="artifact bytes differ"):
        predict_categorical_holdout(
            state,
            fold,
            inputs,
            tuple(_local_map(item) for item in fold.holdout_incident_ids),
            fitted_state_artifact_bytes=b" " + canonical_artifact_bytes(state),
        )
    with pytest.raises(ShortcutCrossfitError, match="immutable byte string"):
        canonical_artifact_sha256(
            state,
            cast(bytes, bytearray(canonical_artifact_bytes(state))),
        )


def test_complete_rule_manifest_set_proves_one_prediction_per_incident_per_axis() -> None:
    registry = _registry()
    manifests: list[CategoricalPredictionManifest] = []
    for fold in registry.folds:
        job = _job(fold)
        examples = tuple(
            CategoricalTrainingExample(
                incident_id=incident_id,
                selector=_selector("x"),
                target_prediction_key=KEY_ZERO,
            )
            for incident_id in fold.train_incident_ids
        )
        state = fit_categorical_train_mode(job, fold, examples)
        inputs = tuple(
            CategoricalHoldoutInput(incident_id=incident_id, selector=_selector("x"))
            for incident_id in fold.holdout_incident_ids
        )
        maps = tuple(_local_map(incident_id) for incident_id in fold.holdout_incident_ids)
        manifests.append(
            predict_categorical_holdout(
                state,
                fold,
                inputs,
                maps,
                fitted_state_artifact_bytes=canonical_artifact_bytes(state),
            )
        )

    validate_complete_rule_prediction_manifests(
        registry,
        "source-identity",
        manifests,
    )
    for axis in AXIS_ORDER:
        predicted_ids = tuple(
            prediction.incident_id
            for manifest in manifests
            if manifest.job.axis == axis
            for prediction in manifest.predictions
        )
        assert sorted(predicted_ids) == [f"i{index}" for index in range(8)]
    with pytest.raises(ShortcutCrossfitError, match="exactly cover"):
        validate_complete_rule_prediction_manifests(
            registry,
            "source-identity",
            manifests[:-1],
        )
    with pytest.raises(ShortcutCrossfitError, match="exactly cover"):
        validate_complete_rule_prediction_manifests(
            registry,
            "source-identity",
            tuple(reversed(manifests)),
        )
    tampered = list(manifests)
    tampered[0] = tampered[0].model_copy(update={"holdout_incident_ids": ("wrong",)})
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        validate_complete_rule_prediction_manifests(
            registry,
            "source-identity",
            tampered,
        )
    empty_prediction_manifest = manifests[0].model_copy(update={"predictions": ()})
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        validate_complete_rule_prediction_manifests(
            registry,
            "source-identity",
            (empty_prediction_manifest, *manifests[1:]),
        )
    foreign_membership = manifests[0].model_copy(
        update={
            "holdout_incident_ids": manifests[1].holdout_incident_ids,
            "holdout_incident_ids_sha256": manifests[1].holdout_incident_ids_sha256,
            "predictions": manifests[1].predictions,
        }
    )
    with pytest.raises(ShortcutCrossfitError, match="membership differs"):
        validate_complete_rule_prediction_manifests(
            registry,
            "source-identity",
            (foreign_membership, *manifests[1:]),
        )


def test_tree_orchestration_uses_exact_train_targets_then_target_free_holdout() -> None:
    fold = _fold(_registry())
    job = _job(fold, rule_id=TREE_RULE)
    train_rows = tuple(
        _row(incident_id, index >= 2) for index, incident_id in enumerate(fold.train_incident_ids)
    )
    targets = {
        incident_id: KEY_ZERO if index < 2 else KEY_ONE
        for index, incident_id in enumerate(fold.train_incident_ids)
    }
    state = fit_tree_train_fold(job, fold, tuple(reversed(train_rows)), targets)
    assert state.tree.train_incident_ids == fold.train_incident_ids

    holdout_rows = tuple(
        _row(incident_id, index >= 2) for index, incident_id in enumerate(fold.holdout_incident_ids)
    )
    maps = tuple(
        _local_map(
            incident_id,
            (KEY_ZERO if index < 2 else KEY_ONE, f"hypothesis-{index}"),
        )
        for index, incident_id in enumerate(fold.holdout_incident_ids)
    )
    manifest = predict_tree_holdout(
        state,
        fold,
        tuple(reversed(holdout_rows)),
        tuple(reversed(maps)),
        fitted_state_artifact_bytes=canonical_artifact_bytes(state),
    )
    assert isinstance(manifest, TreePredictionManifest)
    assert tuple(item.incident_id for item in manifest.predictions) == fold.holdout_incident_ids
    assert all(item.abstention_reason is None for item in manifest.predictions)
    assert manifest.fitted_state_artifact_sha256 == canonical_artifact_sha256(
        state,
        canonical_artifact_bytes(state),
    )
    assert "targets" not in inspect.signature(predict_tree_holdout).parameters
    assert "targets" not in inspect.signature(predict_categorical_holdout).parameters


def test_tree_fit_and_prediction_reject_cross_fold_access_and_wrong_jobs() -> None:
    registry = _registry()
    fold = _fold(registry)
    rows = tuple(_row(item, False) for item in fold.train_incident_ids)
    targets = dict.fromkeys(fold.train_incident_ids, KEY_ZERO)
    with pytest.raises(ShortcutCrossfitError, match="reserved"):
        fit_tree_train_fold(_job(fold), fold, rows, targets)
    with pytest.raises(ShortcutCrossfitError, match="train_prediction"):
        fit_tree_train_fold(
            _job(fold, rule_id=TREE_RULE, stage="holdout_evaluation"),
            fold,
            rows,
            targets,
        )
    with pytest.raises(ShortcutCrossfitError, match="duplicate"):
        fit_tree_train_fold(_job(fold, rule_id=TREE_RULE), fold, (*rows[:-1], rows[0]), targets)
    with pytest.raises(ShortcutCrossfitError, match="exactly"):
        fit_tree_train_fold(_job(fold, rule_id=TREE_RULE), fold, rows[:-1], targets)
    leaked_targets = dict(targets)
    leaked_targets[fold.holdout_incident_ids[0]] = KEY_ZERO
    with pytest.raises(ShortcutCrossfitError, match="exactly"):
        fit_tree_train_fold(_job(fold, rule_id=TREE_RULE), fold, rows, leaked_targets)
    wrong_train_kind = tuple(
        CategoricalHoldoutInput(incident_id=item, selector=_selector("x"))
        for item in fold.train_incident_ids
    )
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        fit_tree_train_fold(
            _job(fold, rule_id=TREE_RULE),
            fold,
            cast(tuple[FeatureVector, ...], wrong_train_kind),
            targets,
        )

    state = fit_tree_train_fold(_job(fold, rule_id=TREE_RULE), fold, rows, targets)
    holdout_rows = tuple(_row(item, False) for item in fold.holdout_incident_ids)
    maps = tuple(_local_map(item) for item in fold.holdout_incident_ids)
    other_fold = _fold(registry, group="family-b")
    with pytest.raises(ShortcutCrossfitError, match="does not match"):
        predict_tree_holdout(
            state,
            other_fold,
            holdout_rows,
            maps,
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )
    altered_tree = state.tree.model_copy(update={"train_incident_ids": ("wrong",)})
    altered_state = state.model_copy(update={"tree": altered_tree})
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        predict_tree_holdout(
            altered_state,
            fold,
            holdout_rows,
            maps,
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )
    with pytest.raises(ShortcutCrossfitError, match="duplicate"):
        predict_tree_holdout(
            state,
            fold,
            (*holdout_rows[:-1], holdout_rows[0]),
            maps,
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )
    with pytest.raises(ShortcutCrossfitError, match="exactly"):
        predict_tree_holdout(
            state,
            fold,
            holdout_rows[:-1],
            maps,
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )
    wrong_holdout_kind = tuple(
        CategoricalHoldoutInput(incident_id=item, selector=_selector("x"))
        for item in fold.holdout_incident_ids
    )
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        predict_tree_holdout(
            state,
            fold,
            cast(tuple[FeatureVector, ...], wrong_holdout_kind),
            maps,
            fitted_state_artifact_bytes=canonical_artifact_bytes(state),
        )


def test_tree_state_and_manifest_models_bind_rule_stage_and_exact_predictions() -> None:
    fold = _fold(_registry())
    rows = tuple(_row(item, False) for item in fold.train_incident_ids)
    targets = dict.fromkeys(fold.train_incident_ids, KEY_ZERO)
    state = fit_tree_train_fold(_job(fold, rule_id=TREE_RULE), fold, rows, targets)
    for job, message in (
        (_job(fold), "sole-kill"),
        (_job(fold, rule_id=TREE_RULE, stage="holdout_evaluation"), "train_prediction"),
    ):
        payload = state.model_dump(mode="python")
        payload["job"] = job
        with pytest.raises(ValidationError, match=message):
            TreeFittedState.model_validate(payload)

    holdout_rows = tuple(_row(item, False) for item in fold.holdout_incident_ids)
    maps = tuple(
        _local_map(item, (KEY_ZERO, f"hypothesis-{index}"))
        for index, item in enumerate(fold.holdout_incident_ids)
    )
    manifest = predict_tree_holdout(
        state,
        fold,
        holdout_rows,
        maps,
        fitted_state_artifact_bytes=canonical_artifact_bytes(state),
    )
    for job, message in (
        (_job(fold), "sole-kill"),
        (_job(fold, rule_id=TREE_RULE, stage="holdout_evaluation"), "train_prediction"),
    ):
        payload = manifest.model_dump(mode="python")
        payload["job"] = job
        with pytest.raises(ValidationError, match=message):
            TreePredictionManifest.model_validate(payload)
    payload = manifest.model_dump(mode="python")
    payload["predictions"] = payload["predictions"][:-1]
    with pytest.raises(ValidationError, match="exactly one prediction"):
        TreePredictionManifest.model_validate(payload)


def test_complete_fitted_and_prediction_roots_use_frozen_domains_and_order() -> None:
    registry = _registry()
    fitted_items = tuple(
        FittedStateRootItem(
            rule_id=rule_id,
            axis=fold.axis,
            holdout_group=fold.holdout_group,
            fitted_state_artifact_sha256=ARTIFACT,
        )
        for rule_id in RULE_ORDER
        for fold in registry.folds
    )
    prediction_items = tuple(
        PredictionRootItem(
            rule_id=rule_id,
            axis=fold.axis,
            holdout_group=fold.holdout_group,
            prediction_manifest_artifact_sha256=ARTIFACT,
        )
        for rule_id in RULE_ORDER
        for fold in registry.folds
    )
    assert fitted_state_root_sha256(registry, fitted_items) == sha256_value(
        {
            "domain": FITTED_STATE_ROOT_DOMAIN,
            "items": [item.model_dump(mode="json") for item in fitted_items],
        }
    )
    assert prediction_root_sha256(registry, prediction_items) == sha256_value(
        {
            "domain": PREDICTION_ROOT_DOMAIN,
            "items": [item.model_dump(mode="json") for item in prediction_items],
        }
    )
    for incomplete in (fitted_items[:-1], tuple(reversed(fitted_items))):
        with pytest.raises(ShortcutCrossfitError, match="exactly follow"):
            fitted_state_root_sha256(registry, incomplete)
    for incomplete in (prediction_items[:-1], tuple(reversed(prediction_items))):
        with pytest.raises(ShortcutCrossfitError, match="exactly follow"):
            prediction_root_sha256(registry, incomplete)

    copied_registry = registry.model_copy(update={"folds": ()})
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        fitted_state_root_sha256(copied_registry, fitted_items)
    with pytest.raises(ShortcutCrossfitError, match="strict revalidation"):
        prediction_root_sha256(copied_registry, prediction_items)


def test_root_items_and_jobs_reject_empty_non_utf8_unknown_and_extra_fields() -> None:
    fold = _fold(_registry())
    for model, hash_field in (
        (FittedStateRootItem, "fitted_state_artifact_sha256"),
        (PredictionRootItem, "prediction_manifest_artifact_sha256"),
    ):
        base = {
            "rule_id": RULE_ORDER[0],
            "axis": fold.axis,
            "holdout_group": "",
            hash_field: ARTIFACT,
        }
        with pytest.raises(ValidationError, match="cannot be empty"):
            model.model_validate(base)
        base["holdout_group"] = "\ud800"
        with pytest.raises(ValidationError, match="valid UTF-8"):
            model.model_validate(base)
    with pytest.raises(ValidationError):
        CrossfitJobIdentity.model_validate(
            {
                "rule_id": "invented-rule",
                "axis": fold.axis,
                "holdout_group": fold.holdout_group,
                "recipient_stage": "train_prediction",
            }
        )
    payload = _job(fold).model_dump(mode="python")
    payload["extra"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        CrossfitJobIdentity.model_validate(payload)
    with pytest.raises(ValidationError, match="cannot be empty"):
        CrossfitJobIdentity(
            rule_id=RULE_ORDER[0],
            axis="hardware_family",
            holdout_group="",
            recipient_stage="train_prediction",
        )


def test_registry_and_rule_constants_are_exactly_frozen() -> None:
    assert AXIS_ORDER == ("hardware_family", "hardware_identity", "fault_family")
    assert RULE_ORDER[:-1] == CATEGORICAL_RULES
    assert RULE_ORDER[-1] == TREE_RULE
    assert len(RULE_ORDER) == 10
    assert canonical_json(_registry().model_dump(mode="json")) == canonical_json(
        _registry().model_dump(mode="json")
    )
    assert cast(str, inspect.getdoc(predict_categorical_holdout)).endswith(
        "without accepting held-out targets."
    )
