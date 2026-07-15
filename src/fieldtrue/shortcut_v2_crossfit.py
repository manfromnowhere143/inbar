"""Pure cross-fitting boundary for Shortcut Authority V2.

This module derives exact leave-one-group-out folds, fits the frozen diagnostic
categorical mode and sole-kill depth-two tree predictors, and freezes held-out
prediction manifests. Process and key destruction, target release, evaluation
truth, scientific verdicts, execution authority, and publication authority are
deliberately out of scope.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping, Sequence
from typing import Annotated, Final, Literal, TypeAlias, TypeVar

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictStr,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)

from fieldtrue.canonical import canonical_json, sha256_bytes, sha256_value
from fieldtrue.domain import Identifier, Sha256
from fieldtrue.shortcut_v2_hashing import incident_id_list_sha256
from fieldtrue.shortcut_v2_tree import (
    ClassCount,
    DepthTwoExactGiniTree,
    FeatureVector,
    PredictionKey,
    TreePrediction,
    fit_depth_two_exact_gini,
    predict_depth_two_tree,
)

Axis: TypeAlias = Literal["hardware_family", "hardware_identity", "fault_family"]
RecipientStage: TypeAlias = Literal["train_prediction", "holdout_evaluation"]
RuleId: TypeAlias = Literal[
    "source-identity",
    "task-identity",
    "system-identity",
    "site-identity",
    "path-and-filename",
    "timestamp",
    "fault-label",
    "annotation",
    "random-identity-embedding",
    "cheapest-deterministic-evidence-only",
]

AXIS_ORDER: Final[tuple[Axis, ...]] = (
    "hardware_family",
    "hardware_identity",
    "fault_family",
)
RULE_ORDER: Final[tuple[RuleId, ...]] = (
    "source-identity",
    "task-identity",
    "system-identity",
    "site-identity",
    "path-and-filename",
    "timestamp",
    "fault-label",
    "annotation",
    "random-identity-embedding",
    "cheapest-deterministic-evidence-only",
)
CATEGORICAL_RULES: Final[tuple[RuleId, ...]] = RULE_ORDER[:-1]
TREE_RULE: Final[RuleId] = "cheapest-deterministic-evidence-only"

ELIGIBLE_INCIDENT_IDS_DOMAIN: Final = "inbar.iter001.eligible-incident-ids.v1"
CROSSFIT_FOLD_ROOT_DOMAIN: Final = "inbar.iter001.shortcut-crossfit-fold-root.v1"
FITTED_STATE_ROOT_DOMAIN: Final = "inbar.iter001.shortcut-fitted-state-root.v1"
PREDICTION_ROOT_DOMAIN: Final = "inbar.iter001.shortcut-prediction-root.v1"

CanonicalSelectorJson = Annotated[str, StringConstraints(min_length=1)]


class ShortcutCrossfitError(ValueError):
    """A cross-fitting input violates the frozen amendment contract."""


class ShortcutCrossfitModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _strict_revalidate(value: _ModelT, model_type: type[_ModelT], *, label: str) -> _ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="python"), strict=True)
    except ValidationError as error:
        raise ShortcutCrossfitError(f"{label} failed strict revalidation") from error


def _utf8(value: str, *, label: str) -> str:
    if not value:
        raise ValueError(f"{label} cannot be empty")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} is not valid UTF-8") from error
    return value


def _utf8_key(value: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ShortcutCrossfitError("value is not valid UTF-8") from error


def _validate_json_utf8(value: object) -> None:
    if isinstance(value, str):
        _utf8(value, label="selector string")
    elif isinstance(value, list):
        for item in value:
            _validate_json_utf8(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("selector object keys must be strings")
            _utf8(key, label="selector object key")
            _validate_json_utf8(item)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ValueError("selector must contain only JSON-native values")


def _incident_ids_sha256(incident_ids: Sequence[str]) -> str:
    return incident_id_list_sha256(incident_ids)


def _eligible_incident_ids_sha256(incident_ids: Sequence[str]) -> str:
    return sha256_value({"domain": ELIGIBLE_INCIDENT_IDS_DOMAIN, "items": list(incident_ids)})


def canonical_artifact_bytes(value: BaseModel) -> bytes:
    """Serialize one strictly revalidated model to its only accepted artifact bytes."""

    try:
        validated = type(value).model_validate(value.model_dump(mode="python"), strict=True)
    except ValidationError as error:
        raise ShortcutCrossfitError("artifact failed strict revalidation") from error
    return canonical_json(validated.model_dump(mode="json"))


def canonical_artifact_sha256(value: BaseModel, artifact_bytes: bytes) -> str:
    """Bind and hash the exact raw bytes of one canonical model artifact."""

    if not isinstance(artifact_bytes, bytes):
        raise ShortcutCrossfitError("artifact bytes must be an immutable byte string")
    if artifact_bytes != canonical_artifact_bytes(value):
        raise ShortcutCrossfitError("artifact bytes differ from canonical fitted state bytes")
    return sha256_bytes(artifact_bytes)


class EligibleIncident(ShortcutCrossfitModel):
    incident_id: Identifier
    hardware_family: StrictStr
    hardware_identity: StrictStr
    fault_family: StrictStr

    @field_validator("hardware_family", "hardware_identity", "fault_family")
    @classmethod
    def group_is_nonempty_utf8(cls, value: str) -> str:
        return _utf8(value, label="axis group")

    def group_for(self, axis: Axis) -> str:
        return {
            "hardware_family": self.hardware_family,
            "hardware_identity": self.hardware_identity,
            "fault_family": self.fault_family,
        }[axis]


class CrossfitCensus(ShortcutCrossfitModel):
    schema_version: Literal["inbar.iter001.crossfit-census.v1"]
    incidents: tuple[EligibleIncident, ...] = Field(min_length=1)
    eligible_incident_ids_sha256: Sha256

    @model_validator(mode="after")
    def census_is_canonical_and_bound(self) -> CrossfitCensus:
        incident_ids = tuple(item.incident_id for item in self.incidents)
        if incident_ids != tuple(sorted(incident_ids, key=_utf8_key)):
            raise ValueError("census incidents must be in canonical UTF-8 order")
        if len(incident_ids) != len(set(incident_ids)):
            raise ValueError("census contains duplicate incident IDs")
        expected = _eligible_incident_ids_sha256(incident_ids)
        if self.eligible_incident_ids_sha256 != expected:
            raise ValueError("eligible incident root does not match the census")
        return self


def build_crossfit_census(incidents: Sequence[EligibleIncident]) -> CrossfitCensus:
    frozen = tuple(
        _strict_revalidate(incident, EligibleIncident, label="eligible incident")
        for incident in incidents
    )
    if not frozen:
        raise ShortcutCrossfitError("cross-fit census cannot be empty")
    incident_ids = tuple(item.incident_id for item in frozen)
    if len(incident_ids) != len(set(incident_ids)):
        raise ShortcutCrossfitError("cross-fit census contains duplicate incident IDs")
    ordered = tuple(sorted(frozen, key=lambda item: _utf8_key(item.incident_id)))
    ordered_ids = tuple(item.incident_id for item in ordered)
    return CrossfitCensus(
        schema_version="inbar.iter001.crossfit-census.v1",
        incidents=ordered,
        eligible_incident_ids_sha256=_eligible_incident_ids_sha256(ordered_ids),
    )


class CrossfitFold(ShortcutCrossfitModel):
    schema_version: Literal["inbar.iter001.crossfit-fold.v1"]
    axis: Axis
    holdout_group: StrictStr
    train_incident_ids: tuple[Identifier, ...] = Field(min_length=1)
    holdout_incident_ids: tuple[Identifier, ...] = Field(min_length=1)
    train_incident_ids_sha256: Sha256
    holdout_incident_ids_sha256: Sha256

    @field_validator("holdout_group")
    @classmethod
    def holdout_group_is_nonempty_utf8(cls, value: str) -> str:
        return _utf8(value, label="holdout group")

    @model_validator(mode="after")
    def fold_is_canonical_and_disjoint(self) -> CrossfitFold:
        for label, incident_ids in (
            ("train", self.train_incident_ids),
            ("holdout", self.holdout_incident_ids),
        ):
            if incident_ids != tuple(sorted(incident_ids, key=_utf8_key)):
                raise ValueError(f"{label} incident IDs must be in canonical UTF-8 order")
            if len(incident_ids) != len(set(incident_ids)):
                raise ValueError(f"{label} incident IDs contain duplicates")
        if set(self.train_incident_ids) & set(self.holdout_incident_ids):
            raise ValueError("train and holdout incidents overlap")
        if self.train_incident_ids_sha256 != _incident_ids_sha256(self.train_incident_ids):
            raise ValueError("train incident root does not match the fold")
        if self.holdout_incident_ids_sha256 != _incident_ids_sha256(self.holdout_incident_ids):
            raise ValueError("holdout incident root does not match the fold")
        return self


def _fold_payloads(census: CrossfitCensus) -> tuple[dict[str, object], ...]:
    all_ids = tuple(item.incident_id for item in census.incidents)
    payloads: list[dict[str, object]] = []
    for axis in AXIS_ORDER:
        groups: dict[str, list[str]] = {}
        for incident in census.incidents:
            groups.setdefault(incident.group_for(axis), []).append(incident.incident_id)
        if len(groups) < 2:
            raise ShortcutCrossfitError(
                f"axis {axis} requires at least two groups so every train complement is nonempty"
            )
        for group in sorted(groups, key=_utf8_key):
            holdout = tuple(sorted(groups[group], key=_utf8_key))
            holdout_set = set(holdout)
            train = tuple(item for item in all_ids if item not in holdout_set)
            payloads.append(
                {
                    "schema_version": "inbar.iter001.crossfit-fold.v1",
                    "axis": axis,
                    "holdout_group": group,
                    "train_incident_ids": train,
                    "holdout_incident_ids": holdout,
                    "train_incident_ids_sha256": _incident_ids_sha256(train),
                    "holdout_incident_ids_sha256": _incident_ids_sha256(holdout),
                }
            )
    return tuple(payloads)


def crossfit_fold_root_sha256(folds: Sequence[CrossfitFold]) -> str:
    frozen = tuple(_strict_revalidate(fold, CrossfitFold, label="cross-fit fold") for fold in folds)
    if not frozen:
        raise ShortcutCrossfitError("cross-fit fold root cannot cover an empty fold sequence")
    keys = tuple((fold.axis, fold.holdout_group) for fold in frozen)
    axis_index = {axis: index for index, axis in enumerate(AXIS_ORDER)}
    ordered_keys = tuple(sorted(keys, key=lambda item: (axis_index[item[0]], _utf8_key(item[1]))))
    if keys != ordered_keys:
        raise ShortcutCrossfitError("cross-fit folds are not in canonical axis and group order")
    if len(keys) != len(set(keys)):
        raise ShortcutCrossfitError("cross-fit fold root contains duplicate axis-group keys")
    items = [
        {
            "axis": fold.axis,
            "holdout_group": fold.holdout_group,
            "train_incident_ids_sha256": fold.train_incident_ids_sha256,
            "holdout_incident_ids_sha256": fold.holdout_incident_ids_sha256,
        }
        for fold in frozen
    ]
    return sha256_value({"domain": CROSSFIT_FOLD_ROOT_DOMAIN, "items": items})


class CrossfitFoldRegistry(ShortcutCrossfitModel):
    schema_version: Literal["inbar.iter001.crossfit-fold-registry.v1"]
    census: CrossfitCensus
    folds: tuple[CrossfitFold, ...] = Field(min_length=1)
    crossfit_fold_root_sha256: Sha256

    @model_validator(mode="after")
    def folds_are_exact_and_canonical(self) -> CrossfitFoldRegistry:
        expected_payloads = _fold_payloads(self.census)
        observed_payloads = tuple(fold.model_dump(mode="python") for fold in self.folds)
        expected_folds = tuple(
            CrossfitFold.model_validate(payload) for payload in expected_payloads
        )
        expected_dump = tuple(fold.model_dump(mode="python") for fold in expected_folds)
        if observed_payloads != expected_dump:
            raise ValueError("fold registry is not the exact canonical census partition")
        expected_root = crossfit_fold_root_sha256(self.folds)
        if self.crossfit_fold_root_sha256 != expected_root:
            raise ValueError("cross-fit fold root does not match the registry")
        return self


def derive_crossfit_folds(census: CrossfitCensus) -> CrossfitFoldRegistry:
    validated_census = _strict_revalidate(census, CrossfitCensus, label="cross-fit census")
    folds = tuple(
        CrossfitFold.model_validate(payload, strict=True)
        for payload in _fold_payloads(validated_census)
    )
    return CrossfitFoldRegistry(
        schema_version="inbar.iter001.crossfit-fold-registry.v1",
        census=validated_census,
        folds=folds,
        crossfit_fold_root_sha256=crossfit_fold_root_sha256(folds),
    )


def validate_crossfit_folds(
    supplied: CrossfitFoldRegistry,
    census: CrossfitCensus,
) -> None:
    validated_supplied = _strict_revalidate(
        supplied,
        CrossfitFoldRegistry,
        label="supplied cross-fit registry",
    )
    expected = derive_crossfit_folds(census)
    if canonical_json(validated_supplied.model_dump(mode="json")) != canonical_json(
        expected.model_dump(mode="json")
    ):
        raise ShortcutCrossfitError("supplied cross-fit registry differs from recomputation")


class CrossfitJobIdentity(ShortcutCrossfitModel):
    rule_id: RuleId
    axis: Axis
    holdout_group: StrictStr
    recipient_stage: RecipientStage

    @field_validator("holdout_group")
    @classmethod
    def job_group_is_nonempty_utf8(cls, value: str) -> str:
        return _utf8(value, label="job holdout group")


class SelectorValue(ShortcutCrossfitModel):
    """An immutable, exact canonical JSON encoding of one typed selector value."""

    canonical_json_text: CanonicalSelectorJson

    @field_validator("canonical_json_text")
    @classmethod
    def selector_is_canonical_json(cls, value: str) -> str:
        _utf8(value, label="selector")
        try:
            decoded = json.loads(
                value,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    ValueError(f"non-finite JSON constant {token}")
                ),
            )
        except (json.JSONDecodeError, ValueError) as error:
            raise ValueError("selector must be finite canonical JSON") from error
        _validate_json_utf8(decoded)
        if canonical_json(decoded).decode("utf-8") != value:
            raise ValueError("selector JSON is not canonical")
        return value


def selector_value(value: JsonValue) -> SelectorValue:
    try:
        _validate_json_utf8(value)
        encoded = canonical_json(value).decode("utf-8")
    except (TypeError, ValueError) as error:
        raise ShortcutCrossfitError("selector value cannot be canonicalized") from error
    return SelectorValue(canonical_json_text=encoded)


class CategoricalTrainingExample(ShortcutCrossfitModel):
    incident_id: Identifier
    selector: SelectorValue
    target_prediction_key: PredictionKey


class CategoricalHoldoutInput(ShortcutCrossfitModel):
    incident_id: Identifier
    selector: SelectorValue


class CategoricalMode(ShortcutCrossfitModel):
    selector: SelectorValue
    class_counts: tuple[ClassCount, ...] = Field(min_length=1)
    prediction_key: PredictionKey | None
    abstention_reason: Literal["class_tie"] | None

    @model_validator(mode="after")
    def output_is_the_unique_mode(self) -> CategoricalMode:
        keys = tuple(item.prediction_key for item in self.class_counts)
        if keys != tuple(sorted(keys, key=_utf8_key)):
            raise ValueError("categorical class counts must be canonically ordered")
        if len(keys) != len(set(keys)):
            raise ValueError("categorical class counts contain duplicate keys")
        maximum = max(item.count for item in self.class_counts)
        winners = tuple(item.prediction_key for item in self.class_counts if item.count == maximum)
        expected_key = winners[0] if len(winners) == 1 else None
        expected_reason = None if expected_key is not None else "class_tie"
        if self.prediction_key != expected_key or self.abstention_reason != expected_reason:
            raise ValueError("categorical output is not its unique train mode")
        return self


class CategoricalFittedState(ShortcutCrossfitModel):
    schema_version: Literal["inbar.iter001.categorical-train-mode-state.v1"]
    job: CrossfitJobIdentity
    train_incident_ids: tuple[Identifier, ...] = Field(min_length=1)
    train_incident_ids_sha256: Sha256
    modes: tuple[CategoricalMode, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def state_is_train_only_and_canonical(self) -> CategoricalFittedState:
        if self.job.recipient_stage != "train_prediction":
            raise ValueError("fitted state requires the train_prediction stage")
        if self.job.rule_id not in CATEGORICAL_RULES:
            raise ValueError("categorical fitted state requires a diagnostic rule")
        if self.train_incident_ids != tuple(sorted(self.train_incident_ids, key=_utf8_key)):
            raise ValueError("state train incidents must be canonically ordered")
        if len(self.train_incident_ids) != len(set(self.train_incident_ids)):
            raise ValueError("state train incidents contain duplicates")
        if self.train_incident_ids_sha256 != _incident_ids_sha256(self.train_incident_ids):
            raise ValueError("state train incident root is incorrect")
        selectors = tuple(item.selector.canonical_json_text for item in self.modes)
        if selectors != tuple(sorted(selectors, key=_utf8_key)):
            raise ValueError("categorical modes must be in canonical selector order")
        if len(selectors) != len(set(selectors)):
            raise ValueError("categorical state contains duplicate selectors")
        return self


class LocalHypothesisAssignment(ShortcutCrossfitModel):
    prediction_key: PredictionKey
    hypothesis_id: Identifier


class IncidentLocalHypothesisMap(ShortcutCrossfitModel):
    incident_id: Identifier
    assignments: tuple[LocalHypothesisAssignment, ...]

    @model_validator(mode="after")
    def assignments_are_canonical_and_bijective(self) -> IncidentLocalHypothesisMap:
        keys = tuple(item.prediction_key for item in self.assignments)
        if keys != tuple(sorted(keys, key=_utf8_key)):
            raise ValueError("local prediction keys must be canonically ordered")
        if len(keys) != len(set(keys)):
            raise ValueError("local hypothesis map contains duplicate prediction keys")
        hypothesis_ids = tuple(item.hypothesis_id for item in self.assignments)
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("local hypothesis map is not one-to-one")
        return self

    def as_mapping(self) -> dict[str, str]:
        return {item.prediction_key: item.hypothesis_id for item in self.assignments}


class CategoricalPrediction(ShortcutCrossfitModel):
    incident_id: Identifier
    proposed_prediction_key: PredictionKey | None
    selected_prediction_key: PredictionKey | None
    selected_hypothesis_id: Identifier | None
    abstention_reason: Literal["class_tie", "unseen_selector", "key_unavailable"] | None

    @model_validator(mode="after")
    def selection_matches_abstention(self) -> CategoricalPrediction:
        if self.abstention_reason in ("class_tie", "unseen_selector"):
            valid = (
                self.proposed_prediction_key is None
                and self.selected_prediction_key is None
                and self.selected_hypothesis_id is None
            )
        elif self.abstention_reason == "key_unavailable":
            valid = (
                self.proposed_prediction_key is not None
                and self.selected_prediction_key is None
                and self.selected_hypothesis_id is None
            )
        elif self.abstention_reason is None:
            valid = (
                self.proposed_prediction_key is not None
                and self.selected_prediction_key == self.proposed_prediction_key
                and self.selected_hypothesis_id is not None
            )
        else:  # pragma: no cover - strict Literal validation makes this unreachable.
            valid = False
        if not valid:
            raise ValueError("categorical selection does not follow its abstention state")
        return self


class CategoricalPredictionManifest(ShortcutCrossfitModel):
    schema_version: Literal["inbar.iter001.categorical-prediction-manifest.v1"]
    job: CrossfitJobIdentity
    fitted_state_artifact_sha256: Sha256
    holdout_incident_ids: tuple[Identifier, ...] = Field(min_length=1)
    holdout_incident_ids_sha256: Sha256
    predictions: tuple[CategoricalPrediction, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def manifest_is_complete_and_canonical(self) -> CategoricalPredictionManifest:
        if self.job.recipient_stage != "train_prediction":
            raise ValueError("prediction manifest must be frozen in train_prediction stage")
        if self.job.rule_id not in CATEGORICAL_RULES:
            raise ValueError("categorical manifest requires a diagnostic rule")
        _validate_manifest_incidents(
            self.holdout_incident_ids,
            self.holdout_incident_ids_sha256,
            tuple(item.incident_id for item in self.predictions),
        )
        return self


class TreeFittedState(ShortcutCrossfitModel):
    schema_version: Literal["inbar.iter001.tree-crossfit-state.v1"]
    job: CrossfitJobIdentity
    tree: DepthTwoExactGiniTree

    @model_validator(mode="after")
    def state_is_the_sole_kill_train_stage(self) -> TreeFittedState:
        if self.job.rule_id != TREE_RULE:
            raise ValueError("tree state is reserved for the sole-kill rule")
        if self.job.recipient_stage != "train_prediction":
            raise ValueError("tree state requires the train_prediction stage")
        return self


class TreePredictionManifest(ShortcutCrossfitModel):
    schema_version: Literal["inbar.iter001.tree-prediction-manifest.v1"]
    job: CrossfitJobIdentity
    fitted_state_artifact_sha256: Sha256
    holdout_incident_ids: tuple[Identifier, ...] = Field(min_length=1)
    holdout_incident_ids_sha256: Sha256
    predictions: tuple[TreePrediction, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def manifest_is_complete_and_canonical(self) -> TreePredictionManifest:
        if self.job.rule_id != TREE_RULE:
            raise ValueError("tree manifest is reserved for the sole-kill rule")
        if self.job.recipient_stage != "train_prediction":
            raise ValueError("prediction manifest must be frozen in train_prediction stage")
        _validate_manifest_incidents(
            self.holdout_incident_ids,
            self.holdout_incident_ids_sha256,
            tuple(item.incident_id for item in self.predictions),
        )
        return self


PredictionManifest: TypeAlias = CategoricalPredictionManifest | TreePredictionManifest


def validate_complete_rule_prediction_manifests(
    registry: CrossfitFoldRegistry,
    rule_id: RuleId,
    manifests: Sequence[PredictionManifest],
) -> None:
    """Require one exact immutable fold manifest for every held-out case on every axis."""

    validated_registry = _strict_revalidate(
        registry,
        CrossfitFoldRegistry,
        label="prediction fold registry",
    )
    manifest_type: type[CategoricalPredictionManifest] | type[TreePredictionManifest] = (
        TreePredictionManifest if rule_id == TREE_RULE else CategoricalPredictionManifest
    )
    frozen = tuple(
        _strict_revalidate(manifest, manifest_type, label="prediction manifest")
        for manifest in manifests
    )
    expected_keys = tuple(
        (rule_id, fold.axis, fold.holdout_group) for fold in validated_registry.folds
    )
    observed_keys = tuple(
        (manifest.job.rule_id, manifest.job.axis, manifest.job.holdout_group) for manifest in frozen
    )
    if observed_keys != expected_keys:
        raise ShortcutCrossfitError(
            "prediction manifests do not exactly cover the rule's canonical fold registry"
        )
    for manifest, fold in zip(frozen, validated_registry.folds, strict=True):
        if (
            manifest.holdout_incident_ids != fold.holdout_incident_ids
            or manifest.holdout_incident_ids_sha256 != fold.holdout_incident_ids_sha256
        ):
            raise ShortcutCrossfitError(
                "prediction manifest holdout membership differs from its frozen fold"
            )


def _validate_manifest_incidents(
    holdout_incident_ids: tuple[str, ...],
    holdout_incident_ids_sha256: str,
    prediction_incident_ids: tuple[str, ...],
) -> None:
    if holdout_incident_ids != tuple(sorted(holdout_incident_ids, key=_utf8_key)):
        raise ValueError("manifest holdout incidents must be canonically ordered")
    if len(holdout_incident_ids) != len(set(holdout_incident_ids)):
        raise ValueError("manifest holdout incidents contain duplicates")
    if holdout_incident_ids_sha256 != _incident_ids_sha256(holdout_incident_ids):
        raise ValueError("manifest holdout incident root is incorrect")
    if prediction_incident_ids != holdout_incident_ids:
        raise ValueError("manifest must contain exactly one prediction per holdout incident")


def _require_job_matches_fold(job: CrossfitJobIdentity, fold: CrossfitFold) -> None:
    if job.axis != fold.axis or job.holdout_group != fold.holdout_group:
        raise ShortcutCrossfitError("job identity does not match the fold")
    if job.recipient_stage != "train_prediction":
        raise ShortcutCrossfitError("fit and prediction require the train_prediction stage")


def _exact_incident_records(
    records: Sequence[CategoricalTrainingExample | CategoricalHoldoutInput | FeatureVector],
    expected_ids: tuple[str, ...],
    *,
    label: str,
) -> tuple[CategoricalTrainingExample | CategoricalHoldoutInput | FeatureVector, ...]:
    frozen = tuple(records)
    incident_ids = tuple(item.incident_id for item in frozen)
    if len(incident_ids) != len(set(incident_ids)):
        raise ShortcutCrossfitError(f"{label} contains duplicate incident IDs")
    if set(incident_ids) != set(expected_ids):
        raise ShortcutCrossfitError(f"{label} does not exactly match the frozen fold")
    return tuple(sorted(frozen, key=lambda item: _utf8_key(item.incident_id)))


def _exact_local_maps(
    local_maps: Sequence[IncidentLocalHypothesisMap],
    expected_ids: tuple[str, ...],
) -> dict[str, IncidentLocalHypothesisMap]:
    frozen = tuple(local_maps)
    incident_ids = tuple(item.incident_id for item in frozen)
    if len(incident_ids) != len(set(incident_ids)):
        raise ShortcutCrossfitError("local maps contain duplicate incident IDs")
    if set(incident_ids) != set(expected_ids):
        raise ShortcutCrossfitError("local maps do not exactly match the holdout fold")
    return {item.incident_id: item for item in frozen}


def fit_categorical_train_mode(
    job: CrossfitJobIdentity,
    fold: CrossfitFold,
    examples: Sequence[CategoricalTrainingExample],
) -> CategoricalFittedState:
    """Fit a diagnostic mode using exact train targets and no held-out records."""

    validated_job = _strict_revalidate(job, CrossfitJobIdentity, label="categorical fit job")
    validated_fold = _strict_revalidate(fold, CrossfitFold, label="categorical fit fold")
    validated_examples = tuple(
        _strict_revalidate(
            example,
            CategoricalTrainingExample,
            label="categorical training example",
        )
        for example in examples
    )
    _require_job_matches_fold(validated_job, validated_fold)
    if validated_job.rule_id not in CATEGORICAL_RULES:
        raise ShortcutCrossfitError("categorical fit requires a diagnostic rule")
    ordered = _exact_incident_records(
        validated_examples,
        validated_fold.train_incident_ids,
        label="training data",
    )
    counts_by_selector: dict[str, Counter[str]] = {}
    for raw_example in ordered:
        if not isinstance(raw_example, CategoricalTrainingExample):
            raise ShortcutCrossfitError("categorical fit received a non-training record")
        selector = raw_example.selector.canonical_json_text
        counts_by_selector.setdefault(selector, Counter())[raw_example.target_prediction_key] += 1
    modes: list[CategoricalMode] = []
    for selector in sorted(counts_by_selector, key=_utf8_key):
        counts = counts_by_selector[selector]
        maximum = max(counts.values())
        winners = tuple(key for key, count in counts.items() if count == maximum)
        prediction_key = winners[0] if len(winners) == 1 else None
        modes.append(
            CategoricalMode(
                selector=SelectorValue(canonical_json_text=selector),
                class_counts=tuple(
                    ClassCount(prediction_key=key, count=count)
                    for key, count in sorted(counts.items(), key=lambda item: _utf8_key(item[0]))
                ),
                prediction_key=prediction_key,
                abstention_reason=None if prediction_key is not None else "class_tie",
            )
        )
    return CategoricalFittedState(
        schema_version="inbar.iter001.categorical-train-mode-state.v1",
        job=validated_job,
        train_incident_ids=validated_fold.train_incident_ids,
        train_incident_ids_sha256=validated_fold.train_incident_ids_sha256,
        modes=tuple(modes),
    )


def validate_categorical_fitted_state(
    supplied: CategoricalFittedState,
    job: CrossfitJobIdentity,
    fold: CrossfitFold,
    examples: Sequence[CategoricalTrainingExample],
) -> None:
    validated_supplied = _strict_revalidate(
        supplied,
        CategoricalFittedState,
        label="supplied categorical state",
    )
    expected = fit_categorical_train_mode(job, fold, examples)
    if canonical_json(validated_supplied.model_dump(mode="json")) != canonical_json(
        expected.model_dump(mode="json")
    ):
        raise ShortcutCrossfitError("supplied categorical state differs from recomputation")


def predict_categorical_holdout(
    state: CategoricalFittedState,
    fold: CrossfitFold,
    inputs: Sequence[CategoricalHoldoutInput],
    local_maps: Sequence[IncidentLocalHypothesisMap],
    *,
    fitted_state_artifact_bytes: bytes,
) -> CategoricalPredictionManifest:
    """Freeze held-out predictions without accepting held-out targets."""

    validated_state = _strict_revalidate(
        state,
        CategoricalFittedState,
        label="categorical prediction state",
    )
    validated_fold = _strict_revalidate(fold, CrossfitFold, label="categorical prediction fold")
    validated_inputs = tuple(
        _strict_revalidate(item, CategoricalHoldoutInput, label="categorical holdout input")
        for item in inputs
    )
    validated_maps = tuple(
        _strict_revalidate(item, IncidentLocalHypothesisMap, label="local hypothesis map")
        for item in local_maps
    )
    _require_job_matches_fold(validated_state.job, validated_fold)
    if validated_state.train_incident_ids != validated_fold.train_incident_ids:
        raise ShortcutCrossfitError("categorical state is not bound to the exact train complement")
    ordered = _exact_incident_records(
        validated_inputs,
        validated_fold.holdout_incident_ids,
        label="holdout inputs",
    )
    maps_by_incident = _exact_local_maps(
        validated_maps,
        validated_fold.holdout_incident_ids,
    )
    mode_by_selector = {item.selector.canonical_json_text: item for item in validated_state.modes}
    predictions: list[CategoricalPrediction] = []
    for raw_input in ordered:
        if not isinstance(raw_input, CategoricalHoldoutInput):
            raise ShortcutCrossfitError("categorical prediction received a non-holdout record")
        mode = mode_by_selector.get(raw_input.selector.canonical_json_text)
        if mode is None:
            proposed = None
            selected = None
            hypothesis_id = None
            reason: Literal["class_tie", "unseen_selector", "key_unavailable"] | None = (
                "unseen_selector"
            )
        elif mode.prediction_key is None:
            proposed = None
            selected = None
            hypothesis_id = None
            reason = "class_tie"
        else:
            proposed = mode.prediction_key
            local_mapping = maps_by_incident[raw_input.incident_id].as_mapping()
            hypothesis_id = local_mapping.get(proposed)
            selected = proposed if hypothesis_id is not None else None
            reason = None if hypothesis_id is not None else "key_unavailable"
        predictions.append(
            CategoricalPrediction(
                incident_id=raw_input.incident_id,
                proposed_prediction_key=proposed,
                selected_prediction_key=selected,
                selected_hypothesis_id=hypothesis_id,
                abstention_reason=reason,
            )
        )
    return CategoricalPredictionManifest(
        schema_version="inbar.iter001.categorical-prediction-manifest.v1",
        job=validated_state.job,
        fitted_state_artifact_sha256=canonical_artifact_sha256(
            validated_state,
            fitted_state_artifact_bytes,
        ),
        holdout_incident_ids=validated_fold.holdout_incident_ids,
        holdout_incident_ids_sha256=validated_fold.holdout_incident_ids_sha256,
        predictions=tuple(predictions),
    )


def fit_tree_train_fold(
    job: CrossfitJobIdentity,
    fold: CrossfitFold,
    rows: Sequence[FeatureVector],
    train_targets: Mapping[str, str],
) -> TreeFittedState:
    """Fit the sole-kill tree with the exact train rows and exact train targets only."""

    validated_job = _strict_revalidate(job, CrossfitJobIdentity, label="tree fit job")
    validated_fold = _strict_revalidate(fold, CrossfitFold, label="tree fit fold")
    validated_rows = tuple(
        _strict_revalidate(row, FeatureVector, label="tree training row") for row in rows
    )
    _require_job_matches_fold(validated_job, validated_fold)
    if validated_job.rule_id != TREE_RULE:
        raise ShortcutCrossfitError("tree fit is reserved for the sole-kill rule")
    ordered_union = _exact_incident_records(
        validated_rows,
        validated_fold.train_incident_ids,
        label="tree rows",
    )
    ordered_rows: tuple[FeatureVector, ...] = tuple(
        row for row in ordered_union if isinstance(row, FeatureVector)
    )
    if len(ordered_rows) != len(ordered_union):
        raise ShortcutCrossfitError("tree fit received a non-feature row")
    if set(train_targets) != set(validated_fold.train_incident_ids):
        raise ShortcutCrossfitError("tree targets do not exactly match the train complement")
    tree = fit_depth_two_exact_gini(ordered_rows, train_targets)
    return TreeFittedState(
        schema_version="inbar.iter001.tree-crossfit-state.v1",
        job=validated_job,
        tree=tree,
    )


def predict_tree_holdout(
    state: TreeFittedState,
    fold: CrossfitFold,
    rows: Sequence[FeatureVector],
    local_maps: Sequence[IncidentLocalHypothesisMap],
    *,
    fitted_state_artifact_bytes: bytes,
) -> TreePredictionManifest:
    """Freeze sole-kill held-out predictions using local key maps and no targets."""

    validated_state = _strict_revalidate(state, TreeFittedState, label="tree prediction state")
    validated_fold = _strict_revalidate(fold, CrossfitFold, label="tree prediction fold")
    validated_rows = tuple(
        _strict_revalidate(row, FeatureVector, label="tree holdout row") for row in rows
    )
    validated_maps = tuple(
        _strict_revalidate(item, IncidentLocalHypothesisMap, label="local hypothesis map")
        for item in local_maps
    )
    _require_job_matches_fold(validated_state.job, validated_fold)
    if validated_state.tree.train_incident_ids != validated_fold.train_incident_ids:
        raise ShortcutCrossfitError("tree state is not bound to the exact train complement")
    ordered_union = _exact_incident_records(
        validated_rows,
        validated_fold.holdout_incident_ids,
        label="tree holdout rows",
    )
    ordered_rows: tuple[FeatureVector, ...] = tuple(
        row for row in ordered_union if isinstance(row, FeatureVector)
    )
    if len(ordered_rows) != len(ordered_union):
        raise ShortcutCrossfitError("tree prediction received a non-feature row")
    maps_by_incident = _exact_local_maps(
        validated_maps,
        validated_fold.holdout_incident_ids,
    )
    predictions = tuple(
        predict_depth_two_tree(
            validated_state.tree,
            row,
            maps_by_incident[row.incident_id].as_mapping(),
        )
        for row in ordered_rows
    )
    return TreePredictionManifest(
        schema_version="inbar.iter001.tree-prediction-manifest.v1",
        job=validated_state.job,
        fitted_state_artifact_sha256=canonical_artifact_sha256(
            validated_state,
            fitted_state_artifact_bytes,
        ),
        holdout_incident_ids=validated_fold.holdout_incident_ids,
        holdout_incident_ids_sha256=validated_fold.holdout_incident_ids_sha256,
        predictions=predictions,
    )


class FittedStateRootItem(ShortcutCrossfitModel):
    rule_id: RuleId
    axis: Axis
    holdout_group: StrictStr
    fitted_state_artifact_sha256: Sha256

    @field_validator("holdout_group")
    @classmethod
    def fitted_group_is_nonempty_utf8(cls, value: str) -> str:
        return _utf8(value, label="fitted-state holdout group")


class PredictionRootItem(ShortcutCrossfitModel):
    rule_id: RuleId
    axis: Axis
    holdout_group: StrictStr
    prediction_manifest_artifact_sha256: Sha256

    @field_validator("holdout_group")
    @classmethod
    def prediction_group_is_nonempty_utf8(cls, value: str) -> str:
        return _utf8(value, label="prediction holdout group")


def _expected_root_keys(registry: CrossfitFoldRegistry) -> tuple[tuple[str, str, str], ...]:
    return tuple(
        (rule_id, fold.axis, fold.holdout_group)
        for rule_id in RULE_ORDER
        for fold in registry.folds
    )


def fitted_state_root_sha256(
    registry: CrossfitFoldRegistry,
    items: Sequence[FittedStateRootItem],
) -> str:
    validated_registry = _strict_revalidate(
        registry,
        CrossfitFoldRegistry,
        label="fitted-state fold registry",
    )
    frozen = tuple(
        _strict_revalidate(item, FittedStateRootItem, label="fitted-state root item")
        for item in items
    )
    keys = tuple((item.rule_id, item.axis, item.holdout_group) for item in frozen)
    if keys != _expected_root_keys(validated_registry):
        raise ShortcutCrossfitError(
            "fitted-state items must exactly follow registry, axis, and holdout-group order"
        )
    return sha256_value(
        {
            "domain": FITTED_STATE_ROOT_DOMAIN,
            "items": [item.model_dump(mode="json") for item in frozen],
        }
    )


def prediction_root_sha256(
    registry: CrossfitFoldRegistry,
    items: Sequence[PredictionRootItem],
) -> str:
    validated_registry = _strict_revalidate(
        registry,
        CrossfitFoldRegistry,
        label="prediction fold registry",
    )
    frozen = tuple(
        _strict_revalidate(item, PredictionRootItem, label="prediction root item") for item in items
    )
    keys = tuple((item.rule_id, item.axis, item.holdout_group) for item in frozen)
    if keys != _expected_root_keys(validated_registry):
        raise ShortcutCrossfitError(
            "prediction items must exactly follow registry, axis, and holdout-group order"
        )
    return sha256_value(
        {
            "domain": PREDICTION_ROOT_DOMAIN,
            "items": [item.model_dump(mode="json") for item in frozen],
        }
    )
