"""Retrospective reconstruction of the susceptibility-confirmation arithmetic.

This module does not recreate a contemporaneous execution artifact. None was retained. It executes
the current source after retained tests compare its relevant AST surface with the source at the
susceptibility freeze, keeps predictions separate from noisy measurements, and derives every
aggregate from the atomic records.

The reconstruction has no authority effect. In particular, it cannot repair Amendment 006's source
binding, make an outcome-informed comparison prospective, or operationalize a falsifier that the
freeze did not define precisely enough to execute.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, model_validator

from fieldtrue.canonical import atomic_write, canonical_json_pretty
from fieldtrue.causal_laboratory import UNKNOWN_MECHANISM_KEY
from fieldtrue.domain import FrozenModel, GitObjectId, Sha256
from fieldtrue.graded_laboratory import (
    GRADED_CONFIG,
    GRADED_INITIAL_STATE,
    GRADED_ONTOLOGY,
    graded_forward_telemetry,
    mechanism_separability_permille,
)
from fieldtrue.masking import (
    COMPENSATOR_GAIN,
    RESOLVABLE_PERMILLE,
    compensator_action,
    measure_cell,
)

FROZEN_BASELINES = (30, 45, 60)
FROZEN_SEVERITIES = (15, 35, 55, 75, 95)
FROZEN_SEEDS = tuple(range(8, 23))
FROZEN_CANDIDATE_KEYS = (*sorted(GRADED_ONTOLOGY.known_keys), UNKNOWN_MECHANISM_KEY)

FREEZE_PATH = (
    "experiments/iter001_physical_causal_evidence_acquisition/ADJUDICATION_FREEZE_SUSCEPTIBILITY.md"
)
FREEZE_COMMIT = "524d5e84b90f7ef68d05ea3e52b5f4f7aaf85b57"
FREEZE_SHA256 = "57bdb965c821b20e3e76007009e0e0e700e73862deaafaae8e5ce1428f3cad38"
FREEZE_TREE = "2e21389799e9ea2a9d2e955f490b02274062c573"

REPORTED_RESULT_PATH = (
    "experiments/iter001_physical_causal_evidence_acquisition/RESULT_SUSCEPTIBILITY_CONFIRMATORY.md"
)
REPORTED_RESULT_COMMIT = "f3bac79a63989499715c54551f2e7e3d5d63ca51"
REPORTED_RESULT_SHA256 = "76c24d455d6d285567063752d787ac38b7d2c09f90b9f23a099c8e0395f7698f"

HISTORICAL_SOURCE_SHA256: dict[str, str] = {
    "pyproject.toml": "b30b947d7a36b9a4bf3d83b9df971cb34f2410d93b1c81fa5e0da601bb538f6c",
    "src/fieldtrue/canonical.py": (
        "17fab2b662edfe8082297bc634168946fd6621b0c62ff515cfbbd1d64fa2fc7d"
    ),
    "src/fieldtrue/causal_laboratory.py": (
        "366df4332e0ec7354388b4a47d9766047971b79cf140f3e5865388dc1f660f8c"
    ),
    "src/fieldtrue/domain.py": ("7648d416e3843dac5d1cf9c3c3be81b8d7cba235ec33c135d2697383a3d8474a"),
    "src/fieldtrue/graded_laboratory.py": (
        "80423ff30cf15bd3bf5bbd374aecb95eb78aaa97f401f98075bb51c4f7afe6ef"
    ),
    "src/fieldtrue/masking.py": (
        "fe305947c86802e483fea3ef25db67ad6c25e50bb5d86be2156ca5096b44c107"
    ),
    "uv.lock": "54e197b09bcfc33fb7374e7bfe7f4f61e964cbb53f330b4561e0829afef7795d",
}

RECONSTRUCTION_LIMITATIONS = (
    "No contemporaneous runner or atomic confirmatory cells were retained.",
    (
        "The replay executes current modules; retained tests require exact or AST-level "
        "equivalence with the source at the freeze commit."
    ),
    "F-S2 did not machine-define how disturbance width maps to command-window distance.",
    "The frozen 0.90 agreement threshold is below the informative set's always-negative accuracy.",
    "The reserved unknown mechanism realizes nominal dynamics at every graded severity.",
    (
        "Prediction and measurement share the same hand-authored forward geometry and "
        "separability rule."
    ),
    "Amendment 006 does not bind the first committed or current graded-laboratory source bytes.",
)


class SusceptibilityReplayError(ValueError):
    """The reconstruction is incomplete, noncanonical, or differs from recomputation."""


class ExactRate(FrozenModel):
    """An exact count ratio; no rounded float is stored as evidence."""

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=1)

    @model_validator(mode="after")
    def numerator_does_not_exceed_denominator(self) -> Self:
        if self.numerator > self.denominator:
            raise ValueError("rate numerator cannot exceed denominator")
        return self


class SusceptibilityPrediction(FrozenModel):
    """One seed-independent, noise-free susceptibility prediction."""

    baseline_command: int = Field(ge=0, le=100)
    mechanism_key: str = Field(min_length=1)
    severity: int = Field(ge=0, le=100)
    predicted_command: int = Field(ge=0, le=100)
    separability_pre_permille: int = Field(ge=0)
    separability_post_permille: int = Field(ge=0)

    @property
    def masking_event(self) -> bool:
        return (
            self.separability_pre_permille >= RESOLVABLE_PERMILLE
            and self.separability_post_permille < RESOLVABLE_PERMILLE
        )


class SusceptibilityMeasurement(FrozenModel):
    """One noisy measurement from the frozen confirmatory schedule."""

    baseline_command: int = Field(ge=0, le=100)
    mechanism_key: str = Field(min_length=1)
    severity: int = Field(ge=0, le=100)
    seed: int = Field(ge=0)
    commanded_correction: int = Field(ge=0, le=100)
    separability_pre_permille: int = Field(ge=0)
    separability_post_permille: int = Field(ge=0)

    @property
    def masking_event(self) -> bool:
        return (
            self.separability_pre_permille >= RESOLVABLE_PERMILLE
            and self.separability_post_permille < RESOLVABLE_PERMILLE
        )


class ReplayCounts(FrozenModel):
    """Counts derived for one complete replay stratum."""

    cells: int = Field(ge=1)
    agreement: ExactRate
    masking_events: int = Field(ge=0)
    exact_command: ExactRate

    @model_validator(mode="after")
    def denominators_match_cells(self) -> Self:
        if self.agreement.denominator != self.cells or self.exact_command.denominator != self.cells:
            raise ValueError("stratum rate denominators must equal its cell count")
        if self.masking_events > self.cells:
            raise ValueError("masking events cannot exceed cells")
        return self


class BaselineReplaySummary(ReplayCounts):
    """One frozen baseline, explicitly labeled informative or vacuous."""

    baseline_command: int = Field(ge=0, le=100)
    verdict: Literal["informative", "vacuous"]

    @model_validator(mode="after")
    def verdict_matches_events(self) -> Self:
        if (self.masking_events == 0) != (self.verdict == "vacuous"):
            raise ValueError("a baseline is vacuous exactly when it has zero masking events")
        return self


class MechanismReplaySummary(ReplayCounts):
    """One mechanism across every frozen baseline, severity, and seed."""

    mechanism_key: str = Field(min_length=1)


class ReplayConfusionMatrix(FrozenModel):
    """Informative-cell confusion counts."""

    true_positive: int = Field(ge=0)
    false_positive: int = Field(ge=0)
    false_negative: int = Field(ge=0)
    true_negative: int = Field(ge=0)


class ReplayDisagreement(FrozenModel):
    """One prediction/measurement disagreement retained in the summary."""

    baseline_command: int = Field(ge=0, le=100)
    mechanism_key: str = Field(min_length=1)
    severity: int = Field(ge=0, le=100)
    seed: int = Field(ge=0)
    predicted_command: int = Field(ge=0, le=100)
    measured_command: int = Field(ge=0, le=100)
    predicted_masking: bool
    measured_masking: bool


class ReplaySummary(FrozenModel):
    """Every reported quantity, recomputed from the two atomic record sets."""

    all_cells: ReplayCounts
    informative_cells: ReplayCounts
    all_negative_comparator: ExactRate
    confusion: ReplayConfusionMatrix
    sensitivity: ExactRate
    specificity: ExactRate
    balanced_accuracy: ExactRate
    per_baseline: tuple[BaselineReplaySummary, ...]
    per_mechanism: tuple[MechanismReplaySummary, ...]
    disagreements: tuple[ReplayDisagreement, ...]


class FreezeBinding(FrozenModel):
    path: str = Field(min_length=1)
    commit: GitObjectId
    tree: GitObjectId
    sha256: Sha256


class ResultBinding(FrozenModel):
    path: str = Field(min_length=1)
    commit: GitObjectId
    sha256: Sha256


class HistoricalSourceBinding(FrozenModel):
    commit: GitObjectId
    tree: GitObjectId
    source_sha256: dict[str, Sha256] = Field(min_length=1)


class LaboratoryBinding(FrozenModel):
    config_sha256: Sha256
    ontology_hash: Sha256
    candidate_keys: tuple[str, ...] = Field(min_length=2)
    mechanism_names_by_key: dict[str, str] = Field(min_length=2)
    resolvable_permille: int = Field(ge=1)
    compensator_gain: int = Field(ge=0)


class ReplaySchedule(FrozenModel):
    baselines: tuple[int, ...] = Field(min_length=1)
    severities: tuple[int, ...] = Field(min_length=1)
    seeds: tuple[int, ...] = Field(min_length=1)
    measurement_cells: int = Field(ge=1)
    prediction_cells: int = Field(ge=1)


class SusceptibilityReconstruction(FrozenModel):
    """Canonical retrospective evidence reconstructed from the frozen schedule."""

    schema_version: Literal["inbar.iter001.susceptibility-reconstruction.v1"] = (
        "inbar.iter001.susceptibility-reconstruction.v1"
    )
    status: Literal["retrospective_reconstruction"] = "retrospective_reconstruction"
    authority_effect: Literal["none"] = "none"
    historical_execution_artifact_retained: Literal[False] = False
    freeze: FreezeBinding
    reported_result: ResultBinding
    historical_source: HistoricalSourceBinding
    laboratory: LaboratoryBinding
    schedule: ReplaySchedule
    predictions: tuple[SusceptibilityPrediction, ...] = Field(min_length=1)
    measurements: tuple[SusceptibilityMeasurement, ...] = Field(min_length=1)
    summary: ReplaySummary
    limitations: tuple[str, ...] = Field(min_length=1)


def reconstruct_predictions() -> tuple[SusceptibilityPrediction, ...]:
    """Reconstruct the 75 seed-independent predictions without calling the noisy plant."""

    predictions: list[SusceptibilityPrediction] = []
    for baseline in FROZEN_BASELINES:
        baseline_action = (baseline,) * GRADED_CONFIG.steps
        for mechanism_key in FROZEN_CANDIDATE_KEYS:
            for severity in FROZEN_SEVERITIES:
                predicted_observation = graded_forward_telemetry(
                    config=GRADED_CONFIG,
                    initial_state=GRADED_INITIAL_STATE,
                    mechanism_key=mechanism_key,
                    severity=severity,
                    action=baseline_action,
                )
                predicted_action = compensator_action(
                    observed_baseline=predicted_observation,
                    config=GRADED_CONFIG,
                    initial_state=GRADED_INITIAL_STATE,
                    baseline=baseline,
                    gain=COMPENSATOR_GAIN,
                )
                predictions.append(
                    SusceptibilityPrediction(
                        baseline_command=baseline,
                        mechanism_key=mechanism_key,
                        severity=severity,
                        predicted_command=predicted_action[0],
                        separability_pre_permille=mechanism_separability_permille(
                            config=GRADED_CONFIG,
                            initial_state=GRADED_INITIAL_STATE,
                            severity=severity,
                            action=baseline_action,
                            injected_key=mechanism_key,
                            candidate_keys=FROZEN_CANDIDATE_KEYS,
                        ),
                        separability_post_permille=mechanism_separability_permille(
                            config=GRADED_CONFIG,
                            initial_state=GRADED_INITIAL_STATE,
                            severity=severity,
                            action=predicted_action,
                            injected_key=mechanism_key,
                            candidate_keys=FROZEN_CANDIDATE_KEYS,
                        ),
                    )
                )
    return tuple(predictions)


def reconstruct_measurements() -> tuple[SusceptibilityMeasurement, ...]:
    """Reconstruct all 1,125 noisy measurement cells from the frozen schedule."""

    measurements: list[SusceptibilityMeasurement] = []
    for baseline in FROZEN_BASELINES:
        for mechanism_key in FROZEN_CANDIDATE_KEYS:
            for severity in FROZEN_SEVERITIES:
                for seed in FROZEN_SEEDS:
                    cell = measure_cell(
                        mechanism_key=mechanism_key,
                        severity=severity,
                        seed=seed,
                        baseline=baseline,
                    )
                    measurements.append(
                        SusceptibilityMeasurement(
                            baseline_command=baseline,
                            mechanism_key=mechanism_key,
                            severity=severity,
                            seed=seed,
                            commanded_correction=cell.commanded_correction,
                            separability_pre_permille=cell.separability_pre_permille,
                            separability_post_permille=cell.separability_post_permille,
                        )
                    )
    return tuple(measurements)


def _prediction_key(prediction: SusceptibilityPrediction) -> tuple[int, str, int]:
    return prediction.baseline_command, prediction.mechanism_key, prediction.severity


def _measurement_key(measurement: SusceptibilityMeasurement) -> tuple[int, str, int, int]:
    return (
        measurement.baseline_command,
        measurement.mechanism_key,
        measurement.severity,
        measurement.seed,
    )


def _counts(
    rows: tuple[tuple[SusceptibilityPrediction, SusceptibilityMeasurement], ...],
) -> ReplayCounts:
    agreement = sum(
        prediction.masking_event == measurement.masking_event for prediction, measurement in rows
    )
    exact_command = sum(
        prediction.predicted_command == measurement.commanded_correction
        for prediction, measurement in rows
    )
    return ReplayCounts(
        cells=len(rows),
        agreement=ExactRate(numerator=agreement, denominator=len(rows)),
        masking_events=sum(measurement.masking_event for _, measurement in rows),
        exact_command=ExactRate(numerator=exact_command, denominator=len(rows)),
    )


def _summary(
    *,
    predictions: tuple[SusceptibilityPrediction, ...],
    measurements: tuple[SusceptibilityMeasurement, ...],
) -> ReplaySummary:
    by_prediction_key = {_prediction_key(prediction): prediction for prediction in predictions}
    if len(by_prediction_key) != len(predictions):
        raise SusceptibilityReplayError("prediction coordinates must be unique")
    if len({_measurement_key(measurement) for measurement in measurements}) != len(measurements):
        raise SusceptibilityReplayError("measurement coordinates must be unique")

    joined: list[tuple[SusceptibilityPrediction, SusceptibilityMeasurement]] = []
    for measurement in measurements:
        key = (
            measurement.baseline_command,
            measurement.mechanism_key,
            measurement.severity,
        )
        try:
            prediction = by_prediction_key[key]
        except KeyError as error:
            raise SusceptibilityReplayError(f"measurement has no prediction: {key}") from error
        joined.append((prediction, measurement))
    all_rows = tuple(joined)

    baseline_summaries: list[BaselineReplaySummary] = []
    informative: list[tuple[SusceptibilityPrediction, SusceptibilityMeasurement]] = []
    for baseline in FROZEN_BASELINES:
        rows = tuple(row for row in all_rows if row[1].baseline_command == baseline)
        counts = _counts(rows)
        verdict: Literal["informative", "vacuous"] = (
            "vacuous" if counts.masking_events == 0 else "informative"
        )
        baseline_summaries.append(
            BaselineReplaySummary(
                baseline_command=baseline,
                verdict=verdict,
                **counts.model_dump(),
            )
        )
        if verdict == "informative":
            informative.extend(rows)
    informative_rows = tuple(informative)

    mechanism_summaries = tuple(
        MechanismReplaySummary(
            mechanism_key=mechanism_key,
            **_counts(
                tuple(row for row in all_rows if row[1].mechanism_key == mechanism_key)
            ).model_dump(),
        )
        for mechanism_key in FROZEN_CANDIDATE_KEYS
    )

    true_positive = sum(
        prediction.masking_event and measurement.masking_event
        for prediction, measurement in informative_rows
    )
    false_positive = sum(
        prediction.masking_event and not measurement.masking_event
        for prediction, measurement in informative_rows
    )
    false_negative = sum(
        not prediction.masking_event and measurement.masking_event
        for prediction, measurement in informative_rows
    )
    true_negative = sum(
        not prediction.masking_event and not measurement.masking_event
        for prediction, measurement in informative_rows
    )
    actual_positive = true_positive + false_negative
    actual_negative = true_negative + false_positive
    balanced_numerator = true_positive * actual_negative + true_negative * actual_positive
    balanced_denominator = 2 * actual_positive * actual_negative
    balanced_divisor = math.gcd(balanced_numerator, balanced_denominator)

    disagreements = tuple(
        ReplayDisagreement(
            baseline_command=measurement.baseline_command,
            mechanism_key=measurement.mechanism_key,
            severity=measurement.severity,
            seed=measurement.seed,
            predicted_command=prediction.predicted_command,
            measured_command=measurement.commanded_correction,
            predicted_masking=prediction.masking_event,
            measured_masking=measurement.masking_event,
        )
        for prediction, measurement in informative_rows
        if prediction.masking_event != measurement.masking_event
    )
    return ReplaySummary(
        all_cells=_counts(all_rows),
        informative_cells=_counts(informative_rows),
        all_negative_comparator=ExactRate(
            numerator=actual_negative,
            denominator=len(informative_rows),
        ),
        confusion=ReplayConfusionMatrix(
            true_positive=true_positive,
            false_positive=false_positive,
            false_negative=false_negative,
            true_negative=true_negative,
        ),
        sensitivity=ExactRate(numerator=true_positive, denominator=actual_positive),
        specificity=ExactRate(numerator=true_negative, denominator=actual_negative),
        balanced_accuracy=ExactRate(
            numerator=balanced_numerator // balanced_divisor,
            denominator=balanced_denominator // balanced_divisor,
        ),
        per_baseline=tuple(baseline_summaries),
        per_mechanism=mechanism_summaries,
        disagreements=disagreements,
    )


def build_reconstruction() -> SusceptibilityReconstruction:
    """Build the complete canonical reconstruction from the frozen schedule."""

    predictions = reconstruct_predictions()
    measurements = reconstruct_measurements()
    mechanism_names = {mechanism.key: mechanism.name for mechanism in GRADED_ONTOLOGY.classes}
    mechanism_names[UNKNOWN_MECHANISM_KEY] = UNKNOWN_MECHANISM_KEY
    return SusceptibilityReconstruction(
        freeze=FreezeBinding(
            path=FREEZE_PATH,
            commit=FREEZE_COMMIT,
            tree=FREEZE_TREE,
            sha256=FREEZE_SHA256,
        ),
        reported_result=ResultBinding(
            path=REPORTED_RESULT_PATH,
            commit=REPORTED_RESULT_COMMIT,
            sha256=REPORTED_RESULT_SHA256,
        ),
        historical_source=HistoricalSourceBinding(
            commit=FREEZE_COMMIT,
            tree=FREEZE_TREE,
            source_sha256=HISTORICAL_SOURCE_SHA256,
        ),
        laboratory=LaboratoryBinding(
            config_sha256=GRADED_CONFIG.config_sha256,
            ontology_hash=GRADED_ONTOLOGY.ontology_hash,
            candidate_keys=FROZEN_CANDIDATE_KEYS,
            mechanism_names_by_key=mechanism_names,
            resolvable_permille=RESOLVABLE_PERMILLE,
            compensator_gain=COMPENSATOR_GAIN,
        ),
        schedule=ReplaySchedule(
            baselines=FROZEN_BASELINES,
            severities=FROZEN_SEVERITIES,
            seeds=FROZEN_SEEDS,
            measurement_cells=(
                len(FROZEN_BASELINES)
                * len(FROZEN_CANDIDATE_KEYS)
                * len(FROZEN_SEVERITIES)
                * len(FROZEN_SEEDS)
            ),
            prediction_cells=(
                len(FROZEN_BASELINES) * len(FROZEN_CANDIDATE_KEYS) * len(FROZEN_SEVERITIES)
            ),
        ),
        predictions=predictions,
        measurements=measurements,
        summary=_summary(predictions=predictions, measurements=measurements),
        limitations=RECONSTRUCTION_LIMITATIONS,
    )


def reconstruction_bytes() -> bytes:
    """Return the exact canonical artifact bytes."""

    return canonical_json_pretty(build_reconstruction())


def write_reconstruction(path: Path) -> None:
    """Write the reconstruction atomically."""

    atomic_write(path, reconstruction_bytes())


def load_and_verify_reconstruction(path: Path) -> SusceptibilityReconstruction:
    """Load canonical bytes and independently compare them with a fresh reconstruction."""

    try:
        raw = path.read_bytes()
        document = json.loads(raw)
        observed = SusceptibilityReconstruction.model_validate(document)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise SusceptibilityReplayError(f"cannot load reconstruction: {error}") from error
    if raw != canonical_json_pretty(observed):
        raise SusceptibilityReplayError("reconstruction is not canonical JSON")
    expected = build_reconstruction()
    if observed != expected:
        raise SusceptibilityReplayError("reconstruction differs from frozen-schedule recomputation")
    return observed
