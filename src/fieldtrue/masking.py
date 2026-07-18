"""Anomaly masking by autonomous corrective action.

PROPOSED. This module is implementation-only and carries no authority. No measurement result,
scientific claim, or comparison is authorized by its existence, and a measurement run requires its
adjudication freeze to be committed first.

The question
------------
Does an autonomous corrective action destroy the evidence required to diagnose the fault that
triggered it?

NASA JPL's Ops-for-Autonomy states the problem: onboard autonomy "may alter the spacecraft state in
response to information that is not immediately available on the ground," so downlink teams must
"identify anomalies that may otherwise be hidden by autonomous decisions." That programme ran FY2020
through FY2023 and appears closed. A dated 2026 literature scan located no taxonomy of the
phenomenon, no detection method, and no dataset. That scan was not systematic and cannot support an
exhaustive novelty claim.

Why this laboratory can measure it
----------------------------------
The separability index is a property of the laboratory, not of any method: it states what is
resolvable in principle before any diagnosis is attempted. Masking is therefore expressible as a
change in that index across an action, with no method in the loop to confound it. A drop in
separability after a corrective action means the evidence itself was degraded, independently of
whether any particular diagnoser would have succeeded.

What is deliberately absent
---------------------------
No diagnosis method appears anywhere in this module. Masking is a property of the evidence, and
introducing a diagnoser would make the result a joint statement about evidence and method. The
compensator is likewise mechanism-blind: it reacts to a symptom and never consults the ontology,
because an autonomy layer that already knew the mechanism would not be the case of interest.
"""

from __future__ import annotations

from typing import Final, Literal, Self

from pydantic import Field, model_validator

from fieldtrue.canonical import sha256_value
from fieldtrue.causal_laboratory import UNKNOWN_MECHANISM_KEY
from fieldtrue.domain import FrozenModel, Identifier, Sha256
from fieldtrue.graded_laboratory import (
    GRADED_CONFIG,
    GRADED_INITIAL_STATE,
    GRADED_ONTOLOGY,
    GradedFaultConfig,
    graded_forward_telemetry,
    graded_run,
    mechanism_separability_permille,
)

# --- Frozen compensator ------------------------------------------------------------------

# A mechanism-blind proportional compensator. It observes only the no-op telemetry, computes the
# deviation of the final observed state from the nominal final state, and commands a constant drive
# proportional to that deviation, clipped to the safe envelope. It is not a diagnosis.
#
# The gain was fixed before any masking measurement, on the ground that it produces a correction of
# comparable magnitude to the deadband threshold at full severity. It was not selected by comparing
# masking outcomes across gains. A sweep over the gain is a secondary analysis and may never replace
# the primary result.
COMPENSATOR_GAIN: Final = 40
SAFE_COMMAND_FLOOR: Final = 0
SAFE_COMMAND_CEILING: Final = 100

# The system is operating, not at rest. This is the correction that made the instrument work.
#
# Freeze v1 and v2 both observed the pre-action state under a no-op and both produced no correction
# at all: a fault that attenuates drive is invisible when the commanded drive is zero, and a fault
# that raises the state cannot be countered by a compensator that may only command positive drive.
# Masking requires something to cancel, and there is nothing to cancel at rest. Under a baseline
# command an actuator fault depresses output and the compensator raises drive to restore setpoint,
# which is the classic case the phenomenon describes.
BASELINE_COMMAND: Final = 50

# A separability index at or above this is resolvable in principle; below it the closest competing
# hypothesis sits inside the disturbance floor.
RESOLVABLE_PERMILLE: Final = 1000


class MaskingError(ValueError):
    """A masking measurement input or record is invalid."""


def nominal_final_state(
    *, config: GradedFaultConfig, initial_state: int, action: tuple[int, ...]
) -> int:
    """The final state a nominal system would reach under an action, noise-free."""
    return graded_forward_telemetry(
        config=config,
        initial_state=initial_state,
        mechanism_key=UNKNOWN_MECHANISM_KEY,
        severity=0,
        action=action,
    )[-1]


def compensator_action(
    *,
    observed_baseline: tuple[int, ...],
    config: GradedFaultConfig,
    initial_state: int,
    baseline: int = BASELINE_COMMAND,
    gain: int = COMPENSATOR_GAIN,
) -> tuple[int, ...]:
    """The corrective action an autonomy layer commands after seeing the baseline telemetry.

    It compares the observed final state against what a nominal system would have reached under the
    same baseline command, and adjusts drive to close the shortfall. Mechanism-blind by
    construction: it sees one telemetry trace and a nominal expectation, and never the ontology, the
    injected mechanism, or the severity.
    """
    baseline_action = (baseline,) * config.steps
    shortfall = (
        nominal_final_state(config=config, initial_state=initial_state, action=baseline_action)
        - observed_baseline[-1]
    )
    commanded = baseline + (gain * shortfall) // 100
    clipped = max(SAFE_COMMAND_FLOOR, min(SAFE_COMMAND_CEILING, commanded))
    return (clipped,) * config.steps


# --- Compensator families ---------------------------------------------------------------
#
# The susceptibility criterion rests on a claim about geometry: masking depends on where a command
# lands relative to a fault's resolvable window, not on how the command was produced. That claim is
# only testable against policies the criterion has never seen. These three are deliberately chosen
# to differ in how much of the disturbance reaches the final command, because the criterion's
# failures are predicted to come from noise moving the actual command across a window edge that the
# predicted command did not cross.

BANG_BANG_THRESHOLD: Final = 20  # shortfall above which the policy commands the ceiling


def bang_bang_action(
    *,
    observed_baseline: tuple[int, ...],
    config: GradedFaultConfig,
    initial_state: int,
    baseline: int = BASELINE_COMMAND,
    gain: int = COMPENSATOR_GAIN,
) -> tuple[int, ...]:
    """Command the ceiling when the shortfall clears a threshold, otherwise hold baseline.

    The command is quantized to two values, so a small disturbance rarely changes it. The criterion
    is predicted to do at least as well here as against a proportional policy.
    """
    del gain
    baseline_action = (baseline,) * config.steps
    shortfall = (
        nominal_final_state(config=config, initial_state=initial_state, action=baseline_action)
        - observed_baseline[-1]
    )
    commanded = SAFE_COMMAND_CEILING if shortfall >= BANG_BANG_THRESHOLD else baseline
    return (max(SAFE_COMMAND_FLOOR, min(SAFE_COMMAND_CEILING, commanded)),) * config.steps


def half_gain_action(
    *,
    observed_baseline: tuple[int, ...],
    config: GradedFaultConfig,
    initial_state: int,
    baseline: int = BASELINE_COMMAND,
    gain: int = COMPENSATOR_GAIN,
) -> tuple[int, ...]:
    """Proportional restoration at half amplitude.

    The same disturbance moves the command half as far, so the criterion is predicted to do at
    least as well here as against the full-gain policy.
    """
    return compensator_action(
        observed_baseline=observed_baseline,
        config=config,
        initial_state=initial_state,
        baseline=baseline,
        gain=gain // 2,
    )


def integrating_action(
    *,
    observed_baseline: tuple[int, ...],
    config: GradedFaultConfig,
    initial_state: int,
    baseline: int = BASELINE_COMMAND,
    gain: int = COMPENSATOR_GAIN,
) -> tuple[int, ...]:
    """Accumulate the shortfall across every step rather than reading only the final state.

    Each step contributes its own disturbance draw to the command, so this policy carries more of
    the noise into the commanded value than any of the others. The criterion is predicted to do
    strictly worse here, and that prediction is what makes the comparison able to fail.
    """
    baseline_action = (baseline,) * config.steps
    nominal = graded_forward_telemetry(
        config=config,
        initial_state=initial_state,
        mechanism_key=UNKNOWN_MECHANISM_KEY,
        severity=0,
        action=baseline_action,
    )
    accumulated = sum(n - o for n, o in zip(nominal, observed_baseline, strict=True))
    commanded = baseline + (gain * accumulated) // (100 * config.steps)
    return (max(SAFE_COMMAND_FLOOR, min(SAFE_COMMAND_CEILING, commanded)),) * config.steps


COMPENSATOR_FAMILIES: Final[dict[str, object]] = {
    "proportional": compensator_action,
    "bang_bang": bang_bang_action,
    "half_gain": half_gain_action,
    "integrating": integrating_action,
}


# --- Records -----------------------------------------------------------------------------


class MaskingCell(FrozenModel):
    """One (mechanism, severity, seed) observation of separability before and after correction."""

    schema_version: Literal["inbar.iter001.masking-cell.v1"] = "inbar.iter001.masking-cell.v1"
    mechanism_key: str = Field(min_length=1)
    severity: int = Field(ge=0, le=100)
    seed: int = Field(ge=0)
    commanded_correction: int = Field(ge=0, le=SAFE_COMMAND_CEILING)
    separability_pre_permille: int = Field(ge=0)
    separability_post_permille: int = Field(ge=0)

    @property
    def masking_index_permille(self) -> int:
        """Positive means the corrective action reduced identifiability."""
        return self.separability_pre_permille - self.separability_post_permille

    @property
    def resolvable_pre(self) -> bool:
        return self.separability_pre_permille >= RESOLVABLE_PERMILLE

    @property
    def resolvable_post(self) -> bool:
        return self.separability_post_permille >= RESOLVABLE_PERMILLE

    @property
    def masking_event(self) -> bool:
        """Resolvable in principle before the action, and not resolvable after it."""
        return self.resolvable_pre and not self.resolvable_post


class MechanismMaskingSummary(FrozenModel):
    """Per-mechanism totals. Reported for every mechanism, including those with zero events."""

    schema_version: Literal["inbar.iter001.masking-mechanism-summary.v1"] = (
        "inbar.iter001.masking-mechanism-summary.v1"
    )
    mechanism_key: str = Field(min_length=1)
    cells_total: int = Field(ge=0)
    cells_resolvable_pre: int = Field(ge=0)
    cells_excluded_unresolvable_pre: int = Field(ge=0)
    masking_events: int = Field(ge=0)
    median_masking_index_permille: int

    @model_validator(mode="after")
    def counts_are_consistent(self) -> Self:
        if self.cells_resolvable_pre + self.cells_excluded_unresolvable_pre != self.cells_total:
            raise ValueError("resolvable and excluded cells must sum to the total")
        if self.masking_events > self.cells_resolvable_pre:
            raise ValueError("a cell that was not resolvable before cannot be masked")
        return self


class MaskingResult(FrozenModel):
    """The measurement, recomputed from atomic cells and bound to its adjudication freeze.

    The three missingness quantities are reported together and none is reported alone: a cell that
    was already unresolvable before the action cannot be masked, so it is excluded from the
    denominator, but its count travels with the rate it was excluded from.
    """

    schema_version: Literal["inbar.iter001.masking-result.v1"] = "inbar.iter001.masking-result.v1"
    result_id: Identifier
    adjudication_freeze_sha256: Sha256
    laboratory_config_sha256: Sha256
    compensator_gain: int
    cells_total: int = Field(ge=1)
    cells_resolvable_pre: int = Field(ge=0)
    cells_excluded_unresolvable_pre: int = Field(ge=0)
    masking_events: int = Field(ge=0)
    per_mechanism: tuple[MechanismMaskingSummary, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def totals_are_consistent(self) -> Self:
        if self.cells_resolvable_pre + self.cells_excluded_unresolvable_pre != self.cells_total:
            raise ValueError("resolvable and excluded cells must sum to the total")
        if self.masking_events > self.cells_resolvable_pre:
            raise ValueError("a cell that was not resolvable before cannot be masked")
        if sum(m.cells_total for m in self.per_mechanism) != self.cells_total:
            raise ValueError("per-mechanism totals must sum to the overall total")
        if sum(m.masking_events for m in self.per_mechanism) != self.masking_events:
            raise ValueError("per-mechanism events must sum to the overall events")
        return self


# --- Measurement --------------------------------------------------------------------------


def measure_cell(
    *,
    mechanism_key: str,
    severity: int,
    seed: int,
    config: GradedFaultConfig = GRADED_CONFIG,
    initial_state: int = GRADED_INITIAL_STATE,
    candidate_keys: tuple[str, ...] | None = None,
    baseline: int = BASELINE_COMMAND,
    gain: int = COMPENSATOR_GAIN,
) -> MaskingCell:
    """Measure separability before and after the autonomous correction for one cell."""
    keys = candidate_keys or (*sorted(GRADED_ONTOLOGY.known_keys), UNKNOWN_MECHANISM_KEY)
    baseline_action = (baseline,) * config.steps

    _, observed_baseline = graded_run(
        config=config,
        initial_state=initial_state,
        seed=seed,
        mechanism_key=mechanism_key,
        severity=severity,
        action=baseline_action,
    )
    correction = compensator_action(
        observed_baseline=observed_baseline,
        config=config,
        initial_state=initial_state,
        baseline=baseline,
        gain=gain,
    )

    # Per-mechanism, not catalog-wide. Freeze v1 specified the catalog-wide index and was vacuous:
    # one degenerate pair drove it to zero for every cell, so no cell was ever resolvable before the
    # action and the denominator was zero by construction. See ADJUDICATION_FREEZE_MASKING_V2.md.
    pre = mechanism_separability_permille(
        config=config,
        initial_state=initial_state,
        severity=severity,
        action=baseline_action,
        injected_key=mechanism_key,
        candidate_keys=keys,
    )
    post = mechanism_separability_permille(
        config=config,
        initial_state=initial_state,
        severity=severity,
        action=correction,
        injected_key=mechanism_key,
        candidate_keys=keys,
    )
    return MaskingCell(
        mechanism_key=mechanism_key,
        severity=severity,
        seed=seed,
        commanded_correction=correction[0],
        separability_pre_permille=pre,
        separability_post_permille=post,
    )


def _median(values: list[int]) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) // 2


def recompute_masking_result(
    *,
    result_id: Identifier,
    cells: tuple[MaskingCell, ...],
    adjudication_freeze_sha256: str,
    config: GradedFaultConfig = GRADED_CONFIG,
    gain: int = COMPENSATOR_GAIN,
) -> MaskingResult:
    """Derive every reported quantity from the atomic cells alone.

    Nothing is carried over from the run. A control recomputes independently and asserts equality,
    which is what makes the result auditable rather than asserted.
    """
    if not cells:
        raise MaskingError("a masking result needs at least one cell")

    by_mechanism: dict[str, list[MaskingCell]] = {}
    for cell in cells:
        by_mechanism.setdefault(cell.mechanism_key, []).append(cell)

    summaries = []
    for key in sorted(by_mechanism):
        rows = by_mechanism[key]
        resolvable = [c for c in rows if c.resolvable_pre]
        summaries.append(
            MechanismMaskingSummary(
                mechanism_key=key,
                cells_total=len(rows),
                cells_resolvable_pre=len(resolvable),
                cells_excluded_unresolvable_pre=len(rows) - len(resolvable),
                masking_events=sum(1 for c in rows if c.masking_event),
                median_masking_index_permille=_median([c.masking_index_permille for c in rows]),
            )
        )

    resolvable_total = sum(1 for c in cells if c.resolvable_pre)
    return MaskingResult(
        result_id=result_id,
        adjudication_freeze_sha256=adjudication_freeze_sha256,
        laboratory_config_sha256=config.config_sha256,
        compensator_gain=gain,
        cells_total=len(cells),
        cells_resolvable_pre=resolvable_total,
        cells_excluded_unresolvable_pre=len(cells) - resolvable_total,
        masking_events=sum(1 for c in cells if c.masking_event),
        per_mechanism=tuple(summaries),
    )


def measurement_plan_hash(
    *, mechanisms: tuple[str, ...], severities: tuple[int, ...], seeds: tuple[int, ...], gain: int
) -> str:
    """Hash of the frozen schedule, so a result can prove which plan produced it."""
    return sha256_value(
        {
            "schema_version": "inbar.iter001.masking-plan.v1",
            "gain": gain,
            "mechanisms": sorted(mechanisms),
            "seeds": sorted(seeds),
            "severities": sorted(severities),
        }
    )
