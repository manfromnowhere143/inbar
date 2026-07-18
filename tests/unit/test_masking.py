"""Adversarial controls for the anomaly-masking measurement.

The measurement claims that an autonomous corrective action can destroy the evidence needed to
diagnose the fault that triggered it. That claim is worthless if the compensator can see the
mechanism it is compensating for, if a cell that was never resolvable can be counted as masked, if
the reported rate can be quoted without the cells it excluded, or if any aggregate is asserted
rather than recomputed from atomic cells. Each control below pins one of those failures shut.

These controls verify internal validity only. They assert nothing about physical systems, no
measurement has been adjudicated, and a simulator branch never counts as a physical incident.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fieldtrue.causal_laboratory import UNKNOWN_MECHANISM_KEY
from fieldtrue.graded_laboratory import (
    GRADED_CONFIG,
    GRADED_INITIAL_STATE,
    GRADED_ONTOLOGY,
    graded_run,
)
from fieldtrue.masking import (
    BASELINE_COMMAND,
    COMPENSATOR_GAIN,
    RESOLVABLE_PERMILLE,
    SAFE_COMMAND_CEILING,
    MaskingCell,
    MaskingError,
    MechanismMaskingSummary,
    compensator_action,
    measure_cell,
    measurement_plan_hash,
    nominal_final_state,
    recompute_masking_result,
)

_BY_NAME = {c.name: c.key for c in GRADED_ONTOLOGY.classes}
ACTUATOR_LOSS = _BY_NAME["actuator_loss"]
SENSOR_BIAS = _BY_NAME["sensor_bias"]
MECHANISMS = (*sorted(GRADED_ONTOLOGY.known_keys), UNKNOWN_MECHANISM_KEY)
NO_OP = (0,) * 8
BASELINE = (BASELINE_COMMAND,) * 8


def _observe(key: str, severity: int, seed: int = 3) -> tuple[int, ...]:
    """Telemetry under the baseline operating command, which is what the compensator sees."""
    _, telemetry = graded_run(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        seed=seed,
        mechanism_key=key,
        severity=severity,
        action=BASELINE,
    )
    return telemetry


# --- The compensator is blind, bounded, and deterministic ------------------------------


def test_compensator_depends_only_on_observed_telemetry() -> None:
    """Two mechanisms producing the same trace must receive the same correction.

    The compensator's whole premise is that it reacts to a symptom. If it could distinguish
    mechanisms that are observationally identical, it would be a diagnoser and the measurement
    would be a joint claim about evidence and method.
    """
    trace = _observe(ACTUATOR_LOSS, 100)
    first = compensator_action(
        observed_baseline=trace, config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE
    )
    second = compensator_action(
        observed_baseline=trace, config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE
    )
    assert first == second


def test_compensator_stays_inside_the_safe_envelope_under_extreme_deviation() -> None:
    """An unbounded command is an unsafe action, regardless of how large the deviation is."""
    huge = _observe(SENSOR_BIAS, 100)
    action = compensator_action(
        observed_baseline=huge,
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        gain=100_000,
    )
    assert all(0 <= u <= SAFE_COMMAND_CEILING for u in action)

    inverted = tuple(-v for v in huge)
    action_low = compensator_action(
        observed_baseline=inverted, config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE
    )
    assert all(0 <= u <= SAFE_COMMAND_CEILING for u in action_low)


def test_a_nominal_system_holds_the_baseline_command() -> None:
    """With no departure there is nothing to compensate, so drive stays at baseline.

    Not zero: the system is operating. A compensator that dropped an untroubled system to no drive
    would itself be the anomaly.
    """
    nominal = nominal_final_state(
        config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE, action=BASELINE
    )
    action = compensator_action(
        observed_baseline=(nominal,) * GRADED_CONFIG.steps,
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
    )
    assert action == (BASELINE_COMMAND,) * GRADED_CONFIG.steps


def test_larger_deviation_commands_a_strictly_larger_correction() -> None:
    """The compensator must be proportional, and the comparison must be strict.

    This control previously asserted `severe >= mild` and passed on `0 >= 0` while the compensator
    was completely inert, which is how an entire measurement reached a frozen protocol before the
    defect was found. A guard that cannot fail is not a guard.
    """
    mild = _observe(ACTUATOR_LOSS, 25)
    severe = _observe(ACTUATOR_LOSS, 100)
    mild_action = compensator_action(
        observed_baseline=mild, config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE
    )
    severe_action = compensator_action(
        observed_baseline=severe, config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE
    )
    assert severe_action[0] > mild_action[0]


# --- Inertness controls -----------------------------------------------------------------
#
# Three components in this laboratory have been built, described as doing something, and found to do
# nothing: a quadratic term that floored to zero under integer division, a first graded laboratory
# that could not defeat its own method, and a compensator that never fired. Each passed every control
# it had, because none of those controls could fail on an inert component. These can.


def test_the_compensator_actually_fires_on_at_least_one_mechanism() -> None:
    """If no correction ever departs from baseline, no masking measurement means anything."""
    commanded = {
        m: measure_cell(mechanism_key=m, severity=100, seed=0).commanded_correction
        for m in MECHANISMS
    }
    assert any(u != BASELINE_COMMAND for u in commanded.values()), (
        f"compensator inert across every mechanism: {commanded}"
    )


def test_the_measurement_moves_separability_somewhere() -> None:
    """Pre and post separability must differ for at least one cell.

    If the corrective action never changes what is resolvable, the masking index is identically
    zero and the protocol cannot return either of its outcomes.
    """
    indices = [
        measure_cell(mechanism_key=m, severity=s, seed=0).masking_index_permille
        for m in MECHANISMS
        for s in (45, 100)
    ]
    assert any(i != 0 for i in indices), f"separability never moved: {indices}"


def test_at_least_one_mechanism_is_resolvable_before_correction() -> None:
    """A denominator of zero makes the primary rate vacuous regardless of the data.

    Freeze v1 returned exactly this and could not have produced information under any outcome.
    """
    resolvable = [
        measure_cell(mechanism_key=m, severity=s, seed=0).resolvable_pre
        for m in MECHANISMS
        for s in (45, 100)
    ]
    assert any(resolvable), "no cell resolvable pre-action: the primary rate would be vacuous"


# --- A cell cannot claim more than it observed -----------------------------------------


def test_a_cell_that_was_never_resolvable_cannot_be_masked() -> None:
    """Masking means evidence was destroyed. Evidence that never existed cannot be destroyed."""
    cell = MaskingCell(
        mechanism_key=ACTUATOR_LOSS,
        severity=100,
        seed=0,
        commanded_correction=40,
        separability_pre_permille=RESOLVABLE_PERMILLE - 1,
        separability_post_permille=0,
    )
    assert not cell.resolvable_pre
    assert not cell.masking_event


def test_masking_event_requires_crossing_the_threshold() -> None:
    masked = MaskingCell(
        mechanism_key=ACTUATOR_LOSS,
        severity=100,
        seed=0,
        commanded_correction=40,
        separability_pre_permille=5000,
        separability_post_permille=RESOLVABLE_PERMILLE - 1,
    )
    survived = MaskingCell(
        mechanism_key=ACTUATOR_LOSS,
        severity=100,
        seed=0,
        commanded_correction=40,
        separability_pre_permille=5000,
        separability_post_permille=RESOLVABLE_PERMILLE,
    )
    assert masked.masking_event
    assert not survived.masking_event
    assert masked.masking_index_permille > survived.masking_index_permille


def test_masking_index_is_signed_so_correction_can_help() -> None:
    """A corrective action that increases identifiability must report a negative index.

    Forcing the index non-negative would make it impossible for this measurement to return the
    finding that autonomy helps, which is a result the protocol must be able to produce.
    """
    helped = MaskingCell(
        mechanism_key=SENSOR_BIAS,
        severity=50,
        seed=1,
        commanded_correction=10,
        separability_pre_permille=1200,
        separability_post_permille=9000,
    )
    assert helped.masking_index_permille < 0


# --- Aggregates are recomputed, never asserted -----------------------------------------


def _cells() -> tuple[MaskingCell, ...]:
    return (
        MaskingCell(
            mechanism_key=ACTUATOR_LOSS,
            severity=100,
            seed=0,
            commanded_correction=40,
            separability_pre_permille=5000,
            separability_post_permille=10,
        ),
        MaskingCell(
            mechanism_key=ACTUATOR_LOSS,
            severity=100,
            seed=1,
            commanded_correction=40,
            separability_pre_permille=5000,
            separability_post_permille=4000,
        ),
        MaskingCell(
            mechanism_key=SENSOR_BIAS,
            severity=100,
            seed=0,
            commanded_correction=20,
            separability_pre_permille=500,
            separability_post_permille=100,
        ),
    )


def test_result_recomputes_every_reported_quantity() -> None:
    result = recompute_masking_result(
        result_id="masking-test", cells=_cells(), adjudication_freeze_sha256="a" * 64
    )
    assert result.cells_total == 3
    assert result.cells_resolvable_pre == 2
    assert result.cells_excluded_unresolvable_pre == 1
    assert result.masking_events == 1
    assert sum(m.cells_total for m in result.per_mechanism) == 3


def test_every_mechanism_appears_including_those_with_no_events() -> None:
    """A mechanism is never dropped from the table for having a null result."""
    result = recompute_masking_result(
        result_id="masking-test", cells=_cells(), adjudication_freeze_sha256="a" * 64
    )
    reported = {m.mechanism_key for m in result.per_mechanism}
    assert reported == {ACTUATOR_LOSS, SENSOR_BIAS}
    sensor = next(m for m in result.per_mechanism if m.mechanism_key == SENSOR_BIAS)
    assert sensor.masking_events == 0
    assert sensor.cells_excluded_unresolvable_pre == 1


def test_result_refuses_an_empty_cell_set() -> None:
    with pytest.raises(MaskingError):
        recompute_masking_result(
            result_id="masking-test", cells=(), adjudication_freeze_sha256="a" * 64
        )


def test_summary_rejects_counts_that_do_not_reconcile() -> None:
    """The three missingness numbers must sum, or a rate could be quoted without its exclusions."""
    with pytest.raises(ValidationError):
        MechanismMaskingSummary(
            mechanism_key=ACTUATOR_LOSS,
            cells_total=10,
            cells_resolvable_pre=4,
            cells_excluded_unresolvable_pre=4,
            masking_events=1,
            median_masking_index_permille=0,
        )


def test_summary_rejects_more_events_than_resolvable_cells() -> None:
    with pytest.raises(ValidationError):
        MechanismMaskingSummary(
            mechanism_key=ACTUATOR_LOSS,
            cells_total=10,
            cells_resolvable_pre=2,
            cells_excluded_unresolvable_pre=8,
            masking_events=3,
            median_masking_index_permille=0,
        )


# --- The measurement itself is deterministic and bound ---------------------------------


def test_measured_cell_is_reproducible() -> None:
    first = measure_cell(mechanism_key=ACTUATOR_LOSS, severity=70, seed=2)
    second = measure_cell(mechanism_key=ACTUATOR_LOSS, severity=70, seed=2)
    assert first == second


def test_measured_cell_records_the_command_it_actually_issued() -> None:
    cell = measure_cell(mechanism_key=ACTUATOR_LOSS, severity=100, seed=0)
    expected = compensator_action(
        observed_baseline=_observe(ACTUATOR_LOSS, 100, seed=0),
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
    )
    assert cell.commanded_correction == expected[0]


def test_plan_hash_changes_with_every_frozen_input() -> None:
    """A result must be able to prove which schedule produced it."""
    base = measurement_plan_hash(
        mechanisms=MECHANISMS, severities=(25, 50), seeds=(0, 1), gain=COMPENSATOR_GAIN
    )
    assert base != measurement_plan_hash(
        mechanisms=MECHANISMS, severities=(25, 51), seeds=(0, 1), gain=COMPENSATOR_GAIN
    )
    assert base != measurement_plan_hash(
        mechanisms=MECHANISMS, severities=(25, 50), seeds=(0, 2), gain=COMPENSATOR_GAIN
    )
    assert base != measurement_plan_hash(
        mechanisms=MECHANISMS, severities=(25, 50), seeds=(0, 1), gain=COMPENSATOR_GAIN + 1
    )
    assert base == measurement_plan_hash(
        mechanisms=tuple(reversed(MECHANISMS)),
        severities=(50, 25),
        seeds=(1, 0),
        gain=COMPENSATOR_GAIN,
    )


def test_result_binds_its_freeze_and_laboratory_configuration() -> None:
    """A measurement that cannot name its frozen protocol is not prospective evidence."""
    result = recompute_masking_result(
        result_id="masking-test", cells=_cells(), adjudication_freeze_sha256="b" * 64
    )
    assert result.adjudication_freeze_sha256 == "b" * 64
    assert result.laboratory_config_sha256 == GRADED_CONFIG.config_sha256
    assert result.compensator_gain == COMPENSATOR_GAIN
