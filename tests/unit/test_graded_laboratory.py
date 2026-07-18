"""Adversarial controls for the severity-graded laboratory.

The graded laboratory exists for one reason: the Amendment 005 laboratory cannot produce a negative
result, so a campaign run in it cannot measure a method. That value is destroyed if the plant and
the forward model silently agree, if the disturbance is decorative against a growing state, if
severity fails to move diagnosability, if the deadband mechanism stops depending on the shape of the
commanded action, or if determinism is lost and a branch hash stops being reproducible across
platforms. Each control below pins one of those failures shut.

These controls verify the laboratory's internal validity. They assert nothing about the physical
world, and a simulator branch never counts as a physical incident.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from fieldtrue.causal_laboratory import UNKNOWN_MECHANISM_KEY
from fieldtrue.graded_laboratory import (
    GRADED_CONFIG,
    GRADED_INITIAL_STATE,
    GRADED_ONTOLOGY,
    GradedFaultConfig,
    GradedLaboratoryError,
    expected_disturbance_l1,
    graded_forward_telemetry,
    graded_run,
    graded_snapshot,
    pairwise_signature_distance,
    resolvable,
    separability_index_permille,
)

_BY_NAME = {c.name: c.key for c in GRADED_ONTOLOGY.classes}
ACTUATOR_LOSS = _BY_NAME["actuator_loss"]
ACTUATOR_DEADBAND = _BY_NAME["actuator_deadband"]
SENSOR_BIAS = _BY_NAME["sensor_bias"]
GAIN_DRIFT = _BY_NAME["gain_drift"]
ALL_KEYS = (*sorted(GRADED_ONTOLOGY.known_keys), UNKNOWN_MECHANISM_KEY)

NO_OP = (0,) * 8
SMALL = (20,) * 8
LARGE = (100,) * 8


def _run(key: str, severity: int, action: tuple[int, ...], seed: int = 7) -> tuple[int, ...]:
    _, telemetry = graded_run(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        seed=seed,
        mechanism_key=key,
        severity=severity,
        action=action,
    )
    return telemetry


def _predict(key: str, severity: int, action: tuple[int, ...]) -> tuple[int, ...]:
    return graded_forward_telemetry(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        mechanism_key=key,
        severity=severity,
        action=action,
    )


# --- Determinism ---------------------------------------------------------------------


def test_run_is_deterministic_across_repeated_calls() -> None:
    """A branch hash is only reproducible if the plant is a pure function of its arguments."""
    first = _run(ACTUATOR_LOSS, 60, LARGE)
    second = _run(ACTUATOR_LOSS, 60, LARGE)
    assert first == second


def test_distinct_seeds_produce_distinct_telemetry() -> None:
    """The disturbance must actually depend on the seed, or the noise floor is fictional."""
    assert _run(GAIN_DRIFT, 100, NO_OP, seed=1) != _run(GAIN_DRIFT, 100, NO_OP, seed=2)


def test_forward_model_is_noise_free_and_seed_independent() -> None:
    """A method's forward model must not carry the custodian-only disturbance."""
    assert _predict(GAIN_DRIFT, 100, NO_OP) == _predict(GAIN_DRIFT, 100, NO_OP)


# --- The model mismatch is real, not cosmetic ----------------------------------------


def test_forward_model_disagrees_with_the_plant_for_the_true_mechanism() -> None:
    """The residual of the *true* mechanism must be nonzero.

    If the forward model were the plant minus noise, diagnosis would be table lookup with a
    tolerance. The actuation lag and the latent offset make the true hypothesis imperfect too,
    which is the ordinary condition of physical diagnosis.
    """
    observed = _run(GAIN_DRIFT, 100, NO_OP)
    predicted = _predict(GAIN_DRIFT, 100, NO_OP)
    residual = sum(abs(o - p) for o, p in zip(observed, predicted, strict=True))
    assert residual > 0


def test_actuation_lag_changes_the_plant_but_not_the_forward_model() -> None:
    """The lag is the structural mismatch: it must appear in the plant and never in the model.

    A prior revision used a quadratic curvature term here. This control is the reason it was
    replaced: it demonstrated the quadratic floored to zero under integer division at the nominal
    operating point, so the laboratory claimed a structural mismatch it did not have.
    """
    flat = GRADED_CONFIG.model_copy(update={"actuation_lag_ppm": 0})
    curved = GRADED_CONFIG.model_copy(update={"actuation_lag_ppm": 800_000})
    flat_model = graded_forward_telemetry(
        config=flat,
        initial_state=GRADED_INITIAL_STATE,
        mechanism_key=UNKNOWN_MECHANISM_KEY,
        severity=0,
        action=LARGE,
    )
    curved_model = graded_forward_telemetry(
        config=curved,
        initial_state=GRADED_INITIAL_STATE,
        mechanism_key=UNKNOWN_MECHANISM_KEY,
        severity=0,
        action=LARGE,
    )
    assert flat_model == curved_model

    _, flat_plant = graded_run(
        config=flat,
        initial_state=GRADED_INITIAL_STATE,
        seed=3,
        mechanism_key=UNKNOWN_MECHANISM_KEY,
        severity=0,
        action=LARGE,
    )
    _, curved_plant = graded_run(
        config=curved,
        initial_state=GRADED_INITIAL_STATE,
        seed=3,
        mechanism_key=UNKNOWN_MECHANISM_KEY,
        severity=0,
        action=LARGE,
    )
    assert flat_plant != curved_plant


def test_nuisance_offset_perturbs_the_plant_only() -> None:
    """The latent initial-state offset must be unobservable to the forward model."""
    quiet = GRADED_CONFIG.model_copy(
        update={"nuisance_amplitude": 0, "noise_amplitude": 0, "noise_ppm": 0}
    )
    noisy_offset = quiet.model_copy(update={"nuisance_amplitude": 40})
    _, without = graded_run(
        config=quiet,
        initial_state=GRADED_INITIAL_STATE,
        seed=5,
        mechanism_key=UNKNOWN_MECHANISM_KEY,
        severity=0,
        action=NO_OP,
    )
    _, with_offset = graded_run(
        config=noisy_offset,
        initial_state=GRADED_INITIAL_STATE,
        seed=5,
        mechanism_key=UNKNOWN_MECHANISM_KEY,
        severity=0,
        action=NO_OP,
    )
    assert without != with_offset


# --- Severity actually grades ---------------------------------------------------------


def test_zero_severity_is_indistinguishable_from_nominal() -> None:
    """A mechanism at severity zero is no departure at all, for every mechanism."""
    nominal = _predict(UNKNOWN_MECHANISM_KEY, 0, LARGE)
    for key in sorted(GRADED_ONTOLOGY.known_keys):
        assert _predict(key, 0, LARGE) == nominal


def test_separation_increases_with_severity() -> None:
    """Diagnosability must be continuous in severity, not a cliff."""
    distances = [
        pairwise_signature_distance(
            config=GRADED_CONFIG,
            initial_state=GRADED_INITIAL_STATE,
            severity=severity,
            action=LARGE,
            left_key=ACTUATOR_LOSS,
            right_key=UNKNOWN_MECHANISM_KEY,
        )
        for severity in (10, 40, 70, 100)
    ]
    assert distances == sorted(distances)
    assert distances[0] < distances[-1]


def test_severity_outside_the_range_is_refused() -> None:
    with pytest.raises(GradedLaboratoryError):
        _predict(ACTUATOR_LOSS, 101, NO_OP)
    with pytest.raises(GradedLaboratoryError):
        _predict(ACTUATOR_LOSS, -1, NO_OP)


# --- The deadband degeneracy, which is why selection is a real problem ---------------


def test_deadband_is_invisible_to_a_command_above_its_threshold() -> None:
    """The whole reason a fixed maximum-amplitude probe is the wrong policy.

    At severity 100 the deadband threshold is 60. A command of 100 passes unattenuated, so the
    mechanism produces exactly nominal behavior and no amount of observation separates them.
    """
    assert _predict(ACTUATOR_DEADBAND, 100, LARGE) == _predict(UNKNOWN_MECHANISM_KEY, 0, LARGE)


def test_deadband_is_visible_to_a_command_below_its_threshold() -> None:
    """And the same mechanism is plainly separable under a milder probe."""
    assert _predict(ACTUATOR_DEADBAND, 100, SMALL) != _predict(UNKNOWN_MECHANISM_KEY, 0, SMALL)


def test_no_single_action_resolves_every_pair() -> None:
    """The requirements run in opposite directions, so a fixed policy must miss something.

    Separating deadband from nominal needs a small command; separating deadband from attenuation
    needs a large one. This is the structural property that makes action selection non-trivial,
    and it is the property most likely to be destroyed by a careless change to the ontology.
    """
    deadband_vs_nominal_small = pairwise_signature_distance(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        severity=100,
        action=SMALL,
        left_key=ACTUATOR_DEADBAND,
        right_key=UNKNOWN_MECHANISM_KEY,
    )
    deadband_vs_nominal_large = pairwise_signature_distance(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        severity=100,
        action=LARGE,
        left_key=ACTUATOR_DEADBAND,
        right_key=UNKNOWN_MECHANISM_KEY,
    )
    deadband_vs_loss_small = pairwise_signature_distance(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        severity=100,
        action=SMALL,
        left_key=ACTUATOR_DEADBAND,
        right_key=ACTUATOR_LOSS,
    )
    deadband_vs_loss_large = pairwise_signature_distance(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        severity=100,
        action=LARGE,
        left_key=ACTUATOR_DEADBAND,
        right_key=ACTUATOR_LOSS,
    )
    # Small probe reveals the deadband against nominal; the large probe cannot see it at all.
    assert deadband_vs_nominal_small > 0
    assert deadband_vs_nominal_large == 0
    # And the ordering inverts for the other pair.
    assert deadband_vs_loss_large > deadband_vs_loss_small


# --- The separability index -----------------------------------------------------------


def test_separability_index_needs_two_hypotheses_and_one_action() -> None:
    with pytest.raises(GradedLaboratoryError):
        separability_index_permille(
            config=GRADED_CONFIG,
            initial_state=GRADED_INITIAL_STATE,
            severity=100,
            actions=(NO_OP,),
            candidate_keys=(ACTUATOR_LOSS,),
        )
    with pytest.raises(GradedLaboratoryError):
        separability_index_permille(
            config=GRADED_CONFIG,
            initial_state=GRADED_INITIAL_STATE,
            severity=100,
            actions=(),
            candidate_keys=ALL_KEYS,
        )


def test_no_op_alone_leaves_the_actuator_pair_unresolvable() -> None:
    """A parameter multiplying the input is unidentifiable when the input is zero.

    This is the Amendment 005 artifact, stated as a control rather than reported as a discovery.
    """
    index = separability_index_permille(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        severity=100,
        actions=(NO_OP,),
        candidate_keys=(ACTUATOR_LOSS, UNKNOWN_MECHANISM_KEY),
    )
    assert index == 0
    assert not resolvable(index)


def test_a_probe_resolves_what_the_no_op_cannot() -> None:
    index = separability_index_permille(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        severity=100,
        actions=(NO_OP, LARGE),
        candidate_keys=(ACTUATOR_LOSS, UNKNOWN_MECHANISM_KEY),
    )
    assert resolvable(index)


def test_disturbance_floor_grows_with_the_state() -> None:
    """A proportional disturbance must not be dominated by a fixed absolute term.

    If the floor were constant, a probe that drives the state higher would win separability for
    free, which is exactly how the prior laboratory made every mechanism trivially separable.
    """
    quiet = expected_disturbance_l1(
        config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE, severity=0, action=NO_OP
    )
    driven = expected_disturbance_l1(
        config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE, severity=0, action=LARGE
    )
    assert driven > quiet


def test_disturbance_floor_is_never_zero() -> None:
    """The index divides by the floor; a zero-noise configuration must not divide by zero."""
    silent = GRADED_CONFIG.model_copy(update={"noise_amplitude": 0, "noise_ppm": 0})
    assert (
        expected_disturbance_l1(
            config=silent, initial_state=GRADED_INITIAL_STATE, severity=0, action=NO_OP
        )
        >= 1
    )


# --- Config binding --------------------------------------------------------------------


def test_config_hash_covers_every_disturbance_parameter() -> None:
    """A configuration change must change the snapshot binding, or a result is not reproducible."""
    base = GRADED_CONFIG.config_sha256
    fields = ("actuation_lag_ppm", "noise_amplitude", "noise_ppm", "nuisance_amplitude", "gain")
    for field in fields:
        altered = GRADED_CONFIG.model_copy(update={field: getattr(GRADED_CONFIG, field) + 1})
        assert altered.config_sha256 != base, field


def test_snapshot_binds_the_configuration_and_seed() -> None:
    first = graded_snapshot(config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE, seed=1)
    second = graded_snapshot(config=GRADED_CONFIG, initial_state=GRADED_INITIAL_STATE, seed=2)
    assert first.snapshot_hash != second.snapshot_hash
    assert first.simulator_id == "inbar-graded-simulator-v1"


def test_configuration_rejects_out_of_range_parameters() -> None:
    with pytest.raises(ValidationError):
        GradedFaultConfig(
            gain=90,
            drive=50,
            bias=10,
            steps=0,
            actuation_lag_ppm=0,
            noise_amplitude=0,
            noise_ppm=0,
            nuisance_amplitude=0,
        )
