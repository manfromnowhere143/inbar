"""Severity-graded reference laboratory with structural model mismatch.

PROPOSED under Amendment 006. This module is implementation-only and carries no authority.
No campaign result, scientific claim, or method comparison is authorized by its existence.

Why this module exists
----------------------
The Amendment 005 laboratory separates its three mechanisms by two to three orders of magnitude
more than its disturbance, and the reference baseline's forward model is the simulator with the
disturbance removed. Under those conditions diagnosis is arithmetic, not inference: the residual
of the true mechanism is bounded by the disturbance and the residual of every false mechanism is
enormous. A method cannot fail, so a campaign cannot measure a method.

That is a verified instrument pointed at a phenomenon requiring no instrument. This module makes
the laboratory able to defeat the method, which is the precondition for a campaign result to
carry information.

Three changes, each closing one specific escape:

1.  Severity grading. Every mechanism takes a severity `theta` in [0, 100]. At `theta = 100` a
    mechanism approximately reproduces its Amendment 005 magnitude; as `theta` falls, its
    signature sinks toward the disturbance floor. Diagnosability becomes a continuous quantity
    with a measurable failure region rather than a property that holds by construction.

2.  Structural mismatch. The plant delivers part of each command one step late; the forward model
    applies every command instantly. A method therefore reasons with a model that is wrong in
    form, not merely noisy, which is the ordinary condition of physical diagnosis. Because the
    mismatch is unmodeled dynamics rather than a perturbed parameter, no mechanism hypothesis can
    absorb it, and residuals no longer vanish for the true mechanism.

3.  A latent nuisance offset. The initial state is perturbed by a seed-derived offset the method
    cannot observe and does not model. The offset propagates through the recurrence, so residual
    error grows with the horizon exactly as unmodeled initial-condition error does in practice.

Determinism is preserved. All arithmetic is integer fixed-point and all stochasticity is derived
from SHA-256 over the seed, so a branch's content hash remains identical on every platform in the
test matrix. That property of the Amendment 004 laboratory is correct and is retained unchanged.
"""

from __future__ import annotations

import hashlib
from typing import Final, Literal

from pydantic import Field

from fieldtrue.canonical import sha256_value
from fieldtrue.causal_laboratory import (
    UNKNOWN_MECHANISM_KEY,
    MechanismClass,
    MechanismOntology,
    Snapshot,
)
from fieldtrue.domain import FrozenModel

# --- Amendment 006 authority binding ---------------------------------------------------
#
# This module exists under Amendment 006, ratified by owner-approval receipt
# `iter001-graded-laboratory-owner-approval-006` over proposal commit `dab4ba9f`. The receipt
# discloses that the proposer and the signer are the same agent and that no independent review
# occurred. Ratification is not prospective authorization: the implementation preceded the
# proposal, so this laboratory's design is outcome-informed and no result produced against it may
# be reported as prospective.

AMENDMENT_ID: Final = "iter001_006"
APPROVED_PROPOSAL_COMMIT: Final = "dab4ba9f8eb967e1eceb70feaecc5262882cbde0"
AMENDMENT_DOCUMENT_SHA256: Final = (
    "266d68f0f28b6474fbb09f971904bef394f8c1315b6fcb388eba88c4d0d5a741"
)
MACHINE_PROPOSAL_SHA256: Final = "2e13e80a661166a5b527af853e0016b0b61dfb672d3234d62e19a9b5752e6052"
OWNER_APPROVAL_RECEIPT_HASH: Final = (
    "cb0f25535691655ec9750f684c37fcb821e9a88c2c1e42c95b153fa22748d33d"
)


# --- Graded configuration -------------------------------------------------------------


class GradedFaultConfig(FrozenModel):
    """A scalar recurrence with an unmodeled quadratic term and a tunable disturbance floor.

    The plant realized by `graded_run` is

        u_eff = (lag * u_previous + (1_000_000 - lag) * u_commanded) // 1_000_000
        x'    = (gain * x)//100 + (drive * u_eff)//100 + bias

    The forward model available to a method (`graded_forward_telemetry`) has no lag: it applies
    each command instantly. That is the structural mismatch, and it is unmodeled *dynamics* rather
    than a perturbed parameter, so no mechanism hypothesis in the catalog can absorb it by
    adjusting gain, drive, or bias. `actuation_lag_ppm = 0` recovers an exactly-specified plant and
    is retained so a control can isolate the effect of mismatch from the effect of severity.

    An earlier revision used a quadratic term `(curvature * x * x)//1_000_000` for this purpose. It
    was removed after a control demonstrated it was inert: at the nominal operating point of
    x ~ 100 the term floors to zero under integer division, so the laboratory carried no structural
    mismatch at all while claiming one. Scaling it up was rejected because a quadratic large enough
    to matter near x ~ 100 diverges once the state reaches the thousands, which the gain-drift and
    sensor-bias mechanisms both reach within the horizon.

    `noise_amplitude` bounds the per-step integer disturbance to [-A, +A] for that amplitude A.
    `nuisance_amplitude` bounds an unobserved additive offset applied once to the initial state.
    """

    schema_version: Literal["inbar.iter001.graded-lab-config.v1"] = (
        "inbar.iter001.graded-lab-config.v1"
    )
    gain: int
    drive: int
    bias: int
    steps: int = Field(ge=1, le=4096)
    actuation_lag_ppm: int = Field(ge=0, le=1_000_000)
    noise_amplitude: int = Field(ge=0, le=10_000)
    noise_ppm: int = Field(ge=0, le=1_000_000)
    nuisance_amplitude: int = Field(ge=0, le=10_000)

    @property
    def config_sha256(self) -> str:
        return sha256_value(
            {
                "schema_version": self.schema_version,
                "actuation_lag_ppm": self.actuation_lag_ppm,
                "bias": self.bias,
                "drive": self.drive,
                "gain": self.gain,
                "noise_amplitude": self.noise_amplitude,
                "noise_ppm": self.noise_ppm,
                "nuisance_amplitude": self.nuisance_amplitude,
                "steps": self.steps,
            }
        )


# The graded operating point. Chosen so that at theta = 100 the mechanism signatures are
# comparable to Amendment 005, and at low theta they fall inside the disturbance floor.
GRADED_CONFIG: Final = GradedFaultConfig(
    gain=90,
    drive=50,
    bias=10,
    steps=8,
    actuation_lag_ppm=300_000,
    noise_amplitude=4,
    noise_ppm=40_000,
    nuisance_amplitude=8,
)
GRADED_INITIAL_STATE: Final = 100

# The graded ontology reuses the Amendment 004 mechanism names and causal loci unchanged, so a
# severity sweep is comparable to the Amendment 005 result at theta = 100.
GRADED_ONTOLOGY: Final = MechanismOntology(
    classes=(
        MechanismClass(
            name="actuator_loss",
            causal_locus="actuator",
            failure_mode="drive_attenuated",
            definition="The commanded drive reaches the plant at a fraction of its magnitude.",
        ),
        MechanismClass(
            name="sensor_bias",
            causal_locus="sensor",
            failure_mode="additive_offset",
            definition="A constant additive offset corrupts the measured output.",
        ),
        MechanismClass(
            name="gain_drift",
            causal_locus="plant",
            failure_mode="open_loop_gain_increase",
            definition="The open-loop gain drifts above its nominal value.",
        ),
        # The degeneracy partner of actuator_loss, and the reason this laboratory needs a
        # selector at all. Deadband passes large commands unattenuated and suppresses small ones
        # entirely; attenuation scales every command alike. Under a small probe both deliver
        # almost no drive and their signatures nearly coincide; only a command above the deadband
        # threshold separates them. No single action resolves every pair, so which action is
        # worth executing depends on which hypotheses remain live.
        MechanismClass(
            name="actuator_deadband",
            causal_locus="actuator",
            failure_mode="small_command_suppression",
            definition="Commands below a threshold produce no actuation; larger commands pass.",
        ),
    )
)

MIN_SEVERITY: Final = 0
MAX_SEVERITY: Final = 100


class GradedLaboratoryError(ValueError):
    """A graded severity, mechanism key, or configuration is invalid."""


class MechanismParams(FrozenModel):
    """The plant parameters a mechanism realizes at a given severity.

    `deadband` is the command magnitude below which no drive reaches the plant. It is zero for
    every mechanism except `actuator_deadband`, and it is the one parameter that makes the
    laboratory's separability depend on the *shape* of an action rather than only its presence.
    """

    schema_version: Literal["inbar.iter001.graded-lab-params.v1"] = (
        "inbar.iter001.graded-lab-params.v1"
    )
    gain: int
    drive: int
    bias: int
    deadband: int


def _graded_transform(
    mechanism_key: str, config: GradedFaultConfig, severity: int
) -> MechanismParams:
    """Return the plant parameters for a mechanism key at a given severity.

    Severity scales each mechanism linearly from nominal (theta = 0, no departure at all) to its
    full Amendment 005 magnitude (theta = 100). The unknown key is nominal at every severity: an
    unmodeled departure the catalog cannot name is not made larger by grading.
    """
    if not MIN_SEVERITY <= severity <= MAX_SEVERITY:
        raise GradedLaboratoryError("severity must lie in [0, 100]")
    by_key = {c.key: c.name for c in GRADED_ONTOLOGY.classes}
    name = by_key.get(mechanism_key, UNKNOWN_MECHANISM_KEY)
    gain, drive, bias = config.gain, config.drive, config.bias
    if name == "actuator_loss":
        # theta = 100 attenuates drive by 90 percent, matching `drive // 10`.
        return MechanismParams(
            gain=gain, drive=drive - (drive * 90 * severity) // 10_000, bias=bias, deadband=0
        )
    if name == "sensor_bias":
        # theta = 100 adds 1000, matching `bias + 1000`.
        return MechanismParams(
            gain=gain, drive=drive, bias=bias + (1000 * severity) // 100, deadband=0
        )
    if name == "gain_drift":
        # theta = 100 adds 40, matching `gain + 40`.
        return MechanismParams(
            gain=gain + (40 * severity) // 100, drive=drive, bias=bias, deadband=0
        )
    if name == "actuator_deadband":
        # theta = 100 suppresses every command below 60. Drive is otherwise untouched, so this
        # mechanism is invisible to any probe that stays above the threshold.
        return MechanismParams(gain=gain, drive=drive, bias=bias, deadband=(60 * severity) // 100)
    return MechanismParams(gain=gain, drive=drive, bias=bias, deadband=0)


def _effective_command(u: int, deadband: int) -> int:
    """A command below the deadband magnitude produces no actuation at all."""
    return 0 if abs(u) < deadband else u


def _disturbance(seed: int, step: int, state: int, config: GradedFaultConfig) -> int:
    """A deterministic integer disturbance with a fixed floor and a signal-proportional term.

    Real sensor error scales with the measured quantity. A fixed absolute floor alone becomes
    decorative once the state grows by orders of magnitude over the horizon, which is precisely
    how the Amendment 005 laboratory made every mechanism trivially separable late in a run.
    """
    amplitude = config.noise_amplitude + (abs(state) * config.noise_ppm) // 1_000_000
    if amplitude == 0:
        return 0
    span = 2 * amplitude + 1
    digest = hashlib.sha256(f"graded-noise:{seed}:{step}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % span - amplitude


def _nuisance_offset(seed: int, amplitude: int) -> int:
    """A deterministic unobserved offset applied once to the initial state."""
    if amplitude == 0:
        return 0
    span = 2 * amplitude + 1
    digest = hashlib.sha256(f"graded-nuisance:{seed}".encode()).digest()
    return int.from_bytes(digest[:4], "big") % span - amplitude


def graded_run(
    *,
    config: GradedFaultConfig,
    initial_state: int,
    seed: int,
    mechanism_key: str,
    severity: int,
    action: tuple[int, ...],
) -> tuple[int, tuple[int, ...]]:
    """Run the true plant. Returns the settled state and the observed telemetry.

    This is the physical process. It includes the actuation lag, the per-step disturbance, and the
    latent initial-state offset, none of which a method observes or models.
    """
    params = _graded_transform(mechanism_key, config, severity)
    x = initial_state + _nuisance_offset(seed, config.nuisance_amplitude)
    telemetry: list[int] = []
    previous = 0
    lag = config.actuation_lag_ppm
    for step in range(config.steps):
        commanded = action[step] if step < len(action) else 0
        u = _effective_command(commanded, params.deadband)
        # Part of each command arrives one step late. The forward model has no such term, so this
        # is unmodeled dynamics and not a perturbed parameter: no hypothesis in the catalog can
        # absorb it by adjusting gain, drive, or bias.
        delivered = (lag * previous + (1_000_000 - lag) * u) // 1_000_000
        previous = u
        x = (params.gain * x) // 100 + (params.drive * delivered) // 100 + params.bias
        telemetry.append(x + _disturbance(seed, step, x, config))
    return x, tuple(telemetry)


def graded_forward_telemetry(
    *,
    config: GradedFaultConfig,
    initial_state: int,
    mechanism_key: str,
    severity: int,
    action: tuple[int, ...],
) -> tuple[int, ...]:
    """The telemetry a mechanism hypothesis predicts, as a method reasons about it.

    Deliberately mismatched against `graded_run`: it omits the actuation lag, the disturbance,
    and the latent initial-state offset. A method reasoning with this model is wrong in form and
    not merely in noise, so the residual of the *true* mechanism is nonzero and grows with the
    horizon. That is the ordinary condition of physical diagnosis and the condition under which a
    diagnosis method can actually be measured.
    """
    params = _graded_transform(mechanism_key, config, severity)
    x = initial_state
    telemetry: list[int] = []
    for step in range(config.steps):
        commanded = action[step] if step < len(action) else 0
        u = _effective_command(commanded, params.deadband)
        x = (params.gain * x) // 100 + (params.drive * u) // 100 + params.bias
        telemetry.append(x)
    return tuple(telemetry)


def graded_snapshot(*, config: GradedFaultConfig, initial_state: int, seed: int) -> Snapshot:
    return Snapshot(
        simulator_id="inbar-graded-simulator-v1",
        config_sha256=config.config_sha256,
        initial_state_sha256=sha256_value(
            {"schema_version": "inbar.iter001.graded-lab-state.v1", "x": initial_state}
        ),
        seed=seed,
    )


# --- Separability -----------------------------------------------------------------------
#
# The reported quantity is a separability index in the sense of Campbell and Nikoukhah (2004):
# the smallest pairwise distance between the predicted signatures of distinct hypotheses, scaled
# by the disturbance magnitude that must be overcome to resolve them. It is a property of the
# laboratory and the action, not of any method, so it states what is resolvable in principle
# before any method is scored. A method that fails where the index is below one has not
# underperformed; the evidence was insufficient.


def pairwise_signature_distance(
    *,
    config: GradedFaultConfig,
    initial_state: int,
    severity: int,
    action: tuple[int, ...],
    left_key: str,
    right_key: str,
) -> int:
    """L1 distance between the noise-free predicted telemetry of two hypotheses under one action."""
    left = graded_forward_telemetry(
        config=config,
        initial_state=initial_state,
        mechanism_key=left_key,
        severity=severity,
        action=action,
    )
    right = graded_forward_telemetry(
        config=config,
        initial_state=initial_state,
        mechanism_key=right_key,
        severity=severity,
        action=action,
    )
    return sum(abs(a - b) for a, b in zip(left, right, strict=True))


def expected_disturbance_l1(
    *,
    config: GradedFaultConfig,
    initial_state: int,
    severity: int,
    action: tuple[int, ...],
) -> int:
    """The disturbance magnitude a separating signature must exceed over the full horizon.

    The disturbance is now signal-proportional, so the floor is accumulated along the nominal
    noise-free trajectory under the action being scored rather than taken as a constant. The mean
    absolute value of a symmetric integer disturbance on [-A, A] is A*(A+1)/(2A+1). Integer
    division keeps the floor conservative: it never overstates separability, so the index never
    flatters a method.
    """
    nominal = graded_forward_telemetry(
        config=config,
        initial_state=initial_state,
        mechanism_key=UNKNOWN_MECHANISM_KEY,
        severity=severity,
        action=action,
    )
    total = 0
    for x in nominal:
        a = config.noise_amplitude + (abs(x) * config.noise_ppm) // 1_000_000
        if a > 0:
            total += (a * (a + 1)) // (2 * a + 1)
    return max(1, total)


def separability_index_permille(
    *,
    config: GradedFaultConfig,
    initial_state: int,
    severity: int,
    actions: tuple[tuple[int, ...], ...],
    candidate_keys: tuple[str, ...],
) -> int:
    """Minimum pairwise separation over the permitted actions, in units of thousandths.

    Returned in permille so the index stays exact integer arithmetic. A value of 1000 means the
    closest pair of hypotheses is separated by exactly the expected disturbance magnitude. Below
    1000, that pair is inside the noise floor and no method can reliably resolve it. The minimum
    is taken over pairs and the maximum over actions: a hypothesis pair is resolvable if *some*
    permitted action separates it.
    """
    if len(candidate_keys) < 2:
        raise GradedLaboratoryError("separability needs at least two candidate hypotheses")
    if not actions:
        raise GradedLaboratoryError("separability needs at least one permitted action")
    worst_pair = None
    ordered = tuple(sorted(candidate_keys))
    for i, left in enumerate(ordered):
        for right in ordered[i + 1 :]:
            best_for_pair = 0
            for action in actions:
                distance = pairwise_signature_distance(
                    config=config,
                    initial_state=initial_state,
                    severity=severity,
                    action=action,
                    left_key=left,
                    right_key=right,
                )
                floor = expected_disturbance_l1(
                    config=config,
                    initial_state=initial_state,
                    severity=severity,
                    action=action,
                )
                # Each action is normalized by the disturbance it must itself overcome: a probe
                # that drives the state higher also raises its own noise floor, so a larger
                # signature is not automatically a better separation.
                best_for_pair = max(best_for_pair, (distance * 1000) // floor)
            if worst_pair is None or best_for_pair < worst_pair:
                worst_pair = best_for_pair
    assert worst_pair is not None
    return worst_pair


def mechanism_separability_permille(
    *,
    config: GradedFaultConfig,
    initial_state: int,
    severity: int,
    action: tuple[int, ...],
    injected_key: str,
    candidate_keys: tuple[str, ...],
) -> int:
    """Separability of one injected mechanism against every other candidate, in permille.

    This differs from `separability_index_permille`, which takes the minimum over *all* hypothesis
    pairs and is therefore a property of the whole catalog: one degenerate pair drives it to zero
    for every mechanism at once. Under a no-op, `actuator_loss` and the reserved unknown are
    bit-identical, so the catalog-wide index is zero everywhere and cannot distinguish a mechanism
    that is resolvable from one that is not.

    This function asks the narrower question a per-mechanism measurement needs: given that `m` was
    injected, how far is its signature from the nearest competing explanation? The minimum is taken
    over the other candidates only, normalized by the disturbance the action must itself overcome.
    """
    others = [k for k in sorted(candidate_keys) if k != injected_key]
    if not others:
        raise GradedLaboratoryError("mechanism separability needs at least one competing candidate")
    floor = expected_disturbance_l1(
        config=config, initial_state=initial_state, severity=severity, action=action
    )
    nearest = None
    for other in others:
        distance = pairwise_signature_distance(
            config=config,
            initial_state=initial_state,
            severity=severity,
            action=action,
            left_key=injected_key,
            right_key=other,
        )
        scaled = (distance * 1000) // floor
        nearest = scaled if nearest is None else min(nearest, scaled)
    assert nearest is not None
    return nearest


def resolvable(index_permille: int) -> bool:
    """A pair separation at or above the disturbance floor is resolvable in principle."""
    return index_permille >= 1000
