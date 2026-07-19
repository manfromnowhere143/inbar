"""Safe, cost-aware active test selection over the graded laboratory.

This module is present as an implementation-only candidate and carries no authority. Amendment 006
does not cover its committed bytes. No campaign result, scientific claim, or method comparison is
authorized by its existence.

What this implements
--------------------
The selection rule frozen in `docs/MATHEMATICS.md`:

    a* = argmax over a in A_safe of  I(H; Y_a | E) / max(C(a) + lambda*T(a) + mu*R(a), epsilon)

That equation has been specified in the mission's mathematics since the preregistration but had not
been implemented before this candidate. Amendment 005 substitutes a single frozen constant,
`TARGETED_TEST_ACTION = (100,)*8`, for the entire argmax. Under the graded laboratory that constant
is provably wrong: a command above the deadband threshold passes unattenuated, so the largest
available probe is structurally blind to `actuator_deadband` and scores zero on it.

Severity is latent
------------------
A hypothesis is a (mechanism, severity) pair, not a mechanism alone. A method does not know how
severe a fault is, and severity is precisely what determines which probe can see it: the deadband
threshold is proportional to severity, so a command that reveals the mechanism at one magnitude
is blind to it at another. Passing the true severity to a method's forward model would hand it
half the answer and would also destroy the selection problem, because the optimal probe would
then be the same in every episode.

Marginalizing severity is what makes selection adaptive. The free no-op constrains severity for
the mechanisms visible at rest, the posterior therefore differs across episodes, and the action
worth buying next depends on which (mechanism, severity) pairs remain live.

Why selection is a real problem here
------------------------------------
In the graded laboratory no single action resolves every hypothesis pair, and the requirements
run in opposite directions:

  * separating `actuator_deadband` from nominal needs a command *below* the deadband threshold;
    above it, the mechanism is invisible and the pairwise separability index is exactly zero.
  * separating `actuator_deadband` from `actuator_loss` needs a command *above* the threshold;
    below it, both suppress drive and their signatures nearly coincide.

So a fixed policy must either miss a fault class or pay for every probe. The scientific question
is therefore not "does probing help" -- that is a theorem, settled by Campbell and Nikoukhah
(2004) and by the interventional-identifiability results of Eberhardt (2005) and Hauser and
Buehlmann (2012) -- but "what is the cheapest action set that resolves the hypotheses still
live." That is the open question, and it is the one the denominator above encodes.

Determinism
-----------
Information gain is estimated by marginalizing over a fixed, seed-derived set of disturbance
draws. The draw schedule is frozen in `EIG_DRAW_SEEDS`, so a selection is a pure function of the
posterior, the catalog, and the weights. Entropy is computed in `Decimal` so the selected action
is identical on every platform in the test matrix.
"""

from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal, getcontext
from typing import Final, Literal, Self

from pydantic import Field, model_validator

from fieldtrue.canonical import sha256_value
from fieldtrue.causal_laboratory import UNKNOWN_MECHANISM_KEY
from fieldtrue.domain import FrozenModel, Identifier
from fieldtrue.graded_laboratory import (
    GradedFaultConfig,
    graded_forward_telemetry,
    graded_run,
)

# --- Amendment 006 historical linkage --------------------------------------------------
#
# These identifiers retain the intended A006 linkage. Amendment 006's bound source hash never
# matched a committed version of this module, so its owner-signature receipt does not cover this
# implementation. The implementation also preceded the proposal, making the design outcome-informed;
# no result produced against it may be reported as prospective.

AMENDMENT_ID: Final = "iter001_006"
APPROVED_PROPOSAL_COMMIT: Final = "dab4ba9f8eb967e1eceb70feaecc5262882cbde0"
AMENDMENT_DOCUMENT_SHA256: Final = (
    "266d68f0f28b6474fbb09f971904bef394f8c1315b6fcb388eba88c4d0d5a741"
)
MACHINE_PROPOSAL_SHA256: Final = "2e13e80a661166a5b527af853e0016b0b61dfb672d3234d62e19a9b5752e6052"
OWNER_APPROVAL_RECEIPT_HASH: Final = (
    "cb0f25535691655ec9750f684c37fcb821e9a88c2c1e42c95b153fa22748d33d"
)


getcontext().prec = 40

_METRIC: Final = Decimal("0.000001")


def _fmt(value: Decimal) -> str:
    return str(value.quantize(_METRIC, rounding=ROUND_HALF_EVEN))


class ActiveSelectionError(ValueError):
    """An action catalog, cost weight, hypothesis space, or posterior is invalid."""


# --- The hypothesis space --------------------------------------------------------------

# The severity bands a method carries. Coarse on purpose: a method is not required to estimate a
# continuous magnitude, only to carry enough resolution that the optimal probe differs across
# bands. The true severity of an episode need not lie in this set, which is the ordinary
# condition of a discretized hypothesis space and a source of honest model error.
SEVERITY_BANDS: Final[tuple[int, ...]] = (30, 65, 100)


class Hypothesis(FrozenModel):
    """One candidate explanation: a mechanism at a severity band.

    The reserved unknown carries severity zero. Grading does not make an unmodeled departure
    larger, so the unknown appears exactly once in a hypothesis space rather than once per band.
    """

    schema_version: Literal["inbar.iter001.selection-hypothesis.v1"] = (
        "inbar.iter001.selection-hypothesis.v1"
    )
    mechanism_key: str = Field(min_length=1)
    severity: int = Field(ge=0, le=100)

    @property
    def label(self) -> str:
        return f"{self.mechanism_key}:{self.severity}"


def build_hypothesis_space(
    mechanism_keys: tuple[str, ...], bands: tuple[int, ...] = SEVERITY_BANDS
) -> tuple[Hypothesis, ...]:
    """Every known mechanism at every severity band, plus the reserved unknown once."""
    if not mechanism_keys:
        raise ActiveSelectionError("a hypothesis space needs at least one mechanism")
    if not bands:
        raise ActiveSelectionError("a hypothesis space needs at least one severity band")
    out = [
        Hypothesis(mechanism_key=key, severity=band)
        for key in sorted(mechanism_keys)
        for band in sorted(bands)
    ]
    out.append(Hypothesis(mechanism_key=UNKNOWN_MECHANISM_KEY, severity=0))
    return tuple(out)


# --- The action catalog ----------------------------------------------------------------


class ActionCandidate(FrozenModel):
    """One executable test, with its declared cost, time, and risk.

    Every term is in one declared cost unit, per the mathematics contract: `time_seconds` is
    converted by `time_weight` and `risk_units` by `risk_weight`, so the denominator is
    dimensionally homogeneous. `safe` records the safety authority's verdict; an unsafe action is
    ineligible regardless of how much information it would yield, and is never scored.
    """

    schema_version: Literal["inbar.iter001.action-candidate.v1"] = (
        "inbar.iter001.action-candidate.v1"
    )
    action_id: Identifier
    action: tuple[int, ...] = Field(min_length=1)
    direct_cost: int = Field(ge=0)
    time_seconds: int = Field(ge=0)
    risk_units: int = Field(ge=0)
    safe: bool

    @property
    def action_sha256(self) -> str:
        return sha256_value({"schema_version": self.schema_version, "u": list(self.action)})


class PlannerWeights(FrozenModel):
    """The frozen cost weights and denominator floor.

    These must be frozen before outcome inspection. The defaults specify numerical behavior only
    and are not a claim that this is the correct operating point for any physical system.
    """

    schema_version: Literal["inbar.iter001.planner-weights.v1"] = "inbar.iter001.planner-weights.v1"
    time_weight: str = Field(default="1.000000", pattern=r"^[0-9]+\.[0-9]{6}$")
    risk_weight: str = Field(default="10.000000", pattern=r"^[0-9]+\.[0-9]{6}$")
    denominator_floor: str = Field(default="0.000001", pattern=r"^[0-9]+\.[0-9]{6}$")

    def generalized_cost(self, candidate: ActionCandidate) -> Decimal:
        """C(a) + lambda*T(a) + mu*R(a), floored so a free action cannot divide by zero."""
        total = (
            Decimal(candidate.direct_cost)
            + Decimal(self.time_weight) * Decimal(candidate.time_seconds)
            + Decimal(self.risk_weight) * Decimal(candidate.risk_units)
        )
        floor = Decimal(self.denominator_floor)
        return total if total > floor else floor


# The reference catalog. Risk rises with commanded amplitude: a larger excitation moves the plant
# further from its nominal operating point, which is what makes "use the biggest probe" a costly
# strategy rather than a free one. The no-op is free and carries no risk. The small-amplitude
# probes exist because the deadband threshold falls with severity, so a mild fault can only be
# seen by a command milder still.
REFERENCE_CATALOG: Final[tuple[ActionCandidate, ...]] = (
    ActionCandidate(
        action_id="no-op", action=(0,) * 8, direct_cost=0, time_seconds=0, risk_units=0, safe=True
    ),
    ActionCandidate(
        action_id="probe-10",
        action=(10,) * 8,
        direct_cost=1,
        time_seconds=2,
        risk_units=1,
        safe=True,
    ),
    ActionCandidate(
        action_id="probe-20",
        action=(20,) * 8,
        direct_cost=1,
        time_seconds=2,
        risk_units=1,
        safe=True,
    ),
    ActionCandidate(
        action_id="probe-40",
        action=(40,) * 8,
        direct_cost=1,
        time_seconds=2,
        risk_units=2,
        safe=True,
    ),
    ActionCandidate(
        action_id="probe-60",
        action=(60,) * 8,
        direct_cost=2,
        time_seconds=3,
        risk_units=4,
        safe=True,
    ),
    ActionCandidate(
        action_id="probe-100",
        action=(100,) * 8,
        direct_cost=2,
        time_seconds=3,
        risk_units=8,
        safe=True,
    ),
    # Retained in the catalog and never scored: the selector must demonstrably refuse an
    # out-of-envelope action rather than silently omit it from consideration.
    ActionCandidate(
        action_id="probe-overdrive",
        action=(400,) * 8,
        direct_cost=2,
        time_seconds=3,
        risk_units=90,
        safe=False,
    ),
)


# --- Posterior and entropy --------------------------------------------------------------

LIKELIHOOD_SCALE: Final = Decimal(4)

# The frozen disturbance-draw schedule used to marginalize predicted observations. Fixed so that
# information gain is a deterministic function of its inputs.
EIG_DRAW_SEEDS: Final[tuple[int, ...]] = (11, 23, 37, 51, 67, 83, 97, 113)


class HypothesisPosterior(FrozenModel):
    """A normalized posterior over hypothesis labels, including the reserved unknown."""

    schema_version: Literal["inbar.iter001.hypothesis-posterior.v1"] = (
        "inbar.iter001.hypothesis-posterior.v1"
    )
    weights: dict[str, str]

    @model_validator(mode="after")
    def weights_are_a_distribution(self) -> Self:
        if len(self.weights) < 2:
            raise ValueError("a posterior must carry at least two hypotheses")
        total = sum(Decimal(v) for v in self.weights.values())
        if not (Decimal("0.999") <= total <= Decimal("1.001")):
            raise ValueError("posterior weights must sum to one")
        return self

    def as_decimal(self) -> dict[str, Decimal]:
        return {k: Decimal(v) for k, v in self.weights.items()}


def uniform_prior(space: tuple[Hypothesis, ...]) -> dict[str, Decimal]:
    share = Decimal(1) / Decimal(len(space))
    return {h.label: share for h in space}


def _entropy(weights: dict[str, Decimal]) -> Decimal:
    """Shannon entropy in nats. Zero-mass hypotheses contribute nothing."""
    total = Decimal(0)
    for value in weights.values():
        if value > 0:
            total -= value * value.ln()
    return total


def posterior_from_residuals(residuals: dict[str, int]) -> dict[str, Decimal]:
    """Exponential likelihood in the summed absolute residual, normalized."""
    if not residuals:
        raise ActiveSelectionError("a posterior needs at least one residual")
    smallest = min(residuals.values())
    # Shift by the minimum before exponentiating so a large residual cannot underflow to zero
    # mass for every hypothesis at once. Shifting is a common factor and cancels in the ratio.
    raw = {
        k: (-(Decimal(v) - Decimal(smallest)) / LIKELIHOOD_SCALE).exp()
        for k, v in residuals.items()
    }
    total = sum(raw.values(), start=Decimal(0))
    return {k: v / total for k, v in raw.items()}


# The forward model is a pure function of its arguments, and the selector evaluates it once per
# (hypothesis, action) for every draw and every candidate. Memoizing it keeps the enlarged
# hypothesis space tractable without changing a single result.
_FORWARD_CACHE: dict[tuple[str, int, str, int, tuple[int, ...]], tuple[int, ...]] = {}


def _forward(
    *,
    config: GradedFaultConfig,
    initial_state: int,
    mechanism_key: str,
    severity: int,
    action: tuple[int, ...],
) -> tuple[int, ...]:
    key = (config.config_sha256, initial_state, mechanism_key, severity, action)
    hit = _FORWARD_CACHE.get(key)
    if hit is None:
        hit = graded_forward_telemetry(
            config=config,
            initial_state=initial_state,
            mechanism_key=mechanism_key,
            severity=severity,
            action=action,
        )
        _FORWARD_CACHE[key] = hit
    return hit


def residuals_for(
    *,
    observed: tuple[int, ...],
    action: tuple[int, ...],
    space: tuple[Hypothesis, ...],
    config: GradedFaultConfig,
    initial_state: int,
) -> dict[str, int]:
    """Summed absolute residual of every hypothesis in the space against one observation."""
    out: dict[str, int] = {}
    for hypothesis in space:
        predicted = _forward(
            config=config,
            initial_state=initial_state,
            mechanism_key=hypothesis.mechanism_key,
            severity=hypothesis.severity,
            action=action,
        )
        out[hypothesis.label] = sum(abs(o - p) for o, p in zip(observed, predicted, strict=True))
    return out


# --- Expected information gain ----------------------------------------------------------


def expected_information_gain(
    *,
    candidate: ActionCandidate,
    prior: dict[str, Decimal],
    space: tuple[Hypothesis, ...],
    config: GradedFaultConfig,
    initial_state: int,
) -> Decimal:
    """I(H; Y_a | E) in nats, marginalized over the frozen disturbance-draw schedule.

    For each hypothesis weighted by its prior, the action's outcome is simulated under every
    frozen draw, the posterior that outcome would induce is computed, and its entropy is averaged.
    The gain is the prior entropy minus that expected posterior entropy. It is non-negative up to
    the discretization of the draw schedule.

    The simulation uses the *true* plant, including the curvature term and nuisance offset the
    method does not model. This is deliberate: the planner is estimating what it would actually
    observe, and a planner that assumed its own forward model were exact would systematically
    overestimate how much every action tells it.
    """
    by_label = {h.label: h for h in space}
    prior_entropy = _entropy(prior)
    expected_posterior_entropy = Decimal(0)

    for label, mass in prior.items():
        if mass <= 0:
            continue
        hypothesis = by_label.get(label)
        if hypothesis is None:
            raise ActiveSelectionError("prior carries a label absent from the hypothesis space")
        per_draw_total = Decimal(0)
        for seed in EIG_DRAW_SEEDS:
            _, observed = graded_run(
                config=config,
                initial_state=initial_state,
                seed=seed,
                mechanism_key=hypothesis.mechanism_key,
                severity=hypothesis.severity,
                action=candidate.action,
            )
            likelihood = posterior_from_residuals(
                residuals_for(
                    observed=observed,
                    action=candidate.action,
                    space=space,
                    config=config,
                    initial_state=initial_state,
                )
            )
            combined = {k: prior[k] * likelihood[k] for k in prior}
            total = sum(combined.values(), start=Decimal(0))
            if total <= 0:
                continue
            per_draw_total += _entropy({k: v / total for k, v in combined.items()})
        expected_posterior_entropy += mass * (per_draw_total / Decimal(len(EIG_DRAW_SEEDS)))

    gain = prior_entropy - expected_posterior_entropy
    return gain if gain > 0 else Decimal(0)


# --- Selection -------------------------------------------------------------------------


class ActionScore(FrozenModel):
    """One scored candidate. Refused actions are scored as refused, never silently dropped."""

    schema_version: Literal["inbar.iter001.action-score.v1"] = "inbar.iter001.action-score.v1"
    action_id: Identifier
    action_sha256: str
    eligible: bool
    refusal_reason: str | None
    information_gain_nats: str
    generalized_cost: str
    score: str


class SelectionResult(FrozenModel):
    """The selected action and the complete scored catalog that justified it."""

    schema_version: Literal["inbar.iter001.selection-result.v1"] = (
        "inbar.iter001.selection-result.v1"
    )
    selected_action_id: Identifier
    selected_action_sha256: str
    scores: tuple[ActionScore, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def selection_is_an_eligible_scored_candidate(self) -> Self:
        chosen = [s for s in self.scores if s.action_id == self.selected_action_id]
        if not chosen:
            raise ValueError("the selected action is absent from the scored catalog")
        if not chosen[0].eligible:
            raise ValueError("the selected action was not eligible")
        if chosen[0].action_sha256 != self.selected_action_sha256:
            raise ValueError("the selected action hash does not match its scored candidate")
        return self


def select_action(
    *,
    catalog: tuple[ActionCandidate, ...],
    prior: dict[str, Decimal],
    space: tuple[Hypothesis, ...],
    weights: PlannerWeights,
    config: GradedFaultConfig,
    initial_state: int,
) -> SelectionResult:
    """Select the highest information-gain-per-unit-cost action inside the safety envelope.

    An unsafe action is recorded with its refusal reason and never scored for selection, so a
    refused action is auditable as refused rather than absent. Ties break on the action hash, so
    selection is deterministic and independent of catalog ordering.
    """
    if not catalog:
        raise ActiveSelectionError("selection needs a non-empty action catalog")
    if len(prior) < 2:
        raise ActiveSelectionError("selection needs at least two live hypotheses")

    scores: list[ActionScore] = []
    for candidate in catalog:
        if not candidate.safe:
            scores.append(
                ActionScore(
                    action_id=candidate.action_id,
                    action_sha256=candidate.action_sha256,
                    eligible=False,
                    refusal_reason="outside the frozen safety envelope",
                    information_gain_nats=_fmt(Decimal(0)),
                    generalized_cost=_fmt(weights.generalized_cost(candidate)),
                    score=_fmt(Decimal(0)),
                )
            )
            continue
        gain = expected_information_gain(
            candidate=candidate,
            prior=prior,
            space=space,
            config=config,
            initial_state=initial_state,
        )
        cost = weights.generalized_cost(candidate)
        scores.append(
            ActionScore(
                action_id=candidate.action_id,
                action_sha256=candidate.action_sha256,
                eligible=True,
                refusal_reason=None,
                information_gain_nats=_fmt(gain),
                generalized_cost=_fmt(cost),
                score=_fmt(gain / cost),
            )
        )

    eligible = [s for s in scores if s.eligible]
    if not eligible:
        raise ActiveSelectionError("no eligible action remains inside the safety envelope")
    best = max(eligible, key=lambda s: (Decimal(s.score), s.action_sha256))
    return SelectionResult(
        selected_action_id=best.action_id,
        selected_action_sha256=best.action_sha256,
        scores=tuple(scores),
    )


def update_posterior(
    *,
    prior: dict[str, Decimal],
    observed: tuple[int, ...],
    action: tuple[int, ...],
    space: tuple[Hypothesis, ...],
    config: GradedFaultConfig,
    initial_state: int,
) -> dict[str, Decimal]:
    """Fold one executed action's telemetry into the posterior."""
    likelihood = posterior_from_residuals(
        residuals_for(
            observed=observed,
            action=action,
            space=space,
            config=config,
            initial_state=initial_state,
        )
    )
    combined = {k: prior[k] * likelihood[k] for k in prior}
    total = sum(combined.values(), start=Decimal(0))
    if total <= 0:
        raise ActiveSelectionError("posterior update produced zero total mass")
    return {k: v / total for k, v in combined.items()}


def marginal_over_mechanism(
    posterior: dict[str, Decimal], space: tuple[Hypothesis, ...]
) -> dict[str, Decimal]:
    """Sum severity bands out of the posterior, leaving mass per mechanism.

    A diagnosis names a mechanism. Severity is a nuisance the method must reason about but is not
    asked to report, so it is marginalized rather than argmaxed jointly: a mechanism supported
    diffusely across several bands should not lose to one supported sharply at a single band.
    """
    by_label = {h.label: h for h in space}
    out: dict[str, Decimal] = {}
    for label, mass in posterior.items():
        hypothesis = by_label.get(label)
        if hypothesis is None:
            raise ActiveSelectionError("posterior carries a label absent from the space")
        out[hypothesis.mechanism_key] = out.get(hypothesis.mechanism_key, Decimal(0)) + mass
    return out


def committed_diagnosis(
    posterior: dict[str, Decimal],
    space: tuple[Hypothesis, ...],
    confidence_floor: Decimal,
) -> tuple[str, bool]:
    """Name the most probable mechanism, or abstain to the reserved unknown below the floor.

    Abstention is a first-class outcome: below the floor the honest answer is that the evidence
    did not resolve the question, which is different from concluding the mechanism is unmodeled.
    """
    marginal = marginal_over_mechanism(posterior, space)
    best = max(sorted(marginal), key=lambda k: marginal[k])
    if marginal[best] < confidence_floor:
        return UNKNOWN_MECHANISM_KEY, True
    return best, False
