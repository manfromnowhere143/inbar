"""Adversarial controls for cost-aware active test selection.

A selection rule is only evidence if it cannot quietly cheat. That value is destroyed if an action
outside the safety envelope can be chosen or can vanish from the record, if information gain can
exceed what the prior actually contains, if selection depends on the order a catalog happens to be
written in, if the memoized forward model returns something the unmemoized one would not, or if a
posterior stops being a distribution. Each control below pins one of those failures shut.

These controls verify internal validity only. The selector is an implemented comparison arm, not a
recommended method: a classical set-based rule matched it at equal accuracy and lower cost. Nothing
here asserts anything about the physical world.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import ValidationError

from fieldtrue.active_selection import (
    EIG_DRAW_SEEDS,
    REFERENCE_CATALOG,
    ActionCandidate,
    ActionScore,
    ActiveSelectionError,
    Hypothesis,
    PlannerWeights,
    SelectionResult,
    build_hypothesis_space,
    committed_diagnosis,
    expected_information_gain,
    marginal_over_mechanism,
    posterior_from_residuals,
    residuals_for,
    select_action,
    uniform_prior,
    update_posterior,
)
from fieldtrue.causal_laboratory import UNKNOWN_MECHANISM_KEY
from fieldtrue.graded_laboratory import (
    GRADED_CONFIG,
    GRADED_INITIAL_STATE,
    GRADED_ONTOLOGY,
    graded_run,
)

_BY_NAME = {c.name: c.key for c in GRADED_ONTOLOGY.classes}
ACTUATOR_LOSS = _BY_NAME["actuator_loss"]
ACTUATOR_DEADBAND = _BY_NAME["actuator_deadband"]
MECHANISMS = tuple(sorted(GRADED_ONTOLOGY.known_keys))
SPACE = build_hypothesis_space(MECHANISMS)
BY_ID = {c.action_id: c for c in REFERENCE_CATALOG}
SAFE_PROBES = tuple(c for c in REFERENCE_CATALOG if c.safe and c.action_id != "no-op")
LN2 = Decimal(2).ln()


def _observe(key: str, severity: int, action: tuple[int, ...], seed: int = 7) -> tuple[int, ...]:
    _, telemetry = graded_run(
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
        seed=seed,
        mechanism_key=key,
        severity=severity,
        action=action,
    )
    return telemetry


def _eig(candidate: ActionCandidate, prior: dict[str, Decimal]) -> Decimal:
    return expected_information_gain(
        candidate=candidate,
        prior=prior,
        space=SPACE,
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
    )


# --- The hypothesis space --------------------------------------------------------------


def test_unknown_appears_exactly_once_regardless_of_band_count() -> None:
    """Grading does not make an unmodeled departure larger, so it must not be duplicated."""
    for bands in ((30,), (30, 65), (10, 30, 65, 100)):
        space = build_hypothesis_space(MECHANISMS, bands)
        unknowns = [h for h in space if h.mechanism_key == UNKNOWN_MECHANISM_KEY]
        assert len(unknowns) == 1
        assert unknowns[0].severity == 0
        assert len(space) == len(MECHANISMS) * len(bands) + 1


def test_hypothesis_space_refuses_degenerate_inputs() -> None:
    with pytest.raises(ActiveSelectionError):
        build_hypothesis_space((), (30,))
    with pytest.raises(ActiveSelectionError):
        build_hypothesis_space(MECHANISMS, ())


def test_hypothesis_labels_are_unique() -> None:
    labels = [h.label for h in SPACE]
    assert len(set(labels)) == len(labels)


# --- The safety envelope is a hard constraint ------------------------------------------


def test_unsafe_action_is_recorded_as_refused_and_never_selected() -> None:
    """A refused action must be auditable as refused rather than absent from the record."""
    result = select_action(
        catalog=REFERENCE_CATALOG,
        prior=uniform_prior(SPACE),
        space=SPACE,
        weights=PlannerWeights(),
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
    )
    refused = [s for s in result.scores if not s.eligible]
    assert refused, "the unsafe candidate vanished from the scored catalog"
    assert all(s.refusal_reason for s in refused)
    assert result.selected_action_id not in {s.action_id for s in refused}


def test_selection_fails_closed_when_every_action_is_unsafe() -> None:
    """No eligible action must raise, never fall back to an out-of-envelope action."""
    unsafe_only = tuple(c for c in REFERENCE_CATALOG if not c.safe)
    with pytest.raises(ActiveSelectionError):
        select_action(
            catalog=unsafe_only,
            prior=uniform_prior(SPACE),
            space=SPACE,
            weights=PlannerWeights(),
            config=GRADED_CONFIG,
            initial_state=GRADED_INITIAL_STATE,
        )


def test_a_result_cannot_name_an_ineligible_action_as_selected() -> None:
    """The contract itself must reject a result that selected a refused candidate."""
    refused = ActionScore(
        action_id="probe-overdrive",
        action_sha256=BY_ID["probe-overdrive"].action_sha256,
        eligible=False,
        refusal_reason="outside the frozen safety envelope",
        information_gain_nats="0.000000",
        generalized_cost="1.000000",
        score="0.000000",
    )
    with pytest.raises(ValidationError):
        SelectionResult(
            selected_action_id="probe-overdrive",
            selected_action_sha256=refused.action_sha256,
            scores=(refused,),
        )


def test_selection_refuses_an_empty_catalog_or_a_single_hypothesis() -> None:
    with pytest.raises(ActiveSelectionError):
        select_action(
            catalog=(),
            prior=uniform_prior(SPACE),
            space=SPACE,
            weights=PlannerWeights(),
            config=GRADED_CONFIG,
            initial_state=GRADED_INITIAL_STATE,
        )
    with pytest.raises(ActiveSelectionError):
        select_action(
            catalog=SAFE_PROBES,
            prior={"only:100": Decimal(1)},
            space=SPACE,
            weights=PlannerWeights(),
            config=GRADED_CONFIG,
            initial_state=GRADED_INITIAL_STATE,
        )


# --- Information gain is bounded and lands on the analytic value ----------------------


def test_a_no_op_yields_no_information_on_a_pair_it_cannot_separate() -> None:
    """A parameter multiplying the input tells you nothing when the input is zero."""
    prior = {
        Hypothesis(mechanism_key=ACTUATOR_LOSS, severity=100).label: Decimal("0.5"),
        Hypothesis(mechanism_key=UNKNOWN_MECHANISM_KEY, severity=0).label: Decimal("0.5"),
    }
    assert _eig(BY_ID["no-op"], prior) == Decimal(0)


def test_a_separating_probe_reaches_the_analytic_bound_on_a_two_hypothesis_prior() -> None:
    """Maximum information from a uniform binary prior is exactly ln(2); nothing may exceed it."""
    prior = {
        Hypothesis(mechanism_key=ACTUATOR_LOSS, severity=100).label: Decimal("0.5"),
        Hypothesis(mechanism_key=ACTUATOR_DEADBAND, severity=100).label: Decimal("0.5"),
    }
    gain = _eig(BY_ID["probe-100"], prior)
    assert gain <= LN2 + Decimal("0.000001")
    assert gain > LN2 - Decimal("0.01")


def test_information_gain_never_exceeds_the_prior_entropy() -> None:
    """An action cannot reveal more than the prior contained, for any action in the catalog."""
    prior = uniform_prior(SPACE)
    ceiling = Decimal(len(SPACE)).ln()
    for candidate in SAFE_PROBES:
        assert _eig(candidate, prior) <= ceiling + Decimal("0.000001")


def test_information_gain_is_never_negative() -> None:
    prior = uniform_prior(SPACE)
    for candidate in SAFE_PROBES:
        assert _eig(candidate, prior) >= Decimal(0)


def test_information_gain_rejects_a_prior_outside_the_space() -> None:
    with pytest.raises(ActiveSelectionError):
        _eig(BY_ID["probe-100"], {"not-a-real-label": Decimal(1), "nor-this": Decimal(0)})


def test_draw_schedule_is_frozen_and_nonempty() -> None:
    """Information gain is only reproducible if its marginalization schedule is fixed."""
    assert len(EIG_DRAW_SEEDS) > 1
    assert len(set(EIG_DRAW_SEEDS)) == len(EIG_DRAW_SEEDS)


# --- Determinism and order independence ------------------------------------------------


def test_selection_is_independent_of_catalog_order() -> None:
    """A selection that depends on write order is not a rule, it is an accident."""
    prior = uniform_prior(SPACE)
    kwargs = {
        "prior": prior,
        "space": SPACE,
        "weights": PlannerWeights(),
        "config": GRADED_CONFIG,
        "initial_state": GRADED_INITIAL_STATE,
    }
    forward = select_action(catalog=SAFE_PROBES, **kwargs)
    reverse = select_action(catalog=tuple(reversed(SAFE_PROBES)), **kwargs)
    assert forward.selected_action_id == reverse.selected_action_id


def test_selection_is_reproducible() -> None:
    kwargs = {
        "catalog": SAFE_PROBES,
        "prior": uniform_prior(SPACE),
        "space": SPACE,
        "weights": PlannerWeights(),
        "config": GRADED_CONFIG,
        "initial_state": GRADED_INITIAL_STATE,
    }
    assert select_action(**kwargs) == select_action(**kwargs)


def test_memoized_forward_model_agrees_with_a_cold_computation() -> None:
    """The cache is an optimization; it must not be able to change a single residual."""
    from fieldtrue import active_selection

    observed = _observe(ACTUATOR_LOSS, 100, BY_ID["probe-60"].action)
    warm = residuals_for(
        observed=observed,
        action=BY_ID["probe-60"].action,
        space=SPACE,
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
    )
    active_selection._FORWARD_CACHE.clear()
    cold = residuals_for(
        observed=observed,
        action=BY_ID["probe-60"].action,
        space=SPACE,
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
    )
    assert warm == cold


# --- The cost model --------------------------------------------------------------------


def test_generalized_cost_combines_every_declared_term() -> None:
    weights = PlannerWeights(time_weight="2.000000", risk_weight="3.000000")
    candidate = ActionCandidate(
        action_id="probe-x", action=(1,), direct_cost=5, time_seconds=7, risk_units=11, safe=True
    )
    assert weights.generalized_cost(candidate) == Decimal(5 + 2 * 7 + 3 * 11)


def test_a_free_action_is_floored_rather_than_dividing_by_zero() -> None:
    weights = PlannerWeights()
    free = ActionCandidate(
        action_id="free", action=(0,), direct_cost=0, time_seconds=0, risk_units=0, safe=True
    )
    assert weights.generalized_cost(free) == Decimal(weights.denominator_floor)


def test_raising_the_risk_weight_raises_the_cost_of_a_risky_action() -> None:
    """Without this the denominator is inert and the largest probe wins by default."""
    risky = BY_ID["probe-100"]
    cheap = PlannerWeights(risk_weight="1.000000").generalized_cost(risky)
    dear = PlannerWeights(risk_weight="50.000000").generalized_cost(risky)
    assert dear > cheap


# --- Posteriors stay distributions ------------------------------------------------------


def test_posterior_from_residuals_normalizes() -> None:
    posterior = posterior_from_residuals({"a": 0, "b": 12, "c": 400})
    assert sum(posterior.values()) == pytest.approx(Decimal(1), abs=Decimal("0.000001"))
    assert posterior["a"] > posterior["b"] > posterior["c"]


def test_posterior_survives_residuals_large_enough_to_underflow() -> None:
    """Shifting by the minimum residual is what stops every hypothesis collapsing to zero mass."""
    posterior = posterior_from_residuals({"a": 10_000_000, "b": 10_000_004})
    assert sum(posterior.values()) == pytest.approx(Decimal(1), abs=Decimal("0.000001"))
    assert posterior["a"] > posterior["b"]


def test_posterior_from_residuals_refuses_an_empty_input() -> None:
    with pytest.raises(ActiveSelectionError):
        posterior_from_residuals({})


def test_update_preserves_normalization() -> None:
    prior = uniform_prior(SPACE)
    observed = _observe(ACTUATOR_LOSS, 100, BY_ID["probe-60"].action)
    posterior = update_posterior(
        prior=prior,
        observed=observed,
        action=BY_ID["probe-60"].action,
        space=SPACE,
        config=GRADED_CONFIG,
        initial_state=GRADED_INITIAL_STATE,
    )
    assert sum(posterior.values()) == pytest.approx(Decimal(1), abs=Decimal("0.000001"))


def test_marginalizing_severity_preserves_total_mass() -> None:
    """A mechanism supported diffusely across bands must not lose mass in the marginal."""
    prior = uniform_prior(SPACE)
    marginal = marginal_over_mechanism(prior, SPACE)
    assert sum(marginal.values()) == pytest.approx(Decimal(1), abs=Decimal("0.000001"))
    assert set(marginal) == {*MECHANISMS, UNKNOWN_MECHANISM_KEY}


def test_marginal_rejects_a_label_outside_the_space() -> None:
    with pytest.raises(ActiveSelectionError):
        marginal_over_mechanism({"ghost:50": Decimal(1)}, SPACE)


# --- Abstention is a first-class outcome ------------------------------------------------


def test_a_flat_posterior_abstains_to_the_reserved_unknown() -> None:
    """Below the floor the honest answer is that the evidence did not resolve the question."""
    key, abstained = committed_diagnosis(uniform_prior(SPACE), SPACE, Decimal("0.600000"))
    assert abstained
    assert key == UNKNOWN_MECHANISM_KEY


def test_a_concentrated_posterior_commits() -> None:
    concentrated = dict.fromkeys((h.label for h in SPACE), Decimal(0))
    concentrated[Hypothesis(mechanism_key=ACTUATOR_LOSS, severity=100).label] = Decimal(1)
    key, abstained = committed_diagnosis(concentrated, SPACE, Decimal("0.600000"))
    assert not abstained
    assert key == ACTUATOR_LOSS


def test_diffuse_support_across_bands_still_commits_to_the_mechanism() -> None:
    """Marginalizing rather than jointly argmaxing is what makes this pass."""
    spread = dict.fromkeys((h.label for h in SPACE), Decimal(0))
    for band in (30, 65, 100):
        spread[Hypothesis(mechanism_key=ACTUATOR_LOSS, severity=band).label] = Decimal("0.3")
    spread[Hypothesis(mechanism_key=UNKNOWN_MECHANISM_KEY, severity=0).label] = Decimal("0.1")
    key, abstained = committed_diagnosis(spread, SPACE, Decimal("0.600000"))
    assert not abstained
    assert key == ACTUATOR_LOSS
