from __future__ import annotations

import pytest

from fieldtrue.domain import PlannerWeights
from fieldtrue.planning import (
    NoEligibleTestError,
    NonDiscriminatingTestError,
    entropy_bits,
    expected_information_gain_bits,
    posterior_after_observation,
    select_discriminating_test,
)
from tests.helpers import envelope, hypotheses, informative_test, sham_test


def test_information_gain_prefers_semantically_informative_test_over_placebo() -> None:
    hypothesis_set = hypotheses()
    informative = informative_test()
    sham = sham_test()
    selected = select_discriminating_test(
        hypothesis_set,
        (sham, informative),
        envelope(sham.test_id, informative.test_id),
    )
    assert selected.test_id == informative.test_id
    assert selected.expected_information_gain_bits > 0
    assert expected_information_gain_bits(selected.posterior_before, sham) == pytest.approx(0)


def test_unsafe_or_unapproved_tests_are_ineligible() -> None:
    unsafe = informative_test(test_id="unsafe", risk=0.9)
    denied = informative_test(test_id="denied", approved=False)
    with pytest.raises(NoEligibleTestError):
        select_discriminating_test(
            hypotheses(),
            (unsafe, denied),
            envelope("unsafe", "denied", max_risk=0.2),
        )


def test_missing_precondition_fails_closed() -> None:
    candidate = informative_test()
    safe = envelope(candidate.test_id).model_copy(update={"satisfied_preconditions": ()})
    with pytest.raises(NoEligibleTestError):
        select_discriminating_test(hypotheses(), (candidate,), safe)


def test_zero_information_test_cannot_be_selected() -> None:
    sham = sham_test()
    with pytest.raises(NonDiscriminatingTestError):
        select_discriminating_test(hypotheses(), (sham,), envelope(sham.test_id))


def test_posterior_update_and_entropy() -> None:
    test = informative_test()
    prior = {item.hypothesis_id: item.prior for item in hypotheses().hypotheses}
    posterior = posterior_after_observation(prior, test, "voltage-recovers")
    assert sum(posterior.values()) == pytest.approx(1)
    assert posterior["power-open"] > prior["power-open"]
    assert entropy_bits(posterior) < entropy_bits(prior)
    with pytest.raises(ValueError, match="unknown or duplicate"):
        posterior_after_observation(prior, test, "not-registered")


def test_denominator_floor_handles_free_replay() -> None:
    candidate = informative_test().model_copy(
        update={"cost_units": 0.0, "duration_seconds": 0.0, "risk": 0.0}
    )
    selected = select_discriminating_test(
        hypotheses(),
        (candidate,),
        envelope(candidate.test_id),
        weights=PlannerWeights(time_weight=0, risk_weight=0, denominator_floor=0.01),
    )
    assert selected.denominator == 0.01


def test_probability_and_model_mismatches_fail_closed() -> None:
    candidate = informative_test()
    with pytest.raises(ValueError, match="cannot be empty"):
        entropy_bits({})
    with pytest.raises(ValueError, match="finite and non-negative"):
        entropy_bits({"a": -1, "b": 2})
    with pytest.raises(ValueError, match="mass must be positive"):
        entropy_bits({"a": 0, "b": 0})
    with pytest.raises(ValueError, match="test/hypothesis mismatch"):
        expected_information_gain_bits({"unmodeled": 1}, candidate)
    with pytest.raises(ValueError, match="current hypothesis set"):
        posterior_after_observation(
            {"power-open": 0.5, "sensor-bias": 0.5},
            candidate,
            "voltage-recovers",
        )
