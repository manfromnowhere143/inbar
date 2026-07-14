from __future__ import annotations

import pytest

from fieldtrue.diagnosis import bayesian_update
from tests.helpers import hypotheses


def test_bayesian_update_preserves_unknown_and_normalizes() -> None:
    updated = bayesian_update(
        hypotheses(),
        {"power-open": 0.8, "sensor-bias": 0.1, "unknown": 0.4},
        evidence_id="voltage-evidence",
    )
    priors = {item.hypothesis_id: item.prior for item in updated.hypotheses}
    assert sum(priors.values()) == pytest.approx(1)
    assert priors["power-open"] > priors["sensor-bias"]
    assert sum(item.unknown for item in updated.hypotheses) == 1


@pytest.mark.parametrize(
    ("likelihoods", "message"),
    [
        ({"power-open": 0.8, "sensor-bias": 0.1}, "exactly match"),
        (
            {"power-open": -1, "sensor-bias": 0.1, "unknown": 0.1},
            "finite and non-negative",
        ),
        (
            {"power-open": 0, "sensor-bias": 0, "unknown": 0},
            "zero probability",
        ),
    ],
)
def test_bayesian_update_rejects_invalid_likelihoods(
    likelihoods: dict[str, float], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        bayesian_update(hypotheses(), likelihoods)
