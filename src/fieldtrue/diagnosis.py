"""Cheap, auditable Bayesian diagnosis primitives."""

from __future__ import annotations

import math
from collections.abc import Mapping

from fieldtrue.domain import CausalHypothesis, HypothesisSet, Identifier


def bayesian_update(
    hypotheses: HypothesisSet,
    likelihood_by_hypothesis: Mapping[str, float],
    *,
    proposer_id: Identifier = "tabular-bayesian-baseline-v1",
    evidence_id: Identifier | None = None,
) -> HypothesisSet:
    identifiers = {hypothesis.hypothesis_id for hypothesis in hypotheses.hypotheses}
    if set(likelihood_by_hypothesis) != identifiers:
        raise ValueError("likelihood keys must exactly match the hypothesis set")
    if any(value < 0 or not math.isfinite(value) for value in likelihood_by_hypothesis.values()):
        raise ValueError("likelihoods must be finite and non-negative")
    weights = {
        hypothesis.hypothesis_id: (
            hypothesis.prior * likelihood_by_hypothesis[hypothesis.hypothesis_id]
        )
        for hypothesis in hypotheses.hypotheses
    }
    normalizer = sum(weights.values())
    if normalizer <= 0:
        raise ValueError("observation has zero probability under every hypothesis")
    updated: list[CausalHypothesis] = []
    for hypothesis in hypotheses.hypotheses:
        supporting = hypothesis.supporting_evidence_ids
        if evidence_id is not None and likelihood_by_hypothesis[hypothesis.hypothesis_id] > 0:
            supporting = (*supporting, evidence_id)
        updated.append(
            hypothesis.model_copy(
                update={
                    "prior": weights[hypothesis.hypothesis_id] / normalizer,
                    "supporting_evidence_ids": supporting,
                }
            )
        )
    return HypothesisSet(
        incident_id=hypotheses.incident_id,
        hypotheses=tuple(updated),
        proposer_id=proposer_id,
    )
