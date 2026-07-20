"""Terminal binding: prediction only under a projection this module derives itself.

`CONTINUITY.md` records the gap this closes. The low-level cross-fit predictors accept a
caller-supplied `IncidentLocalHypothesisMap`, and that model validates ordering and bijectivity but
never provenance. Two failures follow. An omitted mapping manufactures a `key_unavailable`
abstention outside the verified projection path. A substituted mapping binds the proposed key to a
different hypothesis and yields a confident, wrong `selected_hypothesis_id` instead of an
abstention. Omission degrades to silence. Substitution degrades to a false answer, which is
strictly worse and was the undisclosed half.

Amendment 001 constrains a supplied manifest rather than forbidding one, so the primitives are left
exactly as they are: they remain correct as primitives, and 25 existing call sites keep working.
`CONTINUITY.md` places the obligation at the boundary instead, requiring that terminal integration
make raw manifest verification and exact projection mandatory. This module is that boundary.

The enforcement is structural rather than a check. These entry points have no local-maps parameter.
A caller cannot supply a projection because there is nowhere to put one. The projection is derived
here from signed artifacts whose raw bytes, hashes, attestations, and role separation are verified
first, and it is handed to the predictor without ever passing through caller hands.

This module grants no authority. It admits no corpus, creates no target, and closes no gate. It
makes one specific substitution impossible on the terminal path, and nothing more.
"""

from __future__ import annotations

from collections.abc import Sequence

from fieldtrue.shortcut_v2_crossfit import (
    CategoricalFittedState,
    CategoricalHoldoutInput,
    CategoricalPredictionManifest,
    CrossfitFold,
    IncidentLocalHypothesisMap,
    TreeFittedState,
    TreePredictionManifest,
    predict_categorical_holdout,
    predict_tree_holdout,
)
from fieldtrue.shortcut_v2_ontology import (
    BoundCaseVerificationInput,
    PinnedActorBinding,
    ShortcutOntologyVerificationResult,
    verify_shortcut_v2_ontology_artifacts,
)
from fieldtrue.shortcut_v2_tree import FeatureVector


def _holdout_projection(
    projection: ShortcutOntologyVerificationResult,
    fold: CrossfitFold,
) -> tuple[IncidentLocalHypothesisMap, ...]:
    """Select the fold's holdout subset of the derived projection, in fold order.

    A holdout incident with no derived map produces a short tuple, which the predictor's own
    exact-fold check rejects. That check is left to do its job rather than duplicated here, so
    there is one place where the fold and the projection must agree.
    """

    by_incident = {item.incident_id: item for item in projection.local_hypothesis_maps}
    return tuple(
        by_incident[incident] for incident in fold.holdout_incident_ids if incident in by_incident
    )


def _verified_projection(
    *,
    ontology_artifact_bytes: bytes,
    ontology_artifact_sha256: str,
    prediction_key_manifest_artifact_bytes: bytes,
    prediction_key_manifest_artifact_sha256: str,
    caller_pinned_trust_registry_artifact_sha256: str,
    expected_reviewer: PinnedActorBinding,
    bound_cases: Sequence[BoundCaseVerificationInput],
    prohibited_actor_bindings: Sequence[PinnedActorBinding],
) -> ShortcutOntologyVerificationResult:
    """Derive the projection from signed artifacts, never from a caller."""

    return verify_shortcut_v2_ontology_artifacts(
        ontology_artifact_bytes=ontology_artifact_bytes,
        ontology_artifact_sha256=ontology_artifact_sha256,
        prediction_key_manifest_artifact_bytes=prediction_key_manifest_artifact_bytes,
        prediction_key_manifest_artifact_sha256=prediction_key_manifest_artifact_sha256,
        caller_pinned_trust_registry_artifact_sha256=(caller_pinned_trust_registry_artifact_sha256),
        expected_reviewer=expected_reviewer,
        bound_cases=bound_cases,
        prohibited_actor_bindings=prohibited_actor_bindings,
    )


def predict_categorical_under_verified_projection(
    state: CategoricalFittedState,
    fold: CrossfitFold,
    inputs: Sequence[CategoricalHoldoutInput],
    *,
    fitted_state_artifact_bytes: bytes,
    ontology_artifact_bytes: bytes,
    ontology_artifact_sha256: str,
    prediction_key_manifest_artifact_bytes: bytes,
    prediction_key_manifest_artifact_sha256: str,
    caller_pinned_trust_registry_artifact_sha256: str,
    expected_reviewer: PinnedActorBinding,
    bound_cases: Sequence[BoundCaseVerificationInput],
    prohibited_actor_bindings: Sequence[PinnedActorBinding],
) -> CategoricalPredictionManifest:
    """Predict categorical holdout under a projection derived here, not supplied.

    There is deliberately no `local_maps` parameter. Substituting a mapping is impossible on this
    path because no caller value reaches the predictor's map argument.
    """

    projection = _verified_projection(
        ontology_artifact_bytes=ontology_artifact_bytes,
        ontology_artifact_sha256=ontology_artifact_sha256,
        prediction_key_manifest_artifact_bytes=prediction_key_manifest_artifact_bytes,
        prediction_key_manifest_artifact_sha256=prediction_key_manifest_artifact_sha256,
        caller_pinned_trust_registry_artifact_sha256=(caller_pinned_trust_registry_artifact_sha256),
        expected_reviewer=expected_reviewer,
        bound_cases=bound_cases,
        prohibited_actor_bindings=prohibited_actor_bindings,
    )
    return predict_categorical_holdout(
        state,
        fold,
        inputs,
        _holdout_projection(projection, fold),
        fitted_state_artifact_bytes=fitted_state_artifact_bytes,
    )


def predict_tree_under_verified_projection(
    state: TreeFittedState,
    fold: CrossfitFold,
    rows: Sequence[FeatureVector],
    *,
    fitted_state_artifact_bytes: bytes,
    ontology_artifact_bytes: bytes,
    ontology_artifact_sha256: str,
    prediction_key_manifest_artifact_bytes: bytes,
    prediction_key_manifest_artifact_sha256: str,
    caller_pinned_trust_registry_artifact_sha256: str,
    expected_reviewer: PinnedActorBinding,
    bound_cases: Sequence[BoundCaseVerificationInput],
    prohibited_actor_bindings: Sequence[PinnedActorBinding],
) -> TreePredictionManifest:
    """Predict tree holdout under a projection derived here, not supplied.

    There is deliberately no `local_maps` parameter, for the same reason.
    """

    projection = _verified_projection(
        ontology_artifact_bytes=ontology_artifact_bytes,
        ontology_artifact_sha256=ontology_artifact_sha256,
        prediction_key_manifest_artifact_bytes=prediction_key_manifest_artifact_bytes,
        prediction_key_manifest_artifact_sha256=prediction_key_manifest_artifact_sha256,
        caller_pinned_trust_registry_artifact_sha256=(caller_pinned_trust_registry_artifact_sha256),
        expected_reviewer=expected_reviewer,
        bound_cases=bound_cases,
        prohibited_actor_bindings=prohibited_actor_bindings,
    )
    return predict_tree_holdout(
        state,
        fold,
        rows,
        _holdout_projection(projection, fold),
        fitted_state_artifact_bytes=fitted_state_artifact_bytes,
    )
