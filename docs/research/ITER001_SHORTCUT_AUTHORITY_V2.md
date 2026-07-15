# Iteration 001 Shortcut Authority V2

Status: design only; not an active scientific authority

Decision date: 2026-07-15

Decision: `BLOCK_SEAL_PENDING_PROSPECTIVE_AMENDMENT`

## Problem

The current shortcut report binds an arbitrary implementation file, an arbitrary evaluation file,
and a statistician-signed `resolves_mechanism_without_action` Boolean. The validator verifies the
signature and eligible-corpus hash but does not execute the rule or recompute the Boolean.

The frozen preregistration also does not define the corpus-level meaning of “resolves the
mechanism.” It leaves coverage, abstention, exact correctness, unknown-class handling, split
discipline, and rule aggregation unspecified. `TruthRecord.mechanism_ids` is not mapped to the
correct member of the pre-outcome hypothesis set.

No current V1 shortcut report can authorize `PASS_PILOT` or `KILL_CONSTRUCT`. Canonical sealing
remains blocked until a prospective amendment freezes the missing semantics and the validator
executes them.

## Mechanism resolution target

Add a truth-only, mechanism-reviewer-signed record:

```python
class MechanismResolutionTarget(FrozenModel):
    schema_version: Literal["fieldtrue.mechanism-resolution-target.v1"]
    incident_id: Identifier
    truth_record_sha256: Sha256
    hypothesis_set_sha256: Sha256
    mechanism_ids_sha256: Sha256
    target_hypothesis_id: Identifier
    target_kind: Literal["known", "unknown"]
    mapping_evidence: ArtifactBinding
    committed_at: datetime
    mechanism_reviewer_id: Identifier
    attestation: SignedAttestation
```

The validator must establish all of the following:

1. The target occurs exactly once in the bound hypothesis set.
2. The target occurs in `TruthRecord.competing_hypothesis_ids`.
3. The mechanism hash equals the canonical hash of the sorted truth mechanisms.
4. `target_kind` equals the target hypothesis `unknown` flag.
5. The signer is the trusted mechanism reviewer for the dossier.
6. The target and mapping evidence remain truth-only.

The prospective amendment must freeze whether this mapping is committed before safe-test review or
before test execution. The implementation must not choose that chronology silently.

## Declarative rule authority

Replace executable files and plugin identifiers with an internal discriminated union:

```python
class ShortcutRuleSpec(FrozenModel):
    rule_id: ShortcutRuleId
    role: Literal[
        "forbidden_metadata_probe",
        "oracle_leakage_probe",
        "identity_probe",
        "kill_baseline",
    ]
    selector: ShortcutSelector
    predictor: ShortcutPredictor
    permitted_plane: Literal["model_visible", "control_only", "truth_only_oracle"]
    fit_policy: Literal["none", "train_only"]
    tie_policy: Literal["abstain"]
    unseen_policy: Literal["abstain"]
    seed: str | None
    max_operations_per_incident: int
```

Initially permitted predictors are `constant`, `categorical-train-mode`,
`sha256-bucket-train-mode`, and `ordered-decision-list`. The validator implements each predictor.
Python source paths, shell commands, pickles, external plugins, and dynamically imported code are
forbidden.

Train-mode predictors count training targets only. Ties and unseen values abstain. Canonical UTF-8
byte order resolves all ordering. Evidence-only decision lists may read only validator-derived
features from bound pre-cutoff model-visible artifacts.

## Rule registry

```python
class ShortcutRuleRegistry(FrozenModel):
    schema_version: Literal["fieldtrue.shortcut-rule-registry.v2"]
    registry_id: Identifier
    eligible_incident_ids_sha256: Sha256
    eligible_dossier_root_sha256: Sha256
    model_visible_projection_root_sha256: Sha256
    hypothesis_set_root_sha256: Sha256
    split_locks_sha256: Sha256
    resolution_policy: ShortcutResolutionPolicy
    rules: tuple[ShortcutRuleSpec, ...]
    committed_at: datetime
    statistician_id: Identifier
    attestation: SignedAttestation
```

The registry covers the exact frozen ten-rule order and is committed before the earliest truth
release. Neither rules nor resolution policy can change after that boundary.

## Predictions and evaluation

Each supplied prediction is evidence to compare with validator recomputation, never authority.

```python
class ShortcutPrediction(FrozenModel):
    incident_id: Identifier
    hypothesis_set_sha256: Sha256
    input_sha256: Sha256
    selected_hypothesis_id: Identifier | None
    disposition: Literal["selected", "abstain"]

class ShortcutPredictionManifest(FrozenModel):
    schema_version: Literal["fieldtrue.shortcut-prediction-manifest.v1"]
    rule_spec_sha256: Sha256
    split_axis: Literal[
        "none", "hardware_family", "hardware_identity", "fault_family"
    ]
    fit_incident_ids_sha256: Sha256
    prediction_incident_ids_sha256: Sha256
    fitted_state_sha256: Sha256 | None
    predictions: tuple[ShortcutPrediction, ...]
    produced_at: datetime
    statistician_id: Identifier
    attestation: SignedAttestation

class ShortcutRuleEvaluation(FrozenModel):
    rule_id: Identifier
    prediction_manifest_sha256: Sha256
    target_manifest_sha256: Sha256
    denominator_count: int
    selected_count: int
    correct_count: int
    abstention_count: int
    resolving_incident_ids: tuple[Identifier, ...]
    resolves_construct: bool
```

The validator recomputes input extraction, fitted state, every prediction, every count, and the
final Boolean.

## Proposed exact-census amendment

The following criterion is recommended but is not active until Daniel approves a prospective
amendment:

1. Only `role=kill_baseline` can trigger `KILL_CONSTRUCT`.
2. The kill-bearing `cheapest-deterministic-evidence-only` rule uses `fit_policy=none`.
3. It reads only pre-cutoff model-visible evidence.
4. It predicts every eligible physical root before any truth release.
5. A prediction is correct only when its hypothesis ID exactly equals the signed mechanism
   resolution target.
6. Abstention, missing or duplicate prediction, and an invalid target are incorrect.
7. It resolves the construct only when denominator, selected, and correct counts all equal the
   complete eligible census.

This exact-census definition avoids inventing an accuracy threshold from a 30-incident pilot.
Identity probes remain diagnostic unless a separate prospective amendment gives them kill
authority.

## Split and truth release

Identity probes that fit labels use each frozen split axis separately. They fit on `train` only,
freeze predictions for `validation` and `test`, and access those targets only afterward. Axes are
never pooled.

Add two signed receipts:

1. `ShortcutFreezeReceipt` binds the registry, census, split locks, projections, hypotheses, and
   validator Git blob before truth access.
2. `ShortcutTruthReleaseReceipt` binds the frozen prediction-manifest hash when the mechanism
   custodian releases adjudication targets.

Train-only probes need scoped train-target and evaluation-target releases. The current free-form
truth access log cannot prove that separation and therefore cannot support canonical fitted
shortcut results.

## Ten-rule migration

The existing rule IDs remain stable, but their semantics require explicit V2 selectors:

| Rule | V2 role | Required decision |
|---|---|---|
| `source-identity` | forbidden metadata probe | exact source field |
| `task-identity` | forbidden metadata probe | freeze whether task means mission ID or another field |
| `system-identity` | identity probe | freeze family, hardware ID, or both |
| `site-identity` | forbidden metadata probe | exact site field |
| `path-and-filename` | forbidden metadata probe | original-source or projected artifact paths |
| `timestamp` | forbidden metadata probe | exact absolute or relative time fields |
| `fault-label` | truth-only oracle control | never a kill-bearing evidence input |
| `annotation` | forbidden metadata probe | add a typed annotation source before migration |
| `random-identity-embedding` | identity probe | freeze selector, seed, buckets or dimensions, and head |
| `cheapest-deterministic-evidence-only` | sole kill baseline | freeze the exact decision list and features |

The first nine do not automatically kill a leakage-safe construct. A truth-only fault label that
resolves truth is an evaluator positive control, not proof that pre-outcome evidence was trivial.

## Required controls

The V2 authority must reject or correctly classify at least these cases:

- flipped resolution Boolean with fixed predictions;
- tampered rule, seed, fitted state, prediction, denominator, or output hash;
- missing or duplicated eligible incident;
- hypothesis ID absent from the committed set;
- truth, fault label, outcome bytes, or post-cutoff evidence in a kill baseline;
- prediction produced after truth release;
- evaluation truth released before prediction freeze;
- fit using validation or test incidents;
- changed tie or unseen handling;
- unregistered selector or executable implementation artifact;
- abstention counted as correct;
- absent or multiply mapped mechanism target;
- resolving forbidden metadata that remains excluded, which is diagnostic only;
- forbidden metadata exposed model-visible, which is `INVALID`;
- exact evidence-only census resolution, which is `KILL_CONSTRUCT`;
- one missed or abstained incident, which is non-resolving;
- removed or reordered frozen rule ID; and
- annotation or random-embedding migration without prospectively frozen fields.

## Research-engine extraction

The later research engine must distinguish signed reports from recomputed authority. Whenever a
Boolean determines a terminal verdict, it must be derived from content-bound atomic observations,
an exact frozen aggregation rule, and a validator implementation whose Git object is part of the
authority. Undefined thresholds block; they are never filled by engineering convention after data
inspection.
