# Confirmatory Result: Masking Is Predictable from Offline Fault Geometry

Status: RECORDED — CONFIRMATORY

> Current disposition: **CORRECTED — RETROSPECTIVE ENGINEERING RECONSTRUCTION; CONFIRMATORY
> INTERPRETATION INCONCLUSIVE.** The original report is retained below. See the correction appended
> to this document.

Gate: `ADJUDICATION_FREEZE_SUSCEPTIBILITY.md`, SHA-256
`57bdb965c821b20e3e76007009e0e0e700e73862deaafaae8e5ce1428f3cad38`, committed at `524d5e8`
before any confirmatory cell was measured.

Authority effect: none. `iter001-acquisition-contract` remains the sole registered blocker.

## Result

Confirmatory set disjoint from every inspected configuration on all three axes: severities
`{15, 35, 55, 75, 95}`, seeds 8 through 22, baselines `{30, 45, 60}`. 1125 cells measured.

Applying the frozen reporting rule, baseline 60 produced zero masking events and is reported as
**vacuous** rather than as agreement, and is excluded from the aggregate:

| quantity | value |
| --- | --- |
| informative cells | 750 |
| cells in agreement | 746 |
| cells in disagreement | 4 |
| masking events | 64 |
| **agreement** | **0.9947** |
| pre-registered threshold | 0.90 |

Pooling the vacuous baseline would report 0.9964. The freeze forbade that and the lower figure is
the headline.

Per baseline:

| baseline | cells | agreement | masking events | verdict |
| ---: | ---: | ---: | ---: | :--- |
| 30 | 375 | 0.9893 | 49 | informative |
| 45 | 375 | 1.0000 | 15 | informative |
| 60 | 375 | 1.0000 | 0 | **vacuous, excluded** |

Per mechanism, all 1125 cells:

| mechanism | cells | agreement | masking events |
| --- | ---: | ---: | ---: |
| `gain_drift` | 225 | 1.0000 | 0 |
| `actuator_loss` | 225 | 1.0000 | 0 |
| `actuator_deadband` | 225 | 1.0000 | 60 |
| `sensor_bias` | 225 | 1.0000 | 0 |
| `unknown` | 225 | 0.9822 | 4 |

## Falsifier disposition

- **F-S1 — agreement below 0.90: does not fire.** Observed 0.9947 against a threshold fixed before
  measurement.
- **F-S2 — errors not near a window boundary: does not fire.** All four disagreements lie within one
  disturbance-width of a boundary.
- **F-S3 — agreement exactly 1.000 with non-zero masking: does not fire.** Observed 0.9947. This
  falsifier existed because perfect agreement would indicate the prediction and the measurement had
  collapsed into the same computation, which happened once during exploratory work and is recorded
  in `RESULT_SUSCEPTIBILITY.md`.
- **F-S4 — zero masking events: does not fire.** Sixty-four events occurred.

## The independence evidence

The prediction never calls `graded_run`, never draws a disturbance, and never reads a measured cell.
It computes the commanded correction from noise-free forward models alone.

| quantity | value |
| --- | --- |
| exact commanded correction predicted | 334 / 750 = **0.4453** |
| masking outcome predicted | 746 / 750 = **0.9947** |

The gap between those two numbers is the substance of the result. A computation restating the
measurement would reproduce both at 1.0000. This one reproduces the exact command in fewer than half
of cells, because the measurement derives its command from noisy telemetry the prediction cannot
see, and still predicts the masking outcome in 99.47 percent of cells.

## The four disagreements

Every disagreement is `unknown` at severity 55, baseline 30. The prediction issues no correction, as
a fault-free system has no shortfall against its own nominal expectation. The measured commands were
33 to 36, because disturbance produced an apparent shortfall the compensator answered. The
disturbance width at that operating point is 11, so all four fall inside the predicted failure
region.

This reproduces the exploratory failure mode exactly: a fault-free system masked by a correction
that noise alone provoked. The criterion holds except within a disturbance-width of a window
boundary, and that region is itself computable from the window edges and the laboratory's
disturbance model.

## What this establishes

In the Inbar graded laboratory, under this compensator and this configuration, **masking by a
mechanism-blind proportional corrector is predictable from offline fault geometry at 0.9947, on
configurations that were unseen when the prediction rule was frozen.**

The operational form:

> Compute each fault's resolvable command window from the forward models you already have, with no
> episodes run. Compare it against the command envelope your autonomy can traverse. A fault whose
> window that envelope can exit is a fault your autonomy can blind you to, and the prediction fails
> only within a disturbance-width of a window edge.

`gain_drift` and `sensor_bias` are resolvable at every reachable command and were masked zero times
in 450 cells. `actuator_deadband` is resolvable only inside a narrow band and was masked 60 times.
Susceptibility is a property of the fault's geometry against the command envelope, not a property of
autonomy in general.

## What this does not establish

A simulator branch never counts as a physical incident. This establishes nothing about physical
systems, no real autonomy implementation, no other compensator, and no laboratory other than this
one. It is not a diagnosis, recovery, safety, transfer, product-readiness, economic-value, or
state-of-the-art claim.

The 0.9947 figure belongs to one laboratory, one compensator, one gain, one disturbance model, and
three baselines. It is not a general accuracy claim and must not be quoted as one.

No novelty or priority claim is made. The scan suggesting this problem area is unowned was dated and
non-systematic, and an exhaustive claim would require a systematic review that has not been
performed.

## Provenance

- Exploratory derivation and its circular first attempt: `RESULT_SUSCEPTIBILITY.md`
- The masking measurement this criterion explains: `RESULT_MASKING.md`, including its own corrected
  headline
- Prior failed gates on the same question: masking freeze v1 `MEASUREMENT_VACUOUS`, v2 `INFRA_NULL`

Five effects were tested for entailment during this line of work. Four were entailed by construction
and are recorded as such. This is the one that was not.

# Correction: the counts replay, but the confirmatory interpretation does not survive

Status: CORRECTED — RETROSPECTIVE ENGINEERING RECONSTRUCTION; CONFIRMATORY INTERPRETATION
`INCONCLUSIVE`

Recorded: 2026-07-19

Authority effect: none.

The original run retained no executable runner and no atomic confirmatory cells. A retrospective
reconstruction now keeps the 75 seed-independent predictions separate from the 1,125 noisy
measurements and derives every aggregate from those atomic records. The canonical artifact is
`proof/susceptibility_confirmatory_v1/reconstruction.json`, SHA-256
`99f6f08f5e2fc720606dcbc109988b7654dd223861dd212885e0a1e755770151`.

It reproduces the prose arithmetic exactly:

| quantity | exact replay |
| --- | ---: |
| all-cell agreement | 1,121 / 1,125 |
| informative agreement | 746 / 750 |
| masking events | 64 |
| exact commands on informative cells | 334 / 750 |
| disagreements | 4 |
| confusion matrix | TP 60, FP 0, FN 4, TN 686 |
| sensitivity | 60 / 64 |
| specificity | 686 / 686 |
| balanced accuracy | 31 / 32 |

This verifies the reported deterministic calculation against the source and frozen schedule. It
does not recreate evidence that existed at the historical execution time.

## Why the interpretation is corrected

1. The preregistered 0.90 agreement threshold was non-discriminating for this schedule. An
   always-non-masking comparator scores 686/750, or 0.9147, on the informative set without using
   fault geometry. The observed sensitivity and balanced accuracy are stronger retrospective
   diagnostics, but they were not the frozen success rule.
2. F-S2 required disagreements to lie within one disturbance-width of a window boundary but did not
   machine-define the mapping from telemetry disturbance to command-window distance. The four
   disagreements can be located exactly, but the preregistered F-S2 verdict cannot be independently
   executed from the freeze.
3. Prediction and measurement share the same hand-authored forward geometry and separability rule.
   The replay tests disturbance around that structure, not model misspecification or physical
   transfer.
4. The reserved `unknown` mechanism realizes nominal dynamics at every severity, so it is a nominal
   placeholder rather than a genuinely unmodeled fault family.
5. Amendment 006's bound source hashes match neither the first committed nor the current graded
   laboratory. The implementation is not covered by that amendment.

The 0.9947 association inside this deterministic simulator is not refuted. It is an engineering
observation whose confirmatory scientific interpretation is inconclusive. It must not be described
as a physical result, a general accuracy, a state-of-the-art result, or a confirmed result.

Reproduce and verify the retained artifact with:

```bash
uv run pytest tests/unit/test_susceptibility_replay.py -q
```

The controlling authority and evidence correction is
`AMENDMENT_006_EVIDENCE_DEFECT.md`.
