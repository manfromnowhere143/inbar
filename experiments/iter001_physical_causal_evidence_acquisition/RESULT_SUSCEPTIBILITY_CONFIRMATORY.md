# Confirmatory Result: Masking Is Predictable from Offline Fault Geometry

Status: RECORDED — CONFIRMATORY

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
