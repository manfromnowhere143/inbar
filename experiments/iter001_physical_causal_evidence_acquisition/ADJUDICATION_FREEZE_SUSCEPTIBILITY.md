# Adjudication Freeze: Masking Susceptibility Criterion

Status: FROZEN

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none. This freeze grants no authority and no campaign run. It uses only the
simulator authority the mission contract already permits, no compute lease, no network, and no key.

## What is being tested

`RESULT_SUSCEPTIBILITY.md` reports an exploratory finding: masking is predictable from fault
geometry alone. Each mechanism has a **resolvable command window**, the set of constant commanded
inputs at which its signature stays at or above the disturbance floor against every competing
candidate, computed from noise-free forward models with no episode simulated. Masking is predicted
when a correction carries the command out of that window.

On the exploratory set the criterion predicted the masking outcome in 169 of 175 cells, reproducing
the commanded correction exactly in only 92 of 175 — the gap between those two numbers being the
evidence that the prediction does independent work rather than restating the measurement.

That result is outcome-informed: it was derived after inspecting the confirmatory masking
measurement, on severities `{25, 45, 70, 85, 100}`, seeds 1 through 7, and baselines
`{20, 35, 50, 65, 80}`. **Every one of those configurations is contaminated and is excluded here.**

## Confirmatory set, frozen and unseen

No cell in this set has been measured, inspected, or predicted at the time this file is committed.

- Mechanisms: the four known mechanisms plus the reserved unknown.
- **Severities: `{15, 35, 55, 75, 95}`** — disjoint from every severity inspected.
- **Seeds: `8` through `22` inclusive** — disjoint from every seed inspected.
- **Baselines: `{30, 45, 60}`** — disjoint from every baseline inspected.
- Compensator gain: 40, as frozen in the masking freezes.
- Total: 5 x 5 x 15 x 3 = **1125 cells**.
- Laboratory: `GRADED_CONFIG` at its committed hash. No laboratory parameter is tuned here.

## The pre-registered prediction

For each cell the criterion computes, using only noise-free forward models and never calling
`graded_run`:

1. the commanded correction the compensator would issue against a fault-free expectation;
2. the per-mechanism separability at the baseline command;
3. the per-mechanism separability at that predicted command;
4. a predicted masking outcome: resolvable at baseline and not resolvable after.

The measurement independently computes the same outcome from noisy telemetry.

**Predicted agreement: at least 0.90 across the confirmatory set.** This number is fixed here before
any confirmatory cell is measured. It is chosen from the exploratory range of 0.966 to 1.000 with
margin for configurations not yet seen, and it is not adjustable after inspection.

**Predicted error structure: every disagreement lies within one disturbance-width of a window
boundary.** The disturbance magnitude is bounded by the laboratory configuration, so this is
checkable per cell rather than as an aggregate impression.

## Falsifiers, frozen

- **F-S1.** Agreement below 0.90. The criterion does not generalize to unseen configurations and the
  exploratory result was specific to the inspected set.
- **F-S2.** Disagreements do not concentrate within a disturbance-width of a window boundary. The
  stated error mechanism is wrong even if the headline accuracy holds, and the criterion would then
  be predictive for an unknown reason rather than the claimed one.
- **F-S3.** **Agreement is exactly 1.000 while masking events are non-zero.** This is a falsifier,
  not a success. A prediction derived from forward models cannot perfectly reproduce a measurement
  driven by noise the prediction never sees; perfect agreement is evidence that the two computations
  have collapsed into one, which happened once already and was recorded. If F-S3 fires the result is
  `INVALID_CIRCULAR` and no accuracy figure may be reported.
- **F-S4.** Zero masking events across the entire confirmatory set. The measurement is then vacuous
  and cannot test the criterion in either direction, exactly as masking freeze v1 was.

F-S2, F-S3, and F-S4 are evaluated and reported whether or not F-S1 fires.

## Reporting, frozen

Three numbers reported together and none alone: cells in agreement, cells in disagreement, and cells
where masking occurred at all. Per-baseline and per-mechanism agreement is reported individually,
including any cell class with zero masking events, which is reported as vacuous for that class
rather than folded into the aggregate.

A per-baseline agreement of 1.000 accompanied by zero masking events at that baseline is reported as
**vacuous, not as agreement**. That distinction is stated here because the exploratory sweep produced
exactly this pattern at two baselines and it would inflate an aggregate if pooled.

## Claim boundary, frozen

A confirming result establishes that, in the Inbar graded laboratory under this configuration,
masking by a mechanism-blind proportional compensator is predictable from offline fault geometry at
the stated accuracy.

It does not establish, and may not be described as establishing: that the criterion holds for any
physical system, any real autonomy implementation, any other compensator, or any laboratory other
than this one; nor a diagnosis, recovery, safety, transfer, product-readiness, economic-value, or
state-of-the-art claim. A simulator branch never counts as a physical incident.

No novelty or priority claim is made. The scan suggesting this problem area is unowned was dated and
non-systematic.

## What this freeze does not authorise

No campaign run, no compute lease, no census, no network retrieval, no corpus admission, no physical
action, and no change to `iter001-acquisition-contract`, which remains the sole registered blocker.
