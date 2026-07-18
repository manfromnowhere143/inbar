# Adjudication Freeze: Anomaly Masking by Autonomous Corrective Action

Status: FROZEN

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none. This freeze grants no authority and no campaign run.

## Purpose

This file fixes the decision rule, the episode schedule, and the reporting denominators **before any
measurement is taken**, so that no rule can be chosen after seeing which rule would produce a better
number. It exists because Amendment 006 was written after its own comparisons had been run, which
permanently bars any result from that configuration from being reported as prospective. This
measurement is a separate, prospectively frozen gate. It is not a refinement of Amendment 006 and
does not reuse its exploratory numbers.

The freeze commit must precede any execution of the measurement, and names below the exact
implementation it binds and the CI run that verifies the tree, so that the ordering is checkable by
a third party from the repository alone rather than asserted by its author.

At the time this file was committed, no cell of the measurement had been executed. The
implementation in `src/fieldtrue/masking.py` and its sixteen adversarial controls in
`tests/unit/test_masking.py` were written and exercised for reproducibility and command recording
only; no separability value, masking index, or event count had been computed or inspected. That
ordering is the entire purpose of this file and is the discipline Amendment 006 failed.

## The question

Does an autonomous corrective action destroy the evidence required to diagnose the fault that
triggered it?

Stated operationally: for a fault mechanism `m` at severity `theta`, is the mechanism less
identifiable from telemetry observed **after** an autonomous compensating action than from telemetry
observed **before** it?

## Why this question

NASA JPL's Ops-for-Autonomy states the problem directly: onboard autonomy "may alter the spacecraft
state in response to information that is not immediately available on the ground," so downlink teams
must "identify anomalies that may otherwise be hidden by autonomous decisions." That programme ran
FY2020 through FY2023 and appears closed. A 2026 literature scan found no taxonomy of this
phenomenon, no detection method, and no dataset. The problem is named by a credible institution and
is, as far as that scan established, unowned.

It is measurable in this laboratory because the separability index is a property of the laboratory
rather than of any method: it states what is resolvable in principle, before any diagnosis is
attempted. Masking is therefore expressible as a change in that index across an action, with no
method in the loop to confound it.

## Definitions, frozen

Let `S(m, theta, A)` be the separability index in permille of mechanism `m` at severity `theta`
against every other candidate, computed over the observation set `A`, exactly as
`separability_index_permille` already computes it. A value of 1000 means the closest competing
hypothesis is separated by exactly the expected disturbance magnitude; below 1000 the pair is inside
the noise floor and no method can reliably resolve it.

- **Pre-action observation** `A_pre`: the `no_op` branch alone.
- **Post-action observation** `A_post`: the `recovery` branch alone, where the recovery action is the
  frozen autonomous compensator defined below.
- **Masking index** `M(m, theta) = S(m, theta, A_pre) - S(m, theta, A_post)`, in permille.
  Positive means the corrective action reduced identifiability. Negative means it increased it.
- **Masking event**: `S(m, theta, A_pre) >= 1000` and `S(m, theta, A_post) < 1000`. That is, the
  mechanism was resolvable in principle before the action and is not resolvable after it. This is
  the binary quantity of interest; `M` is the continuous one.

## The autonomous compensator, frozen

The corrective action is a fixed, mechanism-blind proportional compensator. It observes only the
`no_op` telemetry, computes the deviation of the final observed state from the nominal final state,
and commands a constant drive proportional to that deviation, clipped to the safe action envelope:

    u_recovery = clip( (K * (x_nominal_final - x_observed_final)) // 100, 0, 100 )

with gain `K = 40`, frozen. The compensator is deliberately blind to which mechanism is present. It
is not a diagnosis and does not consult the ontology. It represents an autonomy layer that reacts to
a symptom, which is the condition under which masking is claimed to occur.

`K = 40` was chosen before any masking measurement, on the ground that it produces a commanded
correction of comparable magnitude to the deadband threshold at full severity. It was not selected
by comparing masking outcomes across gains. A sensitivity sweep over `K` is permitted only as a
separately reported secondary analysis and may not replace the primary result.

## Episode schedule, frozen

- Mechanisms: the four Amendment 006 known mechanisms plus the reserved unknown, unchanged.
- Severities: `{25, 45, 70, 85, 100}`, unchanged from the Amendment 006 comparison so the two are
  commensurable. No severity is added, removed, or reweighted after inspection.
- Seeds: `0` through `7` inclusive, eight per (mechanism, severity) cell.
- Total: 5 mechanisms x 5 severities x 8 seeds = 200 episodes.
- The laboratory configuration is `GRADED_CONFIG` at the committed hash bound by Amendment 006. No
  laboratory parameter is tuned for this measurement.

## Primary result, frozen

The primary reported quantity is the **masking event rate**: the number of (mechanism, severity,
seed) cells that satisfy the masking-event condition, over the number of cells in which the
mechanism was resolvable pre-action. Cells that were already unresolvable pre-action cannot be
masked and are excluded from the denominator, but their count is reported alongside and is never
aggregated away.

Three numbers are reported together and none is reported alone:

1. **observed masking rate** `k / N`, where `N` is cells resolvable pre-action;
2. **excluded-cell count** `u`, cells unresolvable pre-action;
3. **total cells** `N + u`.

Per-mechanism masking rates are reported individually for every mechanism, including those with zero
masking events. No mechanism is dropped from the table for having a null result.

## Falsifiers, frozen

The measurement returns a null, reported at full weight under Invariant 7, if any of the following
hold:

- **F-M1.** The masking event rate is zero across all mechanisms and severities. Autonomous
  correction does not hide faults in this laboratory.
- **F-M2.** The median masking index `M` is non-positive. Correction does not systematically reduce
  identifiability.
- **F-M3.** Masking occurs only in cells where the pre-action index is within ten percent of the
  1000 threshold. The effect would then be a boundary artifact of the threshold rather than a
  property of the corrective action.
- **F-M4.** The result reverses under a change to the compensator gain `K` within the frozen safe
  envelope. A masking effect that depends on one arbitrary gain is not a property of correction.

F-M3 and F-M4 are evaluated and reported whether or not the primary result is positive.

## Claim boundary, frozen

A positive result establishes that a mechanism-blind proportional compensator reduces in-simulator
identifiability of injected faults in the Inbar graded laboratory, under the frozen configuration.

It does not establish, and may not be described as establishing: that anomaly masking occurs in any
physical system; that any real autonomy implementation masks faults; a diagnosis, recovery, safety,
transfer, product-readiness, economic-value, or state-of-the-art result; a first or novel claim
relative to unpublished or private work; or any statement about NASA, JPL, or any named
organisation's systems. A simulator branch never counts as a physical incident.

The observation that the problem appears unowned rests on a dated, non-systematic literature scan
and is not an exhaustive novelty claim. It must be described as such wherever it appears.

## What this freeze does not authorise

No campaign run, no compute lease, no corpus admission, no physical action, and no change to
`iter001-acquisition-contract`, which remains the sole registered blocker.
