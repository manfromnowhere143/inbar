# Adjudication Freeze v3: Anomaly Masking by Autonomous Corrective Action

Status: FROZEN

Supersedes: `ADJUDICATION_FREEZE_MASKING_V2.md`, which superseded
`ADJUDICATION_FREEZE_MASKING.md`. Both are retained unedited and their outcomes stand.

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none. This freeze grants no authority and no campaign run.

## Prior outcomes, stated before anything else

Two measurements preceded this one and neither tested the hypothesis.

**v1 returned `MEASUREMENT_VACUOUS`.** Of 200 cells, zero were resolvable before the corrective
action, because the frozen definition resolved to a catalog-wide index that one degenerate
hypothesis pair drives to zero for every cell. The denominator was zero by construction.

**v2 returned `INFRA_NULL`.** The per-mechanism index fixed the denominator, but the compensator
commanded no correction on any cell at any severity. Observing the pre-action state under a no-op
leaves nothing to compensate: a fault that attenuates drive is invisible when commanded drive is
zero, and a fault that raises the state cannot be countered by a compensator permitted only positive
drive. The instrument could not act. This is recorded as an infrastructure null ahead of any
substantive verdict, and is **not** the F-M1 finding that correction does not mask.

Both were defects in the instrument, not observations about the world.

## Prior exposure, stated without softening

The instrument was corrected exploratorily after v2 failed. The compensator now observes and acts
from a baseline operating command, so an actuator fault depresses output below the baseline
expectation and the compensator raises drive to restore setpoint.

**During that correction, cells at `seed = 0` were inspected**, across mechanisms at severities 45
and 100, and their separability and masking-index values were seen. A candidate pattern was visible
in them. Those cells are therefore contaminated and cannot carry a confirmatory claim.

**Seeds 1 through 7 have never been measured under the corrected instrument.** They are the
confirmatory set frozen below. No value from them has been computed, inspected, or predicted.

The instrument's non-inertness was verified before this freeze and separately from any outcome: with
the compensator gain set to zero it holds baseline on every mechanism and all three inertness guards
fail; with the live gain its commands range across the envelope and all three pass. That check
establishes that the instrument can act. It does not establish what it will find.

## Definitions, frozen

`S(m, theta, A)` is the per-mechanism separability index in permille, computed by
`mechanism_separability_permille`: given mechanism `m` at severity `theta`, the minimum over every
other candidate of the L1 distance between their noise-free predicted telemetry under observation
`A`, normalized by the expected disturbance magnitude that action must overcome.

- **Pre-action observation** `A_pre`: the baseline operating command, `u = 50` on every step.
- **Post-action observation** `A_post`: the compensator's commanded action.
- **Masking index** `M = S(A_pre) - S(A_post)`, signed. Positive means correction reduced
  identifiability; negative means it increased it.
- **Masking event**: `S(A_pre) >= 1000` and `S(A_post) < 1000`.

## The compensator, frozen

Mechanism-blind proportional restoration, baseline `50`, gain `40`, clipped to `[0, 100]`:

    u = clip( baseline + (gain * (x_nominal_final_at_baseline - x_observed_final)) // 100, 0, 100 )

It sees one telemetry trace and a nominal expectation. It never consults the ontology, the injected
mechanism, or the severity. It is not a diagnosis.

## Confirmatory schedule, frozen

- Mechanisms: the four known mechanisms plus the reserved unknown.
- Severities: `{25, 45, 70, 85, 100}`.
- **Seeds: `1` through `7` inclusive. Seed 0 is excluded as contaminated.**
- Total: 5 x 5 x 7 = 175 cells.
- Laboratory: `GRADED_CONFIG` at its committed hash. No laboratory parameter is tuned here.

Seed-0 cells are reported separately and labelled exploratory. They are never pooled with the
confirmatory set and never contribute to the primary rate.

## Primary result, frozen

The **masking event rate**: masking events over cells resolvable pre-action, on the confirmatory set
only. Three numbers reported together, none alone: the observed rate `k / N`; the excluded count `u`
of cells unresolvable pre-action; the total `N + u`. Per-mechanism rates are reported individually
for every mechanism including those with zero events. If `N` is zero the measurement is
`MEASUREMENT_VACUOUS`, as v1 was.

## Falsifiers, frozen

- **F-M1.** Zero masking events across all mechanisms and severities.
- **F-M2.** Non-positive median masking index.
- **F-M3.** Masking occurs only where the pre-action index is within ten percent of the 1000
  threshold, making the effect a boundary artifact of the threshold.
- **F-M4.** The result reverses under a change to the compensator gain within the safe envelope.

F-M3 and F-M4 are evaluated and reported whether or not the primary result is positive.

**A negative median masking index is a substantive finding, not a failure.** It would mean the
corrective action makes faults *more* identifiable, which contradicts the masking hypothesis and
must be reported at full weight under Invariant 7.

## Claim boundary, frozen

A result establishes how a mechanism-blind proportional compensator affects in-simulator
identifiability of injected faults in the Inbar graded laboratory under the frozen configuration.

It does not establish, and may not be described as establishing: that anomaly masking does or does
not occur in any physical system; that any real autonomy implementation masks or reveals faults; a
diagnosis, recovery, safety, transfer, product-readiness, economic-value, or state-of-the-art
result; a first or novel claim relative to unpublished or private work; or any statement about NASA,
JPL, or any named organisation's systems. A simulator branch never counts as a physical incident.

The observation that this problem appears unowned rests on a dated, non-systematic literature scan
and is not an exhaustive novelty claim.

## What this freeze does not authorise

No campaign run, no compute lease, no corpus admission, no physical action, and no change to
`iter001-acquisition-contract`, which remains the sole registered blocker.
