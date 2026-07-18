# Adjudication Freeze v2: Anomaly Masking by Autonomous Corrective Action

Status: FROZEN

Supersedes: `ADJUDICATION_FREEZE_MASKING.md`, SHA-256
`b1107d6d18f642af43183bcff8b8d869c8a1cd74a53c35b3639e32b41e23cb65`, committed at `e0da3eb`

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none. This freeze grants no authority and no campaign run.

## Why v1 was superseded, stated before anything else

Version 1 was executed exactly as frozen and returned a **vacuous** result: of 200 cells, zero were
resolvable before the corrective action, so the denominator of the primary rate was zero by
construction rather than by data. The measurement could not have produced information under any
outcome.

The cause is a defect in v1's own definition, and it is disclosed here rather than repaired quietly.
v1 said:

> "Let `S(m, theta, A)` be the separability index in permille of mechanism `m` at severity `theta`
> **against every other candidate**, computed over the observation set `A`, **exactly as
> `separability_index_permille` already computes it**."

Those two clauses name different quantities. "Of mechanism `m` against every other candidate" is a
per-mechanism index. "Exactly as `separability_index_permille` computes it" is the minimum over
**all** hypothesis pairs, which is a property of the whole catalog. The implementation followed the
second clause. Under a no-op, `actuator_loss` and the reserved unknown produce bit-identical
telemetry, so the catalog-wide minimum is zero for every cell regardless of which mechanism was
injected, and every cell was excluded.

**The disambiguation in this document was chosen after seeing v1 fail.** That is disclosed without
softening. Two facts bear on whether the choice is legitimate:

1. v1's prose states the per-mechanism reading **first**, and the catalog-wide clause was written as
   an implementation shorthand that turned out not to mean the same thing. The per-mechanism reading
   is the one the document's own question requires: masking asks whether *the injected mechanism*
   became harder to identify, which is undefined for a catalog-wide statistic.
2. The correction is not a threshold, a denominator, or a schedule adjustment. It replaces a
   quantity that is provably constant at zero across every cell with one that varies. A rule that
   cannot vary cannot be tuned toward a result, so v1 carried no information that could bias v2.

Neither fact makes this a prospective specification of the disambiguated rule. **v2 is a correction
of a defective instrument, and any result under it must be described as such.** If a reader judges
that the disambiguation was outcome-informed, the correct response is to treat this measurement as
exploratory and demand a third gate specified before any further data. That objection is legitimate
and is recorded here so it cannot be raised as a discovery later.

v1 is retained unedited. The vacuous result stands as a recorded outcome and is not deleted.

## The corrected definition

`S(m, theta, A)` is the **per-mechanism** separability index in permille, computed by
`mechanism_separability_permille`: given that mechanism `m` at severity `theta` was injected, the
minimum over every *other* candidate of the L1 distance between their noise-free predicted
telemetry under observation set `A`, normalized by the expected disturbance magnitude that action
must itself overcome. It answers: how far is the injected mechanism's signature from the nearest
competing explanation?

Everything else is unchanged from v1 and is restated here so this document stands alone.

- **Pre-action observation** `A_pre`: the `no_op` branch alone.
- **Post-action observation** `A_post`: the `recovery` branch alone, under the frozen compensator.
- **Masking index** `M(m, theta) = S(m, theta, A_pre) - S(m, theta, A_post)`, in permille. Positive
  means the corrective action reduced identifiability. Negative means it increased it. The quantity
  is signed, so the measurement can return the finding that autonomy helps.
- **Masking event**: `S(m, theta, A_pre) >= 1000` and `S(m, theta, A_post) < 1000`. Resolvable in
  principle before the action, not resolvable after it.

## The compensator, unchanged from v1

Mechanism-blind proportional compensator, gain `K = 40` frozen, clipped to `[0, 100]`:

    u_recovery = clip( (K * (x_nominal_final - x_observed_final)) // 100, 0, 100 )

It observes only the `no_op` telemetry and never consults the ontology, the injected mechanism, or
the severity. It is not a diagnosis. The gain was fixed before any masking measurement and was not
selected by comparing masking outcomes across gains.

## Episode schedule, unchanged from v1

- Mechanisms: the four known mechanisms plus the reserved unknown.
- Severities: `{25, 45, 70, 85, 100}`.
- Seeds: `0` through `7` inclusive.
- Total: 200 cells.
- Laboratory: `GRADED_CONFIG` at its committed hash. No laboratory parameter is tuned for this
  measurement.

## Primary result, unchanged from v1

The **masking event rate**: masking events over cells resolvable pre-action. Three numbers are
reported together and none is reported alone:

1. observed masking rate `k / N`, where `N` is cells resolvable pre-action;
2. excluded-cell count `u`, cells unresolvable pre-action;
3. total cells `N + u`.

Per-mechanism rates are reported individually for every mechanism, including those with zero events.
No mechanism is dropped for having a null result. **If `N` is zero the measurement is vacuous and is
reported as `MEASUREMENT_VACUOUS`, exactly as v1 was.**

## Falsifiers, unchanged from v1

- **F-M1.** Zero masking events across all mechanisms and severities.
- **F-M2.** Non-positive median masking index.
- **F-M3.** Masking occurs only where the pre-action index is within ten percent of the 1000
  threshold, making the effect a boundary artifact rather than a property of correction.
- **F-M4.** The result reverses under a change to the compensator gain within the safe envelope.

F-M3 and F-M4 are evaluated and reported whether or not the primary result is positive.

## Claim boundary, unchanged from v1

A positive result establishes that a mechanism-blind proportional compensator reduces in-simulator
identifiability of injected faults in the Inbar graded laboratory under the frozen configuration.

It does not establish, and may not be described as establishing: that anomaly masking occurs in any
physical system; that any real autonomy implementation masks faults; a diagnosis, recovery, safety,
transfer, product-readiness, economic-value, or state-of-the-art result; a first or novel claim
relative to unpublished or private work; or any statement about NASA, JPL, or any named
organisation's systems. A simulator branch never counts as a physical incident.

The observation that the problem appears unowned rests on a dated, non-systematic literature scan
and is not an exhaustive novelty claim.

## What this freeze does not authorise

No campaign run, no compute lease, no corpus admission, no physical action, and no change to
`iter001-acquisition-contract`, which remains the sole registered blocker.
