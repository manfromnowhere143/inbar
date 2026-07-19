# Result: Masking Susceptibility Is Predictable from Fault Geometry

Status: EXPLORATORY

> Current repository-wide disposition: historical exploratory simulator record with authority
> effect `none`. Amendment 006 does not cover the committed graded-laboratory bytes. See
> `AMENDMENT_006_EVIDENCE_DEFECT.md`.

Authority effect: none. `iter001-acquisition-contract` remains the sole registered blocker.

## Standing before the result

This is **exploratory**, not confirmatory. It was derived after inspecting the confirmatory masking
measurement recorded in `RESULT_MASKING.md`, so its design is outcome-informed and it may not be
reported as prospective. A confirmatory claim requires a gate frozen before new data, on a
laboratory configuration not selected on the basis of what is reported here.

It is recorded now because the underlying quantity is offline-computable and the honest test of
independence was run and did not return a perfect score. Both facts are stated below.

## The quantity

For a mechanism `m` at severity `theta`, the **resolvable command window** is the set of constant
commanded inputs `u` for which `mechanism_separability_permille` places `m` at or above the
disturbance floor against every competing candidate. It is computed from noise-free forward models
alone. No episode is simulated, no disturbance is drawn, and no measurement is consulted.

At severity 100, over `u` in steps of 5:

| mechanism | resolvable window | collapses at | maskable |
| --- | --- | --- | :---: |
| `gain_drift` | `[0..100]` | never | no |
| `sensor_bias` | `[0..100]` | never | no |
| `actuator_loss` | `[40..100]` | `[0..35]` | yes |
| `actuator_deadband` | `[40..55]` | elsewhere | yes |
| `unknown` | `[5..55]` | elsewhere | yes |

A mechanism is **masking-susceptible** when its window has a boundary the autonomy's command
envelope can cross. `gain_drift` and `sensor_bias` are resolvable at every reachable command and are
therefore not susceptible at any severity. `actuator_deadband` is resolvable only in a narrow band
that a restoring correction exits immediately.

## Independence test, and why it matters here

A first version of this test was **circular and is recorded as such**. It took the commanded
correction from the measured cell and recomputed separability with the same function the measurement
uses, then reported 175/175 agreement. That agreement was guaranteed before the code ran, because
`masking_event` is *defined* as the comparison being recomputed. It was the fourth instance in one
day of reporting an effect entailed by construction.

The corrected test predicts the commanded correction **analytically**, from noise-free forward models
only. It never calls `graded_run`, never draws a disturbance, and never reads a measured cell:

| quantity | result |
| --- | --- |
| commanded correction predicted exactly | 92 / 175 (53%) |
| masking outcome predicted correctly | **169 / 175 (96.6%)** |
| disagreements | 6 |

The 53% command accuracy is the evidence of independence. A restatement would reproduce the command
exactly; this does not, because the measurement derives its command from noisy telemetry and the
prediction cannot see the noise.

## The six failures, characterized

Every disagreement is `unknown` at severity 85. The prediction says `u = 50`: a fault-free system has
no shortfall, so the compensator holds baseline. The measured commands were 53 to 56, because
disturbance produced an apparent shortfall and the compensator responded to it. `unknown`'s
resolvable window at that severity ends at 55, so a noise-driven command of 56 exits it.

**A fault-free system was masked by a correction that noise alone provoked.** The criterion therefore
holds except within a disturbance-width of a window boundary, and that failure region is itself
predictable from the window edges and the disturbance magnitude.

## What this supports

Masking is not a general hazard of corrective autonomy. In this laboratory it is a **geometric
property of a specific fault and a specific command envelope**, and it is identifiable before any
episode is run:

> Compute each fault's resolvable command window from the models you already have. Compare it
> against the command envelope your autonomy can traverse. Any fault whose window that envelope can
> exit is a fault your autonomy can blind you to.

That is a design-time check rather than a postmortem statistic, and it inverts the usual framing:
the question is not whether autonomy masks anomalies, but which faults a given autonomy is
geometrically capable of masking.

## What this does not establish

A simulator branch never counts as a physical incident. This establishes nothing about physical
systems, no real autonomy implementation, and no diagnosis, recovery, safety, transfer,
product-readiness, economic-value, or state-of-the-art claim. It is exploratory and outcome-informed.

The 96.6% figure is a property of one laboratory, one compensator, one baseline, and one disturbance
model. It is not a general accuracy claim and must not be quoted as one.

No novelty or priority claim is made. The scan suggesting this problem area is unowned was dated and
non-systematic.

## Standing discipline this result adds

Before reporting any effect, run the entailment test: **can a computation that never touches the
measurement reproduce it?** If yes at 100%, the effect is a correctness check on the implementation,
not a measurement. Four effects failed this test in one day — the Amendment 005 paired accuracy, the
deadband masking rate, and two versions of this criterion — and one passed it.
