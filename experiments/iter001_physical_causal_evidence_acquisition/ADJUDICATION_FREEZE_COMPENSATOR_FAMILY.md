# Adjudication Freeze: Compensator-Family Invariance of the Susceptibility Criterion

Status: FROZEN

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none. Simulator authority only. No key, no network, no lease, no census.

## What is being tested

`RESULT_SUSCEPTIBILITY_CONFIRMATORY.md` established that masking is predictable from offline fault
geometry at 0.9947, on unseen severities, seeds, and baselines. **It rests on a single compensator**:
mechanism-blind proportional restoration at gain 40.

If the criterion is genuinely geometric — a statement about where a command lands relative to a
fault's resolvable window — it should hold for compensator policies it has never seen, because the
window does not know how the command was produced.

If instead the 0.9947 was specific to one policy's noise behaviour, it will degrade.

## The prediction, and why it can lose

The criterion predicts a command analytically from noise-free forward models, then asks whether that
command leaves the fault's resolvable window. Its failures occur when noise moves the *actual*
command across a window edge that the *predicted* command did not cross.

That yields a structured prediction rather than a single number: **accuracy should track how
noise-sensitive a compensator's command is.**

- A **bang-bang** compensator commands either baseline or ceiling on a threshold test. Its command is
  quantized, so small noise rarely changes it. Predicted accuracy: **at or above the proportional
  case**.
- A **half-gain proportional** compensator responds to the same shortfall with half the amplitude,
  so a given noise perturbation moves the command half as far. Predicted accuracy: **at or above the
  proportional case**.
- An **integrating** compensator accumulates the shortfall across steps, amplifying the disturbance
  contribution to the final command. Predicted accuracy: **below the proportional case**.

Committed before measurement:

1. Bang-bang agreement `>= 0.9947`.
2. Half-gain agreement `>= 0.9947`.
3. Integrating agreement `< 0.9947`, and strictly above 0.80.
4. Ordering: `integrating < proportional <= min(bang-bang, half-gain)`.

Prediction 3 is the one that can embarrass this proposal. It asserts the criterion gets *worse*
under a policy chosen because it should make it worse. A criterion that scored equally everywhere
would suggest the accuracy figure is insensitive to the thing it supposedly measures.

## Confirmatory set, frozen and unseen

- Compensators: `bang_bang`, `half_gain`, `integrating`, implemented at commit `78eeac8` and
  verified by six controls that pin the properties this prediction depends on. Those controls
  observe commanded values only. **No agreement rate, separability comparison, or masking outcome
  has been computed for any of the three at the time this freeze is committed.**

  The distinction is the same one drawn before the masking freeze: verifying that an instrument has
  the properties a prediction rests on is not measuring with it. A reader who judges otherwise should
  treat this gate as exploratory, and that objection is recorded here so it cannot be raised later as
  a discovery.
- Mechanisms: the four known mechanisms plus the reserved unknown.
- Severities: `{15, 35, 55, 75, 95}`.
- Seeds: `23` through `37` inclusive — **disjoint from seeds 1–22 used in all prior work**.
- Baselines: `{30, 45}` — baseline 60 is excluded because it produced zero masking events and is
  known vacuous.
- Total: 3 x 5 x 5 x 15 x 2 = **2250 cells**.

## Falsifiers, frozen

- **F-C1.** Any of predictions 1 through 4 fails. The criterion is not compensator-invariant in the
  predicted way.
- **F-C2.** Integrating agreement is at or above the proportional case. The stated error mechanism —
  that failures come from noise moving the command across a window edge — is wrong, because a policy
  that amplifies noise in the command did not degrade the prediction.
- **F-C3.** Any compensator produces agreement of exactly 1.000 with non-zero masking events.
  `INVALID_CIRCULAR` for that compensator, and no accuracy figure may be reported for it.
- **F-C4.** Any compensator produces zero masking events across its whole set. Vacuous for that
  compensator, reported as such and excluded from any aggregate.

F-C2, F-C3, and F-C4 are evaluated and reported whether or not F-C1 fires.

## Reporting, frozen

Per compensator: cells, agreement, disagreements, masking events, and exact-command-prediction rate.
The exact-command rate is reported because it is the independence evidence; a compensator whose
command is trivially predictable will show a high rate, and its agreement figure must be read in
that light rather than compared naively against the others.

Vacuous compensators are named and excluded, never pooled.

## Claim boundary, frozen

A confirming result establishes that, in this laboratory, the susceptibility criterion holds across
three compensator families in the predicted ordering. It establishes nothing about physical systems,
any real autonomy implementation, or any compensator outside these four. A simulator branch never
counts as a physical incident. No novelty or priority claim is made.
