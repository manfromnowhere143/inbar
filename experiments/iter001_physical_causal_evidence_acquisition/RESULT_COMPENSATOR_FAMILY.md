# Result: Compensator-Family Invariance, and a Falsifier That Was Too Blunt

Status: RECORDED — PARTIALLY VOIDED BY ITS OWN FROZEN RULE

> Current disposition: **CORRECTED — UNRECONSTRUCTED ENGINEERING OBSERVATION; A006 IMPLEMENTATION
> COVERAGE `BLOCKED`.** No atomic family cells or executable result runner are retained, and
> Amendment 006 does not bind the committed graded-laboratory bytes. The historical values remain
> visible but do not establish compensator-family invariance. See
> `AMENDMENT_006_EVIDENCE_DEFECT.md`.

Gate: `ADJUDICATION_FREEZE_COMPENSATOR_FAMILY.md`, SHA-256
`e97b50fbe8775cd2c08f5a69082eb4e849c0a35e4b748b49abdb13e31562791a`, committed at `92c392b`
before any family was measured.

Authority effect: none. `iter001-acquisition-contract` remains the sole registered blocker.

## Verdict first

**F-C3 fires for `bang_bang` and `half_gain`.** Both produced agreement of exactly 1.000 with
non-zero masking events. The frozen rule states that this is `INVALID_CIRCULAR` for that compensator
and that no accuracy figure may be reported for it. That rule is honoured: **no accuracy is claimed
for either family.**

`integrating` is valid and is reported.

## What was measured

Seeds 23 through 37, disjoint from every seed in prior work. Severities `{15, 35, 55, 75, 95}`,
baselines `{30, 45}`, 750 cells per family.

| family | cells | masking events | exact command predicted | reportable agreement |
| --- | ---: | ---: | ---: | :--- |
| `bang_bang` | 750 | 60 | 0.9787 | **voided by F-C3** |
| `half_gain` | 750 | 45 | 0.5360 | **voided by F-C3** |
| `integrating` | 750 | 51 | 0.5240 | **0.9920** |
| `proportional` (prior gate) | 750 | 64 | 0.4453 | 0.9947 |

## The prediction that mattered

The freeze committed four predictions before measurement. The third was written to be able to
embarrass the proposal: **`integrating` must agree strictly below the proportional case**, because it
accumulates every step's disturbance into the commanded value, and the criterion's failures are
predicted to come from noise moving the actual command across a window edge the predicted command
did not cross.

Observed: **0.9920 against 0.9947.** Below, as predicted, and above the 0.80 floor.

F-C2 — which would have fired had `integrating` agreed at or above the proportional case — does not
fire. The stated error mechanism survives a test designed to break it.

## The falsifier defect

F-C3 was written to catch the failure that occurred earlier in this line of work, when a prediction
and a measurement collapsed into the same computation and returned a meaningless 175 of 175. It
fires here on results that are probably legitimate, and the evidence is in the table above.

`half_gain` predicted the exact commanded correction in **53.6 percent** of cells and the masking
outcome in **100 percent**. A circular computation would reproduce the command at 1.000, because it
would be reading the command rather than deriving it. Reproducing barely half the commands while
getting every outcome right is the signature of a genuinely predictive rule whose errors happen not
to cross a window edge — not of a restatement.

`bang_bang` predicted the exact command in 97.9 percent of cells, which is the quantization the
freeze itself anticipated: a command with two possible values is rarely flipped by small noise. Its
perfect agreement is explained by that mechanism.

**The discriminator between circularity and legitimate perfection is the exact-command rate, and
that number was already available when the freeze was drafted.** F-C3 should have been conditioned
on it — for example, firing only when agreement is 1.000 *and* the exact-command rate is also 1.000.
It was not, and the rule as frozen is the rule that governs.

## Why the rule is honoured anyway

Reinterpreting a falsifier after watching it fire inconveniently is the exact failure the freeze
exists to prevent. It is also what this repository already did once, when masking freeze v1's
definition was disambiguated after v1 returned a vacuous result — disclosed at the time, and
disclosed again here.

The two voided figures are therefore not reported, not quoted, and not pooled into any aggregate.
They are recorded as voided so that a corrected gate can be written prospectively rather than
retrofitted around a number already seen.

## What this establishes

In this laboratory, the susceptibility criterion holds against a compensator family it had never
seen, in the predicted direction: **`integrating` degrades the criterion to 0.9920 from the
proportional case's 0.9947**, and it degrades it for the predicted reason, because that policy
carries more of the disturbance into the commanded value.

Two further families produced results that the frozen rule voids. Whether they confirm invariance
remains **undetermined** and requires a corrected gate.

## What this does not establish

A simulator branch never counts as a physical incident. Nothing here concerns physical systems, real
autonomy implementations, or any compensator outside these four. No diagnosis, recovery, safety,
transfer, product-readiness, economic-value, or state-of-the-art claim is made or implied. No
novelty or priority claim is made.

## Next gate, and what it must fix

A corrected freeze must condition the circularity falsifier on the exact-command rate rather than on
agreement alone, and must be committed before `bang_bang` and `half_gain` are measured again. The
figures voided here may not be used to set its thresholds, because they have been seen.
