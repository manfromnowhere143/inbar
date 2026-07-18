# Result: Anomaly Masking by Autonomous Corrective Action

Status: RECORDED

Gate: `ADJUDICATION_FREEZE_MASKING_V3.md`, SHA-256
`e2acf50440e3f08995e900b753eb4566806e71df695ce4bb2d620e466b6f9366`, committed at `d35054b`
before any confirmatory cell was measured.

Authority effect: none. `iter001-acquisition-contract` remains the sole registered blocker.

## Primary result

Confirmatory set: seeds 1 through 7, five mechanisms, five severities, 175 cells. Seed 0 was
excluded as contaminated during instrument correction and is not pooled here.

**Masking event rate: 20 / 133 = 0.1504.** Three numbers reported together:

| quantity | value |
| --- | --- |
| masking events `k` | 20 |
| cells resolvable pre-action `N` | 133 |
| cells excluded, unresolvable pre-action `u` | 42 |
| total cells `N + u` | 175 |

Per mechanism, every mechanism reported including those with zero events:

| mechanism | cells | resolvable | excluded | events | median `M` |
| --- | ---: | ---: | ---: | ---: | ---: |
| `gain_drift` | 35 | 35 | 0 | 0 | +4980 |
| `actuator_loss` | 35 | 35 | 0 | 0 | −4346 |
| `actuator_deadband` | 35 | 14 | 21 | **14** | 0 |
| `sensor_bias` | 35 | 35 | 0 | 0 | −154551 |
| `unknown` | 35 | 14 | 21 | 6 | 0 |

Overall median masking index: **0**. Cells with `M > 0` (correction reduced identifiability): 56 of
175. Cells with `M < 0` (correction increased identifiability): 77 of 175.

## Falsifier disposition

- **F-M1 — zero masking events: does not fire.** Twenty events occurred.
- **F-M2 — non-positive median masking index: FIRES.** The overall median `M` is 0, and more cells
  were revealed than masked. Correction does not systematically reduce identifiability in this
  laboratory.
- **F-M3 — boundary artifact: does not fire.** Masking events span `S_pre` from 1047 to 13023, and
  only 7 of 20 lie within ten percent of the 1000 threshold. The effect is not an artifact of where
  the threshold was placed.
- **F-M4 — gain sensitivity: does not fire.** The rate holds across the safe envelope: 0.1429 at
  gain 10, 0.1504 at 20, 40, and 60, and 0.1654 at 80. No reversal.

## What was found

Masking is real in this laboratory, and it is **mechanism-specific rather than general**. The two
findings must be stated together because either alone misrepresents the result.

**Masking occurs, concentrated entirely in one mechanism.** `actuator_deadband` was masked in 14 of
14 resolvable cells. The mechanism is exact and is visible in the severity breakdown:

| severity | deadband threshold | masked / resolvable | excluded |
| ---: | ---: | :---: | ---: |
| 25 | 15 | 0 / 0 | 7 |
| 45 | 27 | 0 / 0 | 7 |
| 70 | 42 | 0 / 0 | 7 |
| 85 | 51 | **7 / 7** | 0 |
| 100 | 60 | **7 / 7** | 0 |

The baseline command is 50. Masking occurs exactly where the baseline sits *below* the deadband
threshold, so the fault is visible at rest, and the correction raises drive *above* it, where a
deadband passes commands unattenuated and is indistinguishable from nominal. Below severity 70 the
threshold is under 50, the fault is already invisible at baseline, and those cells are correctly
excluded rather than counted as masked.

**Correction reveals more faults than it hides.** `sensor_bias` has a median `M` of −154551 and
`actuator_loss` −4346: raising drive excites the actuator path and separates attenuation faults that
were closer to their neighbours at baseline. Across all cells, 77 were revealed against 56 masked.

The honest one-sentence statement: **an autonomous compensator in this laboratory reveals more than
it masks overall, while reliably destroying the evidence for one specific fault class whose
signature the correction happens to cross.**

## What this does not establish

This is a simulator. A simulator branch never counts as a physical incident. The result does not
establish that anomaly masking does or does not occur in any physical system, that any real autonomy
implementation masks or reveals faults, or a diagnosis, recovery, safety, transfer,
product-readiness, economic-value, or state-of-the-art claim. It says nothing about NASA, JPL, or
any named organisation's systems.

The observation that this problem appears unowned rests on a dated, non-systematic literature scan
and is not an exhaustive novelty claim. Any priority claim requires a systematic review that has not
been performed.

## Prior outcomes on the same question

Two measurements preceded this one and neither tested the hypothesis. Both are retained unedited.

- **v1: `MEASUREMENT_VACUOUS`.** The frozen definition resolved to a catalog-wide index that one
  degenerate hypothesis pair drives to zero for every cell. Denominator zero by construction.
- **v2: `INFRA_NULL`.** The compensator commanded no correction on any cell, because observing the
  pre-action state at rest leaves nothing to compensate. The instrument could not act.

Both were instrument defects, not observations about the world, and neither is reportable as the
F-M1 finding.

## Reproduction

```bash
uv run pytest tests/unit/test_masking.py -q
```

The measurement is deterministic integer arithmetic over hash-derived disturbances. Every reported
quantity is recomputed from atomic cells by `recompute_masking_result`; no aggregate is asserted.
The instrument's non-inertness is verified by three guards that fail against a zero-gain compensator
and pass against the live one.
