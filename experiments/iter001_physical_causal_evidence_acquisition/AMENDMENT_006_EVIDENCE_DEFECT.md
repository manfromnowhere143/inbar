# Amendment 006: Evidence and Artifact-Binding Defect Record

Status: CORRECTION ON THE RECORD

Recorded: 2026-07-19

Subject: `AMENDMENT_006.md`, artifact SHA-256
`266d68f0f28b6474fbb09f971904bef394f8c1315b6fcb388eba88c4d0d5a741`

Authority effect: none. This record grants or removes no authority. It corrects the repository's
description of what Amendment 006 covers and what evidence its selector comparison retains.

## Artifact-binding defect

Amendment 006 binds two source artifacts by SHA-256 and states that if either changes, the amendment
does not cover the changed file and a superseding proposal is required.

| Artifact | A006-bound SHA-256 | First committed A006 implementation | Current SHA-256 at `e88dd38` |
| --- | --- | --- | --- |
| `src/fieldtrue/graded_laboratory.py` | `647472e94cac54dd4a295b3bb2452dc90dbbea42587ba5ac093cd1610cbddfb9` | `b90850fc09d31f32d5c17ea5ef715c4f3a76f3e4e30fb1649c4f24554b031201` | `80423ff30cf15bd3bf5bbd374aecb95eb78aaa97f401f98075bb51c4f7afe6ef` |
| `src/fieldtrue/active_selection.py` | `a58b445f3ef6c532c2500c1f3ac2828fa406e914b126913593212a8a2f00c044` | `cf6846d81c1d3469cebcec5fbe1f408da5708aa3671fe1a7d187946dae4e5044` | `cf6846d81c1d3469cebcec5fbe1f408da5708aa3671fe1a7d187946dae4e5044` |

This forward correction also removes the false A006-coverage wording from the two module
docstrings. Their corrected SHA-256 values are
`b17ac2b3e61ba1c43ca51870b3c0f22c0c15ada0c0503628c6c38f50715ec729` and
`a0c83eef760e66c23c124a42f2cb80f782473c514d804382d98f631cb8062de5`,
respectively. The executable AST used by the replay is unchanged and is checked against the
historical freeze source.

Neither source file entered Git with the hash approved by Amendment 006.
`graded_laboratory.py` then changed again at `eb37d93`. No superseding amendment binds either
committed implementation. Amendment 006 therefore does not cover the current graded laboratory or
active selector.

The amendment says all four scoped artifacts are “bound by content,” but its two test rows contain
control-count prose rather than SHA-256 values. It therefore supplies no exact content binding for
`tests/unit/test_graded_laboratory.py` or `tests/unit/test_active_selection.py`, independent of the
source-file mismatch.

The first masking freeze also states that `GRADED_CONFIG` is at the hash bound by Amendment 006.
That statement is false for every committed version of the graded laboratory. The freeze remains
unchanged as historical evidence; this record is its forward correction.

## Selector-comparison evidence defect

The repository contains no A006-linked implementation of the cost-blind maximum-separation or
cheapest-guaranteed-separation comparator described by Amendment 006, no executable comparison
runner, no atomic campaign records, no frozen risk-weight sweep, and no result-level test that
reconstructs the comparison. The retained tests validate the information-gain selector's mechanics;
they do not reproduce a classical comparison.

The reported 0.950 accuracy, 28.50 and 28.30 costs, within-1.01 sweep, cost-order reversal, and claimed
tie therefore exist only in outcome-informed prose. They cannot be reconstructed from retained
repository evidence.

## Downstream result boundary

Later masking, susceptibility, and compensator-family documents use the committed graded laboratory.
Their stated authority effect was already `none`, but current narrative elevated some of their
simulator observations into scientific-sounding results. The source-binding defect prevents
Amendment 006 from supplying implementation coverage to any of them.

A retrospective reconstruction now reproduces the susceptibility document's 1,121 of 1,125 overall
agreements, 746 of 750 informative agreements, 64 masking events, and four disagreement cells from
the frozen schedule. That reconstruction is useful engineering evidence, not a contemporaneous
execution record and not a repair of Amendment 006. It also establishes two limitations absent from
the original interpretation:

- the frozen 0.90 agreement threshold was below the always-non-masking comparator's 686 of 750
  informative-cell accuracy; and
- F-S2 did not machine-define how a disturbance width maps to distance from a command-window
  boundary, so its disposition cannot be independently replayed as a preregistered falsifier.

The internal association is not refuted: on the same simulator the replay gives sensitivity 60/64,
specificity 686/686, and balanced accuracy 31/32. Its original confirmatory interpretation is
`INCONCLUSIVE`, not `SUPPORTED`.

## Disposition

- Current A006 implementation coverage: `BLOCKED`.
- A006 classical-selector comparison as retained evidence: `INVALID`.
- Susceptibility arithmetic: retrospectively reconstructed as an engineering observation.
- Susceptibility confirmatory interpretation: `INCONCLUSIVE`.
- `INVALID` means unsupported by retained reconstructible evidence; it does not mean the numerical
  selector observation has been refuted.
- Amendment 006, its machine proposal, and its signed receipt remain immutable historical evidence
  and are not rewritten.
- The information-gain selector may be described as implemented in the source tree, but not as
  A006-covered, ratified, superior, tied, sufficient, or scientifically evaluated.
- The active-test milestone remains unresolved. It is not closed as a null.

A future historical reconstruction of the selector comparison would remain exploratory because the
outcome is already known. A claim-bearing comparison requires a prospectively approved superseding
amendment that binds exact committed code, schemas, comparator definitions, episode schedule,
weights, atomic outputs, falsifiers, and independent recomputation before an unseen run.
