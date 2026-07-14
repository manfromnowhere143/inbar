# Verification Amendment 002: Execution Commit Identity

Status: AUTHORIZED CLERICAL CORRECTION BEFORE VERIFICATION AUTHORITY SELECTION

## Trigger

The Git-object audit of Verification Amendment 001 found that its expanded execution commit ID was
incorrect. The contract recorded `ab20d41e77aba35f01352ca5cc379505205d32c8`; the repository's
unique `ab20d41` commit resolves to `ab20d41be48003c443a807c733c4c8ce43445e01`.

The execution tree recorded by Amendment 001 was already correct:
`e3d8a8609e483b37c755b252e4f43b57b4731480`.

## Timing And Outcome Blindness

This defect was detected before selecting or committing a corrected-verifier authority, before
consuming any verification authority, and before inspecting `RESULT.md`, `readiness_report.json`,
`LEARNING.json`, the readiness-adjudicated payload, or the scientific verdict.

## Authorized Change

Only `trigger.execution_commit.git_commit` is corrected. The proof binding, proof files, dataset-
lock exception, original-verifier hash, outcome-blindness declaration, one-use limit, prohibited
actions, resource limits, and local trust limitations from Verification Amendment 001 remain in
force without change.

The corrected verification authority must bind both amendment contracts. It must reject the
incorrect commit ID, require the corrected commit to resolve as a Git commit with the already
recorded execution tree, and verify the ancestry chain through the proof and amendment commits.

## Machine Authority

`protocol/amendments/iter000_verification_002.json` is the controlling clerical correction. It does
not authorize a scientific rerun, a broader verifier exception, proof mutation, or result access.
