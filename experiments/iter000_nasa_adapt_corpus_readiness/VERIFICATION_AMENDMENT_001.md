# Verification Amendment 001: Exact Signed Dataset-Lock Bytes

Status: AUTHORIZED FOR ONE VERIFICATION-ONLY CORRECTION

## Trigger

Attempt 001 consumed its single execution authority, completed acquisition and proof sealing, and
then stopped at independent final verification. The verifier raised
`ProofBundleVerificationError` with the message `dataset lock is not canonical pretty JSON`.

The complete generated proof and durable authority receipt are preserved without modification in
Git commit `15cd75dd761a1c3f1d75994445a9ce702c58810a`. The proof contains sixteen files. Its Git subtree
is `5ad82ba61c522fc3e292ab7ceed9f7085b556673`, and the SHA-256 of its canonical filename-to-file-
SHA-256 map is `bcc358bb5d2f837bb284970cfa686919fd91aa0864452e42c02f17c356556341`.

## Outcome Blindness

This amendment was written before inspecting `RESULT.md`, `readiness_report.json`, `LEARNING.json`,
the readiness-adjudicated ledger payload, or any scientific verdict. Only file names, byte counts,
content hashes, the ledger signature checkpoint, and the verifier exception were inspected.

No embedded result may be interpreted until this amendment, its machine contract, the corrected
verifier, and a separately selected verification authority are committed.

## Defect

The proof-local `dataset_lock.json` is byte-identical to the frozen protocol dataset lock. Its
SHA-256 is `884c1ff5daf60323437ad1d16efb01acb3e769ce71eade62fcde966bfe0a4367`,
which is the hash committed by the signed protocol bundle. The file is valid UTF-8 JSON with a
unique-key object and validates against the strict dataset-lock model. It retains the human-edited
serialization of the frozen protocol file rather than the verifier's preferred canonical pretty
serialization.

Canonical pretty formatting adds no integrity property after the verifier requires exact equality
to a separately selected, signed protocol hash. The test fixtures rewrote dataset locks through the
canonical serializer and therefore failed to exercise the real frozen file's serialization.

## Authorized Change

The corrected verifier may remove only the canonical pretty-JSON requirement for
`dataset_lock.json`. It must retain all of the following controls:

1. The file is regular and not a symbolic link.
2. UTF-8 decoding and JSON parsing succeed.
3. Duplicate JSON object keys are rejected.
4. The strict dataset-lock model rejects unknown or malformed fields.
5. The proof-local file SHA-256 exactly equals the dataset-lock hash in the signed protocol bundle.
6. The signed source event binds the same dataset-lock hash.
7. The verifier rechecks artifact bytes before returning a receipt.

Administrative code may route the exact correction command, validate the historical execution
tree instead of pretending that corrected verifier code was used during execution, and emit one
machine-readable verification receipt. A separately selected verification authority must bind the
old verifier, corrected verifier, amendment contract, exact proof tree, command, and zero-network
policy.

## Prohibited Actions

No producer rerun, download, parser execution, data mutation, proof mutation, ledger append,
signature replacement, threshold change, gate change, claim change, or result rewrite is
authorized. The correction may not canonicalize or replace the proof-local dataset lock. It may not
weaken canonical requirements for any other artifact.

Exactly one corrected verification of the committed proof is authorized. A failure requires a new
prospective amendment. The same-local-owner rollback limitations declared by Amendment 001 remain
unchanged.

## Machine Authority

`protocol/amendments/iter000_verification_001.json` is the controlling correction contract. A later
verification-authority artifact may bind the corrected verifier hash only after implementation and
adversarial tests are complete. Neither artifact authorizes another scientific execution.
