# Reviewer Entry Point

Five questions a skeptical external reviewer should ask, answered against the repository's
own committed bytes. This file is navigation, not evidence: nothing in it upgrades any claim.

## 1. What is this?

Inbar is authority-separated evidence machinery for physical fault diagnosis: typed
contracts, committed engineering-validation receipts, an append-only research memory ledger,
and a generated recovery handoff, built so that no agent grades its own claim. The package,
protocol, and schema namespace is `fieldtrue` — the historical name, retained because
committed signed artifacts and schema identifiers bind it — while the mission identity is
Inbar. The split is recorded in `CONTINUITY.md` and `docs/IDENTITY.md`.

## 2. What is the strongest verified result?

An engineering result, not a scientific one. The test suite passes with zero skipped cases
— 1,793 tests at the receipt current when this file was written — and recomputed
statement-plus-branch coverage is enforced above a 90.01 percent floor, recently about 91.3
percent; the generated `HANDOFF.md` carries the exact current values and their receipt
binding. The sharpest single
control is the guard-coverage ratchet, `scripts/ci/verify_guard_coverage.py`: it
AST-extracts every `raise` in a registered authority module, runs that module's adversarial
suite under a private coverage database, and fails the build naming any guard that no
deliberately broken subject reaches — and its analysis half is itself verified against
deliberately broken subjects. Its registry currently covers exactly two modules,
`src/fieldtrue/shortcut_v2_ontology.py` and `src/fieldtrue/shortcut_v2_target.py`. It is a
one-way ratchet, not a repository-wide property.

## 3. Where is the evidence?

- `HANDOFF.md` — generated deterministically from verified machine state; hand-editing it
  fails `uv run inbar handoff check`.
- `evidence/validation/` — committed engineering-validation receipts with the raw command
  outputs, JUnit, and coverage artifacts they bind.
- `memory/research_engine_extraction.jsonl` — the append-only research memory; CI rejects
  any rewrite of an existing byte.
- The defect post-mortems, linked from `README.md`:
  [`AMENDMENT_006_APPROVAL_DEFECT.md`](experiments/iter001_physical_causal_evidence_acquisition/AMENDMENT_006_APPROVAL_DEFECT.md)
  and
  [`AMENDMENT_006_EVIDENCE_DEFECT.md`](experiments/iter001_physical_causal_evidence_acquisition/AMENDMENT_006_EVIDENCE_DEFECT.md).

## 4. How can it be reproduced?

From a clean clone, the exact commands CI runs, also listed in `HANDOFF.md`:

```bash
uv sync --link-mode copy --reinstall --group dev --frozen
uv run inbar memory verify
uv run inbar schemas check
uv run inbar mission validate --expect-failure iter001-acquisition-contract
uv run inbar handoff check
uv run pytest --cov
```

The `--expect-failure` flag is deliberate: mission validation succeeds only while the
registered blocker still fails, so CI itself asserts that no acquisition authority exists.

## 5. What remains unverified?

Everything scientific. No scientific claim exists: the mission is blocked at
`iter001-acquisition-contract`, no corpus is admitted, and the claim registry activates no
result document. Authority separation is currently design intent, not an established
property: the `iter001-governance` private key sits unencrypted in the operator's working
tree, an automated agent has already used it to mint a valid compute lease, and every
committed receipt records `independent_attestation: false` — same-operator observation, no
independent attestation anywhere. The Amendment 005 laboratory cannot produce a negative
result, so nothing it reports is evidence about any method. The Amendment 006 selector
comparison is `INVALID` as retained evidence — unreconstructible, so no tie, sufficiency
conclusion, or selector disadvantage may be cited. And no independent reviewer exists:
branch protection requires zero approvals precisely because same-actor approval would not
create independence. If you are reading this as that reviewer, you are the control this
repository does not yet have.
