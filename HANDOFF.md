# Inbar Mission Handoff

This file records the current resumable state. Verify every Git, remote, schema, and memory anchor
before relying on it.

## Resume identity

- Workspace: `/Users/danielwahnich/workspace/fieldtrue`
- Owner: Daniel Wahnich
- Branch: `main`
- Active mission and repository name: Inbar
- Preferred command: `inbar`
- Legacy compatibility namespace: `fieldtrue`
- Terminal Phase 1 base commit: `b1e6b369d39de98004b3eacb2770779d86410504`
- Preregistration commit: `52d71e16a75df12adf47e943fd5c329f6e04d5c0`
- Private remote: `https://github.com/manfromnowhere143/inbar.git`
- Public release: not authorized

The identity migration is the commit containing this handoff. It changes active metadata and future
publication identity only. It does not rewrite Git history, signed evidence, frozen protocol IDs,
the `fieldtrue` Python package, or existing research-memory records.

Research-memory V1 remains valid only for the immutable Fieldtrue-era prefix through sequence 49.
New appends use V2 with `mission_id` equal to `inbar`; the verifier rejects identity regression.

## Scientific state

- Iteration: `iter001_physical_causal_evidence_acquisition`
- Source-role verdict: `KILL_PUBLIC_SUBSTRATE`
- Canonical control authority: `bootstrap`
- Production control receipt: absent
- Pilot admission verdict: none
- GPU, cloud, paid, live-system, and download use: zero
- Publication state: blocked

The product wedge is an offline and shadow-mode evidence dossier compiler with ranked,
human-reviewable safe-test recommendations. It has no live command authority.

## Implemented checkpoint

- Same-incident evidence, rights, clock, custody, hypothesis, approval, execution, recovery,
  settled-outcome, split, comparator, review, resource, and candidate-registry contracts
- Exact conjunctive admission over eligible physical incident roots
- Twenty-two isolated, outcome-bound admission controls
- Root-certified terminal verifier certificate model
- Inbar-bound publication signer anchor that rejects legacy cross-mission authority
- Complete input manifests with canonical UTF-8 ordering, mode and content binding, hard-link and
  case-fold controls, descriptor-relative no-follow traversal, mutation detection, and hard bounds
- Typed terminal and invalidity records with Ed25519 issue and read-only verification primitives
- Bound artifact and complete-input replay checks
- Five new generated terminal schemas

Phase 1 remains dormant. No certificate or terminal result was generated, no private verifier key
was loaded, no CLI path was activated, and canonical status was not changed.

## Validation evidence

- Tests: 376 passed, one platform-capability skip
- Branch-aware coverage: 90.20 percent; required minimum: 90 percent
- Terminal-authority module coverage: 90 percent
- Ruff formatting and lint: passed
- Strict mypy: passed across 23 source modules
- Generated schemas: 85 verified
- Dependency lock: verified
- Research memory before identity event: 50 events, head `772dfaa6a959ed9aab529a6e7cc8ee471ca49b3a7351ee6423d600f2fcec8f66`

## Remaining blockers

1. Prospectively freeze shortcut V2 with the exact-census, no-fit rule as the sole construct-kill
   authority.
2. Add shared prediction keys, mechanism-resolution targets, and recipient-scoped truth-release
   receipts.
3. Wire terminal generation and deterministic replay through the production validator, including
   atomic single-use output and reconstructible invalidity records.
4. Add format-specific opaque-media leakage parsers.
5. Seal only after clean committed controls and independent verification.

## Open-source gate

Inbar is intended for open source. Keep the repository private until the exact release commit has a
fully green clean-clone matrix, an explicit license, completed rights and secret scans, consistent
identity, citation, security, contribution, and claim documents, and Daniel's approval of the
license and visibility change.

## Non-negotiable boundaries

- Do not alter frozen Iteration 000 artifacts, consumed authorities, or existing memory records.
- Do not rename `fieldtrue.*` schemas, Python imports, environment variables, or historical command
  records during this migration.
- Do not generate production authority from a dirty or uncommitted tree.
- Do not train, spend cloud credits, command a live system, or publish a performance claim.
- Do not build the standalone general research engine in this repository.

## Resume procedure

```bash
cd /Users/danielwahnich/workspace/fieldtrue
git status --short --branch
git log --oneline --decorate -5
uv sync
uv run inbar memory verify
uv run inbar schemas check
uv run mypy src
uv run ruff check .
uv run pytest
uv run inbar mission validate --expect-failure iter001-acquisition-contract
```

First confirm the private remote, active Inbar identity, immutable memory prefix, and canonical
bootstrap status. Then close blockers in the listed order.
