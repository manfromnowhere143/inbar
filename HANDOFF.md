# Inbar Mission Handoff

This file records the current resumable mission state. Verify every Git anchor and command result
before relying on it.

## Resume identity

- Workspace: `/Users/danielwahnich/workspace/fieldtrue`
- Owner: Daniel Wahnich
- Branch: `main`
- Bootstrap implementation commit: `b79f2d114d1081550f50ab55aefbcace5dcb7521`
- Bootstrap implementation tree: `47ab2201df06d77001c2678584a080cf649cae93`
- Git remotes: none
- Historical repository identity: Fieldtrue
- Selected mission name: Inbar
- Public spelling: title-case `Inbar`, never the acronym form `INBAR`
- Name status: selected by Daniel; formal commercial trademark clearance and any repository or
  package migration remain pending

## Scientific state

- Iteration: `iter001_physical_causal_evidence_acquisition`
- Preregistration commit: `52d71e16a75df12adf47e943fd5c329f6e04d5c0`
- Preregistration SHA-256:
  `47a1920b1b5326601c7404d17a6aac0df3309c2433fa76f56f0dffedf2511ad8`
- Source-role verdict: `KILL_PUBLIC_SUBSTRATE`
- Canonical control authority: `bootstrap`
- Production control receipt: absent
- Pilot admission verdict: none
- Publication state: blocked

No screened public source supplies the full same-incident contract for clocked multimodal evidence,
pre-outcome ambiguity, independent mechanism truth, reviewed diagnostic action, realized diagnostic
and recovery execution, and an independently settled outcome. Public sources remain role-limited
parser, simulator, shift, and shortcut controls. New qualifying physical evidence must come through
prospective human-approved testbeds.

The initial product wedge is an offline and shadow-mode evidence dossier compiler with ranked,
human-reviewable safe-test recommendations. It has no live command authority.

## Implemented bootstrap

- Typed physical evidence, rights, clocks, custody, hypothesis, approval, execution, recovery,
  outcome, resource, split, comparator, and review contracts
- Signed candidate registry that separates discovered roots from complete eligible dossiers
- Conjunctive admission over the same physical incident roots
- Validator-recomputed cross-plane collision, sequence-order, near-duplicate, and leakage controls
- Explicit test-fixture versus canonical authority profiles
- Twenty-two exact outcome-bound admission controls
- Isolated offline and frozen control execution with fixture-tree, Git-blob, dependency-lock, and
  exact ordered source-path bindings
- Delayed governance-key loading after control completion and clean-HEAD rechecks
- Production verification that rejects canonical `bootstrap` authority

## Unresolved release blockers

Do not seal or publish until every item below is closed with executable negative tests:

1. Replace self-asserted shortcut-baseline booleans with executable, truth-bound recomputation.
2. Bind each established physical mechanism to the correct known or unknown hypothesis.
3. Require ambiguity review to finish before safe-test review and downstream outcome access.
4. Bind independent settled-outcome authority to the selected test, observation, and diagnostic
   execution it declares valid.
5. Require derivative-data redistribution permission in the exact rights gate.
6. Bind shortcut, protocol-review, source-registry, and complete input authority into a terminally
   signed output with read-only reconstruction verification.
7. Emit a content-bound `INVALID` artifact for trust or proof-reconstruction failures.
8. Freeze exact clock thresholds in the canonical contract validator.
9. Add format-specific opaque-media leakage parsers beyond the current bounded known-token scan.
10. Raise meaningful branch-aware coverage from `87.50%` to the frozen `90%` minimum.

The canonical contract intentionally contains placeholder validator and control-suite bindings.
`control_authority_status` is `bootstrap`; both production verification paths reject it. Never
replace those placeholders or set `sealed` without a clean committed implementation, a complete
test matrix, a newly generated root-signed receipt, and independent read-only verification.

## Validation evidence

- Full behavioral matrix before the final leakage hardening: `298 passed`
- Branch-aware coverage from that matrix: `87.50%`; required: `90%`; gate failed
- Hardened acquisition and control-authority matrix after the final corrections: `69 passed`
- Ruff formatting and lint: passed
- Strict mypy: passed across `22` source modules
- Generated schema verification: passed
- Dependency lock verification: passed
- Research-memory events: `38`
- Research-memory head:
  `fce24f4b8f488c05bde245904f1eb8cadc5993078eef1e5283dfc3cc66d55edc`

The full coverage failure is a real quality block, not a test failure hidden by reporting. The
focused post-hardening matrix does not replace the required final full matrix.

## Resource state

- GPU seconds: `0`
- Cloud jobs: `0`
- Paid calls: `0`
- Live-system actions: `0`
- Public-dataset downloads in Iteration 001: `0` bytes
- Aggregate engineering wall time, CPU time, and peak memory: not measured; do not report as zero

Daniel reported a mutable shared Google Cloud credit balance for Inbar, Sentinel, and Talos. It is
an operator budget observation, not a frozen protocol value. Inbar must not spend it until a
separate post-admission compute plan defines model scope, per-mission accounting, stop limits, and
approval.

## Non-negotiable boundaries

- Do not rerun or rewrite the frozen Iteration 000 attempt or its consumed correction.
- Do not lower admission, coverage, or safety thresholds.
- Do not generate a production receipt from a dirty or uncommitted tree.
- Do not present synthetic fixture `PASS_PILOT` results as canonical evidence.
- Do not authorize GPU training, cloud execution, live robot or flight commands, or destructive
  tests.
- Do not claim diagnosis benefit, recovery, safety, transfer, product readiness, or economic value.
- Do not push, create a public repository, or publish before Daniel approves the exact identity and
  every release gate is green.
- Do not rename frozen Fieldtrue evidence history during an Inbar identity transition.
- Do not build the separate general research engine in this repository yet.

## Resume procedure

```bash
cd /Users/danielwahnich/workspace/fieldtrue
git status --short --branch
git log --oneline --decorate -5
uv sync --group dev
uv run fieldtrue memory verify
uv run fieldtrue schemas check
uv run mypy src
uv run ruff format --check .
uv run ruff check .
uv run pytest --cov --cov-report=term-missing
```

First confirm commit `b79f2d1`, a verified 38-event memory prefix, and canonical bootstrap status.
Then close the unresolved blockers in severity order. Do not generate or sign the production
control bundle merely because the behavioral tests pass.

## Research-engine extraction

The append-only ledger is `memory/research_engine_extraction.jsonl`. Preserve its exact prefix.
Continue recording decisions, failures, corrections, resources, authority transitions, name
changes, nulls, and handoff state. The later standalone research engine should generalize from
multiple complete missions; it is not authorized for implementation here.
