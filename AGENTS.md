# Inbar Agent Bootstrap

Canonical workspace:
`/Users/danielwahnich/workspace/fieldtrue`.

Run first:

```bash
uv sync --link-mode copy --reinstall --group dev --frozen
uv run inbar mission validate --expect-failure iter001-acquisition-contract
uv run inbar handoff check
uv run pytest --cov
git status --short --branch
```

## Mission boundary

- Owner: Daniel Wahnich.
- This is an independent repository. Do not move it into Aweb, import Aweb internals, share Aweb
  database tables, or require Maestro/MCP to reproduce results.
- Do not build the general-purpose Daniel research engine here. Capture lessons in the append-only
  evidence ledger; build that engine separately only after several complete mission cycles.
- Aweb, Maestro, GCP, GPU, and external models are optional adapters. Discover capabilities at
  runtime; never invent Aweb slugs or provider IDs.

## Research discipline

## Standards, and the defects that produced them

Every rule below is machine-checked by `scripts/ci/verify_conventions.py` and
`scripts/ci/verify_guard_coverage.py`, invoked from `tests/unit/test_conventions.py` and
`tests/unit/test_guard_coverage.py` so they run in CI without editing the workflow. Each exists because
it was broken, and each names the defect so a future reader can judge whether it still earns its
place. A rule that no longer corresponds to a real failure should be deleted, not kept for symmetry.

- **Commit messages carry no trailers.** No `Co-Authored-By`, no session links, no tool attribution,
  no self-praise. Plain factual prose. *Defect 2026-07-18: nine commits reached public `main` with
  `Co-Authored-By`. The history is not uniform — 31 of 108 prior commits carried trailers — but the
  practice had settled clean for a long stretch, so the convention was observable only by reading the
  recent log. Those nine stand uncorrected; rewriting published history to hide a convention error is
  worse than the error.*

- **One cycle, one push, wait for green.** A handoff commit must be the tip of its own push and must
  reach green CI before the next cycle begins. *Defect 2026-07-18: cycles were batched and pushed
  together, so `73679e1`, a fully validated handoff, sits in history with zero CI and always will.
  Sentinel and Telos both push one artifact per commit for exactly this reason.*

- **Every result and every freeze is linked from `README.md`.** *Defect 2026-07-18: three RESULT
  documents existed and none was linked, while the README simultaneously asserted no result existed.
  A result absent from the front page is a broken narrative.*

- **A corrected claim may never reappear.** Superseded statements are pinned as tripwires. *Defect
  2026-07-18: an adversarial audit found nine false or stale statements, including a private remote
  that had become public.*

- **Before reporting any effect, test whether it is entailed.** If a computation that never touches
  the measurement reproduces it exactly, the effect is a correctness check on the implementation, not
  a measurement. *Defect 2026-07-18: four of five effects tested this way were entailed by
  construction, including a published headline that was falsified within the hour.*

- **A guard that cannot fail is not a guard.** Every control must be verified against a deliberately
  broken subject. *Defect 2026-07-18: three components were built, described as doing something, and
  found to do nothing, each having passed controls that could not fail on an inert component.*

- **Every guard in a registered authority module is falsifiable, and that is measured.** A `raise`
  no test can reach is either dead code or an untested control. *Defect 2026-07-19: commit `51d1885`
  shipped an authority module in which 42 of its 71 guards had no test that could make them fire,
  including guards backing `explicit_unknown_verified`, `caller_pinned_group_separation_verified`,
  and `manifest_artifact_hash_verified` — fields the assurance report asserts as verified. One guard
  was provably unreachable. The rule above had been written as prose and never mechanized, so it
  recurred within a day of being recorded. `scripts/ci/verify_guard_coverage.py` now measures it:
  registering a module is a ratchet, and a guard added to one fails the build until a broken subject
  reaches it.*

- **Run the full validation plan before starting a cycle**, not a subset. *Defect 2026-07-18: a
  20-minute cycle failed on a single 101-character line because `ruff check` was skipped in
  preflight.*
- Commit `HYPOTHESIS.md` before experiment-specific tooling or outcome inspection.
- Freeze source, split, baseline ladder, primary outcome, uncertainty method, spend ceiling, stop
  rule, falsifiers, verdict classes, and forbidden claims.
- Preserve raw evidence externally by content hash. Never commit restricted third-party bytes.
- Keep model-visible evidence separate from sealed truth and independent outcome evidence.
- Retain rejected hypotheses and tests with their disposition; never silently discard candidates.
- Validators must have negative fixtures and must fail closed.
- Run the committed analyzer once after proof collection. Amendments are prospective and explicit.
- Publish null, blocked, invalid, infrastructure-null, and correction outcomes at full weight.
- Do not call observational associations causal without intervention or invariant-mechanism proof.

## Safety and authority

- v0 execution authority is limited to `replay`, `simulator`, and human-approved `testbed`.
- No flight, live robot, live spacecraft, destructive, financial, deployment, credential, or secret
  operation is authorized by this repository.
- Frontier multimodal models generate proposals only. Physics constraints, approved action sets,
  independent execution, and calibrated abstention govern decisions.
- GPU, cloud, paid provider, or large dataset staging requires a run-specific resource lease and
  explicit approval receipt. Never inline or log secrets.

## Source of truth

- Machine contract: `mission/contract.json`
- Lifecycle: `mission/loop.json`
- Durable mission context: `CONTINUITY.md`
- Frozen master protocol: `PREREGISTRATION.md`
- Per-iteration authority: `experiments/<id>/HYPOTHESIS.md`
- Claims: `claims/registry.jsonl`
- Dynamic handoff: `HANDOFF.md` (generated; never hand-edit)
