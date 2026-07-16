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
