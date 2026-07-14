# Handoff

Generated from committed mission state. Do not hand-edit this file.

## Resume identity

- Workspace: `/Users/danielwahnich/workspace/fieldtrue`
- Owner: Daniel Wahnich
- Branch: `main`
- Generated from commit: `d276a7e648827372e6198329b2dc7ec00e8b024c`
- Generated from tree: `d980575f8e8c0e6699d63078dc5ee1664097e400`
- Git remotes: `none`
- Frozen repository identity: Fieldtrue
- Selected future-facing name: Holds
- Name status: research selection only; formal trademark clearance and any separate product repository remain pending.

## Verified state

- Iteration: `iter000_nasa_adapt_corpus_readiness`
- Attempt: `attempt_001`
- Verdict: `BLOCKED_EVIDENCE`
- Flow: `normal`
- Result reproducible: `true`
- Proof commit: `15cd75dd761a1c3f1d75994445a9ce702c58810a`
- Proof subtree: `5ad82ba61c522fc3e292ab7ceed9f7085b556673`
- Authority: `iter000_verification_001`
- Authority SHA-256: `154dee03ea4dc30507b9b2bcd57d83617655da7d10501f9f0e881088a7ed5dd9`
- Consumption hash: `48fd3f90e6a4bed28c11b74c54bf5b31d91d3c17057979aa0b4cbc25f3a1f6c7`
- Receipt hash: `e00386a32805d8ff517d3a653a93f6f8b000d6eb4fbd4a505e85dfc15725b68f`
- Receipt signer: `4c67fd1a8cda703c589e8ee00963f5787be09c20ba86e0758eef37bb7878af05`
- Passed gates: `source-integrity`, `parser-integrity`, `truth-separation`
- Blocked gates: `minimum-count`, `ambiguity`, `discriminating-action`, `transfer-support`, `evidence-usefulness`
- Authorized next action: Acquire additional independently verified physical incidents and reviewed safe test actions; ADAPT remains parser and evidence-plane validation only.

## Non-negotiable boundaries

- The verification correction is consumed. Never invoke it again or delete its receipt.
- Attempt 001 is complete. Never rerun it or rewrite its proof.
- Do not lower readiness thresholds to manufacture a pass.
- Do not authorize: GPU or learned-model training.
- Do not authorize: active-diagnosis performance claim.
- Do not authorize: recovery or safety claim.
- Do not authorize: cross-hardware transfer claim.
- Do not authorize: product or economic-value claim.
- Do not present iteration 000 as a model benchmark. It is a corpus and construct-readiness result.
- Do not rename or rewrite the frozen evidence history during a Holds identity transition.
- Do not build the standalone research engine in this repository.
- Do not publish without independent domain review, venue-scope review, rights verification, and traceable manuscript artifacts.

## Quality evidence

- Tests passed: `224`
- Branch-aware coverage: `90.25%`
- Executable gate controls: `16`
- Mission invariants after receipt: `20/20`
- Research-memory events: `28`
- Research-memory head: `2e68dc002ba957830b2e691d9976a329eebe2250f1ee3a4c3b8a0b1beaa299bb`
- Verification resource usage: `{"cloud_jobs": 0, "gpu_hours": 0, "network_access": false, "paid_calls": 0}`

## Start every resumed session

```bash
cd /Users/danielwahnich/workspace/fieldtrue
uv sync --group dev
uv run fieldtrue mission validate
uv run fieldtrue memory verify
uv run pytest --cov
git status --short --branch
```

All five commands must pass or be explained before new mission work begins.

## Next mission decision

Design a prospective corpus-acquisition iteration for independently reviewed incidents across multiple hardware families, then freeze its sources, rights, mechanisms, ambiguity labels, safe actions, transfer groups, cost ceiling, and kill gates before collection or model work.

The next iteration must be prospective. Commit its hypothesis and acquisition contract before collecting data, changing gates, or implementing learned-model experiments. It must specify source rights, at least two hardware families and identities, independently reviewed mechanisms, pre-outcome ambiguity sets, safe discriminating actions, explicit clock domains, transfer grouping, uncertainty, resource ceilings, stop rules, and executable negative controls.

ADAPT remains useful as a frozen parser and evidence-plane regression corpus. It is not sufficient as the sole scientific substrate for the active-diagnosis product claim.

## Research-engine extraction

The append-only ledger is `memory/research_engine_extraction.jsonl`. Preserve its prefix. Continue recording corrections, blocked results, costs, manual work, authority transitions, and resumption state. Generalization into the separate research engine remains deferred until multiple missions contain real data and compute paths.

Generated at `2026-07-14T20:27:37.935658Z` from commit `d276a7e648827372e6198329b2dc7ec00e8b024c`.
