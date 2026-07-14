# Architecture

## Decision

The mission is a local-first Python system with provider-neutral ports. Scientific semantics live
entirely in this repository. Cloud runners, Aweb, Maestro, simulators, test stands, and frontier
models may implement ports but cannot redefine evidence, verdicts, or claims.

## Planes

1. **Evidence plane:** immutable, content-addressed observations with source authority, clock
   domain, acquisition time, license, and transformation lineage.
2. **Truth plane:** separately stored cause, intervention, and settled-outcome records. It is never
   passed into model-visible bundles.
3. **Hypothesis plane:** competing mechanism graphs plus an explicit unknown mechanism, retaining
   rejected candidates and dispositions.
4. **Test plane:** approved diagnostic actions scored by information gain, cost, delay, and risk
   inside a frozen safety envelope.
5. **Execution plane:** deterministic replay first, then simulator, then human-approved physical
   testbed. v0 has no flight authority.
6. **Verification plane:** independent outcome authority evaluates action validity, target
   validity, and settled physical recovery.
7. **Compilation plane:** a verified mechanism becomes a typed monitor specification with validity
   domain, calibration, latency/resource envelope, false-alarm bar, and lineage.
8. **Claim/value plane:** claims link to exact evidence and forbidden wording; economic value uses
   a lower confidence bound after integration, compute, and false-action costs.

## Dependency direction

```text
domain models + mathematics
          ^
          |
provider-neutral ports
          ^
          |
application services
          ^
          |
local / dataset / simulator / cloud adapters
```

Domain code imports no adapter, cloud SDK, Aweb code, model provider, or simulator. The local
replay path is the reference implementation and must reproduce every published result without
credentials.

## Core ports

- `EvidenceSource.load_case`
- `HypothesisEngine.infer`
- `TestPlanner.select`
- `TestExecutor.preview` and `execute`
- `RecoveryVerifier.verify`
- `ArtifactStore.put` and `get`
- `RemoteJobScheduler.plan`, `preflight`, `submit`, `poll`, and `collect`

Execution and verification ports are intentionally distinct. The same learned model cannot be
bound as both proposer and sole outcome authority.

## Evidence state

Every transition emits a signed, hash-chained receipt binding:

- predecessor and run identity;
- source, dataset, case, code, Git tree, environment, model, and configuration hashes;
- evidence inputs and outputs;
- hypothesis priors/posteriors and rejected candidates;
- test authority, safety envelope, cost/risk, approval, and observation;
- independent outcome source;
- latency, compute, monetary cost, retries, and failure disposition;
- claim IDs and permitted/forbidden wording.

Local Ed25519 signatures prove key possession, not historical immutability by themselves. Strong
authorship requires an external timestamp or governed key anchor. Verification must state which
trust level is present.

## Cloud boundary

The core emits immutable `JobSpec` JSON. A valid spec binds an exact Git SHA, immutable OCI digest,
allowlisted command, data/case hashes, resource request, maximum runtime, idempotency key, artifact
prefix, decimal-string budget, independent cost estimate, secret references, execution authority,
and approval-receipt hash. Missing budget, mutable image, unknown quota/cost, unhashed data, absent
approval, or non-allowlisted command fails closed.

No cloud SDK is a core dependency. GPU orchestration remains manual until a provider adapter passes
an end-to-end receipt and artifact-integrity test.

## Product evolution

The same contracts support offline incident replay, live shadow recommendations, approved test
stands, fleet learning, recovery synthesis, and onboard monitor generation. Moving between those
stages changes authority and evidence requirements, not scientific semantics.

