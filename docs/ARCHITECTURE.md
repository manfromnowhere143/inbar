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

Implemented scientific proof and controlled-execution paths that issue authority receipts use
signed, hash-chained records. The engineering-validation receipt described below is unsigned and
relies on exact Git lineage and content hashes. Across a complete authorized scientific run, the
applicable signed receipt set must bind:

- predecessor and run identity;
- source, dataset, case, code, Git tree, environment, model, and configuration hashes;
- evidence inputs and outputs;
- hypothesis priors/posteriors and rejected candidates;
- test authority, safety envelope, cost/risk, approval, and observation;
- independent outcome source;
- latency, compute, monetary cost, retries, and failure disposition;
- claim IDs and permitted/forbidden wording.

A general signed authority for every mission-stage transition is not implemented. The current
mission validator checks the registered stage and selected special transitions, but that is not a
complete evidence-backed lifecycle state machine. Inbar must add reconstructible transition receipts
before advancing beyond corpus qualification.

Local Ed25519 signatures prove key possession, not historical immutability by themselves. Strong
authorship requires an external timestamp or governed key anchor. Verification must state which
trust level is present.

## Recovery rendering

Generated recovery state is rendered from a private, no-hardlink clone of the selected committed
tree, not from ambient imported package objects. The parent overlays only descriptor-verified current
recovery inputs and starts a fresh interpreter against an exact authority-source manifest under a
bounded environment. The child emits a framed, hashed response. The parent validates the frame's
contract and integrity and rechecks the selected commit, recovery manifest, and current memory
record before accepting the rendered bytes.

This construction isolates the render from ambient import order and detects changes to every
descriptor-bound working-tree input during rendering. It does not create an independent custody
boundary or protect against a hostile process with the same operating-system identity that can
replace the launcher, interpreter, Git binary, or prepared dependency bytes. The result is an
internal candidate-tree consistency property whose source still requires review.

## Engineering validation evidence

Engineering validation is recorded separately from the implementation it tests. A canonical receipt
binds the exact subject commit and tree, ordered command plan, environment description, timestamps,
exit observations, stdout and stderr, structured JUnit and coverage artifacts, mission checks, and
unknown resource fields. Unknown cost or compute is never rewritten as zero.

The recovery verifier accepts a current receipt only when its commit is the single-parent child of
the implementation subject and changes only the receipt and its named artifacts. A final clean
recovery commit must in turn be the single-parent child of that evidence commit and change exactly
the memory ledger and generated handoff. The memory blob must strictly append its evidence parent,
and both final paths must remain regular nonexecutable blobs. The verifier re-parses every bound
artifact, binds coverage to the complete committed Python source inventory, requires zero skipped
tests and every registered credibility-control node to appear as a passed JUnit case, and recomputes
the test counts, combined statement-plus-branch coverage, exact mission check inventory, and expected blocker.
Prospective rendering is permitted at the evidence commit, but final checking requires the exact
clean recovery child. The receipt declares same-operator observation without independent
attestation, scientific result, or authority effect. Bound logs and self-recorded exit codes are not
execution attestation; base-controlled CI must independently run its applicable contract and quality
checks on the candidate head.

Recovery materialization accepts exactly the eligible regular files in the selected committed tree,
with path, content, size, and executable-mode parity. Ignored or visible untracked files, dirty
tracked bytes, symbolic or hard links, and special files cannot enter the private snapshot. The
current memory ledger remains the only descriptor-verified overlay needed to render a prospective
recovery commit.

## Control production

The ambient admission-control launcher is a preparation and observation process, not an authority.
It materializes a clean committed snapshot, prepares the hash-authenticated runner, sends one bounded
typed request, and checks the returned request, commit, tree, and durable receipt-byte bindings. It
does not import signing code, open a private key, assemble a receipt, or publish authority artifacts.

The fixture producer runs as a fresh isolated child under the committed launcher. It checks the exact
committed snapshot census, distribution inventory, source closure, contract, Git identity, and
preregistration ancestry and bytes; executes the frozen controls; assembles all signed fields; opens
the fixed fixture key only after final rebinding; and publishes an exact bundle with
descriptor-relative no-replace semantics. Producer V1 receipts use V2 wire schemas, are structurally
`test_fixture`, use a distinct signer and key path, and reject the canonical trust anchor. The
canonical `bootstrap` contract cannot reach key access or publication.

The snapshot materializer preserves committed `0644/0755` semantics while narrowing filesystem
access to owner-only `0400/0500`. The producer is the only production call site that opts into the
explicit private-mode translation when checking its authenticated snapshot. Canonical working-tree
verification and every other production caller retain the ordinary mode policy. This keeps snapshot
files owner-readable or owner-executable only without widening the accepted source state on those
other paths.

The fresh process does not inherit ambient live Python objects, but it cannot authenticate itself
against an ambient process that controls its arguments or prepared dependency bytes before import.
Nor is it an independent custody boundary: a hostile process with the same operating-system identity
can access a mode-0600 key. Production authority therefore requires an independently enforced
supervisor and signer that reconstruct the subject, plus an exact authenticated read-only verifier
and terminal mission integration.

## Proof adjudication

Iteration proof bundles retain the exact data lock, signed resource receipts, coverage, the
model-visible incident manifest, and the separately sealed truth manifest. Third-party raw bytes
remain outside Git because redistribution rights are not established. Their exact hashes and byte
counts remain frozen in the lock and receipts.

The independent verifier does not accept the producer's gate states as authority. It validates the
signed lifecycle and artifact graph, then recomputes source-receipt consistency, parser coverage,
truth commitments, evidence/truth joins, leakage controls, construct counts, transfer support, and
evidence usefulness from proof-local material. A signed report that differs from this recomputation
is rejected. `proof/RESULT.md` and `proof/LEARNING.json` are the only authoritative rendered
outputs; unauthenticated duplicates are not produced.

Execution attempts use distinct proof roots. A failed attempt is never overwritten or completed
in place. A retry requires a prospective machine-readable amendment that binds the triggering
evidence, freezes scientific inputs, enumerates the permitted implementation change, forbids wider
changes, and sets an exact retry count. Mission validation rejects uncommitted trust inputs,
modified failure evidence, insecure transport, symbolic-link attempt roots, and unregistered
attempt identifiers.

An amended attempt also requires a separately selected execution-authority specification. Before
the proof root is created, the producer exclusively creates, signs, flushes, and directory-syncs a
single-use consumption receipt. The authority binds every source file, every protocol schema, the
gate-control execution seal, the lockfile, the validator, and the independent verifier. Proof-local
copies cannot replace the selected authority because verification compares them byte-for-byte.

The current durability boundary is local Git plus a pinned Ed25519 signer. It blocks concurrent
local execution and ordinary replay after deleting proof output. It cannot block the same local
owner from deleting the receipt, rolling back the checkout, or compromising the signing key. An
external timestamp, append-only transparency log, monotonic hardware counter, or write-once store
is required before making a stronger anti-rollback claim.

The TLS recovery path binds both the normalized `certifi` distribution version and the SHA-256 of
the installed CA bundle. Mission validation rebuilds the verified context, confirms certificate and
hostname enforcement, requires TLS 1.2 or newer, compares the loaded authorities to a separately
built context, and rejects a byte-modified trust store even when the modified PEM remains parseable.

## Cloud boundary

The core emits immutable `JobSpec` JSON. A valid spec binds an exact Git SHA, immutable OCI digest,
allowlisted command, data/case hashes, resource request, maximum runtime, idempotency key, artifact
prefix, decimal-string budget, independent cost estimate, secret references, execution authority,
and approval-receipt hash. Missing budget, mutable image, unknown quota/cost, unhashed data, absent
approval, or non-allowlisted command fails closed.

No cloud SDK is a core dependency. GPU orchestration remains manual until a provider adapter passes
an end-to-end receipt and artifact-integrity test.

## Product evolution

The target contracts are intended to support offline incident replay, live shadow recommendations,
approved test stands, fleet learning, recovery synthesis, and onboard monitor generation. These are
planned stages, not current validated capabilities. Moving between them changes authority and
evidence requirements, not scientific semantics.
