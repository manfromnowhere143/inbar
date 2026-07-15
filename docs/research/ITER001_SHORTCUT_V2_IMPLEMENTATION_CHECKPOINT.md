# Shortcut Authority V2 Implementation Checkpoint

Status: implementation only

Canonical control authority: `bootstrap`

Iteration: `iter001_physical_causal_evidence_acquisition`

## Authority binding

The implementation is permitted by the signed owner receipt committed at
`1286d36bbae921fa7ac6f9b1d0aec9d253fd0158`. That receipt approves only the proposal at
`551a4ffb8bad5f12312af4a074a467af6bc0ebc2`.

The bound raw artifact hashes are:

1. Amendment document:
   `9278eb33ef5a837c0ae043112f2fb041df4faa39cf34d26787a47f2326bf360c`
2. Machine proposal:
   `9c13ef9562f1842f238770fc3d2e3741a77b5db291b4a8cf6b3a66f2e218a76a`
3. Owner approval receipt:
   `904bc22b103a1b8835bde86971aa2fbf122eaf3b679de5e2923e794faec45a16`
4. Owner approval semantic receipt hash:
   `482575c10bb58da6b867ee60587cefa290512fa6f09529a324cea3002fd616c3`

The authority loader checks the exact worktree root, approved ancestry, raw Git blobs, owner anchor,
receipt bytes, scope, chronology, and Ed25519 signature. It uses the root-owned `/usr/bin/git`
binary, removes inherited Git control variables, disables replacement objects and external Git
configuration, and rejects legacy grafts. Its return value is a local verification report, not
portable authorization evidence. A new trust boundary must rerun the loader against its own
repository.

## Implemented primitives

### Exact tree

`src/fieldtrue/shortcut_v2_tree.py` implements the sole construct-kill learner:

1. Complete typed feature unions with explicit missingness
2. Canonical UTF-8 categorical values
3. Canonical unbounded decimal strings and exact rational arithmetic
4. Node-local predicates with a 100,000-candidate ceiling
5. Exact weighted Gini selection and canonical byte tie resolution
6. Minimum child size two and maximum depth two
7. Unique modal prediction, explicit class-tie abstention, and key-unavailable abstention
8. Exact algorithm-state and prediction recomputation

Every persisted literal, discriminator, depth, operator, and schema version is explicit. Public
computation boundaries strict-revalidate model bytes so `model_copy` cannot bypass validators.
Incident lists and tree feature definitions use fixed domain-separated hashes. This is the
algorithmic tree core. It is not yet the canonical execution artifact described by the amendment.

### Cross-fitting

`src/fieldtrue/shortcut_v2_crossfit.py` implements deterministic leave-one-group-out folds for
hardware family, hardware identity, and fault family. Every eligible incident is held out once per
axis. Training membership is the exact complement. Diagnostic categorical modes and the sole-kill
tree accept train targets only. Held-out prediction functions have no target parameter and freeze
complete manifests before a later evaluation stage. Prediction requires the exact canonical
fitted-state artifact bytes and hashes those raw bytes; a normalized or differently formatted
artifact is rejected. Aggregate validators independently revalidate registries, manifests, and root
items before computing coverage or roots.

### Recipient-scoped envelopes

`src/fieldtrue/shortcut_v2_release.py` implements dormant cryptographic primitives for recipient
scoped target envelopes. It binds the release context and exact canonical incident membership, uses
exact uint64 framing, pads to `16384 * (incident_count + 1)` bytes with libsodium, encrypts with a
dedicated X25519 sealed box, and validates ciphertext size, actual recipient key bytes, padding,
canonical outer JSON, context, and commitment on open. Sealing strict-revalidates copied models and
requires an explicit atomic one-time salt-claim port before encryption. The generic target entry
proves incident membership and nonempty target content only; it is not the final closed mechanism
target schema.

It does not generate keys or salts, implement the durable salt store, publish bundles, release
truth, or prove process and key destruction.

### Chronology corrections

The implementation audit also closed the following chronology and authority bypasses:

1. A trust registry must not postdate the earliest governed acquisition activity.
2. Global protocol approval must strictly precede the first physical test.
3. A model-visible projection cannot claim a time before source acquisition.
4. An attestation exposes no unsigned duplicate ID or chronology field; chronology belongs in the
   signed parent receipt body.
5. Authority verification does not execute a `git` binary selected from operator-controlled
   `PATH`.
6. A copied recipient model cannot redirect ciphertext to substituted X25519 key bytes.
7. Copied cross-fit registries, manifests, trees, rows, and target envelopes are strict-revalidated
   at computation boundaries.

Each control re-signs the altered artifact with a valid key. The rejection therefore depends on
chronology, not signature failure.

## Candidate schemas

Persisted owner receipt, attestation, tree, feature-vector, cross-fit, fitted-state, prediction,
recipient, release-context, and target-envelope models are exported under `protocol/schemas`.
These schemas are implementation candidates. They become scientific authority only when a future
freeze receipt binds the complete schema root, implementation root, clean Git commit and tree,
dependency lock, execution environment, trust registry, and all required input roots.

## Deliberately unresolved gates

Canonical sealing remains forbidden until all of the following are complete and independently
falsified:

1. Signed mechanism ontology, biconditional shared prediction keys, and per-case local mappings
2. Exact closed mechanism-target and target-subset schemas committed before affected truth access
3. Signed extractor registry, complete feature inventories, identity scanning, and opaque-media
   acquisition disposition
4. Signed census, fold, rule-registry, release-plan, and freeze receipts
5. Dedicated per-job X25519 key generation, possession preflight, atomic durable global salt-claim
   implementation, isolated execution, and demonstrable process and key destruction
6. Atomic no-replace publication with prepared, publication, open, and phase-completion receipts
7. A global prediction barrier followed by fresh holdout-evaluation contexts without refitting
8. Independent full-registry recomputation and target-manifest commitment reveal
9. V2 admission integration, a new control-suite version, complete negative controls, and terminal
   authority binding
10. A canonical fitted-execution wrapper binding the target-release receipt, operation count, fit
    time, training resources, wall and CPU time, peak memory, bytes read, engineering time, and
    direct cost
11. Signed input and provenance roots proving selectors, features, local mappings, and chronology
    were frozen independently of held-out targets
12. Prospective confirmation of implementation-level payload details the approved artifacts did not
    name exactly, including the candidate incident-list domain and final inner target-record shape

No eligible production corpus, target, training target, cloud resource, physical action, scientific
verdict, canonical seal, or publication transition has been created by this checkpoint.

## Research-engine extraction

This checkpoint adds eleven requirements for the future standalone Daniel Wahnich research engine:

1. A verification report is not a transferable capability. Trust boundaries rerun verification.
2. Repository provenance must reject environment redirection, replacement objects, and grafted
   ancestry.
3. Authorization timestamps must strictly precede the actions they govern.
4. Typed parsing must be compared with the original canonical bytes so defaults cannot repair an
   incomplete artifact silently.
5. Scientific tie rules and arithmetic must be executable and exact, not prose conventions.
6. A signed Boolean never replaces recomputation from frozen atomic observations.
7. Every public validator must revalidate nested model bytes; immutable model objects are not proof
   that validation occurred.
8. Cryptographic key bindings are recomputed from the bytes used at the encryption boundary.
9. Never-reuse claims require an atomic durable claim operation, not an optional caller snapshot.
10. Artifact identity hashes exact persisted bytes. Canonical model normalization is not a
    substitute for binding the file that was actually consumed.
11. Algorithm correctness, execution provenance, and scientific authority are separate contracts
    and must never be collapsed into one status.
