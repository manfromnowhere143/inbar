# Iteration 001 Authenticated Control Producer V1

Status: implemented fixture design; not an owner authority receipt; canonical authority remains
bootstrap

Decision date: 2026-07-16

Engineering disposition: `IMPLEMENT_FIXTURE_PRODUCER_WITHOUT_SEALING`

## Purpose

The existing admission controls execute inside authenticated isolated runners, but the long-lived
ambient process still assembles the manifest and receipt, opens the governance key, signs, and
publishes the bundle. File-origin checks do not authenticate live Python functions, globals, import
hooks, or monkeypatches. A valid control result therefore cannot make the ambient process an
authority.

V1 moves the fixture authority-producing path into a fresh child under the unmodified committed
launcher. The launcher may prepare the runner and observe a bounded result. It may not read a private
key, construct a signable body, create authority artifacts, or publish the final directory. This does
not claim resistance to a hostile same-user process that controls child arguments or prepared
dependency bytes before import.

## Non-activation

The operator-directed engineering scope is implementation and synthetic fixture testing only. This
document is not a signed owner approval and grants no authority. It does not authorize a production
key read, canonical control receipt, contract seal, data acquisition, target access, training, cloud
or GPU use, physical execution, scientific verdict, publication, or public release.

The canonical acquisition contract remains `bootstrap`. Its placeholder bindings are not updated by
this implementation phase.

## Process boundary

The public launcher imports no receipt-construction or signing module. It performs only these tasks:

1. Resolve the repository and require the fixed private key and output locations without opening the
   key.
2. Discover a clean trusted Git HEAD and materialize the committed runner snapshot.
3. Prepare the hash-authenticated CPython, dependency, and source environment.
4. Start one child with `-I`, `-B`, and `-S`, a fixed bootstrap, a sanitized environment, bounded
   pipes, a wall-clock deadline, and process-group cleanup.
5. Parse one bounded typed response and bind it to the selected request, commit, tree, and exact
   durable receipt bytes.

Exact independent bundle verification is a prospective consumer operation. It is not performed or
claimed by the current launcher.

The child does not trust caller-supplied identities, source hashes, control outcomes, manifest fields,
receipt body, signature subject, public key, or key bytes. It independently rederives the requested
commit and tree and derives every other authority-bearing field.

## Request and response

The request contains only a schema identifier, the fixed operation identifier, the resolved
repository root, the selected execution commit and tree, the per-control timeout, and a unique
request identifier. Canonical JSON bytes are sent through standard input. Duplicate keys, extra
fields, noncanonical bytes, truncation, and oversized input fail closed.

The response contains only a schema identifier, request hash, status, stable failure code or durable
receipt reference, execution commit and tree, the hash of the exact published receipt bytes,
published relative path, and control count. The launcher requires the returned commit and tree to
equal its clean pre-launch selection and rechecks that repository identity after child completion. It
never receives a seed, private key, raw signature input, environment value, unrestricted diagnostic,
or path outside the repository.

## Child algorithm

1. Verify isolated interpreter flags, exact module origins, explicit dependency roots, fixed startup
   environment, and the runner tree prepared by the committed launcher.
2. Resolve trusted Git independently and require the clean HEAD and tree to equal the request.
3. Reconstruct an exact committed snapshot census, load the execution contract from Git, require the
   stable working bytes to match, and verify preregistration ancestry and bytes, complete source
   closure, validator, generator, tests, project configuration, package initializers, dependency
   lock, and control registry.
4. Open stable repository and private output directory descriptors without following links.
5. Execute every frozen control in its own bounded isolated process and require exact lifecycle and
   machine observation evidence.
6. Recheck the runner, Git HEAD and tree, complete source closure, contract, and dependency lock.
7. Assemble the manifest and receipt body entirely inside the child.
8. Open the distinct fixture key as the final authority input using a descriptor-relative, no-create,
   no-follow read. Require a regular single-link file, exact owner and mode, stable metadata and path,
   exact length, and the contract public key.
9. Sign the domain-separated reconstructed subject, discard mutable seed buffers where the runtime
   permits, write the staged artifacts, require an exact artifact census, fsync and rebind the staging
   directory, and publish with descriptor-relative atomic no-replace semantics.
10. Rebind the published directory, emit one bounded response, and exit. The launcher then enforces
    cleanup of its managed process group.

The producer implementation is V1, while its receipt and execution-manifest wire schemas are V2.
The new schema identities are required because authority-profile, execution-contract, and source-
closure fields are mandatory additions; the committed V1 schema identities are not reinterpreted.

## Kill gates

Implementation fails if any of the following is possible:

1. The launcher opens the key, builds a manifest or receipt, calls signing code, writes final
   authority artifacts, or publishes the bundle.
2. The child proceeds without isolated flags, exact committed sources, authenticated dependencies,
   a clean unchanged HEAD and tree, or preregistration ancestry.
3. A missing, linked, aliased, replaced, broadly readable, wrongly owned, malformed, or wrong-public-
   key private key reaches signing.
4. The committed launcher or producer transports or intentionally emits fixture private-key seed bytes
   through arguments, environment, standard streams, diagnostics, caches, non-key artifacts, or
   research memory.
5. Under the committed launcher, ambient `PYTHONPATH`, startup customization, import hooks, pytest
   plugins, Git configuration, `PATH`, inherited monkeypatches, snapshot additions, or snapshot
   substitutions change a fixture result.
6. A timeout, capture overflow, surviving member of the launcher's managed process group, control
   substitution, missing observation, repository race, source race, output race, fsync failure, or
   existing target can be treated as an accepted bundle. An acknowledgment-loss orphan remains
   immutable, fixture-only, and requires explicit verified quarantine or removal before retry.
7. A signed bundle cannot be reconstructed and verified from its committed source closure and exact
   control evidence.
8. Mission validation stops reporting the sole `iter001-acquisition-contract` blocker during this
   implementation-only phase.

## Residual boundary

An authenticated same-UID child is not a hardware security module, external timestamp, anti-rollback
service, or independent actor. A hostile ambient process can change child arguments or prepared
dependencies before import, and another process with the same operating-system identity can read a
mode-0600 file. Child self-inspection cannot establish independence from that caller. Canonical
sealing therefore also requires an independently enforced launcher and signer, operating-system key
service, hardware-backed key, or equivalent supervisor boundary whose policy reconstructs and
verifies the Inbar receipt subject instead of signing an arbitrary caller-provided digest.

A hostile descendant can also create a new session and process group, close the inherited pipes, and
escape cleanup that is scoped to the launcher's managed process group. Detecting or containing that
case requires the same prospective external supervisor boundary.

This residual limits the claim: V1 provides fresh-process hygiene, exact committed snapshot checks,
and reconstructible fixture execution under the committed launcher. It does not establish hostile
caller resistance, production key secrecy, independent bundle acceptance, or external independence.
