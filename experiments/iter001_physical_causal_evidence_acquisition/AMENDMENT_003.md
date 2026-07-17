# Amendment 003: Census Execution Authority

Status: IMMUTABLE PROPOSAL

Drafted: 2026-07-17

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none without a separate owner-approval receipt

## Decision

Amendment 002 deliberately excluded execution from its implementation authority: its permitted
list contains a fact-locator validator and no retrieval executor, and it froze
`census_execution_requires_separate_resource_authority`. This proposal is that separate
authority's definition. It authorizes implementing the census retrieval executor, the
run-specific execution lease that gates every live run, the content-addressed local store for
retrieved bytes, and the measured run harness that binds Amendment 002's frozen resource
ceiling to real observations.

Approval of this proposal authorizes implementation only. A live census run additionally
requires a per-session execution lease signed by the owner governance key after this
implementation exists. No approval in this chain admits a corpus, creates a target, trains a
model, issues a scientific verdict beyond the frame-scoped census verdict classes, seals
canonical authority, or changes publication state. `iter001-acquisition-contract` remains the
sole registered blocker throughout.

## Trigger

Amendment 002 froze what a valid census observation is but not how one is produced against the
live world. Specifically it left undefined:

- the transport discipline for retrieval, including transport security, methods, redirects,
  and failure handling;
- where retrieved third-party bytes live, given that committing them is forbidden;
- how the frozen per-audit resource ceiling is enforced during a run rather than judged after
  one;
- the concrete enumeration entry points for the nine frozen Stratum B domains; and
- the form of the run-specific resource authority the amendment requires.

Without freezing these, a census run would improvise exactly the evidentiary discipline the
census exists to impose on others.

## Prior exposure

This proposal is drafted after implementing Amendment 002 and reading the mission's committed
contracts, including the TLS trust-store machinery and approval-receipt primitives it reuses.
The drafter has retrieved no candidate artifact, screened no candidate, inspected no
investigation record, and issued no census verdict. The Stratum A blocking gaps remain known to
the drafter as disclosed in Amendment 002; the Stratum B domains remain uninspected.

## Approval basis

This disclosure is part of the approved artifact and is bound by the owner-approval receipt's
`amendment_document_artifact_sha256`. The owner, Daniel Wahnich, authorized this amendment by
standing delegation, directing autonomous progression toward the mission goals and the
execution of signing ceremonies on his behalf with the `iter001-governance` key. The owner did
not read this document before that authorization. The proposer and the signer are the same
agent, exactly as disclosed in Amendment 002, and a reader auditing whether Amendment 003 was
independently reviewed must read this section as the answer: it was not. The owner retains
unrestricted revocation through a prospective superseding amendment.

## Frozen parent and normative binding

The original hypothesis at commit `52d71e16a75df12adf47e943fd5c329f6e04d5c0` and the approved
Amendment 002 artifacts remain byte-identical and in force. This proposal narrows only the
undefined execution discipline. The census unit, frame, strata, object classes, fact-locator
contract, gate order, no-borrowing rule, chronology conditions, role-inheritance conditions,
verdict classes, invalidity set, and resource ceiling are unchanged. Where this document and
Amendment 002 appear to conflict, Amendment 002 prevails and the conflict is `INVALID`.

This document and `protocol/amendments/iter001_003.json` are jointly required; neither may
weaken the other; an implementation that does not bind both raw artifact hashes is `INVALID`.

## Owner-approval receipt

Approval is a separate immutable JSON receipt at
`protocol/approvals/iter001_003_owner_approval.json`, constructed byte-identically to the
Amendment 002 receipt except:

- `schema_version = inbar.owner-amendment-approval-receipt.v3`, which widens the frozen
  decision literal only;
- `decision = approve_census_execution_implementation_only`; and
- `previous_approval_receipt_sha256 =
  6be770e5b619c8a8a56c4718e3ceb10d52a23c93f92090fcd9a050eee9bf808d`, the Amendment 002
  receipt hash. A genesis predecessor is invalid.

All other fields, the owner key and anchor bindings, the hash rule, and the signature rule are
those of the Amendment 002 receipt. The v1 and v2 receipts remain immutable and are never
reinterpreted.

## The execution lease

Every live census run requires exactly one `CensusExecutionLease`, a typed receipt signed by
the owner governance key and verified against the same git-pinned anchor as the approval
chain. It binds at minimum:

- this amendment's both artifact hashes and its owner-approval receipt hash;
- the exact committed frame-registry artifact hash the run may enumerate;
- a fresh session identifier and a fresh 32-byte nonce;
- the frozen resource ceiling restated in base units;
- a validity window; and
- the lease hash and Ed25519 signature, constructed under the approval-receipt hash and
  signature rules.

One lease authorizes at most one census session. A missing, expired, replayed, wrong-frame,
wrong-ceiling, or signature-invalid lease blocks retrieval before any network contact. Issuing
a lease is an owner ceremony under the same standing delegation, and each issued lease is
committed alongside the session's census report.

## Retrieval discipline

- Transport is HTTPS GET only, with certificate verification against the mission's committed
  certifi trust store. Plain HTTP, other methods, and unverified TLS are `CENSUS_INVALID`.
- Redirects are followed to a bounded depth and every hop is recorded; the final URI is the
  locator's retrieval URI.
- Every retrieval produces exactly one fact-locator-compatible retrieval record binding the
  request URI, final URI, retrieval time, response byte count, and response SHA-256, before
  any interpretation of the bytes.
- Retrieved bytes are stored content-addressed by SHA-256 under the git-ignored local census
  store, keyed by session. Third-party bytes are never committed; the session manifest commits
  hashes, counts, and locators only.
- Per-session retrieved bytes are capped by the frozen ceiling; the executor refuses the
  request that would exceed it. CPU, wall, and peak memory are measured live by the committed
  measurement primitive, and a census report without that measurement remains invalid.
- The executor refuses retrieval for any candidate that already has a recorded failing hard
  gate, enforcing the frozen stop rule at the transport boundary.
- No retrieval outside the committed frame registry's enumerated entry points and the
  candidate documents they name. Frame extension still requires a prospective amendment.

## Frame registry

Implementation commits a frame-registry artifact enumerating, for each of the nine frozen
Stratum B domain identifiers, its concrete enumeration entry points and stated method. The
registry names only the domains Amendment 002 froze; it can concretize them but not extend
them. Every lease binds the exact registry hash it authorizes, so changing entry points
invalidates outstanding leases rather than silently widening a run.

## Implementation and activation gate

After exact owner approval, implementation may add only: the typed lease contract, its
issuance and verification path against the pinned anchor and approval chain; the retrieval
executor and its transport, redirect, storage, ceiling, stop-rule, and measurement
enforcement; the content-addressed session store and manifest; the frame registry artifact
and its schema; explicit lease and registry hashes in the census report; and the adversarial
control suite for all of the above. Controls must execute without live network access.

This proposal alone authorizes no retrieval, no lease issuance, no census run, no corpus
acquisition, no resource spend, no seal, no verdict, and no publication transition. The
canonical acquisition contract remains `bootstrap`.

## Unchanged boundaries

No GPU, cloud job, paid call, bulk dataset download, live-system authority, physical action,
training, target creation, truth release, or customer claim is authorized by this proposal or
by any lease under it. `KILL_PUBLIC_SUBSTRATE` remains unreachable by the census instrument. A
completed census, in any verdict, establishes nothing about model performance and admits no
incident.
