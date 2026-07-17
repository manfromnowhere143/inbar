# Amendment 004: Causal Laboratory Plane

Status: IMMUTABLE PROPOSAL

Drafted: 2026-07-17

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none without a separate owner-approval receipt

## Decision

The census settles whether public sources can supply the complete incident construct. Its
honest solo ceiling is a null-or-needs-review verdict, because a qualifying public dossier
requires deep gates — mechanism authority, the pre-committed hypothesis set stated by the
investigating authority, and independent outcome adjudication — that a single exposed reader
cannot certify without violating condition C6. This proposal opens the plane where that
ceiling does not apply.

In a simulator, the mechanism is injected, so the ground truth is known by construction rather
than extracted by a reader. The sealed-truth authority the census cannot obtain from public
records is available here for free, and condition C6 does not bind, because no human reads a
conclusion to establish it. The causal-laboratory plane is therefore where the method itself —
open-world hypothesis proposal, safe discriminating-test selection, recovery, and outcome
adjudication — can be built and tested end to end against known truth.

This proposal authorizes implementation only: the typed causal-laboratory contracts, the
paired-branch protocol, the sealed mechanism-injection and its authority separation, and a
provider-neutral simulator port with a Basilisk adapter. It authorizes no simulation run. Every
executed campaign requires a separate signed compute lease, exactly as census retrieval
requires an execution lease. `iter001-acquisition-contract` remains the sole registered
blocker throughout.

## The frozen boundary that governs everything here

Simulator branches never count as physical incidents. This is the frozen parent rule and this
proposal does not weaken it. A causal-laboratory result qualifies infrastructure and action
logic only. It can establish that the method discriminates a genuinely ambiguous injected
mechanism, selects a test that separates hypotheses, and adjudicates an outcome — inside the
simulator. It can never carry a physical, operational-safety, recovery, transfer, product, or
real-world causal claim. A simulator that succeeds proves the method is worth taking to
physical admission; it proves nothing about the physical world by itself.

## Trigger

The mission's preregistration names a three-plane source architecture whose second plane is a
legally cleared NOS3 configuration or Basilisk fallback executing paired no-op, targeted,
wrong-but-safe, recovery, and blocked-unsafe branches from identical snapshots. That plane is
frozen in intent but has no implemented contract. Without one, a simulation campaign would
improvise the very discipline the mission demands: what a paired branch is, how the injected
mechanism is sealed from the diagnosing system, how the outcome is adjudicated against injected
truth without leaking it, and what a simulator result may and may not claim.

## Prior exposure

This proposal is drafted after implementing the census screening and execution layers and
reading the frozen source architecture, the falsifier suite, and the Basilisk project's
permissive ISC license. The drafter has run no simulation, injected no mechanism, and produced
no causal-laboratory result. No simulator branch, hypothesis prediction, or outcome
adjudication exists.

## Approval basis

This disclosure is part of the approved artifact and is bound by the owner-approval receipt's
`amendment_document_artifact_sha256`. The owner, Daniel Wahnich, authorized this amendment by
standing delegation, directing autonomous progression toward the mission goals and the
execution of signing ceremonies on his behalf with the `iter001-governance` key. The owner did
not read this document before that authorization. The proposer and the signer are the same
agent, as disclosed in Amendments 002 and 003. A reader auditing whether Amendment 004 was
independently reviewed must read this section as the answer: it was not. The owner retains
unrestricted revocation through a prospective superseding amendment.

## Frozen parent and normative binding

The original hypothesis at commit `52d71e16a75df12adf47e943fd5c329f6e04d5c0` and the approved
Amendments 002 and 003 remain byte-identical and in force. This proposal adds the
causal-laboratory implementation discipline. It does not change the scientific unit, the
complete physical-incident contract, the corpus coverage gates, the census, the safety
boundary, the verdict classes, or the forbidden claims. Where this document and any prior
frozen contract appear to conflict, the prior contract prevails and the conflict is `INVALID`.

This document and `protocol/amendments/iter001_004.json` are jointly required; neither may
weaken the other; an implementation that does not bind both raw artifact hashes is `INVALID`.

## Owner-approval receipt

Approval is a separate immutable JSON receipt at
`protocol/approvals/iter001_004_owner_approval.json`, constructed byte-identically to the
Amendment 003 receipt except:

- `schema_version = inbar.owner-amendment-approval-receipt.v4`, which widens the frozen
  decision literal only;
- `decision = approve_causal_laboratory_implementation_only`; and
- `previous_approval_receipt_sha256 =
  2c0001fbb952ae1bff5d8b0fe0f7a04eeff7d2fd556a83006c42ae17428f7ec5`, the Amendment 003
  receipt hash. A genesis predecessor is invalid.

All other fields, the owner key and anchor bindings, the hash rule, and the signature rule are
those of the prior receipts. The v1, v2, and v3 receipts remain immutable and are never
reinterpreted.

## The paired-branch protocol

A causal-laboratory episode begins from one frozen initial snapshot: a complete simulator state
with a content hash. From that identical snapshot, exactly these branches execute, each a
deterministic continuation of the same seed and state:

- `no_op`: no diagnostic action; the fault evolves untouched.
- `targeted_test`: the action the method selected to discriminate its competing hypotheses.
- `wrong_but_safe`: an approved but non-discriminating action, the control that a test which
  changes nothing about the posterior must be distinguishable from.
- `recovery`: the recovery action the method proposed after the diagnostic evidence.
- `blocked_unsafe`: an action the safety authority refused; it is recorded as refused and never
  executed, proving the safety boundary bites.

Every branch binds the snapshot hash it descends from, so the branches are counterfactually
comparable by construction. A branch set whose members descend from different snapshots is
`INVALID`.

## Sealed mechanism injection and authority separation

Before an episode, the mechanism custodian injects exactly one fault mechanism drawn from a
committed mechanism ontology, plus the reserved unknown case, and seals it. The injected
mechanism is the truth record. It is content-addressed and never enters the model-visible
plane, any branch the proposer reads, a log, a filename, or a public artifact before outcome
adjudication.

The hypothesis proposer sees only pre-cutoff model-visible telemetry from the snapshot and the
branches it is permitted, never the injected mechanism. It commits a content-addressed
hypothesis set — at least two plausible known mechanisms and exactly one unknown — before any
truth access, exactly as the physical contract requires. The outcome adjudicator compares the
settled branch states against the injected truth. Because the truth is injected rather than
read from a record, the adjudicator establishes it without human exposure, so condition C6 does
not apply to a simulator episode. The proposer, the safety reviewer, the executor, and the
adjudicator remain distinct authorities; a single actor holding the proposer and the injected
truth is `INVALID`.

## Provider-neutral simulator port

The simulator is a typed port. Basilisk is the first adapter, chosen for its permissive ISC
license and deterministic spacecraft dynamics. The port exposes snapshot capture and restore, a
seeded deterministic step, mechanism injection, and state readout. An adapter must be
deterministic under a fixed seed and snapshot, or its branches are not counterfactually
comparable and the episode is `INVALID`. No adapter may reach the network, a paid provider, a
GPU, or a live system; the simulator is local and offline.

## Compute authority

Implementation authorizes local-CPU construction of the contracts, the port, the Basilisk
adapter, and a single bounded deterministic smoke episode sufficient to prove the paired-branch
and sealing machinery, within the frozen Iteration 001 resource ceiling. It authorizes no
experiment campaign. A campaign of episodes that produces a comparative result requires a
separate signed causal-laboratory compute lease binding the frozen ceiling, the committed
mechanism ontology hash, a session identifier and nonce, and a validity window, verified
against the git-pinned owner anchor exactly as the census execution lease is. GPU, cloud, and
paid-provider compute remain forbidden.

## Implementation and activation gate

After exact owner approval, implementation may add only: the typed causal-laboratory contracts
and schemas; the paired-branch protocol validator; the sealed mechanism-injection and
authority-separation enforcement; the provider-neutral simulator port and its Basilisk adapter;
the compute-lease contract and verifier; explicit episode, snapshot, and lease hashes in the
causal-laboratory report; and the adversarial control suite. Controls must run without a live
network and without a GPU.

This proposal alone authorizes no simulation run, no compute lease issuance, no experiment
campaign, no corpus admission, no scientific verdict, and no publication transition. The
canonical acquisition contract remains `bootstrap`.

## Unchanged boundaries

No GPU, cloud job, paid call, live robot, spacecraft, physical action, training on real
targets, real-target evaluation, or customer claim is authorized by this proposal or any
compute lease under it. A simulator branch never counts as a physical incident. The iteration
still cannot claim diagnosis, intervention benefit, recovery, safety, transfer, product
readiness, economic value, or state of the art. A causal-laboratory result establishes that the
method works inside the simulator and nothing about the physical world.
