# Amendment 005: Diagnosis-Method Port and Causal-Laboratory Campaign

Status: IMMUTABLE PROPOSAL

Drafted: 2026-07-17

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none without a separate owner-approval receipt

## Decision

Amendment 004 built the causal-laboratory harness: paired branches, sealed mechanism injection,
authority-separated adjudication, and a deterministic reference simulator. Its implementation
list is exhaustive and does not include a diagnosis method, so a campaign that runs a method
across many episodes and produces a comparative result is not yet authorized. This proposal is
that authority.

It authorizes implementation only of: a provider-neutral diagnosis-method port; one reference
baseline method drawn from the frozen baseline ladder; a campaign runner that executes bounded
episodes under a signed compute lease; and a comparative result contract. It authorizes no
campaign run. Every campaign additionally requires the causal-laboratory compute lease Amendment
004 defined. `iter001-acquisition-contract` remains the sole registered blocker throughout.

## The frozen boundary that governs everything here

A causal-laboratory campaign result establishes how a method behaves inside the reference
simulator against injected truth, and nothing about the physical world. A simulator branch never
counts as a physical incident. In-simulator diagnosis accuracy, calibration, abstention, or
discriminating-test value is not a diagnosis, recovery, safety, transfer, product, or
real-world causal claim. The reference baseline is a baseline, not a state-of-the-art system;
beating it in simulation proves the harness measures a real difference, not that any method is
good.

## Trigger

Amendment 004 froze how an episode is structured but not how a method reads it or how a campaign
compares conditions. Left undefined: what a method may see and when (it must be blind to the
injected mechanism until adjudication); the reference baseline's exact fitting and abstention
rule; how a campaign holds the simulator, ontology, and episode construction fixed while varying
only the evidence condition; and what a comparative result may and may not claim. Without
freezing these, a campaign would improvise the very discipline that makes an in-simulator
comparison meaningful, and a method could quietly read the truth it is meant to infer.

## Prior exposure

This proposal is drafted after implementing the causal-laboratory harness and reference
simulator and reading the frozen baseline ladder and multimodal-attribution controls. The
drafter has run no campaign, fit no method, and produced no comparative result. No method port,
reference method, campaign, or result exists.

## Approval basis

This disclosure is part of the approved artifact and is bound by the owner-approval receipt's
`amendment_document_artifact_sha256`. The owner, Daniel Wahnich, authorized this amendment by
standing delegation, directing autonomous progression toward the mission goals and the execution
of signing ceremonies on his behalf with the `iter001-governance` key. The owner did not read
this document before that authorization. The proposer and the signer are the same agent, as
disclosed in Amendments 002 through 004. A reader auditing whether Amendment 005 was
independently reviewed must read this section as the answer: it was not. The owner retains
unrestricted revocation through a prospective superseding amendment.

## Frozen parent and normative binding

The original hypothesis at commit `52d71e16a75df12adf47e943fd5c329f6e04d5c0` and the approved
Amendments 002, 003, and 004 remain byte-identical and in force. This proposal adds the
diagnosis-method and campaign implementation discipline. It does not change the scientific unit,
the physical-incident contract, the census, the causal-laboratory harness, the safety boundary,
the verdict classes, or the forbidden claims. Where this document and any prior frozen contract
appear to conflict, the prior contract prevails and the conflict is `INVALID`.

This document and `protocol/amendments/iter001_005.json` are jointly required; neither may
weaken the other; an implementation that does not bind both raw artifact hashes is `INVALID`.

## Owner-approval receipt

Approval is a separate immutable JSON receipt at
`protocol/approvals/iter001_005_owner_approval.json`, constructed byte-identically to the
Amendment 004 receipt except:

- `schema_version = inbar.owner-amendment-approval-receipt.v5`, which widens the frozen decision
  literal only;
- `decision = approve_method_campaign_implementation_only`; and
- `previous_approval_receipt_sha256 =
  59a620b145bc8803e73bc34dcbd594dcfac7526a6ca313e3708ef2e3401db852`, the Amendment 004 receipt
  hash. A genesis predecessor is invalid.

All other fields, the owner key and anchor bindings, the hash rule, and the signature rule are
those of the prior receipts. The v1 through v4 receipts remain immutable and are never
reinterpreted.

## The diagnosis-method port

A method is a provider-neutral typed port. It receives only model-visible telemetry from the
branches it is permitted and the committed mechanism ontology, and it returns a hypothesis set
and a single diagnosis key, never the injected mechanism. The port is called before adjudication
and cannot read the sealed truth, any unsalted target, or any adjudication artifact. A method
that inspects the sealed mechanism, an adjudication result, or a branch it was not granted is
`INVALID`, and its episode is discarded rather than scored.

The reference baseline is `reference_likelihood_diagnoser`: a deterministic method that scores
each ontology mechanism by the likelihood of the observed telemetry under that mechanism's
frozen forward model, diagnoses the single maximum-likelihood mechanism, and abstains to the
reserved unknown when no mechanism's normalized posterior exceeds a frozen confidence floor or
when two mechanisms tie within a frozen margin. Its forward models, floor, tie margin, and
tie-break rule are fixed before any campaign. It is representation-free and reads only the
permitted telemetry; it is a baseline, not a learned system.

## The campaign

A campaign holds the simulator, the mechanism ontology, the snapshot construction, and the
episode seed schedule fixed, and varies only the evidence condition given to the method:

- `passive`: the method sees only the `no_op` branch telemetry.
- `active`: the method additionally sees the `targeted_test` branch telemetry.

For each episode the custodian injects one mechanism (a known key or the reserved unknown) drawn
by the frozen seed schedule, seals it, runs the paired branches, calls the method under each
condition blind to the injection, and adjudicates each diagnosis against the revealed truth. The
paired design is the control: the same injected mechanism and snapshot are diagnosed under both
conditions, so a difference is attributable to the discriminating test, not to episode luck.

A campaign is bounded by the frozen episode count in its compute lease and by the frozen
resource ceiling. The seed schedule, injection distribution, and episode count are committed
before the campaign and cannot be chosen after inspecting results.

## The comparative result

A campaign result binds both proposal artifact hashes, the owner-approval receipt, the compute
lease, the ontology, the simulator identity, and the frozen seed schedule, and reports over the
episode set: per-condition diagnosis accuracy, calibration (whether stated confidence matches
realized correctness), abstention rate and abstention correctness, unknown-injection handling,
and the paired active-minus-passive accuracy difference with an episode-clustered uncertainty
interval. Every quantity is recomputed by the bound harness from the committed episode records.

The result may state, inside the simulator only, whether the discriminating test measurably
improved diagnosis over the passive condition, whether the method was calibrated, and whether it
abstained correctly on genuinely ambiguous or unknown cases. It may not state anything about the
physical world, any real system, any product, or any method other than the reference baseline in
this simulator.

## Implementation and activation gate

After exact owner approval, implementation may add only: the typed diagnosis-method port; the
reference likelihood baseline; the campaign runner and its evidence-condition control; the
comparative result contract and its harness recomputation; explicit method, campaign, and result
hashes bound to the compute lease and episode records; and the adversarial control suite.
Controls must run without a live network and without a GPU.

This proposal alone authorizes no campaign run, no compute-lease issuance, no result, no corpus
admission, no scientific verdict, and no publication transition. The canonical acquisition
contract remains `bootstrap`.

## Unchanged boundaries

No GPU, cloud job, paid call, live system, physical action, training on real targets,
real-target evaluation, or customer claim is authorized by this proposal or any compute lease
under it. A simulator branch never counts as a physical incident. The iteration still cannot
claim diagnosis, intervention benefit, recovery, safety, transfer, product readiness, economic
value, or state of the art. A causal-laboratory campaign result establishes how the reference
baseline behaves inside the reference simulator and nothing about the physical world.
