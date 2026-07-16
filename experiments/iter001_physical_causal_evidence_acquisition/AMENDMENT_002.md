# Amendment 002: Prospective Source-Screening Census

Status: IMMUTABLE PROPOSAL

Drafted: 2026-07-16

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none without a separate owner-approval receipt

## Decision

The current `BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE` verdict is not a scientific result. It is a
Git-anchored engineering opinion produced by a dated reconnaissance that the mission itself records
as not systematic and whose external factual basis is not independently reconstructible. The
mission's central negative premise — that no public source can supply the complete incident
construct — has never been established under the mission's own evidentiary standard.

This proposal freezes a prospective, content-bound, independently reconstructible source-screening
census. The census enumerates its frame before retrieval, binds every gate-bearing external fact to
a content-frozen artifact and an exact locator, screens each candidate in cheapest-failing-gate
order, and returns a frame-scoped verdict.

Either outcome advances the mission. A qualifying candidate nominates a source for separately
authorized acquisition. A null converts an unproven block into an established, frame-scoped,
full-weight result and directs the physical admission plane to prospective testbed work with a
defensible published reason.

The census admits nothing. It screens. It grants no acquisition, download beyond its ceiling,
corpus staging, target creation, training, seal, or publication authority. A census pass is a
nomination, not an admission, and the complete incident contract remains the sole admission gate.

## Trigger

The frozen preregistration requires source-role assignment before download, cheapest-first gate
order, and a stop at the first failing hard gate. It does not define the frame or the evidentiary
discipline of the screen itself. Specifically, it leaves undefined:

- which domains are enumerated, and whether that enumeration is fixed before or after retrieval;
- which object classes are eligible, and in particular whether the screen ranges over machine-learning
  dataset releases only or also over investigation records;
- how an external fact about a source is preserved so an independent auditor can reconstruct it;
- whether a mutable web page may establish a gate-bearing fact;
- whether a historical dated artifact can satisfy the pre-outcome ambiguity and chronology gates,
  and under what conditions;
- whether role independence may be inherited from a producing authority; and
- the scope to which a negative verdict may be generalized.

The legacy reconnaissance answered every one of these implicitly, after looking, and preserved none
of them. It enumerated no frame, so its source set cannot be distinguished from a post-hoc
selection. It retrieved pages that were not content-frozen, so its blocking facts cannot be
re-checked. It generalized a bounded look into the routing label `KILL_PUBLIC_SUBSTRATE`, which the
mission has since had to narrow to `BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE` precisely because the
broader claim was not supported. That correction is the evidence that the defect is real and
already cost the mission a false claim.

This is a latent false-authority path of the same class the mission rejected in V1: a verdict that
a validator cannot recompute from sealed inputs.

## Prior exposure

This proposal is drafted after inspection of `docs/research/ITER001_SOURCE_ROLE_AUDIT.md`, the
Iteration 001 hypothesis and its prior-exposure disclosure, `docs/ROADMAP.md`, `README.md`,
`CONTINUITY.md`, the generated `HANDOFF.md`, and the Iteration 000 NASA ADAPT result.

The drafter therefore knows the sixteen legacy-enumerated sources and each claimed blocking gap.
That knowledge is contamination and is handled explicitly by the stratum discipline below. It is not
neutralized by disclosure.

The drafter has not retrieved, inspected, or verified any content, record count, field availability,
determination, or outcome in the prospective domains enumerated below. No fact locator has been
retrieved. No eligible physical corpus, dossier, hypothesis set, mechanism truth, diagnostic action,
recovery, or settled outcome has been inspected. No census artifact exists.

Iteration 000 NASA ADAPT artifacts remain historical inputs and cannot be relabeled as an
Iteration 001 census.

## Approval basis

This disclosure is part of the approved artifact and is bound by the owner-approval receipt's
`amendment_document_artifact_sha256`. It exists because the frozen receipt schema has no field for
the basis of an approval, and an undisclosed delegation would make a delegated approval
indistinguishable from a reviewed one.

The owner, Daniel Wahnich, authorized this amendment by explicit delegation on 2026-07-16,
directing the drafting agent to proceed and to execute the signing ceremony on his behalf with the
`iter001-governance` key. The owner did not read this document before that authorization. The
decision to approve is the owner's; the drafting and the mechanical signature are the agent's.

The receipt therefore attests owner approval by delegation, not owner review. A reader must not
infer that the owner independently examined the frame, the enumerated domains, the chronology
conditions, the role-inheritance conditions, the verdict classes, or the control suite before
approval.

The scientific purpose of prospective owner approval is that a party other than the proposer decides
before the fact. Delegation weakens that separation, because here the proposer and the signer are
the same agent. This is recorded as a known limitation of this approval, not as an equivalent to
independent review. Any later reader auditing whether Amendment 002 was independently approved must
read this section as the answer: it was not.

The owner retains unrestricted authority to revoke this approval. Revocation requires only a
prospective superseding amendment. Nothing authorized here executes the census, retrieves an
external artifact, spends a resource, or touches a physical system, so a revoked approval leaves no
external effect to undo.

## Frozen parent and normative binding

The original hypothesis at commit `52d71e16a75df12adf47e943fd5c329f6e04d5c0` remains
byte-identical. This proposal narrows the undefined evidentiary discipline of source screening. It
does not change the scientific unit, the complete incident contract, the frozen corpus coverage
gates, the execution ceiling, the safety boundary, the iteration verdict classes, or the forbidden
claims. Where this document appears to touch an admission gate, it constrains only how a *screening*
observation about a source may be recorded and generalized; every admission decision remains
governed by the unmodified parent.

This document and `protocol/amendments/iter001_002.json` are jointly required. The machine proposal
is the exact executable subset; this document supplies scientific semantics and exclusions. Neither
may weaken the other. A conflict, omission, or implementation that does not bind both raw artifact
hashes is `INVALID` and requires a new prospective amendment.

Amendment 001 and its owner-approval receipt remain in force and unmodified. This proposal does not
alter Shortcut Authority V2, its ontology, its feature authority, its release chronology, or its
control suite.

Any later change to the frame, an object class, a gate, a policy, or a verdict class requires a new
prospective amendment committed before the affected retrieval.

## Owner-approval receipt

Approval is a separate immutable JSON receipt at
`protocol/approvals/iter001_002_owner_approval.json`. No new schema implementation is needed to
define its bytes. Its exact fields are:

- `schema_version = inbar.owner-amendment-approval-receipt.v2`;
- `approval_id`;
- `owner_actor_id = daniel-wahnich` and `owner_signing_key_id = iter001-governance`;
- `owner_signer_anchor_artifact_sha256 =
  c5cf91b620ae3f34cc9ecebf936c4f48014f04cfa21e3fdc1cf0713f440b1804`, binding the raw bytes of the
  frozen acquisition contract at commit `2955c1bcca190430cd5c88c57187126bb7531d7a`;
- `owner_key_trust_basis = git-pinned-iter001-governance-ed25519-no-external-timestamp` and
  `owner_ed25519_public_key =
  b0f514d7b91caa7c43ea58ffae42ebeea48164d24948723a8c805f780df38962`, which must equal that
  contract's `trust_anchor_public_key`;
- `proposal_git_commit`, `amendment_document_artifact_sha256`, and
  `machine_proposal_artifact_sha256`;
- `decision = approve_source_census_implementation_only`;
- `previous_approval_receipt_sha256 =
  482575c10bb58da6b867ee60587cefa290512fa6f09529a324cea3002fd616c3`, the receipt hash of the
  Amendment 001 owner approval;
- a fresh 32-byte `nonce` encoded as lowercase hexadecimal;
- `issued_at` in canonical UTC form;
- `receipt_hash`; and
- `signature`.

The `v2` schema version exists solely to widen the frozen `decision` literal. The receipt body,
field order, hash rule, and signature rule are otherwise byte-identical in construction to
`inbar.owner-amendment-approval-receipt.v1`. The `v1` receipt remains immutable and is never
reinterpreted under `v2`. The approval chain is a hash chain: this receipt names the Amendment 001
receipt as its predecessor, and a genesis predecessor here is invalid.

`receipt_hash` is `sha256_value` over the complete receipt body excluding `receipt_hash` and
`signature`. `signature` is Ed25519 over the raw 32 bytes of `receipt_hash`. The pinned owner key,
exact subject hashes, decision, predecessor, nonce uniqueness, timestamp, receipt hash, and
signature must verify. The receipt grants only implementation of this proposal. It grants no
production data access, corpus acquisition, target creation, truth release, resource spend beyond
the frozen census ceiling, physical action, canonical seal, scientific verdict, or publication
transition.

## Hash modes and typed roots

`artifact_sha256` means SHA-256 over exact raw file bytes. `sha256_value` means SHA-256 over the
repository's compact canonical JSON encoding of a parsed value. New semantic roots use
`sha256_value` with an explicit schema-version domain, following Amendment 001.

`response_bytes_sha256` means SHA-256 over the exact octet stream returned by one retrieval, before
any decoding, normalization, decompression beyond the declared transfer encoding, or reformatting.

## The census unit

The census unit is one `screened_source_candidate`: one identified body of evidence offered under
one rights regime by one authority, at one immutable version or one recorded retrieval time.

A candidate is not an incident. Screening a candidate produces no scientific unit, no dossier, and
no count toward the thirty-incident floor. The `root_incident_group` definition in the frozen parent
is unchanged and remains the only scientific unit.

Repeated retrievals, mirrors, derived copies, re-releases, papers describing a source, and
documentation pages are never additional candidates. A new immutable version of the same body of
evidence under the same authority is a new candidate only when its version identifier is issued by
that authority.

## Frozen frame

The frame is the enumerated set of domains that will be searched. It is fixed by this proposal
before any retrieval. A domain is a catalog, registry, docket system, or publication route that can
be enumerated by a stated method — not a hand-picked artifact.

Freezing the frame before retrieval is the control that separates a census from a reconnaissance. A
frame extended after retrieval permits the screen's boundary to be drawn around its own findings.
Any extension therefore requires a new prospective amendment committed before the added domain is
retrieved.

The frame is declared incomplete by construction. It is a judgment made by the drafter from prior
knowledge and cannot be assumed exhaustive of the world. Every verdict is scoped to the frame and
may never be generalized beyond it. This restriction is the direct remedy for the legacy screen's
generalization to `KILL_PUBLIC_SUBSTRATE`.

### Stratum A: prior-exposed domains

The sixteen sources enumerated in `docs/research/ITER001_SOURCE_ROLE_AUDIT.md`, comprising the
aerospace, industrial-reality, and robotics tables and the retained method baseline.

These are contaminated: the drafter knows each claimed blocking gap before screening. Their
re-screening is documentation repair, not a blind test. Its purpose is to bind reconstructible fact
locators to claims the mission already publishes, so that an independent auditor can check them.

The stratum-A asymmetry is frozen now, before retrieval, because it determines how its results may
be read. A stratum-A **failure** merely reproduces the drafter's prior and is weak evidence; it
repairs the record's auditability and nothing more. A stratum-A **pass** contradicts the drafter's
prior and is therefore credible against contamination; it is a correction of the legacy screen and
must be published at full weight as such.

### Stratum B: prospective domains

These domains have not been retrieved or inspected by the drafter for this purpose. They are the
genuinely prospective part of the census and are enumerated here before any retrieval.

The rationale is structural, and it is the census's central hypothesis. The legacy screen ranged
almost entirely over machine-learning dataset releases. The complete incident construct — genuine
pre-outcome ambiguity, a committed competing-mechanism set, a test chosen to discriminate, an
executed recovery, and an independently adjudicated settled outcome — is not the shape of a dataset
release. Nobody assembles a dataset around it. It is the shape of an **investigation**. If the
construct exists in public evidence at all, the frame that could contain it is the investigation
record, not the benchmark.

Enumerated stratum-B domains:

1. National Transportation Safety Board investigation dockets, including the public docket system
   and its aviation, rail, marine, pipeline, and highway modal records.
2. United States Chemical Safety Board completed investigation reports.
3. Nuclear Regulatory Commission Licensee Event Reports and associated information notices and
   inspection records.
4. NASA anomaly and lessons-learned routes, including the Lessons Learned Information System and
   NASA engineering anomaly reporting surfaces reachable without restricted access.
5. Government-Industry Data Exchange Program ALERT and Safe-Alert publications.
6. Federal Aviation Administration Service Difficulty Reporting System records and the
   investigation material cited by airworthiness directives.
7. European Union Aviation Safety Agency and European Space Agency published anomaly and safety
   investigation records reachable without restricted access.
8. Occupational Safety and Health Administration accident investigation records involving robotic
   or automated machinery.
9. Zenodo, Dryad, IEEE DataPort, and equivalent DOI-issuing repositories, enumerated by a stated
   query over fault-injection, anomaly-investigation, and diagnostic-intervention terms.

Each domain is entered by its stated enumeration method. Enumeration methods, queries, cutoff
dates, and result counts are recorded before screening and bound by fact locators.

### Object classes

Exactly two object classes are eligible, and each candidate is assigned exactly one:

- `dataset_release`: a versioned body of recorded evidence published for reuse.
- `investigation_record`: a body of dated documents produced by an investigating authority in the
  course of adjudicating one root physical event.

A candidate that is neither is out of frame. Assignment is recorded before gate screening and cannot
be changed after a gate result is known.

## Fact-locator and reconstructibility contract

Every factual assertion the census makes about a candidate binds one `SourceFactLocator`:

- `assertion_id` and `source_id`;
- the exact assertion text, stated so that it can be checked as true or false;
- `retrieval_uri` and `retrieval_method`;
- `retrieved_at` in canonical UTC form;
- `response_bytes_sha256` over the exact retrieved octet stream;
- `response_bytes` count;
- `locator`, a closed union of `{kind, value}` where `kind` is exactly one of `pdf_page`,
  `section_path`, `line_range`, `record_field`, or `table_cell`;
- `excerpt_sha256`, the SHA-256 of the exact supporting excerpt bytes; and
- `mutability_class`, exactly one of `content_frozen` or `mutable_page`.

`content_frozen` requires an authority-issued immutable identifier: a DOI, a versioned record, a
tagged release, an authority-assigned docket or report number whose bytes that authority does not
revise in place, or an independent archival snapshot that publishes its own content hash.

**A `mutable_page` fact can never establish a gate result.** It may appear only as supporting
context and must be labeled as such in every report. The mission has already paid for this rule
once: the ALFA unit correction in the source-role audit is an existing, published instance of a
gate-bearing claim resting on a page the mission does not control, and that audit explicitly notes
the page is not content-frozen and therefore grants no admission result. The census generalizes that
correction into a frozen contract.

Retrieved third-party bytes are never committed. Only the hash, the byte count, the locator, and the
assertion are committed. Excerpt bytes are bound by hash and retained under the local content-addressed
lock; an excerpt is committed only where the governing terms plainly permit quotation and the
rights disposition records that permission.

Re-retrieval that yields a different `response_bytes_sha256` does not silently update the record. It
is recorded as a distinct observation with its own locator, and any gate result that depended on the
prior bytes is invalidated and re-screened.

## Cheapest-first gate order

The census screens each candidate in this exact order and stops at the first failing hard gate:

1. rights and terms;
2. immutable version or authority-assigned identifier;
3. physical identity and system family;
4. object-class-appropriate evidence presence;
5. mechanism authority;
6. pre-outcome ambiguity and chronology;
7. diagnostic action execution;
8. recovery execution;
9. independent settled outcome;
10. clock contract;
11. role independence; and
12. size and staging feasibility.

Retrieval beyond public metadata, landing records, documentation, and governing terms is forbidden
once an earlier gate has failed. This restates and does not weaken the frozen stop rule.

## No borrowing

A missing construct field cannot be supplied by another candidate, another domain, another object
class, a paper describing the source, or the census author's inference. This restates the frozen
parent. The census additionally forbids a *within-candidate* borrow: a field present for one root
event inside an investigation record does not establish that field for a different root event in the
same record.

## Retrospective chronology

This is the census's hardest question and it is frozen here, before retrieval, because after
retrieval it cannot be answered honestly.

The parent requires that a content-addressed hypothesis set record at least two plausible known
physical mechanisms and exactly one unknown mechanism *before* truth or outcome access. A historical
investigation record was not produced under Inbar's commitment discipline. It may nonetheless
satisfy the gate, but only when every one of the following holds:

- **C1.** The hypothesis-bearing artifact is `content_frozen` and independently retrievable.
- **C2.** Its date is established by the publishing authority's own record, not asserted, inferred,
  or reconstructed by the Inbar researcher.
- **C3.** It demonstrably precedes the truth-determination artifact by that authority's own dating,
  and both artifacts are separately bound.
- **C4.** The competing mechanism set is stated **by the investigating authority in that artifact**.
  A set summarized, inferred, paraphrased, completed, or reconstructed by the Inbar researcher is
  not a hypothesis set. This is the leak that would otherwise let the answer write the question.
- **C5.** An explicit residual or unknown category is present in that artifact, or the authority's
  published protocol establishes one. Unknown mass is never manufactured by the census. Its absence
  is a gate failure and is recorded as such.
- **C6.** The extraction of the hypothesis set is performed by a reviewer who has not accessed the
  determination artifact, under a documented blinding procedure recorded before extraction.

**C6 has a consequence this proposal states plainly rather than discovers later.** A single
researcher who reads an investigation docket reads its conclusion. Once exposed, that researcher
cannot perform the extraction, because the extracted hypothesis set would be selected by knowledge
of the answer. Under C6, an exposed extraction produces a **contaminated** case: diagnostic only,
publishable, and permanently ineligible for the thirty-incident floor. Counted dossiers from
historical records therefore require a second, unexposed reviewer.

This is a real constraint on the mission's feasibility, not a technicality. It is frozen now so that
it cannot be quietly relaxed at the moment it becomes inconvenient.

## Inherited role independence

The parent states that organizational separation is supporting metadata and not proof by itself.
This proposal does not weaken that. It defines the narrow conditions under which a producing
authority's separation may be *eligible* for inheritance, all of which must hold:

- **I1.** The producing authority's own governance documents the separation of safety review,
  execution, and outcome adjudication.
- **I2.** The record names the distinct role-holders or role-holding organizations.
- **I3.** A content-addressed conflict record is constructible from that authority's own
  disclosures.
- **I4.** The outcome adjudicator is not the operator, the hypothesis proposer, or the executor.

Absent any of I1 through I4, organizational separation remains supporting metadata and establishes
nothing. Different display names inside one independence group never establish independence.

## Verdict classes

- `CENSUS_QUALIFYING_CANDIDATE`: at least one candidate passes every gate to the depth reachable by
  metadata and document review. This nominates that candidate for a separately authorized
  acquisition under new rights, resource, and safety authorities. It admits nothing, counts nothing,
  and asserts no incident.
- `CENSUS_NULL_WITHIN_FRAME`: no candidate in the frozen frame passes. This is a full-weight result.
  It converts the currently unproven public-source block into an established, frame-scoped finding
  and directs the physical admission plane to prospective testbed acquisition.
- `CENSUS_BLOCKED_RIGHTS`: the scientific fields may be present, but acquisition, processing,
  retention, independent-review, or publication rights are absent, ambiguous, or conflicting. This
  authorizes rights resolution or source replacement only.
- `CENSUS_INVALID`: the census's own controls fail.
- `CENSUS_INFRASTRUCTURE_NULL`: an authorized census cannot complete for an infrastructure reason
  without evidence about the source landscape.

No verdict may be stated without its frame scope. `KILL_PUBLIC_SUBSTRATE` is not a census verdict
and cannot be reached by this instrument; a bounded frame cannot establish an unbounded negative.

## Invalidity

The following are `CENSUS_INVALID`, not merely negative:

- a fact locator that does not resolve, or whose excerpt is absent at the bound locator;
- a `mutable_page` fact used to establish a gate result;
- a gate result retained after its bound `response_bytes_sha256` fails re-retrieval;
- a domain added to, removed from, or redefined in the frame after any retrieval, without a new
  prospective amendment;
- an object-class assignment changed after a gate result is known;
- a candidate passing by borrowing a field across candidates, domains, object classes, or root
  events;
- a retrospective hypothesis set reconstructed, paraphrased, or completed by the Inbar researcher
  presented as satisfying C4;
- an exposed extraction counted toward the incident floor in violation of C6;
- a determination artifact that does not postdate its bound hypothesis artifact;
- inherited role independence claimed without I1 through I4;
- a stratum-A failure presented as novel evidence rather than as reproduction of a known prior;
- a verdict generalized beyond the frozen frame;
- a census nomination presented as admission, acquisition, or incident authority;
- retrieval beyond the ceiling, bulk corpus download, or third-party bytes committed to the
  repository; or
- any positive authority claim while the acquisition contract remains bootstrap or unsealed.

## Required controls

The implementation must include executable outcome-bound positive, negative, and placebo controls
for at least:

- a fabricated fact locator whose URI does not resolve;
- a locator whose excerpt hash does not match the bytes at the bound locator;
- a `mutable_page` fact attempting to establish each of the twelve gates;
- a `content_frozen` claim without an authority-issued immutable identifier;
- re-retrieval byte drift invalidating a dependent gate result;
- frame extension, contraction, and redefinition after first retrieval;
- object-class reassignment after a known gate result;
- cross-candidate, cross-domain, cross-class, and within-record cross-event field borrowing;
- a researcher-reconstructed hypothesis set presented as authority-stated under C4;
- a hypothesis artifact dated after its determination artifact;
- a manufactured unknown category under C5;
- an exposed extraction counted toward the floor under C6, and an unexposed extraction correctly
  admitted as diagnostic-eligible;
- organizational separation presented as inherited independence without each of I1 through I4
  individually;
- a stratum-A pass correctly published as a legacy correction, and a stratum-A failure correctly
  labeled weak;
- a verdict string generalized beyond the frame, including any attempt to emit
  `KILL_PUBLIC_SUBSTRATE`;
- a nomination presented as admission authority;
- gate-order violation, and retrieval attempted after an earlier hard-gate failure;
- resource-ceiling breach and attempted bulk download; and
- a synthetic candidate constructed to pass every gate, as the evaluator positive control, and a
  synthetic candidate failing exactly one gate, as the conjunctivity control.

The census control suite requires its own version and receipt. Existing Iteration 000 and V1
controls remain historical and cannot be silently reinterpreted as census controls.

## Resource ceiling and stop rules

The census executes under the frozen Iteration 001 contract-and-tooling ceiling: local CPU
execution, public metadata access, source-document review, schema generation, and synthetic
fixtures only. One census audit may use at most four CPU-hours, two elapsed hours, 16 GiB peak
memory, 1 GiB retrieved metadata and documents, and 2 GiB peak staged bytes. Its ceiling is zero GPU
hours, zero cloud jobs, zero paid provider calls, zero live-system authority, zero physical
actuation, zero provider cost, and zero redistribution of third-party data. Missing resource
measurements invalidate the audit.

Retrieval is limited to public metadata, landing records, documentation, governing terms, and
individual investigation documents required by a gate that has not already failed. Bulk corpus
acquisition is forbidden and requires a separate prospective resource lease.

Stop screening a candidate at its first failing hard gate. Stop the census and preserve a full-weight
result when a rights conflict cannot be resolved in writing, when the frame cannot be enumerated by
its stated method, when a control fails, or when the ceiling is reached.

No gate may be lowered after retrieval. Corrections must be prospective, explicit, and append-only.

## Implementation and activation gate

This proposal alone authorizes no implementation, retrieval, census execution, acquisition, resource
spend, control seal, terminal result, scientific verdict, or publication transition.

After exact owner approval, implementation may add only: the typed census contracts and canonical
schemas; the frozen frame registry and its enumeration methods; the fact-locator and retrieval
validator; the stratum, object-class, chronology, and role-inheritance policies defined here; the
gate-order and no-borrowing validators; the census verdict path; the adversarial control suite; and
explicit census hashes in the census report. Implementation does not execute the census; execution
requires the resource authority named above and a clean committed control receipt.

The canonical acquisition contract remains `bootstrap`. Approval of this proposal is not a seal, and
the sole registered `iter001-acquisition-contract` blocker remains in force.

## Unchanged boundaries

No GPU, cloud job, paid call, bulk data download, live robot, spacecraft, physical action, training,
model evaluation, or customer claim is authorized by this proposal. The iteration still cannot claim
diagnosis, intervention benefit, recovery, safety, transfer, product readiness, economic value, or
state of the art. A completed census, in any verdict, establishes nothing about model performance
and does not admit a single incident.
