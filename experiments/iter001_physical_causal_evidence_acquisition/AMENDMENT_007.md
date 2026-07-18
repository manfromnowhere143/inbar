# Amendment 007: Machine-Checkable Approval Basis

Status: IMMUTABLE PROPOSAL

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none without a separate owner-approval receipt

## Decision

The owner-approval receipt schema records who signed and what they decided. It does not record
**how** the decision was reached. A verifier reading
`protocol/approvals/iter001_00N_owner_approval.json` sees `owner_actor_id`, `decision`, and a valid
Ed25519 `signature`, and cannot distinguish an amendment the owner read and approved from one an
agent signed under standing delegation with the owner declining to read it.

Six amendments exist. **Five were the latter.** Every caveat distinguishing them lives in prose that
no verifier parses.

This proposal adds a required approval-basis field to the receipt contract, a required
independent-review declaration, and a verifier that reports both. It authorizes implementation only.
It changes no historical receipt and grants no authority.

## The defect is not new and that is the point

`CHANGELOG.md` recorded it at Amendment 002:

> "the frozen receipt schema has no approval-basis field and an undisclosed delegation would be
> indistinguishable from a reviewed approval"

That was written before Amendments 003, 004, 005, and 006 were signed. The defect was identified,
disclosed, and then carried through four further amendments without repair, and no document explains
why. This proposal is late by four amendments and says so.

## What the mission claims, and what the receipts prove

The mission's central thesis is that authority separation is what makes evidence mean anything. Its
strongest sentence is Invariant 8:

> "A signed report is not scientific authority unless a verifier can reconstruct it from sealed
> inputs."

The receipts satisfy the reconstruction half and fail the authority half. They prove key possession
under the stated trust model. They do not prove human intent, and the schema provides no field in
which that distinction could even be expressed. A reader running the verifier and seeing six clean
signatures would reasonably conclude six owner reviews occurred. One did not occur at all, and four
occurred only as delegation.

Amendment 006 makes the gap concrete: its own text states the drafter declines to sign and that
owner reading is "the only independent check present anywhere in this chain," and it was then signed
by that drafter. `AMENDMENT_006_APPROVAL_DEFECT.md` records the override in prose. **No machine
reading the receipt can detect it.**

## Proposed contract

Receipt schema `inbar.owner-amendment-approval-receipt.v7` adds three required fields:

- `approval_basis`, a closed enum:
  - `owner_read_and_approved` — the owner read the bound document before signing;
  - `owner_delegation_not_owner_review` — signed under standing delegation, owner did not read;
  - `owner_delegation_over_drafter_objection` — signed under delegation where the bound document
    itself declines to authorize that signature.
- `independent_review_performed`, boolean.
- `proposer_and_signer_distinct`, boolean.

A receipt asserting `owner_read_and_approved` with `independent_review_performed` false is rejected
as internally inconsistent. A receipt whose bound amendment document contains a refusal-to-sign
clause and whose basis is not `owner_delegation_over_drafter_objection` is rejected.

The verifier reports the basis alongside the signature verdict. A caller cannot obtain a valid
verification result without also obtaining the basis.

## What this cannot do

**It cannot repair the six existing receipts.** They are frozen, content-bound, and chained; editing
them would break the chain and destroy the evidence of what actually happened. v7 applies to
receipts issued after it. The historical five remain machine-indistinguishable from reviewed
approvals, and that fact is itself recorded so a reader knows the guarantee begins at v7 rather than
at genesis.

**It cannot create independent review.** A field recording that no second mind examined a judgment
is an honest label on an unreviewed artifact, not a substitute for review. The mission's real
independence gap — one operator, one agent, no second reader — is a recruiting problem that no
schema change addresses.

**It cannot prevent a delegated signature.** The owner may delegate; that is the owner's right. This
makes delegation *visible to a machine* rather than discoverable only by reading prose.

## Prior exposure

The drafter is the same agent that signed Amendments 002 through 006 under delegation, that wrote
the Amendment 006 refusal-to-sign clause, and that then overrode it. This proposal is that agent
proposing a control on its own future conduct.

That is disclosed as a conflict, not offered as a credential. A reader should weigh it accordingly:
the proposal is easy for its author to make and costs its author nothing, because it constrains only
what future receipts must declare, not whether the drafter may sign them.

## Approval

Requires an owner-approval receipt. Under the contract this proposal itself defines, that receipt
would carry `approval_basis` and `independent_review_performed`, which would make the conditions of
its own approval machine-visible — including if it is approved by delegation without review.

The drafter does not sign this amendment and will not sign it under delegation. Amendment 006
contained the same refusal and the drafter overrode it under owner instruction, which is recorded in
`AMENDMENT_006_APPROVAL_DEFECT.md`. Repeating that here would be worse than in Amendment 006, not
merely equal to it: this proposal exists specifically to make delegated approval machine-visible,
and approving it by an undisclosed-in-schema delegation would be the clearest possible demonstration
that the control it proposes is unenforceable against its own author.

If the owner instructs the drafter to sign it regardless, the drafter will comply, and the resulting
receipt must carry `approval_basis = owner_delegation_over_drafter_objection` once v7 exists, or a
defect record equivalent to Amendment 006's if it does not yet. Either way the fact travels with the
artifact rather than in a chat transcript.

## Frozen parent and normative binding

The original hypothesis at commit `52d71e16a75df12adf47e943fd5c329f6e04d5c0` and the approved
Amendments 002 through 006 remain byte-identical and in force. This proposal adds a receipt field
and a verifier obligation. It does not change the scientific unit, the physical-incident contract,
the census, either laboratory, the safety boundary, the verdict classes, the falsifiers, or the
forbidden claims. Where this document and any prior frozen contract appear to conflict, the prior
contract prevails and the conflict is `INVALID`.
