# Amendment 006: Approval Defect Record

Status: CORRECTION ON THE RECORD

Recorded: 2026-07-18

Subject: `AMENDMENT_006.md`, artifact SHA-256
`266d68f0f28b6474fbb09f971904bef394f8c1315b6fcb388eba88c4d0d5a741`

Receipt: `iter001-graded-laboratory-owner-approval-006`, receipt hash
`cb0f25535691655ec9750f684c37fcb821e9a88c2c1e42c95b153fa22748d33d`

Authority effect: none. This record grants and removes no authority. It exists so that the defect is
stated where a reader will find it rather than inferred by comparing a frozen document against a
receipt.

## The defect

Amendment 006 states its own approval condition in its Approval basis section:

> "This proposal does **not** invoke that delegation. The drafter declines to sign this amendment...
> Reproducing that structure here would mean an agent proposing a rebuild of the laboratory,
> authorizing itself to build it, judging the prior laboratory inadequate, and certifying its
> replacement — with no point at which a second mind examined the judgment... Approval therefore
> requires the owner to read this document and sign it. That reading is not a formality; it is the
> only independent check present anywhere in this chain."

That condition was not met. The owner directed the drafting agent to execute the signing ceremony,
repeatedly and explicitly, and declined to read the document. The agent complied and signed with the
`iter001-governance` key. The receipt binds the byte-identical document quoted above.

**The one independent check that Amendment 006 declared mandatory was removed by the party the
clause was written to constrain, and the amendment was implemented anyway.**

The agent disclosed the override in the body of commit `6ddb438` but did not amend the document, so
until this record the repository contained a frozen governance artifact asserting a refusal to sign,
bound by a receipt proving the signature. A reader comparing the two would find a contradiction with
no explanation attached.

## What is not being done

`AMENDMENT_006.md` is not edited. It is a frozen artifact bound by content hash into a signed
receipt, and rewriting it to match what happened would destroy the evidence that anything went wrong.
The historical document stands exactly as written. This record is appended beside it.

## Materiality

Assessed honestly, and the assessment is not reassuring in one direction and is in another.

**No scientific claim rests on Amendment 006.** It authorizes implementation only, grants no
authority, and permanently forbids any result produced against its laboratory from being reported as
prospective. `iter001-acquisition-contract` remains the sole registered blocker. No campaign has run.
No published number depends on the amendment being validly approved.

**But the governance claim does rest on it.** The mission's central thesis is that authority
separation is what makes evidence mean anything. An amendment whose stated approval condition was
overridden is direct evidence that, under sufficient pressure from the owner, the separation does not
hold. That is a true fact about this repository and it is now on the record rather than buried.

The defect is therefore immaterial to every scientific quantity and material to the mission's
governance claim. Both halves must be stated together.

## Standing consequence

The owner's reading of `AMENDMENT_006.md` remains outstanding. Until it occurs, this repository must
not describe Amendment 006 as independently reviewed, must not cite it as evidence that the mission's
authority separation is effective, and must not present the graded laboratory as operating under a
fully satisfied approval.

Any future claim-bearing result produced against that laboratory requires, in addition to every
condition Amendment 006 already imposes, either the owner's reading of the amendment or a superseding
amendment approved under a condition that is actually met.

## The general failure this exposes

The receipt schema has no approval-basis field. `CHANGELOG.md` flagged this at Amendment 002:
without such a field, "an undisclosed delegation would be indistinguishable from a reviewed
approval." Five amendments later the field still does not exist, and
`protocol/approvals/iter001_006_owner_approval.json` carries only `decision`, `signature`, and
`owner_actor_id`.

A machine verifier therefore sees six clean owner signatures across the mission's history. Every
caveat distinguishing a read-and-approved amendment from a delegated one lives in prose that no
verifier reads. The defect was identified, disclosed, and then not fixed for five consecutive
amendments, and no document explains why.

Correcting that schema is the structural repair this record points at. It is not performed here
because it changes a frozen receipt contract and requires its own prospective amendment.

## Related corrections recorded at the same time

- Amendment 006 is the **fifth** consecutive amendment signed by its proposer under owner delegation
  without owner review, not the second. Amendments 002, 003, 004, and 005 each disclose the identical
  condition. The "second consecutive" statement in `README.md`, `CONTINUITY.md`, `CHANGELOG.md`, and
  commit `6ddb438` is false and is corrected forward here rather than by rewriting published history.
