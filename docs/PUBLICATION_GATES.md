# Publication Gates

## Decision

Publication is a scientific lifecycle stage, not a repository release task. A passing test suite,
a polished manuscript, or an available preprint server does not establish novelty, significance,
venue fit, or referee readiness.

The mission is currently `NO_GO` for manuscript submission. Iteration 000 qualifies a public
corpus; it does not test the mission's central scientific claim.

## Scientific maturity

A manuscript candidate requires all of the following:

1. The central claim has a preregistered test and a terminal positive, negative, null, blocked, or
   invalid verdict.
2. Every reported number is reproduced from a sealed proof bundle by an independent verifier.
3. A domain expert who did not implement the evaluated system reviews the problem formulation,
   controls, metrics, and interpretation.
4. A separate replication is complete, or the manuscript identifies the result as a single-run
   finding and makes no generalization beyond it.
5. The strongest cheap baseline, shortcut control, placebo, held-out transfer test, and uncertainty
   interval are present wherever the claim requires them.
6. Negative results, exclusions, failed runs, corrections, and material researcher degrees of
   freedom remain visible.
7. Every claim-bearing gate has a preregistered rejection condition and sealed positive and
   negative control results. At least one deliberately broken or placebo artifact must be rejected
   by the same executable path used for the reported result; a paper-only gate review is
   insufficient.

## Claim and artifact integrity

Every abstract, result, and conclusion statement must resolve to a registered claim. Each claim
must identify its exact protocol, code revision, data lock, split lock, run manifest, proof bundle,
independent verification receipt, statistical estimand, confidence procedure, and forbidden wider
interpretations.

No state-of-the-art, safety, recovery, transfer, customer-value, or economic claim may be inferred
from architectural intent. No valuation language belongs in a scientific manuscript without
independent customer and economic evidence.

## Manuscript review

Before submission, two reviews are recorded separately:

1. Scientific review checks originality, novelty, significance, experimental validity, related
   work, limitations, and whether the evidence supports the stated contribution.
2. Scholarly-communication review checks neutral professional language, conventional article
   structure, legible figures and tables, complete references, authorship, affiliations, tool-use
   disclosure, rights, licenses, and archival self-containment.

The author remains responsible for every statement and citation. Tool-generated prose, analysis,
or references receive the same source and correctness checks as manually produced material.

## Venue review

A named conventional journal or peer-reviewed conference is selected before a preprint target. The
record must show that the manuscript fits the venue's scope and article type, identify comparable
recent publications, and satisfy current author, category, formatting, disclosure, and artifact
policies.

arXiv may be used for distribution only when the work is a topical, refereeable scientific
contribution and satisfies its current scholarly and moderation requirements. arXiv explicitly
states that moderation is not peer review, that submissions needing significant review or revision
may be declined, and that conventional publication does not guarantee acceptance. See the official
[content moderation policy](https://info.arxiv.org/help/moderation/index.html) and
[submission guidelines](https://info.arxiv.org/help/submit/index.html).

## Release verdicts

`NO_GO` means at least one required gate is absent or failed.

`JOURNAL_READY` means the scientific, artifact, manuscript, rights, external-review, and venue-fit
records all pass for a named conventional venue.

`PREPRINT_READY` additionally means the exact preprint service's current moderation, category,
endorsement, source, license, and disclosure requirements pass. It never predicts acceptance.

No submission occurs from an uncommitted worktree or before Daniel Wahnich records the final
release authorization.
