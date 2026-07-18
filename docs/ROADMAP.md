# Inbar Roadmap

This roadmap separates implemented software, prospective engineering work, and scientific stages.
It grants no data, execution, compute, claim, publication, or repository-visibility authority. The
machine-readable contracts govern the transitions they explicitly register; a general signed
lifecycle-transition authority is not implemented.

## Current implementation boundary

| Surface | Current state | Not yet established |
| --- | --- | --- |
| Mission governance | Bootstrap contracts, blocked authority, append-only memory, fresh-snapshot generated handoff, and content-bound same-operator engineering-validation receipts | General signed authority for every mission-stage transition or independent validation attestation |
| Corpus admission | Typed contracts, schemas, preassembled-dossier audit, and positive, negative, and placebo fixtures | Qualifying physical dossiers, canonical control authority, or a pilot verdict |
| Hypothesis handling | Typed hypothesis sets and Bayesian updates over caller-supplied hypotheses and likelihoods | An engine that constructs and tests open-world physical mechanisms from raw incident evidence |
| Test planning | Ranking of caller-supplied approved candidates under cost, time, risk, and safety constraints | Candidate-test generation, accredited outcome models, or physical execution authority |
| Execution and recovery | Deterministic local replay fixtures and component-level verification primitives | Shortcut Authority V2 integration, an independently enforced terminal verifier and signer boundary, testbed adapters, or settled physical recovery evidence |
| Monitor compilation | Typed monitor specification and provider-neutral port | A compiled, calibrated, transferred monitor |
| Product | Proposed offline and shadow-mode dossier compiler boundary | A released or validated product |
| External evidence | Dated source-routing decision with bounded legacy reconnaissance; approved and implemented screening (Amendment 002) and execution (Amendment 003) contracts with executable adversarial controls; live transport validated under a real owner-signed lease | A census run to a verdict, any screened candidate, a committed fact locator, or a `CensusReport` |

The machine contract's `offline_spacecraft_and_robotics_test_incident_replay` wedge is the current
research workflow, not a product-readiness claim. The proposed product has two ordered boundaries:
Phase A compiles pre-action evidence and human-reviewable test candidates without outcome truth;
only a later Phase B may ingest separately produced execution receipts and settled outcomes for
post-action assurance. Neither phase executes an action.

## Ordered engineering milestones

1. Credibility baseline. Keep public claims, equations, changelog, recovery state, and evidence scope
   synchronized with executable behavior. A green test suite is necessary but does not close a
   scientific or product gate.
2. Shortcut Authority V2 terminal integration. After a prospective implementation-only approval,
   wire the existing V2 primitives into an independently enforced, read-only terminal verifier that
   recomputes the complete admission subject without signing material, rejects V1 and artifact
   mutation, and proves the bootstrap contract still cannot execute canonically.
3. Lifecycle transition authority. Bind each permitted mission-stage change to a signed transition
   receipt, exact predecessor, required evidence set, denied authorities, and an independently
   replayable validator.
4. Phase A offline dossier compiler. Build the no-command product wedge that assembles evidence,
   clocks, rights, roles, hypotheses, approved test candidates, and claim boundaries without
   accessing outcome truth or executing an action. Phase B post-action assurance remains a later,
   separately authorized milestone.
5. Prospective source screening and acquisition. Under separate metadata, rights, resource, and
   safety authorities, run a frozen source census and then acquire qualifying physical dossiers. No
   model training begins before `PASS_PILOT`.
6. Deterministic ambiguity baselines. Freeze splits and establish whether cheap engineering,
   identity-only, or unimodal baselines kill the construct.
7. Multimodal, active-test, recovery, transfer, and value experiments. Advance one preregistered
   stage at a time, preserving every null, correction, shortcut result, and authority boundary.

## Ordering correction, 2026-07-16

Milestone 5's source screening was advanced ahead of milestone 2's terminal integration, under
Amendment 002 and owner-approval receipt `iter001-source-census-owner-approval-002`. The reason is
that the mission's central negative premise — that no public source can supply the complete incident
construct — had never been established under the mission's own evidentiary standard. It rested on a
reconnaissance this repository records as not systematic, with an external factual basis that is not
independently reconstructible, and it had already produced one overclaim that had to be narrowed
from `KILL_PUBLIC_SUBSTRATE` to `BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE`.

Terminal integration hardens the path that judges a corpus. The census establishes whether a corpus
can exist. Ordering the second before the first would have added verification depth to an admission
path with nothing to admit. This roadmap grants no authority and its ordering is advisory, so the
correction required no change to a frozen contract.

## Direction correction, 2026-07-18

Milestone 6 named deterministic ambiguity baselines and milestone 7 named an active-test experiment.
Both assumed the causal laboratory could measure a method. It could not, and the evidence for that is
now committed: the Amendment 005 effect is an algebraic identity and its constant probe is
structurally blind to a fault class. Amendment 006 rebuilt the laboratory so a method can fail in it.

The active-test milestone is closed as a null rather than pursued. The classical set-based rule of
Campbell and Nikoukhah (2004) ties the cost-aware information-gain selector at identical accuracy
across a fiftyfold risk-weight sweep. Further investment in Bayesian action selection for this
laboratory would be optimizing a component the evidence has already shown is not the bottleneck.

What the work produced instead is an instrument: exact separability over an enumerable hypothesis
space, able to state what is resolvable in principle before any method is scored. A 2026 review of
the external literature identified three problems that require exactly that primitive and that no
one currently owns.

1. **Anomaly masking by autonomy.** JPL's Ops-for-Autonomy states that autonomous onboard decisions
   alter state in response to information the ground never sees, hiding anomalies from downlink
   reconstruction. That programme ran FY2020 through FY2023 and appears closed. No taxonomy,
   detection method, or dataset was found. Masking is measurable here as the separability index
   computed on post-action rather than pre-action observation.
2. **Probe-quality benchmarking.** Existing benchmarks score whether an agent sought information, not
   whether the action it chose was the best available one. Scoring a chosen probe against an
   oracle-optimal probe requires an enumerable candidate space, which this laboratory has.
3. **Identifiability-aware diagnosis.** Published work reasons about reducing uncertainty, almost
   none about irreducibility: recognising that two hypotheses cannot be separated by any available
   observation and deriving what would separate them. The nearest prior art located is a position
   paper.

These are candidate directions, not authorized work. Each requires a prospective amendment. Any
novelty claim must distinguish itself explicitly from R2U2 runtime verification and from the 2026
agent-reconstructability cluster, and the external scan should be repeated before commitment because
that literature moved substantially within three months.

## Immediate next decision

The screening contracts (Amendment 002) and the execution authority (Amendment 003) are implemented
and their adversarial controls execute. Live retrieval has been exercised under a real owner-signed
lease to validate the transport against the frozen frame; three of the first four domains returned
bytes to an honestly-identified crawler and one refused it, which is recorded as an access datum.
That is transport validation. The census itself has **not run to a verdict**: no `CensusReport`
exists, no candidate has been screened against the twelve gates, and no verdict has been issued.

Three decisions are now open and are not interchangeable.

1. Run the census to a verdict. Cheap, local, metadata-only, and bounded by the frozen ceiling under
   a per-session lease. It resolves whether the mission has a subject among public sources. The
   likely outcome is a defensible `CENSUS_NULL_WITHIN_FRAME`, because investigations rarely record a
   pre-committed hypothesis set, an executed discriminating test, and independent outcome
   adjudication in a machine-reconstructible, rights-clear form.
2. Open the causal-laboratory plane. The source-role audit already froze a three-plane
   architecture whose second plane is a legally cleared NOS3 or Basilisk simulator that executes
   paired no-op, targeted, wrong-but-safe, recovery, and blocked-unsafe branches from identical
   snapshots. This is where the method itself can be built and tested against injected ground truth
   independent of whether public data qualifies, and it is the likeliest path to an actual result.
   It requires its own prospective authority and does not begin before the census is settled.
3. Confront the feasibility constraint the census made explicit. Amendment 002 condition C6 holds
   that a reviewer who reads an investigation record has read its conclusion, so an exposed
   extraction is contaminated and permanently ineligible for the incident floor. Combined with the
   parent's role-independence gate, counted dossiers require a second, unexposed reviewer and a
   producing authority whose governance documents role separation. Iteration 001 is therefore
   unlikely to be completable by a single researcher regardless of the census outcome. That is a
   recruiting and partnership question, not an engineering one, and no amount of implementation
   resolves it.

Shortcut Authority V2 terminal integration remains milestone 2 and still requires its own
prospective owner approval freezing interfaces, controls, allowed files, resource ceilings, and the
absence of production keys, corpus access, truth release, sealing, and external compute.
