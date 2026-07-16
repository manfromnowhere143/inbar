# Frontier Research Dossier 2026

- Research cutoff: 2026-07-16
- Evidence policy: primary research papers, author-maintained project records, and official NASA
  or model-provider documents only
- Mission descriptor: Physical Causal Evidence and Verified Intervention Research

## Executive verdict

The strongest research problem is not another general-purpose vision-language-action model, a
new robot benchmark score, an active fault-diagnosis algorithm in isolation, or a recovery
planner in isolation. All four areas have direct prior art, and several apparent advances can be
explained by benchmark shortcuts or deployment metadata rather than the claimed capability.

The selected problem is an end-to-end causal assurance problem for off-nominal physical systems:

> Given heterogeneous, partially trustworthy evidence from a physical system, can a system retain
> competing known and unknown causal mechanisms, select a safe intervention that maximizes
> discrimination per unit cost and risk, execute a recovery through a separately governed path,
> verify settled physical recovery using an independent outcome authority, and compile the result
> into a calibrated monitor that survives held-out hardware, mission, and fault-family transfer?

This question is worth pursuing because each link is useful and individually occupied, while the
dated reconnaissance did not establish the joint evidence contract among its enumerated sources.
That screen was neither systematic nor independently reconstructible, so it cannot support an
exhaustive source or novelty claim. The mission must not claim that the combination is novel until a
prospective systematic review and experiments support that statement. Its initial contribution is a
falsifiable architecture and evaluation protocol, not a performance claim.

The research chain is:

```text
heterogeneous evidence
    -> open-world causal hypotheses
    -> safe, cost-aware discriminating intervention
    -> separately governed recovery execution
    -> independent settled-outcome verification
    -> calibrated monitor with a declared validity domain
    -> economic value lower bound
```

Iteration 000 on NASA ADAPT is only a corpus-readiness adjudication. It cannot test this chain and
must not be presented as a model benchmark.

## Why this problem survives the frontier check

### A benchmark score is not yet a capability measure

The June 2026 manipulation-benchmark audit reports that a 0.09B probe with no language encoder
scores at or near the best reported LIBERO result. The same audit identifies shortcut solvability,
insufficient statistical evidence, test-distribution overfitting, and data-source dependence as
distinct threats to benchmark validity [S1]. This result makes a conventional LIBERO campaign an
unacceptable scientific foundation unless language-free, task-identity, and data-source controls
are run first.

Independent 2026 studies report related failures. ICBench holds the visual scene fixed while
injecting contradictory instructions and finds that several VLA families often continue visually
plausible actions [S2]. LIBERO-CF changes instructions under visually plausible layouts and
attributes errors to visual shortcuts induced by dataset bias [S3]. These papers occupy the broad
claim of discovering language neglect in VLAs.

The identity problem extends below the learned checkpoint. A June 2026 preprint shows that an
action-unnormalization metadata substitution can make identical weights executable-inequivalent,
with large replay failures in its LIBERO study [S4]. Accordingly, a deployable policy identity must
bind model weights, action representation, normalization metadata, controller conventions,
software, configuration, and the physical embodiment. A checkpoint hash alone is insufficient.

### Multimodal control and cross-embodiment transfer are occupied

OpenVLA established an accessible 7B VLA trained on 970,000 robot demonstrations and demonstrated
efficient adaptation across multiple manipulation settings [S5]. Open X-Embodiment assembled data
from 22 robot embodiments and reported positive transfer in RT-X models [S6]. Physical
Intelligence's pi-0.5 combines robot, web, semantic, and low-level action data for open-world
household manipulation [S7]. Google DeepMind's current Gemini Robotics materials describe a
dual-model VLA and embodied-reasoning stack with multimodal perception, planning, success
detection, and layered safeguards [S8].

These results occupy broad claims of multimodal physical control, heterogeneous pretraining,
cross-embodiment learning, and open-world manipulation. They do not establish causal diagnosis,
independent recovery verification, or assurance for a new deployment. Google DeepMind's April
2026 model card expressly excludes safety-critical use, while its robotics safety page states that
its stop behavior is not a guaranteed safety-rated system and that the models have not been tested
on every robot [S8]. This is a documented decision-use boundary, not evidence that any particular
provider lacks internal safety work.

### Active diagnosis and diagnosis-to-recovery planning are occupied

The most direct modern prior is Safe, Real-Time Active Model Discrimination and Fault Diagnosis
for Nonlinear Systems. It optimizes an output-feedback policy over a finite candidate-model set,
uses reachability over-approximations to enforce state and input constraints, and reports real-time
tests across simulated and physical robotic systems [S9]. A 2025 counterfactual diagnosis paper
formulates active perception-system diagnosis as a causal bandit and demonstrates attitude changes
that disambiguate faults in a space-robot navigation scenario [S10].

NASA work makes the occupied boundary older and broader. Its Autonomous Operating System study
starts from an ambiguous fault group, selects active procedures such as a climb or pitch doublet,
uses R2U2 for monitoring, produces a contingency plan, and sends that plan to PLEXIL for execution
[S11]. NASA's Gateway Vehicle System Manager integrates fault management, planning, and execution
and replans after detected failures [S12]. Earlier Livingstone and spacecraft autonomy programs
also integrated model-based diagnosis, planning, and execution.

The mission therefore cannot claim first active diagnosis, first safe diagnostic action, first
diagnosis-to-recovery loop, or first spacecraft autonomy stack. The remaining question is whether
heterogeneous learned evidence, explicit unknown mechanisms, safe information-efficient tests,
separate execution and outcome authority, transfer calibration, and auditable value can work as
one measured system.

### Recovery learning is occupied, but this mission requires stricter recovery evidence

RoboFAC provides failure-focused multimodal training data and an external supervisor for failure
analysis and correction [S13]. B2FF conditions VLA recovery on pre-imagined future milestones and
reports gains on failure-injected LIBERO [S14]. ReSYNC learns recovery skills and then synthesizes
relational concepts for failure-aware planning, including a sim-to-real demonstration [S15]. A
June 2026 real-robot benchmark reports that execution instability dominates many failures and that
recovery varies materially by architecture [S16].

Three additional 2026 systems tighten the occupied boundary. Dream2Fix reports counterfactual
failure-correction synthesis and zero-shot closed-loop recovery in physical deployments [S30].
AgentChord, accepted to RSS 2026, compiles anticipatory recovery branches before execution and uses
low-latency monitors to trigger them [S31]. A confidence-aware human-in-the-loop framework jointly
models module uncertainty and human-intervention cost and reports physical bite-acquisition recovery
experiments [S32]. These systems occupy physical closed-loop correction, proactive contingency
execution, and uncertainty-versus-intervention-cost recovery baselines.

These works occupy failure analysis, correction generation, learned recovery, and learning from
recovery experience. They also expose the unresolved measurement issue: a predicted correction,
visual milestone, evaluator score, or simulator rollout is not itself proof that the physical
system reached and remained in a pre-registered recovered state.

### Open-world reasoning and uncertainty are occupied in parts

Hypothesis-driven Model Expansion under Uncertainty, accepted to RSS 2026, generates, verifies,
and updates abstract world-model hypotheses while planning in unknown environments [S17]. KnowNo
uses conformal prediction to decide when an LLM planner should ask for help [S18]. VLAConf learns a
single-pass post-hoc confidence signal from frozen VLA representations and evaluates it on LIBERO
and a real robot [S19]. These works occupy broad claims about uncertainty-aware planning,
hypothesis verification, abstention, and VLA confidence.

The mission's narrower requirement is an explicit unknown-mechanism state whose mass can grow
when every catalogued mechanism is inconsistent with evidence. It must be evaluated under grouped
hardware, mission, and fault-family shifts. Ordinary split-conformal language must not be used to
claim distribution-free coverage for telemetry sequences without a valid dependence argument.
Recent theory explicitly treats temporal dependence as a violation of exchangeability and bounds
coverage loss only under additional process assumptions [S20].

### A world model can propose evidence, but cannot appoint itself as reality

Google DeepMind demonstrates a Veo-based simulator for nominal, out-of-distribution, and safety
evaluation of robotics policies and validates relative predictions against more than 1,600
real-world evaluations [S21]. This is strong evidence that generative simulation can expand test
coverage. It does not make a generated world an unrestricted outcome authority.

What-If World tests pairs of prompt-conditioned generated videos that vary one described physical
detail and reports that individually plausible videos can still fail the required paired causal
divergence [S22]. NASA-STD-7009B separately requires acceptance criteria and credibility assessment
for models and simulations used in decisions [S23]. The mission may use a simulator inside its
declared, validated decision-use domain; it cannot allow a world model that proposes a recovery to
be the sole verifier of that recovery.

### Aerospace assurance makes independence a system property

NASA-STD-8739.8B defines software assurance, software safety, and IV&V as life-cycle activities and
requires objective evidence for nominal and off-nominal behavior [S24]. NASA's 2023 GN&C best
practices state that autonomous fault management should be independent of hardware and software
that may have caused or diagnosed the fault; the report warns against using the same sensor to
control and independently monitor a loop [S25]. NASA's Autonomy V&V Roadmap identifies a mismatch
between learning-enabled autonomy and certification processes that expect behavior to be specified
and verified before operation [S26]. NASA's model-based fault-diagnosis assurance work identifies
the diagnostic model, engine, and their combination as separate V&V targets [S27].

This evidence supports distinct proposal, execution, and outcome roles. It does not justify a NASA
compliance, certification, flight-readiness, or safety claim for this repository.

## Prior-art and claim map

| Research layer | Direct evidence | Occupied claim | Residual question for this mission |
| --- | --- | --- | --- |
| Generalist multimodal control | OpenVLA, RT-X, pi-0.5, Gemini Robotics [S5-S8] | VLA control, heterogeneous pretraining, cross-embodiment transfer | Can these models contribute hypotheses without becoming truth or outcome authority? |
| Benchmark validity | Manipulation benchmark audit, ICBench, LIBERO-CF [S1-S3] | Language-shortcut discovery and counterfactual language tests | Does any multimodal gain survive cheap identity-only and modality-removal controls? |
| Executable identity | Same Weights, Different Robot [S4] | Checkpoint identity is insufficient | Can every result bind the exact executable policy and physical interface? |
| Open-world planning | Hypothesis-driven model expansion [S17] | Hypothesis generation, verification, and model expansion | Can unknown causal mechanisms be retained and independently settled in fault response? |
| Active diagnosis | Differentiable reachability and causal-bandit FDI [S9-S10] | Safe active model discrimination | Does the chosen test add causal information after cost, delay, risk, and baseline controls? |
| Diagnosis and recovery | NASA AOS and Gateway VSM [S11-S12] | Integrated diagnosis, planning, execution, and contingency response | Can learned multimodal evidence be added without weakening assurance or independence? |
| Learned recovery | RoboFAC, B2FF, ReSYNC, Dream2Fix, AgentChord, and confidence-aware human intervention [S13-S15, S30-S32] | Failure correction, physical closed-loop recovery, anticipatory branches, and cost-aware human recovery | Does a separately executed action reach a pre-registered settled physical state under independent outcome authority? |
| Confidence and abstention | KnowNo and VLAConf [S18-S19] | Planner abstention and VLA confidence | Does calibration survive grouped physical transfer and dependent telemetry? |
| Generative simulation | Veo evaluation and What-If World [S21-S22] | Scalable world-model evaluation and causal stress tests | What decision-use domain is credible, and what still requires physical settlement? |
| Assurance | NASA standards, roadmaps, and GN&C practices [S23-S27] | Model credibility, IV&V, and independence requirements | Can evidence lineage and authority separation make adaptive experiments auditable? |

No row supports a claim that this mission is first. The research claim, if earned, must concern the
measured behavior of the complete chain under the controls below.

## Formal research object

For incident evidence `E`, physical state `z`, discrete mode `q`, parameters `theta`, and mechanism
set `H`, the mission maintains:

```text
p(H, z, theta | E), where H = known mechanisms union {unknown}
```

The learned component may propose residual structure or candidate mechanisms. It may not remove
physical constraints, force an unknown case into a known label, or act as its own verifier.

For approved diagnostic action `a`, outcome `Y_a`, direct cost `C`, delay `T`, bounded risk `R`, and
positive denominator floor `epsilon`, every denominator term is expressed in the same declared cost
unit:

```text
a* = argmax over a in A_safe:
     I(H; Y_a | E) / max(C(a) + lambda*T(a) + mu*R(a), epsilon)
```

`lambda` converts seconds to cost units and `mu` converts one unit of the frozen risk score to cost
units. The executable planner represents them as `PlannerWeights.time_weight` and
`PlannerWeights.risk_weight`; it represents `epsilon` as `denominator_floor`, whose current default
is `1e-9` cost units. A claim-bearing run must freeze the cost unit, cost normalization, risk scale,
weights, and denominator floor before outcome inspection. Defaults are numerical behavior, not an
authorized economic interpretation. Actions outside the frozen safety envelope are ineligible
regardless of score. The action selected for execution must be the exact approved action, not an
equivalent natural-language paraphrase or a substituted test.

A recovery is accepted only when a separately identified outcome authority verifies all of the
following:

1. The action was admissible under the frozen envelope.
2. The action targeted the diagnosed mechanism rather than merely correlating with success.
3. The measured physical state entered and remained in the pre-registered settled-success set.

The compiled monitor must declare its validity domain, sensor and clock assumptions, calibration
set, grouped holdouts, latency and resource bounds, false-action cost, and abstention behavior.

## Proposed identity and shortcut controls

The following controls are a proposed minimum expansion for future claim-bearing protocols, not a
replacement for the master preregistration and Iteration 001 controls. They acquire authority only
through prospective preregistration or amendment. Every already frozen control remains mandatory
before a multimodal benefit claim:

1. Deterministic engineering baseline using only permitted physical rules and telemetry.
2. Task-index or case-identity lookup with no semantic language encoder, plus learned and randomly
   initialized identity embeddings.
3. No-language policy and shuffled-language policy.
4. Telemetry-only, vision-only, log-only, and configuration-only ablations.
5. Early fusion, late fusion, and a compute-matched unimodal ensemble.
6. Modality deletion, permutation, duplication, noise, and bounded clock-jitter controls.
7. Timestamp, filename, row-order, site, vehicle, and operator-identity probes.
8. Nearest-training-source and duplicate-trajectory checks.
9. Frozen-pretraining versus task-specific adaptation comparison.
10. Correct versus substituted action normalization and controller metadata.
11. Exact executable-policy identity binding, including model, transforms, controller, software,
   configuration, and embodiment.
12. Group-held-out evaluation by connected leakage component, hardware family, hardware identity,
    vehicle, mission, environment, fault family, and operating regime.

If a cheap identity-only control matches or exceeds the full system within the pre-registered
uncertainty interval, the multimodal mechanism claim is null even when aggregate accuracy is high.

## Falsification program

Each campaign freezes numerical thresholds, analysis code, group definitions, and stop rules
before outcome inspection. The `C0` through `C9` labels below are integrated-campaign gates. They
refine but do not renumber, replace, or silently amend the frozen `F1` through `F10` falsifiers in
`PREREGISTRATION.md`. Any detail beyond the verbatim frozen master and iteration contracts is a
prospective design candidate. It gains protocol and claim authority only through the relevant
pre-outcome iteration preregistration or an explicit prospective amendment.

### C0: evidence construct

Block the campaign unless all frozen Iteration 001 coverage gates pass on complete root incidents:
at least 30 incidents, three physical system families, two hardware identities per family and six
overall, three fault families, six incidents per included system family, six per included fault
family, and three per included identity. No included system or fault family may exceed 50 percent of
eligible incidents; every system family must cover two fault families; every fault family must occur
on two identities; and every claim-bearing fault family must occur in two system families. The set
must include an aerospace or spacecraft-like family and a robotic family, preserve the frozen split
boundaries, and give every counted dossier independently established cause, pre-outcome ambiguity,
an independently reviewed safe discriminating test, and the complete evidence contract. Source,
parser, truth-separation, or exact-census failures are invalid rather than negative.

### C1: multimodal necessity

Define the frozen primary score `S` so larger values are always better. A cost, error, test-count,
or time measure must therefore enter as a prospectively frozen reduction or sign-reversed score,
never as an ambiguously oriented `M`. The frozen necessity family includes every applicable cheap
deterministic, runbook, FMEA, fault-tree, observer, Bayesian, and physics-only baseline; task and
configuration identity; source, site, system, vehicle, operator, timestamp, filename, and row-order
identity or leakage probes; all unimodal systems; no-language and shuffled-language systems;
modality deletion, permutation, and replacement of a complementary modality by a duplicate; learned
and random identity embeddings; and compute-matched unimodal and placebo controls. For every
eligible necessity baseline `b`, define `Delta_b = S_full - S_b`. Estimate all contrasts without
outcome-selected baseline choice and form simultaneous one-sided 95 percent lower bounds across the
frozen baseline and material-group family. The multimodal necessity claim fails unless every
required `LCB(Delta_b)` is positive.

The frozen evaluation matrix must also include early-fusion, late-fusion, and declared production
fusion architectures under matched information and compute. These are architecture controls, not
automatic necessity-denying baselines. Their results are reported without outcome-selected model
choice; a claim that one fusion architecture is superior requires its own prospectively oriented,
simultaneous contrasts.

Label-preserving duplication, bounded sensor noise, and bounded clock jitter are robustness
controls. Before outcomes, classify each perturbation as benign or destructive and freeze its
magnitude and margin. For benign perturbation `r`, define
`Delta_robust,r = S_perturbed,r - S_clean`; its simultaneous one-sided lower bound must exceed the
negative non-inferiority margin. An invariance claim additionally requires the simultaneous
two-sided interval to lie inside its frozen equivalence bounds. A destructive or invalid
perturbation instead receives a frozen rejection or abstention criterion and cannot be relabeled
benign after outcomes. Cluster resampling for every C1 contrast must preserve the highest required
dependency unit across root incident, acquisition session, and hardware identity, not individual
frames or windows.

### C2: active causal value

Run the complete frozen comparator set: no-op, no test, passive observation, a fixed engineering
test, random safe, cheapest safe, wrong-but-safe, myopic expected information gain, classical optimal
experiment design, belief-tree search, safe reachability-based discrimination where applicable, and
an information-only planner that omits cost and risk. No-op, no test, and passive observation remain
separate unless a prospective protocol proves their operational equivalence. Wrong-but-safe is a
falsification control, not an eligible action recommendation.

The planner ranks actions using prospectively frozen predicted `C_plan`, `T_plan`, and `R_plan`. The
evaluation does not substitute those forecasts for what occurred. For method `m` on incident `i`, let
`G_mi` be prior minus posterior mechanism entropy after the frozen observation horizon and let
`D_mi_observed = max(C_mi_observed + lambda*T_mi_observed + mu*R_mi_observed, epsilon)` in the exact
declared cost unit, using audited realized cost, elapsed time, and intervention-risk outcome. Missing
realized terms remain missing rather than zero. The normalization, risk scale, weights, horizon, and
positive `epsilon` are frozen before outcomes; no-op and zero-direct-cost replay use the same
denominator floor rather than division by zero. For every eligible comparator `b`, define
`Delta_bi = G_active,i/D_active,i_observed - G_b,i/D_b,i_observed` at the independent incident unit.
Use simultaneous one-sided 95 percent lower bounds across frozen comparator and material-group
contrasts with clustering by root incident, acquisition session, and identity. The active causal
value claim fails unless every required `LCB(E[Delta_bi])` is positive and outcome-conditioned
likelihood ratios move the competing mechanisms in the preregistered directions.

The `G/D` contrast is necessary but insufficient: entropy reduction can reward confident error.
Before outcome access, the protocol must freeze an outcome-authority adjudication rule for correct
mechanism isolation, a hypothesis-set coverage target, and a proper-score or calibration metric whose
orientation and non-inferiority margin are explicit. Correct isolation and hypothesis coverage must
meet their preregistered aggregate and material-group gates, and the simultaneous lower bound for the
oriented active-versus-reference proper-score or calibration contrast must exceed the negative frozen
margin. A gain in information per observed cost cannot compensate for failure of any of these gates.

The operational-efficiency gate is evaluated against one prospectively named reference workflow,
selected without outcome access. It additionally fails if the system achieves neither at least 30
percent fewer tests to correct isolation nor at least 25 percent lower blinded engineer time. Define
`Delta_FA = false_action_rate_active - false_action_rate_reference`; its simultaneous one-sided upper
confidence bound must not exceed the prospectively frozen non-inferiority margin. These are
directional eligibility bars; a later experiment preregistration must freeze estimators, margins,
multiplicity, and power before inspecting outcomes. Neither efficiency bar can compensate for failed
correct-isolation, hypothesis-coverage, calibration, information-direction, or false-action gates.

### C3: safety-envelope integrity

Any executed action outside the signed envelope invalidates the campaign. The method fails its
safety objective if the upper confidence bound on hazardous or inadmissible actions exceeds the
pre-registered cap, regardless of diagnostic accuracy.

### C4: open-world behavior

Hold out entire mechanism families. The open-world claim fails if the system forces held-out cases
into known labels above the permitted false-known rate, if unknown recall at the frozen
false-unknown rate misses its threshold, or if abstention does not reduce selective risk as
coverage decreases.

### C5: independent recovery

Compare recovery under matched fault and risk conditions against every prospectively eligible fixed,
model-based, learned physical-recovery, anticipatory-branch, and confidence-aware human-intervention
baseline, including Dream2Fix and AgentChord where their operating assumptions apply. Use
simultaneous clustered contrasts rather than selecting a winner after outcome access. For every
eligible baseline `b`, define
`Delta_recovery,b = settled_success_active - settled_success_b`; every required simultaneous
one-sided 95 percent lower bound must be positive. The recovery claim also fails if the settled-state
dwell requirement is missed or if the outcome verifier is not in a preregistered independence group
separate from the hypothesis proposer, action selector, recovery proposer, and executor. Missing
conflict disclosure, or a shared learned model, sensor dependency, or mutable outcome path that
defeats outcome independence, also fails the claim.

### C6: transfer and calibration

Freeze separate group holdouts for leakage component, hardware family, hardware identity, vehicle,
mission, environment, fault family, and operating regime; a joint connected-component union cannot
erase a crossed axis.
A transfer claim requires a separately preregistered clustered power calculation and, regardless of
a smaller calculated minimum, at least four system families, eight hardware identities, and four
fault families. The frozen phrase `two untouched claim-bearing family units` is not operational by
itself. Before Iteration 006 outcome access, a prospective transfer protocol must define it at minimum
as one complete claim-bearing system family and one complete claim-bearing fault family, each absent
from training, tuning, calibration, threshold selection, and repair and evaluated under separate
axis locks.

That protocol must orient a primary transfer score so larger is better and define each held-out
contrast against a prospectively named reference, with simultaneous one-sided 95 percent lower
bounds across axes and material groups. Results are clustered by root incident, acquisition session,
and identity. A transferable-monitor claim fails if any required transfer-effect lower bound is not
positive, if any required group's empirical coverage lower bound falls below the frozen target, if
worst-group selective risk exceeds its cap, or if a calibration repair uses held-out outcomes without
being declared as adaptation.

### C7: simulation decision use

Simulator evidence is rejected when the simulator lacks an approved decision-use statement,
acceptance criteria, validation evidence, and an uncertainty account for the tested regime. A
generative world's visual plausibility cannot settle a physical recovery claim. Independently of
simulator acceptance, optimization stops when a learned reward or confidence proxy improves while
independently settled physical success degrades or the proxy reverses the true policy ordering. The
physical outcome and ordering authority must be frozen separately from the learned proxy.

### C8: reproducibility and evidence integrity

The result is invalid if an independent verifier cannot reconstruct the same verdict from frozen
source bytes, code, configuration, executable identity, approvals, receipts, and artifacts, or if
truth-plane fields enter any model-visible input.

### C9: economic value

The frozen master protocol retains its aggregate value formula. The following exposure-normalized
estimands are a prospective refinement and become claim-bearing only through a value-stage
preregistration or explicit prospective amendment before customer or outcome access.

For incident `i`, the exact variable net value is `v_i = benefit_i - variable_cost_i` from
`docs/MATHEMATICS.md`. Benefits use prospectively approved, nonoverlapping ledger categories and
rates. Costs include diagnostics, actuation, review, compute, storage, delay, realized intervention
risk, and false actions, but a cost already represented in a `B minus Inbar` benefit delta cannot be
subtracted again. `V_tau_observed` subtracts the fixed integration cost from the audited observed
horizon total. `rho` is target-population variable net value per frozen exposure unit, and
`V_tau_target = E_tau * rho - integration_cost_tau`. Each material group has its own
exposure-normalized `rho_g`.

The target population, assignment or identification design, exposure unit, positive finite target
exposure, independent-unit clustering, missing-data rule, rates, material-group membership and
exposure-allocation rules, and multiplicity procedure are frozen prospectively. A one-sided 95
percent simultaneous confidence procedure must cover the joint family containing `rho` and every
`rho_g`; marginal 95 percent intervals are insufficient. A required group with no positive finite
exposure blocks the value claim rather than passing or disappearing from the family.
Model-imputed or retrospective hypothetical loss reduction is excluded unless prospectively
identified causal evidence and independently settled outcomes support it. The product-value claim
fails when observed horizon value, target horizon lower bound, or any simultaneous material-group
lower bound is not positive. These statistical conditions are necessary but not sufficient for a
pricing or scale claim, which additionally requires independently verified customer or partner
evidence under the frozen master protocol.

## Experimental campaign sequence

| Iteration | Decision | Minimum output | Stop condition |
| --- | --- | --- | --- |
| 000 | Is a public corpus fit for the construct? | Signed source lock, leakage-safe ingestion, exact coverage, gate-by-gate readiness verdict | Stop after `PASS`, `BLOCKED_EVIDENCE`, or `INVALID`; no model run |
| 001 | Can a prospective campaign admit the physical evidence construct? | Signed dossier registry, conjunctive admission and coverage report, and split-feasibility locks | Stop with any registered terminal verdict; only `PASS_PILOT` advances |
| 002 | Is the admitted incident set genuinely ambiguous? | Complete frozen baseline ladder from limits, runbooks, FMEA, fault trees, observers, Bayesian diagnosis, and physics-only simulation through any authorized learned system | Stop with `KILL_CONSTRUCT` if a cheap baseline resolves the cases |
| 003 | Does multimodal evidence add causal information? | Complete frozen modality, fusion, identity, placebo, and compute-matched controls with grouped intervals | Stop the multimodal claim if C1 fires |
| 004 | Does active selection beat the complete frozen comparator set? | Safe-test replay or accredited simulation with mechanistic information evidence, tests-to-isolation, blinded engineer time, false actions, realized cost, and risk | Stop active testing if C2 or C3 fires |
| 005 | Does recovery survive separate execution and verification? | Settled-state physical or accredited testbed outcomes | Stop the recovery claim if C5 fires |
| 006 | Does a compiled monitor transfer and calibrate? | Separately frozen holdout axes, an operational definition of the two untouched claim-bearing family units, clustered power analysis, the minimum family counts, and each transfer estimate with its simultaneous lower bound | Advance only if the required lower bounds are positive; otherwise restrict the validity domain or stop the transfer claim |
| 007 | Does the system create measurable customer value? | Prospective shadow deployment with audited cost records and independently verified customer or partner evidence | Stop the commercial claim if C9 fires |

GPU or cloud scale is justified only after the preceding construct and shortcut gates pass. Scale
cannot repair a non-identifying benchmark.

## Why NASA ADAPT iteration 000 is readiness only

NASA describes ADAPT as a spacecraft-like electrical power testbed for repeatable physical and
software fault insertion. Its public package exposes 128 sensors sampled at 2 Hz, commands,
configuration changes, and fault-related records [S28]. These properties make it useful for testing
source integrity, parsing, clock and lineage contracts, and truth/evidence separation.

They do not establish the mission thesis:

1. The pre-registration disclosed 16 experiment text files, while the frozen construct requires at
   least 30 qualifying incidents.
2. Public fault metadata is not automatically an independent causal adjudication.
3. An injected fault label does not prove that two mechanisms were plausible before the outcome.
4. Recorded commands are not automatically independently reviewed, safe discriminating tests.
5. One testbed does not satisfy the admission floor of three system families and six hardware
   identities, and it cannot establish the later transfer claim.
6. The package was not created to evaluate independent recovery execution or settled-state dwell.
7. Fault-injection, experiment-control, or antagonist-internal rows would leak truth if exposed to
   a model.

Iteration 000 can therefore answer only whether the bytes and records satisfy the frozen evidence
contract. A `BLOCKED_EVIDENCE` result is useful because it prevents training on a construct that
cannot answer the question. An `INVALID` result identifies source, parsing, coverage, or leakage
failure. Neither result is a model failure, and a `PASS` would authorize only the next
pre-registered baseline iteration.

## Product and value model

### Initial product boundary

The current research wedge is offline spacecraft and robotics incident replay. The distinct proposed
Phase A product is an offline assurance workbench for ambiguous physical-system incidents. It would
ingest telemetry, images or video, logs, commands, procedures, and configuration graphs while
keeping outcome truth separate. It would produce competing mechanism records, human-reviewable
diagnostic-test packages, and an assurance case linking every permitted pre-action claim to exact
evidence.

A later Phase B surface may ingest execution receipts and independent recovery verdicts produced
under separate authorities. Neither phase would command a system, replace an organization's safety
authority, or serve as a certification product.

### Expansion path

1. Offline incident replay and evidence qualification.
2. Read-only shadow recommendations beside existing engineering workflows.
3. Approved simulator and hardware-in-the-loop diagnostic campaigns.
4. Governed test-stand execution with independent outcome instrumentation.
5. Fleet-level mechanism and monitor learning across explicitly separated hardware groups.
6. Resource-bounded onboard monitors, only inside a validated and approved authority envelope.

The scientific invariants remain constant while each stage receives its own evidence and authority
contract. This provides a credible path from a narrow evidence product to a broader
mission-assurance system without treating early replay results as flight authority.

### Buyer-relevant measurements

The product case should be evaluated prospectively on:

1. Time from anomaly declaration to a correctly bounded mechanism set.
2. Number and cost of tests required to reach a decision.
3. Rate of unsafe, inadmissible, or non-discriminating test proposals.
4. Settled recovery success and recurrence after the dwell window.
5. Human review time and proposer-verifier disagreement.
6. False alarms, false interventions, and abstention burden.
7. Worst-group calibration and transfer degradation.
8. Independent replay success and evidence reconstruction time.
9. Net value and its 95% lower confidence bound.

NASA's Artemis IV&V program describes the need to target the highest-risk assurance work within a
constrained budget and to communicate residual risk across a multi-program enterprise [S29]. That
is evidence for the operational importance of efficient assurance, not evidence of demand,
procurement, pricing, or revenue for this product. Those require customer discovery and a
prospective deployment.

## Claim discipline

Until the relevant experiments pass, the mission may say that it:

1. Contains typed provider-neutral evidence and authority contracts.
2. Pre-registers shortcut, leakage, safety, transfer, and value falsifiers.
3. Defines separate proposer, executor, and outcome-verifier roles.
4. Retains the bounded Iteration 000 readiness verdict and its content-addressed proof artifacts.

It may not say that it is state of the art, safer than a named organization, certified,
flight-ready, universally transferable, causally correct, economically valuable, or independently
verified merely because the repository contains signatures or an external model critique.

## Remaining uncertainty

1. The search cannot observe private work at SpaceX, Google DeepMind, OpenAI, Anthropic, NASA
   contractors, or other frontier teams. Absence from the public record is not evidence of absence.
2. Several 2026 sources are recent arXiv preprints. Their methods and results may change after
   review, revision, or independent replication.
3. The dated reconnaissance did not establish a public corpus satisfying the full ambiguity,
   safe-test, independent-cause, recovery, and transfer contract; it was not exhaustive.
4. The correct physical domains, risk caps, and settled-success definitions require domain-owner
   approval. A generic repository cannot infer them safely.
5. NASA standards and handbooks inform architecture and evidence discipline but do not make this
   work NASA-compliant or certified. Applicability and tailoring are program decisions.
6. Cryptographic receipts prove integrity and key possession under their stated trust model; they
   do not prove that a sensor was correct, an intervention was safe, or a scientific claim is true.
7. The economic model has no customer data yet. No valuation or revenue claim is supportable.

## Source registry

The legacy reconnaissance records S1-S29 as accessed on 2026-07-14; the recovery-frontier update
records S30-S32 as accessed on 2026-07-16. Page contents and fact locators were not content-frozen, so
this registry is not independently reconstructible evidence.

| ID | Primary or official source | Date and status |
| --- | --- | --- |
| S1 | [What Are We Actually Benchmarking in Robot Manipulation?](https://arxiv.org/abs/2606.04233) and [author project page](https://ripl.github.io/manipulation_benchmark_audit/) | Submitted 2026-06-02; arXiv preprint |
| S2 | [Restoring Linguistic Grounding in VLA Models via Train-Free Attention Recalibration](https://arxiv.org/abs/2603.06001) | Revised 2026-07-02; arXiv preprint |
| S3 | [When Vision Overrides Language: Evaluating and Mitigating Counterfactual Failures in VLAs](https://arxiv.org/abs/2602.17659) | Submitted 2026-02-19; arXiv preprint |
| S4 | [Same Weights, Different Robot: A Deployment Safety View of VLA Policies](https://arxiv.org/abs/2606.03724) | Submitted 2026-06-02; arXiv preprint |
| S5 | [OpenVLA: An Open-Source Vision-Language-Action Model](https://arxiv.org/abs/2406.09246) | Submitted 2024-06-13; arXiv preprint and released code/model |
| S6 | [Open X-Embodiment: Robotic Learning Datasets and RT-X Models](https://arxiv.org/abs/2310.08864) | Submitted 2023-10-13; research paper and released dataset/code |
| S7 | [pi-0.5: a Vision-Language-Action Model with Open-World Generalization](https://arxiv.org/abs/2504.16054) | Submitted 2025-04-22; arXiv preprint |
| S8 | [Gemini Robotics-ER 1.6 model card](https://deepmind.google/models/model-cards/gemini-robotics-er-1-6/) and [robotics safety framework](https://deepmind.google/models/gemini-robotics/responsibly-advancing-ai-and-robotics/) | Model card published 2026-04; official Google DeepMind documents |
| S9 | [Safe, Real-Time Active Model Discrimination and Fault Diagnosis for Nonlinear Systems via Differentiable Reachability](https://arxiv.org/abs/2606.19590) | Submitted 2026-06-17; arXiv preprint |
| S10 | [A Counterfactual Reasoning Framework for Fault Diagnosis in Robot Perception Systems](https://arxiv.org/abs/2509.18460) | Submitted 2025-09-22; arXiv preprint |
| S11 | [Model-based System Health Management and Contingency Planning for Autonomous UAS](https://ntrs.nasa.gov/api/citations/20190002780/downloads/20190002780.pdf) | 2019; NASA-hosted conference paper |
| S12 | [Integrating Planning, Diagnosis and Execution for Vehicle Systems Management](https://ntrs.nasa.gov/citations/20230004265) | 2023; NASA conference paper |
| S13 | [RoboFAC: A Comprehensive Framework for Robotic Failure Analysis and Correction](https://arxiv.org/abs/2505.12224) | Revised 2026-03-22; arXiv preprint and released artifacts |
| S14 | [Back to the Familiar Future: Failure Recovery for VLA Policies via Pre-Imagined Milestone Selection](https://arxiv.org/abs/2606.09258) | Submitted 2026-06-08; arXiv preprint |
| S15 | [Recover, Discover, Plan: Learning Skills and Concepts from Robot Failures](https://arxiv.org/abs/2606.18328) | Submitted 2026-06-16; arXiv preprint |
| S16 | [Benchmarking Vision-Language-Action Models on SO-101: Failure and Recovery Analysis](https://arxiv.org/abs/2606.08881) | Revised 2026-06-11; arXiv preprint |
| S17 | [Hypothesis-driven Model Expansion under Uncertainty for Open-World Robot Planning](https://arxiv.org/abs/2607.06501) | Submitted 2026-07-07; accepted to RSS 2026 |
| S18 | [Robots That Ask For Help: Uncertainty Alignment for Large Language Model Planners](https://proceedings.mlr.press/v229/ren23a.html) | CoRL 2023; peer-reviewed proceedings |
| S19 | [VLAConf: Calibrated Task-Success Confidence for Vision-Language-Action Models](https://arxiv.org/abs/2605.29605) | Submitted 2026-05-28; arXiv preprint |
| S20 | [Predictive inference for time series: why is split conformal effective despite temporal dependence?](https://arxiv.org/abs/2510.02471) | Submitted 2025-10-02; arXiv preprint |
| S21 | [Evaluating Gemini Robotics Policies in a Veo World Simulator](https://arxiv.org/abs/2512.10675) | Submitted 2025-12-11; Google DeepMind research report |
| S22 | [What-If World: A Causal Benchmark for General World Models in Embodied Scenarios](https://arxiv.org/abs/2605.27589) | Submitted 2026-05-26; arXiv preprint |
| S23 | [NASA-STD-7009B, Standard for Models and Simulations](https://standards.nasa.gov/standard/NASA/NASA-STD-7009) and [NASA-HDBK-7009B implementation guide](https://standards.nasa.gov/standard/nasa/nasa-hdbk-7009) | Standard dated 2024-03-05; handbook dated 2026-02-03; official NASA documents |
| S24 | [NASA-STD-8739.8B, Software Assurance and Software Safety Standard](https://standards.nasa.gov/standard/nasa/nasa-std-87398) | Dated 2022-09-08; active official NASA standard |
| S25 | [Best Practices for the Design, Development, and Operation of Robust and Reliable Space Vehicle GN&C Systems](https://ntrs.nasa.gov/api/citations/20230005922/downloads/20230005922.pdf) | NASA/TP-20230005922, 2023 |
| S26 | [Autonomy Verification and Validation Roadmap and Vision 2045](https://ntrs.nasa.gov/citations/20230003734) | NASA/TM-20230003734, 2023; NASA peer committee review |
| S27 | [Assurance of Model-Based Fault Diagnosis](https://ntrs.nasa.gov/citations/20210008090) | 2018; NASA/JPL preprint |
| S28 | [NASA ADAPT Dataset](https://data.nasa.gov/dataset/adapt-dataset) | NASA public dataset; portal record updated 2025-03-31 |
| S29 | [Adaptive IV&V Reduces Risk of Software Impacting Safety in Artemis Missions](https://ntrs.nasa.gov/citations/20230005123) | 2023; NASA-hosted conference paper |
| S30 | [Learning Actionable Manipulation Recovery via Counterfactual Failure Synthesis](https://arxiv.org/abs/2603.13528) | Submitted 2026-03-13; arXiv preprint |
| S31 | [From Reaction to Anticipation: Proactive Failure Recovery through Agentic Task Graph for Robotic Manipulation](https://roboticsconference.org/program/papers/180/) | Accepted to RSS 2026; official conference record |
| S32 | [A Human-in-the-Loop Confidence-Aware Failure Recovery Framework for Modular Robot Policies](https://arxiv.org/abs/2602.10289) | Revised 2026-03-13; arXiv preprint |
