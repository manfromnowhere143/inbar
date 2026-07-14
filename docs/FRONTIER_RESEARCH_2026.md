# Frontier Research Dossier 2026

- Research cutoff: 2026-07-14
- Evidence policy: primary research papers, author-maintained project records, and official NASA
  or model-provider documents only
- Mission descriptor: Active Causal Mission Assurance

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

This question is worth pursuing because each link is useful and individually occupied, while none
of the reviewed public sources establishes the joint evidence contract. The mission must not claim
that the combination is novel until a systematic review and experiments support that statement.
Its initial contribution is a falsifiable architecture and evaluation protocol, not a performance
claim.

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

What-If World tests paired physical interventions and reports that visually plausible videos can
still fail the required causal divergence [S22]. NASA-STD-7009B separately requires acceptance
criteria and credibility assessment for models and simulations used in decisions [S23]. The
mission may use a simulator inside its declared, validated decision-use domain; it cannot allow a
world model that proposes a recovery to be the sole verifier of that recovery.

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
| Learned recovery | RoboFAC, B2FF, ReSYNC [S13-S15] | Failure correction, recovery guidance, learning from recovery | Does a separately executed action reach a pre-registered settled physical state? |
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

For approved diagnostic action `a`, outcome `Y_a`, direct cost `C`, delay `T`, and bounded risk `R`:

```text
a* = argmax over a in A_safe:
     I(H; Y_a | E) / (C(a) + lambda*T(a) + mu*R(a))
```

The denominator is not a cosmetic ranking term. Actions outside the frozen safety envelope are
ineligible. The action selected for execution must be the exact approved action, not an equivalent
natural-language paraphrase or a substituted test.

A recovery is accepted only when a separately identified outcome authority verifies all of the
following:

1. The action was admissible under the frozen envelope.
2. The action targeted the diagnosed mechanism rather than merely correlating with success.
3. The measured physical state entered and remained in the pre-registered settled-success set.

The compiled monitor must declare its validity domain, sensor and clock assumptions, calibration
set, grouped holdouts, latency and resource bounds, false-action cost, and abstention behavior.

## Required identity and shortcut controls

The following controls run before a multimodal benefit claim:

1. Deterministic engineering baseline using only permitted physical rules and telemetry.
2. Task-index or case-identity lookup with no semantic language encoder.
3. No-language policy and shuffled-language policy.
4. Telemetry-only, vision-only, log-only, and configuration-only ablations.
5. Timestamp, filename, row-order, site, vehicle, and operator-identity probes.
6. Nearest-training-source and duplicate-trajectory checks.
7. Frozen-pretraining versus task-specific adaptation comparison.
8. Correct versus substituted action normalization and controller metadata.
9. Exact executable-policy identity binding, including model, transforms, controller, software,
   configuration, and embodiment.
10. Group-held-out evaluation by connected leakage component, hardware, mission, and fault family.

If a cheap identity-only control matches or exceeds the full system within the pre-registered
uncertainty interval, the multimodal mechanism claim is null even when aggregate accuracy is high.

## Falsification program

Each campaign freezes numerical thresholds, analysis code, group definitions, and stop rules
before outcome inspection. The following relationships define the mission-level falsifiers.

### F0: evidence construct

Falsify or block the campaign if fewer than 30 incidents have independently established causes,
at least two plausible pre-outcome mechanisms, at least one independently reviewed safe
discriminating test, two hardware or vehicle identities, two fault families, and at least two
operational evidence channels. Source, parser, truth separation, and exact-coverage failures make
the run invalid rather than negative.

### F1: multimodal necessity

Let `M_full` be the frozen primary metric for the full model and `M_shortcut` the best eligible
identity-only or modality-removal baseline. The multimodal claim fails when the pre-registered 95%
lower confidence bound of `M_full - M_shortcut` is not positive. Cluster resampling must follow the
independent incident or hardware group, not individual frames.

### F2: active causal value

Compare the selected test with passive observation, a fixed engineering test, a random eligible
test, and an information-only planner that omits cost and risk. The active-test claim fails if the
95% lower bound of incremental posterior entropy reduction per realized cost is not positive, or
if outcome-conditioned likelihood ratios do not move the competing mechanisms in the
pre-registered directions.

### F3: safety-envelope integrity

Any executed action outside the signed envelope invalidates the campaign. The method fails its
safety objective if the upper confidence bound on hazardous or inadmissible actions exceeds the
pre-registered cap, regardless of diagnostic accuracy.

### F4: open-world behavior

Hold out entire mechanism families. The open-world claim fails if the system forces held-out cases
into known labels above the permitted false-known rate, if unknown recall at the frozen
false-unknown rate misses its threshold, or if abstention does not reduce selective risk as
coverage decreases.

### F5: independent recovery

Compare recovery with the best fixed or model-based contingency baseline under matched fault and
risk conditions. The recovery claim fails if the lower bound on settled physical success does not
improve, if the settled-state dwell requirement is missed, or if the proposer and sole verifier
share the same learned model, sensor dependency, or mutable outcome path.

### F6: transfer and calibration

Freeze group holdouts for hardware, mission, fault family, and operating regime. A transferable
monitor claim fails if any required group's empirical coverage lower bound falls below the frozen
target, if worst-group selective risk exceeds its cap, or if a calibration repair uses held-out
outcomes without being declared as adaptation.

### F7: simulation decision use

Simulator evidence is rejected when the simulator lacks an approved decision-use statement,
acceptance criteria, validation evidence, and an uncertainty account for the tested regime. A
generative world's visual plausibility cannot settle a physical recovery claim.

### F8: reproducibility and evidence integrity

The result is invalid if an independent verifier cannot reconstruct the same verdict from frozen
source bytes, code, configuration, executable identity, approvals, receipts, and artifacts, or if
truth-plane fields enter any model-visible input.

### F9: economic value

Let the realized net value for deployment group `g` be:

```text
V_g = engineer-hours avoided
    + downtime avoided
    + redundant tests avoided
    + expected-loss reduction
    - integration cost
    - compute and storage cost
    - diagnostic-test and actuation cost
    - human review cost
    - false-action cost
```

Every term is monetized using customer-approved rates recorded before analysis. The product-value
claim fails when the group-aware 95% lower confidence bound of net value is not positive. A point
estimate, total addressable market estimate, or hypothetical loss avoidance is not evidence of
realized value.

## Experimental campaign sequence

| Iteration | Decision | Minimum output | Stop condition |
| --- | --- | --- | --- |
| 000 | Is a public corpus fit for the construct? | Signed source lock, leakage-safe ingestion, exact coverage, gate-by-gate readiness verdict | Stop after `PASS`, `BLOCKED_EVIDENCE`, or `INVALID`; no model run |
| 001 | Is the incident set genuinely ambiguous? | Deterministic and identity-only baseline table | Stop with `KILL_CONSTRUCT` if a cheap baseline resolves the cases |
| 002 | Does multimodal evidence add causal information? | Frozen modality and identity ablations with grouped intervals | Stop the multimodal claim if F1 fires |
| 003 | Does active selection beat passive and fixed tests? | Safe-test replay or accredited simulation with realized cost and risk | Stop active testing if F2 or F3 fires |
| 004 | Does recovery survive separate execution and verification? | Settled-state physical or accredited testbed outcomes | Stop recovery claim if F5 fires |
| 005 | Does a compiled monitor transfer and calibrate? | Hardware, mission, regime, and fault-family holdouts | Restrict validity domain or stop transfer claim if F6 fires |
| 006 | Does the system create measurable customer value? | Prospective shadow deployment with audited cost records | Stop commercial claim if F9 fires |

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
5. One testbed does not establish transfer across two hardware or vehicle identities.
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

The first product is an offline assurance workbench for ambiguous physical-system incidents. It
ingests telemetry, images or video, logs, commands, procedures, and configuration graphs while
keeping outcome truth separate. It produces competing mechanism records, approved diagnostic-test
packages, execution receipts, independent recovery verdicts, validity-domain statements, and an
assurance case that links every permitted claim to exact evidence.

It is not an autonomous flight controller, a replacement for an organization's safety authority,
or a certification product.

### Expansion path

1. Offline incident replay and evidence qualification.
2. Read-only shadow recommendations beside existing engineering workflows.
3. Approved simulator and hardware-in-the-loop diagnostic campaigns.
4. Governed test-stand execution with independent outcome instrumentation.
5. Fleet-level mechanism and monitor learning across explicitly separated hardware groups.
6. Resource-bounded onboard monitors, only inside a validated and approved authority envelope.

The contracts remain constant while execution authority changes. This provides a credible path
from a narrow evidence product to a broader mission-assurance system without treating early replay
results as flight authority.

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

1. Implements a provider-neutral evidence and authority contract.
2. Pre-registers shortcut, leakage, safety, transfer, and value falsifiers.
3. Separates proposer, executor, and outcome-verifier roles.
4. Reproduces released results from content-addressed artifacts.

It may not say that it is state of the art, safer than a named organization, certified,
flight-ready, universally transferable, causally correct, economically valuable, or independently
verified merely because the repository contains signatures or an external model critique.

## Remaining uncertainty

1. The search cannot observe private work at SpaceX, Google DeepMind, OpenAI, Anthropic, NASA
   contractors, or other frontier teams. Absence from the public record is not evidence of absence.
2. Several 2026 sources are recent arXiv preprints. Their methods and results may change after
   review, revision, or independent replication.
3. No public corpus has yet been shown here to satisfy the full ambiguity, safe-test, independent
   cause, recovery, and transfer contract.
4. The correct physical domains, risk caps, and settled-success definitions require domain-owner
   approval. A generic repository cannot infer them safely.
5. NASA standards and handbooks inform architecture and evidence discipline but do not make this
   work NASA-compliant or certified. Applicability and tailoring are program decisions.
6. Cryptographic receipts prove integrity and key possession under their stated trust model; they
   do not prove that a sensor was correct, an intervention was safe, or a scientific claim is true.
7. The economic model has no customer data yet. No valuation or revenue claim is supportable.

## Source registry

All URLs were accessed on 2026-07-14.

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
