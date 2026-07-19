# Inbar Frontier Audit Delta — 2026-07-19

- Status: `exploratory`
- Search cutoff: 2026-07-19
- Scientific effect: none
- Authority effect: none
- Evidence policy: direct research papers and retained artifacts, plus official organization records
- Relationship: supplement to `docs/FRONTIER_RESEARCH_2026.md`; it supersedes no freeze or result

## Verdict

Inbar is aimed at a real and difficult research boundary, but it is not currently a state-of-the-art
scientific result. Its evidence-provenance, default-deny authority, and independent-outcome concepts
are coherent architectural choices. No retained benchmark compares that architecture against
alternatives, so no superiority claim follows.

The public record directly occupies active diagnostic input design, Bayesian belief-space fault
planning, safety-constrained model discrimination, counterfactual robot fault diagnosis, and
autonomous-spacecraft downlink reconstruction. The residual question is narrower:

> Can one prospectively bound system combine untrusted heterogeneous evidence, a genuine
> out-of-model mechanism, risk-bounded diagnostic action, separately governed execution,
> independently settled physical recovery, and reconstruction of state changes caused by autonomy,
> while outperforming strong classical and belief-space comparators under held-out physical
> transfer?

That question remains worth testing. Novelty is unestablished; this exploratory audit is not a
prospective systematic review. Comparative performance remains `blocked` until a prospective
experiment supplies reconstructible evidence. Physical transfer remains `blocked` until the
claim-relevant plant, sensor chain, and fault realization are exercised physically.
Hardware-in-the-loop evidence must be scoped to the physical components it actually exercises. A
physical result alone would not establish novelty, and theoretical or simulator work can still be
scientifically useful when its claim is matched to its evidence.

The Amendment 006 comparison is `invalid` as retained evidence: no exact comparator implementation,
atomic outputs, or executable sweep supports it. Its numerical observation is unreconstructed, not
refuted. The susceptibility reconstruction is `inconclusive`: it is a deterministic simulator
observation whose predictor and measurement share hand-authored geometry, and its current
“unknown” mechanism does not instantiate genuinely out-of-model dynamics.

## Occupied technical boundary

### Classical active fault diagnosis

Input design for discriminating finite model or fault sets is an established field. The literature
covers constraints on amplitude and power, probabilistic discrimination, uncertainty, set
separation, and Bayesian decision criteria. Inbar therefore cannot claim first active diagnosis,
first discriminating input, or first cost-aware diagnostic action. Any Bayesian-selector claim
requires a prospective executable comparison against a strong classical rule under the same action
set, information, constraints, and budget.

### Belief-space and safety-aware fault planning

The 2024 s-FEAST work combines a fault-state belief, marginalized filtering, online tree search,
and probabilistic state constraints. It reports numerical studies and an experiment on a physical
air-bearing spacecraft-simulator testbed; it also retains code and data in Dryad. This directly
occupies Bayesian action selection for constrained active spacecraft fault estimation.

It does not establish flight use, open-world unknown-fault handling, or independently verified
settled recovery. Those distinctions preserve a possible Inbar question, but not a novelty claim.
The Dryad record also states reuse restrictions; no code should be imported before license
disposition.

Two recent preprints further tighten the comparator obligation. Ni et al. formulate finite-model
active diagnosis with reachable-set separation and finite-horizon state/input constraints, reporting
robotic evaluations. Han et al. formulate counterfactual perception diagnosis as a causal bandit and
use tree search to select informative robot actions. These are author-reported preprints, not
independent replications or field consensus.

### NASA/JPL autonomy and downlink

JPL's Operations for Autonomy program states that onboard decisions can change spacecraft state in
response to information unavailable on the ground and can hide anomalies from ordinary downlink
reconstruction. Its 2023 paper treats onboard autonomy as a transfer of some command authority and
requires operators to reconstruct what executed and why. Its 2024 downlink paper compares
reconstructed as-executed behavior with ground Monte Carlo predictions and demonstrates
in-family/out-of-family discrimination in a simulated Neptune–Triton case study.

This is direct support for studying autonomy-induced masking and reconstruction. It is not evidence
that Inbar's masking metric is correct, that its simulator transfers physically, or that recovery
has been independently verified.

## Public company evidence boundary

SpaceX's public Crew-12 mission page and NASA's contemporaneous mission record document Dragon's
approach and docking; NASA states that Dragon is designed to dock autonomously while the crews
monitor it. This establishes an operational autonomy use case, but exposes no admissible comparator
for Inbar's fault diagnosis, masking, provenance, or independent-verification claims.

Tesla's public AI page describes perception, planning, fleet evaluation, and open-loop, closed-loop,
and hardware-in-the-loop test infrastructure. It identifies relevant engineering priorities; it
does not publish a prospective active-fault experiment, atomic telemetry, or an independently
reconstructible comparison suitable for an Inbar claim.

Google DeepMind's Robotics-ER model card documents embodied reasoning, planning, success detection,
evaluation boundaries, and a prohibition on safety-critical use. Its robotics safety material
describes layered safeguards and explicitly avoids treating any layer as perfect. This occupies
multimodal embodied reasoning and provider-run safety evaluation, not causal fault diagnosis,
authority-separated recovery, or physical outcome proof.

These public records reveal only what their authors chose to publish. They cannot establish the
absence of private work, and they cannot support a claim that Inbar is ahead of, behind, or safer
than any named organization. The company and project pages are mutable public records and were not
content-frozen for this exploratory audit.

## Required next falsifier

The next claim-bearing experiment should:

1. Freeze the hypothesis, exact executable identities, action space, budgets, risk rules, and
   endpoints before outcomes are visible.
2. Use independently owned physical evidence for physical-transfer, physical-recovery, or physical
   performance claims. Scope hardware-in-the-loop evidence to the physical components exercised;
   simulator-only results may support bounded theoretical or engineering claims, not physical ones.
3. Include at least one truly misspecified fault whose dynamics are absent from every candidate
   model.
4. Compare passive/no-probe, classical separation, belief-space tree search, and any claimed Inbar
   selector under identical information and constraints.
5. Measure identification sensitivity, specificity, time, intervention cost, constraint violations,
   post-action separability, command fidelity, downlink reconstruction, settled recovery, and
   recurrence.
6. Separate proposer, executor, and outcome-verifier custody.
7. Retain every atomic cell, negative result, source byte, configuration, seed, and reconstruction
   instruction.

Any comparison whose exact comparator bytes and atomic outputs cannot be retained is `blocked`, not
`null`. A valid null is a scientifically useful outcome.

## Source registry

- [Input design for active fault diagnosis — peer-reviewed field review (2019)](https://par.nsf.gov/servlets/purl/10180014)
- [Input Design for Model Discrimination and Fault Detection via Convex Relaxation](https://arxiv.org/abs/1310.7262)
- [Online Tree-based Planning for Active Spacecraft Fault Estimation and Collision Avoidance](https://doi.org/10.1126/scirobotics.adn4722)
- [s-FEAST retained code and data](https://datadryad.org/dataset/doi%3A10.5061/dryad.xgxd254r1)
- [Safe, Real-Time Active Model Discrimination via Differentiable Reachability](https://arxiv.org/abs/2606.19590)
- [A Counterfactual Reasoning Framework for Fault Diagnosis in Robot Perception Systems](https://arxiv.org/abs/2509.18460)
- [JPL Mission Operations Planning for Increasingly Autonomous Spacecraft](https://ai.jpl.nasa.gov/public/projects/ops-for-autonomy/)
- [Operating Deep Space Autonomous Spacecraft: Ground Processes and Tools](https://ai.jpl.nasa.gov/public/documents/papers/castano-et-al-spaceops2023.pdf)
- [Operations for Autonomous Spacecraft: Downlink Analysis of Onboard Decisions and Execution Anomalies](https://www-robotics.jpl.nasa.gov/media/documents/Ops_for_Autonomous_Spacecraft_Downlink.pdf)
- [SpaceX Crew-12 mission record](https://www.spacex.com/launches/crew12)
- [NASA Crew-12 autonomous-docking record](https://www.nasa.gov/blogs/spacestation/2026/02/14/spacex-crew-12-mission-approaching-station-live-on-nasa/)
- [Tesla AI & Robotics](https://www.tesla.com/AI)
- [Gemini Robotics-ER 1.6 model card](https://deepmind.google/models/model-cards/gemini-robotics-er-1-6/)
- [Google DeepMind robotics safety framework](https://deepmind.google/models/gemini-robotics/responsibly-advancing-ai-and-robotics/)
