# Inbar Hardware-in-the-Loop Falsifier Packet — 2026-07-19

- Status: `proposed`
- Scientific effect: none
- Authority effect: none
- Execution authority: none
- Relationship: paper design derived from `INBAR_FRONTIER_AUDIT_2026-07-19.md`

This packet does not authorize a run, hardware access, fault injection, credentials, spending,
external writes, robot or vehicle operation, or flight activity. The Iteration 001 acquisition
contract remains `blocked`. Every powered or physical step requires a prospectively accepted
experiment packet, domain-owner boundaries, and separately held execution authority.

## Decision target

After the evidence-binding and acquisition prerequisites are satisfied, the next high-information
test should be an independently operated, low-energy hardware-in-the-loop falsifier rather than
another simulator expansion.

The design contains two different questions that must not be collapsed into one score:

1. Does a frozen offline-geometry predictor identify when closed-loop compensation destroys
   diagnostic evidence on held-out hardware and held-out fault mechanisms better than trivial and
   non-geometric predictors?
2. Does an Inbar-selected diagnostic action improve held-out fault identification over passive,
   classical-separation, and belief-space policies under identical information, action, risk, and
   intervention budgets?

These are proposed questions, not hypothesis results. Passing both supports two conjunctive
component results; it does not by itself show that geometry caused an action-policy advantage. That
attribution additionally requires a bound predictor-to-selector interface and prospectively frozen
geometry ablations. Success on one test cannot substitute for failure, invalidity, or missing
evidence on the other. The design should be rejected or amended before execution if the domain owner
cannot define a bounded apparatus in which every admissible action stays inside an independently
enforced envelope.

## Prerequisites

No outcome-bearing run may begin until all of the following are retained:

1. A superseding freeze binds the exact repository commit, executable bytes, lockfile, configuration,
   ontology, comparator implementations, reconstruction code, and analysis code.
2. The domain owner defines apparatus limits, emergency stop custody, maximum energy, command
   magnitude, duration, thermal and mechanical limits, and termination criteria.
3. Proposer, execution controller, apparatus owner, data custodian, and outcome verifier are named;
   no actor verifies its own claim or approves its own consequential action.
4. Hardware identity, firmware, calibration, clock synchronization, sensor units, uncertainty, and
   missing-data rules are frozen.
5. Sample size or sequential stopping is justified prospectively against named minimum effects and
   error rates.
6. Known-bad fixtures demonstrate every scientific, binding, independence, boundary, and emergency
   gate.
7. An independent comparator custodian approves implementation fidelity, tuning data, tuning budget,
   and reference-result reproduction before test labels or held-out outcomes are available.
8. The Iteration 001 acquisition blocker is resolved by the authority that owns it.

## Prediction comparators

The evidence-destruction predictor is evaluated as a held-out binary prediction made before the
measured post-action trace is visible. Its comparators receive only the frozen covariates assigned to
them:

1. An always-negative masking classifier.
2. A frozen non-geometric baseline using only permitted operating-point covariates.
3. The prospectively frozen offline-geometry predictor.

The non-geometric baseline must be specified without test labels and must not be deliberately
crippled. All three emit a prediction or frozen abstention before outcome reveal.

## Action-selection arms

Every selection policy receives the same prior information, candidate actions, action constraints,
observation history, computation budget, and stopping rules:

1. Passive or no-probe control.
2. A named classical discrimination method with exact implementation bytes.
3. A named belief-space or tree-search method with exact implementation bytes.
4. The prospectively frozen Inbar selector.
5. The same Inbar selector with the geometry channel removed or frozen to a prospectively defined
   neutral value.
6. The same Inbar selector with a prospectively generated, blinded permutation of valid geometry
   inputs.
7. A wrong-but-admissible placebo selector that satisfies the interface while intentionally ignoring
   diagnostic value.

Any arm that cannot emit a complete atomic decision record is ineligible. A prose reconstruction is
not a comparator implementation. The exact predictor output consumed by the Inbar selector, its
schema, timing, abstention behavior, and transformation into action scores must be content-bound.

## Held-out mechanisms

The test set must contain:

- in-family mechanisms withheld from fitting and tuning;
- at least one genuinely out-of-model mechanism whose transition or observation dynamics are absent
  from every mechanism-specific candidate model and selector ontology;
- non-fault variation capable of producing plausible but irrelevant deviations; and
- a blinded mapping from physical mechanism to analysis label held outside proposer custody.

Renaming a mechanism “unknown” while evaluating it with the same hand-authored simulator geometry
does not satisfy this requirement. A generic `unknown` or abstention output is permitted and
required; it represents rejection of all named mechanisms, not prior knowledge of the held-out
mechanism's identity, parameters, or dynamics.

## Hardware-in-the-loop and physical boundary

The freeze must enumerate which plant, controller, actuator, sensor, clock, disturbance, fault, and
interlock components are physical and which are simulated or emulated. It must bind every emulator,
fault-injection, interface, and timing byte and state the decision-use scope of each measurement.

Real controller hardware connected to a simulated plant is hardware-in-the-loop evidence, but it is
not physical plant or fault-transfer evidence. A simulated out-of-model mechanism establishes only
transfer to that independently built emulator. Any physical-transfer claim requires the relevant
plant, sensor chain, and fault realization to be physical and within the domain owner's approved
scope.

The prediction implementation and its authors may not supply the outcome generator, reference assay,
fault parameters, or generative geometry. Shared code, fitted parameters, calibration cells, or
hand-authored separability rules between prediction and outcome generation make the masking test
`INVALID_CIRCULAR`.

## Independent masking reference standard

The evidence-destruction label must not be computed from the same command-window geometry that makes
the prediction. Before held-out outcomes are visible, a separate outcome authority must freeze:

- the sealed physical or emulator mechanism truth and custody procedure;
- an independent pre-action and post-action persistence or invariance measurement for the underlying
  mechanism, separate from the diagnostic sensor path;
- a reference diagnostic assay, trained and calibrated only on separately retained calibration
  evidence, with exact sensor inputs, windows, units, thresholds, uncertainty treatment, and
  abstention rule;
- the matched pre-action and post-action acquisition procedure;
- blinded adjudication that cannot see the predictor output or policy identity; and
- a sensitivity analysis using at least one independently specified alternative assay when the
  primary reference is model-dependent.

A scheduled cell is a masking positive only when the reference assay satisfies its frozen
detectability criterion for the sealed mechanism before the action, fails that criterion after the
action, and the independent persistence measurement confirms that the mechanism remained present.
It is a masking negative when the criterion is satisfied both before and after. A mechanism that was
removed or physically recovered receives a separate `recovered_or_removed` disposition and cannot
be counted as masking. A cell that was not detectable before the action is `not_preobservable`, not
a negative and not silently discarded; its treatment and denominator are frozen prospectively.
Indeterminate persistence or reference outcomes remain `blocked` or `inconclusive`.

The command-window calculation is a predictor or explanatory analysis. It is not the label
authority.

## Comparator fidelity and trial independence

Exact bytes and equal budgets are necessary but insufficient. Before the held-out run, the
independent comparator custodian must:

- select a recognized implementation or document every deviation;
- reproduce a named reference result within frozen tolerance;
- freeze training and tuning data, parameter ranges, search effort, stopping rules, hardware, and
  wall-clock and computation budgets; and
- reject a comparator that is deliberately weak, misconfigured, or denied information available to
  the claimed method.

Randomization and analysis must block or counterbalance physical unit, mechanism, severity, order,
and carryover. Reset, washout, recalibration, retry, and apparatus-failure rules are frozen before
outcomes. Repeated cells from one apparatus, fault realization, or reset cycle are not independent
replicates; uncertainty and sample-size calculations must use the independently randomized unit or a
predeclared cluster-aware model.

## Atomic evidence cell

Each attempted cell must retain, including failed and terminated cells:

- experiment, task, apparatus, calibration, software, protocol, predictor, and policy identities;
- mechanism custody label, reveal state, severity definition, trial, seed, and randomization record;
- pre-action observation bytes, candidate action set, rejected actions, chosen action, scores, and
  decision latency;
- issued, accepted, and measured command traces with synchronized clocks;
- pre-action and post-action separability values plus all inputs needed to reconstruct them;
- raw sensor references, missingness, saturation, faults in the test apparatus, and timing gaps;
- every constraint evaluation, veto, stop, retry, timeout, override, and operator intervention;
- predicted fault or masking label, confidence or score, decision threshold, and abstention;
- typed outcome kind (`physical` or `emulated`), independently measured outcome, recurrence window,
  and verifier identity; an emulated outcome may never be represented as physical; and
- canonical reconstruction result with content digests for every source byte.

No missing value may be converted to zero. A missing outcome is `blocked` or `inconclusive` according
to the frozen adjudication rule, never implicit success.

## Endpoints and comparators

The prediction question should require simultaneous satisfaction of prospectively chosen
conditions, not raw accuracy alone:

1. balanced-accuracy improvement over the always-negative control;
2. balanced-accuracy improvement over the frozen non-geometric baseline; and
3. a domain-chosen sensitivity floor for evidence-destruction events.

The action-selection question should separately require:

1. improvement over the named classical comparator on a prospectively defined in-family
   mechanism-identification endpoint that counts abstentions, timeouts, and unresolved trials;
2. improvement over the named belief-space comparator on that same in-family endpoint;
3. improvement over both named comparators on a separate out-of-model detection or rejection
   endpoint, where a generic `unknown` can be correct but a fabricated mechanism identity cannot;
4. improvement over the geometry-removed and geometry-permuted Inbar ablations if an integrated
   geometry-to-action attribution is claimed;
5. a frozen ceiling on diagnostic time and intervention cost; and
6. no breach of the independently enforced apparatus envelope. Every `STOP_ENVELOPE` is a primary
   envelope failure for the policy to which the cell was assigned and remains in its
   intention-to-test denominator.

An integrated superiority claim requires every co-primary condition for both questions. Prediction
and policy cells, estimands, and multiplicity families remain separate; they may not be pooled into
one accuracy figure.

Report the full prediction confusion matrix and exact denominators for every predictor and stratum.
For every selection policy report the complete identification/abstention/timeout disposition and
exact denominators. Secondary endpoints may include sensitivity, specificity, positive and negative
predictive value, calibration, time to discrimination, intervention cost, command fidelity,
constraint violations, post-action separability, downlink reconstruction, settled recovery, and
recurrence. Settled recovery and recurrence require independent physical observation and cannot be
inferred from command issuance or simulator state.

The freeze must define minimum effects, uncertainty intervals or tests, familywise multiplicity
handling across all co-primary conditions, excluded-cell rules, abstention treatment, missing-data
handling, equivalence or non-inferiority margins if used, and whether each estimand is
intention-to-test or per-protocol.

An envelope stop cannot be excluded as an ordinary failed trial or censored observation. A
predeclared apparatus-wide malfunction may invalidate an entire randomized block only under a rule
applied without access to policy identity or outcome; it may not selectively erase one arm's stop.

## Required command-window mapping

Any tolerance such as “within one disturbance-width” must be executable before outcomes are visible.
The freeze must map each mechanism, severity, and apparatus calibration to an exact closed interval
or distributional rule over measured commands. It must define boundary inclusion, unit conversion,
sensor uncertainty, clipping, and how a predicted window is joined to a measured trace.

An analyst must be able to decide every cell using only the frozen mapping and atomic record. A
retrospective plausible width is not a confirmatory falsifier.

## Falsification and invalidation states

The prospective adjudicator should emit one of the repository's ordinary result states plus a
specific reason. At minimum, the packet must implement these reason codes:

- `VACUOUS`: a prediction score passes while the predictor emits only the majority class or the
  stratum contains no positive events.
- `CONTRADICTED`: complete valid evidence places the frozen effect or sensitivity interval wholly
  on the adverse side of the prospectively defined target or falsification margin.
- `INCONCLUSIVE_ESTIMATE`: complete valid evidence does not establish the target, but its interval
  overlaps both the target and the null or adverse region. Failure to demonstrate superiority is not
  by itself contradiction.
- `INVALID_CIRCULAR`: the predictor consumes measured outcomes, fitted test labels, or test-only
  information.
- `INVALID_UNKNOWN`: the held-out mechanism's identity, parameters, or dynamics are represented in
  the mechanism-specific candidate models, ontology, tuning data, or hand-authored evaluation
  geometry. A generic `unknown` rejection state alone does not trigger this code.
- `INVALID_BINDING`: any committed source, configuration, comparator, or analysis digest differs
  from the prospectively approved binding.
- `INVALID_INDEPENDENCE`: proposer, executor, label custodian, or outcome verifier separation is
  breached.
- `INVALID_BOUNDARY`: action-set, budget, randomization, measurement, exclusion, or stopping rules
  differ across arms or from the freeze.
- `STOP_ENVELOPE`: the apparatus owner or independent interlock terminates the run at a frozen
  boundary.
- `BLOCKED_EVIDENCE`: an atomic source, calibration, clock relation, typed physical or emulated
  outcome, or reconstruction input is absent or unverifiable.

`STOP_ENVELOPE`, `BLOCKED_EVIDENCE`, and invalid states do not imply a scientific null. Every
`STOP_ENVELOPE` remains a primary assigned-policy envelope failure even when the scientific
comparison is otherwise inconclusive. A valid null or contradiction must remain visible and must not
be rerun into disappearance.

## Mutation and known-bad tests

Before the first claim-bearing trial, automated or independently witnessed fixtures must show that
the pipeline rejects:

- one changed source or comparator byte;
- one missing, duplicated, or relabeled trial;
- one predictor that reads the measured command or outcome;
- one predictor and reference assay that share outcome-generating code, parameters, or calibration
  cells;
- one “unknown” mechanism secretly inserted into the candidate set;
- one exact held-out mechanism hidden behind a generic `unknown` label;
- one removed or recovered mechanism misreported as a masking event;
- one disconnected geometry predictor whose selector ignores its output;
- one geometry-permutation ablation that receives the unpermuted values;
- one comparator that cannot reproduce its frozen reference result;
- one arm given an extra action, observation, or compute budget;
- one repeated apparatus cycle miscounted as independent replication;
- one proposer-supplied outcome verdict;
- one absent clock or calibration record;
- one majority-only predictor that crosses a raw-accuracy threshold;
- one post hoc command-window edit; and
- one apparatus-envelope stop misreported as success, null, or ordinary missingness.

## Bounded mission order

1. Validate and commit the evidence correction and retrospective replay.
2. Resolve the acquisition-contract blocker without weakening it.
3. Obtain independent domain-owner and execution-authority acceptance of a new prospective packet.
4. Validate the apparatus digitally and with non-powered or otherwise domain-approved fixtures.
5. Demonstrate all known-bad gates and emergency-stop custody.
6. If separately authorized, run only the minimum powered, low-energy HIL cells needed by the frozen
   design.
7. Transfer evidence to an independent verifier for byte-level reconstruction and adjudication.

No live robot, road vehicle, spacecraft, destructive fault, or flight test belongs in this packet.
Any such expansion requires a different risk review and explicit authority.
