# Mathematical Contract

## Hybrid physical model

For continuous state `z`, discrete mode `q`, input `u`, physical parameters `theta`, and evidence
`E`, the mission models:

```text
dz/dt = f_physics_q(z, u, theta) + r_phi(z, u, E)
q+    = T(q, event)
```

The learned residual `r_phi` may improve a physical model but cannot erase its constraints or act
as an independent verifier.

## Open-world posterior

Diagnosis maintains:

```text
p(H, z, theta | E),  H in {known mechanisms} union {unknown}
```

Unknown is a real decision state. Low likelihood under every known mechanism must increase unknown
mass or trigger abstention, not force a catalog label.

## Safe active test selection

For an approved test `a`, outcome `Y_a`, direct cost `C`, time `T`, bounded risk `R`, and positive
denominator floor `epsilon`, every denominator term is expressed in one declared cost unit:

```text
a* = argmax over a in A_safe:
     I(H; Y_a | E) / max(C(a) + lambda*T(a) + mu*R(a), epsilon)
```

Information gain is the reduction from current hypothesis entropy to expected posterior entropy.
`lambda` has cost-units-per-second units and `mu` has cost-units-per-risk-unit units. Two executable
planner types currently diverge. `fieldtrue.domain.PlannerWeights`, used by the general planning
path, defaults `time_weight` to `1.0`, `risk_weight` to `1.0`, and `denominator_floor` to `1e-9`.
`fieldtrue.active_selection.PlannerWeights`, used by the graded-laboratory selector and exported as
`selection_planner_weights.schema.json`, defaults `time_weight` to `1.000000`, `risk_weight` to
`10.000000`, and `denominator_floor` to `0.000001` (`1e-6`). Neither default is a scientific choice.
A claim-bearing run must name the planner type and freeze the cost unit, normalization, risk scale,
weights, and denominator floor before outcome inspection. No implementation may be described as
matching one frozen numerical contract until both divergences are prospectively resolved. Actions
outside the frozen safety envelope are ineligible regardless of score.

## Selective uncertainty

Report proper scores and risk-coverage curves. Calibration must be measured separately by hardware,
vehicle, mission, environment, fault family, and operating regime. ECE alone is insufficient.
Time-series conformal guarantees are not assumed under dependence; coverage is empirical unless a
valid dependent-data method is proved for the frozen setting.

## Recovery verification

A recovery passes only if all three gates pass under an independent outcome authority:

1. the action is admissible;
2. the action targets the diagnosed mechanism;
3. the physical state reaches and remains inside a pre-registered settled-success set.

A learned score, verbal critique, or simulator outside its accredited decision-use domain cannot
substitute for settled execution.

## Value

The aggregate formula in `PREREGISTRATION.md` remains the frozen master contract. The
exposure-normalized formulation below is a prospective refinement, not an amendment. It becomes
claim-bearing only after a value-stage preregistration or explicit prospective amendment freezes it
before customer or outcome access.

Fix a prospective evaluation population `P`, comparator workflow `B`, independent deployment units,
exposure unit, target horizon `tau`, positive finite target exposure `E_tau`, material groups, and
integration-cost horizon before observing outcomes. For each incident `i`, define every delta as
`B minus Inbar`, so positive time, downtime, test-count, and loss-risk deltas are benefits. Convert
them to money using prospectively approved, nonoverlapping ledger categories and rates:

```text
benefit_i = delta_engineer_hours_i * engineer_rate_i
          + delta_downtime_hours_i * downtime_rate_i
          + delta_redundant_tests_i * test_rate_i
          + delta_failure_probability_i * approved_loss_i

variable_cost_i = diagnostic_cost_i
                + actuation_cost_i
                + human_review_cost_i
                + compute_cost_i
                + storage_cost_i
                + monetized_delay_i
                + realized_intervention_risk_cost_i
                + false_action_cost_i

v_i = benefit_i - variable_cost_i
V_tau_observed = sum over observed incidents i in tau of v_i - integration_cost_tau

For deployment unit j:
w_j = sum over incidents i assigned to j of v_i
e_j = frozen exposure observed for j

For each material group g under a frozen membership and exposure-allocation rule:
w_jg = sum over incidents i assigned to j with g in G_i of v_i
e_jg = frozen exposure observed for j and allocated to g

rho = E_P[w_j] / E_P[e_j]
rho_g = E_P[w_jg] / E_P[e_jg]
V_tau_target = E_tau * rho - integration_cost_tau
```

`G_i` is the prospectively frozen set of material groups containing incident `i`; groups may overlap
only when the multiplicity family and exposure-allocation rule explicitly permit it. `e_j` and every
`e_jg` are nonnegative. The estimands are admissible only when `0 < E_P[e_j] < infinity` and
`E_P[|w_j|] < infinity`, and when every claim-bearing group satisfies
`0 < E_P[e_jg] < infinity` and `E_P[|w_jg|] < infinity`. A zero-exposure group has no estimand and
cannot be silently dropped or reported as zero.

`V_tau_observed` is an audited descriptive total for the frozen observed horizon. `rho` is the
target population's expected variable net value per exposure unit, and `V_tau_target` is its
horizon-scaled commercial estimand. Benefits and variable costs form one prospectively frozen,
mutually exclusive ledger partition. An Inbar review, test, or delay cost already represented
inside a `B minus Inbar` engineer-time, test-count, or downtime delta cannot also be subtracted as
variable cost; if recorded as variable cost, it is excluded from that delta. The same allocation
rule prevents overlap among engineer time, downtime, test use, and loss avoidance.

The confidence procedure must resample or randomize independent deployment units, retaining every
incident from a selected unit and preserving repeated-incident dependence. It must estimate the
joint vector containing `rho` and every preregistered `rho_g`, then produce simultaneous one-sided
95 percent lower bounds under a frozen familywise procedure such as max-t bootstrap or a declared
multiplicity correction. The target population, assignment or identification design, exposure unit,
minimum independent-unit count, estimator, missing-data rule, rate sources, group membership and
exposure-allocation rules, group set, multiplicity family, and sensitivity analysis must be
preregistered. The lower bound for `V_tau_target` follows from the bound for `rho` only when every
monetary rate, approved loss, target exposure, and integration cost is a genuinely fixed audited
input. Any estimated monetary or exposure input must enter the joint resampling or uncertainty
procedure, or be governed by a prospectively frozen conservative sensitivity bound. A positive lower
bound computed while holding an uncertain loss rate or cost fixed is not admissible. The current
repository does not implement this estimator.

`delta_failure_probability_i` is admissible only when it comes from prospectively identified causal
evidence with independently settled outcomes and declared uncertainty. A model score, simulator
estimate outside an accredited decision-use domain, or retrospective hypothetical loss reduction is
excluded rather than assigned a benefit. Unknown benefits and costs remain unknown rather than zero.

Positive `V_tau_observed`, a positive simultaneous lower bound for `V_tau_target`, and positive
simultaneous lower bounds for every preregistered material-group `rho_g` are necessary statistical
conditions for a commercial value claim. They are not sufficient: pricing or scale claims also
require independently verified customer or partner evidence under the frozen master protocol. A
point estimate, market-size estimate, or hypothetical loss avoidance does not authorize a claim.
