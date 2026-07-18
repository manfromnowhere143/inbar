# Amendment 006: Graded Laboratory and Cost-Aware Active Test Selection

Status: IMMUTABLE PROPOSAL

Drafted: 2026-07-18

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none without a separate owner-approval receipt

## Decision

**This is a ratification request, not a prospective authorization.** The implementation it describes
already exists in the working tree, uncommitted, and was written before this document. Amendments
002 through 005 authorized implementation before it occurred; this one does not, and that difference
is material to what approving it means. The owner is being asked to bless work already performed, on
the strength of the evidence that work produced.

Amendment 005 authorized a diagnosis-method port, a reference likelihood baseline, and a paired
passive/active campaign. It did not examine whether its laboratory can produce a negative result
against the method it evaluates. It cannot, for the reasons set out under Trigger. This proposal
seeks to ratify a rebuilt laboratory in which a method can fail, and an implementation of the
action-selection rule the mission's mathematics has specified since preregistration and never
realized.

It covers implementation only of: a severity-graded reference laboratory with structural model
mismatch and a latent nuisance offset; a mechanism whose observability depends on the shape of the
commanded action; a separability index reported as a property of the laboratory rather than of any
method; an action catalog carrying declared direct cost, time, and risk; the cost-aware expected
information gain selector `a* = argmax I(H; Y_a | E) / max(C(a) + lambda*T(a) + mu*R(a), epsilon)`
restricted to a safety-approved action set; and classical set-based comparison baselines. It covers
no campaign run. Every campaign additionally requires the causal-laboratory compute lease Amendment
004 defined. `iter001-acquisition-contract` remains the sole registered blocker throughout.

The scope of this amendment is exactly the following artifacts, bound by content:

| Artifact | SHA-256 |
| --- | --- |
| `src/fieldtrue/graded_laboratory.py` | `647472e94cac54dd4a295b3bb2452dc90dbbea42587ba5ac093cd1610cbddfb9` |
| `src/fieldtrue/active_selection.py` | `a58b445f3ef6c532c2500c1f3ac2828fa406e914b126913593212a8a2f00c044` |
| `tests/unit/test_graded_laboratory.py` | 20 adversarial controls, all passing |
| `tests/unit/test_active_selection.py` | 28 adversarial controls, all passing |

If either file changes, this amendment does not cover the changed file and a superseding proposal is
required. If the owner declines this amendment, both files are to be deleted from the working tree
and no artifact derived from them may be cited; the Amendment 005 laboratory remains the sole
laboratory and its recorded result stands unaltered.

## The frozen boundary that governs everything here

Every boundary Amendment 005 froze remains in force without modification. A causal-laboratory
result establishes how a method behaves inside a simulator against injected truth and nothing about
the physical world. A simulator branch never counts as a physical incident.

This amendment adds one further prohibition, and it is the most important sentence in the document:

**That an active test outperforms passive observation on faults unidentifiable at rest is a known
theorem and must never be reported as a discovery of this mission.** It is the founding statement
of active fault diagnosis — Campbell and Nikoukhah, *Auxiliary Signal Design for Failure Detection*
(Princeton University Press, 2004), via proper auxiliary signals and the separability index — and
the corresponding result in interventional causal discovery is established by Eberhardt, Glymour and
Scheines (2005) and Hauser and Buehlmann (JMLR, 2012). It was re-demonstrated as recently as Kong,
McMahon and Lahijanian (2025). A campaign that confirms it has performed a correctness check on its
own implementation, not an experiment about the world, and must say so in those words.

The question this laboratory was built to address is narrower: **what is the cheapest action set that
resolves the hypotheses still live**, under declared cost, time, and risk, when the fault magnitude
is unknown. That question is open in general. It is **not** open in this laboratory: the comparison
recorded under Prior exposure found that the classical set-based rule already answers it here, at
equal accuracy and marginally lower cost than the information-gain selector, at every cost weight
tested. This amendment therefore does not propose that the selection question is unresolved; it
proposes a laboratory capable of resolving it, and records that the first resolution went against
the selector.

A result here is a statement about selection efficiency in a simulator. It is not a diagnosis,
recovery, safety, transfer, product, economic-value, or state-of-the-art claim, and the reference
baselines are baselines rather than state-of-the-art systems.

## Trigger

The Amendment 005 laboratory cannot measure a method, for three independent reasons, each verified
by execution rather than inspection:

1. **The mechanisms are separated by two to three orders of magnitude more than the disturbance.**
   The `sensor_bias` signature exceeds nominal by roughly 5,700 units at the final step against a
   disturbance bounded at plus or minus three. Diagnosis is arithmetic.

2. **The forward model is the simulator with the disturbance removed.** A method reasoning with an
   exact model of the generating process performs table lookup with a tolerance, not inference. The
   residual of the true mechanism is bounded by the disturbance; the residual of every false
   mechanism is enormous.

3. **The discriminating action is a frozen constant**, `TARGETED_TEST_ACTION = (100,)*8`. No
   selection occurs anywhere in the campaign. The mathematics contract's argmax is not implemented.

The consequence is that the reported Amendment 005 effect — a paired active-minus-passive accuracy
of 0.25, carried entirely by `actuator_loss` going 0/6 to 6/6 — is an algebraic identity. A
parameter that multiplies the commanded input is unidentifiable when that input is zero. The
campaign does not discover this; `_mechanism_identifiable` already proves it analytically from the
noise-free models. An instrument that cannot produce a negative result cannot produce a measurement.

The rebuilt laboratory demonstrates the point against the existing probe. Under the graded
laboratory at full severity, the Amendment 005 constant probe scores **0.00** on
`actuator_deadband`: a command above the deadband threshold passes unattenuated, so the largest
available probe is structurally blind to that mechanism. A fixed policy is not merely suboptimal
here; it misses a fault class.

## What changes, and what each change closes

1. **Severity grading.** Every mechanism takes a severity in [0, 100], scaling linearly to its
   Amendment 005 magnitude at 100. Diagnosability becomes continuous with a measurable failure
   region instead of a property holding by construction.

2. **Structural mismatch.** The plant delivers part of each command one step late; the forward model
   applies every command instantly. A method is wrong in form, not merely in noise, which is the
   ordinary condition of physical diagnosis. Because the mismatch is unmodeled *dynamics* rather
   than a perturbed parameter, no mechanism hypothesis in the catalog can absorb it.

   This item was originally implemented as a quadratic curvature term and is recorded here as a
   correction rather than silently revised. An adversarial control demonstrated the quadratic was
   **inert**: at the nominal operating point of x ~ 100 the term `(6 * x * x) // 1_000_000` floors to
   zero under integer division, so the laboratory claimed a structural mismatch it did not possess,
   and the nonzero residuals observed for true mechanisms came entirely from the disturbance and the
   nuisance offset. Scaling the quadratic was rejected because a coefficient large enough to matter
   near x ~ 100 diverges once the state reaches the thousands, which both the gain-drift and
   sensor-bias mechanisms do within the horizon. Every quantitative result in this document was
   recomputed after the correction; none was carried over.

3. **A latent nuisance offset** perturbs the initial state, unobserved and unmodeled, propagating
   through the recurrence as unmodeled initial-condition error does in practice.

4. **Signal-proportional disturbance.** A fixed absolute floor becomes decorative once the state
   grows by orders of magnitude over the horizon, which is how the prior laboratory made every
   mechanism trivially separable late in a run.

5. **A degeneracy partner.** `actuator_deadband` suppresses commands below a threshold and passes
   larger ones. Separating it from nominal requires a command *below* the threshold; separating it
   from `actuator_loss` requires one *above*. No single action resolves every pair, and the
   requirements run in opposite directions. This is what makes selection a real problem rather than
   a formality.

6. **Latent severity.** A hypothesis is a (mechanism, severity) pair. A method does not know how
   severe a fault is, and severity determines which probe can see it, since the deadband threshold
   is proportional to severity. Passing true severity to a forward model would hand a method half
   the answer and would collapse the selection problem, because the optimal probe would then be
   identical in every episode. Severity is marginalized, not reported.

7. **A declared cost model.** Risk rises with commanded amplitude. Without this, the largest probe
   dominates trivially and the denominator of the mathematics contract is inert.

8. **Classical comparison baselines.** A cost-blind maximum-separation selector and a cheapest-
   guaranteed-separation selector in the set-based tradition of the 2004 monograph. These were run,
   and the classical rule matched the information-theoretic one. The conclusion drawn is therefore
   that classical active fault diagnosis suffices for this laboratory and the Bayesian layer earns
   nothing, reported at full weight under Invariant 7 rather than deferred or restated as a
   hypothesis. The selector is retained as an implemented comparison arm, not as a recommended
   method.

## Prior exposure

This disclosure is material and is stated without softening.

The drafter implemented the graded laboratory and the selector **and executed comparisons before
drafting this document**. The following were observed prior to this proposal being written: a
severity sweep whose first design failed to defeat the method and was corrected; per-pair
separability tables across probe amplitudes; the 0.00 blindness result for the Amendment 005 probe;
an expected-information-gain validation against the analytic bound `ln(2)`; a homogeneous-episode
comparison in which adaptive selection tied the best fixed policy and did not beat it; and a
heterogeneous-episode comparison in which adaptive selection reached matched accuracy at
approximately one third the cost of the best fixed policy.

A comparison against the classical set-based baselines and a cost-weight sensitivity sweep were in
progress when this section was first written and completed before submission. Their result is
recorded here rather than deferred, because it is adverse to the component this amendment proposes.
At a matched accuracy of 0.950, identical for all three rules at every weight tested, the
cheapest-guaranteed-separation baseline in the 2004 set-based tradition achieved a mean generalized
cost of 28.50 against the information-gain selector's 28.30. The ratio between them stayed within
1.01 across a fifty-fold sweep of the risk weight. The two rules reached the same frontier by
different routes, selecting different probes with indistinguishable outcomes.

The comparison was run twice, before and after the structural-mismatch correction recorded below,
and **the sign of the cost difference reversed between the two runs**: the classical rule was cheaper
by 0.10 under the original plant and dearer by 0.20 under the corrected one. A difference whose
direction is not stable under a change to the plant is not an effect. This is treated as
strengthening the null rather than as a partial result for either rule, and no ordering between the
two methods is claimed in either direction.

The provisional conclusion is therefore that **classical active fault diagnosis is sufficient for
this laboratory and the information-theoretic layer earns no performance advantage over it**. That
null is reported at full weight under Invariant 7. It also narrows what this amendment can be said
to deliver: the graded laboratory is justified because it can measure, but the selector it was built
to evaluate does not beat the classical rule it was compared against.

Two conditions under which an information-gain rule would be expected to outperform
guaranteed-separation — a non-uniform prior over mechanisms, and a variable budget permitting early
stopping — were absent from this comparison, which used a uniform prior and a fixed budget of two
actions. This observation was made after the adverse result was seen and is recorded as a candidate
hypothesis only. It must not be tested as a prospective claim except under a subsequent amendment
that freezes the design and analysis before any further outcome is inspected.

Building and measuring before seeking authority reverses the mission's own discipline, which requires
the design to be frozen before outcomes are inspected. It was done to place executable evidence in
front of the owner before requesting authority, and it means **this laboratory's design is
outcome-informed**. The specific contamination is that the mechanism catalog, the severity bands, the
action catalog, and the cost weights were all chosen by an agent who had already seen which
configurations produce a measurable effect.

The consequence is binding and is proposed as a condition of approval: **no campaign run under this
amendment may report a result as prospective.** Any campaign executed against this laboratory is
exploratory. A claim-bearing result requires a subsequent amendment that freezes the design, the
episode schedule, the cost weights, and the analysis before any further outcome is inspected, and
that runs against a laboratory configuration whose parameters were not selected on the basis of the
effects observed here.

## Approval basis

The owner, Daniel Wahnich, has directed autonomous progression toward the mission goals and holds a
standing delegation for signing ceremonies with the `iter001-governance` key, as disclosed in
Amendments 002 through 005. This proposal does **not** invoke that delegation.

The drafter declines to sign this amendment. Amendment 005 discloses that its proposer and signer
were the same agent and that the owner did not read it before authorization; that document states
plainly that it was not independently reviewed. Reproducing that structure here would mean an agent
proposing a rebuild of the laboratory, authorizing itself to build it, judging the prior laboratory
inadequate, and certifying its replacement — with no point at which a second mind examined the
judgment. The finding this amendment rests on is a criticism of the drafter's own prior work by the
same drafter, which is precisely the configuration the mission's authority separation exists to
prevent.

Approval therefore requires the owner to read this document and sign it. That reading is not a
formality; it is the only independent check present anywhere in this chain.

A separate custody matter is recorded here because it bears on what any signature proves: the
`iter001-governance` private key is stored unencrypted in the working tree at
`.local/keys/iter001-governance.ed25519`, gitignored and unpublished, but readable by any process
with filesystem access to the repository. During the work preceding this proposal an automated agent
read that key and minted and verified a valid compute lease against the frozen owner public key.
Nothing was committed and no campaign was run. The `verify_lab_compute_lease` gate therefore records
that a campaign was authorized and binds it to an ontology, scope, and window — genuine
reproducibility value — but it does not constrain whether a campaign runs. It is an audit trail, not
an access control, and should not be described as one until the key is held outside the reach of the
software that checks it.

## Frozen parent and normative binding

The original hypothesis at commit `52d71e16a75df12adf47e943fd5c329f6e04d5c0` and the approved
Amendments 002, 003, 004, and 005 remain byte-identical and in force. This proposal adds a
laboratory configuration and a selection rule. It does not change the scientific unit, the
physical-incident contract, the census, the causal-laboratory harness, the safety boundary, the
verdict classes, the falsifiers F1 through F10, or the forbidden claims. The Amendment 005 reference
simulator, ontology, and campaign remain in the repository unmodified; this laboratory is an
addition and not a replacement, so the prior result remains reproducible exactly as recorded.

Where this document and any prior frozen contract appear to conflict, the prior contract prevails and
the conflict is `INVALID`.
