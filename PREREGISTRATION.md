# Master Pre-Registration

Frozen mission-level protocol, 2026-07-14. Per-iteration hypotheses may narrow this contract but
cannot weaken it silently.

## Primary research question

From asynchronous heterogeneous evidence, can a system maintain competing physical mechanism
hypotheses including unknown, choose a preapproved safe and cost-aware test that discriminates
among them, verify a proposed recovery against an independent physical oracle, and compile the
verified mechanism into a calibrated monitor that transfers across hardware and fault families?

## Primary outcomes

1. Tests to correct isolation.
2. Risk-, delay-, and cost-weighted isolation regret.
3. Time to isolation and blinded engineer investigation time.
4. Hypothesis-set coverage and size, Brier score, NLL, and risk-coverage behavior.
5. Unsafe-test and false-action counts.
6. Recovery action validity, target validity, and independently settled recovery success.
7. Compiled-monitor false alarms per operating hour, latency, and resource use.
8. Frozen leave-one-hardware, leave-one-vehicle, and leave-one-fault-family transfer.
9. Verified economic value with a positive 95% lower confidence bound.

## Baseline ladder

Run cheap and deterministic systems first: limits/OOL checks, existing test suite, runbook/FMEA,
fault tree, expert lookup, residual/change-point rules, observer bank, Bayesian diagnosis, and
physics-only simulation. Only then authorize retrieval plus a frontier model, causal-physics
graphs, learned multimodal systems, or learned world models.

Active-test controls include no test, random safe test, cheapest safe test, myopic expected
information gain, classical optimal experiment design, belief-tree search, and safe
reachability-based discrimination where applicable.

## Falsifiers

- F1: initial evidence is not genuinely ambiguous.
- F2: the cheapest deterministic or FMEA/Bayesian baseline matches the learned system.
- F3: task/configuration identity, one modality, shuffled modalities, or a compute-matched placebo
  preserves performance.
- F4: selected tests do not reduce tests, time, or cost without increasing unsafe/false actions.
- F5: learned causal edges fail intervention or environment-shift checks.
- F6: absent mechanisms are forced confidently into the known catalog.
- F7: learned reward/confidence improves while physical success or policy ordering degrades.
- F8: recovery is not confirmed by an outcome authority independent of the proposer.
- F9: positive effects fail frozen hardware or fault-family transfer.
- F10: engineer time/value has a non-positive 95% lower confidence bound.

## Split discipline

Split at the incident group level. Hardware, vehicle, mission, environment, and fault-family
identities used for a held-out claim must be disjoint. Freeze IDs and content hashes before feature
extraction. Random telemetry-window splits are forbidden.

## Multimodal attribution controls

Every multimodal claim requires all unimodal baselines; early/late fusion; task/configuration-only;
learned and randomly initialized identity embeddings; modality deletion, permutation, duplication,
noise, and clock jitter; and a compute-matched unimodal ensemble. Attention maps are not causal
evidence.

## Initial numeric bars

Final effect sizes are frozen after corpus qualification and power analysis. Until then, the
minimum directional bars are at least 30% fewer tests to isolation or at least 25% lower blinded
engineer time, with no worse false-action rate; calibrated abstention; and a positive 95% lower
confidence bound on held-out transfer. These are eligibility bars, not achieved results.

## Claim and safety boundaries

- Synthetic NOS3/Basilisk work cannot carry a product, operational-safety, or real-world causal
  headline without independent physical evidence.
- A simulator or world model is authoritative only inside a separately accredited decision-use
  domain. Proxy/true policy-order reversal stops optimization.
- No live autonomous commands. Start with replay and shadow recommendations, then human-approved
  test-stand execution under a run-specific safety envelope.
- No universal safety guarantee. Report empirical calibrated risk only inside frozen distributions.
- Publish nulls and corrections at full weight. A cheap-baseline win is a valid mission result.

## Value model

For incident class `j`, verified value is evaluated as:

```text
LCB95(sum_j(delta_hours_j * engineer_cost_j
          + delta_downtime_j * downtime_cost_j
          + delta_tests_j * test_cost_j
          + delta_failure_probability_j * loss_j)
      - integration_cost - compute_cost - false_action_cost)
```

Pricing or scale claims are forbidden unless this lower bound is positive on independently
verified customer or partner evidence.

