# Fieldtrue

Active Causal Mission Assurance

Fieldtrue is a research system for testing whether multimodal autonomy remains correct when its
claims meet physical reality. Models propose causal hypotheses and recovery candidates. Approved
interventions, independent execution, and settled outcomes determine what is accepted.

The name defines the target property. A system becomes field-true only when its claimed objective
survives independent intervention, physical execution, held-out transfer, and recovery. Benchmark
performance alone is insufficient.

## Research question

Can a system turn asynchronous multimodal incident evidence into competing physical mechanisms,
select the safest cost-aware test that separates them, verify recovery through an independent
outcome authority, and compile the resolved mechanism into a calibrated monitor that transfers to
unseen hardware?

## Current status

The repository is at corpus qualification. Iteration 000 is a preregistered readiness adjudication
over the public NASA ADAPT corpus. It is not a model benchmark. No diagnosis, recovery, safety,
transfer, product-readiness, state-of-the-art, or economic-value claim is authorized.

The expected result is useful even if blocked: it determines whether the corpus can support the
central experiment before model training or cloud spend begins.

## Authority model

1. Evidence: model-visible telemetry, commands, imagery, text, and provenance.
2. Truth: separately committed adjudication records unavailable to proposers.
3. Hypothesis: open-world causal candidates with an explicit unknown mechanism.
4. Intervention: preapproved actions ranked by information, risk, cost, and duration.
5. Outcome: independent execution evidence and a settled-state requirement.
6. Claim: registered scope, uncertainty, falsifiers, and forbidden interpretations.

Learned systems never hold safety authority. Version 0 permits replay, simulation, and explicitly
approved testbed execution. Flight, live spacecraft, live robot, destructive, financial, and
deployment authority are forbidden.

## Engineering invariants

1. Model-visible evidence and adjudication truth are separate artifacts.
2. Artifacts, transitions, approvals, and claims are content-addressed.
3. Every claim-bearing gate must reject a deliberately broken or placebo control.
4. Recovery proposers cannot serve as their sole outcome verifier.
5. Unknown mechanisms and calibrated abstention are first-class outcomes.
6. Evaluation holds out connected hardware, mission, and fault groups rather than random windows.
7. Null, blocked, invalid, interrupted, and correction results retain full evidentiary weight.
8. Aweb, Maestro, cloud providers, and GPU runners remain optional adapters behind typed ports.
9. A signed report is not scientific authority; the verifier recomputes its verdict from the
   sealed evidence and truth planes.

## Verification

```bash
uv sync
uv run ruff check .
uv run ruff format .
uv run mypy src
uv run coverage run -m pytest
uv run coverage report
uv run fieldtrue schemas check
uv run fieldtrue mission validate
```

Third-party dataset bytes are not committed. The frozen iteration hypothesis defines acquisition,
stop rules, verdict classes, expected proof artifacts, and forbidden claims.

The iteration proof contains the exact dataset lock, ingestion receipt, coverage report,
model-visible manifest, separately sealed truth manifest, machine-readable readiness report, and
one authoritative human-readable result. Verification fails when the reported gates differ from
proof-local recomputation, even when every producer artifact and ledger event is validly signed.

## Repository map

```text
src/fieldtrue/  Domain core, ports, adapters, services, verifier, and command line
mission/        Machine-readable ownership, identity, lifecycle, and release gates
protocol/       Frozen data, trust, baseline, split, and control contracts
experiments/    Preregistration, proof bundle, result, and learning record per iteration
claims/         Scoped machine-readable claim registry
memory/         Append-only evidence for the future standalone research engine
docs/           Architecture, mathematics, frontier review, and publication controls
tests/          Unit, adversarial, placebo, integration, and end-to-end verification
```

Read [Architecture](docs/ARCHITECTURE.md), [Preregistration](PREREGISTRATION.md), and
[Claim Boundaries](docs/CLAIM_BOUNDARIES.md) before interpreting a result.
