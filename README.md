# Active Causal Mission Assurance

**Working research descriptor, not the final product name.**

Can a system turn asynchronous multimodal incident evidence into competing physical fault
mechanisms, select the safest and least expensive test that separates them, verify recovery
through an independent execution authority, and compile the resolved mechanism into a calibrated
monitor that transfers to unseen hardware?

This repository is the independent Daniel-owned mission and product seed. It is not an Aweb
package, a Maestro subsystem, an anomaly dashboard, a generic root-cause chatbot, or the future
general-purpose research engine.

## Honest status

The mission launched on 2026-07-14. Iteration 000 is a pre-registered corpus-readiness gate over
NASA ADAPT. No model, active-diagnosis, recovery, safety, transfer, product, state-of-the-art, or
economic claim exists yet. The first public corpus is expected to be useful for parser and
evidence-plane validation but too small to satisfy the 30-incident scientific gate; the committed
analyzer, not prose, owns that verdict.

## Product wedge

The first product-shaped workflow is offline and read-only:

> Provide a spacecraft or robotic test-incident bundle; receive ranked falsifiable mechanisms,
> missing evidence, the next preapproved safe discriminating test, and independently executed
> evidence for or against a proposed recovery.

There is deliberately no live or flight command authority in v0.

## Architecture invariants

- Model-visible evidence and adjudication truth are physically separate artifacts.
- Every artifact, transition, hypothesis, test proposal, result, and claim is content-addressed.
- Learned multimodal systems may propose hypotheses; they are never the safety authority.
- Tests come only from an approved action set and carry explicit cost, duration, and risk.
- The recovery proposer cannot be its sole verifier.
- Unknown mechanisms and calibrated abstention are first-class outcomes.
- Evaluation holds out hardware, vehicle, mission, and fault family, never random windows.
- Aweb, Maestro, Google Cloud, and GPU runners are optional adapters behind typed ports.
- Nulls, corrections, blocked gates, and cheap-baseline wins are publishable results.

## Local verification

```bash
uv sync --all-extras
uv run ruff check .
uv run mypy src
uv run pytest --cov
uv run acma mission validate
```

The NASA ADAPT acquisition and readiness execution are documented in the frozen iteration-000
hypothesis. Third-party dataset bytes are never committed.

## Repository map

```text
src/mission_assurance/     domain core, ports, adapters, application services, CLI
mission/                   machine-readable contract and lifecycle state
protocol/                  frozen datasets, baselines, schemas, and split policy
experiments/               preregistration, proof, result, and learning record per iteration
claims/                    machine-readable scoped claim registry
docs/                      architecture, mathematics, threat model, and frontier boundary
tests/                     unit, mutation, integration, placebo, and end-to-end guards
```

See [the architecture](docs/ARCHITECTURE.md), [master preregistration](PREREGISTRATION.md), and
[claim boundaries](docs/CLAIM_BOUNDARIES.md) before interpreting any result.

