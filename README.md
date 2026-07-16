# Inbar

Physical Causal Evidence and Verified Intervention Research

Inbar is a pre-release research system for testing whether multimodal autonomy remains correct when
its claims meet physical reality. It defines typed contracts for turning asynchronous incident
evidence into competing causal hypotheses, ranking approved tests, and separating proposal authority
from execution, truth, and outcome authority. The complete evidence-to-intervention chain remains a
research target, not a validated capability.

The objective is not another benchmark score. The objective is a defensible chain from evidence to
mechanism, from mechanism to intervention, and from intervention to independently settled physical
outcome.

## Research question

Can an open world multimodal system identify physical mechanisms from incomplete incident evidence,
choose a cost and risk normalized action that separates competing explanations, recover under
separately governed execution and independent outcome verification, and retain calibrated
performance on unseen hardware and fault families?

## Current state

Inbar is in Iteration 001 corpus qualification. No training run, GPU run, GCP scientific job, or
paid-provider mission run has been authorized. Private hosted CI is engineering validation rather
than mission compute, and its time and cost are not fully metered. No diagnosis, recovery, safety,
transfer, product readiness, state of the art, or economic value claim is active.

The dated reconnaissance did not establish a qualifying source among its enumerated public set.
Those corpora remain useful as parser, simulator, distribution-shift, and shortcut controls, but the
screen was not a frozen systematic review and its external evidence is not independently
reconstructible. The current protocol therefore blocks the present public-source-only route.
Qualifying physical evidence may come from prospectively approved testbed work or from existing
real-world evidence that already contains every required field and permits independent audit.

Because that block rests on a screen the mission itself records as not systematic, the mission's
central negative premise is not an established result. Amendment 002 freezes a prospective,
content-bound, independently reconstructible source-screening census to settle it. Its contracts are
implemented and its adversarial controls execute; the census has not run. No domain has been
enumerated, no artifact retrieved, no candidate screened, and no census verdict issued. A census
pass would be a nomination for separately authorized acquisition, never an admission. The census
cannot reach `KILL_PUBLIC_SUBSTRATE`: a bounded frame cannot establish an unbounded negative.

The current research wedge is offline spacecraft and robotics incident replay. The distinct proposed
first product is a pre-action, offline and shadow-mode evidence dossier compiler with ranked,
human-reviewable safe-test recommendations. A later post-action assurance stage may ingest receipts
and outcomes produced under separate authorities; neither product stage would execute commands. No
product or command authority is active.

## Authority model

1. Evidence authority supplies model visible telemetry, commands, imagery, text, clocks, and
   provenance.
2. Hypothesis authority proposes an open set of causal mechanisms with an explicit unknown class.
3. Truth authority remains sealed from proposal and binds each established mechanism to the
   adjudicated target.
4. Safety authority approves the available diagnostic actions and their preconditions.
5. Execution authority performs the selected action without changing the proposal.
6. Outcome authority decides whether the physical state settled and recovery completed.
7. Statistical authority evaluates transfer, calibration, uncertainty, and value independently.

Learned systems never hold safety or execution authority. The current protocol permits replay,
simulation, and explicitly approved testbeds. Flight, live spacecraft, live robots, destructive
tests, and deployment authority remain forbidden.

## Scientific invariants

1. Model visible evidence and adjudication truth are separate artifacts.
2. Every claim bearing gate must reject a deliberately broken or placebo control.
3. Claim-bearing implemented paths bind their artifacts, approvals, and verdict inputs by content;
   a general evidence-backed authority for every lifecycle transition remains prospective.
4. Outcome verification remains in a disclosed independence group separate from the hypothesis
   proposer, action selector, recovery proposer, and executor.
5. Unknown mechanisms and calibrated abstention are first class outcomes.
6. Evaluation freezes separate leakage-component, hardware, vehicle, mission, environment,
   fault-family, and operating-regime holdouts and clusters uncertainty by root incident, acquisition
   session, and identity rather than random windows.
7. Null, blocked, invalid, interrupted, and corrected results retain evidentiary weight.
8. A signed report is not scientific authority unless a verifier can reconstruct it from sealed
   inputs.
9. Cloud providers, GPU runners, Aweb, and Maestro remain replaceable adapters behind typed ports.

## Admission status

Iteration 001 is preregistered and its bootstrap admission implementation has executable positive,
negative, and placebo controls. CI enforces at least 90.01 percent branch-aware coverage in the
Ubuntu 24.04 and Python 3.12 quality job. Uninstrumented compatibility jobs run the full test suite on
Ubuntu 24.04 with Python 3.11, 3.13, and 3.14 and on macOS 15 with Python 3.12 and 3.14. Exact
checkpoint metrics belong in the append-only research ledger rather than in this overview.

Canonical admission remains blocked. The control authority is intentionally marked `bootstrap`, no
production receipt exists, and no pilot verdict has been issued. Release requires executable
Shortcut Authority V2 semantics, truth bound mechanism resolution, terminal signatures over
complete inputs, reconstructible invalidity records, and opaque media leakage controls. The
current implementation-only V2 checkpoint contains exact tree, cross-fit, and encrypted-envelope
primitives, but it grants no data access, target release, execution, result, seal, or publication
authority. Its current boundaries are recorded in
[the implementation checkpoint](docs/research/ITER001_SHORTCUT_V2_IMPLEMENTATION_CHECKPOINT.md).

The committed control launcher starts a fresh child, built from a clean committed source snapshot,
that performs control execution, manifest and receipt assembly, fixture-key access, signing, and
no-replace publication. The child checks an exact snapshot census, locked distribution inventory,
complete source closure, Git identity, committed contract, preregistration ancestry and bytes, and
fixed filesystem boundaries before fixture-key access. The launcher imports no signing surface,
receives no key material, and accepts only a bounded canonical response tied to the selected commit,
tree, request, and exact durable receipt bytes.

This is a fresh-process integrity property under the unmodified committed launcher, not a hostile
same-user isolation claim. A process that controls child arguments or the prepared dependency tree
before import can also alter live child objects, and another process with the same operating-system
identity can read the fixture key. Those threats require an independently enforced supervisor and
signer rather than child self-inspection.

This implementation is deliberately fixture-only. The child rejects the canonical `bootstrap`
contract before key or output access, and V1 cannot be relabeled as production authority. Canonical
sealing still requires the approved Shortcut Authority V2 control suite, an independently enforced
launcher and signer boundary outside the same operating-system identity, exact read-only bundle
verification, and terminal mission integration. Until those artifacts and approvals exist, ordinary
`inbar` invocation cannot authorize acquisition and CI must retain the sole
`iter001-acquisition-contract` blocker.

A non-replayable local fixture rehearsal on macOS was observed to pass from a clean committed
snapshot. A second clean checkout without the fixture private signing key accepted the rebound
bundle through the same-code, nonterminal V1 verifier. The disposable commits and full bundle were
not promoted, so this is a recorded local integration observation rather than reconstructible or
independent acceptance evidence. It produced no canonical receipt, admitted no corpus, exercised no
physical system, and established no scientific, safety, transfer, product, or value result.

These blockers are preserved as blockers. CI accepts the checkpoint only when the mission validator
reports the exact registered blocker set and no additional failure.

## Verification

```bash
uv sync --link-mode copy --reinstall --group dev --frozen
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest --cov --cov-report=term-missing
uv run inbar schemas check
uv run inbar memory verify
uv run inbar mission validate --expect-failure iter001-acquisition-contract
uv run inbar handoff check
```

The mission validator must report exactly the registered acquisition-contract blocker until
canonical authority is sealed. The handoff renderer builds a private, no-hardlink clone of the
selected committed tree. Every materialized recovery file must match that tree's exact eligible
regular-file paths, content hashes, sizes, and executable modes; ignored, untracked, dirty, linked,
and special-file inputs fail closed. Only the descriptor-verified current memory ledger is overlaid
before a fresh interpreter runs against a fixed authority-source manifest. The parent verifies the
framed response and rechecks the selected Git and recovery inputs before accepting the rendered
bytes.

A checkpoint that reports engineering validation must bind an exact implementation commit and tree
to a separately committed, canonical receipt. The handoff verifier recomputes that receipt's
implementation-to-evidence lineage, final evidence-to-recovery lineage, complete artifact set,
command plan, JUnit counts with zero skipped cases, passed results for every registered credibility
control recorded in JUnit evidence, complete committed Python source coverage inventory,
statement-plus-branch coverage, and mission blocker inventory from committed bytes. Final checking
requires the exact clean two-file recovery commit, a strict byte-prefix append of the evidence
parent's memory, and regular nonexecutable Git blobs; prospective rendering at the evidence commit
is not final acceptance. This is a same-operator
engineering observation and candidate-tree consistency check, not independent or base-controlled
attestation and not scientific evidence. An unexpected mission pass, any additional failure, omitted
source or control, substituted artifact, later unvalidated change, or stale recovery state makes the
check fail. Content hashes, nonempty logs, and self-recorded exit codes do not prove that a command
ran; base-controlled CI must independently execute its applicable contract and quality checks on the
exact candidate head.

## Repository map

```text
src/fieldtrue/  Typed domain core, authority boundaries, validators, and command line
mission/        Ownership, lifecycle, stage, and publication contracts
protocol/       Schemas, trust anchors, controls, splits, and frozen data contracts
experiments/    Preregistrations, amendments, proof artifacts, and result records
claims/         Scoped machine readable claim registry
memory/         Append only extraction ledger for the future standalone research engine
docs/           Architecture, mathematics, frontier review, and publication controls
tests/          Unit, adversarial, placebo, integration, and reconstruction verification
```

The internal `fieldtrue` namespace is retained because signed historical evidence and frozen schema
identifiers bind it. Inbar is the mission and repository identity. Historical proof is never
rewritten for a cosmetic migration.

Start with [the architecture](docs/ARCHITECTURE.md), [the roadmap](docs/ROADMAP.md),
[the Iteration 001 hypothesis](experiments/iter001_physical_causal_evidence_acquisition/HYPOTHESIS.md),
and [the claim boundaries](docs/CLAIM_BOUNDARIES.md).
