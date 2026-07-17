# Inbar

**A research program for physical causal evidence: testing whether an open-world multimodal
system can identify the physical mechanism behind an incident from incomplete evidence, choose a
safe test that discriminates competing explanations, recover under independently-governed
execution, and stay calibrated on hardware it has never seen — with the authority to *propose* a
mechanism held permanently separate from the authority to establish truth, to act, and to
adjudicate the outcome.**

> **Honest status up front. Scientific state: `bootstrap`, BLOCKED at `iter001-acquisition-contract`.**
> No corpus is admitted, no incident is screened to a verdict, no simulation campaign has run, and
> no scientific result exists. Iteration 000 returned `BLOCKED_EVIDENCE` on NASA ADAPT: 16 real
> incidents on 1 hardware identity, 0 of a required 30 complete dossiers. The public-source route is
> recorded as `BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE` — a dated, non-systematic reconnaissance,
> not an established negative. Four owner-signed amendments authorize the machinery that now exists:
> A001 shortcut-authority V2, A002 source-screening census, A003 census execution, A004
> causal-laboratory. Under a real owner-signed lease, the census executor made first live contact
> with public investigation sources — NTSB, the Chemical Safety Board, and NASA LLIS returned bytes
> to an honestly-identified crawler; NRC refused it, recorded as a real access datum, not evaded.
> **That is transport validation, not a census run.** No `CensusReport`, no candidate screened
> against the twelve gates, no verdict. The causal-laboratory harness is implemented and covered but
> no episode has run. This is a pre-release research system. A public code checkpoint here does not
> imply a diagnosis, recovery, safety, transfer, product-readiness, state-of-the-art, or
> economic-value result, and none is claimed.

Start with [the architecture](docs/ARCHITECTURE.md), [the roadmap](docs/ROADMAP.md), the
[Iteration 001 hypothesis](experiments/iter001_physical_causal_evidence_acquisition/HYPOTHESIS.md),
and [the claim boundaries](docs/CLAIM_BOUNDARIES.md). The dynamic recovery state is generated into
[`HANDOFF.md`](HANDOFF.md); durable context is [`CONTINUITY.md`](CONTINUITY.md).

## The research question

From asynchronous, heterogeneous incident evidence, can a system maintain competing physical
mechanism hypotheses — including an explicit *unknown* — choose a preapproved, cost-aware, safe
test that discriminates among them, verify a proposed recovery against an independent physical
oracle, and compile the verified mechanism into a calibrated monitor that transfers across hardware
and fault families? The objective is not a benchmark score. It is a defensible chain from evidence
to mechanism, from mechanism to intervention, and from intervention to an independently settled
physical outcome.

## Why authority separation is the whole idea

Most autonomy evaluation asks one model to diagnose, act, and grade itself. That is exactly how a
system fools its own success signal. Inbar makes the failure modes structurally impossible by
splitting the work into authorities that never merge, and by forbidding any learned system from
ever holding safety or execution authority.

```mermaid
flowchart LR
  E["Evidence authority<br/>telemetry · commands · imagery · clocks"]-->H["Hypothesis authority<br/>competing mechanisms + unknown"]
  H-->S{"Safety authority<br/>approves the allowed test"}
  S-->|approved|X["Execution authority<br/>performs the action"]
  S-->|refused|R["Refused · recorded · never run"]
  X-->O["Outcome authority<br/>did the physical state settle?"]
  T["Truth authority<br/>sealed mechanism"]-->O
  O-->Q["Statistical authority<br/>transfer · calibration · value"]
  classDef propose fill:#eaf3ff,stroke:#0969da,color:#0c2d57;
  classDef truth fill:#fff4e5,stroke:#b54708,color:#4a2500;
  classDef stop fill:#fff1f0,stroke:#cf222e,color:#4c1114;
  classDef adjudicate fill:#e6f4ea,stroke:#1a7f37,color:#0f3d1c;
  class E,H propose;
  class T,S truth;
  class R stop;
  class O,Q adjudicate;
```

The proposer sees model-visible evidence and never the sealed truth. The safety authority can
refuse an action, and a refused action is recorded as refused, never executed. The outcome
authority is disclosed as independent of the proposer, the action selector, the recovery proposer,
and the executor. A signed report is not scientific authority unless a verifier can reconstruct it
from sealed inputs. These are not aspirations; they are enforced by typed contracts and executable
controls throughout the repository.

## The scientific arc so far

Every node below is bound to committed evidence. Color is semantic: gray is a null or block that
retains full evidentiary weight, blue is completed engineering, orange is a bounded correction,
green is authorized-and-built.

```mermaid
flowchart TB
  I000["iter000 · NASA ADAPT<br/>BLOCKED_EVIDENCE<br/>16 incidents · 1 identity · 0/30"]
  SRC["source-role audit<br/>KILL_PUBLIC_SUBSTRATE →<br/>BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE"]
  A002["Amendment 002 · source-screening census<br/>frame · fact-locators · C1–C6 · I1–I4"]
  A003["Amendment 003 · census execution<br/>lease · certifi transport · frame registry"]
  WC["first world contact<br/>NTSB · CSB · NASA LLIS returned<br/>NRC refused — access datum"]
  A004["Amendment 004 · causal laboratory<br/>paired branches · sealed injection<br/>C6 dissolves under injected truth"]
  BLK["iter001-acquisition-contract<br/>BLOCKED · no corpus · no verdict"]
  I000-->SRC-->A002-->A003-->WC-->A004
  A002-.->BLK
  A003-.->BLK
  A004-.->BLK
  classDef null fill:#f6f8fa,stroke:#57606a,color:#24292f;
  classDef complete fill:#eaf3ff,stroke:#0969da,color:#0c2d57;
  classDef corrected fill:#fff4e5,stroke:#b54708,color:#4a2500;
  classDef active fill:#e6f4ea,stroke:#1a7f37,color:#0f3d1c;
  class I000,BLK null;
  class SRC corrected;
  class A002,A003,WC complete;
  class A004 active;
```

**Iteration 000 — `BLOCKED_EVIDENCE`.** NASA ADAPT passed source integrity, parser integrity, and
truth separation, but contributed only 16 incidents from one hardware identity and no independently
reviewed ambiguity sets or safe discriminating actions. Its proof and consumed verification
authority are immutable inputs to Iteration 001 and are never rerun or rewritten.

**The public-source block is not an established negative.** A dated reconnaissance did not establish
a qualifying public aerospace, robotics, or industrial corpus among its enumerated set. That screen
was not a frozen systematic review and its external evidence is not independently reconstructible,
so its verdict was narrowed from the legacy `KILL_PUBLIC_SUBSTRATE` to the bounded
`BLOCK_CURRENT_PUBLIC_SOURCE_ONLY_ROUTE`. The central negative premise — that no public source can
supply the complete construct — has never been established under the mission's own evidentiary
standard.

**Amendment 002 — the source-screening census** freezes, before any retrieval: an enumerated frame
in two strata (the prior-exposed legacy sources, and a prospective stratum of *investigation-record*
domains, on the hypothesis that the construct is the shape of an investigation, not a dataset
release); a fact-locator contract requiring a content-frozen, authority-identified artifact for
every gate-bearing fact, so a mutable page can never establish a gate; the retrospective chronology
conditions C1–C6, which hold that a reviewer who reads an investigation's conclusion cannot then
extract its pre-outcome hypothesis set, so counted historical dossiers require a second, unexposed
reviewer; the inherited role-independence conditions I1–I4; five frame-scoped verdict classes; and a
resource ceiling. `KILL_PUBLIC_SUBSTRATE` is unreachable by the instrument: a bounded frame cannot
establish an unbounded negative.

**Amendment 003 — census execution** adds the per-session lease (which can only restate the frozen
ceiling), an HTTPS-only certifi-verified retrieval executor that identifies the crawler honestly and
never mimics a browser, a content-addressed local store that never commits third-party bytes, and a
frame registry enumerating the nine frozen domains. Under a real owner-signed lease, live retrieval
was exercised against the frozen frame: NTSB, the Chemical Safety Board, and NASA LLIS returned
bytes; NRC refused the honest crawler and that refusal is recorded as a genuine access datum rather
than evaded. This is transport validation. No census has run to a verdict.

**Amendment 004 — the causal laboratory** is where the method itself becomes testable. The census
cannot obtain sealed mechanism truth without a human reading a record, which exposes that reader
under C6. A simulator injects its own ground truth, so the truth is known by construction and no
reader is exposed: the full method — a hypothesis proposer that commits before truth, a
discriminating-test selection, a recovery, and an outcome adjudicator — can be built and tested end
to end against known truth without a second reviewer. The harness executes paired branches from one
frozen snapshot and adjudicates a diagnosis against the sealed injected mechanism.

```mermaid
flowchart LR
  SNAP["frozen snapshot"]-->NO["no_op"]
  SNAP-->TT["targeted_test"]
  SNAP-->WS["wrong_but_safe"]
  SNAP-->RC["recovery"]
  SNAP-->BU["blocked_unsafe · refused"]
  SEAL["sealed injected mechanism<br/>truth known by construction"]-->ADJ
  HYP["blind hypothesis set<br/>≥2 known + unknown"]-->ADJ{"adjudicate diagnosis<br/>vs revealed truth"}
  TT-->ADJ
  classDef propose fill:#eaf3ff,stroke:#0969da,color:#0c2d57;
  classDef truth fill:#fff4e5,stroke:#b54708,color:#4a2500;
  classDef stop fill:#fff1f0,stroke:#cf222e,color:#4c1114;
  classDef adjudicate fill:#e6f4ea,stroke:#1a7f37,color:#0f3d1c;
  class SNAP,NO,TT,WS,RC,HYP propose;
  class SEAL truth;
  class BU stop;
  class ADJ adjudicate;
```

A simulator branch never counts as a physical incident. A causal-laboratory result establishes that
the method works inside the simulator and nothing about the physical world.

## What is built, and what is not

| Surface | Built and certified | Not established |
| --- | --- | --- |
| Mission governance | Four owner-signed amendments; git-pinned authority chain reconstructible from committed bytes; append-only research memory; self-regenerating handoff cycle | A general signed authority for every lifecycle transition; an independent attestation |
| Corpus admission | Typed incident contract; positive, negative, and placebo controls; the census screening and execution layers | A qualifying physical dossier; a canonical control seal; a pilot verdict |
| Source screening | Frozen frame; fact-locator, chronology (C1–C6), and role-inheritance (I1–I4) contracts; adversarial controls | A census run to a `CensusReport`; any screened candidate; any verdict |
| Causal laboratory | Paired-branch protocol; sealed injection with authority separation; compute-lease contract; a deterministic reference simulator | A simulation campaign; a Basilisk adapter; any adjudicated method result |
| Claims | Scoped, content-bound claim registry synchronized with executable behavior | Any diagnosis, recovery, safety, transfer, product, or economic-value claim |

## Scientific invariants

1. Model-visible evidence and adjudication truth are separate artifacts.
2. Every claim-bearing gate must reject a deliberately broken or placebo control.
3. Claim-bearing paths bind their artifacts, approvals, and verdict inputs by content.
4. Outcome verification stays in a disclosed independence group, separate from the proposer,
   action selector, recovery proposer, and executor.
5. Unknown mechanisms and calibrated abstention are first-class outcomes.
6. Evaluation freezes leakage-component, hardware, vehicle, mission, environment, fault-family, and
   operating-regime holdouts, clustering uncertainty by root incident and acquisition session.
7. Null, blocked, invalid, interrupted, and corrected results retain full evidentiary weight.
8. A signed report is not scientific authority unless a verifier can reconstruct it from sealed
   inputs.
9. Cloud providers, GPU runners, and external models remain replaceable adapters behind typed
   ports.

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

The mission validator must report exactly the registered `iter001-acquisition-contract` blocker
until canonical authority is sealed. Continuous integration runs the full contract and quality
suite on the exact head across Ubuntu and macOS and Python 3.11 through 3.14; the coverage-bearing
quality job enforces at least 90.01 percent branch-aware coverage. A green public checkpoint proves
engineering discipline, not a scientific result.

## Repository map

```text
src/fieldtrue/  Typed domain core, authority boundaries, validators, and command line
mission/        Ownership, lifecycle, stage, and publication contracts
protocol/       Schemas, trust anchors, controls, splits, and frozen data contracts
experiments/    Preregistrations, amendments, proof artifacts, and result records
claims/         Scoped machine-readable claim registry
memory/         Append-only extraction ledger for the future standalone research engine
docs/           Architecture, mathematics, frontier review, and publication controls
tests/          Unit, adversarial, placebo, integration, and reconstruction verification
```

The internal `fieldtrue` namespace is retained because signed historical evidence and frozen schema
identifiers bind it. Inbar is the mission and repository identity; historical proof is never
rewritten for a cosmetic migration.

## License

The Inbar source code is released under the [Apache License, Version 2.0](LICENSE). This code
release carries no scientific authority; see [`IP_NOTICE.md`](IP_NOTICE.md). Third-party datasets
retain their own terms and are never redistributed here; see [`DATA_LICENSES.md`](DATA_LICENSES.md).
