# Iteration 000: NASA ADAPT Corpus Readiness

Status: **PRE-REGISTERED**  
Frozen: 2026-07-14  
Mission: Active Causal Mission Assurance (working research descriptor)

## Decision question

Does the public NASA ADAPT package satisfy the minimum evidence contract for the first causal
mission-assurance experiment: at least 30 genuinely ambiguous incidents with independently
verified causes and safe tests that can distinguish competing mechanisms?

This is an infrastructure and construct-readiness adjudication. It is not a model benchmark and
cannot establish the mission's scientific thesis.

## Prior exposure disclosure

Before this pre-registration, the operator session performed source reconnaissance and observed:

- the public archive contains 16 experiment text files;
- each file interleaves experiment/fault metadata, sensor samples, commands, and fault-injection
  events;
- the downloaded archive SHA-256 was
  `746f94a7242c02c502126f2e5269e6a72a81f790cd39ce33543ef76c68f7ce78`;
- the experiment-log SHA-256 was
  `28db2a1ba15d19aa6f6009e3245afd9cfb244e45c07f63fc5c21d7d49461ee84`.

The incident-count outcome is therefore not blind. The purpose of this iteration is to bind the
source, prove leakage-safe ingestion, and produce a machine-verifiable readiness verdict without
moving the threshold after inspection.

## Frozen source

- Landing page: `https://data.nasa.gov/dataset/adapt-dataset`
- Text archive:
  `https://c3.ndc.nasa.gov/dashlink/static/media/dataset/dataset_text.zip`
- Experiment log:
  `https://c3.ndc.nasa.gov/dashlink/static/media/dataset/Experiment_Log.xls`
- NASA describes the testbed as a spacecraft-like electrical power system with controlled physical
  and software fault insertion, 128 sensors, and 2 Hz sampling.

## Frozen gates

All gates are conjunctive.

1. **Source integrity:** downloaded bytes match the two frozen SHA-256 digests above.
2. **Parser integrity:** every discovered experiment is either parsed exactly once or causes the
   run to fail; silent row or file loss is forbidden.
3. **Truth separation:** `ExperimentControl`, `FaultInject`, and antagonist-internal command rows
   must never appear in model-visible evidence. Fault type, mode, location, injection method, and
   injection time belong only to a separately hashed truth plane.
4. **Minimum count:** at least 30 incidents have independently identified physical mechanisms.
5. **Ambiguity:** each counted incident has at least two plausible pre-outcome hypotheses.
6. **Discriminating action:** each counted incident has at least one independently reviewed safe
   test whose possible outcomes distinguish those hypotheses.
7. **Transfer support:** the corpus contains at least two hardware or vehicle identities and at
   least two fault families, permitting a frozen group-held-out evaluation.
8. **Evidence usefulness:** at least two operational evidence channels are available per counted
   incident, with explicit clock domains and provenance.

No percentage threshold may replace an absolute count gate.

## Verdict classes

- `PASS`: all eight gates pass.
- `BLOCKED_EVIDENCE`: source and parser integrity pass, but one or more scientific-readiness gates
  are unsupported. This authorizes acquisition of another corpus or partner evidence, not model
  training.
- `INVALID`: source integrity, parsing, leakage separation, or exact coverage fails.
- `KILL_CONSTRUCT`: the cases are not genuinely ambiguous because the cheapest deterministic
  baseline already resolves them. This verdict requires a later, separately pre-registered
  baseline execution; it cannot be issued from this iteration alone.

## Execution and stop rule

The committed implementation will run exactly one ingestion followed by one committed readiness
analyzer. Negative fixtures must prove that checksum mismatches, leaked labels, omitted files,
duplicate incidents, and unsafe truth/evidence joins fail closed.

Stop immediately after the verdict. This iteration authorizes no GPU, cloud job, paid provider,
model training, live command, hardware actuation, or public performance claim.

## Expected proof artifacts

- content-addressed source lock;
- ingestion receipt and hash-chain verification;
- model-visible incident manifest;
- separately stored truth manifest;
- exact file/row coverage report;
- readiness report with each gate's evidence and disposition;
- machine-readable verdict and human-readable `RESULT.md` generated from the same result object.

## Forbidden claims

Regardless of outcome, this iteration cannot claim diagnosis accuracy, active-test quality,
recovery success, safety, cross-hardware transfer, product readiness, state of the art, or economic
value. NASA does not endorse this work.
