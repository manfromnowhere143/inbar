# Amendment 001: Shortcut Authority V2

Status: IMMUTABLE PROPOSAL

Drafted: 2026-07-15

Iteration: `iter001_physical_causal_evidence_acquisition`

Authority effect: none without a separate owner-approval receipt

## Decision

The V1 shortcut report is not scientific authority. It may remain a historical compatibility
artifact, but no V1 implementation path, evaluation file, signature, or
`resolves_mechanism_without_action` Boolean can authorize `PASS_PILOT` or `KILL_CONSTRUCT`.

Shortcut Authority V2 becomes eligible for implementation only after Daniel Wahnich approves the
exact Git commit and raw SHA-256 hashes of this document and its machine-readable proposal in the
separate signed owner-approval receipt defined below. This proposal is immutable: approval does not
change a Boolean or status inside either approved artifact. Approval does not seal canonical
authority, release truth, execute an audit, or create a scientific result.

V2 freezes one construct-kill baseline: a validator-executed depth-two decision tree trained on
pre-action model-visible features under exact leave-one-group-out cross-fitting. Hardware family,
hardware identity, and fault family are evaluated separately. Every eligible incident is held out
exactly once on each axis. The tree algorithm, feature inventory, preprocessing, split construction,
cost ceiling, tie rules, and aggregation are fixed before any target release.

`KILL_CONSTRUCT` requires exact held-out mechanism resolution for every eligible incident on all
three axes. The first nine shortcut rules are diagnostic controls and can never kill the construct.
No target-selected algorithm, hyperparameter, feature subset, threshold, or rule family may become
authority on the observations that selected it.

## Trigger

The preregistration requires the cheapest deterministic evidence-only rule not to resolve the
physical mechanism, but it does not define the target, shared label vocabulary, denominator,
feature completeness, fitting discipline, grouped holdout procedure, abstention, correctness,
unknown handling, aggregation, truth-release chronology, or the meaning of cheapest.

V1 accepts arbitrary implementation and evaluation artifacts and trusts a statistician-signed
Boolean. The validator checks the signature and corpus hash but does not recompute the rule,
predictions, counts, or Boolean. It also permits any of ten rules, including excluded metadata and
truth controls, to trigger `KILL_CONSTRUCT`. That is a latent false-authority path.

## Prior exposure

This proposal is drafted after inspection of the V1 validator, synthetic fixtures, public source
roles, and `docs/research/ITER001_SHORTCUT_AUTHORITY_V2.md`. No eligible Iteration 001 physical
corpus, V2 ontology, prediction-key assignment, total feature inventory, cross-fit fold, mechanism
target, frozen prediction, target release, V2 evaluation, or V2 verdict exists. No truth or outcome
was inspected to choose the tree, depth, impurity criterion, feature rules, or aggregation.

Iteration 000 NASA ADAPT artifacts remain historical inputs and cannot be relabeled as an
Iteration 001 V2 census. Existing V1 synthetic fixtures may test compatibility and negative
controls only.

## Frozen parent and normative binding

The original hypothesis at commit `52d71e16a75df12adf47e943fd5c329f6e04d5c0` remains
byte-identical. This proposal narrows undefined shortcut authority; it does not change the
scientific unit, physical admission gates, coverage floors, execution ceiling, safety boundary,
verdict classes, or forbidden claims.

This document and `protocol/amendments/iter001_001.json` are jointly required. The machine proposal
is the exact executable subset; this document supplies scientific semantics and exclusions.
Neither may weaken the other. A conflict, omission, or implementation that does not bind both raw
artifact hashes is `INVALID` and requires a new prospective amendment.

Any later change to a scientific rule requires a new prospective amendment committed before
affected evidence, target, training-target release, prediction, or evaluation access.

## Owner-approval receipt

Approval is a separate immutable JSON receipt. No new schema implementation is needed to define its
bytes. Its exact fields are:

- `schema_version = inbar.owner-amendment-approval-receipt.v1`;
- `approval_id`;
- `owner_actor_id = daniel-wahnich` and `owner_signing_key_id = iter001-governance`;
- `owner_signer_anchor_artifact_sha256 =
  c5cf91b620ae3f34cc9ecebf936c4f48014f04cfa21e3fdc1cf0713f440b1804`, binding the raw bytes
  of the frozen acquisition contract at commit
  `2955c1bcca190430cd5c88c57187126bb7531d7a`;
- `owner_key_trust_basis = git-pinned-iter001-governance-ed25519-no-external-timestamp` and
  `owner_ed25519_public_key =
  b0f514d7b91caa7c43ea58ffae42ebeea48164d24948723a8c805f780df38962`, which must equal that
  contract's `trust_anchor_public_key`;
- `proposal_git_commit`, `amendment_document_artifact_sha256`, and
  `machine_proposal_artifact_sha256`;
- `decision = approve_shortcut_v2_implementation_only`;
- `previous_approval_receipt_sha256`, which is 64 zeroes for the first receipt;
- a fresh 32-byte `nonce` encoded as lowercase hexadecimal;
- `issued_at` in canonical UTC form;
- `receipt_hash`; and
- `signature`.

`receipt_hash` is `sha256_value` over the complete receipt body excluding `receipt_hash` and
`signature`. `signature` is Ed25519 over the raw 32 bytes of `receipt_hash`. The pinned owner key,
exact subject hashes, decision, predecessor, nonce uniqueness, timestamp, receipt hash, and
signature must verify. The receipt grants only implementation of this proposal. It grants no
production data access, target creation, truth release, resource spend, physical action, canonical
seal, result, or publication transition.

## Hash modes and typed roots

`artifact_sha256` means SHA-256 over exact raw file bytes. It binds Markdown, historical files,
pretty JSON artifacts, ciphertext, and other byte streams. `sha256_value` means SHA-256 over the
repository's compact canonical JSON encoding of a parsed value. The frozen parent artifacts are
grandfathered raw-byte bindings even when their stored JSON formatting is not canonical.

All new semantic roots use `sha256_value` with an explicit schema-version domain. Arrays are ordered
as stated, object keys are canonicalized by the repository encoder, and duplicate keys or items are
invalid. The future typed schemas must implement the exact payload definitions frozen in the
machine proposal for:

- case keys and eligible incident IDs;
- eligible dossiers and model-visible projections;
- hypothesis sets, ontology definitions, and prediction-key assignments;
- extractor registry, total feature inventories, and cross-fit folds;
- split locks and the aggregate target manifest;
- rule registry, fitted-state manifests, prediction manifests, and evaluation reports;
- target-manifest hiding commitment, freeze receipt, and release plan; and
- prepared release, publication, open, phase-completion, and final-recomputation receipts.

An input hash binds the exact validator-derived feature vector read by one rule for one case. It is
not the case key and cannot replace the incident and hypothesis-set join.

`target_manifest_sha256`, per-case target artifact hashes, raw target hashes, truth-record-derived
target commitments, and commitment salts remain truth-only until their exact scope is authorized.
Before then, only the target-manifest hiding commitment defined below may leave the truth plane.

## Signature subjects

Every V2 attestation signs a domain-separated subject hash computed from the canonical body with its
`attestation` field excluded. The attestation and any derived artifact hash are never members of
their own signed subject. Specifically:

`attestation_subject_hash(kind, body) = sha256_value({domain:
"inbar.iter001.shortcut-attestation-subject.v1", kind, subject:body_without_attestation})`.

This rule applies to ontology, target, feature, fold, registry, fit, prediction, evaluation,
target-manifest commitment, freeze, key-preflight, prepared-release, publication, open,
phase-completion, and final-recomputation receipts. A signature or artifact hash included
recursively in its own subject is invalid.

## Two-phase census

The eligible census is frozen from physical, rights, chronology, role, action, recovery, settled
outcome, resource, and non-shortcut completeness gates before Shortcut V2 training-target release.

Shortcut ontology, target, feature, fold, fit, prediction, release, or evaluation failure cannot
remove an incident from that denominator. Once the census is frozen, a missing or duplicated V2
artifact invalidates the audit. This prevents a corrupt target or hard case from shrinking the
denominator.

The denominator is the complete eligible physical-root census. Windows, frames, simulator
branches, repeated annotations, rows, folds, axes, and repeated evaluations never add scientific
units. `KILL_CONSTRUCT` requires the frozen coverage gate to pass and at least 30 eligible roots.
Counts are reported separately per axis; they are never summed into 3N pseudo-observations.

## Shared mechanism ontology and prediction keys

Every known pre-truth hypothesis is assigned one content-derived shared prediction key. A canonical
mechanism-class definition binds its name, causal locus, failure mode, temporal signature,
directionality, and prose definition. Its key is `sha256_value` over that definition with domain
`inbar.iter001.mechanism-class.v1`. The exactly one unknown hypothesis uses the reserved key
`unknown`.

The prediction-key manifest is committed with or before the reviewed hypothesis set and before any
mechanism target. It binds the case key, hypothesis ID, class definition hash, prediction key,
unknown status, proposer, independent ontology reviewer, ambiguity-review receipt, commitment
time, and attestations.

The mapping is biconditional: the same mechanism class must use the same canonical definition and
key in every case, and one key cannot name different classes. Incident, source, site, task, system,
hardware, filename, path, absolute-time, truth, or outcome tokens cannot distinguish a class.
Semantically equivalent definitions must be merged by an ontology reviewer whose independence
group differs from the hypothesis proposer, mechanism reviewer, shortcut workers, and final
evaluator. Within each case, keys are unique.

Predictors learn shared keys, never incident-local hypothesis IDs. If a valid predictor proposes a
key absent from a held-out case, the canonical result is explicit abstention with reason
`key_unavailable`. A supplied manifest that claims a selected local hypothesis for an absent or
multiply mapped key is invalid. Every selected target key and prediction must map to exactly one
local hypothesis.

## Mechanism resolution targets

For every eligible case, the mechanism reviewer creates one truth-only signed target after the
hypothesis set, ontology assignment, and ambiguity review are committed and strictly before
safe-test review. It binds:

- case key and incident ID;
- truth record, hypothesis set, ontology, prediction-key manifest, and canonical sorted mechanism
  hashes;
- exactly one target hypothesis ID and target prediction key;
- whether the target is the known or reserved unknown hypothesis;
- content-addressed physical mapping evidence;
- commitment time, reviewer identity, and attestation.

The target hypothesis must occur exactly once in the bound hypothesis set, occur in the truth
record's competing-hypothesis set, match the prediction-key manifest, and have the declared unknown
status. Every eligible case occurs exactly once in the signed aggregate target manifest. Invalid,
missing, duplicated, or extra targets invalidate the audit rather than count as wrong predictions.

Before any target release, the mechanism custodian samples a fresh 32-byte salt and computes:

`target_manifest_hiding_commitment_sha256 = sha256_value({schema_version:
"inbar.iter001.target-manifest-commitment.v1", target_manifest_sha256, salt_hex})`.

`salt_hex` is exactly 64 lowercase hexadecimal characters.
The signed commitment receipt contains exactly its schema version, hiding commitment, target count,
eligible-incident root, committed time, custodian, and attestation. The salt and target-manifest
root remain custodian-only until final registry recomputation. The public commitment receipt
contains neither. At final reveal, the evaluator recomputes the root and commitment and verifies
every previously released subset against the frozen full manifest.

Target plaintext and all unsalted target hashes may not appear in a shared input tree,
model-visible or control-only plane, log, diagnostic, cache, filename, environment variable,
exception, Git object, or public receipt before authorized release.

## Total model-visible feature authority

The kill baseline reads only pre-cutoff model-visible evidence. Before any V2 designer, extractor,
shortcut worker, or rule author inspects eligible model-visible content, a clean committed
extractor registry freezes every supported media type, extractor schema, implementation root, and
output feature type. Adding, removing, or changing an extractor after that boundary requires a
prospective amendment.

Every model-visible artifact receives exactly one disposition:

- fully extracted by one registered built-in extractor;
- explicitly forbidden because it contains excluded identity, truth, outcome, post-cutoff, or
  rights-prohibited content; or
- unsupported, which makes `cheapest-deterministic-evidence-only`
  `BLOCKED_ACQUISITION`.

Silent omission is forbidden. A signed completeness receipt binds every artifact, byte count,
media type, extractor or exclusion reason, extracted feature keys, and the input and output roots.
The validator recomputes it.

Features are a closed union of:

- `boolean` with values `true` or `false`;
- `numeric` as finite canonical decimal strings; and
- `categorical` as canonical UTF-8 strings.

Missingness is explicit and distinct from every value. A feature key is the
`sha256_value` of `{schema_version:"inbar.iter001.feature-key.v1", extractor_id,
extractor_schema_version, canonical_source_pointer, feature_type}`. All cases share a sorted union
of feature keys. There is no feature selection, learned embedding, hashing trick, dimensionality
reduction, imputation, normalization, scaling, or target-driven pruning.

A canonical decimal matches `^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`, has no exponent or leading plus,
has no trailing fractional zero, and represents zero only as `0`. JSON numeric lexemes are parsed
with unbounded decimal arithmetic and reserialized to that form. Equality and ordering compare
their exact decimal values.

Structured JSON extraction recursively inventories every scalar leaf. Numeric lexemes become exact
decimal strings; arrays retain indexes; duplicate object keys, nonfinite numbers, unsupported
values, or invalid UTF-8 are invalid. Opaque media requires a prospectively registered typed
extractor. Identity and forbidden-field scanners execute before feature emission. A supported
artifact or field that is neither emitted nor rejected invalidates completeness.

At most 4,096 distinct feature keys and 100,000 candidate predicates may reach one tree node.
Exceeding either bound is `BLOCKED_ACQUISITION` and requires a prospective amendment. Subsampling,
heuristic pruning, or post-target extractor changes are forbidden.

## Exact diagnostic selectors

V2 rules are data interpreted by the bound validator. Python paths, source code, shell commands,
pickles, notebooks, external plugins, imported modules, remote calls, and dynamically executed
rule content are forbidden.

The exact selectors are:

- `source_identity`: the canonical UTF-8 `SourceManifest.source_id`;
- `task_identity`: the canonical UTF-8 `IncidentGroupRecord.mission_id`;
- `system_identity`: canonical JSON array `[system_family, hardware_id]`;
- `site_identity`: the canonical UTF-8 `IncidentGroupRecord.site_id`;
- `path_and_filename`: sorted pairs of the validated repository-relative POSIX
  `ArtifactBinding.path` and its final segment, with no filesystem resolution, Unicode
  normalization, case folding, or platform separators;
- `absolute_time_signature`: sorted arrays
  `[evidence_id, normalized_start_ns, normalized_end_ns]` using the already verified integer
  nanosecond fields;
- `fault_label`: canonical UTF-8 `TruthRecord.fault_family`, released as a truth-only oracle
  selector under its own scope;
- `annotation_projection`: the complete canonical value of the prospectively typed and
  content-bound annotation manifest; absence blocks this diagnostic before a V2 seal;
- `sha256_identity_bucket`: the first eight bytes, interpreted unsigned big-endian, of
  `sha256(seed_bytes || 0x00 || canonical_json([system_family, hardware_id]))` modulo 256; and
- `model_visible_feature_inventory`: the complete total feature vector defined above.

The random identity seed bytes are the UTF-8 bytes of
`inbar-shortcut-v2-random-identity-embedding-v1`. Its SHA-256 is
`4eb725c244d2089ebeb42476e52c4bdb290def3091192b999cc837d21eb7c352`.

## Cross-fit folds

Shortcut folds are deterministic and separate from later learned-model train, calibration, and
test locks. For each axis:

- `hardware_family` groups by exact system family;
- `hardware_identity` groups by exact hardware ID; and
- `fault_family` groups by exact adjudicated fault family.

Each distinct group value defines one fold. Its holdout set contains every eligible incident with
that value; its train set is the exact complement. Group values and incidents are ordered by
canonical UTF-8 bytes. Every incident must occur in exactly one holdout fold per axis and in no
holdout fold of another value on that axis. Empty train or holdout sets, group leakage, duplicated
incidents, or a fold root that differs from validator derivation is invalid.

Every `rule_id, axis, holdout_group` fold has two distinct isolated stage jobs in the fixed order
`train_prediction`, then `holdout_evaluation`. Each stage job has its own ephemeral X25519 key,
process, private directory, cache, and execution-isolation ID. The same bound automated worker
implementation may run stage jobs sequentially, but a process, private key, or target state that
served one stage job is destroyed before another begins. The train stage receives only that fold's
train targets, fits the predictor, freezes fitted state and holdout predictions, then destroys its
plaintext target state and key. After the global prediction barrier, a fresh evaluation stage
receives only the immutable prediction artifacts and that fold's holdout targets; it never receives
train targets and never refits. No human shortcut worker receives plaintext targets. This is
required because one fold's train targets include another fold's holdout cases.

## Frozen predictors

Categorical diagnostic predictors build a mapping from selector value to the unique modal shared
target key in that fold's train set. Exact target-count ties abstain. Unseen held-out selector
values abstain. The random identity rule applies the frozen bucket transform before the same modal
mapping. Supplied state and predictions are comparison evidence; the validator recomputes both.

The sole kill predictor is `depth_two_exact_gini_tree`. For each fold it executes:

1. At each node, enumerate candidate predicates only from the train incidents that reach that node.
   Boolean candidates are equality to `true` and `false`. Categorical candidates are equality to
   every distinct nonmissing node-local value. Numeric candidates are `<=` the arithmetic mean of
   every consecutive pair of distinct sorted node-local values, computed with unbounded decimal
   arithmetic and serialized as a canonical decimal string. Every feature also has an
   `is_missing` predicate.
2. A missing value makes equality and numeric predicates false. `is_missing` is true only for
   missing. Held-out categories not seen in train make equality false. No target influences
   predicate enumeration or order.
3. Starting at the root, evaluate every candidate that leaves at least two train incidents in each
   child. For a node set `S`, `G(S) = 1 - sum_k (n_k / |S|)^2`. For children `L` and `R`, split
   score is `(|L| * G(L) + |R| * G(R)) / |S|`. Counts are integers; fractions are reduced exact
   rationals and compared by cross multiplication with no floating point. Select the strict
   minimum. Exact score ties use canonical predicate-spec bytes.
4. Split only when impurity is strictly lower than the parent impurity. Repeat independently at
   each child to maximum depth two. No pruning, tuning, surrogate split, randomization, class
   weighting, or alternate tree is permitted.
5. A leaf emits the unique modal shared target key among its train incidents. A class-count tie
   emits abstention. A key unavailable in the held-out case emits `key_unavailable` abstention.

The canonical tree spec binds every node, predicate, exact impurity fraction, class count, leaf
output, train incident root, feature root, target-release receipt, operation count, and fit time.
The static prediction cost is one root feature read and at most one child feature read, two
predicate evaluations, two branches, one leaf emission, and one local-key mapping check. Training
resource use, wall time, CPU time, peak memory, bytes read, engineering time, and direct cost are
recorded separately. The acquisition resource ceiling remains binding.

There is no algorithm or hyperparameter search. A later discovery analysis may motivate a new
untouched confirmation experiment, but it cannot alter this tree or affect Iteration 001.

The stable historical rule ID `cheapest-deterministic-evidence-only` is operationalized here as this
fixed low-complexity learner. Its zero-split, one-split, and depth-two outcomes share one algorithm;
it stops whenever no strict impurity reduction exists. The claim is not that no imaginable program
has a shorter description. The claim is that this exact representation-free, at-most-two-read
baseline either does or does not resolve every grouped held-out case.

Every predicate spec is exactly the compact canonical JSON encoding of
`{schema_version, feature_key, operator, operand}` with
`schema_version = inbar.iter001.tree-predicate.v1`. `feature_key` is the 64-character lowercase
hexadecimal feature key. The operator vocabulary and operand types are closed:

- `is_missing` requires JSON `null`;
- `equals_boolean` requires a JSON Boolean;
- `equals_categorical` requires the exact canonical UTF-8 categorical string; and
- `less_than_or_equal_numeric` requires the canonical decimal string defined above.

No aliases, extra fields, alternate operand encodings, or invalid operator and operand combination
are permitted. Predicate ordering compares the resulting repository `canonical_json` UTF-8 byte
strings as unsigned byte sequences. This same representation is embedded in the canonical tree
spec and used for every equal-Gini tie.

## Frozen ten-rule registry

The registry order is exact:

| Rule ID | Authority | Selector | Predictor | Plane |
|---|---|---|---|---|
| `source-identity` | diagnostic | `source_identity` | categorical train mode | control only |
| `task-identity` | diagnostic | `task_identity` | categorical train mode | control only |
| `system-identity` | diagnostic | `system_identity` | categorical train mode | control only |
| `site-identity` | diagnostic | `site_identity` | categorical train mode | control only |
| `path-and-filename` | diagnostic | `path_and_filename` | categorical train mode | control only |
| `timestamp` | diagnostic | `absolute_time_signature` | categorical train mode | control only |
| `fault-label` | diagnostic oracle | `fault_label` | categorical train mode | truth-only oracle |
| `annotation` | diagnostic | `annotation_projection` | categorical train mode | control only |
| `random-identity-embedding` | diagnostic | `sha256_identity_bucket` | categorical train mode | control only |
| `cheapest-deterministic-evidence-only` | sole kill | `model_visible_feature_inventory` | depth-two exact Gini tree | model visible |

Every rule runs every cross-fit fold on all three axes. Targets, fitted state, predictions,
recipients, keys, and results cannot be pooled across jobs. Forbidden metadata resolving a target
from an excluded control plane is diagnostic and cannot kill. Forbidden metadata present in the
model-visible plane makes the audit `INVALID`.

The fault-label probe is not required to resolve a held-out fault-family fold: its held-out selector
is unseen and must abstain. Separate direct-target synthetic fixtures provide the evaluator
positive control.

## Prediction and verdict semantics

For each job, the fitted state and all holdout predictions freeze before that job's holdout targets
are released. A prediction is correct only when its selected shared key and local hypothesis ID
exactly equal the signed mechanism target. A structurally valid wrong prediction or abstention is
non-resolving, not invalid.

For each axis, denominator equals the complete eligible census. Every incident contributes exactly
one held-out prediction. `cheapest-deterministic-evidence-only` resolves that axis only when
selected count and correct count both equal the denominator.

Only `cheapest-deterministic-evidence-only` can trigger `KILL_CONSTRUCT`. It does so only when:

- all non-shortcut integrity and coverage gates pass;
- the frozen denominator is at least 30;
- hardware-family, hardware-identity, and fault-family axis reports each cover the exact census;
- every held-out prediction on every axis is selected and correct; and
- the independent final evaluator recomputes the same result from the frozen trusted execution
  boundary.

One wrong prediction or abstention on any axis prevents construct kill. Passing this shortcut gate
does not establish learned-model value, diagnosis, intervention benefit, or transfer.

## Freeze receipt and trusted execution boundary

Before the first training-target release, a shortcut protocol reviewer signs one public
`ShortcutFreezeReceipt`. It binds:

- both proposal artifact hashes, owner-approval receipt, and approved proposal commit;
- canonical acquisition contract, eligible census, dossiers, projections, hypotheses, ontology,
  shared keys, extractor registry, total feature inventory, cross-fit folds, and split locks;
- target-manifest hiding commitment, rule registry, complete release plan, and all pre-target
  control roots;
- trust registry, previous authority receipt, clean Git commit and tree, dependency lock,
  interpreter and operating-system identity, and immutable container digest when used;
- every authority-bearing module, schema, and executable entry point; and
- commitment time, reviewer identity, and attestation.

The freeze receipt is public because it contains the salted target-manifest hiding commitment, not
the target root or salt. Binding `src/fieldtrue/acquisition.py` alone is insufficient.
Canonicalization, models, schemas, splits, signatures, encryption, publication primitives,
dependencies, and entry point are part of the trusted execution boundary. A dirty tree, mutable
dependency, unbound module, or runtime mismatch blocks release.

## Recipient-scoped truth release

Signing and encryption keys are separate. Every release recipient has a dedicated X25519 public
encryption key, key ID, and key epoch in the signed actor trust registry. Ed25519 keys are used only
for signatures. Before any real target exists, the custodian runs a synthetic sealed-box challenge;
the recipient opens it and signs a key-preflight receipt. That receipt binds acquisition session,
proposal commit and hashes, trust registry, challenge ID, fresh 32-byte nonce, purpose and authority
subject, recipient actor and isolated context, key ID, epoch, X25519 public-key hash, challenge
ciphertext and plaintext commitment hashes, issued time, expiry time, open time, result, and
attestation. It is valid for exactly one release subject in one acquisition session, and the
release context names its artifact hash. A failed, missing, expired, replayed, substituted, or
cross-purpose key preflight blocks release.

Target subsets use libsodium `crypto_box_seal` with X25519 and XSalsa20-Poly1305. A sealed box
provides recipient confidentiality and integrity, not sender identity or a time lock. Custodian and
recipient attestations supply sender and open authority.

The canonical release context contains exactly:

- schema version and domain;
- iteration ID and acquisition-session ID;
- approved proposal commit, both proposal artifact hashes, and owner-approval receipt hash;
- canonical acquisition contract, trust registry, public freeze receipt, target-manifest hiding
  commitment, and release-plan hashes;
- release ID, phase ordinal, previous-phase-completion hash, and exact named prerequisite map;
- recipient actor, isolated execution context, encryption key ID, key epoch, and X25519 public-key
  hash, plus the exact key-preflight receipt artifact hash; and
- an `authority_subject` union:
  `{kind:"rule_axis_fold", rule_id, axis, holdout_group, recipient_stage, scope,
  incident_count, incident_ids_sha256}`, where `recipient_stage` is exactly `train_prediction` or
  `holdout_evaluation`, or
  `{kind:"registry_recomputation", rule_registry_sha256, scope:"complete_registry",
  incident_count, incident_ids_sha256}`.

The first phase uses 64 zeroes for `previous_phase_completion_sha256`. Every later phase names the
immediately preceding signed phase-completion receipt. Its prerequisite map additionally names all
freeze, train-release, fit, prediction, publication, open, evaluation, and reveal receipts required
by that phase. A timestamp alone is never order proof.

The envelope payload is exactly:

`{schema_version:"inbar.iter001.target-envelope.v1", release_context, target_subset, salt_hex}`.

`salt_hex` is a fresh 32-byte `randombytes_buf` value encoded as exactly 64 lowercase hexadecimal
characters and never reused. The public hiding commitment is `sha256_value` of this exact envelope
payload. The salt and unsalted targets remain inside the recipient envelope until that scope is
released.

The canonical payload is framed as an unsigned 64-bit big-endian JSON byte length followed by the
JSON bytes. Let `P = 16384 * (incident_count + 1)`. The framed length must be strictly less than
`P`. Call `sodium_pad` with `blocksize=P` and `max_buflen=P` and require output length exactly `P`.
On open, require successful `sodium_unpad` with the same block size, exact frame-length equality,
canonical JSON, no trailing bytes, exact context equality, and commitment equality. Otherwise the
release is invalid. Ciphertext length is therefore target-independent for a public incident count.

Ciphertext bytes remain custodian-only and inaccessible to the recipient until release. Release has
four nonrecursive stages:

1. The custodian signs a `PreparedTruthReleaseReceipt` over its body excluding `attestation`. It
   binds context, envelope commitment, ciphertext artifact hash, recipient inbox, and
   `prepared_at`.
2. An atomic no-replace operation publishes one bundle containing only the ciphertext and prepared
   receipt to that recipient's isolated inbox.
3. After the operation, the custodian signs a separate `TruthReleasePublicationReceipt` binding the
   prepared receipt, bundle root, destination, no-replace primitive, result, and `published_at`.
4. The recipient opens only after a successful publication receipt and signs a
   `TruthReleaseOpenReceipt` binding prepared and publication receipts, context, commitment,
   ciphertext hash, open result, and `opened_at`.

The publication receipt is not inside the bundle it proves. The open receipt binds it. A
`ShortcutPhaseCompletionReceipt` then binds prepared, publication, open, and the phase's fit,
prediction, or evaluation artifacts. The next release chains to that completion receipt.

Public metadata intentionally reveals purpose, rule or registry subject, axis, holdout group,
scope, incident count, incident root, context hash, salted envelope commitment, and ciphertext
artifact hash. It reveals no target value, raw target hash, salt, or target-dependent length.

## Global release chronology

The complete release plan is signed before its first phase:

1. Commit all mechanism targets and the public target-manifest hiding commitment.
2. Freeze the census, ontology, feature authority, folds, rule registry, trusted execution
   boundary, release plan, and pre-target controls.
3. In registry, axis, then holdout-group order, create the isolated `train_prediction` stage job for
   each rule-axis-fold. Release only its train targets and, for the fault-label diagnostic, its
   separately scoped train and holdout selector values without held-out mechanism targets. The
   bound validator fits the frozen predictor and freezes fitted state plus all holdout predictions,
   then the stage process, key, and plaintext state are destroyed.
4. Only after every rule-axis-fold prediction manifest is frozen may held-out targets be released.
   In the same deterministic job order, create a fresh isolated `holdout_evaluation` stage job,
   provide it the immutable prediction artifacts and only that fold's held-out targets, run the
   bound validator without refitting, freeze its evaluation and phase-completion receipt, and
   destroy the evaluation process, key, and plaintext state.
5. Release the complete target manifest, commitment salt, and full registry-recomputation scope to
   a final evaluator whose actor, key, process, private storage, and independence group are disjoint
   from the mechanism custodian, hypothesis proposer, ontology reviewer, shortcut workers, and
   action or outcome roles.
6. The same final scope releases an envelope-reveal manifest. For every phase it binds phase
   ordinal, exact release context, target subset, envelope salt, envelope commitment, and prepared,
   publication, and open receipt hashes. Its signed root is part of the final receipt.
7. The final evaluator verifies the target-manifest reveal, every released subset and envelope
   commitment, every receipt chain, all diagnostic results, all kill predictions, and all per-axis
   counts. It reruns the bound validator in the exact trusted execution environment and signs the
   final recomputation receipt.

The final registry release explicitly authorizes recomputation for the complete frozen rule
registry; kill-only truth cannot be reused for diagnostic recomputation. No actor, private key,
process, cache, or filesystem may receive targets from two jobs whose scope could contaminate an
unfrozen prediction. Missing, duplicated, reordered, replayed, forked, cross-run, or
wrong-predecessor receipts are invalid.

## Invalidity

The following are `INVALID`, not merely incorrect:

- missing, duplicate, extra, or swapped eligible case, feature, fold, prediction, target, shared
  key, ontology assignment, or join;
- target hypothesis absent from or multiply mapped in the bound hypothesis set;
- invalid target kind, mechanism hash, signature, actor, evidence, or commitment chronology;
- incomplete extraction, unsupported content silently omitted, forbidden metadata model-visible,
  or target-driven feature processing;
- changed rule order, selector, predictor, tree depth, predicate grammar, Gini arithmetic,
  minimum-leaf rule, tie rule, unseen rule, cost bound, fitted state, fold, recipient, or release
  plan;
- training on a holdout target or prediction after its holdout target release;
- pooled folds, axes, recipients, state, predictions, counts, or results;
- early, plaintext, wrong-recipient, wrong-key, wrong-scope, wrong-purpose, replayed, or
  unauthorized target access;
- an unsalted target or target-manifest hash leaving the truth plane before authorized release;
- recursive signature subject, publication receipt inside the bundle it proves, missing phase
  predecessor, or inconsistent envelope field;
- an unbound execution tree, dependency, schema, cryptographic primitive, or publication path;
- supplied state, prediction, count, or Boolean differing from recomputation;
- target-selected discovery presented as confirmation or construct-kill authority;
- V1 artifacts presented as canonical V2 authority; or
- any positive authority claim while the acquisition contract remains bootstrap or unsealed.

An absent V2 implementation before execution remains blocked. Once V2 authority is claimed, a
structural, chronology, custody, or trusted-execution defect is invalid.

## Required controls

The implementation must include outcome-bound controls for at least:

- flipped supplied Boolean with fixed predictions;
- tampered feature, fold, fitted state, tree node, prediction, target, denominator, count, or output
  hash;
- same-class different key, same-key different class, positional join, and absent-key selection;
- incomplete feature extraction, opaque omission, identity leakage, and target-driven pruning;
- numeric midpoint, exact Gini fraction, impurity tie, class tie, missing value, unseen category,
  no-improvement leaf, and depth boundary;
- train-target use from the holdout group and cross-job target contamination;
- missing, duplicated, extra, or swapped eligible incident or fold;
- one incident not held out exactly once per axis;
- invalid target, commitment, freeze, preflight, prepared-release, publication, open,
  phase-completion, evaluation, or final-recomputation signature;
- wrong recipient, key epoch, execution context, rule, axis, fold, subset, predecessor, or purpose;
- receipt replay, fork, omission, reordering, cross-run substitution, and nonzero genesis;
- failed key-possession challenge and wrong-recipient decryption;
- ciphertext visible before atomic release, replace-on-existing publication, and publication cycle;
- inconsistent envelope field names, reused or malformed salt, leaked unsalted target hash, invalid
  padding, trailing bytes, and target-dependent length;
- fault-family holdout unseen labels producing abstention;
- direct-target synthetic oracle exact resolution as an evaluator positive control;
- one valid miss and one valid abstention as non-resolving;
- exact held-out census resolution on only one or two axes unable to kill;
- exact held-out census resolution on all three axes as `KILL_CONSTRUCT`;
- target defect unable to shrink the census and zero-count equality unable to resolve;
- dirty or incomplete trusted execution binding; and
- V1 report unable to authorize a canonical verdict.

The V2 control suite requires a new version and receipt. Existing V1 controls remain historical and
cannot be silently reinterpreted.

## Implementation and activation gate

This proposal alone authorizes no implementation, key creation, target creation, truth access,
corpus evaluation, resource spend, control seal, terminal result, or publication transition.

After exact owner approval, implementation may add only the typed contracts, canonical schemas,
structural validators, ontology, total feature authority, cross-fit predictors, separate signing
and encryption keys, scoped release system, recomputation path, adversarial controls, explicit V2
hashes in the admission result, and fail-closed contract state defined here.

The canonical acquisition contract remains `bootstrap` until a later clean committed tree has a
complete passing V2 control receipt, exact trusted-execution bindings, an Inbar publication signer
path, and independent verification. Approval of this proposal is not that seal.

## Unchanged boundaries

No GPU, cloud job, paid call, data download, live robot, spacecraft, physical action, training on
real targets, model evaluation on real targets, or customer claim is authorized by this proposal.
The iteration still cannot claim diagnosis, intervention benefit, recovery, safety, transfer,
product readiness, economic value, or state of the art.
